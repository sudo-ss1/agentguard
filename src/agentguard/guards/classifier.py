"""Injection classifiers behind a swappable interface.

`InjectionClassifier` is what the result scanner calls. `OnnxSequenceClassifier` runs a local
ONNX text-classification model, the pinned, int8-quantized ProtectAI DeBERTa v2 by default, in
the gateway process, with no network access at runtime. Another model can be dropped in by
implementing the interface (or pointing this class at another ONNX export) and compared with
the evaluation harness.

Long inputs are split into overlapping windows of the model's maximum length. A result's
score is its most suspicious window. If there are more windows than `max_windows`, the
scanner can't vouch for the rest, and says so (`complete=False`), so the result can be
withheld rather than partly unscanned.
"""

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel


@dataclass(frozen=True)
class ClassifierScore:
    probability: float  # of the injection label, in the most suspicious window
    windows: int  # windows scored
    complete: bool  # False if the text needed more windows than allowed


class InjectionClassifier(Protocol):
    name: str
    revision: str

    def score(self, text: str) -> ClassifierScore: ...


class ClassifierConfig(BaseModel):
    enabled: bool = False
    model_dir: Path = Path("models/protectai-deberta-v3-base-prompt-injection-v2/onnx")
    model_file: str = "model.int8.onnx"
    model_sha256: str = "95066b0f5017243ee7194e3f3edb32d64513394a91c1be1d75b3115f63f1570a"
    name: str = "protectai/deberta-v3-base-prompt-injection-v2"
    revision: str = "90c9989b1a342275dd0d1a95aad283c04e075671"
    injection_label: int = 1
    threshold: float = 0.5
    window_tokens: int = 510
    window_overlap: int = 64
    max_windows: int = 8
    timeout_s: float = 2.0
    threads: int = 2


class OnnxSequenceClassifier:
    def __init__(self, config: ClassifierConfig) -> None:
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer

        model = config.model_dir / config.model_file
        digest = hashlib.sha256(model.read_bytes()).hexdigest()
        if digest != config.model_sha256:
            raise ValueError(f"classifier model hash mismatch: {digest[:16]}")
        self.config, self.name, self.revision = config, config.name, config.revision
        self._np = np
        self.tokenizer = Tokenizer.from_file(str(config.model_dir / "tokenizer.json"))
        self.tokenizer.no_truncation()
        self.tokenizer.no_padding()
        cls, sep = self.tokenizer.token_to_id("[CLS]"), self.tokenizer.token_to_id("[SEP]")
        if cls is None or sep is None:
            raise ValueError("tokenizer has no [CLS]/[SEP] tokens")
        self.cls, self.sep = cls, sep
        options = ort.SessionOptions()
        options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        options.intra_op_num_threads = config.threads
        self.session = ort.InferenceSession(str(model), options, providers=["CPUExecutionProvider"])
        self.inputs = {i.name for i in self.session.get_inputs()}

    def _windows(self, text: str) -> tuple[list[list[int]], bool]:
        ids = self.tokenizer.encode(text, add_special_tokens=False).ids
        size, step = (
            self.config.window_tokens,
            self.config.window_tokens - self.config.window_overlap,
        )
        starts = list(range(0, max(len(ids), 1), step))
        complete = len(starts) <= self.config.max_windows
        starts = starts[: self.config.max_windows]
        return [[self.cls, *ids[s : s + size], self.sep] for s in starts], complete

    def score(self, text: str) -> ClassifierScore:
        np = self._np
        windows, complete = self._windows(text)
        width = max(map(len, windows))
        ids = np.array([w + [0] * (width - len(w)) for w in windows], dtype=np.int64)
        mask = np.array([[1] * len(w) + [0] * (width - len(w)) for w in windows], dtype=np.int64)
        feeds = {"input_ids": ids, "attention_mask": mask}
        if "token_type_ids" in self.inputs:
            feeds["token_type_ids"] = np.zeros_like(ids)
        logits = self.session.run(None, feeds)[0]
        exp = np.exp(logits - logits.max(axis=1, keepdims=True))
        probabilities = exp / exp.sum(axis=1, keepdims=True)
        return ClassifierScore(
            float(probabilities[:, self.config.injection_label].max()), len(windows), complete
        )


def load_classifier(config: ClassifierConfig) -> InjectionClassifier:
    return OnnxSequenceClassifier(config)
