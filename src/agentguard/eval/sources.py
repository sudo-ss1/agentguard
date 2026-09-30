"""Evaluation inputs, built from the pinned corpora at runtime (see corpora.py).

Nothing here is corpus data: the texts are read from eval/data/, which is hash-checked against
eval/corpora.lock.json and kept out of git.

- `labelled_items()`: every deepset test row (labelled 0 or 1) and every garak prompt (all
  labelled 1; garak has no negatives), for the scanner evaluation.
- `cases()`: the garak prompts with their target strings, for the agent trials.
"""

from pathlib import Path

import yaml

from agentguard.eval import corpora
from agentguard.eval.metrics import Item, ScanFn
from agentguard.eval.trials import Case

DEEPSET_GROUP = "deepset"
GARAK_PREFIX = "garak:"
GATEWAY_CONFIG = corpora.REPO / "config" / "gateway.yaml"


def labelled_items() -> list[Item]:
    items = [Item(r["text"], int(r["label"]), DEEPSET_GROUP) for r in corpora.load_deepset()]
    for probe, prompts in sorted(corpora.load_garak().items()):
        items += [Item(p["prompt"], 1, GARAK_PREFIX + probe) for p in prompts]
    return items


def cases() -> list[Case]:
    """garak prompts with a non-empty target, numbered in a stable order."""
    out: list[Case] = []
    for probe, prompts in sorted(corpora.load_garak().items()):
        for p in prompts:
            if p["trigger"].strip():
                out.append(Case(len(out), GARAK_PREFIX + probe, p["prompt"], p["trigger"]))
    return out


def gateway_tool_names(path: Path = GATEWAY_CONFIG) -> set[str]:
    """The tool names the gateway allowlists, as the gateway gives them to its scanner."""
    config = yaml.safe_load(path.read_text())
    return {t for agent in config["agents"].values() for t in agent["tools"]}


def gateway_scan(classifier: bool = False) -> ScanFn:
    """The gateway's result scanner as a ScanFn, scanning a fetch_url result."""
    from agentguard.guards.classifier import ClassifierConfig
    from agentguard.guards.result_scan import InjectionConfig, ResultScanner

    config = InjectionConfig(classifier=ClassifierConfig(enabled=classifier))
    scanner = ResultScanner(config, gateway_tool_names())

    def scan(page: str) -> tuple[str, bool, bool]:
        visible, result = scanner.scan("fetch_url", None, [page])
        return visible[0], result.taint, result.withhold

    return scan
