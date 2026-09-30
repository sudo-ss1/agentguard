"""The evaluation corpora: fetched at pinned versions, hash-checked, kept out of git.

- deepset/prompt-injections, test split, at a pinned dataset revision.
- garak's latent-injection probe prompts. Generated from garak's pinned source by
  eval/garak_extract.py, in a throwaway environment with light dependencies only (garak's full
  install pulls in PyTorch). The result must hash to the locked value.

`agentguard eval fetch` writes eval/data/. Loading refuses data that doesn't match the lock.
"""

import hashlib
import json
import os
import subprocess
import tarfile
from pathlib import Path
from typing import Any

import httpx

REPO = Path(__file__).resolve().parents[3]
LOCK = REPO / "eval" / "corpora.lock.json"
DATA = REPO / "eval" / "data"
DEEPSET_JSON = DATA / "deepset_test.json"
GARAK_JSON = DATA / "garak_latentinjection.json"
# garak's probe module imports only light packages; these are enough to generate its prompts.
GARAK_LIGHT_DEPS = [
    "colorama",
    "tqdm",
    "pyyaml",
    "toml",
    "jinja2",
    "requests",
    "lorem",
    "nltk",
    "xdg-base-dirs",
    "jsonschema",
    "langdetect",
]


def lock() -> dict[str, Any]:
    return dict(json.loads(LOCK.read_text()))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _check(path: Path, expected: str, what: str) -> None:
    actual = _sha256(path)
    if actual != expected:
        raise ValueError(f"{what}: sha256 {actual[:16]}… does not match the lock {expected[:16]}…")


def fetch_deepset() -> Path:
    import pyarrow.parquet as pq
    from huggingface_hub import hf_hub_download

    pin = lock()["deepset"]
    parquet = Path(
        hf_hub_download(pin["repo"], pin["file"], repo_type="dataset", revision=pin["revision"])
    )
    _check(parquet, pin["sha256"], "deepset test split")
    rows = pq.read_table(parquet).to_pylist()
    DATA.mkdir(parents=True, exist_ok=True)
    DEEPSET_JSON.write_text(json.dumps({"lock": pin, "rows": rows}, ensure_ascii=False))
    return DEEPSET_JSON


def fetch_garak() -> Path:
    pin = lock()["garak"]
    DATA.mkdir(parents=True, exist_ok=True)
    tarball = DATA / "garak-source.tar.gz"
    with httpx.stream("GET", pin["source"], follow_redirects=True, timeout=120) as response:
        response.raise_for_status()
        with tarball.open("wb") as f:
            for chunk in response.iter_bytes():
                f.write(chunk)
    _check(tarball, pin["tarball_sha256"], "garak source")
    source = DATA / "garak-source"
    with tarfile.open(tarball) as archive:
        archive.extractall(source, filter="data")
    (src_dir,) = [p for p in source.iterdir() if p.is_dir()]
    command = ["uv", "run", "--no-project", "--python", "3.12"]
    for dep in GARAK_LIGHT_DEPS:
        command += ["--with", dep]
    command += ["python", str(REPO / "eval" / "garak_extract.py"), str(src_dir), str(GARAK_JSON)]
    subprocess.run(
        command,
        check=True,
        cwd=DATA,
        capture_output=True,
        env={**os.environ, "PYTHONHASHSEED": "0"},
    )
    _check(GARAK_JSON, pin["extraction_sha256"], "garak latent-injection prompts")
    return GARAK_JSON


def load_deepset() -> list[dict[str, Any]]:
    if not DEEPSET_JSON.exists():
        raise FileNotFoundError("run `agentguard eval fetch` first")
    body = json.loads(DEEPSET_JSON.read_text())
    if body["lock"] != lock()["deepset"]:
        raise ValueError("eval/data/deepset_test.json was fetched under a different lock")
    return list(body["rows"])


def load_garak() -> dict[str, list[dict[str, str]]]:
    if not GARAK_JSON.exists():
        raise FileNotFoundError("run `agentguard eval fetch` first")
    _check(GARAK_JSON, lock()["garak"]["extraction_sha256"], "garak latent-injection prompts")
    return dict(json.loads(GARAK_JSON.read_text()))
