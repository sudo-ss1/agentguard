"""The `agentguard eval` commands, with the corpus loaders replaced by placeholder markers."""

import json
import secrets

from typer.testing import CliRunner

from agentguard.cli import app
from agentguard.eval import corpora, sources
from agentguard.eval.metrics import Item

runner = CliRunner()


def markers(n: int, label: int, group: str) -> list[Item]:
    return [Item(f"MARKER-{secrets.token_hex(6)}", label, group) for _ in range(n)]


def test_scanner_prints_a_row_per_group_mode_and_label(monkeypatch, tmp_path):
    items = markers(3, 1, "a") + markers(2, 0, "a")
    monkeypatch.setattr(sources, "labelled_items", lambda: items)
    out = tmp_path / "rows.json"
    result = runner.invoke(app, ["eval", "scanner", "--out", str(out)])
    assert result.exit_code == 0, result.output
    table = [line for line in result.stdout.splitlines() if line.startswith("| a |")]
    assert len(table) == 6  # 3 modes x 2 labels
    rows = json.loads(out.read_text())["rows"]
    visible = {r["label"]: r for r in rows if r["mode"] == "visible"}
    assert visible[1]["reached"] == 3 and visible[1]["detected"] == 0  # plain markers pass
    hidden = {r["label"]: r for r in rows if r["mode"] == "hidden"}
    assert hidden[1]["reached"] == 0  # stripped before the agent


def test_scanner_rejects_an_unknown_mode(monkeypatch):
    monkeypatch.setattr(sources, "labelled_items", lambda: [])
    result = runner.invoke(app, ["eval", "scanner", "--mode", "sideways"])
    assert result.exit_code != 0


def test_fetch_runs_both_fetchers(monkeypatch, tmp_path):
    called = []
    for name in ("fetch_deepset", "fetch_garak"):
        monkeypatch.setattr(corpora, name, lambda name=name: called.append(name) or tmp_path)
    result = runner.invoke(app, ["eval", "fetch"])
    assert result.exit_code == 0, result.output
    assert called == ["fetch_deepset", "fetch_garak"]


def test_llm_rejects_an_unknown_condition():
    result = runner.invoke(app, ["eval", "llm", "--condition", "sideways"])
    assert result.exit_code != 0
    assert "unknown condition" in result.output
