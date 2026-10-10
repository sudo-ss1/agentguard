"""Read receipts back for the harness and tests: one record per call, as in Phase 4.

A ledger stores an allowed call as two receipts: a decision receipt, written before the call is
forwarded, and an outcome receipt (upstream_error, result_scan) after. `calls()` merges each
outcome into its decision, so callers see one flat record per call with the Phase 4 fields.
Phase 4 unsigned logs (flat JSON lines) are read as they are.

This module doesn't verify anything: use ledger.verify for that.
"""

import json
from pathlib import Path
from typing import Any

from agentguard.ledger.canonical import LINE_KEYS

# Body fields that belong to the ledger's structure, not to the call.
STRUCTURAL = frozenset({"v", "ledger_id", "prev", "kind"})
OUTCOME_FIELDS = ("upstream_error", "result_scan")


def line_count(path: Path | None) -> int:
    """Complete lines in the log: a position to read from later with `calls(path, start)`."""
    if path is None or not path.exists():
        return 0
    data = path.read_bytes()
    return data[: data.rfind(b"\n") + 1].count(b"\n")


def _rows(path: Path, start: int, end: int | None) -> list[dict[str, Any]]:
    data = path.read_bytes()
    lines = data[: data.rfind(b"\n") + 1].splitlines()[start:end]
    return [json.loads(line) for line in lines if line.strip()]


def is_ledger_line(row: dict[str, Any]) -> bool:
    return set(row) == LINE_KEYS and isinstance(row.get("body"), dict)


def calls(path: Path | None, start: int = 0, end: int | None = None) -> list[dict[str, Any]]:
    """One record per call in lines [start, end): decision fields, plus the outcome's fields
    when its outcome receipt is in range (`outcome` is "unknown" for an allowed call without
    one)."""
    if path is None or not path.exists():
        return []
    out: list[dict[str, Any]] = []
    by_seq: dict[int, dict[str, Any]] = {}
    for row in _rows(path, start, end):
        if not is_ledger_line(row):
            out.append(row)  # a Phase 4 unsigned receipt
            continue
        body = row["body"]
        if body.get("kind") == "decision":
            record = {k: v for k, v in body.items() if k not in STRUCTURAL}
            if record.get("decision") == "allow":
                record["outcome"] = "unknown"
            by_seq[body["seq"]] = record
            out.append(record)
        elif body.get("kind") == "outcome":
            decided = by_seq.get(body.get("decision_seq", -1))
            if decided is not None:
                decided["outcome"] = "recorded"
                for name in OUTCOME_FIELDS:
                    if name in body:
                        decided[name] = body[name]
    return out


def last_receipt(path: Path | None, kind: str) -> dict[str, Any] | None:
    """The body of the last ledger receipt of `kind`, or None."""
    if path is None or not path.exists():
        return None
    data = path.read_bytes()
    for line in reversed(data[: data.rfind(b"\n") + 1].splitlines()):
        if not line.strip():
            continue
        row = json.loads(line)
        if is_ledger_line(row) and row["body"].get("kind") == kind:
            return dict(row["body"])
    return None


def receipt_at(path: Path, line: int) -> dict[str, Any]:
    """The receipt on a 1-based line, as `grep -n` shows it: its body, for a ledger line."""
    for i, text in enumerate(path.read_text().splitlines(), 1):
        if i == line:
            row = json.loads(text)
            return dict(row["body"]) if is_ledger_line(row) else dict(row)
    raise IndexError(f"{path} has no line {line}")
