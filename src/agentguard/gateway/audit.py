"""Audit helpers for receipt commitments: prove a committed value, or erase it."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from agentguard.gateway.commitments import SaltStore, matches


@dataclass(frozen=True)
class Proof:
    status: Literal["proven", "mismatch", "salt-deleted", "not-committed"]
    detail: str


def commitment_in(receipt: dict[str, Any], attribute: str) -> str | None:
    if attribute == "upstream_error":
        error = receipt.get("upstream_error")
        message = error.get("message") if isinstance(error, dict) else None
        return message.get("commitment") if isinstance(message, dict) else None
    value = receipt.get("reason", {}).get("attributes", {}).get(attribute)
    return value.get("commitment") if isinstance(value, dict) else None


def prove(receipt: dict[str, Any], attribute: str, value: Any, salts: SaltStore) -> Proof:
    """Does this receipt commit `attribute` to exactly `value`? Needs the salt."""
    commitment = commitment_in(receipt, attribute)
    if commitment is None:
        return Proof("not-committed", f"the receipt has no commitment for {attribute!r}")
    salt = salts.salt_for(commitment)
    if salt is None:
        return Proof("salt-deleted", "the salt is gone: the value can no longer be proven")
    if matches(commitment, attribute, value, salt):
        return Proof("proven", f"the receipt commits {attribute} to {value!r}")
    return Proof("mismatch", f"the receipt does not commit {attribute} to {value!r}")


def read_receipt(receipts: Path, line: int) -> dict[str, Any]:
    """1-based line number, as `grep -n` or an editor would show it."""
    for i, text in enumerate(receipts.read_text().splitlines(), 1):
        if i == line:
            return dict(json.loads(text))
    raise IndexError(f"{receipts} has no line {line}")
