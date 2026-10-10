"""Control receipts (Phase 6): every change to the kill list goes into the signed ledger.

The kill list (guards/state.py) is a file that the CLI, the lab harness and the gateway's own
budget guard all write. The gateway is the ledger's only writer, so it records the changes it
observes. One `control` receipt per change:

    {"action": "kill-list", "change": "kill" | "revive" | "reset" | "unknown",
     "by": "cli:alice" | "gateway:budget" | "unknown",
     "added": {"dids": [...], "names": [...], "revocation_ids": [...]},
     "removed": {...},
     "reasons": {"dids/did:key:z...": {"commitment": "..."}},
     "state": {"dids": [...], "names": [...], "revocation_ids": [...]},
     "digest": "<sha256 of the whole list>", "while_stopped": false}

- Ids are public identifiers, in the clear. A kill's free-text reason is a salted commitment
  (receipt option C), as the approved design says.
- `change` and `by` come from the write itself (`last_change`). A hand edit has none: unknown.
- A receipt records the net change since the gateway last looked. Several writes between two
  looks (or while it was stopped) become one receipt, named after the last write.

At startup the gateway compares the list's digest with the last control receipt in the ledger.
If they differ, the list changed while it was stopped: that change is recorded, with
`while_stopped: true`, before the gateway serves any call. No receipt and an empty list agree.
Recording fails closed: the ledger then refuses every later receipt, so no call is made.
"""

import hashlib
from typing import Any

from agentguard.guards.state import KINDS, GuardState, KillList
from agentguard.ledger.canonical import jcs
from agentguard.ledger.read import last_receipt

EMPTY: KillList = {k: {} for k in KINDS}


def digest(kill_list: KillList) -> str:
    return hashlib.sha256(jcs({k: kill_list.get(k, {}) for k in KINDS})).hexdigest()


def ids(kill_list: KillList) -> dict[str, list[str]]:
    return {k: sorted(kill_list.get(k, {})) for k in KINDS}


class ControlRecorder:
    def __init__(self, receipts: Any, state: GuardState) -> None:
        self.receipts, self.state = receipts, state

    def startup(self, ledger_path: Any) -> int | None:
        """Record a change made while the gateway was stopped. Returns the receipt's seq."""
        current = self.state.kill_list()
        last = last_receipt(ledger_path, "control")
        recorded = last.get("digest") if last else digest(EMPTY)
        if digest(current) == recorded:
            return None
        before: dict[str, list[str]] = last.get("state", {}) if last else ids(EMPTY)
        previous: KillList = {k: dict.fromkeys(before.get(k, []), {}) for k in KINDS}
        return self.record(previous, current, while_stopped=True)

    def observed(self, old: KillList, new: KillList) -> None:
        """GuardState callback: the running gateway saw the list change."""
        self.record(old, new, while_stopped=False)

    def record(self, old: KillList, new: KillList, *, while_stopped: bool) -> int:
        change = self.state.last_change or {}
        added = {k: sorted(set(new.get(k, {})) - set(old.get(k, {}))) for k in KINDS}
        removed = {k: sorted(set(old.get(k, {})) - set(new.get(k, {}))) for k in KINDS}
        reasons = {
            f"{k}/{i}": new[k][i].get("reason", "")
            for k in KINDS
            for i in added[k]
            if isinstance(new[k][i], dict)
        }
        return self.receipts.control(
            {
                "action": "kill-list",
                "change": str(change.get("action", "unknown")),
                "by": str(change.get("by", "unknown")),
                "added": added,
                "removed": removed,
                "state": ids(new),
                "digest": digest(new),
                "while_stopped": while_stopped,
            },
            committed=reasons,
        )
