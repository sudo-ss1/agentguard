"""Control receipts (Phase 6): every change to the kill list goes into the signed ledger.

The kill list (guards/state.py) is a file that the CLI, the lab harness and the gateway's own
budget guard all write. The gateway is the ledger's only writer, so it records the changes it
observes. One `control` receipt per change:

    {"action": "kill-list",
     "change": "kill" | "revive" | "reset" | "startup-diff" (a hand edit while stopped) | "unknown",
     "by": "cli:alice" | "gateway:budget" | "unknown",
     "added": {"dids": [...], "names": [...], "revocation_ids": [...]},
     "removed": {...},
     "reasons": {"dids/did:key:z...": {"category": "manual" | "budget" | "unknown",
                                       "reason": {"commitment": "..."}}},
     "state": {"dids": [...], "names": [...], "revocation_ids": [...]},
     "digest": "<sha256 of the whole list>", "while_stopped": false}

- Ids are public identifiers, in the clear. A kill's category is in the clear and its free-text
  reason a salted commitment (receipt option C), the same as in kill-switch denial receipts.
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
        last = last_receipt(ledger_path, "control", action="kill-list")
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
            f"{k}/{i}": (str(entry.get("category", "unknown")), str(entry.get("reason", "")))
            for k in KINDS
            for i in added[k]
            if isinstance(entry := new[k][i], dict)
        }
        if change.get("action"):
            what = str(change["action"])
        else:  # a hand edit: no write recorded what it was
            what = "startup-diff" if while_stopped else "unknown"
        return self.receipts.control(
            {
                "action": "kill-list",
                "change": what,
                "by": str(change.get("by", "unknown")),
                "added": added,
                "removed": removed,
                "state": ids(new),
                "digest": digest(new),
                "while_stopped": while_stopped,
            },
            reasons=reasons,
        )


class PinRecorder:
    """Pins and quarantines, recorded like the kill list:

        {"action": "pins", "change": "pin" | "quarantine" | "pin+quarantine" | "startup-diff",
         "by": "gateway:pins" | "unknown",
         "added": {"pins": ["server/tool", ...], "quarantined": ["server", ...]},
         "removed": {...}, "changed": {"pins": [...]},
         "state": {"pins": {"server/tool": "<description hash>"},
                   "quarantined": {"server": "<why>"}},
         "digest": "...", "while_stopped": false}

    Description hashes and the gateway's quarantine reasons are its own output, so they are in
    the clear. A change while stopped is a hand edit of the pins file (the documented way to
    re-approve a server), so its author is unknown.
    """

    def __init__(self, receipts: Any) -> None:
        self.receipts = receipts

    @staticmethod
    def digest(snapshot: dict[str, Any]) -> str:
        return hashlib.sha256(
            jcs({k: snapshot.get(k, {}) for k in ("pins", "quarantined")})
        ).hexdigest()

    def startup(self, ledger_path: Any, snapshot: dict[str, Any]) -> int | None:
        last = last_receipt(ledger_path, "control", action="pins")
        empty: dict[str, Any] = {"pins": {}, "quarantined": {}}
        previous = last.get("state", empty) if last else empty
        if self.digest(snapshot) == (last.get("digest") if last else self.digest(empty)):
            return None
        return self.record(previous, snapshot, while_stopped=True)

    def observed(self, old: dict[str, Any], new: dict[str, Any]) -> None:
        self.record(old, new, while_stopped=False)

    def record(self, old: dict[str, Any], new: dict[str, Any], *, while_stopped: bool) -> int:
        added = {k: sorted(set(new[k]) - set(old.get(k, {}))) for k in ("pins", "quarantined")}
        removed = {k: sorted(set(old.get(k, {})) - set(new[k])) for k in ("pins", "quarantined")}
        changed = sorted(
            p for p in new["pins"] if p in old.get("pins", {}) and old["pins"][p] != new["pins"][p]
        )
        if while_stopped:
            change = "startup-diff"
        else:
            change = (
                "+".join(
                    name
                    for name, keys in (("pin", added["pins"]), ("quarantine", added["quarantined"]))
                    if keys
                )
                or "update"
            )
        return self.receipts.control(
            {
                "action": "pins",
                "change": change,
                "by": "unknown" if while_stopped else "gateway:pins",
                "added": added,
                "removed": removed,
                "changed": {"pins": changed},
                "state": {"pins": dict(new["pins"]), "quarantined": dict(new["quarantined"])},
                "digest": self.digest(new),
                "while_stopped": while_stopped,
            },
            reasons={},
        )
