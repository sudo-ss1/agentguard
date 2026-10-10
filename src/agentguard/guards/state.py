"""Gateway-local guard state: the kill list, and a reset epoch for in-memory guard state.

Tokens verify offline, so stopping an agent can't wait for the identity service or for its
token to expire. The kill list lives next to the gateway, is checked right after identity,
and overrides any still-valid token. It holds:

- agent DIDs and names
- Biscuit revocation ids: the id of the last block of each token a killed agent presented

For a root token, the last block is its authority block, so killing an agent also kills every
token delegated from it. For a delegated token, it is the delegation block, so killing a
sub-agent leaves its parent alone.

The list is a JSON file. The gateway re-reads it whenever it changes (a stat per call), so a
kill from the CLI (`agentguard kill`) takes effect on the next call and survives restarts. A
CAEP / Shared Signals receiver would be one more writer of this file.

`agentguard guards reset` bumps an epoch file. The gateway then drops its in-memory guard
state (budgets, taint) and reloads the kill list. The lab harness uses this between scenarios.

Every change to the list is audited (Phase 6): each write records who made it (`by`, e.g.
`cli:alice` or `gateway:budget`) and what it was (`last_change`), and the gateway writes a
signed `control` receipt when it sees the list change (gateway/control.py). A hand edit has no
`last_change` of its own, so its receipt says the author is unknown.
"""

import json
import os
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


KINDS = ("dids", "names", "revocation_ids")
KillList = dict[str, dict[str, dict[str, Any]]]  # kind -> id -> {reason, at, by}


class GuardState:
    def __init__(self, state_dir: Path) -> None:
        self.dir = state_dir
        self.dir.mkdir(parents=True, exist_ok=True)
        self.kill_path = self.dir / "killed.json"
        self.seen_path = self.dir / "seen.json"
        self.epoch_path = self.dir / "epoch"
        self._lock = threading.Lock()
        self._kill_sig: tuple[int, int] | None = None
        self._epoch_sig: tuple[int, int] | None = self._sig(self.epoch_path)
        self._killed: KillList = {k: {} for k in KINDS}
        self._last_change: dict[str, Any] | None = None
        self._on_kill_list_change: list[Callable[[KillList, KillList], None]] = []
        self._seen: dict[str, dict[str, Any]] = (
            json.loads(self.seen_path.read_text()) if self.seen_path.exists() else {}
        )
        self._on_reset: list[Callable[[], None]] = []
        self.refresh()

    @staticmethod
    def _sig(path: Path) -> tuple[int, int] | None:
        try:
            st = path.stat()
        except FileNotFoundError:
            return None
        return (st.st_mtime_ns, st.st_size)

    def on_reset(self, callback: Callable[[], None]) -> None:
        self._on_reset.append(callback)

    def on_kill_list_change(self, callback: Callable[[KillList, KillList], None]) -> None:
        """`callback(old, new)` runs whenever a refresh finds the list's content changed."""
        self._on_kill_list_change.append(callback)

    def kill_list(self) -> KillList:
        return {k: dict(v) for k, v in self._killed.items()}

    @property
    def last_change(self) -> dict[str, Any] | None:
        """{action, by, at} of the write that produced the current file, if it recorded one."""
        return self._last_change

    def refresh(self) -> None:
        """Reload the kill list if it changed; clear in-memory state if the epoch moved."""
        epoch = self._sig(self.epoch_path)
        if epoch != self._epoch_sig:
            self._epoch_sig = epoch
            for callback in self._on_reset:
                callback()
        sig = self._sig(self.kill_path)
        if sig != self._kill_sig:
            self._kill_sig = sig
            data = json.loads(self.kill_path.read_text()) if sig else {}
            old = self._killed
            self._killed = {k: dict(data.get(k, {})) for k in KINDS}
            change = data.get("last_change")
            self._last_change = change if isinstance(change, dict) else None
            if self._killed != old:
                for observer in self._on_kill_list_change:
                    observer(old, self.kill_list())

    # --- what the gateway records and checks ----------------------------------------------------

    def record_token(self, did: str, name: str, last_block_revocation_id: str) -> None:
        """Remember which token (by its last block) an agent presented, so a kill by DID or
        name can also revoke it."""
        entry = self._seen.setdefault(did, {"name": name, "revocation_ids": []})
        if last_block_revocation_id not in entry["revocation_ids"]:
            with self._lock:
                entry["revocation_ids"].append(last_block_revocation_id)
                entry["name"] = name
                self.seen_path.write_text(json.dumps(self._seen, indent=2, sort_keys=True))

    def killed_reason(self, did: str, name: str, revocation_ids: list[str]) -> str | None:
        self.refresh()
        for kind, key in (("dids", did), ("names", name)):
            if key in self._killed[kind]:
                return str(self._killed[kind][key]["reason"])
        for rid in revocation_ids:
            if rid in self._killed["revocation_ids"]:
                return str(self._killed["revocation_ids"][rid]["reason"])
        return None

    # --- operations (gateway budget trips, and the CLI) --------------------------------------

    def kill(
        self, reason: str, did: str | None = None, name: str | None = None, by: str = "unknown"
    ) -> list[str]:
        """Kill by DID or name. Returns the DIDs affected."""
        with self._lock:
            data = self._load_kill_file()
            stamp = {"reason": reason, "at": _now(), "by": by}
            dids = [did] if did else [d for d, e in self._seen.items() if e.get("name") == name]
            if name:
                data["names"][name] = stamp
            for d in dids:
                data["dids"][d] = stamp
                for rid in self._seen.get(d, {}).get("revocation_ids", []):
                    data["revocation_ids"][rid] = stamp
            self._write_kill_file(data, "kill", by)
        self.refresh()
        return dids

    def revive(self, did: str | None = None, name: str | None = None, by: str = "unknown") -> None:
        with self._lock:
            data = self._load_kill_file()
            dids = [did] if did else [d for d, e in self._seen.items() if e.get("name") == name]
            if name:
                data["names"].pop(name, None)
            for d in dids:
                data["dids"].pop(d, None)
                for rid in self._seen.get(d, {}).get("revocation_ids", []):
                    data["revocation_ids"].pop(rid, None)
            self._write_kill_file(data, "revive", by)
        self.refresh()

    def reset(self, by: str = "unknown") -> None:
        """Revive everyone and clear in-memory guard state (budgets, taint) in the gateway."""
        with self._lock:
            self._write_kill_file({k: {} for k in KINDS}, "reset", by)
            self.epoch_path.write_text(_now() + f" {os.getpid()} {os.urandom(4).hex()}\n")
        self.refresh()

    def _load_kill_file(self) -> KillList:
        data = json.loads(self.kill_path.read_text()) if self.kill_path.exists() else {}
        return {k: dict(data.get(k, {})) for k in KINDS}

    def _write_kill_file(self, data: KillList, action: str, by: str) -> None:
        body: dict[str, Any] = {**data, "last_change": {"action": action, "by": by, "at": _now()}}
        tmp = self.kill_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(body, indent=2, sort_keys=True))
        tmp.replace(self.kill_path)  # atomic: the gateway never reads a half-written list
