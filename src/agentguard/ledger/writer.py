"""The gateway's single ledger writer.

Receipts are appended to a JSON-lines file, each a signed, canonical line (canonical.py) whose
body carries `seq` and `prev`, the hash of the receipt before it. The first receipt is a
`genesis` receipt naming the signing key.

Ordering: one `Ledger` per file. It takes an exclusive `flock` at start, so a second process
can't open the same ledger, and appends under a lock with no awaits inside, so parallel calls
still produce one gap-free sequence: the order receipts were written.

Durability:
- batched (default): each line is written with one `write` (O_APPEND); a background thread
  fsyncs every `fsync_interval_s`, and before every checkpoint. A process crash loses nothing
  already written. An OS crash can lose the last receipts, including the decision receipt of a
  call already forwarded.
- strict: every receipt except outcome receipts is fsynced before `append` returns, so a
  decision receipt is durable before its call is forwarded. Outcome receipts follow the batched
  schedule; an OS crash can lose one, which verify then reports as "outcome unknown". It costs
  one fsync per call (~6 ms p50 here).

Checkpoints: every `checkpoint_interval_s`, and on close, a signed checkpoint goes to
`<roots_dir>/checkpoints.jsonl`: the ledger size, the head hash, the RFC 9162 Merkle root of the
receipts since the previous checkpoint, and the previous checkpoint's hash. The ledger is
fsynced before each checkpoint is written, so a checkpoint never covers receipts that aren't on
disk.

Starting up, in this order:
1. Torn tail. Bytes after the last newline (only those, never a complete line, even an invalid
   one) are moved aside to `<ledger>.torn-<time>.bin` and cut from the ledger. A signed
   `recovery` receipt records their length and SHA-256.
2. The last complete receipt must verify under this key; otherwise the ledger may have been
   tampered with and the gateway refuses to extend it.
3. The ledger must agree with the latest checkpoint: at least its size, and the receipt at that
   position must have the checkpoint's head hash. Otherwise receipts are missing or were
   replaced, and the gateway refuses to start.
"""

import fcntl
import hashlib
import os
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from agentguard.identity.didkey import AgentKey
from agentguard.ledger import merkle
from agentguard.ledger.canonical import (
    CHECKPOINT_TAG,
    FORMAT_VERSION,
    GENESIS_PREV,
    RECEIPT_TAG,
    LineError,
    body_hash,
    parse_line,
    seal,
    signature_valid,
)

CHECKPOINTS_FILE = "checkpoints.jsonl"
Durability = Literal["batched", "strict"]


class LedgerError(RuntimeError):
    """The ledger can't be opened or extended safely."""


@dataclass(frozen=True)
class Recovery:
    moved_to: Path
    length: int
    sha256: str


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def _append_synced(path: Path, line: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        _write_all(fd, line)
        os.fsync(fd)
    finally:
        os.close(fd)


def read_checkpoints(path: Path) -> list[dict[str, Any]]:
    """Every complete checkpoint line, parsed (unverified)."""
    if not path.exists():
        return []
    data = path.read_bytes()
    complete = data[: data.rfind(b"\n") + 1]
    return [parse_line(line) for line in complete.splitlines() if line]


class Ledger:
    def __init__(
        self,
        path: Path,
        key: AgentKey,
        roots_dir: Path,
        *,
        durability: Durability = "batched",
        fsync_interval_s: float = 0.1,
        checkpoint_interval_s: float = 60.0,
    ) -> None:
        self.path = path
        self.key = key
        self.durability = durability
        self.checkpoints_path = roots_dir / CHECKPOINTS_FILE
        roots_dir.mkdir(parents=True, exist_ok=True)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self._fd)
            raise LedgerError(f"another process has {path} open for writing") from None
        self._lock = threading.Lock()
        self._checkpoint_lock = threading.Lock()
        self._stop = threading.Event()
        self._dirty = False
        self._failed: str | None = None
        self._closed = False
        try:
            self.recovery = self._recover_torn_tail()
            hashes, ledger_id = self._load()
            self.ledger_id = ledger_id or os.urandom(16).hex()
            self.seq = len(hashes) - 1
            self.head = hashes[-1] if hashes else GENESIS_PREV
            self._checkpoint_size, self._last_checkpoint = self._check_against_checkpoint(hashes)
            self._pending = hashes[self._checkpoint_size :]
            if not hashes:
                self.append("genesis", {"key": key.did})
            if self.recovery:
                self.append(
                    "recovery",
                    {
                        "torn_bytes": self.recovery.length,
                        "torn_sha256": self.recovery.sha256,
                        "moved_to": self.recovery.moved_to.name,
                    },
                )
        except BaseException:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
            raise
        self._threads = [
            threading.Thread(target=self._every, args=(fsync_interval_s, self._fsync), daemon=True),
            threading.Thread(
                target=self._every, args=(checkpoint_interval_s, self.checkpoint), daemon=True
            ),
        ]
        for t in self._threads:
            t.start()

    # --- startup -------------------------------------------------------------------------

    def _recover_torn_tail(self) -> Recovery | None:
        data = self.path.read_bytes()
        cut = data.rfind(b"\n") + 1  # 0 if there is no newline at all
        if cut == len(data):
            return None
        torn = data[cut:]
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        moved_to = self.path.with_name(f"{self.path.name}.torn-{stamp}.bin")
        fd = os.open(moved_to, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            _write_all(fd, torn)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.truncate(self.path, cut)  # only the bytes after the last newline
        os.fsync(self._fd)
        return Recovery(moved_to, len(torn), hashlib.sha256(torn).hexdigest())

    def _load(self) -> tuple[list[str], str | None]:
        """The stored hash of every receipt, and the ledger id. Checks the last receipt."""
        hashes: list[str] = []
        last: dict[str, Any] = {}
        with self.path.open("rb") as f:
            for number, raw in enumerate(f, 1):
                try:
                    last = parse_line(raw)
                except LineError as exc:  # never repaired: a complete line is evidence
                    raise LedgerError(
                        f"line {number} of {self.path} is malformed ({exc}); refusing to extend "
                        "the ledger. Run `agentguard ledger verify`."
                    ) from exc
                hashes.append(last["hash"])
        if not hashes:
            return [], None
        body = last["body"]
        ok = (
            body_hash(body) == last["hash"]
            and signature_valid(self.key.public_key, RECEIPT_TAG, last["hash"], last["sig"])
            and body.get("seq") == len(hashes) - 1
        )
        if not ok:
            raise LedgerError(
                f"the last receipt (line {len(hashes)}) does not verify under this gateway's key; "
                "refusing to extend the ledger. Run `agentguard ledger verify`."
            )
        return hashes, str(body["ledger_id"])

    def _check_against_checkpoint(self, hashes: list[str]) -> tuple[int, str]:
        checkpoints = read_checkpoints(self.checkpoints_path)
        if not checkpoints:
            return 0, GENESIS_PREV
        latest = checkpoints[-1]
        body = latest["body"]
        if not (
            body_hash(body) == latest["hash"]
            and signature_valid(self.key.public_key, CHECKPOINT_TAG, latest["hash"], latest["sig"])
        ):
            raise LedgerError("the latest checkpoint does not verify under this gateway's key")
        size = int(body["size"])
        if len(hashes) < size:
            raise LedgerError(
                f"the ledger has {len(hashes)} receipts but checkpoint {latest['hash'][:12]} "
                f"covers {size}: receipts are missing. Run `agentguard ledger verify`."
            )
        if body["ledger_id"] != self.ledger_id:
            raise LedgerError("the latest checkpoint belongs to a different ledger")
        if hashes[size - 1] != body["head"]:
            raise LedgerError(
                f"receipt {size - 1} does not match the latest checkpoint's head: the ledger was "
                "changed. Run `agentguard ledger verify`."
            )
        return size, str(latest["hash"])

    # --- writing -------------------------------------------------------------------------

    def append(self, kind: str, fields: dict[str, Any]) -> tuple[int, str]:
        """Sign and append one receipt. Returns (seq, hash). Raises if it can't be recorded."""
        with self._lock:
            if self._closed:
                raise LedgerError("the ledger is closed")
            if self._failed:
                raise LedgerError(f"the ledger stopped accepting receipts: {self._failed}")
            body = {
                "v": FORMAT_VERSION,
                "ledger_id": self.ledger_id,
                "seq": self.seq + 1,
                "prev": self.head,
                "kind": kind,
                "ts": _now(),
                **fields,
            }
            line, h = seal(self.key.signing_key, RECEIPT_TAG, body)  # raises before any write
            try:
                _write_all(self._fd, line)
                if self.durability == "strict" and kind != "outcome":
                    os.fsync(self._fd)
            except OSError as exc:
                # A partial line may be on disk. Accept nothing more until a restart recovers it.
                self._failed = f"{type(exc).__name__}: {exc}"
                raise LedgerError(f"could not write a receipt: {self._failed}") from exc
            self.seq += 1
            self.head = h
            self._pending.append(h)
            self._dirty = True
            return self.seq, h

    def _fsync(self) -> None:
        if self._dirty:
            self._dirty = False
            os.fsync(self._fd)

    def checkpoint(self) -> str | None:
        """Write a signed checkpoint if there are receipts since the last one. Returns its
        hash."""
        with self._checkpoint_lock:
            with self._lock:
                if not self._pending:
                    return None
                pending, size, head = list(self._pending), self.seq + 1, self.head
            os.fsync(self._fd)  # everything the checkpoint covers is on disk first
            body = {
                "v": FORMAT_VERSION,
                "kind": "checkpoint",
                "ledger_id": self.ledger_id,
                "start": self._checkpoint_size,
                "size": size,
                "head": head,
                "batch_root": merkle.root_hex(pending),
                "prev_checkpoint": self._last_checkpoint,
                "ts": _now(),
                "key": self.key.did,
            }
            line, h = seal(self.key.signing_key, CHECKPOINT_TAG, body)
            _append_synced(self.checkpoints_path, line)
            with self._lock:
                del self._pending[: len(pending)]
            self._checkpoint_size, self._last_checkpoint = size, h
            return h

    def _every(self, interval: float, action: Any) -> None:
        while not self._stop.wait(interval):
            try:
                action()
            except Exception:  # keep going; the next round retries
                time.sleep(interval)

    def close(self) -> None:
        if self._closed:
            return
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5)
        try:
            if not self._failed:
                self.checkpoint()
            os.fsync(self._fd)
        finally:
            with self._lock:
                self._closed = True
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
