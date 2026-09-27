"""Salted commitments for sensitive values in receipts (Phase 3 receipt option C).

A committed value is recorded in a receipt only as a digest, in the style of SD-JWT
disclosures (RFC 9901): the disclosure is [salt, attribute name, value] in RFC 8785 canonical
JSON, and the digest is base64url(SHA-256(base64url(disclosure))). Each value gets its own
random 128-bit salt, kept in a `SaltStore`, a separate file the receipt log never contains.

- Proving a value: whoever holds the salt can show a digest commits to exactly that value.
- Without the salt, the digest reveals nothing useful: guessing likely values (common email
  addresses, paths) doesn't help, because each guess would also need the 128-bit salt.
- Erasing a value: delete its salt. The receipt keeps its digest, unchanged, but nobody can
  recover or prove the value any more. Phase 5 hash-chains receipts, and this leaves the chain
  intact.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
from pathlib import Path
from typing import Any

import rfc8785

SALT_BYTES = 16  # 128 bits, as SD-JWT recommends


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def digest(salt: str, name: str, value: Any) -> str:
    disclosure = _b64u(rfc8785.dumps([salt, name, value]))
    return _b64u(hashlib.sha256(disclosure.encode("ascii")).digest())


def matches(commitment: str, name: str, value: Any, salt: str) -> bool:
    return hmac.compare_digest(commitment, digest(salt, name, value))


class SaltStore:
    """digest -> salt, as JSON lines in a file readable by its owner only."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def commit(self, name: str, value: Any) -> str:
        salt = _b64u(secrets.token_bytes(SALT_BYTES))
        commitment = digest(salt, name, value)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a") as f:
                f.write(json.dumps({"digest": commitment, "salt": salt}) + "\n")
        return commitment

    def salt_for(self, commitment: str) -> str | None:
        if not self.path.exists():
            return None
        for line in self.path.read_text().splitlines():
            entry = json.loads(line)
            if entry["digest"] == commitment:
                return str(entry["salt"])
        return None

    def forget(self, commitment: str) -> bool:
        """Delete a salt (crypto-shredding). True if one was removed."""
        with self._lock:
            if not self.path.exists():
                return False
            lines = self.path.read_text().splitlines()
            kept = [line for line in lines if json.loads(line)["digest"] != commitment]
            self.path.write_text("".join(line + "\n" for line in kept))
            return len(kept) < len(lines)
