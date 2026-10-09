"""Keyed fingerprints: how the scanner names a secret without revealing it.

A fingerprint is HMAC-SHA256(scanner key, domain tag || secret), first 16 hex characters. The
same key in two files gets the same fingerprint, so a finding can be tracked across files and
scans on this machine. Without the scanner key, a fingerprint can't be used to test a guessed
secret. `agentguard fingerprint` computes one for a suspected key, read from stdin.

The key is 32 random bytes, created on first use with mode 0600 and never output. A key file
readable by anyone else is refused rather than used.
"""

import hashlib
import hmac
import os
import secrets
from pathlib import Path

KEY_BYTES = 32
FINGERPRINT_HEX = 16
SECRET_TAG = b"agentguard-scan-secret-v1\0"
ENTRY_TAG = b"agentguard-scan-entry-v1\0"


class ScannerKeyError(Exception):
    pass


def load_or_create_key(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        key = secrets.token_bytes(KEY_BYTES)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        return key
    st = os.stat(path)
    if st.st_mode & 0o077:
        raise ScannerKeyError(f"{path} is readable by others; set its mode to 0600")
    key = path.read_bytes()
    if len(key) != KEY_BYTES:
        raise ScannerKeyError(f"{path} is not a scanner key ({KEY_BYTES} bytes expected)")
    return key


def _mac(key: bytes, tag: bytes, data: bytes) -> str:
    return hmac.new(key, tag + data, hashlib.sha256).hexdigest()[:FINGERPRINT_HEX]


def secret_fingerprint(key: bytes, secret: str) -> str:
    return _mac(key, SECRET_TAG, secret.encode())


def entry_fingerprint(key: bytes, canonical: bytes) -> str:
    """For a whole MCP server entry, whose env values and arguments may hold secrets."""
    return _mac(key, ENTRY_TAG, canonical)
