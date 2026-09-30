"""Exactly which bytes are hashed and signed, so a verifier anywhere gets the same results.

A ledger line is the RFC 8785 (JCS) serialization of

    {"body": {...}, "hash": "<hex>", "sig": "<base64url>"}

followed by a newline.

- `hash` is SHA-256 over RFC 8785(body), as lowercase hex.
- `sig` is Ed25519 over the domain tag followed by the 32 raw hash bytes. Receipts and
  checkpoints have different tags, so a signature for one can never pass as the other.
- A verifier never relies on the file's bytes. It parses each line, rejects duplicate keys,
  and re-serializes the body with RFC 8785 before hashing.
- Only JSON that RFC 8785 represents exactly is accepted when writing: no NaN or infinity,
  and integers within ±(2**53 - 1).
"""

import base64
import hashlib
import json
import math
from typing import Any

import nacl.exceptions
import nacl.signing
import rfc8785

FORMAT_VERSION = 1
RECEIPT_TAG = b"agentguard-receipt-v1\x00"
CHECKPOINT_TAG = b"agentguard-checkpoint-v1\x00"
GENESIS_PREV = "0" * 64
MAX_SAFE_INT = 2**53 - 1
LINE_KEYS = frozenset({"body", "hash", "sig"})


class CanonicalError(ValueError):
    """The value can't be represented exactly in RFC 8785 JSON."""


class LineError(ValueError):
    """A ledger line isn't well-formed."""


def check_representable(value: Any, where: str = "body") -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INT:
            raise CanonicalError(f"{where}: integer {value} is outside ±(2**53 - 1)")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalError(f"{where}: {value} is not a finite number")
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonicalError(f"{where}: key {k!r} is not a string")
            check_representable(v, f"{where}.{k}")
        return
    if isinstance(value, list | tuple):
        for i, v in enumerate(value):
            check_representable(v, f"{where}[{i}]")
        return
    raise CanonicalError(f"{where}: {type(value).__name__} is not JSON")


def jcs(value: Any) -> bytes:
    check_representable(value)
    return bytes(rfc8785.dumps(value))


def body_hash(body: dict[str, Any]) -> str:
    return hashlib.sha256(jcs(body)).hexdigest()


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign(key: nacl.signing.SigningKey, tag: bytes, hex_hash: str) -> str:
    return _b64u(key.sign(tag + bytes.fromhex(hex_hash)).signature)


def signature_valid(public_key: bytes, tag: bytes, hex_hash: str, sig: str) -> bool:
    try:
        nacl.signing.VerifyKey(public_key).verify(tag + bytes.fromhex(hex_hash), _unb64u(sig))
    except (nacl.exceptions.BadSignatureError, ValueError, TypeError):
        return False
    return True


def seal(key: nacl.signing.SigningKey, tag: bytes, body: dict[str, Any]) -> tuple[bytes, str]:
    """The ledger line for `body` (with its trailing newline), and the body's hash."""
    h = body_hash(body)
    line = jcs({"body": body, "hash": h, "sig": sign(key, tag, h)}) + b"\n"
    return line, h


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise LineError(f"duplicate key {k!r}")
        out[k] = v
    return out


def parse_line(text: str | bytes) -> dict[str, Any]:
    """Parse one ledger line into {"body", "hash", "sig"}. Rejects duplicate keys, other
    top-level keys, and non-finite numbers."""
    try:
        value = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    except LineError:
        raise
    except ValueError as exc:
        raise LineError(f"not valid JSON: {exc}") from exc
    if not isinstance(value, dict) or set(value) != LINE_KEYS:
        raise LineError("a ledger line has exactly the keys body, hash and sig")
    if not isinstance(value["body"], dict):
        raise LineError("body is not an object")
    if not isinstance(value["hash"], str) or not isinstance(value["sig"], str):
        raise LineError("hash and sig are strings")
    return value


def _reject_constant(name: str) -> None:
    raise LineError(f"{name} is not valid in a ledger line")
