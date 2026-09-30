"""The gateway's receipt-signing key.

The gateway generates this Ed25519 key itself, on first start, in its own key directory. It is
not issued by the identity service or `agentguard provision`, so the private key never crosses
a container boundary and shares nothing with the issuer or Biscuit root keys. In Docker the
directory is the `ledger-key` volume, mounted into the gateway only (tests/test_compose.py
checks this).

The public half is exported as a did:key next to the checkpoints. A verifier must be given it
out of band and pin it; `verify` never trusts a key found inside the log itself.

Rotation (designed, not built): a `key-rotation` receipt, signed by the old key, names the new
public key; receipts after it are signed by the new key. The verifier starts from the pinned key
and follows rotation receipts.
"""

import json
from pathlib import Path

from agentguard.identity.didkey import AgentKey, did_from_public_key, public_key_from_did

SIGNING_KEY_FILE = "ledger-signing.key"
PUBLIC_KEY_FILE = "ledger-key.pub.json"


def load_or_create(key_dir: Path) -> AgentKey:
    """The signing key in `key_dir` (0600), created on first use."""
    path = key_dir / SIGNING_KEY_FILE
    if path.exists():
        return AgentKey.load(path)
    key = AgentKey.generate()
    key_dir.mkdir(parents=True, exist_ok=True)
    key_dir.chmod(0o700)
    key.save(path)
    return key


def export_public(key: AgentKey, directory: Path) -> Path:
    """Write the public key (only) where verifiers and auditors can read it."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / PUBLIC_KEY_FILE
    path.write_text(json.dumps({"did": key.did}) + "\n")
    return path


def load_public(spec: str | Path) -> bytes:
    """A pinned public key: a did:key string, or a file written by `export_public`."""
    text = str(spec)
    if text.startswith("did:key:"):
        return public_key_from_did(text)
    return public_key_from_did(json.loads(Path(text).read_text())["did"])


def did_for(public_key: bytes) -> str:
    return did_from_public_key(public_key)
