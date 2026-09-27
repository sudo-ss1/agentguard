"""did:key for Ed25519 (W3C CCG did:key method).

A did:key is "did:key:z" + base58btc(multicodec ed25519-pub (0xed 0x01) + 32-byte public key).
The public key is inside the DID, so resolving one needs no network and no registry.
"""

import os
from pathlib import Path
from typing import Self

import base58
import nacl.signing

ED25519_PUB = b"\xed\x01"  # multicodec varint for ed25519-pub
PREFIX = "did:key:z"  # "z" is the multibase code for base58btc


def did_from_public_key(public_key: bytes) -> str:
    if len(public_key) != 32:
        raise ValueError("an Ed25519 public key is 32 bytes")
    return PREFIX + base58.b58encode(ED25519_PUB + public_key).decode()


def public_key_from_did(did: str) -> bytes:
    if not did.startswith(PREFIX):
        raise ValueError(f"not a base58btc did:key: {did[:40]!r}")
    try:
        raw = base58.b58decode(did.removeprefix(PREFIX))
    except ValueError as exc:
        raise ValueError("did:key is not valid base58btc") from exc
    if raw[:2] != ED25519_PUB or len(raw) != 34:
        raise ValueError("did:key is not an Ed25519 key")
    return raw[2:]


class AgentKey:
    """An Ed25519 signing key and its did:key. The private half never leaves this object
    except through `save`."""

    def __init__(self, signing_key: nacl.signing.SigningKey) -> None:
        self.signing_key = signing_key
        self.public_key = bytes(signing_key.verify_key)
        self.did = did_from_public_key(self.public_key)

    @classmethod
    def generate(cls) -> Self:
        return cls(nacl.signing.SigningKey.generate())

    @classmethod
    def load(cls, path: Path) -> Self:
        return cls(nacl.signing.SigningKey(path.read_bytes()))

    def save(self, path: Path) -> None:
        """Write the 32-byte seed, readable by the owner only."""
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(bytes(self.signing_key))
        os.chmod(path, 0o600)  # in case the file already existed with wider permissions

    @property
    def seed(self) -> bytes:
        return bytes(self.signing_key)

    @property
    def verification_method(self) -> str:
        """The key's id inside its DID document: did:key:z...#z..."""
        return f"{self.did}#{self.did.removeprefix('did:key:')}"
