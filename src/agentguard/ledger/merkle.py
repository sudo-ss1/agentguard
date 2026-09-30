"""Merkle tree hashing as in RFC 9162 (Certificate Transparency v2), section 2.1.1.

- The hash of an empty list is SHA-256 of nothing.
- A leaf is SHA-256(0x00 || entry); an interior node is SHA-256(0x01 || left || right). The
  prefixes keep a leaf from ever being mistaken for a node.
- A list of n > 1 entries splits at k, the largest power of two smaller than n.

A checkpoint's batch root covers the receipt hashes (32 raw bytes each) since the previous
checkpoint.
"""

import hashlib


def leaf_hash(entry: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def root(entries: list[bytes]) -> bytes:
    n = len(entries)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hash(entries[0])
    k = _split(n)
    return node_hash(root(entries[:k]), root(entries[k:]))


def root_hex(receipt_hashes: list[str]) -> str:
    return root([bytes.fromhex(h) for h in receipt_hashes]).hex()
