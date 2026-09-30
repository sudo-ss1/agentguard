"""The tamper-evident audit ledger (Phase 5): signed, hash-chained receipts and checkpoints.

- `canonical`: exactly which bytes are hashed and signed.
- `keys`: the gateway's receipt-signing key, kept apart from every other key.
- `merkle`: RFC 9162 Merkle tree hashing for checkpoints.
- `writer`: the gateway's single ledger writer.
- `verify`: replays a ledger and reports the first broken link.
- `read`: reads receipts back as one record per call, for the harness and tests.

Design and decisions: docs/phase5-design.md.
"""
