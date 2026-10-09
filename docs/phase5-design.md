# Phase 5 design: the tamper-evident audit ledger

Approved 2026-09-30. Code: `src/agentguard/ledger/`. Attack 7 ("audit database row edited")
is the test.

## Where receipts were before

Phase 4 appended plain JSON lines (`json.dumps`) to `receipts.jsonl`: no canonical form,
sequence number, hash link, signature, lock or fsync. In Docker the file sat on the
`lab-state` volume, mounted read-write into the agent and all four tool containers. The files
tool is confined to `/lab-state/rootfs`, so no tool call could reach the log. But any
compromised container could edit it directly. An allowed call's receipt was written after the
upstream call returned, so a side effect happened before any record of it existed.

## Decisions

| Topic | Decision |
| --- | --- |
| Storage | JSON lines, not the plan's SQLite. The hash chain and signatures give the tamper evidence either way, and JSON lines stay readable with `jq` (docs/architecture.md). |
| Signing key | The gateway generates its own Ed25519 key on first start, in `ledger.key_dir`: the `ledger-key` volume, mounted into the gateway only, file 0600. The key is not issued by the identity service or `provision`, so it never crosses a container boundary and shares nothing with the issuer or Biscuit keys. `tests/test_compose.py` enforces the mounts. |
| Public key | Exported as a did:key to `ledger-roots/ledger-key.pub.json`, and printed by `agentguard ledger pubkey`. Verifiers must pin it out of band. `verify` never trusts a key found in the log. |
| Rotation | Designed, not built: a `key-rotation` receipt signed by the old key names the new one. The verifier starts from the pinned key and follows rotation receipts. Recovering from a compromised key needs an external copy of the checkpoints. |
| Log location | Receipts move to the `ledger` volume, written by the gateway and mounted read-only into the agent container (the harness). Checkpoints go to `ledger-roots`, with the same access. |
| Canonical form | Each line is RFC 8785 of `{body, hash, sig}`. `hash` is SHA-256(RFC 8785(body)). `sig` is Ed25519 over the domain tag `agentguard-receipt-v1\0` followed by the 32 hash bytes; checkpoints use `agentguard-checkpoint-v1\0`. The body carries `v`, `ledger_id` (random, 128 bits), `seq` and `prev`; the first receipt's `prev` is 64 zeros. Verifiers re-parse, reject duplicate keys, and re-canonicalize. Writing refuses NaN, infinity and integers beyond ±(2⁵³ − 1). A pinned test vector is cross-checked with `sha256sum` and the `cryptography` package. |
| Argument hash | `args_sha256` is now SHA-256 over RFC 8785 of the arguments. Receipts from before 2026-10-01 use the old `json.dumps(sort_keys=True)` hash: `legacy_args_digest` and `args_match` in `gateway/receipts.py` read both. Arguments RFC 8785 can't represent exactly are denied rather than recorded with an ambiguous hash. |
| Two receipts per allowed call | A decision receipt is written before the call is forwarded; if it can't be recorded, the call is not made. An outcome receipt (`decision_seq`, upstream error, result scan) follows. `verify` reports an allowed decision with no outcome as "outcome unknown". Denials have one receipt. |
| Ordering | One writer per ledger: an exclusive `flock` at start, and appends under a lock with no awaits inside. Parallel calls interleave, but the sequence is always one well-defined order: the order receipts were written. |
| Durability | Batched by default: each line is one `write` with O_APPEND, and a background thread fsyncs every 100 ms and before every checkpoint. A process crash loses nothing already written. **An OS crash can lose the last receipts, including the decision receipt of a call already forwarded.** `ledger.durability: strict` fsyncs every decision receipt before `append` returns, which closes that gap. Outcome receipts stay batched: an OS crash can lose one, which `verify` reports as "outcome unknown". |
| Torn last line | On start, only the bytes after the last newline are touched, never a complete line, even an invalid one. They are moved to `receipts.jsonl.torn-<time>.bin` (never deleted), cut from the ledger, and recorded in a signed `recovery` receipt (length and SHA-256). A malformed or unverifiable complete line stops the gateway from starting, and nothing is changed. |
| Checkpoints | Every 60 s and on shutdown, when there are new receipts: `{ledger_id, start, size, head, batch_root, prev_checkpoint, ts, key}`, signed. `batch_root` is the RFC 9162 Merkle root of the receipt hashes since the previous checkpoint. The ledger is fsynced first, so a checkpoint never covers receipts that aren't on disk. |
| Startup check | After recovery, the ledger must agree with the latest checkpoint: at least its size, and the receipt at that position must carry its head hash. Otherwise the gateway refuses to start. |
| Deleting the end of the log | A hash chain alone can't detect it. `verify` detects it against a checkpoint copy the attacker couldn't reach. Without checkpoints, `verify` says so ("tail-unproven") and never claims completeness. Receipts written after the last published checkpoint (up to 60 s of them) can still be cut unnoticed; this is a stated limit. |
| Salts (option C) | Receipts hold commitment digests only. `verify` never needs a salt, and `receipts forget` changes no receipt byte, so the chain stays valid. |
| Publishing | Local: `ledger-roots/checkpoints.jsonl`. **Rekor is future work: skipped in Phase 5, not built, and off by default if it is ever added.** The design for it: a separate `publisher` container on its own internet network mounts `ledger-roots` read-only, never the log or the key, and submits `hashedrekord` entries holding only a checkpoint's SHA-256, its signature and the public key. The gateway keeps no internet access. |

## `agentguard ledger verify`

```
agentguard ledger verify --log receipts.jsonl --public-key <did:key | ledger-key.pub.json>
                         [--checkpoints checkpoints.jsonl] [--require-checkpoint] [--json]
```

It reports the first broken link: line, `seq`, which check failed and why, and the last good
receipt before it. Other problems are listed after it. Exit codes: 0 intact, 1 tampered (or,
with `--require-checkpoint`, some receipt not covered by a verified checkpoint), 2 bad input.

| Tampering | What `verify` reports |
| --- | --- |
| A receipt's content edited | `hash` on that line |
| Edited, and the hash recomputed | `signature` on that line, then `prev` on the next |
| Signed with another key | `signature` on that line |
| Middle receipt deleted | `seq-gap` ("seq N missing") on the next line |
| Receipts reordered | `seq-order` |
| End of the log deleted | `tail-missing`, against a checkpoint |
| Wrong public key | `signature` on every line, with a wrong-key hint |

## Attack 7

- **Guarded:** the agent reads the SSH key (denied), then a receipt edit rewrites that decision
  as a `list_dir`. `verify`, with the key pinned when the lab started, must name exactly that
  line, with the `hash` check.
- **Baseline:** there is no gateway, so the harness writes the Phase 4 unsigned format for the
  same calls. Nothing can verify it, so the edit goes unnoticed: a strict xfail.
- The edit is made on a snapshot of the log, so the session's log stays usable for other tests.
  `verify` reads the same bytes either way.

## Latency

Measured 2026-09-30 with `bench/latency.py` (200 calls per tool per round), end to end through
a local guarded lab, on the WSL2 machine with other work running (load average about 1.1–1.4 on
6 cores). Each round ran four labs in turn: direct (no gateway), the Phase 4 gateway (commit
`5bae7c8`, no ledger), and this gateway in batched and in strict mode. "Added" is each mode
minus that round's direct run; "ledger cost" is minus that round's Phase 4 run, which isolates
the ledger from the rest of the gateway.

Added latency over direct, median across rounds (p50 / p95, ms). Budget: 20 ms.

| Mode | Rounds | read_file | list_dir | fetch_url | Rounds with p95 over 20 ms (any tool) |
| --- | --- | --- | --- | --- | --- |
| Phase 4 gateway (control) | 10 | 6.5 / 8.2 | 6.9 / 8.6 | 7.3 / 8.8 | 2 of 10 (rounds 1 and 10, fetch_url only) |
| Batched (default) | 10 | 7.2 / 8.8 | 7.5 / 9.5 | 8.2 / 9.6 | 2 of 10 (round 1: fetch_url 25.3; round 5: list_dir 42.6, fetch_url 67.3) |
| Strict (one fsync per call) | 5 (rounds 6–10) | 11.9 / 15.2 | 11.9 / 13.8 | 12.2 / 13.0 | 1 of 5 (round 6: fetch_url 30.6) |

Ledger cost over the Phase 4 gateway, median p50 per tool: batched +0.4 to +0.8 ms (10
rounds), strict +5.6 to +5.9 ms (5 rounds). The strict figure is about one fsync, as measured in isolation (5.6–6.3 ms p50).

- **Batched meets the budget at the median with room to spare.** Its cost over the Phase 4 gateway
  is under 1 ms at p50.
- **Its tail over budget is not clearly the ledger's.**
  - The Phase 4 control also went over twice, on fetch_url, whose direct baseline itself varied
    from 20 to 39 ms p50 between rounds.
  - **Round 5's list_dir p95 (+42.6 ms) was seen only in ledger modes, and is unexplained.**
    Strict was also slow in that round, while the Phase 4 control wasn't. A disk stall during
    fsync is plausible, but unproven.
- **Strict fits the budget at the median (p95 13–15 ms).** One fetch_url round went over.
- **An earlier version of strict fsynced every receipt,** two per allowed call, contrary to this
  design. It measured +19–22 ms p50 over direct and missed the budget (rounds 1–5, kept in the
  run log). It was fixed to fsync decision receipts only, as designed. Outcome receipts follow
  the batched schedule, so in strict mode an OS crash can still lose an outcome receipt, which
  `verify` then reports as "outcome unknown".

Raw reports: `run-logs/latency-phase5/controlled/` (a local run log, not published).

Micro-benchmarks from the design stage (5 runs, same machine, 620-byte receipt):

| Step | p50 | p95 |
| --- | --- | --- |
| RFC 8785 | 19–20 µs | 27–35 µs |
| Ed25519 sign | 15–16 µs | 22–30 µs |
| write | 0.4 µs | 1.6 µs |
| write + fsync | 5.6–6.3 ms | 6.8–23.7 ms |
