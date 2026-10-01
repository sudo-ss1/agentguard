# Roadmap

Last updated: 2026-10-01. The phases follow [agentguardplan.md](../agentguardplan.md).

## Done

| Phase | What | Details |
| --- | --- | --- |
| 1 | Vulnerable baseline: an LLM agent with file, web and email tools, a lab with a canary SSH key and an "evil" site, and attack scenarios with oracles | [architecture.md](architecture.md) |
| 2 | Gateway (MCP proxy) with per-agent tool allowlists, Cedar policies and tool-description pinning (attacks 1–3) | [architecture.md](architecture.md) |
| 3 | Agent identity: did:key, Verifiable Credentials, DPoP-bound requests and Biscuit capability tokens with delegation (attacks 4–5) | [phase3-design.md](phase3-design.md) |
| 4 | Runtime guards: secret scanning, human approval, budgets and a kill switch (attack 6); result scanning that strips hidden content; a scanner evaluation and LLM trials | [phase4-design.md](phase4-design.md), [eval-notes.md](eval-notes.md) |
| 5 | Tamper-evident audit ledger: signed, hash-chained receipts, Merkle checkpoints, `agentguard ledger verify` (attack 7); Docker volume isolation for the key, salts and ledger | [phase5-design.md](phase5-design.md) |

All seven attacks succeed against the baseline and are blocked through the gateway, both on a
local lab (`make attack`) and in Docker (`make attack-docker`).

## Next

- **Phase 6, visibility:** a discovery scanner (MCP client configs, SDK imports, keys) that
  outputs an AI bill of materials, a risk engine, and a Streamlit dashboard. Attack 8 ("API key
  committed in a repo") lands here.
- **Write-up:** README polish, the architecture diagram and a blog post.

## Future work

- **LLM trials with tasks that use tools,** taken from an external task set rather than one
  designed for this project. The Phase 4 trials measured answer steering only; no trial made a
  tool call beyond `fetch_url`.
- **Publishing checkpoints to Sigstore Rekor.** Designed but not built, and off by default if
  added: a separate publisher container would submit only checkpoint digests
  ([phase5-design.md](phase5-design.md)).
- **Key rotation for the ledger.** Designed, not built.

## Known open issues

- **"No tools" (unexplained).** In 2 of about 32 runs of the LLM-trial end-to-end test
  (2026-09-30), a freshly started guarded lab's agent was listed no tools. Its gateway had
  pinned all seven tools and logged no error. It didn't recur in 26 later runs, and the cause is
  unknown. To diagnose a repeat:
  - the gateway logs `tools/list from an unverified caller (<reason>)` at WARNING
  - the trial harness records such a trial as the agent error "the gateway listed no tools to
    the agent", never as "target not seen"

  The published Phase 4 LLM results are unaffected: all 72 trials called `fetch_url`.
- **A ledger-only latency outlier (unexplained).** One round showed a +42.6 ms p95 for
  `list_dir`, in ledger modes only. Medians are well within the 20 ms budget
  ([phase5-design.md](phase5-design.md)).
- **The classifier is disabled.** The injection classifier takes about 1.7 s per 512-token
  window on the development laptop (i5-1345U, under WSL2), far over the latency budget.
- **Metrics definition.** "Detected" in the scanner evaluation means tainted or withheld. It is
  an open question whether to report the two separately.
