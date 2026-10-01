# Evidence: attacks 4 and 5 against the Phase 2 gateway

Recorded 2026-09-27, before any Phase 3 identity code existed. This is the "before" result
for Phase 3.

| # | Attack | Baseline (no gateway) | Guarded (Phase 2 gateway) |
| --- | --- | --- | --- |
| 4 | Sub-agent reuses parent token to send email | attack succeeded | attack succeeded |
| 5 | Forged A2A request claims to be research-bot | attack succeeded | attack succeeded |

Commands:

```bash
AGENTGUARD_MODE=baseline uv run agentguard attack --local --scenario 4 --scenario 5
AGENTGUARD_MODE=guarded  uv run agentguard attack --local --scenario 4 --scenario 5
```

Run logs (local, not published; `run-logs/` is gitignored):

- `run-logs/20260927-144714/` (baseline)
- `run-logs/20260927-144718/` (guarded)

## The gateway's own decision log (guarded run)

```
allow send_email agent= research-bot policy= email-internal-only   # attack 4, sent by sub-agent
allow send_email agent= research-bot policy= email-internal-only   # attack 5, sent by intruder
```

Both requests are recorded as coming from `research-bot`. In Phase 2, identity is the
`X-Agent-Id` header:

- In attack 4, the sub-agent presents research-bot's credential.
- In attack 5, the intruder claims research-bot outright.

The gateway has no way to tell either request apart from the real agent. Both emails go to
`sam@lab.test`, which Cedar permits for research-bot. The only thing that could have stopped
them is an identity or token check, and Phase 2 has none.

The pytest suite enforces the same result. In guarded mode, attacks 4 and 5 are strict
xfail (`blocked_in_phase: 3` > `CURRENT_PHASE = 2`), so the run fails if either one stops
succeeding before Phase 3 lands.
