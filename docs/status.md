# Status

Last updated: 2026-09-30.

## Phases

- Phases 1–3: done and committed.
- Phase 4 (runtime guards): guards done and committed. The evaluation harness is in progress.
  The Phase 4 checklist box stays unticked until the user says otherwise.

## Phase 4 evaluation harness

| Step | What | State |
| --- | --- | --- |
| 0 | Pinned corpora (`eval/corpora.lock.json`, `eval/garak_extract.py`, `eval/corpora.py`), Clopper–Pearson statistics, scanner off-switch | Done, `099e417` |
| 1 | Generic page placement (`eval/placement.py`: `place_text`, `reaches_reader`), tested with random markers only | Done, `14d6f8f` |
| 2a | Metrics (`eval/metrics.py`); `reaches_reader` normalizes both sides | Done, `55e4145` (tests written by the user) |
| 2b | CLI: `agentguard eval fetch / scanner / llm`, `eval/sources.py`, `eval/trials.py` | Done (this commit) |
| 3 | Scanner eval on the pinned corpora, results in `docs/eval-notes.md` | Done |
| 4 | LLM trials, 24 per condition, pinned digest; results in `docs/eval-notes.md` | Done |

Both corpora are fetched and hash-verified in `eval/data/`, which is gitignored:

- deepset/prompt-injections test split: revision `4f61ecb0…`, 116 rows (60 positive, 56 negative).
- garak v0.17.0 latent-injection probes (non-Full): 2,216 prompts, each with its trigger string.

## Decisions made

- **Guard verdicts** are no-objection, deny or escalate, never allow. Detection can't loosen
  policy, because `combine()` returns a policy denial unchanged.
- **Receipts** carry structured reasons. Allowlisted attributes are in the clear, and the rest
  are salted SD-JWT-style commitments with a separate 0600 salt store. Each receipt also records
  the denial class, the approval record and the result-scan summary.
- **Secret scanning** uses vendored gitleaks v8.30.1 rules, run on RE2.
- **Result scanning:**
  - Hidden content is stripped before anything else. Hidden text alone doesn't taint the agent.
  - Taint needs a combined signal.
  - A result is withheld only on a Vigil match in visible text, or a classifier flag or failure.
  - Zero-width and bidi characters are stripped silently. Unicode tag characters are decoded
    and scanned.
  - A tool name alone doesn't flag.
  - Results over the 64 KiB cap fail closed.
- **Classifier:** ProtectAI deberta-v3-base-prompt-injection-v2 at a pinned revision, exported to
  int8 ONNX.
  - It runs locally in the gateway, on untrusted sources only, behind a swappable interface.
  - It fails closed.
  - It's disabled by default (about 1.7 s per window on this machine), and its Docker download is
    deferred until it's enabled.
- **Patterns** are vendored, not authored. Tests load attack inputs from files and never embed
  corpus strings in code.
- **Authorizer limits** are explicit (256 facts, 16 iterations, 10 ms). A limit hit is reported as
  `authorizer-limit`.
- **Large pages:** the parser comes first and the 64 KiB cap is the fallback. The 771 KB page's
  latency overage (+20.9 ms p95) is a documented exception.
- **Agent trials** count three things per condition: the target in the final answer; tool calls
  carrying the target in their arguments; and each such call's gateway decision (allowed, or
  denied by which layer). Calls are matched to receipts by argument hash, denied calls included.
  Trials use a 10 s approval timeout. The gateway's default stays 120 s, and a test checks it.
- **Items whose text normalizes to nothing** are left out of the scanner rates and counted per
  group. There are 0 in both corpora.
- **Eval code stays generic.** Placement and metrics know nothing about corpus content. Tests use
  placeholder strings or synthetic labelled data. Names are neutral throughout.

## Standing rules

- Ask before running anything that deletes volumes or data (`down -v`, removing run logs or lab
  state). Don't delete or revert uncommitted work.
- Commit locally as `sudo-ss1 <290857932+sudo-ss1@users.noreply.github.com>`. Don't push yet.
- Commit after each step once its tests and lint pass.
- Don't tick the Phase 4 box.
- Stop and report before anything else if something could ever produce a wrong allow.
- If a step is stopped again, say which one. The user will write that piece or review it.

## Open questions

- Metrics: should `detected` stay "tainted or withheld", or should taint and withhold be reported
  as separate columns, with detection defined as either?
- Reporting: the corpora hold mostly direct injections, while the gateway defends against indirect
  (tool-result) injection. The report needs to say so, and to say the classifier was disabled.
- LLM trials: which model digest to pin, and whether to use the lab Ollama host (<ollama-host>).
