# Phase 4 design: runtime guards

Approved 2026-09-29. Targets attack 6 (the 500-fetch loop). Adds injection and secret
scanning, human approval, budgets and a kill switch.

## Guiding rule

Detection supplements policy and never replaces it. The gateway has two stages:

1. **Policy stage** (the Phase 2–3 pipeline): identity → capability token → pins → allowlist →
   arguments → Cedar. Only this stage can grant a call.
2. **Guard stage**: kill switch, secret scan, taint, approval, budgets. It runs only after
   policy allows the call.

A guard returns `no-objection`, `deny` or `escalate`. There is no allow value, so a guard
cannot express permission. The two stages combine by taking the stricter answer. A human
approval turns `escalate` into allow; it can never turn a deny into allow. A policy denial
never creates an approval request.

## Decisions

| Area | Decision |
| --- | --- |
| Injection classifier | `protectai/deberta-v3-base-prompt-injection-v2` (Apache-2.0, ungated), at a pinned revision, exported to ONNX with int8 weights. It runs locally in the gateway process, never remotely or on the Ollama machine, behind a swappable interface. Llama Prompt Guard 2 was requested and declined on Hugging Face. |
| What gets scanned | The rules layer runs on every tool result. The classifier runs only on results from untrusted sources: `fetch_url` and third-party MCP servers, not workspace files. |
| Scanner failure | If the classifier errors, times out or can't load, the result is withheld. |
| Flagged result | The result is withheld and the agent gets a notice instead. The agent is tainted for 10 minutes. |
| Approval | `send_email` and `delete_file` always need approval. While the agent is tainted, `write_file`, `send_email` and `fetch_url` escalate to approval too. Timeout (120 s), error or a restart means deny. An approval covers exactly one call. |
| Approval timeouts in results | Recorded separately from policy denials, in both receipts and `results.md`. A timeout never counts as "the gateway blocked the attack". Attack 4 must still be stopped by the token check. |
| Secret scanning | gitleaks' rules at a pinned version, evaluated with RE2, on every string argument. Receipts record the rule id in the clear and the matched value only as a commitment (receipt option C). |
| Budgets | Per agent, after Cedar and approval: per-tool rate limits and a cost budget. Attack 6 must be blocked here. |
| Kill switch | A gateway-local kill list of DIDs and Biscuit revocation ids, checked right after identity. Triggered by a budget trip or by the CLI. It persists and overrides a still-valid token. |
| Docker | The model is downloaded at image build time. The gateway never downloads anything at runtime, and the agent container can't reach the model files. |
| Latency | Measured over 5+ runs with realistic page sizes, including tens of KB, as p50 and p95 against the 20 ms budget. If it doesn't fit: stop, report, and fall back to rules only. |
| Evaluation | Two corpora: `deepset/prompt-injections` and garak's latent-injection probes. 20+ LLM trials with the pinned model (`qwen2.5:7b-instruct`, digest `845dbda0ea48`, Q4_K_M, temperature 0, seed 7). Report the model card's limitations and the direct-vs-indirect mismatch. |

## Order of work

1. Guard-stage structure and the "detection never loosens policy" test.
2. Budgets and the kill switch (attack 6).
3. Secret scanning.
4. Approvals.
5. The injection scanner and its latency measurement. Stop and report here.
6. The evaluation harness.

## Step 5 results (2026-09-29): injection scanner

### Rules layer

- **Vigil:** `deadbits/vigil-llm` at commit `f2b4c134d060bae81d29fad07003f3c657e63fc8`
  (Apache-2.0), vendored unmodified by download into `src/agentguard/guards/data/vigil/`
  with its LICENSE and a NOTICE. File hashes are checked at load, and the rules are evaluated
  with `yara-python==4.5.4`.
  - **Vigil is unmaintained: it has had no commits since January 2024.**
  - Rules used: `InstructionBypass`, `SystemInstructions_vigil`, `ContainsGuidance`,
    `ContainsReAct_txt`, `MarkdownExfiltration`.
- **Coverage of the design's categories:**

  | Category | Covered by |
  | --- | --- |
  | Override phrasing | Vigil |
  | Role markers | Vigil |
  | Tool-name lures | Vigil's ReAct rule (format only), plus the structural lure detector |
  | Hidden-text markup | the structural hidden-text detector |

  Remaining gaps: none of the four categories is unhandled. Lure detection is limited to
  exact tool names. Hidden text is limited to inline styles, `hidden`, and simple
  `.class{}` rules in `<style>` blocks; external stylesheets and complex selectors aren't
  resolved.
- **Measured on the deepset train sample** (200 rows):
  - Vigil flagged 0 of 37 injections, and 0 of 163 benign rows.
  - The invisible-Unicode check flagged 2 benign rows, both from zero-width spaces.
  - Markup and tool-lure checks flagged nothing.
- **Real-page false positive (fixed):** withholding on any hidden text withheld a benign
  Wikipedia article beyond about 60 KB. The strip-instead-of-withhold redesign below replaced
  that approach.

### Classifier

`protectai/deberta-v3-base-prompt-injection-v2`, revision `90c9989b`, ProtectAI's ONNX export
(sha256 `f0ea7f23…`), quantized to int8 (sha256 `95066b0f…`, 244 MB).

- **Agreement:** int8 agrees with fp32 on 188 of 200 deepset train rows.
- **Latency** on 6 CPU threads, including real HTML at several page sizes:

  | Input | p50 | p95 |
  | --- | --- | --- |
  | A 1-window weather result | 35 ms | 51 ms |
  | 2 KB page | 1,910 ms | 2,203 ms |
  | 10 KB page | about 7.5 s (per-run medians) | |
  | 30 KB page | about 24 s | |
  | 60 KB page | about 50 s | |

- **Profile** (2026-09-29): benign filler text, the model loaded once, median of 5 calls. The
  hardware is an **Intel i5-1345U laptop chip, 3 physical cores / 6 logical CPUs, under WSL2**,
  with AVX-VNNI.

  | Model | Threads | Tokens | Mode | p50 |
  | --- | --- | --- | --- | --- |
  | int8 | 1 / 3 / 6 | 32 | 1 window | 35 / 32 / 29 ms |
  | int8 | 1 / 3 / 6 | 128 | 1 window | 115 / 110 / 127 ms |
  | int8 | 1 / 3 / 6 | 256 | 1 window | 280 / 259 / 305 ms |
  | int8 | 1 / 3 / 6 | 510 | 1 window | 1,725 / 1,768 / 1,677 ms |
  | int8 | 3 | 1,020 | 2 windows, batched | 2,822 ms |
  | int8 | 3 | 1,020 | 2 windows, one at a time | 3,696 ms |
  | fp32 | 3 | 510 | 1 window | 2,775 ms |

  What the profile rules out, and what it shows:

  - **Padding** isn't the cause: a single window is never padded.
  - **Reloading** isn't the cause: the model is loaded once, and timings are warm.
  - **Unbatched windows** aren't the cause: batching is on, and is 24% faster than one window
    at a time.
  - **Thread contention** isn't the cause either. 1, 3 and 6 threads perform the same, so
    extra threads aren't helping on this setup, but they aren't slowing it down.
  - **Sequence length is the cause.** Cost is superlinear in tokens, so 2 KB of HTML (about
    1,000 tokens, two full windows) costing about 2 s is consistent, not a bug.
  - **Precision:** int8 is 1.6× faster than fp32.
- **Decision:** a full 512-token window takes about 1.7 s, and even 32 tokens take about 30 ms,
  so the classifier can't meet the 20 ms budget on this machine. It ships disabled
  (`classifier.enabled: false`), and the rules-only fallback is active. It could be re-evaluated:
  - on faster hardware (more cores, a GPU or an NPU)
  - with a smaller model, e.g. a DeBERTa-small or distilled classifier whose training data can
    be checked for overlap with the eval corpora
  - after investigating why onnxruntime doesn't scale with threads here
- **Docker:** the model is downloaded at build time only once the classifier is enabled. For
  now nothing is downloaded.

### Rules-only cost

Vigil and both structural detectors, 200 scans per size:

| Page size | p50 | p95 |
| --- | --- | --- |
| 2 KB | 0.14 ms | 0.42 ms |
| 10 KB | 1.05 ms | 3.55 ms |
| 30 KB | 5.5 ms | 16.9 ms |
| 60 KB | 7.3 ms | 12.2 ms |

End to end, on the bench's small pages, the gateway adds 4.9–5.1 ms at p50 over direct calls.

### Redesign: strip hidden content, taint only on a combined signal (approved 2026-09-29)

**Stripping.** Every tool result has its hidden content removed, and the agent gets the
visible text:

- CSS-hidden elements (`display:none`, `visibility:hidden`, zero font size or opacity, text
  coloured like its background, the `hidden` attribute, simple `.class{}` rules from
  `<style>` blocks)
- off-screen positioning
- HTML comments
- invisible characters:
  - Ordinary zero-width and bidi characters are removed silently. They occur in ordinary
    text, and two benign deepset rows contain them.
  - Unicode tag characters are removed too, and the text they spell is scanned like other
    hidden content.

Stripping applies to every string in both the text blocks and the structured content,
because the MCP client rejects a result that has lost its structured content. Identical
strings are stripped every time but counted once. The receipt records what was stripped:
category and count, with the stripped content as a salted commitment only.

**Taint (the combined signal).** Hidden content alone doesn't taint the agent. It is tainted
when:

- stripped content matches a Vigil rule or names a gateway tool
- the visible text matches Vigil
- a tool name appears in visible text alongside another finding

A tool name alone in visible text is not a signal.

**Withhold.** A result is withheld only when the visible text itself matches Vigil, or when
the classifier (if enabled) flags it or can't finish.

**Results:**

- **Benign pages:** 0 withheld and 0 tainted, including a real 767 KB Wikipedia article
  ("Tomato"), where 37 hidden items were stripped.
- **deepset train sample:** 0 withheld, 0 tainted.
- **Attack 1:**
  - The fetched page's hidden instruction is stripped, and the visible recipe reaches the
    agent.
  - The agent is tainted, because the stripped text names `read_file` and `send_email`.
  - The decision log still shows both policy denials (`no-ssh-keys`, `default-deny`).

**Test note.** One full-suite run failed an assertion that a token authorizes a tool (reason
`rights`). It did not reproduce in 10 further full runs or 25 targeted runs of the two
candidate files. The cause is not identified.
