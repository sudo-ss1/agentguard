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
  so the classifier can't meet the 20 ms budget on the development laptop. It ships disabled
  (`classifier.enabled: false`), and the rules-only fallback is active. It could be re-evaluated:
  - on faster hardware (more cores, a GPU or an NPU)
  - with a smaller model, e.g. a DeBERTa-small or distilled classifier whose training data can
    be checked for overlap with the eval corpora
  - after investigating why onnxruntime doesn't scale with threads here
- **Docker:** the model is downloaded at build time only once the classifier is enabled. For
  now nothing is downloaded.

### Obtaining the classifier model (by hand)

The model isn't in the repo, and no AgentGuard command downloads it (`agentguard eval fetch`
fetches only the evaluation corpora). It is needed only if `classifier.enabled` is set, which
it isn't by default. To obtain it:

1. Download ProtectAI's own ONNX export at the pinned revision into the folder the gateway
   reads (`ClassifierConfig.model_dir`):

   ```bash
   uv sync --extra models
   uv run python - <<'PY'
   from huggingface_hub import hf_hub_download
   for name in ["model.onnx", "tokenizer.json", "tokenizer_config.json",
                "special_tokens_map.json", "config.json"]:
       hf_hub_download("protectai/deberta-v3-base-prompt-injection-v2", f"onnx/{name}",
                       revision="90c9989b1a342275dd0d1a95aad283c04e075671",
                       local_dir="models/protectai-deberta-v3-base-prompt-injection-v2")
   PY
   ```

2. Quantize the weights to int8 (dynamic quantization, onnxruntime's defaults otherwise):

   ```bash
   uv run python -c "
   from onnxruntime.quantization import quantize_dynamic, QuantType
   d = 'models/protectai-deberta-v3-base-prompt-injection-v2/onnx/'
   quantize_dynamic(d + 'model.onnx', d + 'model.int8.onnx', weight_type=QuantType.QInt8)"
   ```

   onnxruntime prints a warning suggesting pre-processing first; it was not applied.

3. Check the hashes:

   | File | SHA-256 |
   | --- | --- |
   | `onnx/model.onnx` (ProtectAI's export, fp32, 739 MB) | `f0ea7f239f765aedbde7c9e163a7cb38a79c5b8853d3f76db5152172047b228c` |
   | `onnx/model.int8.onnx` (the file the gateway loads, 244 MB) | `95066b0f5017243ee7194e3f3edb32d64513394a91c1be1d75b3115f63f1570a` |
   | `onnx/tokenizer.json` | `752fe5f0d5678ad563e1bd2ecc1ddf7a3ba7e2024d0ac1dba1a72975e26dff2f` |

The gateway refuses to load an `model.int8.onnx` whose hash differs (`model_sha256` in
`ClassifierConfig`). Step 2 was re-run on 2026-10-09 from the downloaded fp32 file and
produced the pinned int8 hash exactly, with onnxruntime 1.30.0 and onnx 1.23.1
(huggingface_hub 1.33.0). Other onnxruntime versions may quantize to different bytes; if the
hash doesn't match, use those versions. The model is Apache-2.0.

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

## The intermittent token failure, and authorizer limits (2026-09-30)

**What it was.** One full-suite run failed an assertion that a valid token authorizes a tool
(reason `rights`, no failed checks). It was a wrongful **deny**, never an allow.

- **Cause:** Biscuit's authorizer has a default 1 ms time limit. Under CPU load on the development
  laptop (i5-1345U, 3 physical cores, WSL), plain authorizations reached 4.1 ms, so a valid call was
  occasionally denied.
- **Mislabelled:** the classifier reported that limit error as `rights`.
- **Reproduced** under full CPU load: 2 of 5,000 valid calls were denied. Under the same load,
  0 of 5,000 calls for a tool the token lacks were allowed. Hitting a limit is always a deny.
- **Ruled out:**
  - The expiry boundary is deterministic: valid at the exact expiry second, denied one second
    later, in 1,000 runs each.
  - The order of failed checks was identical in 1,000 runs.
  - The replay cache accepted exactly 1 of 64 racing threads in each of 200 rounds.
  - 200 parallel calls through a real gateway were all allowed.

**Fix** (`tokens/biscuit.py`). All three authorizer limits are set explicitly:

| Limit | Value | Role |
| --- | --- | --- |
| Facts | 256 | Primary, deterministic protection. Our tokens hold facts and checks but no rules, so legitimate authorizations need a few dozen facts. |
| Iterations | 16 | Primary, deterministic protection: legitimate authorizations need a couple of rounds. |
| Time | 10 ms | The bound on cost (see below). |

After the fix, 0 of 20,000 valid calls are denied under full CPU load, and 200 stress runs of
the token-related tests with 3 cores busy all passed.

**Budget impact.** A hostile token can consume up to about the time limit, **10 ms, half the
20 ms per-call budget**, before it is denied. The fact limit is checked between evaluation
rounds, so a single expensive round runs to completion first. A holder-appended rule joining
100 facts with themselves took about 12 ms to reach the fact-limit denial, measured under load.
The clock therefore bounds the cost, while the fact limit gives a deterministic denial. A limit
hit is reported with its own reason, `authorizer-limit`, never as a missing right (`rights`).
Tests: `test_an_exploding_appended_rule_is_denied_by_the_fact_limit_not_the_clock` and
`test_hitting_the_time_limit_denies_and_says_why`.

## Latency with stripping, and the result size cap (2026-09-30)

End-to-end `fetch_url` latency, direct against through the gateway, on the benign Wikipedia
"Tomato" article cut to each size. Hardware: i5-1345U under WSL.

**Before:** html.parser stripping, no cap. The gateway added more than 20 ms beyond about
60 KB: 200 KB added +46.1 / +51.9 ms, and the full 771 KB page +165.5 / +170.0 ms (p50 / p95).
Profiling the full page put 88 of the 121 ms of scanning in Python's html.parser.

**Changes:**

- **A faster tokenizer:** stripping now uses a small tokenizer on the C regex engine. It is
  2.7× faster, and finds identical spans to html.parser on 219 inputs. A test keeps the old
  parser as a reference (`tests/reference_hidden_spans.py`).
  - A C DOM parser (selectolax) was faster still, at 15.5 ms on the full page, but was
    rejected. It re-serializes the whole document, and rewrote a JSON fragment into
    `<html><body>…&lt;…`.
- **No doubled scanning:** Vigil and the tool-name lures scan each distinct string once. They
  previously scanned the text and structured copies of the same page both times.
- **A result size cap** (`guards.injection.max_result_chars`, 64 KiB), which fails closed:
  - A longer result is cut to the cap before scanning, and the agent receives only the scanned
    part, with a note that it was cut.
  - The receipt records the original and kept sizes (`truncated`).
  - A hidden element cut in half by the cap stays hidden.

**After** (added over direct; 100 samples per size, 5 runs):

| Page | Added p50 / p95 |
| --- | --- |
| 2 KB | +4.8 / +6.4 ms |
| 10 KB | +5.7 / +2.8 ms |
| 30 KB | +9.1 / +11.6 ms |
| 60 KB | +10.9 / +11.1 ms |
| 128 KB | +12.0 / +17.4 ms |
| 200 KB | +14.8 / +17.2 ms |
| 771 KB | **+18.3 / +20.9 ms** |

**Documented exception.** Results beyond roughly 500 KB exceed the 20 ms budget at p95, by
about 1 ms at 771 KB. The cause isn't scanning, since only 64 KiB is scanned. The gateway has
to receive the whole result from the upstream tool before it can cut it, and MCP servers send
it twice (text plus structured content). A smaller gateway cap can't remove that; only
bounding the upstream response size would.
