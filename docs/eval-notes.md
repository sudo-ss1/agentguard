# Evaluation notes

These are interim measurements, taken while building Phase 4. The scanner evaluation proper
(an external corpus test split, 20+ LLM trials with pinned settings) is still to come.

## Pattern rules catch little, which is why policy does the protecting

Vigil's 5 vendored prompt-injection rules (deadbits/vigil-llm at commit `f2b4c134`,
unmaintained since January 2024) flagged **0 of 37** labelled injections in a 200-row sample
of `deepset/prompt-injections` (train split). They flagged 0 of 163 benign rows.

The rule set is small: most rules have 1–9 patterns. It also targets exact phrasings, while
real injections are paraphrased, translated or obfuscated. That result is expected, and it is
the reason AgentGuard doesn't depend on detection. Attacks 1–6 are stopped by policy:
allowlists, Cedar, identity, capability tokens and budgets. Scanners only add friction on top
(stripping hidden content, tainting, escalating to approval), and a clean scanner result can
never allow a call that policy denies (`tests/test_guards.py`).

## The classifier isn't in use

`protectai/deberta-v3-base-prompt-injection-v2` (int8 ONNX) takes about 1.7 s per full
512-token window on this machine: an i5-1345U, 3 physical cores, under WSL. That is far over
the 20 ms per-call budget, so it ships disabled. See docs/phase4-design.md for the profile.

## Caveats for the evaluation proper

- **deepset** is mostly *direct* injections: text addressed to the model by the user.
  AgentGuard's case is *indirect*: text inside tool results. Its rates may not transfer.
- **The ProtectAI model's card** says it is English-only and doesn't detect jailbreaks.
  deepset includes German rows, so results will be reported separately for English and for
  other languages.
- **Train-split rows** have been used only in unit tests. The evaluation uses the test split.

## Scanner evaluation (step 3)

Run with `agentguard eval scanner` on 2026-09-30 against the pinned corpora in
`eval/corpora.lock.json`. The classifier was off, so these numbers are the gateway's
rule-based scanner only. Items whose text normalizes to nothing: 0 in every group. Intervals
are 95% Clopper–Pearson. The full per-group table is in `run-logs/scanner-eval/results.md`.

"Detected" means the agent was tainted or the result withheld. "Reached" means the placed
text is still in what the agent receives.

| Corpus | Label | n | Mode | Detected | Reached |
| --- | --- | --- | --- | --- | --- |
| deepset | positive | 60 | raw / visible | 0/60 (0%; 0–6%) | 60/60 (100%; 94–100%) |
| deepset | positive | 60 | hidden | 0/60 (0%; 0–6%) | 0/60 (0%; 0–6%) |
| deepset | negative | 56 | any | 0/56 (0%; 0–6%) false positives ¹ | 56/56 raw / visible; 0/56 hidden |
| garak, all 9 probes | positive | 2,216 | raw / visible | 232/2,216 (10.5%; 9.2–11.8%) | 1,984/2,216 (89.5%) |
| garak, all 9 probes | positive | 2,216 | hidden | 232/2,216 (10.5%; 9.2–11.8%) | 0/2,216 (0%; 0–0.2%) |

- ¹ With n = 56, the false-positive interval is wide: its upper bound is 6.4%. Earlier
  real-page tests support a low rate but aren't pooled with it here
  (`docs/phase4-design.md`, "Results"). A real 767 KB Wikipedia article ("Tomato") gave
  0 withheld and 0 tainted, with 37 hidden items stripped. The 200-row deepset train sample
  gave 0 withheld and 0 tainted. Of those rows, 163 are benign: 0/163 false positives, with
  a 95% CI of 0–2.2%. The other 37 are injections, and none was detected.
- Every garak detection came from one Vigil rule, `InstructionBypass`, in three probes:
  TranslationEnFr 85/256, TranslationEnZh 91/256 and Whois 56/168. The other six probes had
  0 detections.
- In visible and raw placement, every detection withheld the result, and every undetected
  item reached the agent. Hidden placement never reached the agent, because stripping removes
  it whether or not a rule matches. Hidden text tainted the agent only when a rule matched it,
  as designed.
- deepset: 0/60 injections detected in any placement, and 0/56 false positives.
- The rules miss almost all of this, which matches the earlier note: in visible placement,
  about 90% of garak's injections and all of deepset's reach the agent. What happens next is
  down to policy, which the agent trials measure.
- Neither corpus matches our threat. deepset is mostly direct injections, and garak's are
  embedded in documents but written for a model reading the document directly. Neither was
  written for hidden HTML, so the hidden rows measure stripping, not detection.
