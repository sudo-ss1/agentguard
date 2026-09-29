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
