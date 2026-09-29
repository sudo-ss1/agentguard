"""Secret scanning on tool arguments, with gitleaks' own rules (vendored, pinned).

The rules are gitleaks v8.30.1's `config/gitleaks.toml` (MIT, see data/GITLEAKS-LICENSE),
evaluated with RE2, the same regex engine gitleaks uses, so patterns behave as they do there.
Every string argument is scanned, at any depth, before the call leaves the gateway.

Implemented gitleaks semantics:

- `keywords` prefilter
- `regex`; the secret is `secretGroup`, else the first non-empty capture group, else the match
- Shannon `entropy` threshold
- per-rule and global allowlists: `regexes` (with `regexTarget`: secret, match or line),
  `stopwords`, and `condition = AND`

`paths` allowlists don't apply to tool arguments. The one path-only rule is skipped.

A finding is a deny. The receipt records the rule id and argument name in the clear, and the
matched secret only as a salted commitment (receipt option C).
"""

import math
import tomllib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import re2

from agentguard.gateway.checks import CallContext
from agentguard.guards import NO_OBJECTION, GuardResult

RULES_PATH = Path(__file__).parent / "data" / "gitleaks.toml"
GITLEAKS_VERSION = "v8.30.1"
RULES_SHA256 = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts, n = Counter(text), len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


@dataclass
class _Allowlist:
    regexes: list[Any]
    target: str  # secret | match | line
    stopwords: list[str]
    all_of: bool  # condition = AND

    @classmethod
    def parse(cls, raw: dict[str, Any]) -> "_Allowlist":
        return cls(
            [re2.compile(r) for r in raw.get("regexes", [])],
            raw.get("regexTarget") or "secret",
            [w.lower() for w in raw.get("stopwords", [])],
            (raw.get("condition") or "OR").upper() == "AND",
        )

    def allows(self, secret: str, match: str, line: str) -> bool:
        target = {"secret": secret, "match": match, "line": line}[self.target]
        checks = []
        if self.regexes:
            checks.append(any(r.search(target) for r in self.regexes))
        if self.stopwords:
            checks.append(any(w in secret.lower() for w in self.stopwords))
        if not checks:
            return False
        return all(checks) if self.all_of else any(checks)


@dataclass
class _Rule:
    id: str
    regex: Any
    keywords: list[str]
    entropy: float | None
    secret_group: int
    allowlists: list[_Allowlist]


@dataclass(frozen=True)
class SecretFinding:
    rule_id: str
    argument: str  # e.g. "body" or "headers.authorization"
    secret: str


class SecretScanner:
    def __init__(self, path: Path = RULES_PATH) -> None:
        config = tomllib.loads(path.read_text())
        self.rules = [
            _Rule(
                r["id"],
                re2.compile(r["regex"]),
                [k.lower() for k in r.get("keywords", [])],
                r.get("entropy"),
                int(r.get("secretGroup", 0)),
                [_Allowlist.parse(a) for a in r.get("allowlists", [])],
            )
            for r in config["rules"]
            if "regex" in r
        ]
        self.global_allowlist = _Allowlist.parse(config.get("allowlist", {}))

    def scan_text(self, text: str) -> list[tuple[str, str]]:
        """(rule_id, secret) for every finding in `text`."""
        lowered, found = text.lower(), []
        for rule in self.rules:
            if rule.keywords and not any(k in lowered for k in rule.keywords):
                continue
            for m in rule.regex.finditer(text):
                groups = [g for g in m.groups() if g]
                secret = (
                    m.group(rule.secret_group)
                    if rule.secret_group
                    else (groups[0] if groups else m.group(0))
                )
                if not secret:
                    continue
                if rule.entropy is not None and shannon_entropy(secret) < rule.entropy:
                    continue
                start = text.rfind("\n", 0, m.start()) + 1
                end = text.find("\n", m.end())
                line = text[start : end if end != -1 else len(text)]
                if self.global_allowlist.allows(secret, m.group(0), line):
                    continue
                if any(a.allows(secret, m.group(0), line) for a in rule.allowlists):
                    continue
                found.append((rule.id, secret))
        return found

    def scan_arguments(self, arguments: dict[str, Any]) -> list[SecretFinding]:
        findings = []
        for name, text in _strings(arguments):
            findings += [SecretFinding(rule, name, secret) for rule, secret in self.scan_text(text)]
        return findings


def _strings(value: Any, prefix: str = "") -> list[tuple[str, str]]:
    if isinstance(value, str):
        return [(prefix or "value", value)]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in _strings(v, f"{prefix}.{k}" if prefix else k)]
    if isinstance(value, list):
        return [s for i, v in enumerate(value) for s in _strings(v, f"{prefix}[{i}]")]
    return []


class SecretScanGuard:
    """Deny a call whose arguments carry a secret. Runs before approval, so nobody is asked
    to approve sending one."""

    name = "secret-scan"

    def __init__(self, scanner: SecretScanner | None = None) -> None:
        self.scanner = scanner or SecretScanner()

    def check(self, ctx: CallContext) -> GuardResult:
        findings = self.scanner.scan_arguments(ctx.arguments)
        if not findings:
            return NO_OBJECTION
        first = findings[0]
        return GuardResult(
            "deny",
            f"secret in arguments ({len(findings)} finding(s))",
            "secret-scan",
            {"rule_id": first.rule_id, "argument": first.argument, "secret": first.secret},
        )
