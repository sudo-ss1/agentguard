"""Secret scanning with gitleaks' own rules (vendored, pinned): tool arguments, and files.

The rules are gitleaks v8.30.1's `config/gitleaks.toml` (MIT, see data/GITLEAKS-LICENSE),
evaluated with RE2, the same regex engine gitleaks uses, so patterns behave as they do there.
Every string argument is scanned, at any depth, before the call leaves the gateway.

Implemented gitleaks semantics:

- `keywords` prefilter
- `regex`; the secret is `secretGroup`, else the first non-empty capture group, else the match
- Shannon `entropy` threshold
- per-rule and global allowlists: `regexes` (with `regexTarget`: secret, match or line),
  `stopwords`, and `condition = AND`

Tool arguments have no path, so `paths` allowlists, a rule's `path` and the one path-only
rule don't apply to them. File scanning (`find(text, path)`, used by the discovery scanner)
applies all three: the global path allowlist skips the file, a rule with a `path` runs only on
matching files, and the path-only rule reports the file itself.

In the gateway, a finding is a deny. The receipt records the rule id and argument name in the
clear, and the matched secret only as a salted commitment (receipt option C).
"""

import math
import tomllib
from collections import Counter
from dataclasses import dataclass, field
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
    paths: list[Any]

    @classmethod
    def parse(cls, raw: dict[str, Any]) -> "_Allowlist":
        return cls(
            [re2.compile(r) for r in raw.get("regexes", [])],
            raw.get("regexTarget") or "secret",
            [w.lower() for w in raw.get("stopwords", [])],
            (raw.get("condition") or "OR").upper() == "AND",
            [re2.compile(r) for r in raw.get("paths", [])],
        )

    def allows_path(self, path: str) -> bool:
        return any(r.search(path) for r in self.paths)

    def allows(self, secret: str, match: str, line: str, path: str | None = None) -> bool:
        """`path` is None for tool arguments, where path conditions don't apply."""
        target = {"secret": secret, "match": match, "line": line}[self.target]
        checks = []
        if self.regexes:
            checks.append(any(r.search(target) for r in self.regexes))
        if self.stopwords:
            checks.append(any(w in secret.lower() for w in self.stopwords))
        if self.paths and path is not None:
            checks.append(self.allows_path(path))
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
    path: Any = None  # files only: the rule applies to files whose path matches


@dataclass(frozen=True)
class TextFinding:
    """A finding in text. `secret` is None for a path-only rule; `start` is its offset."""

    rule_id: str
    secret: str | None
    start: int

    def __repr__(self) -> str:  # never show the secret, even in a traceback or a log
        return f"TextFinding(rule_id={self.rule_id!r}, start={self.start})"


@dataclass(frozen=True)
class SecretFinding:
    rule_id: str
    argument: str  # e.g. "body" or "headers.authorization"
    secret: str = field(repr=False)  # never in a repr, a traceback or a log


class SecretScanner:
    def __init__(self, path: Path = RULES_PATH, extra_allowlists: Path | None = None) -> None:
        """`extra_allowlists`: an operator's gitleaks-format file (`[[allowlists]]`), applied
        like the global allowlist. A scanned repo's own `.gitleaks.toml` is never read."""
        config = tomllib.loads(path.read_text())
        self.rules = [
            _Rule(
                r["id"],
                re2.compile(r["regex"]),
                [k.lower() for k in r.get("keywords", [])],
                r.get("entropy"),
                int(r.get("secretGroup", 0)),
                [_Allowlist.parse(a) for a in r.get("allowlists", [])],
                re2.compile(r["path"]) if "path" in r else None,
            )
            for r in config["rules"]
            if "regex" in r
        ]
        self.path_rules = [
            (r["id"], re2.compile(r["path"]))
            for r in config["rules"]
            if "regex" not in r and "path" in r
        ]
        self.global_allowlist = _Allowlist.parse(config.get("allowlist", {}))
        self.extra_allowlists: list[_Allowlist] = []
        if extra_allowlists is not None:
            extra = tomllib.loads(extra_allowlists.read_text())
            raw = extra.get("allowlists", []) + (
                [extra["allowlist"]] if "allowlist" in extra else []
            )
            self.extra_allowlists = [_Allowlist.parse(a) for a in raw]

    def scan_text(self, text: str) -> list[tuple[str, str]]:
        """(rule_id, secret) for every finding in `text` (a tool argument)."""
        return [(f.rule_id, f.secret) for f in self.find(text) if f.secret is not None]

    def skips_path(self, path: str) -> bool:
        """gitleaks' global path allowlist: lock files, images, vendored dependencies…"""
        return self.global_allowlist.allows_path(path)

    def find(self, text: str, path: str | None = None) -> list[TextFinding]:
        """Every finding in `text`. With `path` (a file, relative to the scanned root, with
        forward slashes), path rules and path allowlists apply as in gitleaks."""
        found: list[TextFinding] = []
        if path is not None:
            if self.skips_path(path):
                return []
            found += [TextFinding(rid, None, 0) for rid, rx in self.path_rules if rx.search(path)]
        lowered = text.lower()
        for rule in self.rules:
            if path is not None and rule.path is not None and not rule.path.search(path):
                continue
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
                if self.global_allowlist.allows(secret, m.group(0), line, path):
                    continue
                if any(
                    a.allows(secret, m.group(0), line, path)
                    for a in rule.allowlists + self.extra_allowlists
                ):
                    continue
                found.append(TextFinding(rule.id, secret, m.start()))
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
