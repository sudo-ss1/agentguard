"""Injection scanning on tool results, run after the upstream call and before the agent sees it.

None of this module holds phrase lists; patterns come from vendored data files.

1. **Strip hidden content** from every result, and pass the visible text on:
   - CSS-hidden and off-screen elements, and HTML comments
   - ordinary zero-width and bidi characters, removed silently
   - Unicode tag characters; the text they spell is kept for scanning

   The receipt records what was stripped (category and count), with the content as a
   commitment only. Stripping on its own is not a signal.
2. **Vigil rules** (vendored YARA, Apache-2.0, hash-checked) run on both the stripped content
   and the visible text.
3. **Tool-name lures:** the gateway's own tool names, taken from its allowlist config. A tool
   name alone isn't a signal. It counts inside hidden content, or together with another
   finding.
4. **Classifier:** only on untrusted results (fetch_url, third-party MCP servers), when
   enabled. It is currently disabled; see docs/phase4-design.md for why.

**Taint** (approvals.py) needs a combined signal: stripped content that matches a Vigil rule or
a tool name, a Vigil match in the visible text, or a visible tool name alongside another
finding. A result is **withheld** only when its visible text matches Vigil, or the classifier
flags it, or the classifier is needed but can't finish. The gateway fails closed. Detection
only ever strips, withholds or escalates, and only on calls policy already allowed.
"""

import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yara
from pydantic import BaseModel

from agentguard.guards.classifier import ClassifierConfig, InjectionClassifier, load_classifier

VIGIL_DIR = Path(__file__).parent / "data" / "vigil"


# --- layer 1: Vigil's YARA rules -----------------------------------------------------------------


class VigilRules:
    def __init__(self, directory: Path = VIGIL_DIR) -> None:
        manifest = json.loads((directory / "MANIFEST.json").read_text())
        files = {}
        for name in manifest["rules_used"]:
            path = directory / name
            if hashlib.sha256(path.read_bytes()).hexdigest() != manifest["sha256"][name]:
                raise ValueError(f"vendored rule file {name} does not match its pinned hash")
            files[name.removesuffix(".yar")] = str(path)
        self.commit = manifest["commit"]
        self.rules = yara.compile(filepaths=files)

    def match(self, text: str) -> list[str]:
        return sorted({f"vigil:{m.rule}" for m in self.rules.match(data=text.encode("utf-8"))})


# --- layer 2: hidden content, stripped (structural) --------------------------------------------
#
# What a human reader of the page wouldn't see is removed before the agent sees it:
# CSS-hidden and off-screen elements, HTML comments, and invisible characters. Stripping
# alone is not a finding. What was stripped is scanned (layers 1 and 3), and only a match
# there taints the agent.

_HIDING_CSS = [  # (category, CSS declaration pattern)
    ("css-hidden-text", re.compile(r"display\s*:\s*none", re.I)),
    ("css-hidden-text", re.compile(r"visibility\s*:\s*hidden", re.I)),
    (
        "css-hidden-text",
        re.compile(r"font-size\s*:\s*0(?:\.0*)?\s*(?:px|pt|em|rem|%)?\s*(?:;|$)", re.I),
    ),
    ("css-hidden-text", re.compile(r"opacity\s*:\s*0(?:\.0*)?\s*(?:;|$)", re.I)),
    (
        "offscreen-text",
        re.compile(
            r"(?:left|top|right|bottom|text-indent|margin-left|margin-top)\s*:\s*-\d{3,}", re.I
        ),
    ),
]
_COLOR = re.compile(r"(?<![-\w])color\s*:\s*([^;]+)", re.I)
_BACKGROUND = re.compile(r"background(?:-color)?\s*:\s*([^;]+)", re.I)


def _chars(*ranges: tuple[int, int]) -> str:
    return "".join(f"{chr(a)}-{chr(b)}" if a != b else chr(a) for a, b in ranges)


# Ordinary invisible characters: zero-width space/joiners, word joiner and invisible operators,
# BOM, and bidi controls. They occur in ordinary text, so they are removed without a finding.
_ZERO_WIDTH_RANGES = (
    (0x200B, 0x200D),
    (0x2060, 0x2064),
    (0xFEFF, 0xFEFF),
    (0x202A, 0x202E),
    (0x2066, 0x2069),
)
_ZERO_WIDTH = re.compile(f"[{_chars(*_ZERO_WIDTH_RANGES)}]")
# Unicode tag characters (U+E0000-U+E007F) mirror ASCII invisibly and can spell out whole hidden
# messages. They are removed, and the text they spell is treated as hidden content.
_TAGS = re.compile(f"[{_chars((0xE0000, 0xE007F))}]+")
_VOID = {
    "area",
    "base",
    "br",
    "col",
    "embed",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "source",
    "track",
    "wbr",
}


def _style_hides(style: str) -> str | None:
    for category, pattern in _HIDING_CSS:
        if pattern.search(style):
            return category
    color, background = _COLOR.search(style), _BACKGROUND.search(style)
    if (
        color
        and background
        and color.group(1).strip().lower() == background.group(1).strip().lower()
    ):
        return "css-hidden-text"  # text coloured like its background
    return None


_TOKEN = re.compile(r"<!--|<(/?)([A-Za-z][\w:-]*)((?:\"[^\"]*\"|'[^']*'|[^'\">])*)>", re.S)
_ATTR = re.compile(r"""([^\s/=>"']+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?""")
_RAWTEXT = {"script", "style", "textarea", "title"}
_CLASS_RULE = re.compile(r"\.([\w-]+)\s*\{([^}]*)\}")


def _attrs(raw: str) -> dict[str, str]:
    return {
        m.group(1).lower(): (m.group(2) or m.group(3) or m.group(4) or "")
        for m in _ATTR.finditer(raw)
    }


def _hidden_spans(text: str) -> list[tuple[int, int, str]]:
    """Character spans (start, end, category) of outermost hidden elements and of comments.

    A small tokenizer on the C regex engine (about 2.7x faster than html.parser on large pages,
    with identical spans on every page and fragment in the tests). It keeps source positions,
    so spans are cut from the original text and everything else stays byte-identical, even for
    non-HTML text that happens to contain "<". Contents of script/style/textarea/title are not
    markup; style contents feed simple .class{} hiding rules.
    """
    spans: list[tuple[int, int, str]] = []
    class_rules: dict[str, str] = {}
    stack: list[tuple[str, bool]] = []  # (tag, whether it opened the hidden span)
    hidden_from: tuple[int, str] | None = None
    pos, n = 0, len(text)
    while True:
        m = _TOKEN.search(text, pos)
        if not m:
            break
        start = m.start()
        if m.group(0) == "<!--":
            end = text.find("-->", start + 4)
            end = n if end == -1 else end + 3
            if hidden_from is None:
                spans.append((start, end, "html-comment"))
            pos = end
            continue
        closing, tag, raw = m.group(1), m.group(2).lower(), m.group(3)
        end = m.end()
        if closing:
            if tag in _VOID or not any(t == tag for t, _ in stack):
                pos = end
                continue
            while stack:
                open_tag, starts = stack.pop()
                if starts and hidden_from is not None:
                    spans.append((hidden_from[0], end, hidden_from[1]))
                    hidden_from = None
                if open_tag == tag:
                    break
            pos = end
            continue
        rawtext_end = None
        if tag in _RAWTEXT:  # contents aren't markup; style contents feed class rules
            close = re.compile(rf"</{tag}\s*>", re.I).search(text, end)
            rawtext_end = close.start() if close else n
            if tag == "style":
                for selector, body in _CLASS_RULE.findall(text[end:rawtext_end]):
                    rule = _style_hides(body)
                    if rule:
                        class_rules[selector] = rule
        if tag in _VOID or raw.rstrip().endswith("/"):
            pos = end
            continue
        why: str | None = None
        if raw and ("style" in raw or "hidden" in raw or "class" in raw):
            a = _attrs(raw)
            why = _style_hides(a.get("style", "")) or ("css-hidden-text" if "hidden" in a else None)
            why = why or next(
                (class_rules[c] for c in a.get("class", "").split() if c in class_rules), None
            )
        starts = False
        if why is not None and hidden_from is None:
            hidden_from, starts = (start, why), True
        stack.append((tag, starts))
        pos = rawtext_end if rawtext_end is not None else end
    if hidden_from is not None:
        spans.append((hidden_from[0], n, hidden_from[1]))
    return sorted(spans)


@dataclass
class Stripped:
    # Tool result content, visible and hidden: neither is ever in a repr.
    visible: str = field(repr=False)
    removed: list[tuple[str, str]] = field(default_factory=list, repr=False)  # (category, content)


def strip_hidden(text: str) -> Stripped:
    removed: list[tuple[str, str]] = []
    for run in _TAGS.findall(text):  # decode what tag characters spell (U+E0020..E007E -> ASCII)
        spelled = "".join(chr(ord(c) - 0xE0000) for c in run if 0xE0020 <= ord(c) <= 0xE007E)
        removed.append(("unicode-tags", spelled))
    text = _TAGS.sub("", text)
    zero_width = len(_ZERO_WIDTH.findall(text))
    text = _ZERO_WIDTH.sub("", text)
    if zero_width:
        removed.append(("zero-width", ""))  # counted, but these are ordinary: never a signal
    if "<" in text:
        kept, cursor = [], 0
        for start, end, category in _hidden_spans(text):
            if start < cursor:
                continue
            kept.append(text[cursor:start])
            removed.append((category, text[start:end]))
            cursor = end
        kept.append(text[cursor:])
        text = "".join(kept)
    return Stripped(text, removed)


def hidden_text(text: str) -> list[str]:
    """The categories of hidden content in `text` (ordinary zero-width characters excluded)."""
    return sorted({f"hidden-text:{c}" for c, _ in strip_hidden(text).removed if c != "zero-width"})


# --- layer 3: tool-name lures --------------------------------------------------------------------


class ToolNameLures:
    """Results that mention the gateway's own tools. Names come from its allowlist config."""

    def __init__(self, tool_names: set[str]) -> None:
        self.tool_names = sorted(tool_names)
        self.pattern = (
            re.compile(r"(?<![\w-])(" + "|".join(map(re.escape, self.tool_names)) + r")(?![\w-])")
            if self.tool_names
            else None
        )

    def match(self, text: str) -> list[str]:
        if self.pattern is None:
            return []
        return sorted({f"tool-name-lure:{m}" for m in self.pattern.findall(text)})


# --- the scanner ----------------------------------------------------------------------------------


class InjectionConfig(BaseModel):
    # False turns result scanning off entirely: results pass through unmodified. Only for the
    # evaluation's control condition; never in a deployed gateway.
    enabled: bool = True
    untrusted_tools: list[str] = ["fetch_url"]
    untrusted_servers: list[str] = ["weather"]  # third-party MCP servers
    # Results longer than this are cut before scanning, and only the scanned part reaches the
    # agent (fail closed). Measured end to end on the lab machine, 64 KiB keeps the gateway's
    # added cost within the 20 ms budget up to 200 KB pages (p95 +17.2 ms). Beyond that the
    # upstream transfer itself dominates: a 771 KB page adds +20.9 ms at p95, a documented
    # exception (docs/phase4-design.md).
    max_result_chars: int = 64 * 1024
    classifier: ClassifierConfig = ClassifierConfig()


@dataclass
class ScanResult:
    """What scanning a result did.

    - `stripped`: category -> count of removed hidden content.
    - `stripped_content`: the removed content. It is in memory only; the receipt log records
      it as a commitment.
    - `taint`: the combined signal was present.
    - `withhold`: the result must not reach the agent at all (a Vigil match in the visible
      text, a classifier flag, or a scan that couldn't complete).
    """

    findings: list[str] = field(default_factory=list)  # rule / detector ids, never text
    stripped: dict[str, int] = field(default_factory=dict)
    stripped_content: str = field(default="", repr=False)
    taint: bool = False
    untrusted: bool = False
    classifier: dict[str, Any] | None = None
    error: str | None = None
    visible_flagged: bool = False
    truncated: dict[str, int] | None = None  # original_chars / kept_chars, if cut to the cap

    @property
    def flagged(self) -> bool:
        return self.taint

    @property
    def withhold(self) -> bool:
        return self.visible_flagged or self.error is not None

    @property
    def action(self) -> str:
        if self.withhold:
            return "withheld"
        if self.truncated:
            return "truncated"
        return "stripped" if self.stripped else "passed"

    def record(self) -> dict[str, Any]:
        """What goes in the receipt: ids, counts and scores. `stripped_content` is replaced by
        a commitment by the receipt log."""
        body: dict[str, Any] = {
            "findings": self.findings,
            "taint": self.taint,
            "untrusted": self.untrusted,
            "action": self.action,
        }
        if self.stripped:
            body["stripped"] = self.stripped
            body["stripped_content"] = self.stripped_content
        if self.classifier is not None:
            body["classifier"] = self.classifier
        if self.error is not None:
            body["error"] = self.error
        if self.truncated is not None:
            body["truncated"] = self.truncated
        return body


def _cap(texts: list[str], limit: int) -> tuple[dict[str, str], dict[str, int] | None]:
    """Cut distinct strings so their total length fits `limit`, in order. A hidden element cut
    in half stays hidden to the end (strip_hidden treats an unclosed hidden element that way)."""
    total = sum(map(len, texts))
    if total <= limit:
        return {t: t for t in texts}, None
    cut, left = {}, limit
    for t in texts:
        cut[t] = t[:left]
        left -= len(cut[t])
    return cut, {"original_chars": total, "kept_chars": limit}


class ResultScanner:
    def __init__(
        self,
        config: InjectionConfig,
        tool_names: set[str],
        classifier: InjectionClassifier | None = None,
    ) -> None:
        self.config = config
        self.vigil = VigilRules()
        self.lures = ToolNameLures(tool_names)
        self.classifier: InjectionClassifier | None = classifier
        self.load_error: str | None = None
        if classifier is None and config.classifier.enabled:
            try:
                self.classifier = load_classifier(config.classifier)
            except Exception as exc:  # fail closed later, for every untrusted result
                self.load_error = f"classifier failed to load ({type(exc).__name__})"
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="classifier")

    def is_untrusted(self, tool: str, server: str | None) -> bool:
        return tool in self.config.untrusted_tools or server in self.config.untrusted_servers

    def scan(self, tool: str, server: str | None, texts: list[str]) -> tuple[list[str], ScanResult]:
        """Strip each text, then judge the result as a whole. Returns the visible texts."""
        if not self.config.enabled:
            return list(texts), ScanResult(untrusted=self.is_untrusted(tool, server))
        # A result often carries the same string twice (MCP servers mirror their text block in
        # structured content). Every copy is stripped; each distinct string is counted once.
        cut, truncated = _cap(list(dict.fromkeys(texts)), self.config.max_result_chars)
        unique = {t: strip_hidden(cut[t]) for t in cut}
        if truncated:
            note = f"\n[AgentGuard: result cut to {self.config.max_result_chars // 1024} KiB]"
            for t in unique:
                if cut[t] != t:
                    unique[t].visible += note
        visible = [unique[t].visible for t in texts]
        removed = [r for s in unique.values() for r in s.removed]
        result = ScanResult(untrusted=self.is_untrusted(tool, server), truncated=truncated)
        for category, _ in removed:
            result.stripped[category] = result.stripped.get(category, 0) + 1
        hidden_payload = "\n".join(c for cat, c in removed if cat != "zero-width" and c)
        result.stripped_content = hidden_payload
        seen = "\n".join(unique[t].visible for t in unique)  # each distinct string once

        hidden_hits = self.vigil.match(hidden_payload) + self.lures.match(hidden_payload)
        visible_vigil = self.vigil.match(seen)
        visible_lures = self.lures.match(seen)
        other_signal = bool(
            hidden_hits or visible_vigil or any(c != "zero-width" for c, _ in removed)
        )
        result.findings = sorted(
            {
                *(f"hidden:{h}" for h in hidden_hits),
                *visible_vigil,
                *(visible_lures if other_signal else []),
            }
        )
        # The combined signal: hidden content that matches a rule or a tool name, a Vigil match
        # in the visible text, or a visible tool name alongside another finding.
        result.taint = bool(hidden_hits or visible_vigil or (visible_lures and other_signal))
        result.visible_flagged = bool(visible_vigil)

        if result.untrusted and self.config.classifier.enabled:
            self._classify(result, seen)
        return visible, result

    def _classify(self, result: ScanResult, text: str) -> None:
        cfg = self.config.classifier
        if self.classifier is None:
            result.error = self.load_error or "classifier not loaded"
            return
        try:
            score = self._pool.submit(self.classifier.score, text).result(timeout=cfg.timeout_s)
        except FutureTimeout:
            result.error = f"classifier timed out after {cfg.timeout_s}s"
            return
        except Exception as exc:
            result.error = f"classifier failed ({type(exc).__name__})"
            return
        result.classifier = {
            "model": self.classifier.name,
            "revision": self.classifier.revision,
            "score": round(score.probability, 4),
            "windows": score.windows,
            "complete": score.complete,
        }
        if score.probability >= cfg.threshold:
            result.findings.append(f"classifier:{self.classifier.name}")
            result.taint = result.visible_flagged = True
        if not score.complete:
            result.error = f"text longer than the classifier's {cfg.max_windows} windows"
