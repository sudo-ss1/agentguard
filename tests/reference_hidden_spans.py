"""The original html.parser-based hidden-span finder, kept only as a test reference.

The gateway uses a faster tokenizer (result_scan._hidden_spans). This reference proves the two
find identical spans; see test_result_scan.py.
"""

import re
from html.parser import HTMLParser

from agentguard.guards.result_scan import _VOID, _style_hides


class _HiddenSpans(HTMLParser):
    """Finds the character spans of outermost hidden elements and of comments."""

    def __init__(self, text: str) -> None:
        super().__init__(convert_charrefs=True)
        self.text = text
        self._line_starts = [0] + [i + 1 for i, c in enumerate(text) if c == "\n"]
        self.spans: list[tuple[int, int, str]] = []  # (start, end, category)
        self.class_rules: dict[str, str] = {}
        self.open: list[tuple[str, str | None]] = []  # (tag, category if it starts a hidden span)
        self.hidden_from: tuple[int, str] | None = None  # the open hidden span, if any
        self.in_style = False

    def _offset(self) -> int:
        line, col = self.getpos()
        return self._line_starts[line - 1] + col

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "style":
            self.in_style = True
        if tag in _VOID:
            return
        a = {k.lower(): (v or "") for k, v in attrs}
        why = _style_hides(a.get("style", "")) or ("css-hidden-text" if "hidden" in a else None)
        why = why or next(
            (self.class_rules[c] for c in a.get("class", "").split() if c in self.class_rules), None
        )
        starts_span = why is not None and self.hidden_from is None
        if starts_span:
            assert why is not None
            self.hidden_from = (self._offset(), why)
        self.open.append((tag, why if starts_span else None))

    def handle_endtag(self, tag: str) -> None:
        if tag == "style":
            self.in_style = False
        if tag in _VOID or not any(t == tag for t, _ in self.open):
            return
        end = self.text.find(">", self._offset())
        end = len(self.text) if end == -1 else end + 1
        while self.open:
            open_tag, category = self.open.pop()
            if category is not None and self.hidden_from is not None:
                self.spans.append((self.hidden_from[0], end, category))
                self.hidden_from = None
            if open_tag == tag:
                break

    def handle_data(self, data: str) -> None:
        if self.in_style:
            for selector, body in re.findall(r"\.([\w-]+)\s*\{([^}]*)\}", data):
                category = _style_hides(body)
                if category:
                    self.class_rules[selector] = category

    def handle_comment(self, data: str) -> None:
        if self.hidden_from is not None:
            return  # already inside a hidden span
        start = self._offset()
        end = self.text.find("-->", start)
        self.spans.append((start, len(self.text) if end == -1 else end + 3, "html-comment"))

    def finish(self) -> list[tuple[int, int, str]]:
        if self.hidden_from is not None:  # never closed: hide everything after it
            self.spans.append((self.hidden_from[0], len(self.text), self.hidden_from[1]))
        return sorted(self.spans)


def reference_spans(text: str) -> list[tuple[int, int, str]]:
    parser = _HiddenSpans(text)
    try:
        parser.feed(text)
        parser.close()
    except Exception:
        pass
    return parser.finish()
