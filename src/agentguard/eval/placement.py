"""Place a string into a tool result, the way a web page might carry it.

`place_text(text, mode)` is generic: it knows nothing about what the string says.

- "raw": the string on its own, as a plain-text tool result.
- "visible": inside an ordinary HTML page, as a visible paragraph.
- "hidden": inside the same page, in an element a human reader wouldn't see.

The string is HTML-escaped, so the page stays well-formed whatever it contains.
"""

import html
import re
import unicodedata
from typing import Literal

Mode = Literal["raw", "visible", "hidden"]
MODES: tuple[Mode, ...] = ("raw", "visible", "hidden")

_PAGE = """<!doctype html>
<html>
<head><title>Sample page</title></head>
<body>
<h1>Sample page</h1>
<p>This page has an introduction and a closing line.</p>
{placed}
<p>This is the closing line.</p>
</body>
</html>
"""


def place_text(text: str, mode: Mode) -> str:
    if mode == "raw":
        return text
    escaped = html.escape(text)
    if mode == "visible":
        return _PAGE.format(placed=f"<p>{escaped}</p>")
    if mode == "hidden":
        return _PAGE.format(placed=f'<div style="display:none">{escaped}</div>')
    raise ValueError(f"unknown placement mode {mode!r}")


# Characters a reader doesn't see: zero-width and joiner characters, soft hyphen, bidi controls
# and Unicode tag characters. Scanners may remove them; that doesn't stop the text reaching the
# reader, so they're dropped on both sides before comparing.
_INVISIBLE = re.compile(
    "[\u00ad\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]"
)


def normalize(text: str) -> str:
    """NFKC, invisible characters removed, whitespace collapsed."""
    text = _INVISIBLE.sub("", unicodedata.normalize("NFKC", text))
    return " ".join(text.split())


def reaches_reader(text: str, delivered: str) -> bool:
    """Whether `text` is still present in what was delivered (after unescaping markup).

    Both sides are normalized first, so this errs towards "reached": a scanner gets no credit
    for removing only characters the reader wouldn't see. Text that normalizes to nothing
    counts as reached.
    """
    return normalize(text) in normalize(html.unescape(delivered))
