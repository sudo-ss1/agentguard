"""Place a string into a tool result, the way a web page might carry it.

`place_text(text, mode)` is generic: it knows nothing about what the string says.

- "raw": the string on its own, as a plain-text tool result.
- "visible": inside an ordinary HTML page, as a visible paragraph.
- "hidden": inside the same page, in an element a human reader wouldn't see.

The string is HTML-escaped, so the page stays well-formed whatever it contains.
"""

import html
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


def reaches_reader(text: str, delivered: str) -> bool:
    """Whether `text` is still present in what was delivered (after unescaping markup)."""
    return " ".join(text.split()) in " ".join(html.unescape(delivered).split())
