"""Tool-description pinning against MCP rug pulls (trust on first use).

The first time the gateway sees a tool it records a hash of its name, description and input
schema. If a pinned tool later changes, its whole server is quarantined: every tool it
serves is hidden and every call to it is denied. To re-approve a server, stop the gateway
and remove it from `quarantined` (and its old pins) in the pins file.

Every change is audited (Phase 6): new pins and quarantines become signed control receipts as
they happen, and an edit made while the gateway was stopped (such as a re-approval) is
recorded when it starts (gateway/control.py).
"""

import hashlib
import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from mcp.types import Tool

from agentguard.gateway.checks import CallContext, Decision

log = logging.getLogger(__name__)


def tool_hash(tool: Tool) -> str:
    canonical = json.dumps(
        {
            "name": tool.name,
            "description": tool.description or "",
            "input_schema": tool.input_schema,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


class PinStore:
    name = "pins"

    def __init__(self, path: Path) -> None:
        self.path = path
        data = json.loads(path.read_text()) if path.exists() else {}
        self.pins: dict[str, str] = data.get("pins", {})
        self.quarantined: dict[str, str] = data.get("quarantined", {})
        self._observers: list[Callable[[dict[str, Any], dict[str, Any]], None]] = []

    def snapshot(self) -> dict[str, Any]:
        return {"pins": dict(self.pins), "quarantined": dict(self.quarantined)}

    def on_change(self, callback: Callable[[dict[str, Any], dict[str, Any]], None]) -> None:
        """`callback(old, new)` runs after each change is saved."""
        self._observers.append(callback)

    def verify(self, server: str, tools: list[Tool]) -> None:
        """Pin new tools and quarantine the server if a pinned tool changed."""
        old = self.snapshot()
        changed = False
        for tool in tools:
            key, digest = f"{server}/{tool.name}", tool_hash(tool)
            pinned = self.pins.get(key)
            if pinned is None:
                self.pins[key] = digest
                changed = True
                log.info("pinned %s %s", key, digest[:12])
            elif pinned != digest and server not in self.quarantined:
                self.quarantined[server] = (
                    f"description of {tool.name!r} changed since it was pinned"
                )
                changed = True
                log.warning("quarantined %s: %s", server, self.quarantined[server])
        if changed:
            self._save()
            for observer in self._observers:
                observer(old, self.snapshot())

    def evaluate(self, ctx: CallContext) -> Decision:
        if ctx.server in self.quarantined:
            return Decision(
                "deny",
                f"server {ctx.server!r} quarantined: {self.quarantined[ctx.server]}",
                "pin-quarantine",
            )
        return Decision("allow", "server not quarantined", "pins")

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(
                {"pins": self.pins, "quarantined": self.quarantined}, indent=2, sort_keys=True
            )
        )
