"""Tool-description pinning against MCP rug pulls (trust on first use).

The first time the gateway sees a tool it records a hash of its name, description and input
schema. If a pinned tool later changes, its whole server is quarantined: every tool it
serves is hidden and every call to it is denied. To re-approve a server, stop the gateway
and remove it from `quarantined` (and its old pins) in the pins file.
"""

import hashlib
import json
import logging
from pathlib import Path

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

    def verify(self, server: str, tools: list[Tool]) -> None:
        """Pin new tools and quarantine the server if a pinned tool changed."""
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
