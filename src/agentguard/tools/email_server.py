"""Email MCP server. A stub: messages are appended to OUTBOX_PATH, never sent."""

import json
from datetime import UTC, datetime

from mcp.server.mcpserver import MCPServer

from agentguard.settings import get_settings

server = MCPServer("email")


@server.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email."""
    outbox = get_settings().outbox_path
    outbox.parent.mkdir(parents=True, exist_ok=True)
    message = {"to": to, "subject": subject, "body": body, "sent_at": datetime.now(UTC).isoformat()}
    with outbox.open("a") as f:
        f.write(json.dumps(message) + "\n")
    return f"email sent to {to}"
