from typing import Any

from mcp.server.lowlevel import Server
from mcp.server.mcpserver import MCPServer

from agentguard.tools import email_server, files_server, weather_server, web_server

SERVERS: dict[str, MCPServer | Server[Any]] = {
    "files": files_server.server,
    "web": web_server.server,
    "email": email_server.server,
    "weather": weather_server.server,
}
