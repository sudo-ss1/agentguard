"""Web MCP server. Deliberately unfiltered: returns raw page text from any URL."""

import httpx
from mcp.server.mcpserver import MCPServer

server = MCPServer("web")


@server.tool()
async def fetch_url(url: str) -> str:
    """Fetch a web page and return its text."""
    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.text
