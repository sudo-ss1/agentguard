"""One MCP client connection per configured server, shared by the LLM agent and
the scripted driver. (langchain-mcp-adapters 0.3 does not support mcp 2.x yet.)"""

import json
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Any, Self

from langchain_core.tools import StructuredTool, ToolException
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client
from mcp.types import TextContent, Tool

from agentguard.identity.client import Credentials
from agentguard.identity.dpop import create_proof

AGENT_HEADER = "X-Agent-Id"  # an unverified name, sent when there are no credentials (baseline)


def _signing_hook(credentials: Credentials) -> Any:
    """Sign every POST: credential, capability token, and a DPoP proof for this exact message."""

    async def sign(request: Any) -> None:
        if request.method != "POST":
            return
        message = json.loads(request.content)
        htu = f"{request.url.scheme}://{request.url.netloc.decode()}{request.url.path}"
        if credentials.vc:
            request.headers["X-AgentGuard-Credential"] = credentials.vc
        if credentials.token:
            request.headers["Authorization"] = f"DPoP {credentials.token}"
        request.headers["DPoP"] = create_proof(
            credentials.key, "POST", htu, message, credentials.token
        )

    return sign


class ToolCallError(ToolException):
    """The tool server reported an error (or, from Phase 2, the gateway denied the call).

    A ToolException, so LangChain hands it back to the model instead of aborting the run.
    """


@dataclass
class ToolResult:
    text: str
    is_error: bool


class Toolbox:
    def __init__(self, servers: dict[str, str], identity: str | Credentials) -> None:
        """`identity` is a bare agent name (sent unverified) or credentials to sign with."""
        self.servers = servers
        self.identity = identity
        self.tools: dict[str, Tool] = {}
        self._connected: list[Client] = []
        self._clients: dict[str, Client] = {}  # tool name -> client
        self.call_log: list[tuple[str, dict[str, Any], ToolResult]] = []
        self._stack = AsyncExitStack()

    async def __aenter__(self) -> Self:
        for url in self.servers.values():
            if isinstance(self.identity, Credentials):
                http = create_mcp_http_client()
                http.event_hooks["request"].append(_signing_hook(self.identity))
            else:
                http = create_mcp_http_client(headers={AGENT_HEADER: self.identity})
            http = await self._stack.enter_async_context(http)
            client = Client(streamable_http_client(url, http_client=http))
            self._connected.append(await self._stack.enter_async_context(client))
        await self.refresh()
        return self

    async def refresh(self) -> None:
        """Re-list tools. A tool that disappears keeps its route, so a call to it still reaches
        the server (or gateway) and gets its answer there, the way a stale agent would."""
        self.tools = {}
        for client in self._connected:
            for tool in (await client.list_tools(cache_mode="bypass")).tools:
                self.tools[tool.name] = tool
                self._clients[tool.name] = client

    async def __aexit__(self, *exc: object) -> None:
        await self._stack.aclose()

    async def call(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        # A tool nobody listed still goes out if there is only one server to send it to (the
        # gateway): callers aren't limited to what they were shown, and the gateway should see
        # and record every attempt. With several servers there is no way to route it.
        client = self._clients.get(name) or (
            self._connected[0] if len(self._connected) == 1 else None
        )
        if client is not None:
            response = await client.call_tool(name, arguments)
            text = "\n".join(c.text for c in response.content if isinstance(c, TextContent))
            result = ToolResult(text, is_error=bool(response.is_error))
        else:
            result = ToolResult(f"unknown tool {name!r}", is_error=True)
        self.call_log.append((name, arguments, result))
        return result

    def langchain_tools(self) -> list[StructuredTool]:
        return [self._to_langchain(tool) for tool in self.tools.values()]

    def _to_langchain(self, tool: Tool) -> StructuredTool:
        async def invoke(**kwargs: Any) -> str:
            result = await self.call(tool.name, kwargs)
            if result.is_error:
                raise ToolCallError(result.text)
            return result.text

        return StructuredTool.from_function(
            coroutine=invoke,
            name=tool.name,
            description=tool.description or "",
            args_schema=tool.input_schema,
            handle_tool_error=True,
        )
