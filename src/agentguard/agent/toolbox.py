"""One MCP client connection per configured server, shared by the LLM agent and
the scripted driver. (langchain-mcp-adapters 0.3 does not support mcp 2.x yet.)"""

from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Any, Self

from langchain_core.tools import StructuredTool, ToolException
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client
from mcp.types import TextContent, Tool

AGENT_HEADER = "X-Agent-Id"  # Phase 2 identity; Phase 3 replaces it with capability tokens


class ToolCallError(ToolException):
    """The tool server reported an error (or, from Phase 2, the gateway denied the call).

    A ToolException, so LangChain hands it back to the model instead of aborting the run.
    """


@dataclass
class ToolResult:
    text: str
    is_error: bool


class Toolbox:
    def __init__(self, servers: dict[str, str], agent_id: str) -> None:
        self.servers = servers
        self.agent_id = agent_id
        self.tools: dict[str, Tool] = {}
        self._connected: list[Client] = []
        self._clients: dict[str, Client] = {}  # tool name -> client
        self.call_log: list[tuple[str, dict[str, Any], ToolResult]] = []
        self._stack = AsyncExitStack()

    async def __aenter__(self) -> Self:
        for url in self.servers.values():
            http = await self._stack.enter_async_context(
                create_mcp_http_client(headers={AGENT_HEADER: self.agent_id})
            )
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
        if name in self._clients:
            response = await self._clients[name].call_tool(name, arguments)
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
