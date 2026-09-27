"""The AgentGuard gateway: an MCP server in front of the real MCP tool servers.

tools/list returns the gateway's own verified copies of tool definitions, filtered to what the
calling agent may use, so a changed upstream description never reaches the agent. A background
loop re-fetches upstream tool lists and quarantines any server whose pinned tools changed.
(The list handler must stay cheap: the MCP HTTP transport calls it before every tools/call.)

tools/call runs the check pipeline, writes a receipt, and forwards the call only if every
check allows it.

Phase 2 identifies the agent by the X-Agent-Id header; Phase 3 replaces it with tokens.
"""

import asyncio
import logging
import time
from contextlib import AsyncExitStack
from typing import Any, Self

from mcp import Client, types
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server

from agentguard.gateway.checks import (
    AllowlistCheck,
    ArgumentSchemaCheck,
    CallContext,
    Check,
    Decision,
    run_pipeline,
)
from agentguard.gateway.config import GatewayConfig
from agentguard.gateway.pins import PinStore
from agentguard.gateway.receipts import ReceiptLog
from agentguard.policy.cedar import CedarCheck

log = logging.getLogger(__name__)
AGENT_HEADER = "x-agent-id"


def _agent_id(ctx: ServerRequestContext[Any, Any]) -> str | None:
    request = ctx.request
    return request.headers.get(AGENT_HEADER) if request is not None else None


def _error(text: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=True)


class Gateway:
    def __init__(self, config: GatewayConfig) -> None:
        self.config = config
        self.pins = PinStore(config.pins_path)
        self.allowlist = AllowlistCheck({a: set(p.tools) for a, p in config.agents.items()})
        self.checks: list[Check] = [
            self.pins,
            self.allowlist,
            ArgumentSchemaCheck(),
            CedarCheck(config.policy_dir),
        ]
        self.receipts = ReceiptLog(config.receipts_path)
        self.upstreams: dict[str, Client] = {}
        self.routes: dict[str, tuple[str, types.Tool]] = {}  # tool name -> (server, tool)
        self._stack = AsyncExitStack()
        self._refresher: asyncio.Task[None] | None = None

    async def __aenter__(self) -> Self:
        for name, url in self.config.upstreams.items():
            self.upstreams[name] = await self._stack.enter_async_context(Client(url))
        await self.refresh()
        self._refresher = asyncio.create_task(self._refresh_loop())
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._refresher:
            self._refresher.cancel()
        await self._stack.aclose()

    async def _refresh_loop(self) -> None:
        while True:
            await asyncio.sleep(self.config.refresh_interval_s)
            try:
                await self.refresh()
            except Exception:
                log.exception("refresh failed; keeping the last verified tool list")

    async def refresh(self) -> None:
        routes: dict[str, tuple[str, types.Tool]] = {}
        for server, client in self.upstreams.items():
            try:
                tools = (await client.list_tools(cache_mode="bypass")).tools
            except Exception:
                log.exception("listing tools from %s failed; its tools are unavailable", server)
                continue
            self.pins.verify(server, tools)
            for tool in tools:
                if tool.name in routes:  # tool shadowing: the first upstream in config wins
                    log.warning(
                        "%s also offers %r; ignored in favour of %s",
                        server,
                        tool.name,
                        routes[tool.name][0],
                    )
                    continue
                routes[tool.name] = (server, tool)
        self.routes = routes

    def server(self) -> Server[Any]:
        return Server(
            "agentguard-gateway", on_list_tools=self.on_list_tools, on_call_tool=self.on_call_tool
        )

    async def on_list_tools(
        self, ctx: ServerRequestContext[Any, Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        agent = _agent_id(ctx)
        return types.ListToolsResult(
            tools=[
                tool
                for server, tool in self.routes.values()
                if server not in self.pins.quarantined and self.allowlist.permits(agent, tool.name)
            ]
        )

    async def on_call_tool(
        self, ctx: ServerRequestContext[Any, Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        start = time.perf_counter()
        server, tool = self.routes.get(params.name, (None, None))
        call = CallContext(
            _agent_id(ctx),
            params.name,
            server,
            dict(params.arguments or {}),
            tool.input_schema if tool else {},
        )
        if server is None:
            decision = Decision("deny", f"unknown tool {params.name!r}", "unknown-tool")
        else:
            decision = run_pipeline(self.checks, call)
        decided_ms = round((time.perf_counter() - start) * 1000, 3)

        if not decision.allowed:  # needs_approval is denied until Phase 4 adds approvals
            self.receipts.write(call, decision, decision_ms=decided_ms)
            return _error(
                f"AgentGuard denied {params.name}: {decision.reason} [policy: {decision.policy_id}]"
            )
        assert server is not None
        try:
            result = await self.upstreams[server].call_tool(params.name, call.arguments)
        except Exception as exc:
            self.receipts.write(call, decision, decision_ms=decided_ms, upstream_error=repr(exc))
            return _error(f"upstream {server} failed: {exc}")
        self.receipts.write(
            call, decision, decision_ms=decided_ms, upstream_error=bool(result.is_error)
        )
        return types.CallToolResult(
            content=result.content,
            is_error=result.is_error,
            structured_content=result.structured_content,
        )
