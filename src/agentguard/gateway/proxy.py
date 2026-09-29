"""The AgentGuard gateway: an MCP server in front of the real MCP tool servers.

tools/list returns the gateway's own verified copies of tool definitions, filtered to what the
calling agent may use, so a changed upstream description never reaches the agent. A background
loop re-fetches upstream tool lists and quarantines any server whose pinned tools changed.
(The list handler must stay cheap: the MCP HTTP transport calls it before every tools/call.)

tools/call runs the check pipeline, writes a receipt, and forwards the call only if every
check allows it.

Identity (Phase 3): `IdentityMiddleware` verifies each request's credential, DPoP proof and
capability token before the handlers run. The agent name used by the allowlist and Cedar is
the one in the verified credential. X-Agent-Id is ignored.
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
from agentguard.gateway.commitments import SaltStore
from agentguard.gateway.config import GatewayConfig
from agentguard.gateway.identity import (
    CapabilityTokenCheck,
    Identity,
    IdentityCheck,
    IdentityMiddleware,
    IdentityVerifier,
    identity_of,
)
from agentguard.gateway.pins import PinStore
from agentguard.gateway.receipts import ReceiptLog
from agentguard.guards import Guard, combine, run_guards
from agentguard.guards.budgets import BudgetGuard
from agentguard.guards.killswitch import KillSwitchCheck
from agentguard.guards.state import GuardState
from agentguard.policy.cedar import CedarCheck
from agentguard.tokens.biscuit import load_root_public_key

log = logging.getLogger(__name__)


def _identity(ctx: ServerRequestContext[Any, Any]) -> Identity:
    return identity_of(ctx.request)


def _error(text: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=True)


class Gateway:
    def __init__(self, config: GatewayConfig) -> None:
        self.config = config
        root = load_root_public_key(config.identity.biscuit_root_key)
        self.verifier = IdentityVerifier({config.identity.issuer_did}, root)
        self.pins = PinStore(config.pins_path)
        self.allowlist = AllowlistCheck({a: set(p.tools) for a, p in config.agents.items()})
        self.guard_state = GuardState(config.guards.state_dir)
        # Who is calling (and whether they've been stopped), then what their token lets them
        # do, then local policy.
        self.checks: list[Check] = [
            IdentityCheck(),
            KillSwitchCheck(self.guard_state, root),
            CapabilityTokenCheck(root),
            self.pins,
            self.allowlist,
            ArgumentSchemaCheck(),
            CedarCheck(config.policy_dir),
        ]
        # Guard stage (Phase 4): runs only after policy allows a call, and can only add a denial
        # or an escalation to human approval (see agentguard.guards).
        self.pre_guards: list[Guard] = []
        # Budgets run last, after Cedar and approval, as the plan orders.
        self.budget_guards: list[Guard] = [BudgetGuard(config.guards.budgets, self.guard_state)]
        self.receipts = ReceiptLog(config.receipts_path, SaltStore(config.salts_path))
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

    def app(self, host: str) -> Any:
        """The HTTP app: the MCP server behind identity verification."""
        return IdentityMiddleware(self.server().streamable_http_app(host=host), self.verifier)

    async def on_list_tools(
        self, ctx: ServerRequestContext[Any, Any], params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        identity = _identity(ctx)
        if identity.profile is None:
            return types.ListToolsResult(tools=[])
        agent, credential_tools = identity.profile.name, set(identity.profile.allowed_tools)
        return types.ListToolsResult(
            tools=[
                tool
                for server, tool in self.routes.values()
                if server not in self.pins.quarantined
                and self.allowlist.permits(agent, tool.name)
                and tool.name in credential_tools
            ]
        )

    async def on_call_tool(
        self, ctx: ServerRequestContext[Any, Any], params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        start = time.perf_counter()
        server, tool = self.routes.get(params.name, (None, None))
        identity = _identity(ctx)
        call = CallContext(
            identity.profile.name if identity.profile else None,
            params.name,
            server,
            dict(params.arguments or {}),
            tool.input_schema if tool else {},
            identity,
        )
        if server is None:
            policy = Decision("deny", "unknown tool", "unknown-tool")
        else:
            policy = run_pipeline(self.checks, call)
        guard_results = run_guards(self.pre_guards, call) if policy.allowed else []
        decision = combine(policy, guard_results)
        decided_ms = round((time.perf_counter() - start) * 1000, 3)

        if decision.allowed:  # budgets last: after Cedar and approval, as the plan orders
            decision = combine(decision, run_guards(self.budget_guards, call))

        if not decision.allowed:
            denial_class = "policy" if not policy.allowed else "guard"
            self.receipts.write(call, decision, decision_ms=decided_ms, denial_class=denial_class)
            return _error(
                f"AgentGuard denied {params.name}: {decision.reason} [policy: {decision.policy_id}]"
            )
        assert server is not None
        try:
            result = await self.upstreams[server].call_tool(params.name, call.arguments)
        except Exception as exc:
            self.receipts.write(call, decision, decision_ms=decided_ms, upstream_exception=exc)
            return _error(f"upstream {server} failed: {exc}")
        self.receipts.write(
            call,
            decision,
            decision_ms=decided_ms,
            upstream_error=bool(result.is_error),
        )
        return types.CallToolResult(
            content=result.content,
            is_error=result.is_error,
            structured_content=result.structured_content,
        )
