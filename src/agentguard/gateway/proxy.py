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
from agentguard.guards.approvals import ApprovalQueue, ApprovalRequirement, TaintTracker
from agentguard.guards.budgets import BudgetGuard
from agentguard.guards.killswitch import KillSwitchCheck
from agentguard.guards.result_scan import ResultScanner
from agentguard.guards.secrets import SecretScanGuard
from agentguard.guards.state import GuardState
from agentguard.policy.cedar import CedarCheck
from agentguard.tokens.biscuit import load_root_public_key

log = logging.getLogger(__name__)


def _identity(ctx: ServerRequestContext[Any, Any]) -> Identity:
    return identity_of(ctx.request)


def _walk_strings(value: Any, out: list[str]) -> None:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            _walk_strings(v, out)
    elif isinstance(value, list):
        for v in value:
            _walk_strings(v, out)


def _replace_strings(value: Any, it: Any) -> Any:
    if isinstance(value, str):
        return next(it)
    if isinstance(value, dict):
        return {k: _replace_strings(v, it) for k, v in value.items()}
    if isinstance(value, list):
        return [_replace_strings(v, it) for v in value]
    return value


def _result_strings(result: types.CallToolResult) -> list[str]:
    """Every string in a result the agent could read: text blocks, then structured content."""
    out = [c.text for c in result.content if isinstance(c, types.TextContent)]
    _walk_strings(result.structured_content, out)
    return out


def _with_strings(result: types.CallToolResult, strings: list[str]) -> types.CallToolResult:
    """The same result with its strings replaced, in the order `_result_strings` gave them."""
    it = iter(strings)
    content = [
        c.model_copy(update={"text": next(it)}) if isinstance(c, types.TextContent) else c
        for c in result.content
    ]
    structured = _replace_strings(result.structured_content, it)
    return types.CallToolResult(
        content=content, is_error=result.is_error, structured_content=structured
    )


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
        approvals = config.guards.approvals
        self.taint = TaintTracker(approvals.taint_ttl_s, self.guard_state)
        self.approvals = ApprovalQueue(config.guards.state_dir / "approvals", approvals)
        voided = self.approvals.void_stale()
        if voided:
            log.warning("voided %d approval request(s) left by a previous gateway run", voided)
        # Secrets first: nobody should be asked to approve a call that carries one.
        self.pre_guards: list[Guard] = [
            SecretScanGuard(),
            ApprovalRequirement(approvals, self.taint),
        ]
        # Result scanning: every tool name the gateway knows can be a lure in a tool result.
        self.scanner = ResultScanner(
            config.guards.injection, {t for p in config.agents.values() for t in p.tools}
        )
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

        approval: dict[str, Any] | None = None
        if decision.verdict == "needs_approval":  # only reachable when policy allowed
            waited = time.perf_counter()
            answer = await self.approvals.request(call, decision.reason)
            approval = {
                "id": answer.request_id,
                "outcome": answer.outcome,
                "approver": answer.approver,
                "escalated_by": decision.policy_id,
                "wait_ms": round((time.perf_counter() - waited) * 1000, 1),
            }
            if answer.outcome == "approved":
                decision = Decision("allow", f"approved by {answer.approver}", policy.policy_id)
            else:
                decision = Decision(
                    "deny", f"approval {answer.outcome}", f"approval-{answer.outcome}"
                )
        if decision.allowed:  # budgets last: after Cedar and approval, as the plan orders
            decision = combine(decision, run_guards(self.budget_guards, call))

        if not decision.allowed:
            if not policy.allowed:
                denial_class = "policy"
            elif approval is not None and approval["outcome"] != "approved":
                denial_class = f"approval-{approval['outcome']}"  # never "the gateway blocked it"
            else:
                denial_class = "guard"
            self.receipts.write(
                call, decision, decision_ms=decided_ms, denial_class=denial_class, approval=approval
            )
            return _error(
                f"AgentGuard denied {params.name}: {decision.reason} [policy: {decision.policy_id}]"
            )
        assert server is not None
        try:
            result = await self.upstreams[server].call_tool(params.name, call.arguments)
        except Exception as exc:
            self.receipts.write(
                call, decision, decision_ms=decided_ms, approval=approval, upstream_exception=exc
            )
            return _error(f"upstream {server} failed: {exc}")
        visible, scan = await asyncio.to_thread(
            self.scanner.scan, params.name, server, _result_strings(result)
        )
        if scan.taint and identity.profile is not None:
            self.taint.taint(identity.profile.did)
        self.receipts.write(
            call,
            decision,
            decision_ms=decided_ms,
            approval=approval,
            upstream_error=bool(result.is_error),
            result_scan=scan.record(),
        )
        if scan.withhold:  # the visible text itself matched, or it couldn't be fully scanned
            why = (
                "flagged as possible prompt injection: " + ", ".join(scan.findings)
                if scan.visible_flagged
                else f"could not be fully scanned: {scan.error}"
            )
            follow_up = (
                " High-risk actions now need human approval for a while." if scan.taint else ""
            )
            return _error(f"AgentGuard withheld this tool result ({why}).{follow_up}")
        return _with_strings(result, visible)  # hidden content stripped
