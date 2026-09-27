"""The gateway's check pipeline. Each check can allow, deny or (Phase 4) ask for approval.

The first non-allow decision ends the call. Any exception is a deny: fail closed.
"""

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, Protocol

if TYPE_CHECKING:
    from agentguard.gateway.identity import Identity

Verdict = Literal["allow", "deny", "needs_approval"]


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: str
    policy_id: str

    @property
    def allowed(self) -> bool:
        return self.verdict == "allow"


@dataclass
class CallContext:
    agent_id: str | None  # the verified agent name (from its credential), None if unverified
    tool: str
    server: str | None  # upstream that serves the tool, None if unknown
    arguments: dict[str, Any]
    input_schema: dict[str, Any] = field(default_factory=dict)
    identity: "Identity | None" = None


class Check(Protocol):
    name: str

    def evaluate(self, ctx: CallContext) -> Decision: ...


def run_pipeline(checks: list[Check], ctx: CallContext) -> Decision:
    last = Decision("deny", "no checks configured", "no-checks")
    for check in checks:
        try:
            last = check.evaluate(ctx)
        except Exception as exc:
            return Decision("deny", f"{check.name} failed: {exc}", f"{check.name}-error")
        if not last.allowed:
            return last
    return last


class AllowlistCheck:
    """Per-agent tool allowlist from gateway.yaml. Unknown agents get nothing."""

    name = "allowlist"

    def __init__(self, allowed: dict[str, set[str]]) -> None:
        self.allowed = allowed

    def permits(self, agent_id: str | None, tool: str) -> bool:
        return agent_id is not None and tool in self.allowed.get(agent_id, set())

    def evaluate(self, ctx: CallContext) -> Decision:
        if self.permits(ctx.agent_id, ctx.tool):
            return Decision("allow", "tool on agent allowlist", "allowlist")
        return Decision(
            "deny", f"{ctx.tool!r} is not on the allowlist for agent {ctx.agent_id!r}", "allowlist"
        )


class ArgumentSchemaCheck:
    """Deny arguments the pinned input schema does not declare (e.g. a smuggled `notes`)."""

    name = "arguments"

    def evaluate(self, ctx: CallContext) -> Decision:
        declared = set(ctx.input_schema.get("properties", {}))
        unknown = sorted(set(ctx.arguments) - declared)
        if unknown:
            return Decision(
                "deny", f"arguments not in the pinned schema: {unknown}", "undeclared-arguments"
            )
        return Decision("allow", "arguments match the pinned schema", "arguments")
