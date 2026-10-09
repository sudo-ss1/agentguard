"""Runtime guards (Phase 4): the stage that runs after policy has allowed a call.

The guiding rule is that detection supplements policy and never replaces it. That is
enforced by structure, not convention:

- A guard's verdict is `no-objection`, `deny` or `escalate`. There is no allow, so a guard
  cannot grant anything.
- `combine` returns the policy decision unchanged when policy denied, before looking at any
  guard. Otherwise it takes the strictest verdict: deny, then escalate, then policy's allow.
- A human approval (approvals.py) is only ever asked for an `escalate`, so it can turn an
  escalation into allow but can never turn a deny into allow.
- A guard that raises or returns anything unexpected is a deny: fail closed.
"""

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from agentguard.gateway.checks import CallContext, Decision

GuardVerdict = Literal["no-objection", "deny", "escalate"]
_VERDICTS = ("no-objection", "deny", "escalate")


@dataclass(frozen=True)
class GuardResult:
    verdict: GuardVerdict
    reason: str = ""
    guard_id: str = ""
    # Like Decision.attributes: in memory only, redacted by the receipt log (option C). They can
    # hold a matched secret, so they are left out of the repr (logs, tracebacks, test output).
    attributes: dict[str, Any] = field(default_factory=dict, repr=False)


NO_OBJECTION = GuardResult("no-objection")


class Guard(Protocol):
    name: str

    def check(self, ctx: CallContext) -> GuardResult: ...


def run_guards(guards: list[Guard], ctx: CallContext) -> list[GuardResult]:
    """Run guards in order and stop at the first deny. A guard that raises or returns
    something that isn't a GuardResult with a known verdict is a deny."""
    results: list[GuardResult] = []
    for guard in guards:
        try:
            result = guard.check(ctx)
            if not isinstance(result, GuardResult) or result.verdict not in _VERDICTS:
                raise TypeError(f"guard returned {result!r}")
        except Exception as exc:
            result = GuardResult(
                "deny",
                f"{guard.name} failed ({type(exc).__name__})",
                f"{guard.name}-error",
                {"error_message": str(exc)},
            )
        results.append(result)
        if result.verdict == "deny":
            break
    return results


def combine(policy: Decision, guard_results: list[GuardResult]) -> Decision:
    """The final decision. It can only be as permissive as policy, never more."""
    if not policy.allowed:
        return policy  # guards are never consulted for a policy denial
    for result in guard_results:
        if result.verdict == "deny":
            return Decision("deny", result.reason, result.guard_id, result.attributes)
    for result in guard_results:
        if result.verdict == "escalate":
            return Decision("needs_approval", result.reason, result.guard_id, result.attributes)
    unknown = [r for r in guard_results if r.verdict not in _VERDICTS]
    if unknown:  # defensive: run_guards already maps these to deny
        return Decision("deny", "guard returned an unknown verdict", "guard-error")
    return policy
