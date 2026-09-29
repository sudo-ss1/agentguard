"""The guiding rule: detection supplements policy and never replaces it.

Guards (scanners, approvals, budgets) can only add a denial or an escalation. A clean guard
result must never allow a call that the policy stage (identity, token, pins, allowlist,
arguments, Cedar) denied.
"""

import pytest

from agentguard.gateway.checks import CallContext, Decision
from agentguard.gateway.identity import Identity
from agentguard.guards import GuardResult, combine, run_guards
from tests.gateway_helpers import RESEARCH_BOT, call, ctx, identity, receipts

POLICY_DENY = Decision("deny", "no policy permits this call", "default-deny", {"path": "/"})
POLICY_ALLOW = Decision("allow", "permitted", "files-read-workspace")
CTX = CallContext("research-bot", "read_file", "files", {"path": "notes.txt"})


class Fixed:
    def __init__(self, result, name="fixed"):
        self.result, self.name, self.calls = result, name, 0

    def check(self, ctx):
        self.calls += 1
        return self.result


@pytest.mark.parametrize(
    "results",
    [
        [],
        [GuardResult("no-objection")],
        [GuardResult("escalate", "risky", "approval")],
        [GuardResult("deny", "secret", "secret-scan")],
    ],
)
def test_combine_returns_the_policy_denial_unchanged(results):
    assert combine(POLICY_DENY, results) is POLICY_DENY


def test_strictest_guard_verdict_wins_when_policy_allows():
    escalate = GuardResult("escalate", "needs a human", "approval")
    deny = GuardResult("deny", "secret found", "secret-scan")
    assert combine(POLICY_ALLOW, []) is POLICY_ALLOW
    assert combine(POLICY_ALLOW, [GuardResult("no-objection")]) is POLICY_ALLOW
    assert combine(POLICY_ALLOW, [escalate]).verdict == "needs_approval"
    assert combine(POLICY_ALLOW, [escalate, deny]).policy_id == "secret-scan"


def test_a_guard_cannot_express_allow():
    """There is no allow verdict. A guard that returns one anyway is treated as a failure."""
    rogue = Fixed(GuardResult("allow", "trust me", "rogue"))  # type: ignore[arg-type]
    (result,) = run_guards([rogue], CTX)
    assert result.verdict == "deny" and result.guard_id == "fixed-error"


def test_a_guard_that_raises_denies():
    class Broken:
        name = "broken"

        def check(self, ctx):
            raise RuntimeError("model file missing")

    (result,) = run_guards([Broken()], CTX)
    assert result.verdict == "deny" and result.guard_id == "broken-error"
    assert combine(POLICY_ALLOW, [result]).verdict == "deny"


def test_guards_stop_at_the_first_deny():
    later = Fixed(GuardResult("no-objection"), "later")
    run_guards([Fixed(GuardResult("deny", "x", "first")), later], CTX)
    assert later.calls == 0


# --- through the real gateway ----------------------------------------------------------------

POLICY_DENIED_CALLS = [
    ("research-bot", call("read_file", path="~/.ssh/id_rsa"), "no-ssh-keys"),
    ("research-bot", call("read_file", path="/workspace/../etc/passwd"), "default-deny"),
    ("research-bot", call("delete_file", path="/"), "allowlist"),  # not on this agent's list
    (None, call("read_file", path="notes.txt"), "identity"),
    ("borrowed", call("read_file", path="notes.txt"), "capability-token"),
    ("research-bot", call("no_such_tool"), "unknown-tool"),
]


@pytest.mark.parametrize(("who", "params", "policy_id"), POLICY_DENIED_CALLS)
async def test_clean_guards_never_loosen_a_policy_denial(gateway, who, params, policy_id):
    clean = Fixed(GuardResult("no-objection"), "clean-scanner")
    gateway.pre_guards = [clean]
    if who == "borrowed":  # a verified agent holding someone else's token
        who = Identity(identity("research-bot").profile, RESEARCH_BOT.token)
    result = await gateway.on_call_tool(ctx(who), params)
    assert result.is_error
    (receipt,) = receipts(gateway)
    assert receipt["decision"] == "deny" and receipt["policy_id"] == policy_id
    assert clean.calls == 0  # never even consulted for a policy denial


async def test_guards_are_consulted_when_policy_allows(gateway):
    """Control: the clean guard is wired in, so the zero-call assertions above mean something."""
    clean = Fixed(GuardResult("no-objection"), "clean-scanner")
    gateway.pre_guards = [clean]
    result = await gateway.on_call_tool(ctx("research-bot"), call("read_file", path="notes.txt"))
    assert not result.is_error and clean.calls == 1


async def test_a_guard_denial_is_added_on_top_of_a_policy_allow(gateway):
    gateway.pre_guards = [Fixed(GuardResult("deny", "secret found", "secret-scan"), "secrets")]
    result = await gateway.on_call_tool(ctx("research-bot"), call("read_file", path="notes.txt"))
    assert result.is_error and receipts(gateway)[0]["policy_id"] == "secret-scan"
    assert gateway.upstreams["files"].calls == []
