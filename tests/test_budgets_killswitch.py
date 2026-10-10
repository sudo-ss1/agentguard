"""Budgets (rate and cost) and the gateway-local kill switch."""

from datetime import UTC, datetime, timedelta

import pytest

from agentguard.gateway.checks import CallContext
from agentguard.gateway.identity import Identity
from agentguard.guards.budgets import BudgetConfig, BudgetGuard
from agentguard.guards.killswitch import KillSwitchCheck
from agentguard.guards.state import GuardState
from agentguard.identity.didkey import AgentKey
from agentguard.identity.vc import AgentProfile
from agentguard.tokens.biscuit import RootAuthority, authorize, delegate
from tests.gateway_helpers import ROOT, call, ctx, identity, receipts


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def ctx_for(who: Identity, tool="fetch_url"):
    return CallContext(who.profile.name, tool, "web", {}, identity=who)


@pytest.fixture
def state(tmp_path):
    return GuardState(tmp_path / "guards")


@pytest.fixture
def clock():
    return Clock()


def budget(state, clock, **overrides):
    return BudgetGuard(BudgetConfig(**overrides), state, clock)


# --- budgets -----------------------------------------------------------------------------------


def test_calls_under_the_rate_limit_pass(state, clock):
    """Positive control."""
    guard, agent = budget(state, clock), identity("research-bot")
    assert all(guard.check(ctx_for(agent)).verdict == "no-objection" for _ in range(30))


def test_rate_limit_denies_the_31st_fetch_and_the_window_slides(state, clock):
    guard, agent = budget(state, clock), identity("research-bot")
    for _ in range(30):
        guard.check(ctx_for(agent))
    denied = guard.check(ctx_for(agent))
    assert denied.verdict == "deny" and denied.attributes["limit"] == 30
    clock.t += 61
    assert guard.check(ctx_for(agent)).verdict == "no-objection"


def test_repeated_rate_denials_trip_the_kill_switch(state, clock):
    guard, agent = budget(state, clock), identity("research-bot")
    for _ in range(30):
        guard.check(ctx_for(agent))
    results = [guard.check(ctx_for(agent)) for _ in range(20)]
    assert [r.attributes.get("kill_switch") for r in results].count("tripped") == 1
    assert results[-1].attributes["kill_switch"] == "tripped"
    assert state.killed_reason(agent.profile.did, "research-bot", []) is not None


def test_a_passing_call_resets_the_trip_counter(state, clock):
    guard, agent = budget(state, clock, trip_after_rate_denials=3), identity("research-bot")
    for _ in range(30):
        guard.check(ctx_for(agent))
    guard.check(ctx_for(agent))
    guard.check(ctx_for(agent))
    clock.t += 61
    guard.check(ctx_for(agent))  # passes: counter back to 0
    assert state.killed_reason(agent.profile.did, "research-bot", []) is None


def test_cost_budget_exhaustion_trips_the_kill_switch(state, clock):
    guard = budget(state, clock, cost_budget=12)
    agent = identity("research-bot")
    assert guard.check(ctx_for(agent, "send_email")).verdict == "no-objection"  # 5
    assert guard.check(ctx_for(agent, "send_email")).verdict == "no-objection"  # 10
    result = guard.check(ctx_for(agent, "send_email"))  # would be 15 > 12
    assert result.verdict == "deny" and result.attributes["kill_switch"] == "tripped"


def test_budgets_are_per_agent(state, clock):
    guard = budget(state, clock)
    a, b = identity("research-bot"), identity("sub-agent")
    for _ in range(31):
        guard.check(ctx_for(a))
    assert guard.check(ctx_for(b)).verdict == "no-objection"


def test_reset_epoch_clears_budgets(state, clock):
    guard, agent = budget(state, clock), identity("research-bot")
    for _ in range(31):
        guard.check(ctx_for(agent))
    GuardState(state.dir).reset()  # e.g. `agentguard guards reset` from another process
    state.refresh()
    assert guard.check(ctx_for(agent)).verdict == "no-objection"


# --- kill switch -------------------------------------------------------------------------------


def seen(check: KillSwitchCheck, who: Identity) -> None:
    check.evaluate(ctx_for(who))  # the gateway records the token as a side effect


def test_kill_overrides_a_still_valid_token(state):
    agent = identity("research-bot")
    check = KillSwitchCheck(state, ROOT.public_key)
    assert check.evaluate(ctx_for(agent)).allowed
    state.kill("manual", name="research-bot")
    # the token itself still authorizes the call...
    assert authorize(agent.token, ROOT.public_key, agent.profile.did, "read_file").allowed
    decision = check.evaluate(ctx_for(agent, "read_file"))  # ...but the kill switch refuses it
    assert not decision.allowed and decision.policy_id == "kill-switch"


def test_kill_persists_across_restarts_and_revive_lifts_it(state):
    agent = identity("research-bot")
    state.kill("manual", did=agent.profile.did)
    restarted = GuardState(state.dir)
    assert restarted.killed_reason(agent.profile.did, "research-bot", []) == "manual"
    restarted.revive(did=agent.profile.did)
    assert GuardState(state.dir).killed_reason(agent.profile.did, "research-bot", []) is None


def _parent_and_sub():
    root = RootAuthority.generate()
    parent_key, sub_key = AgentKey.generate(), AgentKey.generate()
    expires = datetime.now(UTC) + timedelta(hours=1)
    parent_token = root.mint(parent_key.did, ["fetch_url"], expires)
    sub_token = delegate(
        parent_token,
        root.public_key,
        parent_key,
        sub_key.did,
        ["fetch_url"],
        datetime.now(UTC) + timedelta(minutes=5),
    )
    parent = Identity(
        AgentProfile("research-bot", parent_key.did, "s", "p", ("fetch_url",), "m"), parent_token
    )
    sub = Identity(AgentProfile("sub-agent", sub_key.did, "s", "p", ("fetch_url",), "m"), sub_token)
    return root, parent, sub


def test_killing_the_parent_revokes_its_delegations(state):
    root, parent, sub = _parent_and_sub()
    check = KillSwitchCheck(state, root.public_key)
    seen(check, parent)
    seen(check, sub)
    state.kill("manual", name="research-bot")
    assert not check.evaluate(ctx_for(sub)).allowed  # the sub's token derives from the parent's


def test_killing_a_sub_agent_leaves_its_parent_alone(state):
    root, parent, sub = _parent_and_sub()
    check = KillSwitchCheck(state, root.public_key)
    seen(check, parent)
    seen(check, sub)
    state.kill("manual", name="sub-agent")
    assert not check.evaluate(ctx_for(sub)).allowed
    assert check.evaluate(ctx_for(parent)).allowed


async def test_kill_switch_denial_at_the_gateway(gateway):
    gateway.guard_state.kill("incident 42", name="research-bot")
    result = await gateway.on_call_tool(ctx("research-bot"), call("read_file", path="notes.txt"))
    assert result.is_error and gateway.upstreams["files"].calls == []
    (receipt,) = receipts(gateway)
    assert receipt["policy_id"] == "kill-switch"
    attributes = receipt["reason"]["attributes"]
    assert attributes["kill_category"] == "manual"  # a fixed category, in the clear
    assert set(attributes["kill_reason"]) == {"commitment"}  # free text, committed
    assert "incident 42" not in gateway.config.receipts_path.read_text()
