"""Human approval: which calls escalate, how a human answers, and failing closed."""

import asyncio
import json

import pytest

from agentguard.attacks import load_scenario, run_scripted
from agentguard.guards.approvals import decide, list_pending
from agentguard.lab_stack import local_lab
from tests.gateway_helpers import add_tool, call, ctx, identity, receipts

SENDER = identity("research-bot", tools=("send_email", "fetch_url", "read_file", "delete_file"))


@pytest.fixture
def gw(gateway):
    gateway.approvals.config.timeout_s = 0.6
    gateway.approvals.config.poll_s = 0.02
    add_tool(gateway, "send_email", "email", ["to", "subject", "body"])
    add_tool(gateway, "fetch_url", "web", ["url"])
    return gateway


def approvals_dir(gw):
    return gw.config.guards.state_dir / "approvals"


async def answer(gw, approve, approver="alice", after_s=0.05):
    """A human answering through the queue, as `agentguard approvals approve` does."""
    while True:
        await asyncio.sleep(after_s)
        pending = list_pending(approvals_dir(gw))
        if pending:
            assert decide(approvals_dir(gw), pending[0]["id"], approve, approver)
            return pending[0]


EMAIL = dict(to="sam@lab.test", subject="Q3", body="summary attached")


async def test_approved_call_goes_through_with_the_approval_recorded(gw):
    human = asyncio.create_task(answer(gw, approve=True))
    result = await gw.on_call_tool(ctx(SENDER), call("send_email", **EMAIL))
    request = await human
    assert not result.is_error and gw.upstreams["email"].calls
    assert request["arguments"] == EMAIL  # the approver saw exactly what they approved
    (receipt,) = receipts(gw)
    assert receipt["decision"] == "allow" and receipt["policy_id"] == "email-internal-only"
    assert receipt["approval"]["outcome"] == "approved"
    assert receipt["approval"]["approver"] == "alice"


async def test_human_denial(gw):
    human = asyncio.create_task(answer(gw, approve=False, approver="bob"))
    result = await gw.on_call_tool(ctx(SENDER), call("send_email", **EMAIL))
    await human
    assert result.is_error and not gw.upstreams["email"].calls
    (receipt,) = receipts(gw)
    assert receipt["denial_class"] == "approval-denied" and receipt["approval"]["approver"] == "bob"


async def test_timeout_denies_and_is_classed_as_a_timeout_not_a_block(gw):
    result = await gw.on_call_tool(ctx(SENDER), call("send_email", **EMAIL))
    assert result.is_error and not gw.upstreams["email"].calls
    (receipt,) = receipts(gw)
    assert receipt["policy_id"] == "approval-timeout"
    assert receipt["denial_class"] == "approval-timeout"
    assert list_pending(approvals_dir(gw)) == []  # voided: a late "approve" can't apply


async def test_a_late_approval_has_nothing_to_approve(gw):
    await gw.on_call_tool(ctx(SENDER), call("send_email", **EMAIL))
    assert not decide(approvals_dir(gw), "whatever", True, "alice")


async def test_a_decision_for_a_different_call_is_an_error(gw):
    async def tamper():
        while not list_pending(approvals_dir(gw)):
            await asyncio.sleep(0.02)
        request = list_pending(approvals_dir(gw))[0]
        (approvals_dir(gw) / "decided" / f"{request['id']}.json").write_text(
            json.dumps(
                {
                    "id": request["id"],
                    "args_sha256": "0" * 64,
                    "decision": "approve",
                    "approver": "mallory",
                }
            )
        )

    task = asyncio.create_task(tamper())
    result = await gw.on_call_tool(ctx(SENDER), call("send_email", **EMAIL))
    await task
    assert result.is_error
    assert receipts(gw)[0]["denial_class"] == "approval-error"


async def test_an_approval_covers_one_call_only(gw):
    human = asyncio.create_task(answer(gw, approve=True))
    first = await gw.on_call_tool(ctx(SENDER), call("send_email", **EMAIL))
    await human
    second = await gw.on_call_tool(ctx(SENDER), call("send_email", **EMAIL))  # nobody answers
    assert not first.is_error and second.is_error
    assert [r.get("denial_class") for r in receipts(gw)] == [None, "approval-timeout"]


async def test_taint_escalates_fetch_url(gw):
    assert not (await gw.on_call_tool(ctx(SENDER), call("fetch_url", url="http://a.test"))).is_error
    gw.taint.taint(SENDER.profile.did)
    tainted = await gw.on_call_tool(ctx(SENDER), call("fetch_url", url="http://a.test"))
    assert tainted.is_error
    assert receipts(gw)[-1]["approval"]["escalated_by"] == "approval-taint"


async def test_policy_denied_high_risk_call_never_reaches_a_human(gw):
    asked = []
    original = gw.approvals.request

    async def spy(*args, **kwargs):
        asked.append(args)
        return await original(*args, **kwargs)

    gw.approvals.request = spy
    await gw.on_call_tool(
        ctx(SENDER), call("send_email", to="attacker@evil.test", subject="s", body="b")
    )
    await gw.on_call_tool(ctx(SENDER), call("delete_file", path="/"))
    assert asked == []
    assert [r["denial_class"] for r in receipts(gw)] == ["policy", "policy"]


async def test_a_call_carrying_a_secret_is_denied_before_approval(gw):
    key = (gw.config.policy_dir.parents[1] / "lab/rootfs/home/agent/.ssh/id_rsa").read_text()
    result = await gw.on_call_tool(
        ctx(SENDER), call("send_email", to="sam@lab.test", subject="s", body=key)
    )
    assert result.is_error and list_pending(approvals_dir(gw)) == []
    assert receipts(gw)[0]["policy_id"] == "secret-scan"


def test_stale_requests_are_voided_at_startup(tmp_path):
    from agentguard.guards.approvals import ApprovalConfig, ApprovalQueue

    queue = ApprovalQueue(tmp_path / "approvals", ApprovalConfig())
    (tmp_path / "approvals" / "pending" / "old.json").write_text("{}")
    assert ApprovalQueue(tmp_path / "approvals", ApprovalConfig()).void_stale() == 1
    assert list_pending(tmp_path / "approvals") == [] and queue


# --- attacks 4 and 5 are still stopped by identity/token, not by approval ----------------------


@pytest.mark.parametrize(("scenario", "layer"), [(4, "capability-token"), (5, "identity")])
def test_attacks_4_and_5_never_reach_approval(scenario, layer):
    with local_lab(guarded=True) as lab:
        outcome = asyncio.run(run_scripted(load_scenario(scenario), lab))
        rows = [json.loads(line) for line in lab.receipts_path.read_text().splitlines()]
        pending = list_pending(lab.guard_state_dir / "approvals")
    assert not outcome.succeeded
    assert [(r["policy_id"], r["denial_class"]) for r in rows] == [(layer, "policy")]
    assert all("approval" not in r for r in rows) and pending == []
