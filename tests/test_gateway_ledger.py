"""The gateway on the ledger: a decision receipt before forwarding, an outcome after, one
gap-free chain for parallel calls, and salts that never matter to verification."""

import asyncio
import contextlib
import json

from agentguard.gateway.commitments import SaltStore
from agentguard.ledger import keys
from agentguard.ledger.canonical import parse_line
from agentguard.ledger.read import line_count
from agentguard.ledger.verify import verify
from agentguard.ledger.writer import CHECKPOINTS_FILE
from tests.gateway_helpers import call, ctx, receipts


def bodies(gw) -> list[dict]:
    return [parse_line(line)["body"] for line in gw.config.receipts_path.read_bytes().splitlines()]


def call_bodies(gw) -> list[dict]:
    """Without the control receipts the gateway writes when it pins its upstreams at start."""
    return [b for b in bodies(gw) if b["kind"] != "control"]


def check(gw):
    gw.ledger.checkpoint()
    public = keys.load_public(gw.config.ledger.roots_dir / keys.PUBLIC_KEY_FILE)
    return verify(gw.config.receipts_path, public, gw.config.ledger.roots_dir / CHECKPOINTS_FILE)


async def test_the_decision_is_on_record_before_the_call_is_forwarded(gateway):
    upstream = gateway.upstreams["files"]
    seen: list[int] = []
    original = upstream.call_tool

    async def spying(name, arguments):
        seen.append(line_count(gateway.config.receipts_path))
        return await original(name, arguments)

    upstream.call_tool = spying
    await gateway.on_call_tool(ctx("research-bot"), call("list_dir", path="/workspace"))
    kinds = [b["kind"] for b in call_bodies(gateway)]
    assert kinds == ["genesis", "decision", "outcome"]
    pinned = len(bodies(gateway)) - len(call_bodies(gateway))
    assert seen == [2 + pinned]  # genesis, pins and the decision were written before the call
    decision, outcome = call_bodies(gateway)[1:]
    assert decision["decision"] == "allow" and decision["agent_did"].startswith("did:key:")
    assert outcome["decision_seq"] == decision["seq"] and outcome["upstream_error"] is False
    (row,) = receipts(gateway)
    assert row["outcome"] == "recorded" and "result_scan" in row


async def test_a_denial_has_one_receipt(gateway):
    await gateway.on_call_tool(ctx("research-bot"), call("read_file", path="~/.ssh/id_rsa"))
    assert [b["kind"] for b in call_bodies(gateway)] == ["genesis", "decision"]
    assert gateway.upstreams["files"].calls == []


async def test_no_receipt_no_call(gateway, monkeypatch):
    def fail(kind, fields):
        raise OSError("disk full")

    monkeypatch.setattr(gateway.ledger, "append", fail)
    result = await gateway.on_call_tool(ctx("research-bot"), call("list_dir", path="/workspace"))
    assert result.is_error and "not made" in result.content[0].text
    assert gateway.upstreams["files"].calls == []


async def test_arguments_rfc8785_cannot_represent_are_not_forwarded(gateway):
    upstream = gateway.upstreams["files"]
    result = await gateway.on_call_tool(
        ctx("research-bot"), call("list_dir", path="/workspace", depth=2**60)
    )
    assert result.is_error and upstream.calls == []
    (row,) = receipts(gateway)  # refused, and still on record
    assert row["args_hash"] == "legacy-json" and row["decision"] == "deny"


async def test_parallel_calls_make_one_gap_free_chain(gateway):
    await asyncio.gather(
        *(
            gateway.on_call_tool(ctx("research-bot"), call("list_dir", path=f"/workspace/{i}"))
            for i in range(40)
        )
    )
    report = check(gateway)
    assert report.intact and report.outcome_unknown == []
    assert [b["seq"] for b in bodies(gateway)] == list(range(len(bodies(gateway))))
    assert len(call_bodies(gateway)) == 1 + 2 * 40


async def test_an_allowed_call_without_an_outcome_is_outcome_unknown(gateway):
    async def never_returns(name, arguments):
        raise asyncio.CancelledError  # the gateway stops mid-call

    gateway.upstreams["files"].call_tool = never_returns
    with contextlib.suppress(asyncio.CancelledError):
        await gateway.on_call_tool(ctx("research-bot"), call("list_dir", path="/workspace"))
    report = check(gateway)
    [decision] = [b for b in call_bodies(gateway) if b["kind"] == "decision"]
    assert report.intact and report.outcome_unknown == [decision["seq"]]


async def test_forgetting_a_salt_leaves_the_chain_valid(gateway):
    await gateway.on_call_tool(ctx("research-bot"), call("read_file", path="~/.ssh/id_rsa"))
    before = gateway.config.receipts_path.read_bytes()
    decision = call_bodies(gateway)[1]
    committed = json.dumps(decision["reason"]).split('"commitment": "')[1].split('"')[0]
    assert SaltStore(gateway.config.salts_path).forget(committed)
    assert gateway.config.receipts_path.read_bytes() == before  # not one byte changed
    assert check(gateway).intact  # and verify never needed the salts
