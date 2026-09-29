"""Gateway routing, filtering and receipts, with fake upstreams (no network)."""

import json

from agentguard.gateway.identity import Identity
from tests.gateway_helpers import RESEARCH_BOT, call, ctx, identity, receipts, tool


async def test_list_shows_only_allowlisted_tools(gateway):
    names = {t.name for t in (await gateway.on_list_tools(ctx("research-bot"), None)).tools}
    # delete_file is in the credential but not on the gateway's allowlist
    assert names == {"read_file", "list_dir", "get_weather"}


async def test_list_is_also_bounded_by_the_credential(gateway):
    narrow = identity("research-bot", tools=("read_file",))
    names = {t.name for t in (await gateway.on_list_tools(ctx(narrow), None)).tools}
    assert names == {"read_file"}


async def test_unknown_or_missing_agent_sees_and_calls_nothing(gateway):
    for agent in ("intruder", None):
        assert (await gateway.on_list_tools(ctx(agent), None)).tools == []
        result = await gateway.on_call_tool(ctx(agent), call("read_file", path="notes.txt"))
        assert result.is_error
    assert gateway.upstreams["files"].calls == []
    # a verified agent the gateway doesn't know hits the allowlist; an unverified one, identity
    assert [r["policy_id"] for r in receipts(gateway)] == ["allowlist", "identity"]


async def test_token_is_checked_for_the_verified_holder(gateway):
    """A verified agent presenting someone else's token is refused by the token's holder
    caveat, before local policy."""
    borrowed = Identity(identity("research-bot").profile, RESEARCH_BOT.token)
    result = await gateway.on_call_tool(ctx(borrowed), call("read_file", path="notes.txt"))
    assert result.is_error and "capability-token" in result.content[0].text
    assert receipts(gateway)[0]["reason"] == {
        "rule": "capability-token",
        "summary": "token caveat failed: holder",
    }


async def test_allowed_call_is_forwarded_with_receipt(gateway):
    result = await gateway.on_call_tool(ctx("research-bot"), call("read_file", path="notes.txt"))
    assert not result.is_error and result.content[0].text == "files result 1"
    (receipt,) = receipts(gateway)
    assert receipt["decision"] == "allow" and receipt["policy_id"] == "files-read-workspace"
    assert "notes.txt" not in json.dumps(receipt)  # arguments are hashed, not stored


async def test_denied_call_never_reaches_upstream(gateway):
    result = await gateway.on_call_tool(
        ctx("research-bot"), call("read_file", path="~/.ssh/id_rsa")
    )
    assert result.is_error and "no-ssh-keys" in result.content[0].text
    assert gateway.upstreams["files"].calls == []
    assert receipts(gateway)[0]["decision"] == "deny"


async def test_shadowing_tool_from_later_upstream_is_ignored(gateway):
    await gateway.on_call_tool(ctx("research-bot"), call("read_file", path="notes.txt"))
    assert gateway.upstreams["shadow"].calls == []
    assert gateway.routes["read_file"][0] == "files"


async def test_rug_pull_hides_and_blocks_the_whole_server(gateway):
    gateway.upstreams["weather"].tools = [tool("get_weather", "now with hidden instructions")]
    listed = (await gateway.on_list_tools(ctx("research-bot"), None)).tools
    assert [t.description for t in listed if t.name == "get_weather"] == ["d"]  # verified copy
    await gateway.refresh()  # what the background loop does
    names = {t.name for t in (await gateway.on_list_tools(ctx("research-bot"), None)).tools}
    assert "get_weather" not in names
    result = await gateway.on_call_tool(ctx("research-bot"), call("get_weather"))
    assert result.is_error and "pin-quarantine" in result.content[0].text


async def test_undeclared_argument_is_denied(gateway):
    result = await gateway.on_call_tool(
        ctx("research-bot"), call("read_file", path="notes.txt", notes="smuggled")
    )
    assert result.is_error and "undeclared-arguments" in result.content[0].text
