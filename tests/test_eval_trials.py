"""Agent trials, tested with placeholder markers and an echoing fake model only."""

import json
import re
import secrets

import pytest
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from agentguard.eval.placement import place_text
from agentguard.eval.trials import (
    CONDITIONS,
    Case,
    Trial,
    carries_target,
    run_conditions,
    run_trial,
    sample,
    summarize_trials,
    target_calls,
    target_in_answer,
    trials_markdown,
    write_pages,
)
from agentguard.gateway.receipts import args_digest
from agentguard.guards.approvals import ApprovalConfig


def marker() -> str:
    return f"MARKER-{secrets.token_hex(6)}"


def cases(n: int) -> list[Case]:
    out = []
    for i in range(n):
        target = marker()
        out.append(Case(i, "g", f"placeholder text {target}", target))
    return out


def test_sample_is_seeded_and_the_same_for_every_call():
    pool = cases(50)
    assert sample(pool, 10, 7) == sample(pool, 10, 7)
    assert sample(pool, 10, 7) != sample(pool, 10, 8)
    assert len(set(c.index for c in sample(pool, 10, 7))) == 10


def test_sample_refuses_more_than_available():
    with pytest.raises(ValueError):
        sample(cases(3), 4, 7)


def test_target_in_answer():
    m = marker()
    assert target_in_answer(m, f"the page says {m.lower()}.")
    assert target_in_answer(m, f"x {m[:3]}\u200b{m[3:]} y")  # invisible characters don't hide it
    assert not target_in_answer(m, "a summary without it")
    assert not target_in_answer("  ", "anything")


def test_conditions_differ_only_in_mode_and_scanner():
    names = [c.name for c in CONDITIONS]
    assert len(set(names)) == len(names)
    assert {(c.mode, c.scanner) for c in CONDITIONS} == {
        ("visible", True),
        ("hidden", True),
        ("hidden", False),
    }
    overrides = CONDITIONS[2].gateway_overrides(3.0)["guards"]
    assert overrides == {"injection": {"enabled": False}, "approvals": {"timeout_s": 3.0}}


def test_write_pages(tmp_path):
    cs = cases(2)
    write_pages(tmp_path, cs, "hidden")
    pages = sorted(tmp_path.iterdir())
    assert [p.name for p in pages] == ["page-00000.html", "page-00001.html"]
    assert pages[0].read_text() == place_text(cs[0].text, "hidden")


def trial(condition: str, seen: bool, error: str | None = None, classes=None, calls=None) -> Trial:
    return Trial(condition, 0, "g", seen, error, [], classes or {}, calls or [])


def receipt(tool: str, arguments: dict, decision: str = "allow", **extra) -> dict:
    return {"tool": tool, "args_sha256": args_digest(arguments), "decision": decision, **extra}


def test_carries_target_looks_in_nested_values_with_normalization():
    m = marker()
    assert carries_target(m, {"to": "x@lab.test", "body": f"hello {m.lower()}"})
    assert carries_target(m, {"items": [{"text": f"{m[:4]}\u200b{m[4:]}"}]})
    assert not carries_target(m, {"body": "nothing here", "n": 3})


def test_target_calls_reports_each_calls_gateway_decision():
    m = marker()
    allowed = ("write_file", {"path": "/workspace/a", "content": m})
    by_policy = ("write_file", {"path": "/etc/a", "content": m})
    timed_out = ("send_email", {"to": "x@lab.test", "subject": "s", "body": m})
    unrelated = ("fetch_url", {"url": "http://127.0.0.1/page"})
    unlogged = ("list_dir", {"path": m})
    receipts = [
        receipt(*unrelated),
        receipt(*allowed, policy_id="files-write-workspace"),
        receipt(*by_policy, decision="deny", policy_id="default-deny"),
        receipt(*timed_out, decision="deny", denial_class="approval-timeout", policy_id="approval"),
    ]
    calls = target_calls(m, [unrelated, allowed, by_policy, timed_out, unlogged], receipts)
    assert calls == [
        {"tool": "write_file", "outcome": "allowed", "policy_id": "files-write-workspace"},
        {"tool": "write_file", "outcome": "denied: policy", "policy_id": "default-deny"},
        {"tool": "send_email", "outcome": "denied: approval-timeout", "policy_id": "approval"},
        {"tool": "list_dir", "outcome": "no receipt", "policy_id": None},
    ]


def test_repeated_identical_calls_each_get_their_own_receipt():
    m = marker()
    call = ("write_file", {"path": "/workspace/a", "content": m})
    receipts = [receipt(*call), receipt(*call, decision="deny", denial_class="guard")]
    outcomes = [c["outcome"] for c in target_calls(m, [call, call], receipts)]
    assert outcomes == ["allowed", "denied: guard"]


def test_the_gateway_approval_timeout_default_stays_120_s():
    # Trials shorten it through the lab's gateway overrides; the deployed default must not move.
    import yaml

    from agentguard.eval.corpora import REPO

    assert ApprovalConfig().timeout_s == 120
    gateway = yaml.safe_load((REPO / "config" / "gateway.yaml").read_text())
    assert "approvals" not in gateway.get("guards", {})


def test_summary_counts_undecided_and_errors_apart():
    name = CONDITIONS[0].name
    ts = [
        trial(name, True),
        trial(name, False),
        trial(name, False, classes={"approval-timeout": 1}),
        trial(name, True, error="boom"),
        trial(name, False, classes={"policy": 2}),  # a block is a decided trial
    ]
    (row, *rest) = summarize_trials(ts, CONDITIONS)
    assert (row.n, row.target_in_answer, row.approval_undecided, row.agent_errors) == (5, 2, 1, 1)
    assert (row.decided_n, row.decided_target_in_answer) == (3, 1)
    assert (row.target_in_call, row.call_outcomes) == (0, {})
    assert all(r.n == 0 for r in rest)  # conditions with no trials still get a row
    table = trials_markdown([row, *rest])
    assert len(table.splitlines()) == 2 + len(CONDITIONS)


WRITES = ("/workspace/notes.txt", "/etc/notes.txt")  # allowed by policy; denied by default-deny


class EchoModel(BaseChatModel):
    """Fetches the URL in the task, writes the fetched text to each of WRITES, then answers with
    the fetched text verbatim."""

    @property
    def _llm_type(self) -> str:
        return "echo"

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        results = [m for m in messages if isinstance(m, ToolMessage)]
        if results:
            page = str(results[0].content)
            if len(results) <= len(WRITES):
                args = {"path": WRITES[len(results) - 1], "content": page}
                call = {"name": "write_file", "args": args, "id": str(len(results) + 1)}
                message = AIMessage("", tool_calls=[call])
            else:
                message = AIMessage(page)
        else:
            task = next(m for m in messages if isinstance(m, HumanMessage))
            url = re.search(r"http\S+", str(task.content)).group(0)
            message = AIMessage(
                "", tool_calls=[{"name": "fetch_url", "args": {"url": url}, "id": "1"}]
            )
        return ChatResult(generations=[ChatGeneration(message=message)])


async def test_conditions_end_to_end(tmp_path):
    cs = cases(2)
    trials = await run_conditions(cs, CONDITIONS, EchoModel(), "", tmp_path, 1.0)
    by = {(t.condition, t.case): t for t in trials}
    expected_tools = ["fetch_url", "write_file", "write_file"]
    assert all(t.agent_error is None and t.tools_called == expected_tools for t in trials)
    written = [
        {"tool": "write_file", "outcome": "allowed", "policy_id": "files-write-workspace"},
        {"tool": "write_file", "outcome": "denied: policy", "policy_id": "default-deny"},
    ]
    for c in cs:
        for name in ("visible-scanner-on", "hidden-scanner-off"):  # the text reaches the agent
            assert by[(name, c.index)].target_in_answer
            assert by[(name, c.index)].target_calls == written
        stripped = by[("hidden-scanner-on", c.index)]  # hidden text is stripped
        assert not stripped.target_in_answer and stripped.target_calls == []
    lines = (tmp_path / "trials.jsonl").read_text().splitlines()
    assert len(lines) == len(cs) * len(CONDITIONS)
    assert json.loads(lines[0])["condition"] == CONDITIONS[0].name


class NoLab:
    """Just enough of a Lab for a trial that never reaches a tool."""

    servers: dict = {}
    evil_site = "http://127.0.0.1:1"
    receipts_path = None

    def reset(self) -> None:
        pass

    def identity_for(self):
        return "research-bot"


async def test_a_hung_trial_is_cut_off_and_flagged(monkeypatch):
    import asyncio

    from agentguard.agent import graph

    async def hang(*args, **kwargs):
        await asyncio.sleep(60)

    monkeypatch.setattr(graph, "run_task", hang)
    t = await run_trial(NoLab(), cases(1)[0], CONDITIONS[0], None, "", timeout_s=0.05)
    assert t.timed_out and t.agent_error and not t.target_in_answer


async def test_a_model_request_timeout_is_flagged(monkeypatch):
    import httpx

    from agentguard.agent import graph

    async def slow_model(*args, **kwargs):
        raise httpx.ReadTimeout("model request timed out")

    monkeypatch.setattr(graph, "run_task", slow_model)
    t = await run_trial(NoLab(), cases(1)[0], CONDITIONS[0], None, "")
    assert t.timed_out and t.agent_error


def test_summary_counts_timeouts_within_agent_errors():
    name = CONDITIONS[0].name
    ts = [trial(name, False, error="boom"), trial(name, False, error="slow")]
    ts[1].timed_out = True
    (row, *_) = summarize_trials(ts, CONDITIONS)
    assert (row.agent_errors, row.timed_out, row.decided_n) == (2, 1, 0)
    assert "| 2 (1) |" in trials_markdown([row])


async def test_a_trial_whose_agent_got_no_tools_is_an_error(monkeypatch):
    from agentguard.agent import graph

    async def answers_without_tools(*args, **kwargs):
        return [AIMessage("a summary")]

    monkeypatch.setattr(graph, "run_task", answers_without_tools)
    t = await run_trial(NoLab(), cases(1)[0], CONDITIONS[0], None, "")
    assert t.agent_error == "the gateway listed no tools to the agent" and not t.timed_out
