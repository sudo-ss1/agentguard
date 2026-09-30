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
    run_conditions,
    sample,
    summarize_trials,
    target_in_answer,
    trials_markdown,
    write_pages,
)


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


def trial(condition: str, seen: bool, error: str | None = None, classes=None) -> Trial:
    return Trial(condition, 0, "g", seen, error, [], classes or {})


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
    assert (row.n, row.target_seen, row.approval_undecided, row.agent_errors) == (5, 2, 1, 1)
    assert (row.decided_n, row.decided_target_seen) == (3, 1)
    assert all(r.n == 0 for r in rest)  # conditions with no trials still get a row
    table = trials_markdown([row, *rest])
    assert len(table.splitlines()) == 2 + len(CONDITIONS)


class EchoModel(BaseChatModel):
    """Fetches the URL in the task, then answers with the fetched text verbatim."""

    @property
    def _llm_type(self) -> str:
        return "echo"

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        fetched = [m for m in messages if isinstance(m, ToolMessage)]
        if fetched:
            message = AIMessage(str(fetched[-1].content))
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
    seen = {(t.condition, t.case): t.target_seen for t in trials}
    assert all(t.agent_error is None and t.tools_called == ["fetch_url"] for t in trials)
    for c in cs:
        assert seen[("visible-scanner-on", c.index)]  # visible text reaches the agent
        assert not seen[("hidden-scanner-on", c.index)]  # hidden text is stripped
        assert seen[("hidden-scanner-off", c.index)]  # the control: nothing strips it
    lines = (tmp_path / "trials.jsonl").read_text().splitlines()
    assert len(lines) == len(cs) * len(CONDITIONS)
    assert json.loads(lines[0])["condition"] == CONDITIONS[0].name
