"""Exercise the LangGraph agent loop end to end with a fake model (no Ollama needed)."""

from langchain_core.messages import AIMessage, ToolMessage

from agentguard.agent.graph import run_task
from agentguard.agent.toolbox import Toolbox
from agentguard.lab_stack import local_lab
from tests.fakes import ToolCallingFake, tool_call


async def test_agent_calls_mcp_tools_and_surfaces_errors():
    model = ToolCallingFake(
        responses=[
            tool_call("read_file", {"path": "/workspace/notes.txt"}, "1"),
            tool_call("read_file", {"path": "/does/not/exist"}, "2"),
            AIMessage("done"),
        ]
    )
    with local_lab() as lab:
        async with Toolbox(lab.servers, lab.agent_id) as toolbox:
            messages = await run_task(model, toolbox, "system", "read my notes")

    tool_messages = [m for m in messages if isinstance(m, ToolMessage)]
    assert "Q3 research summary" in tool_messages[0].content
    assert tool_messages[1].status == "error"
    assert messages[-1].content == "done"
