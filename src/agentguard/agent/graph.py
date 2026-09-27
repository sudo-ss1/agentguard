"""The agent: an explicit LangGraph loop of model -> tools -> model."""

from typing import Annotated, TypedDict

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AnyMessage, HumanMessage, SystemMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition

from agentguard.agent.toolbox import Toolbox

MAX_STEPS = 25


class State(TypedDict):
    messages: Annotated[list[AnyMessage], add_messages]


def build_graph(model: BaseChatModel, toolbox: Toolbox, system_prompt: str):
    tools = toolbox.langchain_tools()
    bound = model.bind_tools(tools)

    async def call_model(state: State) -> dict:
        response = await bound.ainvoke([SystemMessage(system_prompt), *state["messages"]])
        return {"messages": [response]}

    graph = StateGraph(State)
    graph.add_node("model", call_model)
    graph.add_node("tools", ToolNode(tools))
    graph.add_edge(START, "model")
    graph.add_conditional_edges("model", tools_condition, {"tools": "tools", END: END})
    graph.add_edge("tools", "model")
    return graph.compile()


async def run_task(model: BaseChatModel, toolbox: Toolbox, system_prompt: str, task: str) -> list:
    graph = build_graph(model, toolbox, system_prompt)
    state = await graph.ainvoke(
        {"messages": [HumanMessage(task)]}, {"recursion_limit": MAX_STEPS * 2}
    )
    return state["messages"]
