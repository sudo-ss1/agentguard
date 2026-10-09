"""Scripted driver: replays a fixed list of tool calls with no LLM, for deterministic tests.

Arguments may reference earlier results as "{results[N]}" (0-based step index)
and the evil site base URL as "{evil_site}". A step can instead run a lab action:
`rug_pull` (flip the weather server) or `refresh_tools` (re-list tools, as an agent would).

A tool step can run as a different identity with `as: {agent, token, claims}`, e.g. a
sub-agent presenting its parent's token (attack 4) or an intruder claiming to be
research-bot (attack 5). Without `as`, steps run as the lab's agent.
"""

from collections.abc import Awaitable, Callable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentguard.agent.toolbox import Toolbox


class Acting(BaseModel):
    """Who performs a step, and with which credentials."""

    model_config = ConfigDict(frozen=True)

    agent: str  # who actually sends the request (and, from Phase 3, holds the signing key)
    # whose token it presents; None means its own. A credential, so kept out of the repr.
    token: str | None = Field(default=None, repr=False)
    claims: str | None = None  # the identity it asserts, if not its own

    @property
    def presented_agent_id(self) -> str:
        """The identity the request asserts. In Phase 2 this is all the gateway sees: the
        X-Agent-Id header, which anyone can set."""
        return self.claims or self.token or self.agent


class Step(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    tool: str | None = None
    args: dict[str, Any] = Field(default_factory=dict, repr=False)  # raw tool arguments
    repeat: int = 1
    action: Literal["rug_pull", "refresh_tools"] | None = None
    acting: Acting | None = Field(default=None, alias="as")

    @model_validator(mode="after")
    def _tool_or_action(self) -> "Step":
        if (self.tool is None) == (self.action is None):
            raise ValueError("a step needs exactly one of `tool` or `action`")
        if self.acting and self.action:
            raise ValueError("`as` applies to tool steps only")
        return self


def _fill(value: Any, variables: dict[str, Any]) -> Any:
    if isinstance(value, str):
        return value.format(**variables)
    if isinstance(value, dict):
        return {k: _fill(v, variables) for k, v in value.items()}
    return value


async def run_script(
    toolbox: Toolbox,
    steps: list[Step],
    evil_site: str,
    lab_actions: dict[str, Callable[[], None]] | None = None,
    toolbox_for: Callable[[Acting], Awaitable[Toolbox]] | None = None,
) -> None:
    results: list[str] = []
    for step in steps:
        if step.action == "refresh_tools":
            await toolbox.refresh()
            results.append("")
            continue
        if step.action:
            (lab_actions or {})[step.action]()
            results.append("")
            continue
        assert step.tool
        box = toolbox
        if step.acting:
            if toolbox_for is None:
                raise ValueError("this script has `as` steps but no toolbox_for was given")
            box = await toolbox_for(step.acting)
        args = _fill(step.args, {"results": results, "evil_site": evil_site})
        for _ in range(step.repeat):
            result = await box.call(step.tool, args)
        results.append(result.text)
