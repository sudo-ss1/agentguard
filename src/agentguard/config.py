"""Agent config: which MCP server URLs the agent talks to.

Phase 2 puts the gateway in front by changing these URLs and nothing else.
"""

from pathlib import Path

import yaml
from pydantic import BaseModel


class AgentConfig(BaseModel):
    agent_id: str = "research-bot"
    system_prompt: str
    servers: dict[str, str]


def load_config(path: Path) -> AgentConfig:
    return AgentConfig.model_validate(yaml.safe_load(path.read_text()))
