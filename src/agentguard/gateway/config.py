from pathlib import Path

import yaml
from pydantic import BaseModel


class AgentPolicy(BaseModel):
    tools: list[str]


class IdentityTrust(BaseModel):
    """Public material pinned at setup. The gateway never calls the identity service."""

    issuer_did: str
    biscuit_root_key: str  # hex Ed25519 public key


class GatewayConfig(BaseModel):
    upstreams: dict[str, str]
    identity: IdentityTrust
    agents: dict[str, AgentPolicy]
    policy_dir: Path = Path("config/policies")
    pins_path: Path = Path(".lab-state/pins.json")
    receipts_path: Path = Path(".lab-state/receipts.jsonl")
    # How often upstream tool lists are re-fetched and checked against their pins.
    refresh_interval_s: float = 5.0


def load_gateway_config(path: Path) -> GatewayConfig:
    return GatewayConfig.model_validate(yaml.safe_load(path.read_text()))
