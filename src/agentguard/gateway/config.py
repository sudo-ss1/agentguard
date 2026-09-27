import json
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
    # Salts for the receipts' commitments. Keep this away from the receipt log: whoever can
    # read it can prove (or recover) the committed values; deleting an entry erases one.
    salts_path: Path = Path(".lab-state/receipt-salts.jsonl")
    # How often upstream tool lists are re-fetched and checked against their pins.
    refresh_interval_s: float = 5.0


def load_gateway_config(path: Path) -> GatewayConfig:
    """`identity` may be given inline, or as `identity_file`: a JSON file of public trust
    material written at provisioning time (the Docker lab does this)."""
    data = yaml.safe_load(path.read_text())
    identity_file = data.pop("identity_file", None)
    if identity_file and "identity" not in data:
        data["identity"] = json.loads(Path(identity_file).read_text())
    return GatewayConfig.model_validate(data)
