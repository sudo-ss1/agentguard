import json
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel

from agentguard.guards.approvals import ApprovalConfig
from agentguard.guards.budgets import BudgetConfig
from agentguard.guards.result_scan import InjectionConfig


class AgentPolicy(BaseModel):
    tools: list[str]


class IdentityTrust(BaseModel):
    """Public material pinned at setup. The gateway never calls the identity service."""

    issuer_did: str
    biscuit_root_key: str  # hex Ed25519 public key


class GuardsConfig(BaseModel):
    # Kill list, recorded tokens and the reset epoch (Phase 4). Gateway-local.
    state_dir: Path = Path(".lab-state/guards")
    budgets: BudgetConfig = BudgetConfig()
    approvals: ApprovalConfig = ApprovalConfig()
    injection: InjectionConfig = InjectionConfig()


class LedgerConfig(BaseModel):
    """The audit ledger (Phase 5, docs/phase5-design.md)."""

    # The receipt-signing key. Gateway-only: in Docker its own volume, mounted nowhere else.
    key_dir: Path = Path(".lab-state/ledger-key")
    # Signed checkpoints and the exported public key. Readable by auditors; never the key.
    roots_dir: Path = Path(".lab-state/ledger-roots")
    checkpoint_interval_s: float = 60.0
    # batched: fsync on a background thread every fsync_interval_s, and before every
    #   checkpoint. An OS crash can lose the last receipts, including a decision receipt for a
    #   call already forwarded.
    # strict: fsync every decision receipt before the call is forwarded (one fsync per call);
    #   outcome receipts stay batched.
    durability: Literal["batched", "strict"] = "batched"
    fsync_interval_s: float = 0.1


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
    guards: GuardsConfig = GuardsConfig()
    ledger: LedgerConfig = LedgerConfig()


def load_gateway_config(path: Path) -> GatewayConfig:
    """`identity` may be given inline, or as `identity_file`: a JSON file of public trust
    material written at provisioning time (the Docker lab does this)."""
    data = yaml.safe_load(path.read_text())
    identity_file = data.pop("identity_file", None)
    if identity_file and "identity" not in data:
        data["identity"] = json.loads(Path(identity_file).read_text())
    return GatewayConfig.model_validate(data)
