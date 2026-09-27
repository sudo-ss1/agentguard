"""What an agent does to get credentials: prove its key to the identity service."""

from dataclasses import dataclass

import httpx

from agentguard.identity.didkey import AgentKey
from agentguard.identity.service import registration_proof


@dataclass(frozen=True)
class Credentials:
    name: str
    key: AgentKey
    vc: str | None  # its credential (None for an unregistered caller)
    token: str | None  # its root Biscuit, or a token delegated to it


@dataclass(frozen=True)
class IssuerInfo:
    did: str
    biscuit_root_key: str  # hex


def register(identity_url: str, key: AgentKey, name: str) -> Credentials:
    response = httpx.post(
        f"{identity_url}/agents", json={"registration": registration_proof(key, name)}, timeout=10
    )
    response.raise_for_status()
    body = response.json()
    return Credentials(name, key, body["vc"], body["token"])


def issuer_info(identity_url: str) -> IssuerInfo:
    body = httpx.get(f"{identity_url}/issuer", timeout=10).json()
    return IssuerInfo(body["did"], body["biscuit_root_key"])
