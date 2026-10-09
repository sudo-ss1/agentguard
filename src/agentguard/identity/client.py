"""What an agent does to get credentials: prove its key to the identity service."""

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from agentguard.identity.didkey import AgentKey
from agentguard.identity.service import registration_proof


@dataclass(frozen=True)
class Credentials:
    name: str
    key: AgentKey = field(repr=False)  # holds the private key
    vc: str | None  # its credential (None for an unregistered caller)
    token: str | None = field(repr=False)  # its root Biscuit, or a token delegated to it


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


def save_credentials(directory: Path, credentials: Credentials) -> None:
    """<name>.key (the private key, mode 0600) and <name>.json (VC and token, both public)."""
    credentials.key.save(directory / f"{credentials.name}.key")
    (directory / f"{credentials.name}.json").write_text(
        json.dumps(
            {"name": credentials.name, "vc": credentials.vc, "token": credentials.token}, indent=2
        )
    )


def load_credentials(directory: Path) -> dict[str, Credentials]:
    found = {}
    for meta in sorted(directory.glob("*.json")):
        body = json.loads(meta.read_text())
        key = AgentKey.load(directory / f"{body['name']}.key")
        found[body["name"]] = Credentials(body["name"], key, body["vc"], body["token"])
    return found


def wait_for(identity_url: str, timeout_s: float = 30) -> IssuerInfo:
    """Poll until the identity service answers (for provisioning at container start)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return issuer_info(identity_url)
        except httpx.HTTPError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.5)
