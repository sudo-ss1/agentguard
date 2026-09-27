"""Give the lab's agents keys and credentials, and produce the gateway's public trust material.

Used by the local lab (then the identity service is stopped) and by `agentguard provision` in
the Docker lab. An agent's key is reused if it already exists, and re-registering the same DID
is idempotent, so provisioning can be re-run to refresh expiring tokens.
"""

from pathlib import Path

from agentguard.identity.client import (
    Credentials,
    issuer_info,
    load_credentials,
    register,
    save_credentials,
)
from agentguard.identity.didkey import AgentKey

REGISTERED_AGENTS = ("research-bot", "sub-agent")  # registered with the identity service
UNREGISTERED_AGENTS = ("intruder",)  # has a key, but no credential


def provision(identity_url: str, creds_dir: Path) -> tuple[dict[str, Credentials], dict[str, str]]:
    """Returns every lab agent's credentials and the trust material the gateway pins."""
    existing = load_credentials(creds_dir) if creds_dir.exists() else {}
    credentials = {}
    for name in (*REGISTERED_AGENTS, *UNREGISTERED_AGENTS):
        key = existing[name].key if name in existing else AgentKey.generate()
        credentials[name] = (
            register(identity_url, key, name)
            if name in REGISTERED_AGENTS
            else Credentials(name, key, None, None)
        )
        save_credentials(creds_dir, credentials[name])
    info = issuer_info(identity_url)
    return credentials, {"issuer_did": info.did, "biscuit_root_key": info.biscuit_root_key}
