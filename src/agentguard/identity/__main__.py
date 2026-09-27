"""Run the identity service:

    python -m agentguard.identity --config config/identity.yaml --state-dir DIR --port 8100

DIR holds the issuer key, the Biscuit root key (both mode 0600) and the name->DID bindings.
Keys are created on first start. Verifiers need only the public values from GET /issuer.
"""

import argparse
from pathlib import Path

import uvicorn

from agentguard.identity.didkey import AgentKey
from agentguard.identity.service import IdentityService, create_app, load_identity_config
from agentguard.tokens.biscuit import RootAuthority


def load_or_create(path: Path) -> AgentKey:
    if path.exists():
        return AgentKey.load(path)
    key = AgentKey.generate()
    key.save(path)
    return key


parser = argparse.ArgumentParser()
parser.add_argument("--config", type=Path, default=Path("config/identity.yaml"))
parser.add_argument("--state-dir", type=Path, required=True)
parser.add_argument("--host", default="0.0.0.0")
parser.add_argument("--port", type=int, default=8100)
args = parser.parse_args()

issuer = load_or_create(args.state_dir / "issuer.key")
root_path = args.state_dir / "biscuit-root.key"
load_or_create(root_path)  # an Ed25519 seed, like agent keys
service = IdentityService(
    issuer,
    RootAuthority.load(root_path),
    load_identity_config(args.config),
    args.state_dir / "bindings.json",
)
uvicorn.run(create_app(service), host=args.host, port=args.port, log_level="warning")
