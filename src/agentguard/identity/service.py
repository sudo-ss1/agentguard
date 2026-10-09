"""The identity service: registers agents and issues their credentials.

An agent registers by sending a JWS signed with its own did:key, so the service never sees a
private key. The service checks the name is one it manages and not already bound to another
DID, then issues a VC whose tools, purpose and sponsor come from config/identity.yaml.
Verifiers (the gateway) only need the service's issuer DID; they never call it.
"""

import json
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from agentguard.identity import jose
from agentguard.identity.didkey import AgentKey
from agentguard.identity.vc import AgentProfile, issue_vc
from agentguard.tokens.biscuit import RootAuthority

REGISTRATION_TYP = "agent-registration+jwt"
AUDIENCE = "agentguard-identity"
MAX_CLOCK_SKEW = timedelta(seconds=60)


class AgentEntry(BaseModel):
    sponsor: str
    purpose: str
    tools: list[str]
    model: str


class IdentityConfig(BaseModel):
    issuer_name: str = AUDIENCE
    vc_valid_for_s: int = 86400
    root_token_valid_for_s: int = 3600
    agents: dict[str, AgentEntry]


class RegistrationError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status, self.detail = status, detail


@dataclass
class Registration:
    profile: AgentProfile
    vc: str
    # root Biscuit: the VC's tools as rights, owned by the agent's DID. Kept out of the repr.
    token: str = field(repr=False)


class IdentityService:
    def __init__(
        self,
        issuer: AgentKey,
        root: RootAuthority,
        config: IdentityConfig,
        bindings_path: Path,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.issuer, self.root, self.config = issuer, root, config
        self.bindings_path, self.clock = bindings_path, clock
        self.bindings: dict[str, str] = (
            json.loads(bindings_path.read_text()) if bindings_path.exists() else {}
        )
        self._lock = threading.Lock()

    def register(self, registration: str) -> Registration:
        try:
            did = jose.unverified_kid_did(registration)
            claims = jose.verify(registration, did, REGISTRATION_TYP)  # proves it holds the key
        except (jose.SignatureError, ValueError) as exc:
            raise RegistrationError(401, f"registration proof invalid: {exc}") from exc
        now = self.clock()
        iat = claims.get("iat")
        if claims.get("aud") != AUDIENCE or not isinstance(iat, int | float):
            raise RegistrationError(401, "registration proof has the wrong audience or no iat")
        if abs(now - datetime.fromtimestamp(iat, UTC)) > MAX_CLOCK_SKEW:
            raise RegistrationError(401, "registration proof is stale")
        name = claims.get("name")
        if not isinstance(name, str) or name not in self.config.agents:
            raise RegistrationError(403, f"{name!r} is not an agent this service registers")
        entry = self.config.agents[name]
        with self._lock:
            bound = self.bindings.setdefault(name, did)
            if bound != did:
                raise RegistrationError(409, f"{name!r} is already registered to another DID")
            self._save()
        profile = AgentProfile(
            name, did, entry.sponsor, entry.purpose, tuple(entry.tools), entry.model
        )
        vc = issue_vc(self.issuer, profile, timedelta(seconds=self.config.vc_valid_for_s), now)
        expires = now + timedelta(seconds=self.config.root_token_valid_for_s)
        token = self.root.mint(did, entry.tools, expires)
        return Registration(profile, vc, token)

    def _save(self) -> None:
        self.bindings_path.parent.mkdir(parents=True, exist_ok=True)
        self.bindings_path.write_text(json.dumps(self.bindings, indent=2, sort_keys=True))


def registration_proof(key: AgentKey, name: str, now: datetime | None = None) -> str:
    """What an agent sends to register: its name, signed with its own key."""
    iat = int((now or datetime.now(UTC)).timestamp())
    return jose.sign(key, {"name": name, "aud": AUDIENCE, "iat": iat}, REGISTRATION_TYP)


class RegisterRequest(BaseModel):
    registration: str = Field(repr=False)  # a signed proof of key possession


def create_app(service: IdentityService) -> FastAPI:
    app = FastAPI(title="AgentGuard identity service")

    @app.get("/issuer")
    def issuer() -> dict[str, str]:
        """Public material verifiers pin at setup: they never call the service to verify."""
        return {"did": service.issuer.did, "biscuit_root_key": service.root.public_key_hex()}

    @app.post("/agents")
    def register(request: RegisterRequest) -> dict[str, object]:
        try:
            result = service.register(request.registration)
        except RegistrationError as exc:
            raise HTTPException(exc.status, exc.detail) from exc
        return {
            "name": result.profile.name,
            "did": result.profile.did,
            "vc": result.vc,
            "token": result.token,
        }

    return app


def load_identity_config(path: Path) -> IdentityConfig:
    return IdentityConfig.model_validate(yaml.safe_load(path.read_text()))
