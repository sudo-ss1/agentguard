"""Verified identity for gateway requests (Phase 3). Replaces the forgeable X-Agent-Id header.

Every POST to the gateway must carry three headers:

- X-AgentGuard-Credential: the agent's VC (vc+jwt), issued by a trusted identity service
- Authorization: "DPoP <token>": its Biscuit capability token
- DPoP: a proof signed with the key of the DID the VC names, for exactly this request

`IdentityMiddleware` reads each POST body once and verifies all three offline: the pinned
issuer DID, the Biscuit root public key and a replay cache are all it needs. It attaches the
result to the request. It never rejects a request itself: the MCP handlers deny calls from
unverified callers and write a receipt, so forgery attempts are logged like any other denial.
"""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from biscuit_auth import PublicKey
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from agentguard.gateway.checks import CallContext, Decision
from agentguard.identity.dpop import ProofError, ReplayCache, verify_proof
from agentguard.identity.vc import AgentProfile, CredentialError, verify_vc
from agentguard.tokens.biscuit import TokenError, authorize, parse

CREDENTIAL_HEADER = "x-agentguard-credential"
STATE_KEY = "agentguard_identity"
MAX_BODY = 4 * 1024 * 1024


@dataclass(frozen=True)
class Identity:
    """The outcome of verifying one request. `profile` is set only if every check passed."""

    profile: AgentProfile | None
    token: str | None = None
    error: str | None = None

    @property
    def verified(self) -> bool:
        return self.profile is not None


UNVERIFIED_NO_REQUEST = Identity(None, error="request carried no verifiable identity")


class IdentityVerifier:
    def __init__(self, trusted_issuers: set[str], biscuit_root: PublicKey) -> None:
        self.trusted_issuers = trusted_issuers
        self.biscuit_root = biscuit_root
        self.replay_cache = ReplayCache()

    def verify(
        self, headers: dict[str, str], htu: str, body: bytes, now: datetime | None = None
    ) -> Identity:
        now = now or datetime.now(UTC)
        try:
            message = json.loads(body)
            if not isinstance(message, dict):
                raise ValueError("batched JSON-RPC is not supported")
        except ValueError as exc:
            return Identity(None, error=f"unreadable request body: {exc}")
        vc = headers.get(CREDENTIAL_HEADER)
        if not vc:
            return Identity(None, error="request has no credential")
        auth = headers.get("authorization", "")
        token = auth.removeprefix("DPoP ").strip() if auth.startswith("DPoP ") else None
        try:
            profile = verify_vc(vc, self.trusted_issuers, now)
            verify_proof(
                headers.get("dpop"),
                profile.did,
                "POST",
                htu,
                message,
                token,
                self.replay_cache,
                now,
            )
            if token is not None:
                parse(token, self.biscuit_root)  # the whole signature chain, offline
        except (CredentialError, ProofError, TokenError) as exc:
            return Identity(None, error=f"{type(exc).__name__}: {exc}")
        return Identity(profile, token)


def _htu(scope: Scope, headers: dict[str, str]) -> str:
    """The URL the client addressed (RFC 9449 htu: no query or fragment)."""
    host = headers.get("host") or f"{scope['server'][0]}:{scope['server'][1]}"
    return f"{scope.get('scheme', 'http')}://{host}{scope['path']}"


class IdentityMiddleware:
    def __init__(self, app: ASGIApp, verifier: IdentityVerifier) -> None:
        self.app, self.verifier = app, verifier

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        state = scope.setdefault("state", {})
        if scope["method"] != "POST":
            state[STATE_KEY] = UNVERIFIED_NO_REQUEST
            await self.app(scope, receive, send)
            return
        body, more = b"", True
        while more:
            message = await receive()
            body += message.get("body", b"")
            more = message.get("more_body", False)
            if len(body) > MAX_BODY:
                break
        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])
        }
        state[STATE_KEY] = (
            self.verifier.verify(headers, _htu(scope, headers), body)
            if len(body) <= MAX_BODY
            else Identity(None, error="request body too large")
        )
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


def identity_of(request: Any) -> Identity:
    state = getattr(request, "state", None)
    identity = getattr(state, STATE_KEY, None) if state is not None else None
    return identity if isinstance(identity, Identity) else UNVERIFIED_NO_REQUEST


class IdentityCheck:
    """First in the pipeline: only verified callers get any further."""

    name = "identity"

    def evaluate(self, ctx: CallContext) -> Decision:
        identity = ctx.identity
        if identity is None or not identity.verified:
            error = identity.error if identity else "no identity"
            return Decision("deny", f"caller identity not verified: {error}", "identity")
        return Decision("allow", "identity verified", "identity")


class CapabilityTokenCheck:
    """The caller's Biscuit must authorize this tool for this holder, checked offline."""

    name = "capability-token"

    def __init__(self, root: PublicKey) -> None:
        self.root = root

    def evaluate(self, ctx: CallContext) -> Decision:
        identity = ctx.identity
        if identity is None or identity.profile is None:
            return Decision("deny", "no verified identity", "capability-token")
        if identity.token is None:
            return Decision("deny", "no capability token presented", "capability-token")
        try:
            result = authorize(identity.token, self.root, identity.profile.did, ctx.tool)
        except TokenError as exc:
            return Decision("deny", str(exc), "capability-token")
        if result.allowed:
            return Decision("allow", "token authorizes this call", "capability-token")
        return Decision("deny", f"token caveat failed: {result.reason}", "capability-token")
