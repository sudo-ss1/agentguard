"""Per-request proof of possession: DPoP (RFC 9449) with Ed25519 did:key keys.

Every request to the gateway carries a DPoP proof, a JWS signed with the agent's key over:

- htm, htu: the HTTP method and URL
- iat, jti: when it was made, and a nonce so it can't be replayed
- ath: a hash of the capability token sent with it, so a proof can't be moved to another token
- mcp: the MCP message it authorizes: method and, for tools/call, the tool name and a digest
  of the arguments (RFC 8785 canonical JSON). This claim is AgentGuard's one extension to DPoP.
  DPoP binds method and URL, but every MCP call is POST /mcp, so without it a captured proof
  could authorize a different tool call.

As RFC 9449 requires, the header carries the public key as `jwk`. The verifier checks it is
the same key as the DID the agent's credential names.
"""

import base64
import hashlib
import secrets
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import rfc8785

from agentguard.identity import jose
from agentguard.identity.didkey import AgentKey, public_key_from_did

DPOP_TYP = "dpop+jwt"
MAX_AGE = timedelta(seconds=60)


class ProofError(Exception):
    """A DPoP proof is missing, malformed, forged, stale, replayed, or for another request."""


def args_digest(arguments: dict[str, Any]) -> str:
    return _b64u(hashlib.sha256(rfc8785.dumps(arguments)).digest())


def token_hash(token: str) -> str:
    """RFC 9449 `ath`: base64url(SHA-256(ASCII token))."""
    return _b64u(hashlib.sha256(token.encode("ascii")).digest())


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def mcp_claim(message: dict[str, Any]) -> dict[str, Any]:
    """What a proof binds from a JSON-RPC message."""
    method = message.get("method")
    claim: dict[str, Any] = {"method": method}
    if method == "tools/call":
        params = message.get("params") or {}
        claim["tool"] = params.get("name")
        claim["args_digest"] = args_digest(params.get("arguments") or {})
    return claim


def create_proof(
    key: AgentKey,
    htm: str,
    htu: str,
    message: dict[str, Any],
    token: str | None,
    now: datetime | None = None,
) -> str:
    claims: dict[str, Any] = {
        "htm": htm,
        "htu": htu,
        "iat": int((now or datetime.now(UTC)).timestamp()),
        "jti": secrets.token_urlsafe(16),
        "mcp": mcp_claim(message),
    }
    if token is not None:
        claims["ath"] = token_hash(token)
    return jose.sign(key, claims, DPOP_TYP, {"jwk": jose.public_jwk_dict(key.public_key)})


class ReplayCache:
    """Remembers proof nonces (jti) for as long as a proof could still be accepted."""

    def __init__(self, window: timedelta = MAX_AGE * 2) -> None:
        self.window = window.total_seconds()
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def check_and_add(self, jti: str) -> bool:
        """True the first time a jti is seen, False on a replay."""
        now = time.monotonic()
        with self._lock:
            for old in [j for j, t in self._seen.items() if now - t > self.window]:
                del self._seen[old]
            if jti in self._seen:
                return False
            self._seen[jti] = now
            return True


@dataclass(frozen=True)
class VerifiedProof:
    did: str
    jti: str


def verify_proof(
    proof: str | None,
    did: str,
    htm: str,
    htu: str,
    message: dict[str, Any],
    token: str | None,
    replay_cache: ReplayCache,
    now: datetime | None = None,
) -> VerifiedProof:
    """Verify `proof` was made by `did`'s key, just now, once, for exactly this request."""
    if not proof:
        raise ProofError("request has no DPoP proof")
    try:
        header = jose.unverified_header(proof)
        if header.get("jwk") != jose.public_jwk_dict(public_key_from_did(did)):
            raise ProofError("proof's jwk is not the credential's key")
        claims = jose.verify(proof, did, DPOP_TYP)
    except (jose.SignatureError, ValueError) as exc:
        raise ProofError(f"proof signature invalid: {exc}") from exc
    now = now or datetime.now(UTC)
    iat = claims.get("iat")
    if not isinstance(iat, int | float) or abs(now - datetime.fromtimestamp(iat, UTC)) > MAX_AGE:
        raise ProofError("proof is stale or has no iat")
    if claims.get("htm") != htm or claims.get("htu") != htu:
        raise ProofError("proof is for a different method or URL")
    if claims.get("mcp") != mcp_claim(message):
        raise ProofError("proof is for a different MCP message")
    if token is not None and claims.get("ath") != token_hash(token):
        raise ProofError("proof is bound to a different token")
    if token is None and "ath" in claims:
        raise ProofError("proof is bound to a token that was not sent")
    jti = claims.get("jti")
    if not isinstance(jti, str) or not replay_cache.check_and_add(jti):
        raise ProofError("proof nonce missing or already used (replay)")
    return VerifiedProof(did, jti)
