"""Compact JWS/JWT signing and verification with Ed25519 did:key keys (RFC 7515, RFC 8037).

Uses the fully specified "Ed25519" algorithm name from RFC 9864 ("EdDSA" is deprecated).
"""

import base64
from typing import Any

from joserfc import jws, jwt
from joserfc.errors import JoseError
from joserfc.jwk import OKPKey

from agentguard.identity.didkey import AgentKey, public_key_from_did

ALG = "Ed25519"


class SignatureError(Exception):
    """A JWS failed to parse or verify."""


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _private_jwk(key: AgentKey) -> OKPKey:
    return OKPKey.import_key(
        {"kty": "OKP", "crv": "Ed25519", "x": _b64u(key.public_key), "d": _b64u(key.seed)}
    )


def _public_jwk(did: str) -> OKPKey:
    return OKPKey.import_key(public_jwk_dict(public_key_from_did(did)))


def public_jwk_dict(public_key: bytes) -> dict[str, str | list[str]]:
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64u(public_key)}


def sign(
    key: AgentKey, claims: dict[str, Any], typ: str, extra_header: dict[str, Any] | None = None
) -> str:
    header = {"alg": ALG, "typ": typ, "kid": key.verification_method, **(extra_header or {})}
    return jwt.encode(header, claims, _private_jwk(key), algorithms=[ALG])


def unverified_header(token: str) -> dict[str, Any]:
    try:
        return dict(jws.extract_compact(token.encode()).headers())
    except (JoseError, ValueError) as exc:
        raise SignatureError(f"malformed JWS: {exc}") from exc


def unverified_kid_did(token: str) -> str:
    """The DID a token claims to be signed by. Untrusted until `verify` succeeds."""
    kid = unverified_header(token).get("kid")
    if not isinstance(kid, str):
        raise SignatureError("JWS has no kid")
    return kid.split("#", 1)[0]


def verify(token: str, did: str, typ: str) -> dict[str, Any]:
    """Verify `token` was signed by `did`'s key and has the expected `typ`; return its claims."""
    try:
        decoded = jwt.decode(token, _public_jwk(did), algorithms=[ALG])
    except (JoseError, ValueError) as exc:
        raise SignatureError(f"signature check failed: {type(exc).__name__}") from exc
    if decoded.header.get("typ") != typ:
        raise SignatureError(f"expected typ {typ!r}, got {decoded.header.get('typ')!r}")
    if decoded.header.get("kid", "").split("#", 1)[0] != did:
        raise SignatureError("kid does not name the verifying DID")
    return dict(decoded.claims)
