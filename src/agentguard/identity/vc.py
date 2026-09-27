"""Agent credentials: W3C Verifiable Credentials (Data Model 2.0) secured as JOSE (vc+jwt).

The identity service signs a VC that binds an agent's did:key to its name, sponsor, purpose,
allowed tools and model version. Anyone holding the issuer's DID can verify it offline.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from agentguard.identity import jose
from agentguard.identity.didkey import AgentKey, public_key_from_did

VC_TYP = "vc+jwt"
VC_CONTEXT = "https://www.w3.org/ns/credentials/v2"
VC_TYPE = "AgentCredential"


class CredentialError(Exception):
    """A VC is malformed, untrusted, tampered with, or outside its validity period."""


@dataclass(frozen=True)
class AgentProfile:
    name: str
    did: str
    sponsor: str
    purpose: str
    allowed_tools: tuple[str, ...]
    model_version: str


def _iso(t: datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def issue_vc(
    issuer: AgentKey, profile: AgentProfile, valid_for: timedelta, now: datetime | None = None
) -> str:
    now = now or datetime.now(UTC)
    credential = {
        "@context": [VC_CONTEXT],
        "type": ["VerifiableCredential", VC_TYPE],
        "issuer": issuer.did,
        "validFrom": _iso(now),
        "validUntil": _iso(now + valid_for),
        "credentialSubject": {
            "id": profile.did,
            "name": profile.name,
            "sponsor": profile.sponsor,
            "purpose": profile.purpose,
            "allowedTools": list(profile.allowed_tools),
            "modelVersion": profile.model_version,
        },
    }
    return jose.sign(issuer, credential, VC_TYP)


def verify_vc(token: str, trusted_issuers: set[str], now: datetime | None = None) -> AgentProfile:
    """Check the issuer is trusted, the signature is the issuer's, and the VC is current."""
    now = now or datetime.now(UTC)
    try:
        issuer = jose.unverified_kid_did(token)
        if issuer not in trusted_issuers:
            raise CredentialError(f"issuer {issuer[:32]}... is not trusted")
        claims = jose.verify(token, issuer, VC_TYP)
    except jose.SignatureError as exc:
        raise CredentialError(str(exc)) from exc
    return _profile(claims, issuer, now)


def _profile(claims: dict[str, Any], issuer: str, now: datetime) -> AgentProfile:
    try:
        if claims["issuer"] != issuer:
            raise CredentialError("issuer claim does not match the signing key")
        if VC_TYPE not in claims["type"] or "VerifiableCredential" not in claims["type"]:
            raise CredentialError("not an agent credential")
        start = datetime.fromisoformat(claims["validFrom"])
        end = datetime.fromisoformat(claims["validUntil"])
        subject = claims["credentialSubject"]
        public_key_from_did(subject["id"])  # the subject must be a well-formed did:key
        profile = AgentProfile(
            name=subject["name"],
            did=subject["id"],
            sponsor=subject["sponsor"],
            purpose=subject["purpose"],
            allowed_tools=tuple(subject["allowedTools"]),
            model_version=subject["modelVersion"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CredentialError(f"malformed credential: {exc}") from exc
    if not start <= now <= end:
        raise CredentialError("credential is not currently valid")
    return profile
