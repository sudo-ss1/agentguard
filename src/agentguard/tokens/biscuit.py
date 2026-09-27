"""Biscuit capability tokens with delegation that can only narrow authority.

The identity service mints each agent a root token signed with the Biscuit root key. Its
authority block lists the agent's tools as `right` facts, names the agent as `owner`, expires,
and requires the request's holder to be the owner or someone the owner delegated to:

    check if holder($h), owner($h) or holder($h), delegate($h) trusting ed25519/<owner key>

A delegation is a third-party block signed with the owner's did:key (an Ed25519 key, the
type Biscuit uses for third-party blocks). It names the delegate and adds narrowing checks.
So a delegate is trusted only because the owner signed that block. Every block can only add
checks. Trailing blocks can't be removed without breaking the signature chain.

The gateway authorizes with only the root public key, fully offline. It supplies
`tool`, `holder` (the DID proven by the request's DPoP signature) and `time`, and the policy
`allow if tool($t), right($t)`. `right` facts count only from the authority block.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from biscuit_auth import (
    Algorithm,
    AuthorizationError,
    AuthorizerBuilder,
    Biscuit,
    BiscuitBuilder,
    BlockBuilder,
    KeyPair,
    PrivateKey,
    PublicKey,
)

from agentguard.identity.didkey import AgentKey, public_key_from_did


class TokenError(Exception):
    """A token failed to parse or its signature chain does not verify against the root key."""


# biscuit-python 0.4.0's bundled stubs lag its runtime: at runtime `from_bytes` requires the
# algorithm and `Algorithm.Ed25519` exists (the tests exercise both). Hence the ignores.
ED25519 = Algorithm.Ed25519  # type: ignore[attr-defined]


def _biscuit_keypair(key: AgentKey) -> KeyPair:
    return KeyPair.from_private_key(PrivateKey.from_bytes(key.seed, ED25519))  # type: ignore[call-arg]


def _biscuit_public_key(did: str) -> PublicKey:
    return PublicKey.from_bytes(public_key_from_did(did), ED25519)  # type: ignore[call-arg]


class RootAuthority:
    """The Biscuit root key. The identity service holds it; the gateway only needs `public_key`."""

    def __init__(self, keypair: KeyPair) -> None:
        self.keypair = keypair

    @classmethod
    def generate(cls) -> "RootAuthority":
        return cls(KeyPair())

    @classmethod
    def load(cls, path: Path) -> "RootAuthority":
        return cls(_biscuit_keypair(AgentKey.load(path)))

    @property
    def public_key(self) -> PublicKey:
        return self.keypair.public_key

    def public_key_hex(self) -> str:
        return bytes(self.keypair.public_key.to_bytes()).hex()

    def mint(self, owner_did: str, tools: Iterable[str], expires: datetime) -> str:
        builder = BiscuitBuilder(
            """
            owner({owner});
            check if time($t), $t <= {expires};
            check if holder($h), owner($h) or holder($h), delegate($h) trusting {owner_key};
            """,
            {"owner": owner_did, "expires": expires},
            {"owner_key": _biscuit_public_key(owner_did)},
        )
        for tool in sorted(set(tools)):
            builder.add_code("right({tool});", {"tool": tool})
        return builder.build(self.keypair.private_key).to_base64()


def load_root_public_key(hex_key: str) -> PublicKey:
    return PublicKey.from_bytes(bytes.fromhex(hex_key), ED25519)  # type: ignore[call-arg]


def parse(token: str, root_public_key: PublicKey) -> Biscuit:
    """Deserialize and verify the whole signature chain against the root key."""
    try:
        return Biscuit.from_base64(token, root_public_key)
    except Exception as exc:  # biscuit_auth raises several validation/serialization errors
        raise TokenError(f"token failed verification: {type(exc).__name__}") from exc


def delegate(
    token: str,
    root_public_key: PublicKey,
    owner: AgentKey,
    to_did: str,
    tools: Iterable[str],
    expires: datetime,
) -> str:
    """The owner narrows its token for a delegate: only `tools`, only until `expires`."""
    parent = parse(token, root_public_key)
    block = BlockBuilder(
        """
        delegate({to});
        check if tool($t), {tools}.contains($t);
        check if time($t), $t <= {expires};
        """,
        {"to": to_did, "tools": set(tools), "expires": expires},
    )
    owner_kp = _biscuit_keypair(owner)
    signed = parent.third_party_request().create_block(owner_kp.private_key, block)
    return parent.append_third_party(owner_kp.public_key, signed).to_base64()


@dataclass(frozen=True)
class TokenDecision:
    allowed: bool
    reason: str  # "authorized", or which kind of caveat failed: holder, tool, expired, rights
    failed_checks: tuple[str, ...] = ()


_FAILED_CHECK = re.compile(r"Check n°\d+ in block n°\d+: (check if .*?)(?=, Check n°|$)")


def _classify(checks: tuple[str, ...], rights_matched: bool) -> str:
    kinds = []
    if any("holder(" in c for c in checks):
        kinds.append("holder")
    if any("tool(" in c for c in checks):
        kinds.append("tool")
    if any("time(" in c for c in checks):
        kinds.append("expired")
    if not rights_matched:
        kinds.append("rights")
    return "+".join(kinds) or "denied"


def authorize(
    token: str,
    root_public_key: PublicKey,
    holder_did: str,
    tool: str,
    now: datetime | None = None,
) -> TokenDecision:
    """May `holder_did` (proven by its request signature) call `tool` with this token?"""
    biscuit = parse(token, root_public_key)
    authorizer = AuthorizerBuilder(
        """
        tool({tool});
        holder({holder});
        time({now});
        allow if tool($t), right($t);
        """,
        {"tool": tool, "holder": holder_did, "now": now or datetime.now(UTC)},
    ).build(biscuit)
    try:
        authorizer.authorize()
    except AuthorizationError as exc:
        message = str(exc)
        checks = tuple(m.strip() for m in _FAILED_CHECK.findall(message))
        rights_matched = "an allow policy matched" in message
        return TokenDecision(False, _classify(checks, rights_matched), checks)
    return TokenDecision(True, "authorized")
