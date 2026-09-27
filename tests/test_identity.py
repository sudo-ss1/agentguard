"""did:key, Verifiable Credentials and the identity service."""

import base64
import stat
from datetime import UTC, datetime, timedelta

import base58
import nacl.signing
import pytest
from fastapi.testclient import TestClient

from agentguard.identity import jose
from agentguard.identity.didkey import AgentKey, did_from_public_key, public_key_from_did
from agentguard.identity.service import (
    AgentEntry,
    IdentityConfig,
    IdentityService,
    create_app,
    registration_proof,
)
from agentguard.identity.vc import AgentProfile, CredentialError, issue_vc, verify_vc
from agentguard.tokens.biscuit import RootAuthority, authorize

# From the did:key spec (w3c-ccg/did-key-spec, index.html): an Ed25519 DID and, in its DID
# document, the X25519 key derived from it. Deriving that X25519 key from our decoding of the
# DID checks we extract the right 32 bytes, independently of our own encoder.
SPEC_ED25519_DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
SPEC_DERIVED_X25519 = "z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p"


def test_did_key_matches_spec_example():
    public_key = public_key_from_did(SPEC_ED25519_DID)
    x25519 = nacl.signing.VerifyKey(public_key).to_curve25519_public_key()
    assert "z" + base58.b58encode(b"\xec\x01" + bytes(x25519)).decode() == SPEC_DERIVED_X25519
    assert did_from_public_key(public_key) == SPEC_ED25519_DID


@pytest.mark.parametrize(
    "bad",
    [
        "did:web:example.com",  # not did:key
        "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",  # multicodec is not 0xed01
        "did:key:z0OIl",  # not base58btc
        "did:key:z6Mk",  # truncated
    ],
)
def test_malformed_or_non_ed25519_did_rejected(bad):
    with pytest.raises(ValueError):
        public_key_from_did(bad)


def test_key_file_is_owner_only_and_round_trips(tmp_path):
    key = AgentKey.generate()
    path = tmp_path / "keys" / "agent.key"
    key.save(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert AgentKey.load(path).did == key.did


# --- Verifiable Credentials -------------------------------------------------------------

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)


@pytest.fixture
def issuer():
    return AgentKey.generate()


def profile(did, name="research-bot", tools=("read_file", "send_email")):
    return AgentProfile(name, did, "lab-owner", "research", tools, "qwen2.5:7b-instruct")


def test_vc_round_trip(issuer):
    agent = AgentKey.generate()
    vc = issue_vc(issuer, profile(agent.did), timedelta(hours=1), NOW)
    assert verify_vc(vc, {issuer.did}, NOW) == profile(agent.did)


def test_tampered_vc_rejected(issuer):
    """Edit the signed payload (grant a tool) and keep the original signature."""
    vc = issue_vc(issuer, profile(AgentKey.generate().did), timedelta(hours=1), NOW)
    header, payload, sig = vc.split(".")
    claims = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    tampered = claims.replace(b'"read_file"', b'"delete_file"')
    assert tampered != claims  # the edit really happened
    forged = base64.urlsafe_b64encode(tampered).rstrip(b"=").decode()
    with pytest.raises(CredentialError):
        verify_vc(f"{header}.{forged}.{sig}", {issuer.did}, NOW)


def test_vc_from_untrusted_issuer_rejected(issuer):
    rogue = AgentKey.generate()
    vc = issue_vc(rogue, profile(AgentKey.generate().did), timedelta(hours=1), NOW)
    with pytest.raises(CredentialError, match="not trusted"):
        verify_vc(vc, {issuer.did}, NOW)


def test_vc_signed_by_other_key_but_claiming_trusted_issuer_rejected(issuer):
    """A rogue key puts the trusted issuer's DID in `kid`: the signature won't verify."""
    rogue = AgentKey.generate()
    rogue.did = issuer.did  # lie about who signed it
    vc = issue_vc(rogue, profile(AgentKey.generate().did), timedelta(hours=1), NOW)
    with pytest.raises(CredentialError):
        verify_vc(vc, {issuer.did}, NOW)


@pytest.mark.parametrize("at", [NOW - timedelta(minutes=1), NOW + timedelta(hours=2)])
def test_vc_outside_validity_rejected(issuer, at):
    vc = issue_vc(issuer, profile(AgentKey.generate().did), timedelta(hours=1), NOW)
    with pytest.raises(CredentialError, match="not currently valid"):
        verify_vc(vc, {issuer.did}, at)


# --- Identity service --------------------------------------------------------------------

ROOT = RootAuthority.generate()
CONFIG = IdentityConfig(
    agents={
        "research-bot": AgentEntry(
            sponsor="lab-owner",
            purpose="research",
            tools=["read_file", "send_email"],
            model="qwen2.5:7b-instruct",
        ),
        "sub-agent": AgentEntry(
            sponsor="research-bot",
            purpose="fetch",
            tools=["fetch_url"],
            model="qwen2.5:7b-instruct",
        ),
    }
)


@pytest.fixture
def service(tmp_path, issuer):
    return IdentityService(issuer, ROOT, CONFIG, tmp_path / "bindings.json", clock=lambda: NOW)


@pytest.fixture
def client(service):
    return TestClient(create_app(service))


def register(client, key, name, at=NOW):
    return client.post("/agents", json={"registration": registration_proof(key, name, at)})


def test_registration_issues_vc_with_tools_from_config(client, issuer):
    key = AgentKey.generate()
    response = register(client, key, "sub-agent")
    assert response.status_code == 200
    vc_profile = verify_vc(response.json()["vc"], {issuer.did}, NOW)
    assert vc_profile.did == key.did and vc_profile.allowed_tools == ("fetch_url",)
    # the root token carries the same tools, owned by the registering DID
    token = response.json()["token"]
    assert authorize(token, ROOT.public_key, key.did, "fetch_url", NOW).allowed
    assert authorize(token, ROOT.public_key, key.did, "send_email", NOW).reason == "rights"


def test_unknown_agent_rejected(client):
    assert register(client, AgentKey.generate(), "intruder").status_code == 403


def test_name_cannot_be_rebound_to_another_did(client):
    """An intruder can't register as research-bot once research-bot has registered."""
    assert register(client, AgentKey.generate(), "research-bot").status_code == 200
    assert register(client, AgentKey.generate(), "research-bot").status_code == 409


def test_re_registering_same_did_is_idempotent(client):
    key = AgentKey.generate()
    assert register(client, key, "research-bot").status_code == 200
    assert register(client, key, "research-bot").status_code == 200


def test_registration_must_be_signed_by_the_did_it_names(client):
    """A proof whose kid names one DID but is signed by another key is refused."""
    victim, rogue = AgentKey.generate(), AgentKey.generate()
    rogue.did = victim.did
    assert register(client, rogue, "research-bot").status_code == 401


def test_stale_registration_rejected(client):
    old = NOW - timedelta(minutes=5)
    assert register(client, AgentKey.generate(), "research-bot", at=old).status_code == 401


def test_bindings_survive_restart(tmp_path, issuer):
    first = IdentityService(issuer, ROOT, CONFIG, tmp_path / "b.json", clock=lambda: NOW)
    first.register(registration_proof(AgentKey.generate(), "research-bot", NOW))
    again = TestClient(
        create_app(IdentityService(issuer, ROOT, CONFIG, tmp_path / "b.json", clock=lambda: NOW))
    )
    assert register(again, AgentKey.generate(), "research-bot").status_code == 409


def test_jws_helper_rejects_wrong_key_and_typ():
    a, b = AgentKey.generate(), AgentKey.generate()
    token = jose.sign(a, {"x": 1}, "t+jwt")
    with pytest.raises(jose.SignatureError):
        jose.verify(token, b.did, "t+jwt")
    with pytest.raises(jose.SignatureError):
        jose.verify(token, a.did, "other+jwt")
