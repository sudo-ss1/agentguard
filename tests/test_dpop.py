"""DPoP proofs: each way of forging or reusing one must fail, and only for its own reason."""

from datetime import UTC, datetime, timedelta

import pytest

from agentguard.identity import jose
from agentguard.identity.didkey import AgentKey
from agentguard.identity.dpop import (
    ProofError,
    ReplayCache,
    args_digest,
    create_proof,
    verify_proof,
)

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
URL = "http://127.0.0.1:8000/mcp"
TOKEN = "biscuit-token-b64"


def call(tool="send_email", **arguments):
    arguments = arguments or {"to": "sam@lab.test", "subject": "s", "body": "b"}
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }


@pytest.fixture
def agent():
    return AgentKey.generate()


def check(proof, did, message=None, token=TOKEN, cache=None, htm="POST", htu=URL, now=NOW):
    return verify_proof(proof, did, htm, htu, message or call(), token, cache or ReplayCache(), now)


def test_valid_proof_accepted(agent):
    proof = create_proof(agent, "POST", URL, call(), TOKEN, NOW)
    assert check(proof, agent.did).did == agent.did


def test_missing_proof_rejected(agent):
    with pytest.raises(ProofError, match="no DPoP proof"):
        check(None, agent.did)


def test_proof_by_another_key_claiming_the_did_rejected(agent):
    """An intruder puts research-bot's DID in kid and research-bot's public key in jwk, but
    can only sign with its own key."""
    intruder = AgentKey.generate()
    intruder.did, intruder.public_key = agent.did, agent.public_key  # claim to be the agent
    proof = create_proof(intruder, "POST", URL, call(), TOKEN, NOW)
    with pytest.raises(ProofError, match="signature invalid"):
        check(proof, agent.did)


def test_proof_whose_jwk_is_not_the_credentials_key_rejected(agent):
    proof = create_proof(AgentKey.generate(), "POST", URL, call(), TOKEN, NOW)
    with pytest.raises(ProofError, match="jwk"):
        check(proof, agent.did)


@pytest.mark.parametrize("age", [timedelta(minutes=5), -timedelta(minutes=5)])
def test_stale_or_future_proof_rejected(agent, age):
    proof = create_proof(agent, "POST", URL, call(), TOKEN, NOW - age)
    with pytest.raises(ProofError, match="stale"):
        check(proof, agent.did)


def test_replayed_proof_rejected(agent):
    cache = ReplayCache()
    proof = create_proof(agent, "POST", URL, call(), TOKEN, NOW)
    check(proof, agent.did, cache=cache)
    with pytest.raises(ProofError, match="replay"):
        check(proof, agent.did, cache=cache)


@pytest.mark.parametrize(
    "other",
    [
        call("send_email", to="attacker@evil.test", subject="s", body="b"),  # same tool, new args
        call("delete_file", path="/"),  # different tool
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    ],  # different MCP method
)
def test_proof_cannot_be_moved_to_another_mcp_message(agent, other):
    proof = create_proof(agent, "POST", URL, call(), TOKEN, NOW)
    with pytest.raises(ProofError, match="different MCP message"):
        check(proof, agent.did, message=other)


def test_proof_for_other_url_rejected(agent):
    proof = create_proof(agent, "POST", "http://elsewhere/mcp", call(), TOKEN, NOW)
    with pytest.raises(ProofError, match="different method or URL"):
        check(proof, agent.did)


def test_proof_bound_to_another_token_rejected(agent):
    proof = create_proof(agent, "POST", URL, call(), "some-other-token", NOW)
    with pytest.raises(ProofError, match="different token"):
        check(proof, agent.did)


def test_proof_bound_to_a_token_that_was_not_sent_rejected(agent):
    proof = create_proof(agent, "POST", URL, call(), TOKEN, NOW)
    with pytest.raises(ProofError, match="not sent"):
        check(proof, agent.did, token=None)


def test_rejected_proof_does_not_burn_its_nonce(agent):
    """A proof checked against the wrong message is refused without consuming its jti."""
    cache = ReplayCache()
    proof = create_proof(agent, "POST", URL, call(), TOKEN, NOW)
    with pytest.raises(ProofError):
        check(proof, agent.did, message=call("delete_file", path="/"), cache=cache)
    assert check(proof, agent.did, cache=cache).did == agent.did


def test_args_digest_is_canonical():
    assert args_digest({"b": 1, "a": "x"}) == args_digest({"a": "x", "b": 1})
    assert args_digest({"a": 1}) != args_digest({"a": 2})


def test_header_is_rfc9449_shape(agent):
    header = jose.unverified_header(create_proof(agent, "POST", URL, call(), TOKEN, NOW))
    assert header["typ"] == "dpop+jwt" and header["alg"] == "Ed25519"
    assert header["jwk"] == jose.public_jwk_dict(agent.public_key) and "d" not in header["jwk"]
