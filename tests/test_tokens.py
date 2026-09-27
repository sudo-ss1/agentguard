"""Biscuit capability tokens, attack 4: offline verification and delegation that only narrows.

Every token here is minted by a real identity-service process, which is then stopped. All
authorization runs with outbound network blocked, so any call home fails the test.
"""

import base64
import socket
import subprocess
import sys
from datetime import UTC, datetime, timedelta

import pytest
from biscuit_auth import Biscuit, BiscuitValidationError, BlockBuilder, UnverifiedBiscuit

from agentguard.identity.client import issuer_info, register
from agentguard.identity.didkey import AgentKey
from agentguard.lab_stack import REPO_ROOT, _free_port, _wait_for_port
from agentguard.tokens.biscuit import (
    TokenError,
    _biscuit_keypair,
    authorize,
    delegate,
    load_root_public_key,
)

# --- a real identity service, stopped before any test runs -------------------------------


@pytest.fixture(scope="module")
def minted(tmp_path_factory):
    state = tmp_path_factory.mktemp("identity")
    port = _free_port()
    service = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "agentguard.identity",
            "--config",
            str(REPO_ROOT / "config" / "identity.yaml"),
            "--state-dir",
            str(state),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for_port(port, service)
        url = f"http://127.0.0.1:{port}"
        parent_key, sub_key = AgentKey.generate(), AgentKey.generate()
        parent = register(url, parent_key, "research-bot")
        sub = register(url, sub_key, "sub-agent")
        root_hex = issuer_info(url).biscuit_root_key
    finally:
        service.terminate()
        service.wait(timeout=10)
    with socket.socket() as s:  # the service is really gone
        assert s.connect_ex(("127.0.0.1", port)) != 0
    root = load_root_public_key(root_hex)
    assert parent.token is not None
    # research-bot narrows its own token for the sub-agent: web fetches only, for 5 minutes.
    # This is local work with the parent's key; no service involved.
    narrowed = delegate(
        parent.token,
        root,
        parent_key,
        sub_key.did,
        ["fetch_url"],
        datetime.now(UTC) + timedelta(minutes=5),
    )
    return {"root": root, "parent": parent, "sub": sub, "narrowed": narrowed}


class NetworkBlocked(AssertionError):
    pass


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise NetworkBlocked("outbound network attempted during an offline test")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def test_network_block_is_active():
    """Guard against a vacuous offline claim: the block really stops connections."""
    with pytest.raises(NetworkBlocked):
        socket.create_connection(("127.0.0.1", 9))


def decide(minted, token, holder_did, tool, at=None):
    return authorize(token, minted["root"], holder_did, tool, at)


# --- positive controls ---------------------------------------------------------------------


def test_parent_can_use_its_own_token(minted):
    parent = minted["parent"]
    assert decide(minted, parent.token, parent.key.did, "send_email").allowed


def test_sub_agent_can_use_its_narrowed_token_for_the_delegated_tool(minted):
    """(f) So the denials below aren't a blanket failure."""
    assert decide(minted, minted["narrowed"], minted["sub"].key.did, "fetch_url").allowed


# --- attack 4 and its variants: all rejected offline -----------------------------------------


def test_sub_agent_reusing_parent_token_is_rejected(minted):
    """(b) Attack 4 itself: the sub-agent presents research-bot's un-narrowed token. Nothing
    signed by research-bot delegates to the sub-agent, so the holder caveat fails."""
    decision = decide(minted, minted["parent"].token, minted["sub"].key.did, "send_email")
    assert not decision.allowed and decision.reason == "holder"


def test_narrowed_token_rejects_tools_outside_the_delegation(minted):
    """(a) The narrowed token's tool caveat stops send_email."""
    decision = decide(minted, minted["narrowed"], minted["sub"].key.did, "send_email")
    assert not decision.allowed and decision.reason == "tool"


def test_sub_agent_cannot_widen_with_its_own_block(minted):
    """(c) First-party blocks can add facts, but `right` counts only from the authority block
    and `delegate` only from a block research-bot signed."""
    widened = Biscuit.from_base64(minted["narrowed"], minted["root"]).append(
        BlockBuilder('right("send_email"); delegate({d});', {"d": minted["sub"].key.did})
    )
    decision = decide(minted, widened.to_base64(), minted["sub"].key.did, "send_email")
    assert not decision.allowed and decision.reason == "tool"


def test_sub_agent_cannot_self_delegate_the_parent_token(minted):
    """(c) Appending delegate(sub) to the parent's token, signed by nobody or by the sub-agent
    itself, doesn't satisfy `trusting <research-bot's key>`."""
    parent = Biscuit.from_base64(minted["parent"].token, minted["root"])
    sub_did = minted["sub"].key.did
    unsigned = parent.append(BlockBuilder("delegate({d});", {"d": sub_did}))
    sub_kp = _biscuit_keypair(minted["sub"].key)
    self_signed = parent.append_third_party(
        sub_kp.public_key,
        parent.third_party_request().create_block(
            sub_kp.private_key, BlockBuilder("delegate({d});", {"d": sub_did})
        ),
    )
    for forged in (unsigned, self_signed):
        decision = decide(minted, forged.to_base64(), sub_did, "send_email")
        assert not decision.allowed and decision.reason == "holder"


def test_delegation_expires(minted):
    """(e) Ten minutes on, the 5-minute delegation no longer authorizes anything."""
    later = datetime.now(UTC) + timedelta(minutes=10)
    decision = decide(minted, minted["narrowed"], minted["sub"].key.did, "fetch_url", later)
    assert not decision.allowed and decision.reason == "expired"


# --- (d) stripping the narrowing block --------------------------------------------------------
# Biscuit's wire format is protobuf: Biscuit { rootKeyId = 1; authority = 2;
# repeated blocks = 3; proof = 4 }. These helpers walk the top-level fields, keeping each
# field's exact bytes so a re-encoding changes nothing except what is removed.


def _varint(buf: bytes, i: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = buf[i]
        value |= (byte & 0x7F) << shift
        i += 1
        if not byte & 0x80:
            return value, i
        shift += 7


def _top_level_fields(buf: bytes) -> list[tuple[int, bytes]]:
    fields, i = [], 0
    while i < len(buf):
        start = i
        key, i = _varint(buf, i)
        number, wire_type = key >> 3, key & 7
        if wire_type == 0:
            _, i = _varint(buf, i)
        elif wire_type == 2:
            length, i = _varint(buf, i)
            i += length
        else:
            raise ValueError(f"unexpected wire type {wire_type}")
        fields.append((number, buf[start:i]))
    return fields


def _b64decode(token: str) -> bytes:
    return base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode()


def test_reencoding_helper_is_faithful(minted):
    """Control: re-encoding with nothing removed gives identical bytes that still verify, so
    the failure below is caused by the removal and nothing else."""
    raw = _b64decode(minted["narrowed"])
    rebuilt = b"".join(field for _, field in _top_level_fields(raw))
    assert rebuilt == raw
    assert Biscuit.from_base64(_b64encode(rebuilt), minted["root"]).block_count() == 2


def test_stripping_the_narrowing_block_breaks_the_signature_chain(minted):
    """(d) Remove the delegation block and re-serialize. The result is a well-formed token,
    since it parses without verification, but its proof no longer matches the last block, so
    verification against the root key fails."""
    raw = _b64decode(minted["narrowed"])
    fields = _top_level_fields(raw)
    block_fields = [i for i, (number, _) in enumerate(fields) if number == 3]
    assert len(block_fields) == 1  # exactly one attenuation block: the delegation
    stripped = _b64encode(b"".join(f for i, (_, f) in enumerate(fields) if i != block_fields[0]))

    unverified = UnverifiedBiscuit.from_base64(stripped)  # parsing succeeds...
    assert unverified.block_count() == 1  # ...and the narrowing block is gone
    with pytest.raises(BiscuitValidationError, match="failed verifying the signature"):
        unverified.verify(minted["root"])  # ...but the signature chain does not verify
    with pytest.raises(TokenError, match="failed verification"):
        decide(minted, stripped, minted["sub"].key.did, "send_email")


def test_token_from_another_root_is_rejected(minted):
    from agentguard.tokens.biscuit import RootAuthority

    rogue = RootAuthority.generate()
    forged = rogue.mint(
        minted["sub"].key.did, ["send_email"], datetime.now(UTC) + timedelta(hours=1)
    )
    with pytest.raises(TokenError):
        decide(minted, forged, minted["sub"].key.did, "send_email")
