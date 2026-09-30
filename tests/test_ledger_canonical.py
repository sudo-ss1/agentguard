"""The ledger's canonical form: exactly which bytes are hashed and signed.

The fixed vector below was cross-checked outside this code: its JCS text hashes to the same
value with `sha256sum`, and its signature verifies with the `cryptography` package's Ed25519.
"""

import hashlib
import json

import nacl.signing
import pytest

from agentguard.ledger.canonical import (
    CHECKPOINT_TAG,
    GENESIS_PREV,
    RECEIPT_TAG,
    CanonicalError,
    LineError,
    body_hash,
    jcs,
    parse_line,
    seal,
    signature_valid,
)

SEED = bytes(range(32))
PUBLIC_HEX = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
BODY = {
    "v": 1,
    "ledger_id": "00112233445566778899aabbccddeeff",
    "seq": 0,
    "prev": GENESIS_PREV,
    "kind": "decision",
    "tool": "send_email",
    "decision": "deny",
    "decision_ms": 3.25,
    "reason": {"rule": "default-deny", "summary": "café €"},
}
JCS_TEXT = (
    '{"decision":"deny","decision_ms":3.25,"kind":"decision",'
    '"ledger_id":"00112233445566778899aabbccddeeff",'
    '"prev":"0000000000000000000000000000000000000000000000000000000000000000",'
    '"reason":{"rule":"default-deny","summary":"café €"},'
    '"seq":0,"tool":"send_email","v":1}'
)
HASH = "ac8a9bb7665eb3a898ce7bfbb87563166cd3ff698c4e706f8ff864b186be6f49"
SIG = "_NjKxX2etyP24g-Ou9hHJSf6_1Y1qsLgJS3rzEaXR1kCrYu_wxNoIsf8MuqQI_7Sm9YhDUwEwOzNk-dpoI1BCQ"

KEY = nacl.signing.SigningKey(SEED)


def test_fixed_vector():
    assert bytes(KEY.verify_key).hex() == PUBLIC_HEX
    assert jcs(BODY) == JCS_TEXT.encode("utf-8")
    assert hashlib.sha256(JCS_TEXT.encode("utf-8")).hexdigest() == HASH == body_hash(BODY)
    line, h = seal(KEY, RECEIPT_TAG, BODY)
    assert h == HASH
    assert line == ('{"body":' + JCS_TEXT + ',"hash":"' + HASH + '","sig":"' + SIG + '"}\n').encode(
        "utf-8"
    )


def test_fixed_vector_signature_verifies_with_an_independent_library():
    ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    import base64

    public = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(PUBLIC_HEX))
    public.verify(base64.urlsafe_b64decode(SIG + "=="), RECEIPT_TAG + bytes.fromhex(HASH))


def test_jcs_rules():
    assert jcs({"b": 1, "a": {"d": [True, None], "c": "x"}}) == (
        b'{"a":{"c":"x","d":[true,null]},"b":1}'
    )
    assert jcs({"x": 1.0}) == b'{"x":1}'  # ES6 number formatting
    assert jcs({"x": 1e21}) == b'{"x":1e+21}'
    assert jcs({"x": "\u000f"}) == b'{"x":"\\u000f"}'  # control characters escaped
    assert jcs({"x": "€"}) == '{"x":"€"}'.encode()  # other text stays UTF-8


@pytest.mark.parametrize(
    "value",
    [
        {"x": float("nan")},
        {"x": float("inf")},
        {"x": 2**53},
        {"x": -(2**53)},
        {"x": {1, 2}},
        {1: "non-string key"},
        {"x": b"bytes"},
    ],
)
def test_values_rfc8785_cannot_represent_exactly_are_refused(value):
    with pytest.raises(CanonicalError):
        jcs(value)


def test_limits_themselves_are_allowed():
    assert jcs({"x": 2**53 - 1, "y": -(2**53 - 1)})


def test_signatures():
    public = bytes(KEY.verify_key)
    assert signature_valid(public, RECEIPT_TAG, HASH, SIG)
    assert not signature_valid(public, CHECKPOINT_TAG, HASH, SIG)  # domain-separated
    other = bytes(nacl.signing.SigningKey(bytes(32)).verify_key)
    assert not signature_valid(other, RECEIPT_TAG, HASH, SIG)  # wrong key
    assert not signature_valid(public, RECEIPT_TAG, "00" * 32, SIG)  # different hash
    assert not signature_valid(public, RECEIPT_TAG, HASH, "not base64!")
    assert not signature_valid(public, RECEIPT_TAG, "zz", SIG)


def test_parse_line_recanonicalizes():
    line, h = seal(KEY, RECEIPT_TAG, BODY)
    spaced = json.dumps(json.loads(line), indent=2)  # same content, different bytes
    parsed = parse_line(spaced)
    assert body_hash(parsed["body"]) == h == parsed["hash"]


@pytest.mark.parametrize(
    "text",
    [
        '{"body": {"a": 1, "a": 2}, "hash": "h", "sig": "s"}',  # duplicate key
        '{"body": {}, "hash": "h", "sig": "s", "extra": 1}',
        '{"body": {}, "hash": "h"}',
        '{"body": [], "hash": "h", "sig": "s"}',
        '{"body": {}, "hash": 1, "sig": "s"}',
        '{"body": {"x": NaN}, "hash": "h", "sig": "s"}',
        "not json",
        "[]",
    ],
)
def test_malformed_lines_are_rejected(text):
    with pytest.raises(LineError):
        parse_line(text)
