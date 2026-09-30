"""Receipt option C: structured reasons, salted commitments, proving and erasing values."""

import asyncio
import json

import pytest
from typer.testing import CliRunner

from agentguard.attacks import load_scenario, run_scripted
from agentguard.cli import app
from agentguard.gateway.audit import commitment_in, prove, read_receipt
from agentguard.gateway.checks import CallContext, Decision
from agentguard.gateway.commitments import SaltStore, digest, matches
from agentguard.gateway.receipts import ReceiptLog, path_class
from agentguard.identity.didkey import AgentKey
from agentguard.lab_stack import local_lab
from agentguard.ledger.read import calls
from agentguard.ledger.writer import Ledger

# --- commitments ------------------------------------------------------------------------------


def test_commitment_proves_only_the_committed_value(tmp_path):
    salts = SaltStore(tmp_path / "salts.jsonl")
    c = salts.commit("recipient", "attacker@evil.test")
    salt = salts.salt_for(c)
    assert matches(c, "recipient", "attacker@evil.test", salt)
    assert not matches(c, "recipient", "sam@lab.test", salt)  # wrong value
    assert not matches(c, "path", "attacker@evil.test", salt)  # wrong attribute name
    assert not matches(c, "recipient", "attacker@evil.test", "A" * 22)  # wrong salt


def test_same_value_gets_unlinkable_commitments(tmp_path):
    """Fresh salt per value: two denials for the same recipient can't be linked by digest."""
    salts = SaltStore(tmp_path / "salts.jsonl")
    assert salts.commit("recipient", "x@evil.test") != salts.commit("recipient", "x@evil.test")


def test_salt_store_is_owner_only(tmp_path):
    salts = SaltStore(tmp_path / "salts.jsonl")
    salts.commit("path", "/")
    assert (tmp_path / "salts.jsonl").stat().st_mode & 0o777 == 0o600


# --- structured reasons -------------------------------------------------------------------------


def write(tmp_path, decision, upstream_exception=None):
    """Record one call; returns it as one record (decision and outcome merged), and the log."""
    ledger = Ledger(tmp_path / "r.jsonl", AgentKey.generate(), tmp_path / "roots")
    log = ReceiptLog(ledger, SaltStore(tmp_path / "s.jsonl"))
    context = CallContext("research-bot", "send_email", "email", {})
    seq = log.decision(context, decision, decision_ms=0.1)
    if upstream_exception is not None:
        log.outcome(seq, context, upstream_exception=upstream_exception)
    ledger.close()
    (record,) = calls(tmp_path / "r.jsonl")
    return record, (tmp_path / "r.jsonl").read_text()


def test_coarse_values_in_clear_precise_values_committed(tmp_path):
    context = {"recipient": "attacker@evil.test", "recipient_domain": "evil.test"}
    receipt, text = write(
        tmp_path, Decision("deny", "no policy permits this call", "default-deny", context)
    )
    attributes = receipt["reason"]["attributes"]
    assert receipt["reason"]["rule"] == "default-deny"
    assert attributes["recipient_domain"] == "evil.test"
    assert set(attributes["recipient"]) == {"commitment"}
    assert "attacker@evil.test" not in text


def test_path_gets_a_coarse_class_and_a_commitment(tmp_path):
    receipt, text = write(
        tmp_path,
        Decision("deny", "forbidden by policy", "no-ssh-keys", {"path": "/home/agent/.ssh/id_rsa"}),
    )
    attributes = receipt["reason"]["attributes"]
    assert attributes["path_class"] == "outside /workspace"
    assert set(attributes["path"]) == {"commitment"}
    assert ".ssh" not in text


def test_unknown_attributes_are_committed_by_default(tmp_path):
    receipt, text = write(
        tmp_path,
        Decision(
            "deny",
            "cedar failed (ValueError)",
            "cedar-error",
            {"error_message": "bad value SECRET-123"},
        ),
    )
    assert set(receipt["reason"]["attributes"]["error_message"]) == {"commitment"}
    assert "SECRET-123" not in text


def test_upstream_error_is_class_plus_commitment_never_repr(tmp_path):
    exc = ConnectionError("POST http://files:8001/mcp?token=SECRET-TOKEN failed")
    receipt, text = write(
        tmp_path, Decision("allow", "permitted", "email-internal-only"), upstream_exception=exc
    )
    assert receipt["upstream_error"]["exception"] == "ConnectionError"
    assert set(receipt["upstream_error"]["message"]) == {"commitment"}
    assert "SECRET-TOKEN" not in text and "files:8001" not in text


@pytest.mark.parametrize(
    ("path", "cls"),
    [
        ("/workspace/tmp/a", "inside /workspace/tmp"),
        ("/workspace/notes.txt", "inside /workspace"),
        ("/workspace", "inside /workspace"),
        ("/workspacex", "outside /workspace"),
        ("/", "outside /workspace"),
    ],
)
def test_path_classes(path, cls):
    assert path_class(path) == cls


# --- real attack runs ---------------------------------------------------------------------------

SENSITIVE = ["attacker@evil.test", "/home/agent/.ssh/id_rsa", "~/.ssh", "id_rsa"]


@pytest.fixture(scope="module")
def attack_receipts():
    with local_lab(guarded=True) as lab:
        for scenario in (1, 2):
            outcome = asyncio.run(run_scripted(load_scenario(scenario), lab))
            assert not outcome.succeeded
        yield lab, lab.receipts_path.read_text(), SaltStore(lab.salts_path)


def test_real_attack_receipts_hold_no_recipient_or_exact_path(attack_receipts):
    lab, text, _ = attack_receipts
    for needle in SENSITIVE:
        assert needle not in text, f"{needle!r} leaked into the receipt log"
    for receipt in calls(lab.receipts_path):
        attributes = receipt["reason"].get("attributes", {})
        for name in ("recipient", "path", "error_message"):
            if name in attributes:  # present only as a commitment
                assert set(attributes[name]) == {"commitment"}, (name, receipt)
        assert "context" not in json.dumps(receipt["reason"]["summary"])


def test_attack_2_delete_of_root_is_class_and_commitment_only(attack_receipts):
    lab, _, salts = attack_receipts
    (delete,) = [r for r in calls(lab.receipts_path) if r["tool"] == "delete_file"]
    attributes = delete["reason"]["attributes"]
    assert attributes["path_class"] == "outside /workspace"
    assert prove(delete, "path", "/", salts).status == "proven"


def test_revealing_the_salt_proves_the_recipient(attack_receipts):
    lab, _, salts = attack_receipts
    (email,) = [r for r in calls(lab.receipts_path) if r["tool"] == "send_email"]
    assert prove(email, "recipient", "attacker@evil.test", salts).status == "proven"
    assert prove(email, "recipient", "sam@lab.test", salts).status == "mismatch"


def test_deleting_the_salt_erases_the_value_but_not_the_receipt(attack_receipts):
    lab, _, salts = attack_receipts
    before = lab.receipts_path.read_bytes()
    lines = before.decode().splitlines()
    number = next(
        i for i, line in enumerate(lines, 1) if '"read_file"' in line and '"deny"' in line
    )
    receipt = read_receipt(lab.receipts_path, number)
    assert prove(receipt, "path", "/home/agent/.ssh/id_rsa", salts).status == "proven"

    assert salts.forget(commitment_in(receipt, "path"))
    assert prove(receipt, "path", "/home/agent/.ssh/id_rsa", salts).status == "salt-deleted"
    assert lab.receipts_path.read_bytes() == before  # the receipt log is untouched
    # the salt store no longer holds anything for this commitment
    assert commitment_in(receipt, "path") not in salts.path.read_text()


def test_cli_prove_exit_codes(attack_receipts):
    lab, text, _ = attack_receipts
    number = next(i for i, line in enumerate(text.splitlines(), 1) if '"send_email"' in line)
    base = [
        "receipts",
        "prove",
        "--receipts",
        str(lab.receipts_path),
        "--line",
        str(number),
        "--attribute",
        "recipient",
        "--salts",
        str(lab.salts_path),
    ]
    runner = CliRunner()
    good = runner.invoke(app, [*base, "--value", "attacker@evil.test"])
    bad = runner.invoke(app, [*base, "--value", "sam@lab.test"])
    assert good.exit_code == 0 and good.output.startswith("proven")
    assert bad.exit_code == 1 and bad.output.startswith("mismatch")


def test_digest_is_sd_jwt_style():
    """base64url(SHA-256(base64url(JCS([salt, name, value])))): 43 chars, no padding."""
    d = digest("c2FsdA", "path", "/")
    assert len(d) == 43 and "=" not in d
