"""The ledger writer and verifier: chaining, checkpoints, recovery, and every tampering case."""

import hashlib
import json
import threading

import pytest

from agentguard.identity.didkey import AgentKey
from agentguard.ledger import merkle, writer
from agentguard.ledger.canonical import (
    RECEIPT_TAG,
    CanonicalError,
    body_hash,
    parse_line,
    seal,
)
from agentguard.ledger.read import calls
from agentguard.ledger.verify import VerifyInputError, verify
from agentguard.ledger.writer import Ledger, LedgerError

N = 10  # receipts after genesis


@pytest.fixture
def key():
    return AgentKey.generate()


def open_ledger(tmp_path, key, **kw) -> Ledger:
    kw = {"checkpoint_interval_s": 3600, "fsync_interval_s": 3600, **kw}
    return Ledger(tmp_path / "receipts.jsonl", key, tmp_path / "roots", **kw)


def decision(i: int, verdict: str = "deny") -> dict:
    return {"tool": "send_email", "decision": verdict, "policy_id": "default-deny", "i": i}


@pytest.fixture
def ledger_file(tmp_path, key):
    """A closed ledger: genesis + N decisions, with a final checkpoint."""
    led = open_ledger(tmp_path, key)
    for i in range(N):
        led.append("decision", decision(i))
    led.close()
    return tmp_path / "receipts.jsonl"


def checkpoints(tmp_path):
    return tmp_path / "roots" / writer.CHECKPOINTS_FILE


def lines_of(path):
    return path.read_bytes().splitlines(keepends=True)


def write_lines(path, lines):
    path.write_bytes(b"".join(lines))


def edit_body(line: bytes, **changes) -> bytes:
    row = json.loads(line)
    row["body"].update(changes)
    return (json.dumps(row) + "\n").encode()


def run(tmp_path, key, with_checkpoints=True, public_key=None):
    return verify(
        tmp_path / "receipts.jsonl",
        public_key or key.public_key,
        checkpoints(tmp_path) if with_checkpoints else None,
    )


# --- positive controls -----------------------------------------------------------------------


def test_an_untouched_ledger_verifies(tmp_path, key, ledger_file):
    report = run(tmp_path, key)
    assert report.intact and report.tampering == [] and report.warnings == []
    assert report.receipts == N + 1
    assert report.proven_size == N + 1 and report.verified_checkpoints == 1
    assert report.exit_code(require_checkpoint=True) == 0
    bodies = [parse_line(line)["body"] for line in lines_of(ledger_file)]
    assert [b["seq"] for b in bodies] == list(range(N + 1))
    assert bodies[0]["kind"] == "genesis" and bodies[0]["key"] == key.did
    assert all(
        b["prev"] == parse_line(p)["hash"]
        for b, p in zip(bodies[1:], lines_of(ledger_file)[:-1], strict=True)
    )


def test_reopening_continues_the_chain(tmp_path, key, ledger_file):
    led = open_ledger(tmp_path, key)
    assert led.seq == N
    led.append("decision", decision(99))
    led.close()
    report = run(tmp_path, key)
    assert report.intact and report.receipts == N + 2 and report.verified_checkpoints == 2


def test_parallel_appends_give_one_gap_free_chain(tmp_path, key):
    led = open_ledger(tmp_path, key)
    threads = [
        threading.Thread(target=lambda: [led.append("decision", decision(i)) for i in range(200)])
        for _ in range(8)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    led.close()
    report = run(tmp_path, key)
    assert report.intact and report.receipts == 1 + 8 * 200


def test_a_value_rfc8785_cannot_represent_is_refused_and_nothing_is_written(tmp_path, key):
    led = open_ledger(tmp_path, key)
    before = (tmp_path / "receipts.jsonl").read_bytes()
    with pytest.raises(CanonicalError):
        led.append("decision", {"x": float("nan")})
    assert (tmp_path / "receipts.jsonl").read_bytes() == before and led.seq == 0
    led.append("decision", decision(1))
    led.close()
    assert run(tmp_path, key).intact


# --- attack 7 and the other tampering cases --------------------------------------------------


def test_an_edited_receipt_is_the_broken_link(tmp_path, key, ledger_file):
    lines = lines_of(ledger_file)
    lines[5] = edit_body(lines[5], decision="allow")  # line 6, seq 5
    write_lines(ledger_file, lines)
    report = run(tmp_path, key)
    assert not report.intact
    first = report.first_broken
    assert (first.line, first.seq, first.check) == (6, 5, "hash")
    assert "changed after it was signed" in first.detail
    assert len(report.tampering) == 1  # nothing else looks wrong
    assert report.last_good_seq == 4
    assert "FIRST BROKEN LINK: line 6 (seq 5): hash" in report.text()


def test_an_edited_and_rehashed_receipt_fails_its_signature(tmp_path, key, ledger_file):
    lines = lines_of(ledger_file)
    row = json.loads(lines[5])
    row["body"]["decision"] = "allow"
    row["hash"] = body_hash(row["body"])  # the attacker fixes the hash, but can't sign
    lines[5] = (json.dumps(row) + "\n").encode()
    write_lines(ledger_file, lines)
    report = run(tmp_path, key)
    first = report.first_broken
    assert (first.line, first.check) == (6, "signature")
    next_link = [f for f in report.tampering if f.line == 7]
    assert next_link and next_link[0].check == "prev"  # and the next receipt no longer links


def test_a_forged_signature_is_detected(tmp_path, key, ledger_file):
    lines = lines_of(ledger_file)
    body = dict(parse_line(lines[5])["body"], decision="allow")
    lines[5], _ = seal(AgentKey.generate().signing_key, RECEIPT_TAG, body)  # the wrong key
    write_lines(ledger_file, lines)
    first = run(tmp_path, key).first_broken
    assert (first.line, first.seq, first.check) == (6, 5, "signature")


def test_a_deleted_middle_receipt_is_named(tmp_path, key, ledger_file):
    lines = lines_of(ledger_file)
    del lines[5]  # seq 5
    write_lines(ledger_file, lines)
    report = run(tmp_path, key, with_checkpoints=False)
    first = report.first_broken
    assert (first.line, first.seq, first.check) == (6, 6, "seq-gap")
    assert "seq 5 missing" in first.detail and "prev" in first.checks


def test_reordered_receipts_are_named(tmp_path, key, ledger_file):
    lines = lines_of(ledger_file)
    lines[5], lines[6] = lines[6], lines[5]
    write_lines(ledger_file, lines)
    report = run(tmp_path, key)
    first = report.first_broken
    assert (first.line, first.seq, first.check) == (6, 6, "seq-order")
    assert "out of order" in first.detail


def test_a_deleted_tail_is_caught_only_against_a_checkpoint(tmp_path, key, ledger_file):
    write_lines(ledger_file, lines_of(ledger_file)[:-3])
    without = run(tmp_path, key, with_checkpoints=False)
    assert without.intact  # the chain alone can't tell...
    assert [w.check for w in without.warnings] == ["tail-unproven"]  # ...and says so
    assert without.exit_code(require_checkpoint=True) == 1
    report = run(tmp_path, key)
    assert not report.intact
    (missing,) = [f for f in report.tampering if f.check == "tail-missing"]
    assert f"seq {N - 2}–{N} were deleted from the end" in missing.detail


def test_the_wrong_public_key_fails_every_receipt(tmp_path, key, ledger_file):
    report = run(tmp_path, key, public_key=AgentKey.generate().public_key)
    assert (report.first_broken.line, report.first_broken.check) == (1, "signature")
    assert len([f for f in report.tampering if f.line is not None]) == N + 1
    assert report.warnings[0].check == "wrong-key" and key.did in report.warnings[0].detail
    assert any(f.check == "checkpoint-signature" for f in report.tampering)


def test_an_edited_checkpoint_is_detected(tmp_path, key, ledger_file):
    path = checkpoints(tmp_path)
    row = json.loads(path.read_text())
    row["body"]["size"] = 3
    path.write_text(json.dumps(row) + "\n")
    report = run(tmp_path, key)
    assert "checkpoint-signature" in [f.check for f in report.tampering]


def test_a_phase4_unsigned_log_is_not_a_ledger(tmp_path, key):
    log = tmp_path / "receipts.jsonl"
    log.write_text(json.dumps({"tool": "send_email", "decision": "deny"}) + "\n")
    with pytest.raises(VerifyInputError, match="not a signed ledger"):
        verify(log, key.public_key)


# --- outcome unknown -------------------------------------------------------------------------


def test_an_allowed_decision_without_an_outcome_is_outcome_unknown(tmp_path, key):
    led = open_ledger(tmp_path, key)
    done, _ = led.append("decision", decision(1, "allow"))
    led.append("outcome", {"decision_seq": done, "upstream_error": False})
    pending, _ = led.append("decision", decision(2, "allow"))
    led.append("decision", decision(3, "deny"))  # a denial needs no outcome
    led.close()
    report = run(tmp_path, key)
    assert report.intact and report.outcome_unknown == [pending]
    assert "outcome unknown: 1 allowed call(s)" in report.text()
    rows = calls(tmp_path / "receipts.jsonl")
    assert [r.get("outcome") for r in rows] == ["recorded", "unknown", None]
    assert rows[0]["upstream_error"] is False


# --- torn tail recovery ----------------------------------------------------------------------

TORN = b'{"body":{"decision":"deny","kind":"deci'


def test_a_torn_tail_is_moved_aside_and_recorded(tmp_path, key, ledger_file):
    complete = ledger_file.read_bytes()
    ledger_file.write_bytes(complete + TORN)
    before = run(tmp_path, key)
    assert before.intact and before.warnings[0].check == "torn-tail"
    led = open_ledger(tmp_path, key)
    moved = led.recovery.moved_to
    assert moved.read_bytes() == TORN  # moved, never deleted
    assert led.recovery.sha256 == hashlib.sha256(TORN).hexdigest()
    led.close()
    data = ledger_file.read_bytes()
    assert data.startswith(complete)  # every complete line untouched
    body = parse_line(data.splitlines()[N + 1])["body"]
    assert body["kind"] == "recovery" and body["torn_bytes"] == len(TORN)
    assert body["torn_sha256"] == hashlib.sha256(TORN).hexdigest()
    assert run(tmp_path, key).intact


def test_recovery_never_touches_a_complete_line_even_an_invalid_one(tmp_path, key, ledger_file):
    lines = lines_of(ledger_file)
    lines[-1] = edit_body(lines[-1], decision="allow")  # a complete but invalid last line
    write_lines(ledger_file, lines)
    complete = ledger_file.read_bytes()
    with pytest.raises(LedgerError, match="does not verify"):
        open_ledger(tmp_path, key)
    assert ledger_file.read_bytes() == complete  # not repaired, not truncated
    ledger_file.write_bytes(complete + TORN)
    with pytest.raises(LedgerError, match="does not verify"):
        open_ledger(tmp_path, key)
    assert ledger_file.read_bytes() == complete  # only the torn bytes went...
    (moved,) = tmp_path.glob("receipts.jsonl.torn-*.bin")
    assert moved.read_bytes() == TORN  # ...and they were kept


def test_a_malformed_complete_line_stops_startup_untouched(tmp_path, key, ledger_file):
    lines = lines_of(ledger_file)
    lines[3] = b"this is not json\n"
    write_lines(ledger_file, lines)
    before = ledger_file.read_bytes()
    with pytest.raises(LedgerError, match="line 4"):
        open_ledger(tmp_path, key)
    assert ledger_file.read_bytes() == before


def test_the_checkpoint_check_runs_after_recovery(tmp_path, key, ledger_file):
    # The last receipt is deleted, then a crash leaves torn bytes behind.
    write_lines(ledger_file, lines_of(ledger_file)[:-1])
    ledger_file.write_bytes(ledger_file.read_bytes() + TORN)
    with pytest.raises(LedgerError, match="receipts are missing"):
        open_ledger(tmp_path, key)
    (moved,) = tmp_path.glob("receipts.jsonl.torn-*.bin")  # recovery ran first
    assert moved.read_bytes() == TORN
    assert ledger_file.read_bytes().endswith(b"\n")


def test_a_torn_tail_alone_passes_the_checkpoint_check(tmp_path, key, ledger_file):
    ledger_file.write_bytes(ledger_file.read_bytes() + TORN)
    open_ledger(tmp_path, key).close()  # the checkpoint still matches after recovery
    assert run(tmp_path, key).intact


def test_an_emptied_ledger_with_checkpoints_refuses_to_start(tmp_path, key, ledger_file):
    ledger_file.write_bytes(b"")
    with pytest.raises(LedgerError, match="receipts are missing"):
        open_ledger(tmp_path, key)


def test_a_replaced_checkpointed_receipt_refuses_to_start(tmp_path, key, ledger_file):
    lines = lines_of(ledger_file)
    body = dict(parse_line(lines[-1])["body"], decision="allow")
    lines[-1], _ = seal(key.signing_key, RECEIPT_TAG, body)  # even with the gateway's own key
    write_lines(ledger_file, lines)
    with pytest.raises(LedgerError, match="checkpoint's head"):
        open_ledger(tmp_path, key)


# --- single writer and durability ------------------------------------------------------------


def test_a_second_writer_is_refused(tmp_path, key):
    led = open_ledger(tmp_path, key)
    with pytest.raises(LedgerError, match="another process"):
        open_ledger(tmp_path, key)
    led.close()
    open_ledger(tmp_path, key).close()  # free again once closed


def count_fsyncs(monkeypatch) -> list[int]:
    calls_made: list[int] = []
    real = writer.os.fsync
    monkeypatch.setattr(writer.os, "fsync", lambda fd: (calls_made.append(fd), real(fd))[1])
    return calls_made


def test_strict_durability_fsyncs_every_decision_receipt(tmp_path, key, monkeypatch):
    led = open_ledger(tmp_path, key, durability="strict")
    fsyncs = count_fsyncs(monkeypatch)
    for i in range(5):
        seq, _ = led.append("decision", decision(i, "allow"))
        assert len(fsyncs) == i + 1  # durable before append returns
        led.append("outcome", {"decision_seq": seq})
    assert len(fsyncs) == 5  # outcome receipts follow the batched schedule
    led.close()


def test_batched_durability_fsyncs_in_the_background(tmp_path, key, monkeypatch):
    led = open_ledger(tmp_path, key, fsync_interval_s=0.05)
    fsyncs = count_fsyncs(monkeypatch)
    for i in range(5):
        led.append("decision", decision(i))
    assert fsyncs == []  # appends don't wait for the disk
    threading.Event().wait(0.3)
    assert fsyncs  # the background thread did
    led.close()


def test_periodic_checkpoints(tmp_path, key):
    led = open_ledger(tmp_path, key, checkpoint_interval_s=0.05)
    led.append("decision", decision(1))
    threading.Event().wait(0.3)
    assert len(writer.read_checkpoints(checkpoints(tmp_path))) == 1
    led.close()  # nothing new since: no second checkpoint
    assert len(writer.read_checkpoints(checkpoints(tmp_path))) == 1


# --- Merkle ----------------------------------------------------------------------------------


def naive_root(entries: list[bytes]) -> bytes:
    """RFC 9162 section 2.1.1, transcribed directly."""
    if not entries:
        return hashlib.sha256(b"").digest()
    if len(entries) == 1:
        return hashlib.sha256(b"\x00" + entries[0]).digest()
    k = 1
    while k << 1 < len(entries):
        k <<= 1
    return hashlib.sha256(b"\x01" + naive_root(entries[:k]) + naive_root(entries[k:])).digest()


@pytest.mark.parametrize("n", [0, 1, 2, 3, 4, 5, 7, 8, 9, 31, 64])
def test_merkle_root(n):
    entries = [hashlib.sha256(bytes([i])).digest() for i in range(n)]
    assert merkle.root(entries) == naive_root(entries)
    if n == 3:  # the unbalanced shape RFC 9162 specifies: (a, b), c
        a, b, c = (merkle.leaf_hash(e) for e in entries)
        assert merkle.root(entries) == merkle.node_hash(merkle.node_hash(a, b), c)
