"""`agentguard ledger verify` and `ledger pubkey`: output and exit codes."""

import json

from typer.testing import CliRunner

from agentguard.cli import app
from agentguard.identity.didkey import AgentKey
from agentguard.ledger import keys
from agentguard.ledger.writer import CHECKPOINTS_FILE, Ledger

runner = CliRunner()


def make(tmp_path, n=5):
    key = keys.load_or_create(tmp_path / "key")
    led = Ledger(tmp_path / "receipts.jsonl", key, tmp_path / "roots", checkpoint_interval_s=3600)
    for i in range(n):
        led.append("decision", {"tool": "list_dir", "decision": "deny", "i": i})
    led.close()
    keys.export_public(key, tmp_path / "roots")
    return key


def verify_args(tmp_path, *extra):
    return [
        "ledger",
        "verify",
        "--log",
        str(tmp_path / "receipts.jsonl"),
        "--public-key",
        str(tmp_path / "roots" / keys.PUBLIC_KEY_FILE),
        *extra,
    ]


def test_intact_exits_0(tmp_path):
    make(tmp_path)
    result = runner.invoke(
        app, verify_args(tmp_path, "--checkpoints", str(tmp_path / "roots" / CHECKPOINTS_FILE))
    )
    assert result.exit_code == 0, result.output
    assert "result: INTACT" in result.output


def test_tampered_exits_1_and_names_the_line(tmp_path):
    make(tmp_path)
    log = tmp_path / "receipts.jsonl"
    lines = log.read_text().splitlines(keepends=True)
    row = json.loads(lines[3])
    row["body"]["decision"] = "allow"
    lines[3] = json.dumps(row) + "\n"
    log.write_text("".join(lines))
    result = runner.invoke(app, verify_args(tmp_path))
    assert result.exit_code == 1
    assert "FIRST BROKEN LINK: line 4 (seq 3): hash" in result.output
    as_json = runner.invoke(app, [*verify_args(tmp_path), "--json"])
    report = json.loads(as_json.stdout)
    assert report["intact"] is False and report["first_broken"]["line"] == 4


def test_without_checkpoints_require_checkpoint_fails(tmp_path):
    make(tmp_path)
    assert runner.invoke(app, verify_args(tmp_path)).exit_code == 0
    assert runner.invoke(app, verify_args(tmp_path, "--require-checkpoint")).exit_code == 1


def test_a_phase4_log_or_missing_file_exits_2(tmp_path):
    make(tmp_path)
    (tmp_path / "receipts.jsonl").write_text(json.dumps({"tool": "x", "decision": "deny"}) + "\n")
    result = runner.invoke(app, verify_args(tmp_path))
    assert result.exit_code == 2 and "not a signed ledger" in result.output
    (tmp_path / "receipts.jsonl").unlink()
    assert runner.invoke(app, verify_args(tmp_path)).exit_code == 2


def test_the_wrong_key_as_a_did(tmp_path):
    make(tmp_path)
    args = verify_args(tmp_path)
    args[args.index("--public-key") + 1] = AgentKey.generate().did
    result = runner.invoke(app, args)
    assert result.exit_code == 1 and "wrong public key" in result.output


def test_pubkey_prints_the_did(tmp_path):
    key = make(tmp_path)
    result = runner.invoke(app, ["ledger", "pubkey", "--key-dir", str(tmp_path / "key")])
    assert result.exit_code == 0 and result.output.strip() == key.did
