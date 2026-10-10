"""The dashboard (Phase 6): it shows only what receipts show, can't write the ledger, acts only
through the CLI's functions as the OS user, and serves only on the required options."""

import ast
import builtins
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from streamlit import config as st_config
from streamlit.testing.v1 import AppTest
from typer.testing import CliRunner

from agentguard import ops
from agentguard.cli import DASHBOARD_OPTIONS, app
from agentguard.dashboard import data
from agentguard.dashboard.app import REQUIRED_OPTIONS
from agentguard.discovery.inventory import Inventory
from agentguard.guards.secrets import SecretScanner
from agentguard.ledger import keys
from agentguard.ledger.writer import CHECKPOINTS_FILE
from tests.canaries import anthropic_canary, assert_absent, github_canary
from tests.gateway_helpers import call, ctx

REPO = Path(__file__).parents[1]
PAGE = REPO / "src/agentguard/dashboard/app.py"
REASON = "suspected exfiltration to the partner bucket"
runner = CliRunner()


@pytest.fixture
async def lab(gateway, tmp_path):
    """A real gateway's ledger, pins and guard state, holding canaries everywhere a value could
    leak: call arguments, a kill reason, a pending approval's arguments, a scanned key."""
    in_path, in_approval, in_repo = github_canary(), anthropic_canary(), anthropic_canary()
    # policy allows the read, the secret scanner denies it: the token is committed
    await gateway.on_call_tool(ctx("research-bot"), call("read_file", path=f"/workspace/{in_path}"))
    await gateway.on_call_tool(ctx("research-bot"), call("read_file", path="~/.ssh/id_rsa"))
    state = gateway.config.guards.state_dir
    ops.kill(state, ops.operator("cli"), REASON, agent="sub-agent")
    gateway.guard_state.refresh()
    pending = state / "approvals" / "pending"
    pending.mkdir(parents=True, exist_ok=True)
    (pending / "a1b2c3.json").write_text(
        json.dumps(
            {"id": "a1b2c3", "created": "2026-10-10T08:00:00+00:00", "agent": "research-bot",
             "tool": "send_email", "why": "send_email always needs human approval",
             "arguments": {"to": "sam@lab.test", "body": f"key {in_approval}"},
             "args_sha256": "f" * 64}
        )
    )  # fmt: skip
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "settings.py").write_text(f'import anthropic\nKEY = "{in_repo}"\n')
    inv = Inventory(SecretScanner(), b"k" * 32)
    inv.scan_root(repo)
    (tmp_path / "inventory.json").write_text(json.dumps(inv.to_json("t", False)))
    gateway.ledger.checkpoint()
    roots = gateway.config.ledger.roots_dir
    src = data.Sources(
        receipts=gateway.config.receipts_path,
        public_key=str(roots / keys.PUBLIC_KEY_FILE),
        checkpoints=roots / CHECKPOINTS_FILE,
        pins=gateway.config.pins_path,
        inventory=tmp_path / "inventory.json",
        gateway_config=REPO / "config/gateway.yaml",
        policy_dir=REPO / "config/policies",
        state_dir=state,
    )
    return src, [in_path, in_approval, in_repo, REASON]


def every_view(src: data.Sources) -> str:
    return json.dumps(
        [
            data.ledger_status(src),
            data.recent_calls(src),
            data.control_receipts(src),
            data.kill_list(src),
            data.pending_approvals(src),
            data.pins_summary(src),
            data.risk(src),
            data.inventory(src),
        ],
        default=str,
    )


# --- what it shows ---------------------------------------------------------------------------


def test_no_view_shows_arguments_secrets_or_free_text_reasons(lab):
    src, canaries = lab
    assert_absent(canaries, every_view(src))


def test_views_show_what_receipts_show(lab):
    src, _ = lab
    assert data.ledger_status(src)["state"] == "intact"
    calls = {c["rule"]: c for c in data.recent_calls(src)}
    assert calls["secret-scan"]["attributes"]["rule_id"] == "github-pat"
    assert calls["secret-scan"]["attributes"]["secret"].startswith("committed (")
    assert calls["no-ssh-keys"]["attributes"]["path_class"] == "outside /workspace"
    [approval] = data.pending_approvals(src)
    assert approval["attributes"] == {"recipient_domain": "lab.test"}
    assert "arguments" not in approval
    [killed] = data.kill_list(src)["entries"]
    assert (killed["id"], killed["category"]) == ("sub-agent", "manual")
    assert "reason" not in killed
    assert {p["server"] for p in data.pins_summary(src)} == {"files", "shadow", "weather"}
    assert all(set(p) == {"server", "tools", "quarantined"} for p in data.pins_summary(src))
    [repo_agent] = [a for a in data.inventory(src) if a["kind"] == "shadow"]
    assert repo_agent["credentials"][0]["fingerprint"]


def test_view_only_reads_the_kill_list_from_the_ledger(lab):
    src, _ = lab
    view_only = data.Sources(**{**src.__dict__, "state_dir": None})
    assert not view_only.can_act and data.pending_approvals(view_only) is None
    killed = data.kill_list(view_only)
    assert killed["source"].startswith("control receipt seq")
    assert killed["entries"] == [{"kind": "names", "id": "sub-agent"}]


# --- it can't write the ledger ---------------------------------------------------------------

WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND


def test_the_dashboard_cannot_write_the_ledger_checkpoints_or_pins(lab, monkeypatch):
    src, _ = lab
    protected = [src.receipts, src.checkpoints, src.pins, Path(src.public_key)]
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in protected}
    for p in protected:
        p.chmod(0o444)
    writes: list[str] = []
    real_os_open, real_io_open = os.open, io.open

    def watch_os_open(path, flags, *args, **kwargs):
        if Path(path).resolve() in {p.resolve() for p in protected} and flags & WRITE_FLAGS:
            writes.append(str(path))
        return real_os_open(path, flags, *args, **kwargs)

    def watch_io_open(file, mode="r", *args, **kwargs):
        if isinstance(file, str | Path) and Path(file).resolve() in {
            p.resolve() for p in protected
        } and set(str(mode)) - {"r", "b", "t"}:  # fmt: skip
            writes.append(str(file))
        return real_io_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(os, "open", watch_os_open)
    monkeypatch.setattr(io, "open", watch_io_open)
    monkeypatch.setattr(builtins, "open", watch_io_open)
    try:
        every_view(src)
        assert src.state_dir is not None
        ops.kill(src.state_dir, ops.operator("dashboard"), "x", agent="research-bot")
        ops.revive(src.state_dir, ops.operator("dashboard"), agent="research-bot")
        ops.decide(src.state_dir, "a1b2c3", False, ops.os_user())
        every_view(src)
    finally:
        for p in protected:
            p.chmod(0o644)
    assert writes == []
    assert {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in protected} == before


def test_the_dashboard_never_loads_the_ledger_writer_or_the_gateway():
    code = (
        "import sys, agentguard.dashboard.data, agentguard.ops\n"
        "bad = [m for m in ('agentguard.ledger.writer', 'agentguard.gateway.proxy',"
        " 'agentguard.gateway.receipts') if m in sys.modules]\n"
        "print(bad)"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]"
    forbidden = {
        "agentguard.ledger.writer",
        "agentguard.gateway.proxy",
        "agentguard.gateway.receipts",
    }
    for path in [*(REPO / "src/agentguard/dashboard").glob("*.py"), REPO / "src/agentguard/ops.py"]:
        tree = ast.parse(path.read_text())
        imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        imported |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        assert not imported & forbidden, path
        names = {getattr(n, "attr", None) or getattr(n, "id", None) for n in ast.walk(tree)}
        assert "load_or_create" not in names, path  # never creates or loads a signing key


# --- actions are the CLI's -------------------------------------------------------------------


@pytest.fixture
def served(monkeypatch):
    """Run the page as `agentguard dashboard` would: the required server options set."""
    saved = {name: st_config.get_option(name) for name in REQUIRED_OPTIONS}
    for name, value in REQUIRED_OPTIONS.items():
        st_config.set_option(name, value)
    yield
    for name, value in saved.items():
        st_config.set_option(name, value)


def page(src: data.Sources, monkeypatch) -> AppTest:
    monkeypatch.setenv(data.ENV, src.to_env())
    return AppTest.from_file(str(PAGE), default_timeout=30).run()


def rendered(at: AppTest) -> str:
    parts = [str(e.value) for kind in ("markdown", "caption", "json", "info", "success", "code")
             for e in getattr(at, kind)]  # fmt: skip
    parts += [json.dumps(d.value.to_dict() if hasattr(d.value, "to_dict") else str(d.value),
                         default=str) for d in at.dataframe]  # fmt: skip
    return "\n".join(parts)


def test_the_page_refuses_to_serve_on_other_options(lab, monkeypatch):
    src, _ = lab
    at = page(src, monkeypatch)
    assert at.error and "Refusing to run" in at.error[0].value
    assert not at.tabs


def test_the_rendered_page_shows_no_canary(lab, served, monkeypatch):
    src, canaries = lab
    at = page(src, monkeypatch)
    assert not at.exception and not at.error
    assert_absent(canaries, rendered(at))


def test_dashboard_actions_go_through_ops_as_the_os_user(lab, served, monkeypatch):
    src, _ = lab
    seen: list[tuple[str, tuple]] = []
    for name in ("kill", "revive", "decide"):
        real = getattr(ops, name)
        monkeypatch.setattr(
            ops, name, lambda *a, _n=name, _r=real, **k: (seen.append((_n, a)), _r(*a, **k))[1]
        )
    at = page(src, monkeypatch)
    at.text_input[0].input("research-bot")
    at.checkbox[0].check()
    [kill] = [b for b in at.button if b.label == "Kill"]
    at = kill.click().run()
    [approve] = [b for b in at.button if b.label == "Approve"]
    at = approve.click().run()
    assert [n for n, _ in seen] == ["kill", "decide"]
    entries = json.loads((src.state_dir / "killed.json").read_text())
    assert entries["names"]["research-bot"]["by"] == f"dashboard:{ops.os_user()}"
    assert entries["names"]["research-bot"]["category"] == "manual"
    decided = json.loads((src.state_dir / "approvals/decided/a1b2c3.json").read_text())
    assert decided["approver"] == ops.os_user() and decided["decision"] == "approve"


def test_a_dashboard_kill_and_a_cli_kill_leave_the_same_state(tmp_path):
    cli_dir, dash_dir = tmp_path / "cli", tmp_path / "dash"
    result = runner.invoke(
        app, ["kill", "--agent", "bot", "--reason", "r", "--state-dir", str(cli_dir)]
    )
    assert result.exit_code == 0
    ops.kill(dash_dir, ops.operator("dashboard"), "r", agent="bot")

    def normalized(d):
        body = json.loads((d / "killed.json").read_text())
        for stamp in body["names"].values():
            stamp.pop("at"), stamp.pop("by")
        body.pop("last_change")
        return body

    assert normalized(cli_dir) == normalized(dash_dir)


def test_cli_approvals_record_the_os_user(lab):
    src, _ = lab
    result = runner.invoke(app, ["approvals", "deny", "a1b2c3", "--state-dir", str(src.state_dir)])
    assert result.exit_code == 0, result.output
    decided = json.loads((src.state_dir / "approvals/decided/a1b2c3.json").read_text())
    assert decided["approver"] == ops.os_user()


def test_the_launcher_sets_the_required_options():
    result = runner.invoke(app, ["dashboard", "--dry-run"])
    assert result.exit_code == 0
    required = [
        "--server.address=127.0.0.1",
        "--browser.gatherUsageStats=false",
        "--server.enableXsrfProtection=true",
        "--client.toolbarMode=viewer",
    ]
    for option in required:
        assert option in DASHBOARD_OPTIONS and option in result.stdout


def test_raw_values_in_old_receipts_are_hidden(tmp_path):
    """Phase 4 receipts (unsigned, flat) could carry values the clear list doesn't allow."""
    leaked = "attacker@evil.test"
    log = tmp_path / "receipts.jsonl"
    log.write_text(
        json.dumps({"ts": "2026-09-27T12:00:00+00:00", "agent": "research-bot",
                    "tool": "send_email", "decision": "deny", "policy_id": "default-deny",
                    "reason": {"summary": "no policy permits this call",
                               "attributes": {"recipient": leaked,
                                              "recipient_domain": "evil.test"}}}) + "\n"
    )  # fmt: skip
    [row] = data.recent_calls(data.Sources(receipts=log))
    assert row["attributes"] == {"recipient": "hidden", "recipient_domain": "evil.test"}
    assert leaked not in json.dumps(row)
