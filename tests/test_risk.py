"""Risk scores (Phase 6): fixed inputs give exact breakdowns; unknowns score as worst case; a
score never reaches the gateway's decisions."""

import ast
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from agentguard.cli import app
from agentguard.gateway.checks import CallContext
from agentguard.guards.approvals import ApprovalConfig
from agentguard.identity.didkey import AgentKey
from agentguard.ledger.keys import export_public
from agentguard.ledger.writer import Ledger as LedgerWriter
from agentguard.policy.cedar import CedarCheck
from agentguard.risk import (
    GatewayView,
    Ledger,
    RiskConfig,
    Server,
    anomaly,
    assess,
    autonomy,
    data_sensitivity,
    privilege,
    supply_chain,
)

REPO = Path(__file__).parents[1]
runner = CliRunner()
CONFIG = RiskConfig()
RESEARCH_BOT_TOOLS = [
    "delete_file", "fetch_url", "get_weather", "list_dir", "read_file", "send_email", "write_file",
]  # fmt: skip
NOW = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
PINS = {
    "pins": {
        f"{server}/{tool}": "x"
        for server, tools in {
            "files": ["read_file", "write_file", "list_dir", "delete_file"],
            "web": ["fetch_url"],
            "email": ["send_email"],
            "weather": ["get_weather"],
        }.items()
        for tool in tools
    },
    "quarantined": {},
}
CREDENTIAL = {
    "rule_id": "anthropic-api-key",
    "file": "repo/app/settings.py",
    "line": 3,
    "fingerprint": "3fa2c9e0aa11b2c4",
    "commit": None,
}


@pytest.fixture(scope="module")
def cedar():
    return CedarCheck(REPO / "config/policies")


def probe_with(check):
    return lambda agent, tool, path: (
        check.evaluate(CallContext(agent, tool, None, {"path": path})).allowed
    )


def research_bot(credentials=()) -> dict:
    return {
        "agent": "research-bot",
        "kind": "registered",
        "tools": RESEARCH_BOT_TOOLS,
        "credentials": list(credentials),
        "mcp_servers": [],
    }


def breakdown(result) -> dict[str, float]:
    return {f.name: round(f.value, 4) for f in result.factors}


# --- the worked example (docs/phase6-design.md) ----------------------------------------------


def test_research_bot_on_a_fresh_lab_scores_42_with_this_breakdown(cedar):
    view = GatewayView(ApprovalConfig().always, probe_with(cedar), PINS)
    [r] = assess({"agents": [research_bot()]}, CONFIG, view, Ledger(True, "intact"), NOW)
    assert breakdown(r) == {
        "privilege": 0.6,
        "data_sensitivity": 0.3,
        "autonomy": 0.5,
        "supply_chain": 0.5,
        "anomaly": 0.0,
    }
    assert r.score == 42
    assert not any(f.unknown for f in r.factors)


def test_a_committed_key_raises_it_to_54_and_the_breakdown_names_the_finding(cedar):
    view = GatewayView(ApprovalConfig().always, probe_with(cedar), PINS)
    [r] = assess({"agents": [research_bot([CREDENTIAL])]}, CONFIG, view, Ledger(True, "ok"), NOW)
    assert r.score == 54
    [priv] = [f for f in r.factors if f.name == "privilege"]
    assert priv.value == 1.0
    assert any(
        "anthropic-api-key at repo/app/settings.py:3 (fp 3fa2c9e0aa11b2c4)" in w for w in priv.why
    )


def test_unknown_inputs_score_as_worst_case_and_say_so():
    shadow = {"agent": "repo:x", "kind": "shadow", "credentials": [], "mcp_servers": []}
    [r] = assess({"agents": [shadow]}, CONFIG, GatewayView(), None, NOW)
    assert breakdown(r) == dict.fromkeys(breakdown(r), 1.0) | {"privilege": 0.6}
    assert [f.name for f in r.factors if f.unknown] == [
        "privilege", "data_sensitivity", "autonomy", "supply_chain", "anomaly",
    ]  # fmt: skip
    assert r.score == 88
    assert all("worst case" in " ".join(f.why) for f in r.factors)


def test_a_registered_agent_with_no_gateway_inputs_is_unknown_where_it_matters():
    [r] = assess({"agents": [research_bot()]}, CONFIG, GatewayView(), None, NOW)
    assert {f.name for f in r.factors if f.unknown} == {
        "data_sensitivity", "autonomy", "supply_chain", "anomaly",
    }  # fmt: skip
    assert r.score == 18 + 20 + 20 + 15 + 15


# --- each factor -----------------------------------------------------------------------------


def test_privilege_takes_the_most_dangerous_tool():
    assert privilege(["read_file"], [], CONFIG).value == pytest.approx(0.6 / 3)
    assert privilege(["read_file", "write_file"], [], CONFIG).value == pytest.approx(0.4)
    assert privilege(["mystery_tool"], [], CONFIG).value == 0.6  # unlisted counts as tier 1
    assert privilege([], [], CONFIG).value == 0.0


def test_data_sensitivity_comes_from_the_real_policies(cedar, tmp_path):
    probe = probe_with(cedar)
    rb = data_sensitivity(RESEARCH_BOT_TOOLS, lambda t, p: probe("research-bot", t, p), CONFIG)
    assert rb.value == 0.3 and rb.evidence["permitted"] == [
        "read_file /workspace/notes.txt",
        "list_dir /workspace/notes.txt",
    ]
    stranger = data_sensitivity(["read_file"], lambda t, p: probe("nobody", t, p), CONFIG)
    assert stranger.value == 0.0  # Cedar denies by default
    assert data_sensitivity(["send_email"], None, CONFIG).value == 0.0  # no read tools

    loose = tmp_path / "policies"
    loose.mkdir()
    (loose / "schema.cedarschema").write_text(
        (REPO / "config/policies/schema.cedarschema").read_text()
    )
    (loose / "p.cedar").write_text(
        'permit (principal == Agent::"research-bot", action == Action::"read_file", resource);\n'
    )
    open_probe = probe_with(CedarCheck(loose))
    wide = data_sensitivity(["read_file"], lambda t, p: open_probe("research-bot", t, p), CONFIG)
    assert wide.value == 1.0 and "read_file /etc/passwd" in wide.evidence["permitted"]


def test_autonomy_is_the_unapproved_share_of_side_effects():
    always = ApprovalConfig().always  # send_email, delete_file
    assert autonomy(RESEARCH_BOT_TOOLS, always, CONFIG).value == 0.5
    assert autonomy(["write_file", "fetch_url"], always, CONFIG).value == 1.0
    assert autonomy(["read_file", "get_weather"], always, CONFIG).value == 0.0
    assert autonomy(["send_email"], None, CONFIG).unknown


def test_supply_chain_scores_unsigned_unpinned_and_quarantined():
    assert supply_chain([Server("a", pinned=True)]).value == 0.5
    assert supply_chain([Server("a", pinned=False)]).value == 1.0
    assert supply_chain([Server("a", pinned=True, quarantined=True)]).value == 1.0
    assert supply_chain([Server("a", pinned=None)]).value == 1.0  # unknown pinning
    assert supply_chain([Server("a", True), Server("b", False)]).value == 0.75
    assert supply_chain([]).value == 0.0
    assert supply_chain(None).unknown


def test_a_quarantined_upstream_raises_supply_chain_for_agents_using_it(cedar):
    pins = {**PINS, "quarantined": {"weather": "description changed"}}
    view = GatewayView(ApprovalConfig().always, probe_with(cedar), pins)
    [r] = assess({"agents": [research_bot()]}, CONFIG, view, Ledger(True, "ok"), NOW)
    [sc] = [f for f in r.factors if f.name == "supply_chain"]
    assert sc.value == pytest.approx((0.5 * 3 + 1.0) / 4)
    assert "quarantined: weather" in sc.why


# --- anomaly, from the agent's own receipts --------------------------------------------------


def calls(agent: str, tools: list[str], start: datetime, denied: int = 0, **extra) -> list[dict]:
    out = []
    for i, tool in enumerate(tools):
        out.append(
            {
                "agent": agent,
                "tool": tool,
                "decision": "deny" if i < denied else "allow",
                "denial_class": "policy" if i < denied else None,
                "ts": (start + timedelta(seconds=i)).isoformat(),
                **extra,
            }
        )
    return out


def test_anomaly_is_the_denied_share_of_recent_calls():
    recent = calls("bot", ["read_file"] * 10, NOW - timedelta(minutes=5), denied=3)
    f = anomaly("bot", Ledger(True, "ok", recent), NOW, CONFIG)
    assert f.value == pytest.approx(0.3)
    assert any("new-tool check skipped" in w for w in f.why)


def test_approval_timeouts_are_not_counted_as_denials():
    recent = calls("bot", ["send_email"] * 4, NOW - timedelta(minutes=5), denied=2)
    for c in recent[:2]:
        c["denial_class"] = "approval-timeout"
    assert anomaly("bot", Ledger(True, "ok", recent), NOW, CONFIG).value == 0.0


def test_a_kill_switch_trip_is_maximal():
    recent = calls("bot", ["fetch_url"] * 5, NOW - timedelta(minutes=5))
    recent[-1] |= {"decision": "deny", "denial_class": "guard", "policy_id": "kill-switch"}
    f = anomaly("bot", Ledger(True, "ok", recent), NOW, CONFIG)
    assert f.value == 1.0 and "the kill switch stopped it" in f.why


def test_new_tools_count_only_against_an_established_baseline():
    baseline = calls("bot", ["read_file"] * 20, NOW - timedelta(hours=3))
    recent = calls(
        "bot", ["read_file", "send_email", "delete_file", "read_file"], NOW - timedelta(minutes=1)
    )
    f = anomaly("bot", Ledger(True, "ok", baseline + recent), NOW, CONFIG)
    assert f.value == 0.5 and f.evidence["baseline_calls"] == 20
    short = anomaly("bot", Ledger(True, "ok", baseline[:19] + recent), NOW, CONFIG)
    assert short.value == 0.0


def test_other_agents_and_old_calls_do_not_count():
    other = calls("someone-else", ["x"] * 5, NOW - timedelta(minutes=5), denied=5)
    old = calls("bot", ["x"] * 5, NOW - timedelta(hours=5), denied=5)
    f = anomaly("bot", Ledger(True, "ok", other + old), NOW, CONFIG)
    assert f.value == 0.0 and f.why == ["no calls in the last 1 h"]


def test_an_unverified_ledger_is_worst_case_and_flagged():
    f = anomaly("bot", Ledger(False, "hash at line 3"), NOW, CONFIG)
    assert f.value == 1.0 and f.unknown and f.evidence["ledger_verified"] is False
    assert "hash at line 3" in f.why[0]


# --- weights ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "weights",
    [
        {"privilege": 0.5, "data_sensitivity": 0.2, "autonomy": 0.2, "supply_chain": 0.15,
         "anomaly": 0.15},  # sums to 1.2
        {"privilege": 1.0},  # missing factors
        {"privilege": 1.2, "data_sensitivity": -0.2, "autonomy": 0, "supply_chain": 0,
         "anomaly": 0},  # out of range
    ],
)  # fmt: skip
def test_bad_weights_are_refused(weights):
    with pytest.raises(ValidationError):
        RiskConfig(weights=weights)


def test_the_shipped_config_is_the_approved_weights():
    from agentguard.risk import load_risk_config

    assert load_risk_config(REPO / "config/risk.yaml").weights == RiskConfig().weights


# --- a score never decides anything ----------------------------------------------------------


def test_nothing_in_the_gateway_or_guards_imports_the_risk_engine():
    for package in ("gateway", "guards", "policy", "tokens", "identity", "ledger"):
        for path in (REPO / "src/agentguard" / package).rglob("*.py"):
            tree = ast.parse(path.read_text())
            names = {
                n.module if isinstance(n, ast.ImportFrom) else a.name
                for n in ast.walk(tree)
                if isinstance(n, ast.Import | ast.ImportFrom)
                for a in (n.names if isinstance(n, ast.Import) else [n])
            }
            assert not {m for m in names if m and m.startswith("agentguard.risk")}, path


# --- end to end ------------------------------------------------------------------------------


def test_the_cli_verifies_the_ledger_before_using_it(tmp_path):
    key = AgentKey.generate()
    led = LedgerWriter(tmp_path / "receipts.jsonl", key, tmp_path / "roots",
                       checkpoint_interval_s=3600, fsync_interval_s=3600)  # fmt: skip
    for _ in range(4):
        led.append("decision", {"agent": "research-bot", "tool": "read_file", "decision": "deny",
                                "denial_class": "policy", "policy_id": "no-ssh-keys"})  # fmt: skip
    led.close()
    pub = export_public(key, tmp_path / "pub")
    inventory = tmp_path / "inv.json"
    inventory.write_text(json.dumps({"agents": [research_bot()]}))
    args = [
        "risk",
        "--inventory", str(inventory),
        "--gateway-config", str(REPO / "config/gateway.yaml"),
        "--policy-dir", str(REPO / "config/policies"),
        "--receipts", str(tmp_path / "receipts.jsonl"),
        "--json",
    ]  # fmt: skip

    [ok] = json.loads(runner.invoke(app, [*args, "--public-key", str(pub)]).stdout)
    assert ok["factors"]["anomaly"]["value"] == 1.0  # 4 of 4 recent calls denied
    assert ok["factors"]["anomaly"]["unknown"] is False

    [unpinned] = json.loads(runner.invoke(app, args).stdout)
    assert unpinned["factors"]["anomaly"]["unknown"] is True
    assert "no public key" in unpinned["factors"]["anomaly"]["why"][0]

    lines = (tmp_path / "receipts.jsonl").read_text().splitlines()
    lines[2] = lines[2].replace('"no-ssh-keys"', '"files-read-workspace"')
    (tmp_path / "receipts.jsonl").write_text("\n".join(lines) + "\n")
    [tampered] = json.loads(runner.invoke(app, [*args, "--public-key", str(pub)]).stdout)
    assert tampered["factors"]["anomaly"]["evidence"]["ledger_verified"] is False
    assert "line 3" in tampered["factors"]["anomaly"]["why"][0]


def test_the_text_report_shows_every_factor(tmp_path):
    inventory = tmp_path / "inv.json"
    inventory.write_text(json.dumps({"agents": [research_bot([CREDENTIAL])]}))
    out = runner.invoke(app, ["risk", "--inventory", str(inventory)]).stdout
    for name in ("privilege", "data_sensitivity", "autonomy", "supply_chain", "anomaly"):
        assert name in out
    assert "anthropic-api-key at repo/app/settings.py:3" in out
    assert "count as worst case" in out
