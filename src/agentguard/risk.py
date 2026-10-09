"""Risk scores (Phase 6): an explainable 0-100 score per agent. See docs/phase6-design.md.

Risk = 100 x sum(weight x factor), five factors each in [0, 1]:

- privilege: the agent's allowed tools (inventory: credential AND gateway allowlist), and
  credentials the scanner found in its sources
- data sensitivity: fixed read probes run through the agent's real Cedar policies
- autonomy: the gateway's approval config
- supply chain: the gateway's pins (registered agents) or the inventory's MCP servers (shadow)
- anomaly: the agent's own receipts, used only after `ledger verify` passes

An input that can't be determined counts as 1 and is marked `unknown`, so an agent nobody
registered ranks high until shown otherwise. Every factor carries the reasons and evidence
behind its value.

The score is a view. Nothing in the gateway imports this module: a score never allows a call
or changes a policy. The weights are judgment calls, good to about one significant figure.
"""

from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, model_validator

FACTORS = ("privilege", "data_sensitivity", "autonomy", "supply_chain", "anomaly")
READ_TOOLS = ("read_file", "list_dir")


class RiskConfig(BaseModel):
    weights: dict[str, float] = {
        "privilege": 0.30,
        "data_sensitivity": 0.20,
        "autonomy": 0.20,
        "supply_chain": 0.15,
        "anomaly": 0.15,
    }
    # 1/3 read only; 2/3 local write; 1 external effect or destructive. Unlisted tools score 1.
    tool_tiers: dict[str, float] = {
        "read_file": 1 / 3,
        "list_dir": 1 / 3,
        "get_weather": 1 / 3,
        "write_file": 2 / 3,
        "delete_file": 1.0,
        "send_email": 1.0,
        "fetch_url": 1.0,
    }
    # Tools with side effects outside the agent (unlisted tools count as side-effecting).
    read_only_tools: list[str] = ["read_file", "list_dir", "get_weather"]
    # Paths probed through Cedar: anything permitted outside /workspace scores 1.
    probe_outside: list[str] = ["~/.ssh/id_rsa", "/etc/passwd"]
    probe_workspace: str = "/workspace/notes.txt"
    workspace_score: float = 0.3
    window_s: float = 3600  # "recent" calls, for anomaly
    min_baseline_calls: int = 20  # earlier calls needed before "new tools" counts

    @model_validator(mode="after")
    def _weights_sum_to_one(self) -> "RiskConfig":
        if set(self.weights) != set(FACTORS):
            raise ValueError(f"weights must name exactly {', '.join(FACTORS)}")
        if any(not 0 <= w <= 1 for w in self.weights.values()):
            raise ValueError("each weight must be between 0 and 1")
        if abs(sum(self.weights.values()) - 1) > 1e-9:
            raise ValueError("weights must sum to 1")
        return self


def load_risk_config(path: Path) -> RiskConfig:
    return RiskConfig.model_validate(yaml.safe_load(path.read_text()) or {})


@dataclass
class Factor:
    name: str
    value: float
    why: list[str]
    unknown: bool = False
    evidence: dict[str, Any] = field(default_factory=dict)


def _unknown(name: str, why: str) -> Factor:
    return Factor(name, 1.0, [f"unknown ({why}): scored as worst case"], unknown=True)


# --- the five factors (pure: fixed inputs give fixed results) --------------------------------


def privilege(
    tools: list[str] | None, credentials: list[dict[str, Any]], config: RiskConfig
) -> Factor:
    """0.6 x the most dangerous allowed tool's tier + 0.4 if the agent's sources hold a
    credential (standing authority that doesn't pass through the gateway)."""
    why: list[str] = []
    if tools is None:
        tier, why, unknown = 1.0, ["tools unknown: tier scored as worst case"], True
    else:
        unknown = False
        tiers = {t: config.tool_tiers.get(t, 1.0) for t in tools}
        tier = max(tiers.values(), default=0.0)
        top = sorted(t for t, v in tiers.items() if v == tier)
        why.append(f"tool tier {tier:.2f}" + (f" ({', '.join(top)})" if top else " (no tools)"))
    found = [c for c in credentials if c.get("rule_id")]
    if found:
        listed = "; ".join(
            f"{c['rule_id']} at {c['file']}"
            + (f":{c['line']}" if c.get("line") else "")
            + (f" (fp {c['fingerprint']})" if c.get("fingerprint") else "")
            + (f" in commit {c['commit'][:12]}" if c.get("commit") else "")
            for c in found
        )
        why.append(f"{len(found)} credential(s) in its sources: {listed}")
    else:
        why.append("no credentials found in its sources")
    value = 0.6 * tier + 0.4 * (1.0 if found else 0.0)
    evidence = {"tool_tier": tier, "credentials": len(found)}
    return Factor("privilege", value, why, unknown, evidence)


def data_sensitivity(
    tools: list[str] | None,
    probe: Callable[[str, str], bool] | None,
    config: RiskConfig,
) -> Factor:
    """`probe(tool, path)` asks the agent's Cedar policies whether that read is permitted.
    None means the policies aren't available."""
    if tools is None:
        return _unknown("data_sensitivity", "tools unknown")
    reads = [t for t in READ_TOOLS if t in tools]
    if not reads:
        return Factor("data_sensitivity", 0.0, ["no read tools"], evidence={"permitted": []})
    if probe is None:
        return _unknown("data_sensitivity", "policies not available")
    permitted = [
        f"{t} {p}"
        for t in reads
        for p in [*config.probe_outside, config.probe_workspace]
        if probe(t, p)
    ]
    outside = [x for x in permitted if x.split(" ", 1)[1] in config.probe_outside]
    if outside:
        value, why = 1.0, [f"policy permits reads outside /workspace: {', '.join(outside)}"]
    elif permitted:
        value, why = (
            config.workspace_score,
            [f"policy permits reads in /workspace only ({permitted[0]})"],
        )
    else:
        value, why = 0.0, ["policy permits none of the probed reads"]
    return Factor("data_sensitivity", value, why, evidence={"permitted": permitted})


def autonomy(
    tools: list[str] | None, needs_approval: list[str] | None, config: RiskConfig
) -> Factor:
    """The share of the agent's side-effecting tools that run without a human's approval."""
    if tools is None:
        return _unknown("autonomy", "tools unknown")
    acting = sorted(t for t in tools if t not in config.read_only_tools)
    if not acting:
        return Factor("autonomy", 0.0, ["no side-effecting tools"], evidence={"unapproved": []})
    if needs_approval is None:
        return _unknown("autonomy", "approval config not available")
    unapproved = [t for t in acting if t not in needs_approval]
    approved = [t for t in acting if t in needs_approval]
    why = [
        f"{len(unapproved)} of {len(acting)} side-effecting tools need no approval"
        + (f" ({', '.join(unapproved)})" if unapproved else ""),
    ]
    if approved:
        why.append(f"always approved by a human: {', '.join(approved)}")
    return Factor(
        "autonomy",
        len(unapproved) / len(acting),
        why,
        evidence={"unapproved": unapproved, "approved": approved},
    )


@dataclass(frozen=True)
class Server:
    name: str
    pinned: bool | None  # None: unknown
    quarantined: bool = False
    signed: bool = False  # nothing in the lab is signed: MCP has no server signing here


def supply_chain(servers: list[Server] | None) -> Factor:
    """Mean over the agent's MCP servers: +0.5 if unsigned, +0.5 if unpinned or quarantined."""
    if servers is None:
        return _unknown("supply_chain", "its MCP servers are unknown")
    if not servers:
        return Factor("supply_chain", 0.0, ["no MCP servers reachable"], evidence={"servers": []})
    scores = {
        s.name: (0.0 if s.signed else 0.5) + (0.5 if s.quarantined or not s.pinned else 0.0)
        for s in servers
    }
    unsigned = [s.name for s in servers if not s.signed]
    loose = [s.name for s in servers if s.quarantined or not s.pinned]
    why = [f"{len(servers)} server(s); unsigned: {len(unsigned)}"]
    why.append(f"unpinned or quarantined: {', '.join(loose)}" if loose else "all pinned")
    quarantined = [s.name for s in servers if s.quarantined]
    if quarantined:
        why.append(f"quarantined: {', '.join(quarantined)}")
    return Factor(
        "supply_chain", sum(scores.values()) / len(scores), why, evidence={"servers": scores}
    )


@dataclass(frozen=True)
class Ledger:
    """The agent's calls, from a ledger that passed verification."""

    verified: bool
    detail: str  # why it is or isn't trusted
    calls: list[dict[str, Any]] = field(default_factory=list)


def _blocked(call: dict[str, Any]) -> bool:
    if call.get("decision") != "deny":
        return False
    return call.get("denial_class", "policy") in ("policy", "guard")


def _tripped(call: dict[str, Any]) -> bool:
    reason = call.get("reason")
    summary = str(reason.get("summary", "")) if isinstance(reason, dict) else ""
    stopped = call.get("policy_id") == "kill-switch" and call.get("decision") == "deny"
    return stopped or "kill switch tripped" in summary


def anomaly(agent: str, ledger: Ledger | None, now: datetime, config: RiskConfig) -> Factor:
    """The highest of: a kill-switch trip in the window (1); the share of recent calls denied
    by policy or a guard; the share of recent calls to tools absent from the agent's earlier
    calls (only with at least min_baseline_calls earlier calls)."""
    if ledger is None:
        return _unknown("anomaly", "no ledger: its calls aren't recorded")
    if not ledger.verified:
        f = _unknown("anomaly", f"the ledger failed verification: {ledger.detail}")
        f.evidence["ledger_verified"] = False
        return f
    start = now - timedelta(seconds=config.window_s)
    mine = [c for c in ledger.calls if c.get("agent") == agent and isinstance(c.get("ts"), str)]
    recent = [c for c in mine if start <= datetime.fromisoformat(c["ts"]) <= now]
    before = [c for c in mine if datetime.fromisoformat(c["ts"]) < start]
    window = f"last {config.window_s / 3600:g} h"
    if not recent:
        return Factor("anomaly", 0.0, [f"no calls in the {window}"], evidence={"recent_calls": 0})
    signals = {"kill_switch": 1.0 if any(_tripped(c) for c in recent) else 0.0}
    denied = sum(_blocked(c) for c in recent)
    signals["denied_share"] = denied / len(recent)
    why = [f"{len(recent)} call(s) in the {window}, {denied} denied by policy or a guard"]
    if signals["kill_switch"]:
        why.append("the kill switch stopped it")
    if len(before) >= config.min_baseline_calls:
        known = {c.get("tool") for c in before}
        new = [c for c in recent if c.get("tool") not in known]
        signals["new_tool_share"] = len(new) / len(recent)
        if new:
            why.append(f"{len(new)} call(s) to tools not in its baseline")
    else:
        why.append(
            f"new-tool check skipped: {len(before)} earlier call(s), "
            f"{config.min_baseline_calls} needed for a baseline"
        )
    evidence = {"recent_calls": len(recent), "baseline_calls": len(before), **signals}
    return Factor("anomaly", max(signals.values()), why, evidence=evidence)


# --- the score -------------------------------------------------------------------------------


@dataclass
class AgentRisk:
    agent: str
    kind: str
    score: int
    factors: list[Factor]

    def as_dict(self, config: RiskConfig) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "kind": self.kind,
            "score": self.score,
            "factors": {
                f.name: {
                    **{k: v for k, v in asdict(f).items() if k != "name"},
                    "value": round(f.value, 4),
                    "weight": config.weights[f.name],
                    "points": round(100 * config.weights[f.name] * f.value, 1),
                }
                for f in self.factors
            },
        }


def score(factors: list[Factor], config: RiskConfig) -> int:
    total = 100 * sum(config.weights[f.name] * f.value for f in factors)
    return int(total + 0.5)  # half up, not Python's half-to-even


@dataclass
class GatewayView:
    """What the risk engine reads from the gateway's side. A None field is unknown."""

    needs_approval: list[str] | None = None
    probe: Callable[[str, str, str], bool] | None = None  # (agent, tool, path) -> permitted
    pins: dict[str, Any] | None = (
        None  # pins.json: {"pins": {"server/tool": ...}, "quarantined": {...}}
    )


def _registered_servers(tools: list[str], pins: dict[str, Any] | None) -> list[Server] | None:
    """The upstream servers that serve any of the agent's tools, from the gateway's pins."""
    if not tools:
        return []  # nothing reachable, whatever the pins say
    if pins is None:
        return None
    serving = [key.split("/", 1) for key in pins.get("pins", {})]
    names = sorted({server for server, tool in serving if tool in tools})
    quarantined = pins.get("quarantined", {})
    return [Server(n, pinned=True, quarantined=n in quarantined) for n in names]


def assess(
    inventory: dict[str, Any],
    config: RiskConfig,
    gateway: GatewayView | None = None,
    ledger: Ledger | None = None,
    now: datetime | None = None,
) -> list[AgentRisk]:
    """Score every agent in a scanner inventory."""
    gateway = gateway or GatewayView()
    now = now or datetime.now().astimezone()
    out = []
    for agent in inventory.get("agents", []):
        name, kind = agent["agent"], agent["kind"]
        registered = kind == "registered"
        tools = list(agent.get("tools", [])) if registered else None
        probe = partial(gateway.probe, name) if gateway.probe else None
        if registered:
            servers = _registered_servers(tools or [], gateway.pins)
        else:
            servers = [
                Server(s.get("name") or "(unnamed)", pinned=s.get("pinned"))
                for s in agent.get("mcp_servers", [])
            ] or None
        factors = [
            privilege(tools, agent.get("credentials", []), config),
            data_sensitivity(tools, probe, config),
            autonomy(tools, gateway.needs_approval if registered else None, config),
            supply_chain(servers),
            anomaly(name, ledger if registered else None, now, config),
        ]
        out.append(AgentRisk(name, kind, score(factors, config), factors))
    return sorted(out, key=lambda r: (-r.score, r.agent))


def text_report(results: list[AgentRisk], config: RiskConfig) -> str:
    lines = []
    for r in results:
        lines.append(f"{r.agent} ({r.kind}): risk {r.score}/100")
        for f in r.factors:
            w = config.weights[f.name]
            flag = "  [unknown]" if f.unknown else ""
            lines.append(
                f"  {f.name:<17} {f.value:4.2f} x {w:.2f} = {100 * w * f.value:4.1f}{flag}"
            )
            lines += [f"      {why}" for why in f.why]
    lines.append(
        "Unknown inputs count as worst case (1.0), so unregistered agents rank high by design."
    )
    return "\n".join(lines)
