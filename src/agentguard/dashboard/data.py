"""Read-only, redacted views for the dashboard. No Streamlit here, so every view is testable.

Nothing is shown that a receipt wouldn't show: no argument values, no tool results, no secret
and no free-text kill reason. Coarse attributes appear only if receipts keep them in the clear
(`CLEAR_ATTRIBUTES`); anything else appears as "committed", with the start of its commitment.
Credentials appear as rule, file, line and fingerprint, as the scanner reports them.

Files are only ever read. The ledger, checkpoints and pins are the gateway's; the guard-state
folder is read for the kill list and pending approvals, and written only by `agentguard.ops`.
"""

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from agentguard.gateway.receipt_fields import CLEAR_ATTRIBUTES, path_class
from agentguard.guards.state import KINDS
from agentguard.ledger.keys import load_public
from agentguard.ledger.read import bodies, calls
from agentguard.ledger.verify import VerifyInputError, verify

ENV = "AGENTGUARD_DASHBOARD"


@dataclass
class Sources:
    """Where the dashboard reads from. `state_dir` is the gateway's guard-state folder: given,
    the dashboard can act (local lab); absent, it is view-only (a Docker snapshot)."""

    receipts: Path | None = None
    public_key: str | None = None  # a did:key, or ledger-key.pub.json
    checkpoints: Path | None = None
    pins: Path | None = None
    inventory: Path | None = None
    gateway_config: Path | None = None
    policy_dir: Path | None = None
    state_dir: Path | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def can_act(self) -> bool:
        return self.state_dir is not None

    def to_env(self) -> str:
        return json.dumps({k: str(v) for k, v in asdict(self).items() if v and k != "notes"})

    @classmethod
    def from_env(cls) -> "Sources":
        raw = json.loads(os.environ.get(ENV, "{}"))

        def path(name: str) -> Path | None:
            return Path(raw[name]) if raw.get(name) else None

        return cls(
            receipts=path("receipts"),
            public_key=raw.get("public_key"),
            checkpoints=path("checkpoints"),
            pins=path("pins"),
            inventory=path("inventory"),
            gateway_config=path("gateway_config"),
            policy_dir=path("policy_dir"),
            state_dir=path("state_dir"),
        )


def _short(commitment: str) -> str:
    return f"committed ({commitment[:10]}…)"


def redact(attributes: Any) -> dict[str, str]:
    """A receipt's reason attributes, as the dashboard may show them."""
    out: dict[str, str] = {}
    if not isinstance(attributes, dict):
        return out
    for name, value in attributes.items():
        if isinstance(value, dict) and isinstance(value.get("commitment"), str):
            out[name] = _short(value["commitment"])
        elif name in CLEAR_ATTRIBUTES and isinstance(value, str | int | float | bool):
            out[name] = str(value)
        else:  # not known to be coarse: never shown, even from an old receipt
            out[name] = "hidden"
    return out


# --- the ledger ------------------------------------------------------------------------------


def ledger_status(src: Sources) -> dict[str, Any]:
    if src.receipts is None or not src.receipts.exists():
        return {"state": "no ledger"}
    if src.public_key is None:
        return {"state": "not verified", "why": "no public key pinned"}
    try:
        report = verify(src.receipts, load_public(src.public_key), src.checkpoints)
    except (VerifyInputError, ValueError, OSError) as exc:
        return {"state": "cannot verify", "why": type(exc).__name__}
    first = report.first_broken
    return {
        "state": "intact" if report.intact else "TAMPERED",
        "receipts": report.receipts,
        "checkpoints verified": f"{report.verified_checkpoints} of {report.checkpoints}",
        "covered by a checkpoint": report.proven_size,
        "first broken link": None if first is None else f"line {first.line}: {first.check}",
        "warnings": [w.check for w in report.warnings],
    }


def recent_calls(src: Sources, limit: int = 200) -> list[dict[str, Any]]:
    rows = []
    for c in calls(src.receipts)[-limit:]:
        reason: dict[str, Any] = c["reason"] if isinstance(c.get("reason"), dict) else {}
        approval: dict[str, Any] = c["approval"] if isinstance(c.get("approval"), dict) else {}
        rows.append(
            {
                "seq": c.get("seq"),
                "time": c.get("ts"),
                "agent": c.get("agent"),
                "tool": c.get("tool"),
                "decision": c.get("decision"),
                "rule": c.get("policy_id"),
                "denial class": c.get("denial_class"),
                "summary": reason.get("summary"),
                "attributes": redact(reason.get("attributes")),
                "approver": approval.get("approver"),
                "args sha256": str(c.get("args_sha256", ""))[:16],
            }
        )
    return list(reversed(rows))


def control_receipts(src: Sources, limit: int = 50) -> list[dict[str, Any]]:
    rows = []
    for c in bodies(src.receipts, "control")[-limit:]:
        reasons: dict[str, Any] = c["reasons"] if isinstance(c.get("reasons"), dict) else {}
        rows.append(
            {
                "seq": c.get("seq"),
                "time": c.get("ts"),
                "action": c.get("action"),
                "change": c.get("change"),
                "by": c.get("by"),
                "while stopped": c.get("while_stopped"),
                "added": {k: v for k, v in (c.get("added") or {}).items() if v},
                "removed": {k: v for k, v in (c.get("removed") or {}).items() if v},
                "categories": sorted({str(r.get("category", "-")) for r in reasons.values()}),
            }
        )
    return list(reversed(rows))


# --- the gateway's state ---------------------------------------------------------------------


def kill_list(src: Sources) -> dict[str, Any]:
    """Who is stopped: from the gateway's kill list if readable, else from the ledger's last
    kill-list control receipt. Categories, never the free-text reason."""
    path = src.state_dir / "killed.json" if src.state_dir else None
    if path is not None and path.exists():
        data = json.loads(path.read_text())
        entries = [
            {
                "kind": kind,
                "id": key,
                "category": str(stamp.get("category", "unknown")),
                "by": stamp.get("by"),
                "since": stamp.get("at"),
            }
            for kind in KINDS
            for key, stamp in sorted(data.get(kind, {}).items())
            if isinstance(stamp, dict)
        ]
        return {"source": "kill list", "entries": entries}
    last = [c for c in bodies(src.receipts, "control") if c.get("action") == "kill-list"]
    state = last[-1].get("state", {}) if last else {}
    entries = [{"kind": k, "id": i} for k in KINDS for i in state.get(k, [])]
    source = f"control receipt seq {last[-1].get('seq')}" if last else "no kill-list receipts"
    return {"source": source, "entries": entries}


def _coarse(tool: str, arguments: Any) -> dict[str, str]:
    """What a receipt would show of these arguments: the clear attributes only."""
    from agentguard.policy.cedar import build_context

    try:
        context = build_context(tool, arguments if isinstance(arguments, dict) else {}, {})
    except Exception:
        return {}
    out = {k: str(v) for k, v in context.items() if k in CLEAR_ATTRIBUTES}
    if isinstance(context.get("path"), str):
        out["path_class"] = path_class(context["path"])
    return out


def pending_approvals(src: Sources) -> list[dict[str, Any]] | None:
    """Pending requests without their arguments: only the coarse attributes and the hash.
    None when the dashboard has no access to the gateway's state (view-only)."""
    if src.state_dir is None:
        return None
    from agentguard.guards.approvals import list_pending

    return [
        {
            "id": r.get("id"),
            "created": r.get("created"),
            "agent": r.get("agent"),
            "tool": r.get("tool"),
            "why": r.get("why"),
            "attributes": _coarse(str(r.get("tool")), r.get("arguments")),
            "args sha256": str(r.get("args_sha256", ""))[:16],
        }
        for r in list_pending(src.state_dir / "approvals")
    ]


def pins_summary(src: Sources) -> list[dict[str, Any]]:
    """Servers, the tools pinned for each, and quarantines. No description hashes."""
    if src.pins is None or not src.pins.exists():
        return []
    data = json.loads(src.pins.read_text())
    servers: dict[str, list[str]] = {}
    for key in data.get("pins", {}):
        server, _, tool = key.partition("/")
        servers.setdefault(server, []).append(tool)
    quarantined = data.get("quarantined", {})
    return [
        {
            "server": s,
            "tools": sorted(servers.get(s, [])),
            "quarantined": quarantined.get(s),
        }
        for s in sorted(set(servers) | set(quarantined))
    ]


# --- inventory and risk ----------------------------------------------------------------------


def risk(src: Sources) -> list[dict[str, Any]]:
    """Every inventory agent's score and breakdown, from the same inputs `agentguard risk`
    takes. The ledger is used only if it verifies."""
    if src.inventory is None or not src.inventory.exists():
        return []
    from agentguard.gateway.checks import CallContext
    from agentguard.guards.approvals import ApprovalConfig
    from agentguard.policy.cedar import CedarCheck
    from agentguard.risk import GatewayView, Ledger, RiskConfig, assess

    view = GatewayView()
    if src.gateway_config is not None and src.gateway_config.exists():
        raw = yaml.safe_load(src.gateway_config.read_text()) or {}
        approvals = (raw.get("guards") or {}).get("approvals") or {}
        view.needs_approval = ApprovalConfig.model_validate(approvals).always
    if src.policy_dir is not None and src.policy_dir.is_dir():
        cedar = CedarCheck(src.policy_dir)

        def probe(agent: str, tool: str, path: str) -> bool:
            try:
                return cedar.evaluate(CallContext(agent, tool, None, {"path": path})).allowed
            except Exception:
                return True  # fail closed: the riskier answer

        view.probe = probe
    if src.pins is not None and src.pins.exists():
        view.pins = json.loads(src.pins.read_text())
    ledger = None
    status = ledger_status(src)
    if status["state"] == "intact":
        ledger = Ledger(True, "intact", calls(src.receipts), bodies(src.receipts, "control"))
    elif status["state"] != "no ledger":
        ledger = Ledger(False, str(status.get("why") or status.get("first broken link")))
    config = RiskConfig()
    inventory = json.loads(src.inventory.read_text())
    return [r.as_dict(config) for r in assess(inventory, config, view, ledger)]


def inventory(src: Sources) -> list[dict[str, Any]]:
    """The scanner's agents, as it reported them (fingerprints, never secrets)."""
    if src.inventory is None or not src.inventory.exists():
        return []
    return list(json.loads(src.inventory.read_text()).get("agents", []))
