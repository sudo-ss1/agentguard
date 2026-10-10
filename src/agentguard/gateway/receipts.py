"""What goes in a receipt. The ledger (agentguard.ledger) signs and chains them.

Every call gets a decision receipt, written before an allowed call is forwarded: if it can't be
recorded, the call isn't made. An allowed call then gets an outcome receipt (`decision_seq`,
upstream error, result scan). A decision with no outcome is reported by `verify` as "outcome
unknown".

Receipts never contain argument values. Arguments appear only as a hash (`args_sha256`). A
decision's reason is a structured record (receipt option C, docs/phase3-design.md):

    {"rule": "default-deny", "summary": "no policy permits this call",
     "attributes": {"recipient_domain": "evil.test",
                    "recipient": {"commitment": "<digest>"}}}

- Coarse attributes are kept in the clear, so triage stays readable.
- Every other attribute value (full recipient, exact path, error messages) becomes a salted
  commitment. Its salt goes to a separate `SaltStore`, never to this log.
- Paths are also classified coarsely, e.g. "outside /workspace".
- A failed upstream call records the exception class and a commitment to its message, never
  `repr(exc)`.
"""

from typing import Any

from agentguard.gateway.checks import CallContext, Decision
from agentguard.gateway.commitments import SaltStore
from agentguard.gateway.receipt_fields import (  # re-exported: callers import them from here
    CLEAR_ATTRIBUTES,
    args_digest,
    args_match,
    legacy_args_digest,
    path_class,
)
from agentguard.ledger.canonical import CanonicalError
from agentguard.ledger.writer import Ledger

__all__ = [
    "CLEAR_ATTRIBUTES",
    "ReceiptLog",
    "args_digest",
    "args_match",
    "legacy_args_digest",
    "path_class",
]


class ReceiptLog:
    def __init__(self, ledger: Ledger, salts: SaltStore) -> None:
        self.ledger = ledger
        self.salts = salts

    def _redact(self, attributes: dict[str, Any]) -> dict[str, Any]:
        record: dict[str, Any] = {}
        for name, value in attributes.items():
            if name in CLEAR_ATTRIBUTES:
                record[name] = value
            else:  # anything not known to be coarse is committed, never written in the clear
                record[name] = {"commitment": self.salts.commit(name, value)}
            if name == "path" and isinstance(value, str):
                record["path_class"] = path_class(value)
        return record

    def reason(self, decision: Decision) -> dict[str, Any]:
        reason: dict[str, Any] = {"rule": decision.policy_id, "summary": decision.reason}
        if decision.attributes:
            reason["attributes"] = self._redact(decision.attributes)
        return reason

    def decision(
        self,
        ctx: CallContext,
        decision: Decision,
        *,
        decision_ms: float,
        denial_class: str | None = None,
        approval: dict[str, Any] | None = None,
    ) -> int:
        """Record the decision; returns its seq. Raises if it can't be recorded."""
        profile = ctx.identity.profile if ctx.identity is not None else None
        receipt: dict[str, Any] = {
            "agent": ctx.agent_id,
            "agent_did": profile.did if profile is not None else None,
            "tool": ctx.tool,
            "server": ctx.server,
            "decision": decision.verdict,
            "policy_id": decision.policy_id,
            "reason": self.reason(decision),
            "decision_ms": decision_ms,
        }
        try:
            receipt["args_sha256"] = args_digest(ctx.arguments)
        except CanonicalError:  # still recorded; such a call is never forwarded (proxy.py)
            receipt["args_sha256"] = legacy_args_digest(ctx.arguments)
            receipt["args_hash"] = "legacy-json"
        if denial_class is not None:
            # policy | guard | approval-denied | approval-timeout | approval-error.
            # Only policy and guard denials mean the gateway blocked the call on its merits.
            receipt["denial_class"] = denial_class
        if approval is not None:
            receipt["approval"] = approval
        seq, _ = self.ledger.append("decision", receipt)
        return seq

    def control(self, fields: dict[str, Any], reasons: dict[str, tuple[str, str]]) -> int:
        """A control receipt (gateway/control.py). `reasons` maps an entry to (category, free
        text): the category is kept in the clear, the text only as a salted commitment."""
        receipt = dict(fields)
        receipt["reasons"] = {
            name: {
                "category": category,
                "reason": {"commitment": self.salts.commit("kill_reason", text)},
            }
            for name, (category, text) in sorted(reasons.items())
        }
        seq, _ = self.ledger.append("control", receipt)
        return seq

    def outcome(
        self,
        decision_seq: int,
        ctx: CallContext,
        *,
        upstream_error: bool | None = None,
        upstream_exception: BaseException | None = None,
        result_scan: dict[str, Any] | None = None,
    ) -> int:
        receipt: dict[str, Any] = {"decision_seq": decision_seq, "tool": ctx.tool}
        if result_scan is not None:  # ids, counts and scores; stripped content only as a commitment
            scan = dict(result_scan)
            if scan.get("stripped_content") is not None:
                scan["stripped_content"] = {
                    "commitment": self.salts.commit("stripped_content", scan["stripped_content"])
                }
            receipt["result_scan"] = scan
        if upstream_exception is not None:
            receipt["upstream_error"] = {
                "exception": type(upstream_exception).__name__,
                "message": {
                    "commitment": self.salts.commit("upstream_error", str(upstream_exception))
                },
            }
        elif upstream_error is not None:
            receipt["upstream_error"] = upstream_error
        seq, _ = self.ledger.append("outcome", receipt)
        return seq
