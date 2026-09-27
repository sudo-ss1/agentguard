"""Decision receipts as JSON lines. Phase 5 turns this into the signed, hash-chained ledger.

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

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentguard.gateway.checks import CallContext, Decision
from agentguard.gateway.commitments import SaltStore

# Attribute values that are coarse enough to keep in the clear.
CLEAR_ATTRIBUTES = frozenset({"recipient_domain", "url_host", "url_scheme", "path_class"})


def args_digest(arguments: dict[str, Any]) -> str:
    """The receipt's argument hash. Receipts never store argument values themselves."""
    canonical = json.dumps(arguments, sort_keys=True, default=str).encode()
    return hashlib.sha256(canonical).hexdigest()


def path_class(path: str) -> str:
    if path == "/workspace/tmp" or path.startswith("/workspace/tmp/"):
        return "inside /workspace/tmp"
    if path == "/workspace" or path.startswith("/workspace/"):
        return "inside /workspace"
    return "outside /workspace"


class ReceiptLog:
    def __init__(self, path: Path, salts: SaltStore) -> None:
        self.path = path
        self.salts = salts
        path.parent.mkdir(parents=True, exist_ok=True)

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

    def write(
        self,
        ctx: CallContext,
        decision: Decision,
        *,
        decision_ms: float,
        upstream_error: bool | None = None,
        upstream_exception: BaseException | None = None,
    ) -> None:
        receipt: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(),
            "agent": ctx.agent_id,
            "tool": ctx.tool,
            "server": ctx.server,
            "args_sha256": args_digest(ctx.arguments),
            "decision": decision.verdict,
            "policy_id": decision.policy_id,
            "reason": self.reason(decision),
            "decision_ms": decision_ms,
        }
        if upstream_exception is not None:
            receipt["upstream_error"] = {
                "exception": type(upstream_exception).__name__,
                "message": {
                    "commitment": self.salts.commit("upstream_error", str(upstream_exception))
                },
            }
        elif upstream_error is not None:
            receipt["upstream_error"] = upstream_error
        with self.path.open("a") as f:
            f.write(json.dumps(receipt) + "\n")
