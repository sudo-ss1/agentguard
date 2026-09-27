"""Decision receipts as JSON lines. Phase 5 replaces this with the signed, hash-chained ledger."""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentguard.gateway.checks import CallContext, Decision


def args_digest(arguments: dict[str, Any]) -> str:
    """The receipt's argument hash. Receipts never store argument values themselves."""
    canonical = json.dumps(arguments, sort_keys=True, default=str).encode()
    return hashlib.sha256(canonical).hexdigest()


class ReceiptLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, ctx: CallContext, decision: Decision, **extra: Any) -> None:
        receipt = {
            "ts": datetime.now(UTC).isoformat(),
            "agent": ctx.agent_id,
            "tool": ctx.tool,
            "server": ctx.server,
            "args_sha256": args_digest(ctx.arguments),
            "decision": decision.verdict,
            "policy_id": decision.policy_id,
            "reason": decision.reason,
            **extra,
        }
        with self.path.open("a") as f:
            f.write(json.dumps(receipt) + "\n")
