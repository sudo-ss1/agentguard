"""Human approval for high-risk calls, and the taint that escalates more calls to it.

- **Which calls:** `ApprovalRequirement` escalates `always` tools (send_email, delete_file) and,
  while an agent is tainted, `when_tainted` tools (write_file, send_email, fetch_url). The
  injection scanner taints an agent for `taint_ttl_s` when one of its tool results is flagged.
  It only ever escalates. A policy denial never reaches it, so approval can't loosen policy.
- **How approval works:** `ApprovalQueue` writes a request to a gateway-private directory
  (mode 0600; it holds the full arguments, so the approver can see what they approve) and
  holds the call open. `agentguard approvals approve|deny <id>` writes the decision. The
  decision must name the request's argument hash, so it covers exactly that call, once.
- **Failing closed:** a timeout, an unreadable or mismatched decision, or a gateway restart
  (stale requests are voided at startup) all mean deny. Each is reported with its own
  outcome, so a timeout is never mistaken for the gateway blocking something.
"""

import asyncio
import json
import os
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from agentguard.gateway.checks import CallContext
from agentguard.gateway.receipt_fields import args_digest
from agentguard.guards import NO_OBJECTION, GuardResult
from agentguard.guards.state import GuardState

Outcome = Literal["approved", "denied", "timeout", "error"]


class ApprovalConfig(BaseModel):
    always: list[str] = ["send_email", "delete_file"]
    when_tainted: list[str] = ["write_file", "send_email", "fetch_url"]
    timeout_s: float = 120
    poll_s: float = 0.2
    taint_ttl_s: float = 600


class TaintTracker:
    """Which agents recently received a flagged tool result. In memory; a guard reset clears it."""

    def __init__(self, ttl_s: float, state: GuardState, clock=time.monotonic) -> None:
        self.ttl_s, self.clock = ttl_s, clock
        self._until: dict[str, float] = {}
        state.on_reset(self._until.clear)

    def taint(self, did: str) -> None:
        self._until[did] = self.clock() + self.ttl_s

    def is_tainted(self, did: str) -> bool:
        until = self._until.get(did)
        return until is not None and self.clock() < until


class ApprovalRequirement:
    name = "approval"

    def __init__(self, config: ApprovalConfig, taint: TaintTracker) -> None:
        self.config, self.taint = config, taint

    def check(self, ctx: CallContext) -> GuardResult:
        if ctx.tool in self.config.always:
            return GuardResult("escalate", f"{ctx.tool} always needs human approval", "approval")
        profile = ctx.identity.profile if ctx.identity else None
        if profile and ctx.tool in self.config.when_tainted and self.taint.is_tainted(profile.did):
            return GuardResult(
                "escalate", "agent is tainted by a flagged tool result", "approval-taint"
            )
        return NO_OBJECTION


@dataclass(frozen=True)
class ApprovalResult:
    request_id: str
    outcome: Outcome
    approver: str | None = None
    detail: str = ""


def _write_private(path: Path, body: dict) -> None:
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(body, f, indent=2)
    tmp.replace(path)


class ApprovalQueue:
    def __init__(self, directory: Path, config: ApprovalConfig) -> None:
        self.pending_dir, self.decided_dir = directory / "pending", directory / "decided"
        for d in (self.pending_dir, self.decided_dir):
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)
        self.config = config

    def void_stale(self) -> int:
        """At gateway start: requests from a previous run can't be answered any more."""
        stale = list(self.pending_dir.glob("*.json")) + list(self.decided_dir.glob("*.json"))
        for path in stale:
            path.unlink(missing_ok=True)
        return len(stale)

    async def request(self, ctx: CallContext, why: str) -> ApprovalResult:
        request_id = secrets.token_hex(6)
        profile = ctx.identity.profile if ctx.identity else None
        pending = self.pending_dir / f"{request_id}.json"
        decided = self.decided_dir / f"{request_id}.json"
        try:
            _write_private(
                pending,
                {
                    "id": request_id,
                    "created": datetime.now(UTC).isoformat(timespec="seconds"),
                    "agent": ctx.agent_id,
                    "did": profile.did if profile else None,
                    "tool": ctx.tool,
                    "arguments": ctx.arguments,  # for the approver's eyes; never in receipts
                    "args_sha256": args_digest(ctx.arguments),
                    "why": why,
                },
            )
            deadline = time.monotonic() + self.config.timeout_s
            while time.monotonic() < deadline:
                if decided.exists():
                    return self._consume(request_id, decided, args_digest(ctx.arguments))
                await asyncio.sleep(self.config.poll_s)
            return ApprovalResult(request_id, "timeout", detail="no decision in time")
        except Exception as exc:
            return ApprovalResult(request_id, "error", detail=type(exc).__name__)
        finally:  # single use: nothing about this request survives it
            pending.unlink(missing_ok=True)
            decided.unlink(missing_ok=True)

    @staticmethod
    def _consume(request_id: str, decided: Path, digest: str) -> ApprovalResult:
        try:
            body = json.loads(decided.read_text())
        except ValueError:
            return ApprovalResult(request_id, "error", detail="unreadable decision")
        if body.get("args_sha256") != digest or body.get("id") != request_id:
            return ApprovalResult(request_id, "error", detail="decision is for a different call")
        if body.get("decision") == "approve":
            return ApprovalResult(request_id, "approved", str(body.get("approver") or "unknown"))
        if body.get("decision") == "deny":
            return ApprovalResult(request_id, "denied", str(body.get("approver") or "unknown"))
        return ApprovalResult(request_id, "error", detail="decision is neither approve nor deny")


# --- the approver's side (CLI) -------------------------------------------------------------


def list_pending(directory: Path) -> list[dict]:
    return [json.loads(p.read_text()) for p in sorted((directory / "pending").glob("*.json"))]


def decide(directory: Path, request_id: str, approve: bool, approver: str) -> bool:
    """Answer a pending request. False if it doesn't exist (answered, voided or timed out)."""
    pending = directory / "pending" / f"{request_id}.json"
    try:
        request = json.loads(pending.read_text())
    except FileNotFoundError:
        return False
    _write_private(
        directory / "decided" / f"{request_id}.json",
        {
            "id": request_id,
            "args_sha256": request["args_sha256"],
            "decision": "approve" if approve else "deny",
            "approver": approver,
            "at": datetime.now(UTC).isoformat(timespec="seconds"),
        },
    )
    return True
