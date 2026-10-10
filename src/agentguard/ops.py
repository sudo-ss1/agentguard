"""Operator actions, shared by the CLI and the dashboard: one path for each, so both are
audited the same way.

- kill, revive and reset write the gateway's kill list; the gateway records each change as a
  signed control receipt (gateway/control.py).
- approve and deny answer a pending request; the gateway records the decision, with the
  approver, in that call's receipt.

`by` and `approver` name the operating-system user, never a free-text field: `cli:<user>` or
`dashboard:<user>` for kill-list changes, `<user>` as an approver.
"""

import getpass
from pathlib import Path

from agentguard.guards.approvals import decide as _decide
from agentguard.guards.approvals import list_pending
from agentguard.guards.state import GuardState


def os_user() -> str:
    return getpass.getuser()


def operator(channel: str) -> str:
    """Who is acting, for control receipts: e.g. `cli:alice`."""
    return f"{channel}:{os_user()}"


def kill(
    state_dir: Path, by: str, reason: str, agent: str | None = None, did: str | None = None
) -> list[str]:
    """Stop an agent by name or DID. Returns the DIDs affected."""
    if (agent is None) == (did is None):
        raise ValueError("pass exactly one of agent or did")
    return GuardState(state_dir).kill(reason, did=did, name=agent, by=by, category="manual")


def revive(state_dir: Path, by: str, agent: str | None = None, did: str | None = None) -> None:
    if (agent is None) == (did is None):
        raise ValueError("pass exactly one of agent or did")
    GuardState(state_dir).revive(did=did, name=agent, by=by)


def reset(state_dir: Path, by: str) -> None:
    GuardState(state_dir).reset(by=by)


def approvals_dir(state_dir: Path) -> Path:
    return state_dir / "approvals"


def pending(state_dir: Path) -> list[dict]:
    """Pending approval requests, as the gateway wrote them, raw arguments included. The CLI
    shows them to the approver; the dashboard shows only a redacted view."""
    return list_pending(approvals_dir(state_dir))


def decide(state_dir: Path, request_id: str, approve: bool, approver: str) -> bool:
    """Answer one pending request. False if it is no longer pending."""
    return _decide(approvals_dir(state_dir), request_id, approve, approver)
