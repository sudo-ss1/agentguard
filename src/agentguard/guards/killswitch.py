"""Kill switch check: right after identity, before the capability token is even looked at.

A killed agent is refused even though its token is still valid, because the token is never
consulted. See state.py for what the kill list holds.
"""

from biscuit_auth import PublicKey

from agentguard.gateway.checks import CallContext, Decision
from agentguard.guards.state import GuardState
from agentguard.tokens.biscuit import TokenError, parse


class KillSwitchCheck:
    name = "kill-switch"

    def __init__(self, state: GuardState, root: PublicKey) -> None:
        self.state, self.root = state, root

    def evaluate(self, ctx: CallContext) -> Decision:
        identity = ctx.identity
        if identity is None or identity.profile is None:
            return Decision("deny", "no verified identity", "kill-switch")
        revocation_ids: list[str] = []
        if identity.token is not None:
            try:
                revocation_ids = list(parse(identity.token, self.root).revocation_ids)
            except TokenError:
                revocation_ids = []  # the token check right after this one will refuse it
            if revocation_ids:
                self.state.record_token(
                    identity.profile.did, identity.profile.name, revocation_ids[-1]
                )
        reason = self.state.killed_reason(
            identity.profile.did, identity.profile.name, revocation_ids
        )
        if reason is not None:
            return Decision(
                "deny",
                "agent is stopped by the kill switch",
                "kill-switch",
                {"kill_reason": reason},
            )
        return Decision("allow", "not killed", "kill-switch")
