"""Per-agent rate and cost budgets. They run in the guard stage, after Cedar and approval.

- Rate: calls per tool per sliding window (e.g. fetch_url: 30 per 60 s).
- Cost: each tool has a cost, and an agent may spend `cost_budget` per `cost_window_s`.

A call over either limit is denied. The kill switch trips for that agent when its cost budget
is exhausted, or after `trip_after_rate_denials` consecutive rate-limited attempts, since an
agent that keeps hammering a limit is behaving like a runaway (attack 6). Only calls that
pass count against the budget.
"""

import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable

from pydantic import BaseModel

from agentguard.gateway.checks import CallContext
from agentguard.guards import NO_OBJECTION, GuardResult
from agentguard.guards.state import GuardState


class BudgetConfig(BaseModel):
    window_s: float = 60
    calls_per_window: dict[str, int] = {"fetch_url": 30, "default": 60}
    cost: dict[str, int] = {"send_email": 5, "delete_file": 5, "default": 1}
    cost_budget: int = 200
    cost_window_s: float = 3600
    trip_after_rate_denials: int = 20


class BudgetGuard:
    name = "budget"

    def __init__(
        self,
        config: BudgetConfig,
        state: GuardState,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config, self.state, self.clock = config, state, clock
        self._lock = threading.Lock()
        self.reset()
        state.on_reset(self.reset)

    def reset(self) -> None:
        self._calls: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._spend: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._rate_denials: dict[str, int] = defaultdict(int)

    def _limit(self, tool: str) -> int:
        return self.config.calls_per_window.get(tool, self.config.calls_per_window["default"])

    def _cost(self, tool: str) -> int:
        return self.config.cost.get(tool, self.config.cost["default"])

    def check(self, ctx: CallContext) -> GuardResult:
        identity = ctx.identity
        if identity is None or identity.profile is None:
            return GuardResult("deny", "no verified identity", "budget")
        did, now = identity.profile.did, self.clock()
        with self._lock:
            calls = self._calls[(did, ctx.tool)]
            while calls and now - calls[0] >= self.config.window_s:
                calls.popleft()
            spend = self._spend[did]
            while spend and now - spend[0][0] >= self.config.cost_window_s:
                spend.popleft()
            spent, cost, limit = (
                sum(c for _, c in spend),
                self._cost(ctx.tool),
                self._limit(ctx.tool),
            )

            if spent + cost > self.config.cost_budget:
                return self._trip(
                    ctx,
                    "cost budget exhausted",
                    {"limit": self.config.cost_budget, "window_s": self.config.cost_window_s},
                )
            if len(calls) >= limit:
                self._rate_denials[did] += 1
                attributes = {"limit": limit, "window_s": self.config.window_s}
                if self._rate_denials[did] >= self.config.trip_after_rate_denials:
                    return self._trip(ctx, "rate limit hit repeatedly", attributes)
                return GuardResult("deny", f"rate limit for {ctx.tool}", "budget", attributes)

            self._rate_denials[did] = 0
            calls.append(now)
            spend.append((now, cost))
        return NO_OBJECTION

    def _trip(self, ctx: CallContext, why: str, attributes: dict) -> GuardResult:
        assert ctx.identity is not None and ctx.identity.profile is not None
        self.state.kill(f"budget: {why}", did=ctx.identity.profile.did, by="gateway:budget")
        return GuardResult(
            "deny",
            f"{why}; kill switch tripped",
            "budget",
            {**attributes, "kill_switch": "tripped"},
        )
