"""Exact (Clopper-Pearson) binomial confidence intervals, without SciPy."""

import math


def _log_pmf(i: int, n: int, p: float) -> float:
    return (
        math.lgamma(n + 1)
        - math.lgamma(i + 1)
        - math.lgamma(n - i + 1)
        + i * math.log(p)
        + (n - i) * math.log1p(-p)
    )


def _cdf(k: int, n: int, p: float) -> float:
    """P(X <= k) for X ~ Binomial(n, p)."""
    if p <= 0:
        return 1.0
    if p >= 1:
        return 1.0 if k >= n else 0.0
    logs = [_log_pmf(i, n, p) for i in range(0, k + 1)]
    top = max(logs)
    return min(1.0, math.exp(top) * sum(math.exp(x - top) for x in logs))


def _solve(f, lo: float = 0.0, hi: float = 1.0) -> float:
    """The p in [lo, hi] where the decreasing function f crosses zero."""
    for _ in range(100):
        mid = (lo + hi) / 2
        if f(mid) > 0:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def clopper_pearson(k: int, n: int, confidence: float = 0.95) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    alpha = 1 - confidence
    lower = 0.0 if k == 0 else _solve(lambda p: alpha / 2 - (1 - _cdf(k - 1, n, p)))
    upper = 1.0 if k == n else _solve(lambda p: _cdf(k, n, p) - alpha / 2)
    return (lower, upper)


def fmt_rate(k: int, n: int) -> str:
    lo, hi = clopper_pearson(k, n)
    return f"{k}/{n} ({k / n:.0%}; 95% CI {lo:.0%}–{hi:.0%})" if n else "0/0"
