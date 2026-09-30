"""Clopper-Pearson intervals against standard reference values."""

import pytest

from agentguard.eval.stats import clopper_pearson, fmt_rate


@pytest.mark.parametrize(
    ("k", "n", "lower", "upper"),
    [
        (0, 20, 0.0, 0.1684),
        (2, 20, 0.0123, 0.3170),
        (20, 20, 0.8316, 1.0),
        (1, 5, 0.0051, 0.7164),
        (30, 60, 0.3681, 0.6319),
    ],
)
def test_matches_reference_values(k, n, lower, upper):
    lo, hi = clopper_pearson(k, n)
    assert lo == pytest.approx(lower, abs=1e-4) and hi == pytest.approx(upper, abs=1e-4)


def test_large_n_is_stable():
    lo, hi = clopper_pearson(1000, 2216)
    assert 0.43 < lo < 0.452 < hi < 0.475


def test_formatting():
    assert fmt_rate(2, 20) == "2/20 (10%; 95% CI 1%–32%)"
    assert fmt_rate(0, 0) == "0/0"
