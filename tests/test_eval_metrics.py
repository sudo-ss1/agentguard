"""Tests for agentguard.eval.metrics.

Synthetic labelled items and fake scan functions only. No corpus data is used here.

Most tests replace place_text and reaches_reader with simple stand-ins, so they test the
scoring logic in isolation. The tests in the last section use the real placement code and
cover the fixes requested in review; they are expected to fail until those fixes land.
"""

import json

import pytest

from agentguard.eval import metrics
from agentguard.eval.metrics import Item, Row, as_json, markdown, score, summarize
from agentguard.eval.placement import MODES, Mode
from agentguard.eval.stats import clopper_pearson

RAW: Mode = "raw"


# --- Fake scan functions: each returns (delivered, tainted, withheld) -----------------------


def passthrough(page: str) -> tuple[str, bool, bool]:
    return page, False, False


def withhold_but_keep_text(page: str) -> tuple[str, bool, bool]:
    # Withheld, yet the returned text still contains the item. It must not count as reached.
    return page, False, True


def taint_only(page: str) -> tuple[str, bool, bool]:
    return page, True, False


def flag_on_marker(page: str) -> tuple[str, bool, bool]:
    if "FLAGME" in page:
        return "[result withheld]", True, True
    return page, False, False


@pytest.fixture
def simple_placement(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(metrics, "place_text", lambda text, mode: f"<page {mode}>{text}</page>")
    monkeypatch.setattr(metrics, "reaches_reader", lambda text, delivered: text in delivered)


def items(n: int, label: int, group: str = "g", prefix: str = "MARKER") -> list[Item]:
    return [Item(f"{prefix}-{i:04d}", label, group) for i in range(n)]


# --- score() ---------------------------------------------------------------------------------


def test_passthrough_reaches_everything_and_detects_nothing(simple_placement: None) -> None:
    scored = score(items(5, 1), RAW, passthrough)
    assert len(scored) == 5
    assert all(s.reached and not s.detected and not s.withheld for s in scored)
    assert all(s.mode == RAW for s in scored)


def test_withheld_is_detected_and_never_reached(simple_placement: None) -> None:
    scored = score(items(3, 1), RAW, withhold_but_keep_text)
    assert all(s.withheld and s.detected and not s.reached for s in scored)


def test_taint_without_withhold_is_detected_but_still_reached(simple_placement: None) -> None:
    scored = score(items(3, 1), RAW, taint_only)
    assert all(s.detected and s.reached and not s.withheld for s in scored)


def test_detected_includes_withheld(simple_placement: None) -> None:
    mixed = items(2, 1, prefix="FLAGME") + items(3, 1, prefix="PLAIN")
    rows = summarize(score(mixed, RAW, flag_on_marker))
    assert len(rows) == 1
    row = rows[0]
    assert (row.n, row.detected, row.withheld, row.reached) == (5, 2, 2, 3)
    assert row.withheld <= row.detected


def test_score_accepts_a_generator(simple_placement: None) -> None:
    scored = score((it for it in items(4, 0)), RAW, passthrough)
    assert len(scored) == 4


# --- summarize() -----------------------------------------------------------------------------


def test_summarize_splits_by_group_mode_and_label(simple_placement: None) -> None:
    data = items(3, 1, group="a") + items(2, 0, group="a") + items(4, 1, group="b")
    other = next(m for m in MODES if m != RAW)
    scored = score(data, RAW, passthrough) + score(items(1, 1, group="a"), other, passthrough)
    rows = summarize(scored)
    keys = {(r.group, r.mode, r.label): r.n for r in rows}
    assert keys[("a", RAW, 1)] == 3
    assert keys[("a", RAW, 0)] == 2
    assert keys[("b", RAW, 1)] == 4
    assert keys[("a", other, 1)] == 1
    assert sum(r.n for r in rows) == 10


def test_detection_and_false_positive_rates(simple_placement: None) -> None:
    positives = items(8, 1, prefix="FLAGME") + items(2, 1, prefix="PLAIN")
    negatives = items(19, 0, prefix="PLAIN") + items(1, 0, prefix="FLAGME")
    rows = {r.label: r for r in summarize(score(positives + negatives, RAW, flag_on_marker))}
    assert (rows[1].n, rows[1].detected) == (10, 8)  # detection rate 8/10
    assert (rows[0].n, rows[0].detected) == (20, 1)  # false-positive rate 1/20
    assert rows[1].reached == 2


def test_summarize_empty() -> None:
    assert summarize([]) == []


# --- intervals -------------------------------------------------------------------------------


def test_interval_matches_clopper_pearson() -> None:
    row = Row("g", RAW, 1, 20, 7, 5, 3)
    assert row.interval("detected") == clopper_pearson(7, 20)
    assert row.interval("reached") == clopper_pearson(5, 20)
    assert row.interval("withheld") == clopper_pearson(3, 20)


def test_interval_known_values() -> None:
    zero = Row("g", RAW, 1, 20, 0, 20, 0)
    lo, hi = zero.interval("detected")
    assert lo == 0.0
    assert hi == pytest.approx(0.1684, abs=1e-3)
    lo, hi = zero.interval("reached")  # 20/20
    assert hi == 1.0
    assert lo == pytest.approx(0.8316, abs=1e-3)


# --- output ----------------------------------------------------------------------------------


def test_markdown_has_header_and_one_line_per_row(simple_placement: None) -> None:
    rows = summarize(score(items(3, 1) + items(2, 0), RAW, passthrough))
    lines = markdown(rows).splitlines()
    assert len(lines) == 2 + len(rows)
    assert lines[0].startswith("| Group |")
    body = "\n".join(lines[2:])
    assert "positive" in body and "negative" in body


def test_markdown_empty() -> None:
    assert len(markdown([]).splitlines()) == 2


def test_as_json_is_serializable_with_intervals(simple_placement: None) -> None:
    rows = summarize(score(items(4, 1), RAW, passthrough))
    out = as_json(rows)
    assert len(out) == 1
    for field in ("detected", "reached", "withheld"):
        assert f"{field}_ci95" in out[0]
        assert out[0][field] == getattr(rows[0], field)
    json.dumps(out)


def test_as_json_empty() -> None:
    assert as_json([]) == []


# --- Requested fixes: expected to fail until metrics.py is updated ---------------------------


def test_rows_follow_modes_order(simple_placement: None) -> None:
    scored = []
    for mode in reversed(MODES):
        scored += score(items(1, 1), mode, passthrough)
    assert [r.mode for r in summarize(scored)] == list(MODES)


def test_interval_rejects_unknown_field() -> None:
    with pytest.raises(ValueError):
        Row("g", RAW, 1, 5, 1, 1, 1).interval("detcted")


@pytest.mark.parametrize("bad", [2, -1])
def test_item_rejects_bad_label(bad: int) -> None:
    with pytest.raises(ValueError):
        Item("MARKER", bad, "g")


def test_reached_ignores_removed_invisible_characters() -> None:
    # Real placement. Removing a zero-width character from inside the string must not
    # count as "didn't reach": the meaningful text still got through.
    item = Item("MARKER\u200b-4821", 1, "g")

    def strip_zero_width(page: str) -> tuple[str, bool, bool]:
        return page.replace("\u200b", ""), False, False

    (scored,) = score([item], RAW, strip_zero_width)
    assert scored.reached


def test_reached_false_when_text_fully_removed() -> None:
    item = Item("MARKER-7730", 1, "g")

    def remove_item(page: str) -> tuple[str, bool, bool]:
        return page.replace("MARKER-7730", ""), False, False

    (scored,) = score([item], RAW, remove_item)
    assert not scored.reached


def test_split_empty_leaves_out_text_that_normalizes_to_nothing() -> None:
    kept, empty = metrics.split_empty(
        [Item("MARKER-1", 1, "a"), Item(" \u200b\n", 1, "a"), Item("\U000e0041", 0, "b")]
    )
    assert [i.text for i in kept] == ["MARKER-1"]
    assert empty == {"a": 1, "b": 1}
