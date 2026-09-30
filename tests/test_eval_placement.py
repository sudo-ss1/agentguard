"""Page placement, tested with random markers only."""

import secrets

import pytest

from agentguard.eval.placement import MODES, place_text, reaches_reader
from agentguard.guards.result_scan import strip_hidden


def marker() -> str:
    return f"marker-{secrets.token_hex(8)}"


def test_raw_is_the_string_itself():
    m = marker()
    assert place_text(m, "raw") == m


@pytest.mark.parametrize("mode", ["visible", "hidden"])
def test_the_marker_is_placed_in_a_page(mode):
    m = marker()
    page = place_text(m, mode)
    assert page.startswith("<!doctype html>") and m in page


def test_a_visible_marker_survives_stripping():
    m = marker()
    visible = strip_hidden(place_text(m, "visible")).visible
    assert reaches_reader(m, visible)


def test_a_hidden_marker_is_stripped():
    m = marker()
    page = place_text(m, "hidden")
    assert reaches_reader(m, page)  # it is in the page...
    assert not reaches_reader(m, strip_hidden(page).visible)  # ...but not after stripping


def test_markup_characters_are_escaped_and_still_match():
    m = f"{marker()} <b>&</b> 'quoted'"
    page = place_text(m, "visible")
    assert "<b>" not in page  # escaped, so the page stays well-formed
    assert reaches_reader(m, strip_hidden(page).visible)


def test_reaches_reader_ignores_whitespace_differences():
    m = marker()
    assert reaches_reader(f"a  {m}\nb", f"x a {m} b y")
    assert not reaches_reader(m, "something else")


def test_unknown_mode_is_rejected():
    with pytest.raises(ValueError):
        place_text(marker(), "sideways")  # type: ignore[arg-type]


def test_modes():
    assert MODES == ("raw", "visible", "hidden")
