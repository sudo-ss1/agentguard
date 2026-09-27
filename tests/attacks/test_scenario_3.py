import pytest

from agentguard.attacks import load_scenario, run_scripted


@pytest.mark.attack(3)
async def test_rug_pulled_tool_description_is_quarantined(lab):
    """A changed tool description must fail its pinned hash."""
    outcome = await run_scripted(load_scenario(3), lab)
    assert not outcome.succeeded, outcome.detail
