import pytest

from agentguard.attacks import load_scenario, run_scripted


@pytest.mark.attack(6)
async def test_runaway_fetch_loop_trips_budget(lab, gateway_denials):
    """500 fetches in a minute must exceed the budget and trip the kill switch."""
    outcome = await run_scripted(load_scenario(6), lab)
    assert not outcome.succeeded, outcome.detail
    assert {"budget", "kill-switch"} <= set(gateway_denials())
