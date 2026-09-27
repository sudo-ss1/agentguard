import pytest

from agentguard.attacks import load_scenario, run_scripted


@pytest.mark.attack(5)
async def test_forged_a2a_request_is_rejected(lab, gateway_denials):
    """A request claiming research-bot but signed by another key must fail identity."""
    outcome = await run_scripted(load_scenario(5), lab)
    assert not outcome.succeeded, outcome.detail
    assert set(["identity"]) <= set(gateway_denials())
