import pytest

from agentguard.attacks import load_scenario, run_scripted


@pytest.mark.attack(5)
async def test_forged_a2a_request_is_rejected(lab):
    """A request signed with the wrong key must fail the DID check."""
    outcome = await run_scripted(load_scenario(5), lab)
    assert not outcome.succeeded, outcome.detail
