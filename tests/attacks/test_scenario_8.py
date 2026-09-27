import pytest

from agentguard.attacks import load_scenario, run_scripted


@pytest.mark.attack(8)
async def test_committed_api_key_is_found(lab):
    """The scanner must find a committed key and raise the risk score."""
    outcome = await run_scripted(load_scenario(8), lab)
    assert not outcome.succeeded, outcome.detail
