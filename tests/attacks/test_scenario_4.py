import pytest

from agentguard.attacks import load_scenario, run_scripted


@pytest.mark.attack(4)
async def test_sub_agent_cannot_widen_attenuated_token(lab):
    """A sub-agent's narrowed Biscuit must not allow send_email."""
    outcome = await run_scripted(load_scenario(4), lab)
    assert not outcome.succeeded, outcome.detail
