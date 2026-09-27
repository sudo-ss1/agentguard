import pytest

from agentguard.attacks import load_scenario, run_scripted


@pytest.mark.attack(4)
async def test_sub_agent_cannot_reuse_parent_token(lab, gateway_denials):
    """A sub-agent presenting its parent's token must fail the token's holder caveat."""
    outcome = await run_scripted(load_scenario(4), lab)
    assert not outcome.succeeded, outcome.detail
    assert set(["capability-token"]) <= set(gateway_denials())
