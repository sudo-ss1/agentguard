import pytest

from agentguard.attacks import load_scenario, run_scripted


@pytest.mark.attack(2)
async def test_agent_cannot_delete_filesystem(lab):
    """delete_file / must be denied by path policy."""
    outcome = await run_scripted(load_scenario(2), lab)
    assert not outcome.succeeded, outcome.detail
