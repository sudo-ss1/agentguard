import pytest

from agentguard.attacks import load_scenario, run_scripted


@pytest.mark.attack(7)
async def test_edited_audit_row_is_detected(lab):
    """verify must report the broken link after a receipt is edited."""
    outcome = await run_scripted(load_scenario(7), lab)
    assert not outcome.succeeded, outcome.detail
