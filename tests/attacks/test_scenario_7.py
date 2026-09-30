import pytest

from agentguard.attacks import load_scenario, run_scripted


@pytest.mark.attack(7)
async def test_edited_audit_row_is_detected(lab):
    """verify must name exactly the edited receipt, and say its content changed."""
    outcome = await run_scripted(load_scenario(7), lab)
    assert not outcome.succeeded, outcome.detail
    assert outcome.detail.endswith(": hash"), outcome.detail
