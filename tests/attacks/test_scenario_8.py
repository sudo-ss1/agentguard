import re

import pytest

from agentguard.attacks import load_scenario, run_scripted


@pytest.mark.attack(8)
async def test_committed_api_key_is_found(lab):
    """The scanner must list a committed key, and research-bot's risk score must rise with
    that finding named as the reason."""
    outcome = await run_scripted(load_scenario(8), lab)
    assert not outcome.succeeded, outcome.detail
    assert (
        "scanner listed anthropic-api-key at app/settings.py:5 in the working tree and in commit"
        in outcome.detail
    )
    before, after = map(int, re.search(r"risk (\d+) -> (\d+)", outcome.detail).groups())
    assert after > before
    assert "privilege 0.60 -> 1.00" in outcome.detail
