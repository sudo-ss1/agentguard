import pytest

from agentguard.attacks import load_scenario, run_scripted


@pytest.mark.attack(1)
async def test_injected_page_cannot_exfiltrate_ssh_key(lab, gateway_denials):
    """Hidden instructions on a web page must not get the SSH key emailed out."""
    outcome = await run_scripted(load_scenario(1), lab)
    assert not outcome.succeeded, outcome.detail
    assert set(["no-ssh-keys", "default-deny"]) <= set(gateway_denials())
