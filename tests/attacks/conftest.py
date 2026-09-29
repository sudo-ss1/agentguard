"""Attack tests assert the attack is *blocked*.

AGENTGUARD_MODE=baseline: the agent talks to the tools directly, so every runnable attack is
xfail(strict=True). The run fails if an attack stops working against the unprotected stack.

AGENTGUARD_MODE=guarded: the agent goes through the gateway. Attacks whose control has
landed (blocked_in_phase <= CURRENT_PHASE) must be blocked; later ones are still strict
xfail, so a phase can't claim a block it doesn't deliver.
"""

import json

import pytest

from agentguard import CURRENT_PHASE
from agentguard.attacks import load_scenario
from agentguard.lab_stack import local_lab
from agentguard.settings import get_settings


@pytest.fixture(scope="session")
def lab():
    with local_lab(guarded=get_settings().agentguard_mode == "guarded") as lab:
        yield lab


def pytest_collection_modifyitems(items):
    mode = get_settings().agentguard_mode
    for item in items:
        marker = item.get_closest_marker("attack")
        if marker is None:
            continue
        scenario = load_scenario(marker.args[0])
        if not scenario.runnable:
            item.add_marker(
                pytest.mark.skip(
                    reason=f"scenario {scenario.id} lands in phase {scenario.available_from_phase}"
                )
            )
        elif mode == "baseline":
            item.add_marker(
                pytest.mark.xfail(strict=True, reason="baseline: attack is expected to succeed")
            )
        elif scenario.blocked_in_phase > CURRENT_PHASE:
            item.add_marker(
                pytest.mark.xfail(
                    strict=True, reason=f"blocked from phase {scenario.blocked_in_phase}"
                )
            )


@pytest.fixture
def gateway_denials(lab):
    """Policy ids of the gateway denials recorded during the test (guarded mode only).

    Attack tests use it to check the block came from the intended layer at the gateway, not
    from the client quietly refusing a call it was never shown.
    """
    path = lab.receipts_path
    start = len(path.read_text().splitlines()) if path and path.exists() else 0

    def denials() -> list[str]:
        if path is None or not path.exists():
            return []
        lines = path.read_text().splitlines()[start:]
        return [r["policy_id"] for r in map(json.loads, lines) if r["decision"] != "allow"]

    return denials


@pytest.fixture
def gateway_receipts(lab):
    """All gateway receipts recorded during the test (guarded mode only)."""
    path = lab.receipts_path
    start = len(path.read_text().splitlines()) if path and path.exists() else 0

    def rows() -> list[dict]:
        if path is None or not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()[start:]]

    return rows
