"""An attack run fails, rather than shrinks, when a scenario it must cover can't run.

A stale Docker image once ran attack 8's old stub (no oracle), skipped it, and reported a clean
table. These tests use stand-in scenarios and a fake lab, so no lab is started.
"""

from contextlib import contextmanager

import pytest
from typer.testing import CliRunner

from agentguard import cli
from agentguard.attacks import Oracle, Outcome, Scenario, missing_scenarios

runner = CliRunner()


def scenario(i: int, phase: int, runnable: bool = True) -> Scenario:
    return Scenario(
        id=i,
        name=f"s{i}",
        owasp="-",
        available_from_phase=phase,
        blocked_in_phase=phase,
        oracle=Oracle(type="tool_succeeded", tool="t") if runnable else None,
    )


def test_missing_scenarios_names_each_gap():
    available = [scenario(1, 1), scenario(2, 2, runnable=False), scenario(9, 9, runnable=False)]
    assert missing_scenarios(available, None, 2) == [
        "scenario 2: expected at phase 2 but has no oracle (stale code?)"
    ]
    assert missing_scenarios(available, None, 1) == []  # 2 isn't expected yet; 9 never is
    assert missing_scenarios(available, [1, 7], 1) == ["scenario 7: no such scenario"]


@pytest.fixture
def fake_run(monkeypatch):
    ran: list[int] = []

    @contextmanager
    def no_lab(local, log_dir=None):
        yield object()

    async def run(sc, lab):
        ran.append(sc.id)
        return Outcome(False, "blocked")

    monkeypatch.setattr(cli, "open_lab", no_lab)
    monkeypatch.setattr(cli, "run_scripted", run)
    return ran


def test_a_scenario_expected_at_this_phase_that_cannot_run_fails_the_run(fake_run, monkeypatch):
    monkeypatch.setattr(cli, "load_all", lambda: [scenario(1, 1), scenario(2, 2, runnable=False)])
    result = runner.invoke(cli.app, ["attack", "--expect-phase", "2"])
    assert result.exit_code == 1
    assert "attack run incomplete: scenario 2" in result.stderr
    assert fake_run == []  # it fails before running anything


def test_a_requested_scenario_that_cannot_run_fails_the_run(fake_run, monkeypatch):
    """The Docker loop runs one scenario per container: a stale image must fail, not skip."""
    monkeypatch.setattr(cli, "load_all", lambda: [scenario(1, 1), scenario(8, 6, runnable=False)])
    result = runner.invoke(cli.app, ["attack", "--scenario", "8", "--expect-phase", "5"])
    assert result.exit_code == 1 and "scenario 8" in result.stderr


def test_a_scenario_that_produced_no_result_fails_even_if_the_first_check_missed_it(
    fake_run, monkeypatch
):
    monkeypatch.setattr(cli, "load_all", lambda: [scenario(1, 1), scenario(2, 1, runnable=False)])
    monkeypatch.setattr(cli, "missing_scenarios", lambda *args: [])  # a bug in the first check
    result = runner.invoke(cli.app, ["attack", "--expect-phase", "1"])
    assert result.exit_code == 1
    assert "no result for scenario(s) [2]" in result.stderr


def test_a_complete_run_passes(fake_run, monkeypatch):
    monkeypatch.setattr(cli, "load_all", lambda: [scenario(1, 1), scenario(2, 2)])
    result = runner.invoke(cli.app, ["attack", "--expect-phase", "2"])
    assert result.exit_code == 0, result.output
    assert fake_run == [1, 2]
