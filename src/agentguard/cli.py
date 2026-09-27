"""`agentguard` CLI: run the agent, and run attack scenarios against the lab."""

import asyncio
import signal
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated

import typer
import yaml

from agentguard.attacks import Scenario, load_all, run_llm, run_scripted
from agentguard.config import load_config
from agentguard.lab_stack import Lab, local_lab
from agentguard.runlog import RunLog, TrialRecord, new_run_dir, summarize_attempts
from agentguard.settings import get_settings

app = typer.Typer(no_args_is_help=True)


@app.callback()
def main() -> None:
    # Turn SIGTERM into a normal exit so local_lab's cleanup stops its child servers.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(128 + signal.SIGTERM))


LocalOpt = Annotated[bool, typer.Option(help="Spawn the lab as local processes instead of Docker.")]


@contextmanager
def open_lab(local: bool, log_dir: Path | None = None) -> Iterator[Lab]:
    s = get_settings()
    cfg = load_config(s.agent_config_path)
    if local:
        with local_lab(guarded=s.agentguard_mode == "guarded", log_dir=log_dir) as lab:
            lab.agent_id = cfg.agent_id
            yield lab
        return
    guarded = s.agentguard_mode == "guarded"
    yield Lab(
        cfg.servers,
        s.evil_site,
        s.lab_root,
        s.outbox_path,
        s.rugpull_flag,
        s.receipts_path if guarded else None,
        cfg.agent_id,
        s.rug_pull_settle_s if guarded else 0.0,
    )


@app.command()
def run(
    task: Annotated[str | None, typer.Option(help="Task for the LLM agent.")] = None,
    scripted: Annotated[
        Path | None, typer.Option(help="Scenario YAML to replay without an LLM.")
    ] = None,
    local: LocalOpt = False,
) -> None:
    """Run the agent on a task, or replay a scripted scenario."""
    from agentguard.agent.graph import run_task
    from agentguard.agent.llm import get_chat_model
    from agentguard.agent.scripted import Step
    from agentguard.agent.toolbox import Toolbox
    from agentguard.attacks import run_steps

    if (task is None) == (scripted is None):
        raise typer.BadParameter("pass exactly one of --task or --scripted")
    s = get_settings()

    async def go(lab: Lab) -> None:
        if scripted:
            steps = [
                Step.model_validate(x) for x in yaml.safe_load(scripted.read_text())["scripted"]
            ]
            call_log = await run_steps(lab, steps)
        else:
            async with Toolbox(lab.servers, lab.agent_id) as toolbox:
                cfg = load_config(s.agent_config_path)
                messages = await run_task(get_chat_model(s), toolbox, cfg.system_prompt, task or "")
                typer.echo(messages[-1].content)
                call_log = toolbox.call_log
        for name, args, result in call_log:
            status = "ERROR" if result.is_error else "ok"
            typer.echo(f"  [{status}] {name}({args}) -> {result.text[:80]!r}", err=True)

    with open_lab(local) as lab:
        asyncio.run(go(lab))


@app.command()
def attack(
    scenario: Annotated[list[int] | None, typer.Option(help="Scenario id(s); default all.")] = None,
    llm: Annotated[
        bool, typer.Option(help="Also run each scenario's task through the LLM agent.")
    ] = False,
    trials: Annotated[int, typer.Option(help="LLM trials per scenario.")] = 5,
    local: LocalOpt = False,
) -> None:
    """Run attack scenarios and print a markdown results table.

    With --local, the run's gateway decision log, a per-trial index (trials.jsonl) and the
    table (results.md) are kept in <RUN_LOG_DIR>/<timestamp>/.
    """
    s = get_settings()
    scenarios = [x for x in load_all() if x.runnable and (not scenario or x.id in scenario)]
    run_dir = new_run_dir(s.run_log_dir) if local else None
    guarded = s.agentguard_mode == "guarded"

    async def go(lab: Lab) -> list[list[str]]:
        runlog = (
            RunLog(run_dir, s.agentguard_mode, lab.receipts_path, lab.lab_root) if run_dir else None
        )
        model = system_prompt = None
        if llm:
            from agentguard.agent.llm import get_chat_model

            model, system_prompt = get_chat_model(s), load_config(s.agent_config_path).system_prompt
        rows = []
        for sc in scenarios:
            scripted = await run_scripted(sc, lab)
            typer.echo(f"#{sc.id} scripted: {scripted.detail}", err=True)
            rows.append([str(sc.id), sc.name, sc.owasp, _verdict(scripted.succeeded)])
            if llm:
                if not sc.task:
                    rows[-1] += ["n/a (scripted only)"] + (["n/a"] if guarded else [])
                    continue
                records = await _llm_trials(sc, lab, model, system_prompt or "", trials, runlog)
                wins = sum(r.attack_succeeded for r in records)
                errors = sum(1 for r in records if r.agent_error)
                rows[-1].append(
                    f"{wins}/{trials}" + (f" ({errors} ended in agent error)" if errors else "")
                )
                if guarded:
                    rows[-1].append(summarize_attempts(sc, records))
        return rows

    with open_lab(local, log_dir=run_dir) as lab:
        rows = asyncio.run(go(lab))
    header = ["#", "Attack", "OWASP", f"Scripted ({s.agentguard_mode})"]
    if llm:
        header.append(f"LLM success rate ({s.agentguard_mode})")
        if guarded:
            header.append("Attack calls in the gateway log")
    table = _markdown_table(header, rows)
    typer.echo(table)
    if run_dir:
        (run_dir / "results.md").write_text(table + "\n")
        typer.echo(f"run log: {run_dir}", err=True)


async def _llm_trials(
    sc: Scenario, lab: Lab, model, system_prompt: str, trials: int, runlog: RunLog | None
) -> list[TrialRecord]:
    records = []
    for i in range(trials):
        start = runlog.mark() if runlog else 0
        outcome = await run_llm(sc, lab, model, system_prompt)
        typer.echo(f"#{sc.id} llm trial {i + 1}: {outcome.detail}", err=True)
        if runlog:
            records.append(runlog.record(sc, i + 1, outcome, start))
        else:
            records.append(
                TrialRecord(
                    sc.id, "", i + 1, outcome.succeeded, outcome.detail, None, outcome.agent_error
                )
            )
    return records


def _verdict(attack_succeeded: bool) -> str:
    return "attack succeeded" if attack_succeeded else "blocked"


def _markdown_table(header: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + " --- |" * len(header)]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines)
