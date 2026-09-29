"""`agentguard` CLI: run the agent, and run attack scenarios against the lab."""

import asyncio
import json
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
from agentguard.identity.client import load_credentials, wait_for
from agentguard.identity.provision import provision as run_provision
from agentguard.lab_stack import Lab, local_lab
from agentguard.runlog import RunLog, TrialRecord, new_run_dir, summarize_attempts
from agentguard.settings import get_settings

app = typer.Typer(no_args_is_help=True)
guards_app = typer.Typer(no_args_is_help=True, help="Gateway runtime guards (Phase 4).")
app.add_typer(guards_app, name="guards")
receipts_app = typer.Typer(
    no_args_is_help=True, help="Prove or erase values committed in receipts."
)
app.add_typer(receipts_app, name="receipts")


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
    lab = Lab(
        cfg.servers,
        s.evil_site,
        s.lab_root,
        s.outbox_path,
        s.rugpull_flag,
        s.receipts_path if guarded else None,
        cfg.agent_id,
        s.rug_pull_settle_s if guarded else 0.0,
    )
    if guarded:  # credentials written by `agentguard provision`
        lab.credentials = load_credentials(s.credentials_dir)
        if lab.agent_id not in lab.credentials:
            raise typer.BadParameter(
                f"no credentials for {lab.agent_id!r} in {s.credentials_dir}; "
                "run `agentguard provision` first"
            )
    yield lab


@app.command()
def provision(
    identity_url: Annotated[str, typer.Option(help="The identity service.")],
    creds_dir: Annotated[Path, typer.Option(help="Where agent keys and credentials go.")],
    trust_file: Annotated[Path, typer.Option(help="Where the gateway's public trust goes.")],
) -> None:
    """Register the lab's agents and write the gateway's trust file. Safe to re-run: keys are
    reused and tokens refreshed (root tokens last an hour)."""
    wait_for(identity_url)
    credentials, trust = run_provision(identity_url, creds_dir)
    trust_file.parent.mkdir(parents=True, exist_ok=True)
    trust_file.write_text(json.dumps(trust, indent=2) + "\n")
    for name, c in credentials.items():
        status = "registered" if c.vc else "key only (unregistered)"
        typer.echo(f"{name:13} {c.key.did[:32]}...  {status}")
    typer.echo(f"trust: {trust_file}")


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
            async with Toolbox(lab.servers, lab.identity_for()) as toolbox:
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


@receipts_app.command("prove")
def receipts_prove(
    receipts: Annotated[Path, typer.Option(help="The receipt log (receipts.jsonl).")],
    line: Annotated[int, typer.Option(help="The receipt's line number (1-based).")],
    attribute: Annotated[str, typer.Option(help="e.g. recipient, path, upstream_error")],
    value: Annotated[str, typer.Option(help="The value you claim was committed.")],
    salts: Annotated[Path, typer.Option(help="The salt store (kept apart from receipts).")],
) -> None:
    """Show whether a receipt commits an attribute to a value. Exit code 0 only if proven."""
    from agentguard.gateway.audit import prove, read_receipt
    from agentguard.gateway.commitments import SaltStore

    result = prove(read_receipt(receipts, line), attribute, value, SaltStore(salts))
    typer.echo(f"{result.status}: {result.detail}")
    raise typer.Exit(0 if result.status == "proven" else 1)


@receipts_app.command("forget")
def receipts_forget(
    salts: Annotated[Path, typer.Option(help="The salt store.")],
    commitment: Annotated[str, typer.Option(help="The commitment whose salt to delete.")],
) -> None:
    """Delete a salt so the committed value can never be recovered or proven. The receipt
    itself is not touched."""
    from agentguard.gateway.commitments import SaltStore

    removed = SaltStore(salts).forget(commitment)
    typer.echo("salt deleted" if removed else "no salt for that commitment")
    raise typer.Exit(0 if removed else 1)


StateDirOpt = Annotated[
    Path | None, typer.Option(help="Gateway guard state dir (default: GUARD_STATE_DIR).")
]


def _guard_state(state_dir: Path | None):
    from agentguard.guards.state import GuardState

    return GuardState(state_dir or get_settings().guard_state_dir)


@app.command()
def kill(
    agent: Annotated[str | None, typer.Option(help="Agent name to stop.")] = None,
    did: Annotated[str | None, typer.Option(help="Agent DID to stop.")] = None,
    reason: Annotated[str, typer.Option(help="Why (recorded in receipts).")] = "manual kill",
    state_dir: StateDirOpt = None,
) -> None:
    """Stop an agent now, even though its token is still valid. Also revokes tokens it was
    seen presenting, and so everything delegated from them."""
    if (agent is None) == (did is None):
        raise typer.BadParameter("pass exactly one of --agent or --did")
    affected = _guard_state(state_dir).kill(reason, did=did, name=agent)
    typer.echo(f"killed {agent or did} ({len(affected)} DID(s) with recorded tokens)")


@app.command()
def revive(
    agent: Annotated[str | None, typer.Option(help="Agent name.")] = None,
    did: Annotated[str | None, typer.Option(help="Agent DID.")] = None,
    state_dir: StateDirOpt = None,
) -> None:
    """Lift a kill."""
    if (agent is None) == (did is None):
        raise typer.BadParameter("pass exactly one of --agent or --did")
    _guard_state(state_dir).revive(did=did, name=agent)
    typer.echo(f"revived {agent or did}")


@guards_app.command("reset")
def guards_reset(state_dir: StateDirOpt = None) -> None:
    """Revive every agent and clear budgets and taint in the running gateway."""
    _guard_state(state_dir).reset()
    typer.echo("guard state reset")
