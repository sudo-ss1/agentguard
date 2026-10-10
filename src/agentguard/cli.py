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

from agentguard import CURRENT_PHASE
from agentguard.attacks import Scenario, load_all, missing_scenarios, run_llm, run_scripted
from agentguard.config import load_config
from agentguard.identity.client import load_credentials, wait_for
from agentguard.identity.provision import provision as run_provision
from agentguard.lab_stack import Lab, local_lab
from agentguard.ledger.keys import PUBLIC_KEY_FILE, load_public
from agentguard.runlog import (
    RunLog,
    TrialRecord,
    new_run_dir,
    scripted_verdict,
    summarize_attempts,
)
from agentguard.settings import get_settings

app = typer.Typer(no_args_is_help=True)
guards_app = typer.Typer(no_args_is_help=True, help="Gateway runtime guards (Phase 4).")
app.add_typer(guards_app, name="guards")
approvals_app = typer.Typer(no_args_is_help=True, help="Answer the gateway's approval requests.")
app.add_typer(approvals_app, name="approvals")
receipts_app = typer.Typer(
    no_args_is_help=True, help="Prove or erase values committed in receipts."
)
app.add_typer(receipts_app, name="receipts")
eval_app = typer.Typer(no_args_is_help=True, help="Evaluate the result scanner and the agent.")
app.add_typer(eval_app, name="eval")
ledger_app = typer.Typer(no_args_is_help=True, help="Verify the signed audit ledger (Phase 5).")
app.add_typer(ledger_app, name="ledger")


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
        lab.pins_path = s.pins_path
        # Pin the ledger's public key now, at setup, as a verifier would be given it.
        public_key_file = s.ledger_roots_dir / PUBLIC_KEY_FILE
        if public_key_file.exists():
            lab.ledger_roots_dir = s.ledger_roots_dir
            lab.ledger_public_key = load_public(public_key_file)
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
    expect_phase: Annotated[
        int | None,
        typer.Option(
            help="Fail unless every scenario available at this phase runs (default: "
            "this code's phase; Docker runs pass the host's)."
        ),
    ] = None,
) -> None:
    """Run attack scenarios and print a markdown results table.

    With --local, the run's gateway decision log, a per-trial index (trials.jsonl) and the
    table (results.md) are kept in <RUN_LOG_DIR>/<timestamp>/. Exits 1 if any scenario the run
    must cover can't run or produced no result.
    """
    s = get_settings()
    available = load_all()
    problems = missing_scenarios(available, scenario, expect_phase or CURRENT_PHASE)
    if problems:
        for problem in problems:
            typer.echo(f"attack run incomplete: {problem}", err=True)
        raise typer.Exit(1)
    scenarios = [x for x in available if x.runnable and (not scenario or x.id in scenario)]
    must = (
        set(scenario)
        if scenario
        else {x.id for x in available if x.available_from_phase <= (expect_phase or CURRENT_PHASE)}
    )
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
            start = runlog.mark() if runlog else 0
            scripted = await run_scripted(sc, lab)
            classes = runlog.classes_between(start, runlog.mark()) if runlog else None
            typer.echo(f"#{sc.id} scripted: {scripted.detail}", err=True)
            rows.append(
                [
                    str(sc.id),
                    sc.name,
                    sc.owasp,
                    scripted_verdict(scripted.succeeded, classes, sc.control == "detection"),
                ]
            )
            if llm:
                if not sc.task:
                    rows[-1] += ["n/a (scripted only)"] + (["n/a"] if guarded else [])
                    continue
                records = await _llm_trials(sc, lab, model, system_prompt or "", trials, runlog)
                wins = sum(r.attack_succeeded for r in records)
                errors = sum(1 for r in records if r.agent_error)
                undecided = sum(1 for r in records if r.approval_undecided)
                notes = [f"{errors} ended in agent error"] if errors else []
                if undecided:
                    notes.append(f"{undecided} hit an approval timeout/error")
                rows[-1].append(f"{wins}/{trials}" + (f" ({'; '.join(notes)})" if notes else ""))
                if guarded:
                    rows[-1].append(summarize_attempts(sc, records))
        return rows

    with open_lab(local, log_dir=run_dir) as lab:
        rows = asyncio.run(go(lab))
    not_run = sorted(must - {int(row[0]) for row in rows})
    if not_run:
        typer.echo(f"attack run incomplete: no result for scenario(s) {not_run}", err=True)
        raise typer.Exit(1)
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


def _approvals_dir(state_dir: Path | None) -> Path:
    return (state_dir or get_settings().guard_state_dir) / "approvals"


@approvals_app.command("list")
def approvals_list(state_dir: StateDirOpt = None) -> None:
    """Show pending requests, with the full arguments the approver is deciding on."""
    from agentguard.guards.approvals import list_pending

    pending = list_pending(_approvals_dir(state_dir))
    if not pending:
        typer.echo("no pending approvals")
    for r in pending:
        typer.echo(f"{r['id']}  {r['created']}  {r['agent']}  {r['tool']}  ({r['why']})")
        typer.echo(f"    arguments: {json.dumps(r['arguments'])[:500]}")


def _decide(request_id: str, approve: bool, approver: str, state_dir: Path | None) -> None:
    from agentguard.guards.approvals import decide

    if not decide(_approvals_dir(state_dir), request_id, approve, approver):
        typer.echo(f"no pending request {request_id} (already answered, timed out or voided)")
        raise typer.Exit(1)
    typer.echo(f"{'approved' if approve else 'denied'} {request_id} as {approver}")


@approvals_app.command("approve")
def approvals_approve(
    request_id: str,
    approver: Annotated[str, typer.Option(help="Who is approving (recorded in the receipt).")],
    state_dir: StateDirOpt = None,
) -> None:
    """Approve one pending call (exactly that call, once)."""
    _decide(request_id, True, approver, state_dir)


@approvals_app.command("deny")
def approvals_deny(
    request_id: str,
    approver: Annotated[str, typer.Option(help="Who is denying (recorded in the receipt).")],
    state_dir: StateDirOpt = None,
) -> None:
    """Deny one pending call."""
    _decide(request_id, False, approver, state_dir)


@eval_app.command("fetch")
def eval_fetch() -> None:
    """Fetch the pinned corpora into eval/data/ and check them against eval/corpora.lock.json."""
    from agentguard.eval import corpora

    for fetch in (corpora.fetch_deepset, corpora.fetch_garak):
        typer.echo(f"ok: {fetch()}")


@eval_app.command("scanner")
def eval_scanner(
    mode: Annotated[
        list[str] | None, typer.Option(help="Placement mode(s): raw, visible, hidden; default all.")
    ] = None,
    classifier: Annotated[bool, typer.Option(help="Enable the classifier.")] = False,
    out: Annotated[Path | None, typer.Option(help="Also write the rows as JSON here.")] = None,
) -> None:
    """Score the gateway's result scanner on the pinned corpora and print a markdown table.

    Detected means tainted or withheld: the detection rate for positives, the false-positive
    rate for negatives. Reached means the placed text is still in what the agent receives.
    """
    from agentguard.eval import metrics, sources
    from agentguard.eval.placement import MODES

    modes = mode or list(MODES)
    unknown = sorted(set(modes) - set(MODES))
    if unknown:
        raise typer.BadParameter(f"unknown mode(s): {', '.join(unknown)}")
    items, empty = metrics.split_empty(sources.labelled_items())
    scan = sources.gateway_scan(classifier=classifier)
    scored = [s for m in MODES if m in modes for s in metrics.score(items, m, scan)]
    rows = metrics.summarize(scored)
    typer.echo(metrics.markdown(rows))
    groups = sorted({i.group for i in items} | set(empty))
    typer.echo(
        "\nLeft out (text normalizes to nothing): "
        + ", ".join(f"{g} {empty.get(g, 0)}" for g in groups)
    )
    if out:
        body = {"classifier": classifier, "left_out_empty": empty, "rows": metrics.as_json(rows)}
        out.write_text(json.dumps(body))
        typer.echo(f"rows: {out}", err=True)


@eval_app.command("llm")
def eval_llm(
    n: Annotated[int, typer.Option(help="Cases per condition (the same cases in each).")] = 24,
    sample_seed: Annotated[int, typer.Option(help="Seed for choosing the cases.")] = 7,
    condition: Annotated[
        list[str] | None, typer.Option(help="Condition name(s); default all.")
    ] = None,
    model_digest: Annotated[
        str | None, typer.Option(help="Refuse to run unless the Ollama model has this digest.")
    ] = None,
    approval_timeout: Annotated[
        float, typer.Option(help="Seconds before an unanswered approval is denied.")
    ] = 10.0,
    trial_timeout: Annotated[
        float, typer.Option(help="Wall-clock limit per trial, in seconds; flagged if hit.")
    ] = 1200.0,
) -> None:
    """Run agent trials through a local guarded lab and print a markdown table.

    Each trial asks the agent to summarize one generated page and checks whether the case's
    target string is in its answer. Results go to <RUN_LOG_DIR>/<timestamp>/.
    """
    from agentguard.agent.llm import get_chat_model
    from agentguard.eval import sources, trials

    s = get_settings()
    known = {c.name: c for c in trials.CONDITIONS}
    unknown = sorted(set(condition or []) - set(known))
    if unknown:
        raise typer.BadParameter(
            f"unknown condition(s): {', '.join(unknown)}; known: {list(known)}"
        )
    conditions = [c for c in trials.CONDITIONS if not condition or c.name in condition]
    digest = None
    if s.llm_provider == "ollama":
        digest = trials.ollama_digest(s.ollama_base_url, s.ollama_model)
        if digest is None:
            raise typer.BadParameter(f"{s.ollama_model} is not on {s.ollama_base_url}")
        if model_digest and digest != model_digest:
            raise typer.BadParameter(f"{s.ollama_model} has digest {digest}, not {model_digest}")
    cases = trials.sample(sources.cases(), n, sample_seed)
    run_dir = new_run_dir(s.run_log_dir)
    settings = {
        "provider": s.llm_provider,
        "model": s.ollama_model if s.llm_provider == "ollama" else s.anthropic_model,
        "model_digest": digest,
        "temperature": 0,
        "seed": s.llm_seed,
        "num_ctx": s.llm_num_ctx,
        "n": n,
        "sample_seed": sample_seed,
        "cases": [c.index for c in cases],
        "conditions": [c.name for c in conditions],
        "approval_timeout_s": approval_timeout,
        "trial_timeout_s": trial_timeout,
    }
    (run_dir / "settings.json").write_text(json.dumps(settings, indent=2))
    typer.echo(f"run log: {run_dir}", err=True)

    done: list[trials.Trial] = []
    total = len(cases) * len(conditions)
    note = (
        f"\n\nApproval timeout during these trials: {approval_timeout:g} s "
        "(the gateway's default is 120 s)."
    )

    def write_results(final: bool) -> None:
        table = trials.trials_markdown(trials.summarize_trials(done, conditions)) + note
        if not final:
            table = f"Partial: {len(done)} of {total} trials done.\n\n" + table
        (run_dir / "results.md").write_text(table + "\n")

    def progress(t: "trials.Trial") -> None:
        done.append(t)
        write_results(final=False)
        notes = [
            x
            for x in (
                t.agent_error and ("timed out" if t.timed_out else "agent error"),
                t.approval_undecided and "approval timeout/error",
            )
            if x
        ]
        typer.echo(
            f"{t.condition} case {t.case}: target in answer {t.target_in_answer}, "
            f"in {len(t.target_calls)} tool call(s)" + (f" ({', '.join(notes)})" if notes else ""),
            err=True,
        )

    model = get_chat_model(s)
    system_prompt = load_config(s.agent_config_path).system_prompt
    asyncio.run(
        trials.run_conditions(
            cases,
            conditions,
            model,
            system_prompt,
            run_dir,
            approval_timeout,
            progress,
            trial_timeout,
        )
    )
    write_results(final=True)
    typer.echo((run_dir / "results.md").read_text())


@ledger_app.command("verify")
def ledger_verify(
    log: Annotated[Path, typer.Option(help="The ledger (receipts.jsonl).")],
    public_key: Annotated[
        str, typer.Option(help="The pinned public key: a did:key, or ledger-key.pub.json.")
    ],
    checkpoints: Annotated[
        Path | None, typer.Option(help="Signed checkpoints, from a copy the attacker can't reach.")
    ] = None,
    require_checkpoint: Annotated[
        bool, typer.Option(help="Fail if any receipt isn't covered by a verified checkpoint.")
    ] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Print the report as JSON.")] = False,
) -> None:
    """Replay the ledger and report the first broken link (exit 0 intact, 1 tampered, 2 bad
    input). Never needs the commitment salts."""
    from agentguard.ledger.keys import load_public
    from agentguard.ledger.verify import VerifyInputError, verify

    try:
        report = verify(log, load_public(public_key), checkpoints)
    except (VerifyInputError, ValueError, OSError) as exc:
        typer.echo(f"cannot verify: {exc}", err=True)
        raise typer.Exit(2) from exc
    typer.echo(json.dumps(report.as_dict(), indent=2) if as_json else report.text())
    raise typer.Exit(report.exit_code(require_checkpoint))


@ledger_app.command("pubkey")
def ledger_pubkey(
    key_dir: Annotated[Path, typer.Option(help="The gateway's ledger key directory.")],
) -> None:
    """Print the ledger's public key (a did:key) to pin for verifiers. Run where the key is,
    e.g. `docker compose exec gateway agentguard ledger pubkey --key-dir /ledger-key`."""
    from agentguard.identity.didkey import AgentKey
    from agentguard.ledger.keys import SIGNING_KEY_FILE

    typer.echo(AgentKey.load(key_dir / SIGNING_KEY_FILE).did)


# --- discovery (Phase 6) ------------------------------------------------------------------------

KeyFileOpt = Annotated[
    Path | None,
    typer.Option(help="Fingerprint key (default: $XDG_STATE_HOME/agentguard/scanner.key)."),
]


@app.command()
def scan(
    paths: Annotated[list[Path] | None, typer.Argument(help="Repos or folders to scan.")] = None,
    machine: Annotated[
        bool, typer.Option(help="Also read this user's MCP client configs (incl. WSL's /mnt/c).")
    ] = False,
    history: Annotated[
        bool, typer.Option(help="Also scan every commit of each git repo (read with dulwich).")
    ] = False,
    agents: Annotated[
        Path | None, typer.Option(help="Agent-to-source mapping, e.g. config/inventory.yaml.")
    ] = None,
    receipts: Annotated[
        Path | None, typer.Option(help="Ledger to read registered agents' last_seen from.")
    ] = None,
    allowlist: Annotated[
        Path | None, typer.Option(help="Your own gitleaks-format allowlist file.")
    ] = None,
    key_file: KeyFileOpt = None,
    out: Annotated[Path | None, typer.Option(help="Write the JSON here (default: stdout).")] = None,
) -> None:
    """Inventory agents, MCP servers, LLM SDKs and credentials. Read-only and offline.

    Credentials are reported as rule id, file, line and a keyed fingerprint, never the secret.
    Exit code: 0 complete and no credentials, 1 credentials found, 3 something wasn't scanned
    (listed in `not_scanned`), 2 bad input.
    """
    import hashlib
    from datetime import UTC, datetime

    from agentguard.discovery.fingerprint import ScannerKeyError, load_or_create_key
    from agentguard.discovery.inventory import Inventory, load_inventory_config
    from agentguard.discovery.mcp_configs import machine_config_paths
    from agentguard.guards.secrets import RULES_PATH, RULES_SHA256, SecretScanner

    if not paths and not machine and agents is None:
        raise typer.BadParameter("give PATHS, --machine or --agents")
    if hashlib.sha256(RULES_PATH.read_bytes()).hexdigest() != RULES_SHA256:
        typer.echo("the vendored gitleaks rules don't match their pinned hash", err=True)
        raise typer.Exit(2)
    try:
        key = load_or_create_key(key_file or get_settings().scanner_key_path)
    except ScannerKeyError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2) from None
    started = datetime.now(UTC).isoformat(timespec="seconds")
    config = load_inventory_config(agents) if agents else None
    inventory = Inventory(SecretScanner(extra_allowlists=allowlist), key, config)
    roots = list(paths or []) + [s for a in (config.agents if config else {}).values()
                                 for s in a.sources]  # fmt: skip
    seen: set[Path] = set()
    for root in roots:
        if root.resolve() not in seen:
            seen.add(root.resolve())
            inventory.scan_root(root)
            if history:
                inventory.scan_history(root)
    if machine:
        windows = Path("/mnt/c/Users")
        for path in machine_config_paths(Path.home(), windows if windows.is_dir() else None):
            inventory.scan_client_config(path)
    result = inventory.to_json(started, history=history, receipts=receipts)
    text = json.dumps(result, indent=2) + "\n"
    if out is None:
        typer.echo(text, nl=False)
    else:
        out.write_text(text)
    found = sum(len(a["credentials"]) for a in result["agents"])
    typer.echo(
        f"{len(result['agents'])} agent(s), {found} credential finding(s), "
        f"{len(result['not_scanned'])} path(s) not scanned",
        err=True,
    )
    if found:
        raise typer.Exit(1)
    if result["not_scanned"]:
        raise typer.Exit(3)


@app.command()
def fingerprint(key_file: KeyFileOpt = None) -> None:
    """Print the scanner fingerprint of a suspected secret, read from stdin (never an
    argument, which would land in shell history and the process list)."""
    import getpass

    from agentguard.discovery.fingerprint import load_or_create_key, secret_fingerprint

    secret = getpass.getpass("secret: ") if sys.stdin.isatty() else sys.stdin.read()
    secret = secret.rstrip("\r\n")
    if not secret:
        raise typer.BadParameter("no secret on stdin")
    typer.echo(
        secret_fingerprint(load_or_create_key(key_file or get_settings().scanner_key_path), secret)
    )


@app.command()
def risk(
    inventory: Annotated[Path, typer.Option(help="An inventory from `agentguard scan`.")],
    risk_config: Annotated[Path, typer.Option(help="Weights and tool tiers.")] = Path(
        "config/risk.yaml"
    ),
    gateway_config: Annotated[
        Path | None, typer.Option(help="The gateway's config: approvals and policy dir.")
    ] = None,
    policy_dir: Annotated[
        Path | None, typer.Option(help="Cedar policies (default: the gateway config's).")
    ] = None,
    pins: Annotated[Path | None, typer.Option(help="The gateway's pins.json.")] = None,
    receipts: Annotated[Path | None, typer.Option(help="The ledger (receipts.jsonl).")] = None,
    public_key: Annotated[
        str | None, typer.Option(help="The ledger's pinned public key, to verify it first.")
    ] = None,
    checkpoints: Annotated[Path | None, typer.Option(help="The ledger's checkpoints.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print JSON.")] = False,
) -> None:
    """Score each agent 0-100, with the breakdown behind every score. Read-only.

    Any input not given (or not readable) counts as worst case and is marked unknown.
    """
    from agentguard.gateway.checks import CallContext
    from agentguard.guards.approvals import ApprovalConfig
    from agentguard.ledger.keys import load_public
    from agentguard.ledger.read import calls
    from agentguard.ledger.verify import VerifyInputError, verify
    from agentguard.policy.cedar import CedarCheck
    from agentguard.risk import GatewayView, Ledger, assess, load_risk_config, text_report

    config = load_risk_config(risk_config)
    view = GatewayView()
    if gateway_config is not None:
        raw = yaml.safe_load(gateway_config.read_text()) or {}
        approvals = ApprovalConfig.model_validate((raw.get("guards") or {}).get("approvals") or {})
        view.needs_approval = approvals.always
        policy_dir = policy_dir or Path(raw.get("policy_dir", "config/policies"))
    if policy_dir is not None and policy_dir.is_dir():
        cedar = CedarCheck(policy_dir)

        def probe(agent: str, tool: str, path: str) -> bool:
            try:
                return cedar.evaluate(CallContext(agent, tool, None, {"path": path})).allowed
            except Exception:  # fail closed: an error counts as permitted, the riskier answer
                return True

        view.probe = probe
    if pins is not None and pins.is_file():
        view.pins = json.loads(pins.read_text())
    ledger = None
    if receipts is not None:
        if public_key is None:
            ledger = Ledger(False, "no public key pinned to verify it")
        else:
            try:
                report = verify(receipts, load_public(public_key), checkpoints)
            except (VerifyInputError, ValueError, OSError) as exc:
                ledger = Ledger(False, f"cannot verify ({type(exc).__name__})")
            else:
                first = report.first_broken
                detail = "intact" if first is None else f"{first.check} at line {first.line}"
                ledger = Ledger(report.intact, detail, calls(receipts) if report.intact else [])
    results = assess(json.loads(inventory.read_text()), config, view, ledger)
    if as_json:
        typer.echo(json.dumps([r.as_dict(config) for r in results], indent=2))
    else:
        typer.echo(text_report(results, config))
