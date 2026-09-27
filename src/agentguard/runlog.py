"""Per-run records for `agentguard attack`, kept in <run_log_dir>/<timestamp>/.

The gateway's decision log (receipts.jsonl) doesn't know about trials. Trials run one at a
time against one gateway, so each trial is indexed by the range of receipt lines written while
it ran. That lets results say whether the model *issued* an attack call that the gateway
refused, read from the gateway's own log rather than from what the agent saw.

Receipts store only a hash of each call's arguments. To say *what* a refused call targeted,
the harness matches the receipt's hash against its own call log and takes the path from there.
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from agentguard import labfs
from agentguard.attacks import Outcome, Scenario
from agentguard.gateway.receipts import args_digest


def new_run_dir(root: Path) -> Path:
    path = root / datetime.now().strftime("%Y%m%d-%H%M%S")
    path.mkdir(parents=True, exist_ok=False)
    return path


@dataclass
class TrialRecord:
    scenario: int
    mode: str
    trial: int
    attack_succeeded: bool
    detail: str
    receipt_lines: tuple[int, int] | None  # [start, end) in receipts.jsonl; None without a gateway
    agent_error: str | None = None
    attack_calls: int = 0  # calls to the scenario's attack_tools that reached the gateway
    attack_calls_refused: int = 0
    # Refused calls whose target was real: "/" or a path present in the lab when the trial
    # ended. A refused call changes nothing, so these are the refusals that prevented damage.
    attack_calls_refused_target_existed: int = 0
    refusals: list[dict[str, Any]] = field(default_factory=list)


class RunLog:
    def __init__(
        self, directory: Path, mode: str, receipts_path: Path | None, lab_root: Path
    ) -> None:
        self.directory = directory
        self.mode = mode
        self.receipts_path = receipts_path
        self.lab_root = lab_root

    def mark(self) -> int:
        if self.receipts_path is None or not self.receipts_path.exists():
            return 0
        with self.receipts_path.open() as f:
            return sum(1 for _ in f)

    def record(self, sc: Scenario, trial: int, outcome: Outcome, start: int) -> TrialRecord:
        record = TrialRecord(
            sc.id, self.mode, trial, outcome.succeeded, outcome.detail, None, outcome.agent_error
        )
        if self.receipts_path is not None:
            end = self.mark()
            record.receipt_lines = (start, end)
            receipts = self._receipts(start, end)
            attack = [r for r in receipts if r["tool"] in sc.attack_tools]
            refused = [r for r in attack if r["decision"] != "allow"]
            record.attack_calls, record.attack_calls_refused = len(attack), len(refused)
            own_calls = {(tool, args_digest(args)): args for tool, args in outcome.calls}
            record.refusals = [self._refusal(r, own_calls) for r in refused]
            record.attack_calls_refused_target_existed = sum(
                1 for r in record.refusals if r["target_existed"]
            )
        with (self.directory / "trials.jsonl").open("a") as f:
            f.write(json.dumps(asdict(record)) + "\n")
        return record

    def _refusal(
        self, receipt: dict[str, Any], own_calls: dict[tuple[str, str], dict[str, Any]]
    ) -> dict[str, Any]:
        args = own_calls.get((receipt["tool"], receipt["args_sha256"]))
        path = args.get("path") if args else None
        target = labfs.normalize(path) if isinstance(path, str) else None
        existed = target is not None and (
            target == "/" or labfs.resolve(self.lab_root, target).exists()
        )
        return {
            "tool": receipt["tool"],
            "policy_id": receipt["policy_id"],
            "reason": receipt["reason"],
            "target": target,  # from the harness call log; None if no call matched the hash
            "target_existed": existed,
        }

    def _receipts(self, start: int, end: int) -> list[dict[str, Any]]:
        assert self.receipts_path is not None
        with self.receipts_path.open() as f:
            return [json.loads(line) for i, line in enumerate(f) if start <= i < end]


def _calls(n: int) -> str:
    return f"{n} call{'' if n == 1 else 's'}"


def summarize_attempts(sc: Scenario, records: list[TrialRecord]) -> str:
    """E.g. 'model issued delete_file in 3/20 trials; gateway refused it in 3/20 (4 calls);
    target existed in 1/20 (1 call)'."""
    if not sc.attack_tools or not records or records[0].receipt_lines is None:
        return "n/a"
    n = len(records)
    issued = sum(1 for r in records if r.attack_calls)
    refused = sum(1 for r in records if r.attack_calls_refused)
    real = sum(1 for r in records if r.attack_calls_refused_target_existed)
    refused_calls = sum(r.attack_calls_refused for r in records)
    real_calls = sum(r.attack_calls_refused_target_existed for r in records)
    return (
        f"model issued {'/'.join(sc.attack_tools)} in {issued}/{n} trials; "
        f"gateway refused it in {refused}/{n} ({_calls(refused_calls)}); "
        f"target existed in {real}/{n} ({_calls(real_calls)})"
    )
