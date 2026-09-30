"""Replay a ledger and report exactly where it breaks.

Inputs: the ledger (receipts.jsonl), the pinned public key, and optionally the signed
checkpoints. Keys found inside the log are never trusted.

Checks, receipt by receipt:
- format: the line parses (no duplicate keys, exactly body/hash/sig) and canonicalizes
- version and ledger-id: the same format version and ledger throughout
- hash: the stored hash is SHA-256 of the canonical body (content changed after signing?)
- signature: the stored hash is signed by the pinned key
- seq: the next sequence number (a gap means receipts were deleted; a step back, reordering)
- prev: the receipt links to the hash of the one before it

Checks, checkpoint by checkpoint: signature, same ledger, chained to the previous checkpoint,
size within the log (larger means receipts were cut from the end), head hash and Merkle batch
root matching the receipts.

Warnings, not tampering:
- torn-tail: an incomplete last line (a crash mid-write; the gateway recovers it on restart)
- tail-unproven: receipts no verified checkpoint covers, so their deletion would go unnoticed
- outcome-unknown: an allowed decision with no outcome receipt (the gateway stopped, or an
  OS crash lost it, after the call was forwarded)

Salts are never needed: receipts hold commitment digests, and deleting a salt (`receipts
forget`) changes no receipt byte.
"""

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from agentguard.ledger import merkle
from agentguard.ledger.canonical import (
    CHECKPOINT_TAG,
    FORMAT_VERSION,
    GENESIS_PREV,
    RECEIPT_TAG,
    CanonicalError,
    LineError,
    body_hash,
    parse_line,
    signature_valid,
)
from agentguard.ledger.keys import did_for

EXPLAIN = {
    "format": "the line is not a well-formed ledger receipt",
    "version": "unexpected format version",
    "ledger-id": "the receipt belongs to a different ledger (spliced in?)",
    "hash": "the receipt's content was changed after it was signed",
    "signature": "the signature does not verify under the pinned key "
    "(forged or re-hashed receipt, or the wrong key)",
    "seq-gap": "receipts are missing before this one (deleted)",
    "seq-order": "receipts are out of order (reordered or duplicated)",
    "prev": "it does not link to the receipt before it "
    "(one before it was removed, replaced or moved)",
}


class VerifyInputError(ValueError):
    """The input isn't a signed ledger at all (or can't be read)."""


@dataclass
class Finding:
    check: str  # a key of EXPLAIN, or a checkpoint-* / warning check
    detail: str
    line: int | None = None
    seq: int | None = None
    checks: list[str] = field(default_factory=list)  # every check that failed on this line


@dataclass
class Report:
    log: str
    public_key: str
    receipts: int = 0
    checkpoints: int = 0
    verified_checkpoints: int = 0
    proven_size: int = 0  # receipts covered by a verified checkpoint
    tampering: list[Finding] = field(default_factory=list)
    warnings: list[Finding] = field(default_factory=list)
    outcome_unknown: list[int] = field(default_factory=list)  # seqs of those decisions
    last_good_seq: int | None = None  # last receipt before the first broken link

    @property
    def intact(self) -> bool:
        return not self.tampering

    @property
    def first_broken(self) -> Finding | None:
        with_line = [f for f in self.tampering if f.line is not None]
        return with_line[0] if with_line else (self.tampering[0] if self.tampering else None)

    def exit_code(self, require_checkpoint: bool = False) -> int:
        if not self.intact:
            return 1
        if require_checkpoint and any(w.check == "tail-unproven" for w in self.warnings):
            return 1
        return 0

    def as_dict(self) -> dict[str, Any]:
        body = asdict(self)
        body["intact"] = self.intact
        body["first_broken"] = asdict(self.first_broken) if self.first_broken else None
        return body

    def text(self) -> str:
        out = [
            f"ledger: {self.log}",
            f"receipts: {self.receipts}, pinned key {self.public_key}",
            f"checkpoints: {self.verified_checkpoints} of {self.checkpoints} verified, "
            f"covering {self.proven_size} receipt(s)",
        ]
        first = self.first_broken
        if first:
            where = f"line {first.line} (seq {first.seq})" if first.line else "checkpoints"
            out.append(f"FIRST BROKEN LINK: {where}: {first.check}: {first.detail}")
            if first.line is not None:
                good = "none" if self.last_good_seq is None else f"seq {self.last_good_seq}"
                out.append(f"  last good receipt before it: {good}")
            for f in self.tampering:
                if f is not first:
                    where = f"line {f.line} (seq {f.seq})" if f.line else "checkpoints"
                    out.append(f"  also: {where}: {f.check}: {f.detail}")
        for w in self.warnings:
            where = f"line {w.line}: " if w.line else ""
            out.append(f"warning: {where}{w.check}: {w.detail}")
        if self.outcome_unknown:
            shown = ", ".join(map(str, self.outcome_unknown[:10]))
            more = "…" if len(self.outcome_unknown) > 10 else ""
            out.append(
                f"outcome unknown: {len(self.outcome_unknown)} allowed call(s) with no outcome "
                f"receipt (decision seq {shown}{more})"
            )
        out.append("result: " + ("INTACT" if self.intact else "TAMPERED"))
        return "\n".join(out)


def _describe(checks: list[str]) -> tuple[str, str]:
    order = ["format", "ledger-id", "version", "hash", "signature", "seq-gap", "seq-order", "prev"]
    main = next(c for c in order if c in checks)
    return main, EXPLAIN[main]


def verify(log: Path, public_key: bytes, checkpoints: Path | None = None) -> Report:
    if not log.exists():
        raise VerifyInputError(f"{log} does not exist")
    report = Report(str(log), did_for(public_key))
    data = log.read_bytes()
    cut = data.rfind(b"\n") + 1
    if cut < len(data):
        report.warnings.append(
            Finding(
                "torn-tail",
                f"the last {len(data) - cut} byte(s) are an incomplete line (a crash mid-write?)",
                line=data[:cut].count(b"\n") + 1,
            )
        )
    lines = data[:cut].splitlines()
    if not lines:
        raise VerifyInputError(f"{log} has no receipts")

    stored: list[str | None] = []  # the stored hash on each line, for checkpoints
    seqs: list[int | None] = []
    findings: dict[int, Finding] = {}
    expected_seq, expected_prev = 0, GENESIS_PREV
    ledger_id: str | None = None
    parsed_any = False
    signature_failures = 0
    allowed: dict[int, int] = {}  # decision seq -> line
    completed: set[int] = set()
    genesis_key: str | None = None

    for number, raw in enumerate(lines, 1):
        checks: list[str] = []
        detail: list[str] = []
        try:
            entry = parse_line(raw)
            recomputed = body_hash(entry["body"])
        except (LineError, CanonicalError) as exc:
            findings[number] = Finding("format", str(exc), number, None, ["format"])
            stored.append(None)
            seqs.append(None)
            expected_seq += 1
            expected_prev = None  # type: ignore[assignment]  # unknown: can't check the next link
            continue
        parsed_any = True
        body = entry["body"]
        seq = body.get("seq")
        seq = seq if isinstance(seq, int) and not isinstance(seq, bool) else None
        stored.append(entry["hash"])
        seqs.append(seq)
        if number == 1 and body.get("kind") == "genesis":
            genesis_key = body.get("key")
        if body.get("v") != FORMAT_VERSION:
            checks.append("version")
        if ledger_id is None:
            ledger_id = body.get("ledger_id")
        elif body.get("ledger_id") != ledger_id:
            checks.append("ledger-id")
        if recomputed != entry["hash"]:
            checks.append("hash")
            detail.append(
                f"stored hash {entry['hash'][:16]}…, content hashes to {recomputed[:16]}…"
            )
        if not signature_valid(public_key, RECEIPT_TAG, entry["hash"], entry["sig"]):
            checks.append("signature")
            signature_failures += 1
        if seq is None or seq != expected_seq:
            checks.append("seq-gap" if seq is not None and seq > expected_seq else "seq-order")
            detail.append(f"seq {seq}, expected {expected_seq}")
        if expected_prev is not None and body.get("prev") != expected_prev:
            checks.append("prev")
            detail.append(
                f"prev {str(body.get('prev'))[:16]}…, the receipt before it hashes to "
                f"{expected_prev[:16]}…"
            )
        if checks:
            findings[number] = Finding(checks[0], "; ".join(detail), number, seq, checks)
        else:
            if body.get("kind") == "decision" and body.get("decision") == "allow":
                allowed[seq] = number  # type: ignore[index]
            if body.get("kind") == "outcome" and isinstance(body.get("decision_seq"), int):
                completed.add(body["decision_seq"])
        # Resynchronize on this receipt, so each independent problem is reported once.
        expected_seq = (seq if seq is not None else expected_seq) + 1
        expected_prev = entry["hash"]

    if not parsed_any:
        raise VerifyInputError(
            f"{log} is not a signed ledger: no line has body, hash and sig "
            "(a Phase 4 unsigned log?)"
        )
    report.receipts = len(lines)

    # Name each broken line's problem. A gap whose "missing" seqs appear later in the file is
    # reordering, not deletion.
    last_line_of: dict[int, int] = {}
    for number, seq in enumerate(seqs, 1):
        if seq is not None:
            last_line_of[seq] = number
    for number, f in sorted(findings.items()):
        if "seq-gap" in f.checks and f.seq is not None:
            prior = next((s for s in reversed(seqs[: number - 1]) if s is not None), None)
            missing = range(0 if prior is None else prior + 1, f.seq)
            if all(last_line_of.get(m, 0) > number for m in missing):
                f.checks[f.checks.index("seq-gap")] = "seq-order"
            else:
                span = (
                    f"seq {missing[0]}" if len(missing) == 1 else f"seq {missing[0]}–{missing[-1]}"
                )
                f.detail = f"{span} missing; {f.detail}"
        f.check, explanation = _describe(f.checks)
        f.detail = explanation + (f" ({f.detail})" if f.detail else "")
    report.tampering = [findings[n] for n in sorted(findings)]
    if (
        signature_failures == len(lines) - sum(1 for s in stored if s is None)
        and signature_failures
    ):
        hint = "no receipt's signature verifies under the pinned key: wrong public key?"
        if genesis_key and genesis_key != report.public_key:
            hint += f" The log's genesis receipt names {genesis_key}."
        report.warnings.insert(0, Finding("wrong-key", hint))
    if report.tampering and report.tampering[0].line:
        first_line = report.tampering[0].line
        good = [s for s in seqs[: first_line - 1] if s is not None]
        report.last_good_seq = good[-1] if good else None
    else:
        good = [s for s in seqs if s is not None]
        report.last_good_seq = good[-1] if good else None

    report.outcome_unknown = sorted(s for s in allowed if s not in completed)
    _verify_checkpoints(report, public_key, checkpoints, ledger_id, stored)
    return report


def _verify_checkpoints(
    report: Report,
    public_key: bytes,
    path: Path | None,
    ledger_id: str | None,
    stored: list[str | None],
) -> None:
    n = len(stored)
    if path is None or not path.exists():
        report.warnings.append(
            Finding(
                "tail-unproven",
                "no checkpoints given: nothing proves receipts weren't deleted from the end",
            )
        )
        return
    data = path.read_bytes()
    lines = data[: data.rfind(b"\n") + 1].splitlines()
    report.checkpoints = len(lines)
    prev_hash, prev_size = GENESIS_PREV, 0
    cut_from: tuple[int, int] | None = None  # (checkpoint number, its size), largest
    for number, raw in enumerate(lines, 1):
        name = f"checkpoint {number}"
        try:
            entry = parse_line(raw)
            recomputed = body_hash(entry["body"])
        except (LineError, CanonicalError) as exc:
            report.tampering.append(Finding("checkpoint-format", f"{name}: {exc}"))
            continue
        body = entry["body"]
        problems = []
        if recomputed != entry["hash"] or not signature_valid(
            public_key, CHECKPOINT_TAG, entry["hash"], entry["sig"]
        ):
            problems.append(("checkpoint-signature", "does not verify under the pinned key"))
        if body.get("ledger_id") != ledger_id:
            problems.append(("checkpoint-ledger-id", "belongs to a different ledger"))
        if body.get("prev_checkpoint") != prev_hash or body.get("start") != prev_size:
            problems.append(("checkpoint-chain", "does not follow the checkpoint before it"))
        size = body.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size < 1:
            problems.append(("checkpoint-format", "has no valid size"))
            size = None
        elif size > n:
            if cut_from is None or size > cut_from[1]:
                cut_from = (number, size)
        elif stored[size - 1] != body.get("head"):
            problems.append(
                ("checkpoint-head", f"its head is not the hash of receipt {size - 1} (line {size})")
            )
        else:
            start = body.get("start") if isinstance(body.get("start"), int) else 0
            batch = stored[start:size]
            if None in batch or merkle.root_hex(batch) != body.get("batch_root"):  # type: ignore[arg-type]
                problems.append(
                    (
                        "checkpoint-root",
                        f"its Merkle root doesn't match receipts {start}–{size - 1}",
                    )
                )
        for check, detail in problems:
            report.tampering.append(Finding(check, f"{name} {detail}"))
        if not problems and size is not None and size <= n:
            report.verified_checkpoints += 1
            report.proven_size = max(report.proven_size, size)
        prev_hash, prev_size = entry["hash"], (size or prev_size)
    if cut_from is not None:
        number, size = cut_from
        report.tampering.append(
            Finding(
                "tail-missing",
                f"checkpoint {number} covers {size} receipts but the log has {n}: "
                f"seq {n}–{size - 1} were deleted from the end",
            )
        )
    if report.proven_size < n:
        report.warnings.append(
            Finding(
                "tail-unproven",
                f"seq {report.proven_size}–{n - 1} are not covered by a verified checkpoint: "
                "their deletion would go unnoticed",
            )
        )
