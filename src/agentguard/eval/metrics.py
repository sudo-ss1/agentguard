"""Generic scanner metrics over labelled items, with Clopper-Pearson intervals.

An item is any string with a label (1 = positive, 0 = negative) and a group name. Each item is
placed into a tool result (placement.place_text), scanned, and scored:

- detected: the scanner tainted the agent or withheld the result
- reached: the placed string is still in what the agent would receive
- withheld: the result was withheld

For positives, detected is the detection rate and reached is how often the string got through
to the agent. For negatives, detected is the false-positive rate.
"""

from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from typing import Any

from agentguard.eval.placement import MODES, Mode, normalize, place_text, reaches_reader
from agentguard.eval.stats import clopper_pearson, fmt_rate


@dataclass(frozen=True)
class Item:
    text: str
    label: int  # 1 positive, 0 negative
    group: str

    def __post_init__(self) -> None:
        if self.label not in (0, 1):
            raise ValueError(f"label must be 0 or 1, not {self.label!r}")


@dataclass(frozen=True)
class Scored:
    item: Item
    mode: Mode
    detected: bool
    reached: bool
    withheld: bool


# A scan function takes a placed tool result and returns what the agent would receive, plus
# whether the scanner tainted and whether it withheld.
ScanFn = Callable[[str], tuple[str, bool, bool]]


def split_empty(items: Iterable[Item]) -> tuple[list[Item], dict[str, int]]:
    """Separate items whose text normalizes to nothing (only whitespace or invisible characters).

    reaches_reader counts such text as reached whatever the scanner does, so scoring them would
    distort the rates. They are left out and counted per group instead."""
    kept: list[Item] = []
    empty: dict[str, int] = {}
    for item in items:
        if normalize(item.text):
            kept.append(item)
        else:
            empty[item.group] = empty.get(item.group, 0) + 1
    return kept, empty


def score(items: Iterable[Item], mode: Mode, scan: ScanFn) -> list[Scored]:
    scored = []
    for item in items:
        delivered, tainted, withheld = scan(place_text(item.text, mode))
        reached = not withheld and reaches_reader(item.text, delivered)
        scored.append(Scored(item, mode, tainted or withheld, reached, withheld))
    return scored


RATE_FIELDS = ("detected", "reached", "withheld")


@dataclass(frozen=True)
class Row:
    group: str
    mode: Mode
    label: int
    n: int
    detected: int
    reached: int
    withheld: int

    def interval(self, field: str) -> tuple[float, float]:
        if field not in RATE_FIELDS:
            raise ValueError(f"no rate field {field!r}; expected one of {RATE_FIELDS}")
        return clopper_pearson(getattr(self, field), self.n)


def summarize(scored: Iterable[Scored]) -> list[Row]:
    """One row per (group, mode, label), ordered by group, then MODES order, then label."""
    buckets: dict[tuple[str, Mode, int], list[Scored]] = {}
    for s in scored:
        buckets.setdefault((s.item.group, s.mode, s.item.label), []).append(s)
    ordered = sorted(buckets.items(), key=lambda kv: (kv[0][0], MODES.index(kv[0][1]), kv[0][2]))
    return [
        Row(
            group,
            mode,
            label,
            len(xs),
            sum(x.detected for x in xs),
            sum(x.reached for x in xs),
            sum(x.withheld for x in xs),
        )
        for (group, mode, label), xs in ordered
    ]


def markdown(rows: list[Row]) -> str:
    lines = [
        "| Group | Placement | Label | n | Detected (tainted or withheld) | Reached the agent "
        "| Withheld |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in rows:
        label = "positive" if r.label == 1 else "negative"
        rates = " | ".join(fmt_rate(getattr(r, f), r.n) for f in RATE_FIELDS)
        lines.append(f"| {r.group} | {r.mode} | {label} | {r.n} | {rates} |")
    return "\n".join(lines)


def as_json(rows: list[Row]) -> list[dict[str, Any]]:
    out = []
    for r in rows:
        body: dict[str, Any] = asdict(r)
        for field in RATE_FIELDS:
            body[f"{field}_ci95"] = r.interval(field)
        out.append(body)
    return out
