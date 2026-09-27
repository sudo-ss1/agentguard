"""Per-call tool latency, direct to the tool servers (Phase 1) or via the gateway (Phase 2+).

uv run python bench/latency.py --out bench/baseline.json
"""

import argparse
import asyncio
import json
import statistics
import time
from pathlib import Path

from agentguard.agent.toolbox import Toolbox
from agentguard.lab_stack import Lab, local_lab

CALLS = {
    "read_file": {"path": "/workspace/notes.txt"},
    "list_dir": {"path": "/workspace"},
    "fetch_url": {"url": "{evil_site}/index.html"},
    "send_email": {"to": "bench@lab.test", "subject": "bench", "body": "x"},
}


async def measure(lab: Lab, n: int) -> dict[str, dict[str, float]]:
    report = {}
    evil_site = lab.evil_site
    async with Toolbox(lab.servers, lab.agent_id) as toolbox:
        for tool, args in CALLS.items():
            args = {k: v.format(evil_site=evil_site) for k, v in args.items()}
            await toolbox.call(tool, args)  # warm up
            samples = []
            for _ in range(n):
                start = time.perf_counter()
                result = await toolbox.call(tool, args)
                samples.append((time.perf_counter() - start) * 1000)
                assert not result.is_error, result.text
            q = statistics.quantiles(samples, n=100)
            report[tool] = {"p50_ms": round(q[49], 2), "p95_ms": round(q[94], 2), "n": n}
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", type=int, default=200)
    parser.add_argument("--guarded", action="store_true", help="Measure through the gateway.")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--compare", type=Path, help="A direct-mode report to diff against.")
    args = parser.parse_args()
    with local_lab(guarded=args.guarded) as lab:
        report = asyncio.run(measure(lab, args.n))
    text = json.dumps({"mode": "gateway" if args.guarded else "direct", "tools": report}, indent=2)
    print(text)
    if args.out:
        args.out.write_text(text + "\n")
    if args.compare:
        base = json.loads(args.compare.read_text())["tools"]
        for tool, stats in report.items():
            added = {q: round(stats[q] - base[tool][q], 2) for q in ("p50_ms", "p95_ms")}
            print(f"{tool:12} added p50 {added['p50_ms']:+.2f} ms, p95 {added['p95_ms']:+.2f} ms")


if __name__ == "__main__":
    main()
