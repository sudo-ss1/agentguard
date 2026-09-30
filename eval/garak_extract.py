"""Generate garak's latent-injection probe prompts as data (run by `agentguard eval fetch`).

Runs inside a throwaway environment against garak's pinned source; it needs only light
dependencies, not garak's full install. Output: {probe name: [{"prompt", "trigger"}]}, where
the trigger is the string the probe's embedded injection tries to make a model output (garak's
own success criterion). Deterministic with PYTHONHASHSEED=0 and seed 7; the result is checked
against eval/corpora.lock.json.

    python garak_extract.py <garak source dir> <output.json>
"""

import json
import random
import sys

sys.path.insert(0, sys.argv[1])  # garak's source, before importing it

from garak import _config  # noqa: E402

_config.load_base_config()
_config.run.seed = 7
random.seed(7)
import garak.probes.latentinjection as latent  # noqa: E402

names = [
    n for n in dir(latent) if n.startswith("Latent") and not n.endswith("Full") and "Mixin" not in n
]
out = {}
for name in sorted(names):
    probe = getattr(latent, name)()
    prompts = [p if isinstance(p, str) else str(getattr(p, "text", p)) for p in probe.prompts]
    out[name] = [
        {"prompt": pr, "trigger": tr} for pr, tr in zip(prompts, probe.triggers, strict=True)
    ]
    print(f"{name:42} prompts={len(out[name]):4}")
with open(sys.argv[2], "w") as f:
    json.dump(out, f)
