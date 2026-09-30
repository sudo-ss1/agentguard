"""Run the lab without Docker: tool servers, the evil site and (guarded) the gateway as local
subprocesses. Used by the tests, the latency bench and `agentguard ... --local`.
"""

import os
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from agentguard import labfs
from agentguard.agent.scripted import Acting
from agentguard.guards.state import GuardState
from agentguard.identity.client import Credentials
from agentguard.identity.provision import provision

REPO_ROOT = labfs.SEED_ROOT.parents[1]
EVIL_SITE_DIR = REPO_ROOT / "lab" / "evil_site"
TOOL_SERVERS = ("files", "web", "email", "weather")
LOCAL_REFRESH_S = 0.2


@dataclass
class Lab:
    servers: dict[str, str]  # what the agent connects to: the tools, or just the gateway
    evil_site: str
    lab_root: Path
    outbox_path: Path
    rugpull_flag: Path
    receipts_path: Path | None = None
    agent_id: str = "research-bot"
    # Behind the gateway, give its refresh loop time to notice the rug pull.
    settle_s: float = 0.0
    # Guarded labs: every lab agent's credentials. Empty in baseline (no identity layer).
    credentials: dict[str, Credentials] = field(default_factory=dict)
    salts_path: Path | None = None  # the receipts' commitment salts (guarded labs)
    guard_state_dir: Path | None = None  # kill list and reset epoch (guarded labs)

    def identity_for(self, acting: Acting | None = None) -> str | Credentials:
        """What a toolbox presents for `acting` (the lab agent by default).

        Signing key: always the acting agent's own. Credential: the VC of whoever it claims to
        be. Token: the root token of whoever's token it uses. Without an identity layer, it is
        just the name the request asserts.
        """
        acting = acting or Acting(agent=self.agent_id)
        if not self.credentials:
            return acting.presented_agent_id
        own = self.credentials[acting.agent]
        claimed = self.credentials.get(acting.claims or acting.agent)
        token_of = self.credentials.get(acting.token or acting.agent)
        return Credentials(
            acting.agent,
            own.key,
            claimed.vc if claimed else None,
            token_of.token if token_of else None,
        )

    def reset(self) -> None:
        labfs.reset(self.lab_root)
        self.outbox_path.unlink(missing_ok=True)
        self.rugpull_flag.unlink(missing_ok=True)
        if self.guard_state_dir is not None:  # revive agents, clear budgets and taint
            GuardState(self.guard_state_dir).reset()

    def rug_pull(self) -> None:
        self.rugpull_flag.touch()
        time.sleep(self.settle_s)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, proc: subprocess.Popen, timeout: float = 20) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"process exited early: {proc.args!r}")
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise TimeoutError(f"port {port} did not open: {proc.args!r}")


def _provision_identities(
    lab: Lab, start: Callable[[list[str]], int], tmp: Path, procs: list[subprocess.Popen]
) -> dict[str, str]:
    """Run the identity service just long enough to register the lab's agents, then stop it.
    The gateway starts afterwards with only the public trust material, so every guarded run
    also shows the gateway works with the identity service down."""
    port = start(
        [
            "-m",
            "agentguard.identity",
            "--config",
            str(REPO_ROOT / "config" / "identity.yaml"),
            "--state-dir",
            str(tmp / "identity"),
            "--host",
            "127.0.0.1",
            "--port",
        ]
    )
    service = procs[-1]
    url = f"http://127.0.0.1:{port}"
    try:
        credentials, trust = provision(url, tmp / "keys")
    finally:
        service.terminate()
        service.wait(timeout=10)
        procs.remove(service)
    lab.credentials.update(credentials)
    return trust


@contextmanager
def local_lab(
    guarded: bool = False,
    log_dir: Path | None = None,
    gateway_overrides: dict | None = None,
    site_dir: Path = EVIL_SITE_DIR,
) -> Iterator[Lab]:
    """Start the lab. With `log_dir`, the gateway's decision log and pins are written there and
    kept after the lab stops; otherwise they live in the lab's temporary folder. `site_dir` is
    what the lab's web site serves (the evaluation serves its own generated pages)."""
    with tempfile.TemporaryDirectory(prefix="agentguard-lab-") as tmp_dir:
        tmp = Path(tmp_dir)
        logs = log_dir or tmp
        logs.mkdir(parents=True, exist_ok=True)
        lab = Lab({}, "", tmp / "rootfs", tmp / "outbox.jsonl", tmp / "rugpull.flag")
        lab.reset()
        env = {
            **os.environ,
            "LAB_ROOT": str(lab.lab_root),
            "OUTBOX_PATH": str(lab.outbox_path),
            "RUGPULL_FLAG": str(lab.rugpull_flag),
        }
        procs: list[subprocess.Popen] = []

        def start(args: list[str]) -> int:
            port = _free_port()
            proc = subprocess.Popen(
                [sys.executable, *args, str(port)],
                env=env,
                cwd=REPO_ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            procs.append(proc)
            _wait_for_port(port, proc)
            return port

        try:
            evil = start(["-m", "http.server", "--bind", "127.0.0.1", "--directory", str(site_dir)])
            lab.evil_site = f"http://127.0.0.1:{evil}"
            tools = {
                name: f"http://127.0.0.1:"
                f"{start(['-m', 'agentguard.tools', name, '--host', '127.0.0.1', '--port'])}/mcp"
                for name in TOOL_SERVERS
            }
            lab.servers = tools
            if guarded:
                identity = _provision_identities(lab, start, tmp, procs)
                lab.receipts_path = logs / "receipts.jsonl"
                lab.salts_path = logs / "receipt-salts.jsonl"
                lab.guard_state_dir = tmp / "guards"
                config = tmp / "gateway.yaml"
                gateway = yaml.safe_load((REPO_ROOT / "config" / "gateway.yaml").read_text())
                gateway.update(
                    upstreams=tools,
                    policy_dir=str(REPO_ROOT / "config" / "policies"),
                    pins_path=str(logs / "pins.json"),
                    receipts_path=str(lab.receipts_path),
                    salts_path=str(logs / "receipt-salts.jsonl"),
                    guards={
                        **gateway.get("guards", {}),
                        "state_dir": str(tmp / "guards"),
                        **(gateway_overrides.get("guards", {}) if gateway_overrides else {}),
                    },
                    refresh_interval_s=LOCAL_REFRESH_S,
                    identity=identity,
                )
                lab.settle_s = LOCAL_REFRESH_S * 3
                config.write_text(yaml.safe_dump(gateway))
                port = start(
                    [
                        "-m",
                        "agentguard.gateway",
                        "--config",
                        str(config),
                        "--host",
                        "127.0.0.1",
                        "--port",
                    ]
                )
                lab.servers = {"gateway": f"http://127.0.0.1:{port}/mcp"}
            yield lab
        finally:
            for proc in procs:
                proc.terminate()
            for proc in procs:
                proc.wait(timeout=10)
