"""The inventory (AI bill of materials): agents, and what was found for each.

Agents are either registered (in the identity config, so they have a credential and go through
the gateway) or `shadow`: anything agent-related found outside a registered agent's sources.

- `config/inventory.yaml` maps registered agents to their source paths. A file under one of
  those paths belongs to that agent.
- Any other scanned root that holds a credential, an MCP server or an LLM SDK import becomes
  a shadow agent named `repo:<folder>`. An MCP client config from `--machine` becomes one
  named after its client (`claude-desktop`, `cursor`, `vscode`).

Owners: a registered agent's sponsor, otherwise the OS owner of its folder or config file.
`last_seen`: a registered agent's newest ledger receipt (unverified: the risk engine verifies
the ledger before using it), otherwise the newest modification time among its files.
"""

import os
import pwd
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path, PurePath
from typing import Any

import yaml
from pydantic import BaseModel

from agentguard.discovery.files import NotScanned, TextFile, describe, read_text, walk
from agentguard.discovery.fingerprint import secret_fingerprint
from agentguard.discovery.mcp_configs import UnparsedConfig, client_of, servers_in, summarize
from agentguard.discovery.sdks import models_in, sdks_in
from agentguard.guards.secrets import GITLEAKS_VERSION, RULES_SHA256, SecretScanner
from agentguard.identity.service import load_identity_config
from agentguard.ledger.read import calls


class AgentSources(BaseModel):
    sources: list[Path] = []


class InventoryConfig(BaseModel):
    identity_config: Path | None = None
    gateway_config: Path | None = None
    agents: dict[str, AgentSources] = {}


def load_inventory_config(path: Path) -> InventoryConfig:
    return InventoryConfig.model_validate(yaml.safe_load(path.read_text()) or {})


@dataclass
class _Agent:
    name: str
    kind: str  # registered | shadow
    owner: str | None = None
    tools: list[str] = field(default_factory=list)
    models: set[str] = field(default_factory=set)
    sdks: set[str] = field(default_factory=set)
    servers: list[dict[str, Any]] = field(default_factory=list)
    credentials: list[dict[str, Any]] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)
    newest_mtime: float | None = None

    def saw(self, mtime: float) -> None:
        self.newest_mtime = max(self.newest_mtime or mtime, mtime)

    @property
    def has_signal(self) -> bool:
        return bool(self.kind == "registered" or self.credentials or self.servers or self.sdks)


def _user(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat(timespec="seconds")


class Inventory:
    def __init__(
        self, scanner: SecretScanner, key: bytes, config: InventoryConfig | None = None
    ) -> None:
        self.scanner, self.key = scanner, key
        self.config = config or InventoryConfig()
        self.agents: dict[str, _Agent] = {}
        self.not_scanned: list[NotScanned] = []
        self.roots: list[str] = []
        self._sources: list[tuple[Path, str]] = []
        self._register()

    def _register(self) -> None:
        cfg = self.config
        allowed: dict[str, list[str]] | None = None
        if cfg.gateway_config is not None:  # the raw YAML: only the allowlists are needed
            raw = yaml.safe_load(cfg.gateway_config.read_text()) or {}
            allowed = {n: list(a.get("tools", [])) for n, a in (raw.get("agents") or {}).items()}
        if cfg.identity_config is not None:
            for name, entry in load_identity_config(cfg.identity_config).agents.items():
                tools = entry.tools
                if allowed is not None:  # what the credential grants and the gateway allows
                    tools = [t for t in tools if t in allowed.get(name, [])]
                self.agents[name] = _Agent(
                    name, "registered", entry.sponsor, sorted(tools), {entry.model}
                )
        for name, agent in cfg.agents.items():
            self.agents.setdefault(name, _Agent(name, "shadow"))
            for source in agent.sources:
                self._sources.append((source.resolve(), name))
        self._sources.sort(key=lambda s: len(s[0].parts), reverse=True)  # most specific first

    def _owner_of(self, path: Path, fallback: str) -> str:
        real = path.resolve()
        for source, name in self._sources:
            if real == source or source in real.parents:
                return name
        return fallback

    def _shadow(self, name: str, owner_uid: int) -> _Agent:
        if name not in self.agents:
            self.agents[name] = _Agent(name, "shadow", _user(owner_uid))
        return self.agents[name]

    # --- scanning ----------------------------------------------------------------------------

    def scan_root(self, root: Path) -> None:
        self.roots.append(str(root))
        try:
            root_uid = root.stat().st_uid
        except OSError as exc:
            self.not_scanned.append(NotScanned(str(root), describe(exc)))
            return
        real = root.resolve()
        default = f"repo:{real.name}"
        for item in walk(root):
            if isinstance(item, NotScanned):
                self.not_scanned.append(item)
                if item.rel is not None:  # path-only rules (e.g. a .p12 file) need no content
                    agent = self._shadow_or_mapped(Path(item.path), default, root_uid)
                    self._path_rule_findings(agent, item)
                continue
            agent = self._shadow_or_mapped(item.path, default, root_uid)
            agent.sources.add(str(root))
            self._scan_file(agent, item, str(item.path))

    def _shadow_or_mapped(self, path: Path, default: str, uid: int) -> _Agent:
        name = self._owner_of(path, default)
        return self.agents[name] if name in self.agents else self._shadow(name, uid)

    def _path_rule_findings(self, agent: _Agent, item: NotScanned) -> None:
        assert item.rel is not None
        for f in self.scanner.find("", item.rel):
            agent.credentials.append(
                {"rule_id": f.rule_id, "file": item.path, "line": None, "fingerprint": None}
            )

    def _scan_file(self, agent: _Agent, file: TextFile, display: str) -> None:
        try:
            findings = self.scanner.find(file.text, file.rel)
            servers: list[dict[str, Any]] = []
            client = client_of(PurePath(file.rel))
            if client is not None:
                servers = [
                    summarize(n, e, client[0], display, self.key, self.scanner)
                    for n, e in sorted(servers_in(file.text, client[1]).items())
                ]
            sdks = sdks_in(file.rel, file.text)
            models = models_in(file.rel, file.text, self.scanner)
        except UnparsedConfig as exc:
            self.not_scanned.append(NotScanned(display, f"unparsed MCP config ({exc})"))
            return
        except Exception as exc:  # fail closed: reported, never silently dropped
            self.not_scanned.append(NotScanned(display, describe(exc)))
            return
        for f in findings:
            agent.credentials.append(
                {
                    "rule_id": f.rule_id,
                    "file": display,
                    "line": file.text.count("\n", 0, f.start) + 1 if f.secret else None,
                    "fingerprint": secret_fingerprint(self.key, f.secret) if f.secret else None,
                }
            )
        agent.servers += servers
        agent.sdks |= sdks
        agent.models |= models
        agent.saw(file.mtime)

    def scan_client_config(self, path: Path) -> None:
        """A per-user MCP client config (`--machine`)."""
        client = client_of(path)
        if client is None:
            return
        try:
            text, st = read_text(path)
        except Exception as exc:
            self.not_scanned.append(NotScanned(str(path), describe(exc)))
            return
        agent = self._shadow_or_mapped(path, client[0], st.st_uid)
        agent.sources.add(str(path))
        self._scan_file(agent, TextFile(path, path.name, text, st.st_mtime, st.st_uid), str(path))

    # --- output ------------------------------------------------------------------------------

    def to_json(self, started: str, history: bool, receipts: Path | None = None) -> dict[str, Any]:
        last_call: dict[str, str] = {}
        for record in calls(receipts):
            agent, ts = record.get("agent"), record.get("ts")
            if isinstance(agent, str) and isinstance(ts, str):
                last_call[agent] = max(last_call.get(agent, ts), ts)
        agents = []
        for a in sorted(self.agents.values(), key=lambda a: a.name):
            if not a.has_signal:
                continue
            if a.kind == "registered":
                seen = {"at": last_call.get(a.name), "source": "ledger" if receipts else None}
            else:
                at = _iso(a.newest_mtime) if a.newest_mtime is not None else None
                seen = {"at": at, "source": "file-mtime"}
            agents.append(
                {
                    "agent": a.name,
                    "kind": a.kind,
                    "owner": a.owner,
                    "models": sorted(a.models),
                    "tools": a.tools,
                    "mcp_servers": sorted(a.servers, key=lambda s: (s["config"], s["name"] or "")),
                    "sdks": sorted(a.sdks),
                    "credentials": sorted(
                        a.credentials, key=lambda c: (c["file"], c["line"] or 0, c["rule_id"])
                    ),
                    "last_seen": seen,
                    "sources": sorted(a.sources),
                }
            )
        return {
            "scanner": {
                "version": version("agentguard"),
                "rules": f"gitleaks {GITLEAKS_VERSION}",
                "rules_sha256": RULES_SHA256,
                "started": started,
                "roots": self.roots,
                "history": history,
                "user": _user(os.getuid()),
            },
            "agents": agents,
            "not_scanned": [
                {"path": n.path, "reason": n.reason}
                for n in sorted(self.not_scanned, key=lambda n: n.path)
            ],
        }
