"""Discovery scanner (Phase 6): what it finds, what it never reveals, and that it only reads.

Every secret here is a canary made at test time, so nothing key-shaped is committed. The
scanner never reads this machine's real config locations: `--machine` is tested with a fake
home folder.
"""

import builtins
import io
import json
import os
import secrets
import socket
import stat
import string
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentguard.cli import app
from agentguard.discovery import files as files_mod
from agentguard.discovery import inventory as inventory_mod
from agentguard.discovery.fingerprint import (
    ScannerKeyError,
    load_or_create_key,
    secret_fingerprint,
)
from agentguard.discovery.inventory import Inventory, InventoryConfig
from agentguard.discovery.mcp_configs import (
    machine_config_paths,
    package_of,
    strip_jsonc,
)
from agentguard.guards.secrets import SecretFinding, SecretScanner

runner = CliRunner()
URLSAFE = string.ascii_letters + string.digits + "_-"
ALNUM = string.ascii_letters + string.digits


def anthropic_canary() -> str:
    """Shaped like an Anthropic API key (gitleaks `anthropic-api-key`), marked as a canary."""
    body = "AGENTGUARDCANARY" + "".join(secrets.choice(URLSAFE) for _ in range(93 - 16))
    return f"sk-ant-api03-{body}AA"


def github_canary() -> str:
    return "ghp_" + "".join(secrets.choice(ALNUM) for _ in range(36))


def pieces(secret: str, n: int = 8) -> set[str]:
    return {secret[i : i + n] for i in range(len(secret) - n + 1)}


def assert_absent(canaries: list[str], *outputs: str) -> None:
    for canary in canaries:
        for output in outputs:
            leaked = [p for p in pieces(canary) if p in output]
            assert not leaked, f"{len(leaked)} piece(s) of a canary appear in the output"


@pytest.fixture(scope="module")
def scanner():
    return SecretScanner()


@pytest.fixture
def key(tmp_path):
    return load_or_create_key(tmp_path / "state" / "scanner.key")


@pytest.fixture
def repo(tmp_path):
    """A repo holding canaries in every shape the scanner must handle."""
    root = tmp_path / "repo"
    c = {name: anthropic_canary() for name in ("env", "settings", "vscode", "binary", "big")}
    c |= {name: github_canary() for name in ("mcp_env", "mcp_arg", "mcp_url", "mcp_header")}
    c["server_name"] = github_canary()
    c["outside"] = anthropic_canary()
    c["fifo"] = anthropic_canary()
    servers = {
        "github": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-github", f"--token={c['mcp_arg']}"],
            "env": {"GITHUB_TOKEN": c["mcp_env"]},
        },
        "files": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/tmp"],
        },
        "fetch": {
            "command": "uvx",
            "args": ["--from", "mcp-server-fetch==2025.4.7", "mcp-server-fetch"],
        },
        "box": {
            "command": "docker",
            "args": ["run", "-i", "--rm", "-e", "X", "ghcr.io/x/y@sha256:" + "a" * 64],
        },
        "remote": {
            "url": f"https://user:{c['mcp_url']}@mcp.example.test/sse?key={c['mcp_url']}",
            "headers": {"Authorization": f"Bearer {c['mcp_header']}"},
        },
        c["server_name"]: {"command": "node", "args": ["server.js"]},
    }
    files = {
        ".env": f"MODEL=claude-sonnet-5\nANTHROPIC_API_KEY={c['env']}\n",
        "app/settings.py": f'import anthropic\n\nAPI_KEY = "{c["settings"]}"\n',
        "package.json": json.dumps({"dependencies": {"@anthropic-ai/sdk": "^0.30.0"}}),
        ".cursor/mcp.json": json.dumps({"mcpServers": servers}),
        ".vscode/mcp.json": (
            "// VS Code allows comments\n"
            '{"servers": {"weather": {"command": "uvx", "args": ["weather-mcp"],\n'
            f'  /* inline */ "env": {{"KEY": "{c["vscode"]}"}},}}}}}}\n'
        ),
        ".mcp.json": '{"mcpServers": {"broken": ',  # unparsed
        ".gitleaks.toml": "[[allowlists]]\npaths = ['''.*''']\n",  # the repo's own: ignored
    }  # fmt: skip
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    (root / "blob.bin").write_bytes(b"\0\1" + c["binary"].encode())
    (root / "big.txt").write_text("x" * (files_mod.MAX_FILE_BYTES + 1) + c["big"])
    (root / "cert.p12").write_bytes(b"\0\x30\x82")
    os.mkfifo(root / "pipe")
    (tmp_path / "elsewhere.env").write_text(f"KEY={c['outside']}\n")
    (root / "link.env").symlink_to(tmp_path / "elsewhere.env")
    (root / "node_modules/pkg").mkdir(parents=True)
    (root / "node_modules/pkg/k.env").write_text(f"KEY={c['fifo']}\n")
    return root, c


def scan(root: Path, key: bytes, scanner: SecretScanner, config=None) -> dict:
    inv = Inventory(scanner, key, config)
    inv.scan_root(root)
    return inv.to_json("2026-10-09T00:00:00+00:00", history=False)


def the_agent(result: dict, name: str) -> dict:
    return next(a for a in result["agents"] if a["agent"] == name)


# --- what it finds ---------------------------------------------------------------------------


def test_credentials_are_listed_by_rule_file_line_and_fingerprint(repo, key, scanner):
    root, c = repo
    agent = the_agent(scan(root, key, scanner), "repo:repo")
    found = {(x["rule_id"], Path(x["file"]).relative_to(root).as_posix(), x["line"]): x
             for x in agent["credentials"]}  # fmt: skip
    assert ("anthropic-api-key", ".env", 2) in found
    assert ("anthropic-api-key", "app/settings.py", 3) in found
    assert ("anthropic-api-key", ".vscode/mcp.json", 3) in found
    assert ("github-pat", ".cursor/mcp.json", 1) in found
    assert ("pkcs12-file", "cert.p12", None) in found  # path-only rule, on a binary file
    fp = found[("anthropic-api-key", ".env", 2)]["fingerprint"]
    assert fp == secret_fingerprint(key, c["env"]) and len(fp) == 16
    assert set(found[("anthropic-api-key", ".env", 2)]) == {
        "rule_id",
        "file",
        "line",
        "fingerprint",
    }


def test_the_repos_own_gitleaks_allowlist_is_ignored_but_the_operators_applies(repo, key, tmp_path):
    root, _ = repo
    assert the_agent(scan(root, key, SecretScanner()), "repo:repo")["credentials"]
    mine = tmp_path / "allow.toml"
    mine.write_text("[[allowlists]]\npaths = ['''(^|/)\\.env$''']\n")
    agent = the_agent(scan(root, key, SecretScanner(extra_allowlists=mine)), "repo:repo")
    assert not [x for x in agent["credentials"] if x["file"].endswith("/.env")]
    assert [x for x in agent["credentials"] if x["file"].endswith("settings.py")]


def test_sdks_models_and_mcp_servers(repo, key, scanner):
    root, _ = repo
    agent = the_agent(scan(root, key, scanner), "repo:repo")
    assert agent["kind"] == "shadow" and agent["owner"]
    assert {"anthropic", "@anthropic-ai/sdk"} <= set(agent["sdks"])
    assert "claude-sonnet-5" in agent["models"]
    servers = {s["name"]: s for s in agent["mcp_servers"]}
    assert servers["github"]["package"] == "@modelcontextprotocol/server-github"
    assert servers["github"]["pinned"] is False
    assert servers["github"]["env"] == ["GITHUB_TOKEN"]
    assert servers["files"]["pinned"] is True
    assert servers["fetch"]["package"] == "mcp-server-fetch==2025.4.7"
    assert servers["fetch"]["pinned"] is True
    assert servers["box"]["pinned"] is True
    assert servers["remote"]["host"] == "mcp.example.test"
    assert servers["remote"]["pinned"] is False
    assert servers["remote"]["headers"] == ["Authorization"]
    assert servers["weather"]["client"] == "vscode"  # parsed from JSONC
    assert None in servers  # the server named with a token: name dropped, entry kept
    assert set(servers["github"]) == {
        "name", "client", "config", "transport", "command", "package", "pinned", "host", "env",
        "headers", "entry_fingerprint",
    }  # fmt: skip


def test_nothing_is_skipped_silently(repo, key, scanner):
    root, _ = repo
    reasons = {Path(n["path"]).name: n["reason"] for n in scan(root, key, scanner)["not_scanned"]}
    assert reasons["blob.bin"] == "binary"
    assert reasons["big.txt"].startswith("larger than")
    assert reasons["pipe"] == "not a regular file"
    assert reasons["link.env"] == "symlink to outside the scanned root"
    assert reasons["node_modules"] == "dependency or cache directory"
    assert reasons[".mcp.json"] == "unparsed MCP config (not valid JSON)"


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any file")
def test_an_unreadable_file_is_reported(tmp_path, key, scanner):
    (tmp_path / "r").mkdir()
    locked = tmp_path / "r/secret.env"
    locked.write_text(f"KEY={anthropic_canary()}\n")
    locked.chmod(0)
    try:
        result = scan(tmp_path / "r", key, scanner)
    finally:
        locked.chmod(0o600)
    assert result["not_scanned"] == [
        {"path": str(locked), "reason": "unreadable (PermissionError)"}
    ]


# --- what it never reveals -------------------------------------------------------------------


def test_no_canary_appears_in_any_output(repo, tmp_path, caplog):
    root, c = repo
    out, key_file = tmp_path / "inv.json", tmp_path / "state/scanner.key"
    caplog.set_level("DEBUG")
    result = runner.invoke(app, ["scan", str(root), "--key-file", str(key_file), "--out", str(out)])
    assert result.exit_code == 1, result.output  # credentials found
    to_stdout = runner.invoke(app, ["scan", str(root), "--key-file", str(key_file)])
    assert json.loads(to_stdout.stdout)["agents"]
    logs = "\n".join(r.getMessage() for r in caplog.records)
    assert_absent(
        list(c.values()),
        out.read_text(),
        result.stdout,
        result.stderr,
        to_stdout.stdout,
        to_stdout.stderr,
        logs,
    )


def test_an_error_while_scanning_a_file_reports_only_its_class(repo, key, scanner, monkeypatch):
    root, c = repo

    def explode(rel, text):
        raise ValueError(text)  # an error message quoting the file

    monkeypatch.setattr(inventory_mod, "sdks_in", explode)
    result = scan(root, key, scanner)
    reasons = [n["reason"] for n in result["not_scanned"]]
    assert "unreadable (ValueError)" in reasons
    assert_absent(list(c.values()), json.dumps(result))


def test_findings_never_show_the_secret_in_a_repr(scanner):
    canary = anthropic_canary()
    assert_absent([canary], repr(scanner.find(f"k={canary}\n", "a.env")))
    assert_absent([canary], repr(SecretFinding("anthropic-api-key", "body", canary)))


# --- read-only and offline -------------------------------------------------------------------

WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND


def snapshot(root: Path) -> dict[str, tuple[bytes, int, int]]:
    out = {}
    for p in sorted(root.rglob("*")):
        st = p.lstat()
        if stat.S_ISREG(st.st_mode) and not p.is_symlink():
            out[str(p)] = (p.read_bytes(), st.st_mtime_ns, st.st_mode)
    return out


def test_scanning_only_reads_and_never_connects(repo, tmp_path, monkeypatch):
    root, _ = repo
    before = snapshot(root)
    opened: list[tuple[str, object]] = []
    real_os_open, real_io_open = os.open, io.open

    def watch_os_open(path, flags, *args, **kwargs):
        opened.append((str(path), flags))
        return real_os_open(path, flags, *args, **kwargs)

    def watch_io_open(file, mode="r", *args, **kwargs):
        opened.append((str(file), mode))
        return real_io_open(file, mode, *args, **kwargs)

    def refuse(*args, **kwargs):
        raise AssertionError("the scanner tried to use the network")

    monkeypatch.setattr(os, "open", watch_os_open)
    monkeypatch.setattr(io, "open", watch_io_open)
    monkeypatch.setattr(builtins, "open", watch_io_open)
    for name in ("connect", "connect_ex"):
        monkeypatch.setattr(socket.socket, name, refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)

    result = runner.invoke(app, ["scan", str(root), "--key-file", str(tmp_path / "k/scanner.key")])
    assert result.exit_code == 1, result.output
    under_root = [(p, f) for p, f in opened if Path(p).resolve().is_relative_to(root.resolve())]
    assert under_root, "the watch saw no opens"
    for path, how in under_root:
        if isinstance(how, int):
            assert not how & WRITE_FLAGS, path
        else:
            assert set(str(how)) <= {"r", "b", "t"}, path
    assert snapshot(root) == before


# --- configuration and attribution -----------------------------------------------------------


def test_registered_agents_get_their_sources_tools_owner_and_last_seen(tmp_path, key, scanner):
    src = tmp_path / "bot"
    src.mkdir()
    (src / "agent.py").write_text(f'import openai\nKEY = "{anthropic_canary()}"\n')
    identity = tmp_path / "identity.yaml"
    identity.write_text(
        "agents:\n  bot:\n    sponsor: lab-owner\n    purpose: test\n"
        "    tools: [read_file, send_email]\n    model: qwen2.5:7b-instruct\n"
    )
    gateway = tmp_path / "gateway.yaml"
    gateway.write_text("agents:\n  bot:\n    tools: [read_file]\n")
    receipts = tmp_path / "receipts.jsonl"
    receipts.write_text(
        '{"agent": "bot", "tool": "read_file", "ts": "2026-10-09T10:00:00+00:00"}\n'
        '{"agent": "bot", "tool": "read_file", "ts": "2026-10-09T11:00:00+00:00"}\n'
    )
    config = InventoryConfig.model_validate(
        {"identity_config": identity, "gateway_config": gateway,
         "agents": {"bot": {"sources": [str(src)]}}}
    )  # fmt: skip
    inv = Inventory(scanner, key, config)
    inv.scan_root(src)
    bot = the_agent(inv.to_json("t", False, receipts), "bot")
    assert bot["kind"] == "registered" and bot["owner"] == "lab-owner"
    assert bot["tools"] == ["read_file"]  # granted by the credential AND allowed by the gateway
    assert bot["models"] == ["qwen2.5:7b-instruct"]
    assert bot["sdks"] == ["openai"]
    assert [x["rule_id"] for x in bot["credentials"]] == ["anthropic-api-key"]
    assert bot["last_seen"] == {"at": "2026-10-09T11:00:00+00:00", "source": "ledger"}
    assert not [a for a in inv.to_json("t", False)["agents"] if a["kind"] == "shadow"]


def test_machine_config_locations_are_found_under_the_given_home_only(tmp_path):
    home, users = tmp_path / "home", tmp_path / "Users"
    for p in (
        home / ".config/Claude/claude_desktop_config.json",
        home / ".cursor/mcp.json",
        users / "someone/AppData/Roaming/Code/User/mcp.json",
    ):
        p.parent.mkdir(parents=True)
        p.write_text("{}")
    found = machine_config_paths(home, users)
    assert sorted(p.relative_to(tmp_path).as_posix() for p in found) == [
        "Users/someone/AppData/Roaming/Code/User/mcp.json",
        "home/.config/Claude/claude_desktop_config.json",
        "home/.cursor/mcp.json",
    ]


def test_a_client_config_becomes_a_shadow_agent_named_after_its_client(tmp_path, key, scanner):
    path = tmp_path / "Claude/claude_desktop_config.json"
    path.parent.mkdir()
    path.write_text('{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "srv"]}}}')
    inv = Inventory(scanner, key)
    inv.scan_client_config(path)
    agent = the_agent(inv.to_json("t", False), "claude-desktop")
    assert agent["kind"] == "shadow" and agent["mcp_servers"][0]["package"] == "srv"


@pytest.mark.parametrize(
    ("command", "args", "expected"),
    [
        ("npx", ["-y", "pkg"], ("pkg", False)),
        ("npx", ["-y", "pkg@latest"], ("pkg@latest", False)),
        ("npx", ["-y", "@scope/pkg@1.2.3"], ("@scope/pkg@1.2.3", True)),
        ("uvx", ["pkg==1.0"], ("pkg==1.0", True)),
        ("uvx", ["pkg"], ("pkg", False)),
        ("docker", ["run", "-i", "img:latest"], ("img:latest", False)),
        ("node", ["server.js"], (None, None)),
        ("npx", ["-y", "https://evil.test/x.tgz"], (None, None)),  # not a package name
    ],
)
def test_package_pinning(command, args, expected):
    assert package_of(command, args) == expected


def test_jsonc_keeps_slashes_inside_strings():
    text = '{"u": "http://x/y", /* c */ "v": [1,2,],} // end'
    assert json.loads(strip_jsonc(text)) == {"u": "http://x/y", "v": [1, 2]}


# --- the fingerprint key ---------------------------------------------------------------------


def test_the_key_is_private_and_a_shared_one_is_refused(tmp_path):
    path = tmp_path / "s/scanner.key"
    key = load_or_create_key(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert load_or_create_key(path) == key
    path.chmod(0o644)
    with pytest.raises(ScannerKeyError):
        load_or_create_key(path)


def test_fingerprints_depend_on_the_key():
    canary = anthropic_canary()
    a, b = secrets.token_bytes(32), secrets.token_bytes(32)
    assert secret_fingerprint(a, canary) == secret_fingerprint(a, canary)
    assert secret_fingerprint(a, canary) != secret_fingerprint(b, canary)


def test_the_fingerprint_command_confirms_a_suspected_key(repo, tmp_path):
    root, c = repo
    key_file = tmp_path / "state/scanner.key"
    scanned = runner.invoke(app, ["scan", str(root), "--key-file", str(key_file)])
    fps = {x["fingerprint"] for a in json.loads(scanned.stdout)["agents"] for x in a["credentials"]}
    result = runner.invoke(app, ["fingerprint", "--key-file", str(key_file)], input=c["env"] + "\n")
    assert result.exit_code == 0 and result.stdout.strip() in fps
    assert_absent([c["env"]], result.stdout, result.stderr)


def test_scan_exit_codes(tmp_path):
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "a.py").write_text("print('hi')\n")
    args = ["--key-file", str(tmp_path / "k/scanner.key")]
    assert runner.invoke(app, ["scan", str(clean), *args]).exit_code == 0
    (clean / "b.bin").write_bytes(b"\0")
    assert runner.invoke(app, ["scan", str(clean), *args]).exit_code == 3  # incomplete
    (clean / "c.env").write_text(f"K={anthropic_canary()}\n")
    assert runner.invoke(app, ["scan", str(clean), *args]).exit_code == 1
    assert runner.invoke(app, ["scan", *args]).exit_code == 2
