"""MCP client configs: which MCP servers a client (Claude Desktop, Cursor, VS Code, Claude Code)
will start or connect to.

A server entry's arguments, env values and headers often carry tokens, so they are never
copied. What is kept is a fixed set of fields: the server name, transport, command basename,
the package or image it runs (only if it parses as one, and no secret rule matches it), the
remote host, env and header *names*, and a keyed fingerprint of the whole entry so a changed
entry shows up between scans.
"""

import json
import re
from pathlib import Path, PurePath
from typing import Any
from urllib.parse import urlsplit

from agentguard.discovery.fingerprint import entry_fingerprint
from agentguard.guards.secrets import SecretScanner

# (file name, parent folder name or None for any) -> (client, key holding the servers)
_CLIENTS: list[tuple[str, frozenset[str] | None, str, str]] = [
    ("claude_desktop_config.json", None, "claude-desktop", "mcpServers"),
    (".mcp.json", None, "claude-code", "mcpServers"),
    ("mcp.json", frozenset({".cursor"}), "cursor", "mcpServers"),
    ("mcp.json", frozenset({".vscode", "User"}), "vscode", "servers"),
    ("settings.json", frozenset({".vscode", "User"}), "vscode", "mcp.servers"),
]


def client_of(path: PurePath) -> tuple[str, str] | None:
    """(client, servers key) if `path` is an MCP client config, else None."""
    for name, parents, client, key in _CLIENTS:
        if path.name == name and (parents is None or path.parent.name in parents):
            return client, key
    return None


def machine_config_paths(home: Path, windows_users: Path | None = None) -> list[Path]:
    """Known per-user config locations that exist: Linux and macOS under `home`, and in WSL the
    Windows profiles under `windows_users` (/mnt/c/Users)."""
    rel = [
        ".config/Claude/claude_desktop_config.json",
        "Library/Application Support/Claude/claude_desktop_config.json",
        ".cursor/mcp.json",
        ".config/Code/User/mcp.json",
        ".config/Code/User/settings.json",
        "Library/Application Support/Code/User/mcp.json",
        "Library/Application Support/Code/User/settings.json",
    ]
    found = [home / r for r in rel]
    if windows_users is not None and windows_users.is_dir():
        for profile in sorted(windows_users.iterdir()):
            found += [
                profile / "AppData/Roaming/Claude/claude_desktop_config.json",
                profile / ".cursor/mcp.json",
                profile / "AppData/Roaming/Code/User/mcp.json",
                profile / "AppData/Roaming/Code/User/settings.json",
            ]
    return [p for p in found if p.is_file()]


def strip_jsonc(text: str) -> str:
    """JSON with comments and trailing commas (VS Code's format) to plain JSON."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            out.append(text[i : j + 1])
            i = j + 1
        elif text.startswith("//", i):
            i = text.find("\n", i)
            i = n if i == -1 else i
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
        else:
            out.append(c)
            i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


class UnparsedConfig(Exception):
    """The message is a fixed reason, never file content."""


def servers_in(text: str, key: str) -> dict[str, Any]:
    try:
        data = json.loads(strip_jsonc(text))
    except ValueError:
        raise UnparsedConfig("not valid JSON") from None
    for part in key.split("."):
        if not isinstance(data, dict):
            raise UnparsedConfig("unexpected structure")
        data = data.get(part, {})
    if not isinstance(data, dict):
        raise UnparsedConfig("unexpected structure")
    return data


_NAME = re.compile(r"^[\w.@ -]{1,64}$")
_NPM = re.compile(r"^(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*(@(?P<v>[\w.^~<>=*|-]+))?$")
_PYPI = re.compile(r"^[A-Za-z0-9][\w.-]*(\[[\w,-]+\])?((==|@)(?P<v>[\w.+!*-]+))?$")
_DOCKER = re.compile(r"^[a-z0-9][\w./:-]*(@(?P<v>sha256:[0-9a-f]{64}))?$")
_EXACT = re.compile(r"^\d+(\.\d+){1,3}([+-][\w.-]+)?$")
_DOCKER_VALUE_OPTS = frozenset(
    {"-e", "--env", "--env-file", "-v", "--volume", "--mount", "--name", "-p", "--publish",
     "--network", "-w", "--workdir", "--entrypoint", "-u", "--user", "-l", "--label"}
)  # fmt: skip


def _positional(args: list[str], value_opts: frozenset[str] = frozenset()) -> str | None:
    skip = False
    for a in args:
        if skip:
            skip = False
        elif a in value_opts:
            skip = True
        elif not a.startswith("-"):
            return a
    return None


def package_of(command: str, args: list[str]) -> tuple[str | None, bool | None]:
    """(package spec, pinned) for a server started by a package runner. pinned is None when
    it can't be told (a script path, an unknown runner)."""
    runner = PurePath(command).name.removesuffix(".exe").removesuffix(".cmd")
    if runner in ("npx", "bunx", "pnpx"):
        spec, rx = _positional(args), _NPM
    elif runner == "uvx":
        frm = args.index("--from") if "--from" in args else -1
        spec = args[frm + 1] if 0 <= frm < len(args) - 1 else _positional(args)
        rx = _PYPI
    elif runner in ("docker", "podman") and "run" in args:
        spec = _positional(args[args.index("run") + 1 :], _DOCKER_VALUE_OPTS)
        rx = _DOCKER
    else:
        return None, None
    m = rx.match(spec or "")
    if not m:
        return None, None
    version = m.group("v")
    pinned = bool(version) and (rx is _DOCKER or bool(_EXACT.match(version)))
    return spec, pinned


def summarize(
    name: str, entry: Any, client: str, config: str, key: bytes, scanner: SecretScanner
) -> dict[str, Any]:
    """One server, as fixed fields only. Anything that might be a secret is dropped."""

    def clean(value: str | None) -> str | None:
        return value if value is not None and not scanner.scan_text(value) else None

    entry = entry if isinstance(entry, dict) else {}
    command = entry.get("command") if isinstance(entry.get("command"), str) else None
    args = [a for a in entry.get("args") or [] if isinstance(a, str)]
    url = entry.get("url") if isinstance(entry.get("url"), str) else None
    package, pinned = package_of(command, args) if command else (None, None)
    host = None
    if url:
        try:
            host = urlsplit(url).hostname
        except ValueError:
            host = None
        pinned = False  # a remote server can change at any time
    canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str).encode()
    return {
        "name": clean(name) if _NAME.match(name) else None,
        "client": client,
        "config": config,
        "transport": str(entry.get("type") or ("http" if url else "stdio"))[:16],
        "command": clean(PurePath(command).name[:64]) if command else None,
        "package": clean(package),
        "pinned": pinned,
        "host": clean(host),
        "env": sorted(k for k in (entry.get("env") or {}) if isinstance(k, str) and _NAME.match(k)),
        "headers": sorted(
            k for k in (entry.get("headers") or {}) if isinstance(k, str) and _NAME.match(k)
        ),
        "entry_fingerprint": entry_fingerprint(key, canonical),
    }
