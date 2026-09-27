"""Files MCP server. Deliberately unrestricted: any path, including delete."""

import shutil

from mcp.server.mcpserver import MCPServer

from agentguard.labfs import resolve
from agentguard.settings import get_settings

server = MCPServer("files")


def _path(path: str):
    return resolve(get_settings().lab_root, path)


@server.tool()
def read_file(path: str) -> str:
    """Read a text file and return its contents."""
    return _path(path).read_text()


@server.tool()
def write_file(path: str, content: str) -> str:
    """Write content to a file, creating parent directories as needed."""
    target = _path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    return f"wrote {len(content)} bytes to {path}"


@server.tool()
def list_dir(path: str = "/workspace") -> list[str]:
    """List the entries in a directory."""
    return sorted(p.name + ("/" if p.is_dir() else "") for p in _path(path).iterdir())


@server.tool()
def delete_file(path: str) -> str:
    """Delete a file or directory (recursively)."""
    target = _path(path)
    if target == get_settings().lab_root.resolve():
        for child in target.iterdir():
            shutil.rmtree(child) if child.is_dir() else child.unlink()
    elif target.is_dir():
        shutil.rmtree(target)
    else:
        target.unlink()
    return f"deleted {path}"
