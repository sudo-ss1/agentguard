"""`agentguard scan --history`: committed keys are found, and a hostile repo runs nothing.

Fixture repos are built with the git binary (we trust our own fixtures), isolated from the
user's and system git config. Scanning them must never run git or anything else.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentguard.cli import app
from agentguard.discovery.inventory import Inventory
from agentguard.guards.secrets import SecretScanner
from tests.canaries import anthropic_canary, assert_absent

runner = CliRunner()
ISOLATED = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.test",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.test",
    "GIT_PAGER": "",
}


def git(repo: Path, *args: str, check: bool = True, stdin: bytes | None = None) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), *args],
        env={**os.environ, **ISOLATED},
        input=stdin,
        capture_output=True,
    )
    if check and out.returncode:
        raise AssertionError(f"git {args[0]} failed: {out.stderr.decode()}")
    return out.stdout.decode()


def commit_all(repo: Path, message: str) -> str:
    git(repo, "add", "-A")
    git(repo, "-c", "core.hooksPath=" + os.devnull, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD").strip()


@pytest.fixture
def key_file(tmp_path):
    return tmp_path / "state/scanner.key"


def scan_json(root: Path, key_file: Path, *extra: str) -> tuple[int, dict, str]:
    result = runner.invoke(app, ["scan", str(root), "--key-file", str(key_file), *extra])
    return result.exit_code, json.loads(result.stdout), result.stdout + result.stderr


def credentials(result: dict) -> list[dict]:
    return [c for a in result["agents"] for c in a["credentials"]]


@pytest.fixture
def repo_with_deleted_key(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    (repo / "app").mkdir()
    (repo / "app/main.py").write_text("print('hello')\n")
    commit_all(repo, "start")
    canary = anthropic_canary()
    (repo / "app/settings.py").write_text(f'import anthropic\n\nKEY = "{canary}"\n')
    introduced = commit_all(repo, "add settings")
    (repo / "app/settings.py").write_text("import anthropic\nimport os\n\nKEY = os.environ['K']\n")
    commit_all(repo, "read the key from the environment")
    return repo, canary, introduced


def test_a_key_committed_then_removed_is_found_only_with_history(repo_with_deleted_key, key_file):
    repo, canary, introduced = repo_with_deleted_key
    code, without, _ = scan_json(repo, key_file)
    assert code == 0 and credentials(without) == []
    code, with_history, output = scan_json(repo, key_file, "--history")
    assert code == 1
    assert with_history["scanner"]["history"] is True
    [finding] = credentials(with_history)
    assert finding["rule_id"] == "anthropic-api-key"
    assert finding["file"] == str(repo / "app/settings.py") and finding["line"] == 3
    assert finding["commit"] == introduced
    assert_absent([canary], output)


def test_a_key_that_comes_back_is_credited_to_the_commit_that_first_added_it(tmp_path, key_file):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    text = f"KEY={anthropic_canary()}\n"
    (repo / "k.env").write_text(text)
    first = commit_all(repo, "add")
    (repo / "k.env").unlink()
    commit_all(repo, "remove")
    (repo / "k.env").write_text(text)
    commit_all(repo, "add it back")
    _, result, _ = scan_json(repo, key_file, "--history")
    assert [c["commit"] for c in credentials(result) if c["commit"]] == [first]


def test_a_bare_repo_and_a_key_reachable_only_through_a_tag(repo_with_deleted_key, tmp_path):
    repo, canary, _ = repo_with_deleted_key
    main = git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
    git(repo, "checkout", "-q", "--orphan", "side")
    git(repo, "rm", "-rqf", ".")
    (repo / "old.env").write_text(f"KEY={anthropic_canary()}\n")
    tagged = commit_all(repo, "orphan")
    git(repo, "tag", "-a", "v0", "-m", "v0")
    git(repo, "checkout", "-q", "-f", main)
    git(repo, "branch", "-D", "side")
    bare = tmp_path / "bare.git"
    git(tmp_path, "clone", "-q", "--bare", str(repo), str(bare))
    inv = Inventory(SecretScanner(), b"k" * 32)
    inv.scan_history(bare)
    found = {
        (c["file"].rsplit("/", 1)[-1], c["commit"]) for c in credentials(inv.to_json("t", True))
    }
    assert ("old.env", tagged) in found  # only the annotated tag reaches this commit
    assert len(found) == 2


# --- a hostile repo ------------------------------------------------------------------------


def arm(repo: Path, traps: Path) -> dict[str, Path]:
    """Config that runs a command through every route found in the design review. Each writes
    its own marker file if it runs."""
    traps.mkdir()
    markers = {}

    def script(name: str) -> str:
        markers[name] = traps / f"ran-{name}"
        path = traps / f"{name}.sh"
        path.write_text(f'#!/bin/sh\ntouch "{markers[name]}"\ncat "$@" 2>/dev/null\nexit 0\n')
        path.chmod(0o755)
        return str(path)

    config = {
        "diff.external": script("external-diff"),
        "diff.evil.textconv": script("textconv"),
        "diff.evil.command": script("diff-command"),
        "core.fsmonitor": script("fsmonitor"),
        "core.pager": script("pager"),
        "core.sshCommand": script("ssh"),
        "log.showSignature": "true",
        "gpg.program": script("gpg"),
        "filter.evil.clean": script("filter-clean"),
        "filter.evil.smudge": script("filter-smudge"),
        "filter.evil.process": script("filter-process"),
    }
    for k, v in config.items():
        git(repo, "config", k, v)
    (repo / ".gitattributes").write_text("* diff=evil filter=evil\n")
    hooks = repo / ".git/hooks"
    for hook in ("pre-commit", "post-commit", "post-checkout", "post-merge", "pre-push",
                 "reference-transaction", "fsmonitor-watchman"):  # fmt: skip
        (hooks / hook).write_text(f'#!/bin/sh\n"{script("hook-" + hook)}"\n')
        (hooks / hook).chmod(0o755)
    return markers


def add_signed_looking_commit(repo: Path) -> None:
    """A commit with a gpgsig header, so `log.showSignature` hands it to `gpg.program`."""
    raw = git(repo, "cat-file", "commit", "HEAD")
    head, _, rest = raw.partition("\n\n")
    signed = (
        head + "\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n -----END PGP SIGNATURE-----\n\n" + rest
    )
    sha = git(repo, "hash-object", "-t", "commit", "-w", "--stdin", stdin=signed.encode()).strip()
    git(repo, "update-ref", "HEAD", sha)


@pytest.fixture
def hostile_repo(tmp_path):
    repo = tmp_path / "hostile"
    repo.mkdir()
    git(repo, "init", "-q")
    canary = anthropic_canary()
    (repo / "notes.txt").write_text("first\n")
    commit_all(repo, "one")
    (repo / "notes.txt").write_text(f"second\nKEY={canary}\n")
    commit_all(repo, "two")  # committed before arming, so no filter runs while building
    markers = arm(repo, tmp_path / "traps")
    add_signed_looking_commit(repo)  # git's update-ref runs the reference-transaction hook
    for marker in markers.values():
        marker.unlink(missing_ok=True)
    return repo, canary, markers


def test_control_the_hostile_repo_does_run_code_through_git(hostile_repo):
    """Proves the traps are armed: real git, honouring the repo's config, runs them."""
    repo, _, markers = hostile_repo
    git(repo, "log", "-p", check=False)
    git(repo, "status", check=False)
    git(repo, "--no-pager", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull,
        "log", "-p", "--no-ext-diff", "--no-textconv", check=False)  # fmt: skip
    ran = {name for name, m in markers.items() if m.exists()}
    assert {"textconv", "fsmonitor", "gpg"} <= ran, ran


def test_scanning_the_hostile_repo_runs_nothing(hostile_repo, key_file, monkeypatch):
    repo, canary, markers = hostile_repo

    def refuse(*args, **kwargs):
        raise AssertionError("the scanner tried to start a process")

    assert not [m for m in markers.values() if m.exists()]
    monkeypatch.setattr(subprocess, "Popen", refuse)
    for name in ("system", "execv", "execve", "execvp", "posix_spawn", "posix_spawnp", "fork"):
        monkeypatch.setattr(os, name, refuse)
    code, result, output = scan_json(repo, key_file, "--history")
    assert code == 1, output
    assert {c["rule_id"] for c in credentials(result)} == {"anthropic-api-key"}
    assert [c["commit"] for c in credentials(result) if c["commit"]], "found in history"
    assert not [name for name, m in markers.items() if m.exists()]
    assert_absent([canary], output)


# --- refused repos -------------------------------------------------------------------------


def reasons(result: dict) -> list[str]:
    return [n["reason"] for n in result["not_scanned"] if n["path"].endswith("(history)")]


def test_alternates_are_refused(repo_with_deleted_key, key_file, tmp_path):
    repo, _, _ = repo_with_deleted_key
    (repo / ".git/objects/info/alternates").write_text(str(tmp_path / "elsewhere/objects") + "\n")
    _, result, _ = scan_json(repo, key_file, "--history")
    assert reasons(result) == ["uses objects/info/alternates (objects from other paths)"]


def test_a_dot_git_file_is_refused(tmp_path, key_file):
    repo = tmp_path / "worktree"
    repo.mkdir()
    (repo / ".git").write_text(f"gitdir: {tmp_path}/somewhere-else\n")
    _, result, _ = scan_json(repo, key_file, "--history")
    assert reasons(result) == [".git is a file or link (a worktree or submodule elsewhere)"]


def test_an_unknown_ref_format_is_refused_not_read_as_empty(repo_with_deleted_key, key_file):
    repo, _, _ = repo_with_deleted_key
    (repo / ".git/refs/heads/odd").write_text("ab" * 32 + "\n")  # a SHA-256-sized id
    _, result, _ = scan_json(repo, key_file, "--history")
    assert reasons(result) == ["a ref is not a SHA-1 id (unsupported object format)"]


def test_a_folder_that_is_not_a_repo_is_reported(tmp_path, key_file):
    (tmp_path / "plain").mkdir()
    (tmp_path / "plain/a.txt").write_text("hi\n")
    code, result, _ = scan_json(tmp_path / "plain", key_file, "--history")
    assert code == 3 and reasons(result) == ["not a git repository"]
