"""Session-wide guard: tests must not write into the repository.

Tests use their temp folders (tmp_path, local_lab's TemporaryDirectory). A test that writes
anywhere else under the repo, e.g. a default path like .lab-state/, fails the whole run and
the offending files are listed. Added after a gateway test wrote a salt file to .lab-state/.
"""

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
IGNORED_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache"}


def _snapshot() -> dict[Path, tuple[int, int]]:
    files = {}
    for path in REPO.rglob("*"):
        if IGNORED_DIRS.intersection(path.relative_to(REPO).parts) or not path.is_file():
            continue
        stat = path.stat()
        files[path] = (stat.st_mtime_ns, stat.st_size)
    return files


def written_since(before: dict[Path, tuple[int, int]]) -> list[str]:
    after = _snapshot()
    return sorted(str(p.relative_to(REPO)) for p, sig in after.items() if before.get(p) != sig)


def pytest_sessionstart(session: pytest.Session) -> None:
    session.config.stash[_BEFORE] = _snapshot()


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    written = written_since(session.config.stash[_BEFORE])
    if written:
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_sep("=", "tests wrote outside their temp folders", red=True)
            for path in written:
                reporter.write_line(f"  {path}")
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


_BEFORE = pytest.StashKey[dict[Path, tuple[int, int]]]()
