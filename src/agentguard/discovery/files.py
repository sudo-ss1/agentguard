"""Read-only file access for the scanner.

Every file is opened with O_RDONLY | O_NOFOLLOW | O_NONBLOCK, and O_NOATIME where the kernel
allows it (only for the file's owner), so scanning changes neither content nor access times
where it can avoid it. O_NONBLOCK keeps a FIFO from hanging the scan; anything that isn't a
regular file is reported, not read.

Nothing is skipped silently: a file or directory that isn't read is returned as `NotScanned`
with a reason, so an incomplete scan can never look like a clean one.
"""

import os
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

MAX_FILE_BYTES = 1 << 20
# Dependency and cache folders: large, and full of other people's test keys. Each one skipped is
# reported once.
SKIP_DIRS = frozenset(
    {
        ".venv",
        "venv",
        "node_modules",
        "site-packages",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".tox",
    }
)
# Git's own folder isn't file content: `--history` reads it as objects (discovery/history.py).
GIT_DIR = ".git"


@dataclass(frozen=True)
class NotScanned:
    path: str
    reason: str
    rel: str | None = None  # for a file under a root: gitleaks' path-only rules still apply


@dataclass(frozen=True)
class TextFile:
    path: Path  # as found under the root the caller gave
    rel: str  # relative to that root, with forward slashes, as gitleaks path rules expect
    text: str
    mtime: float
    uid: int

    def __repr__(self) -> str:  # never show file content
        return f"TextFile(path={str(self.path)!r})"


class Unreadable(Exception):
    """A file that is deliberately not read. The message is a fixed reason, never content."""


_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_NOATIME = getattr(os, "O_NOATIME", 0)


def read_text(path: Path, max_bytes: int = MAX_FILE_BYTES) -> tuple[str, os.stat_result]:
    """The file's text and its stat. Raises Unreadable, or OSError."""
    try:
        fd = os.open(path, _FLAGS | _NOATIME)
    except PermissionError:
        if not _NOATIME:
            raise
        fd = os.open(path, _FLAGS)  # O_NOATIME is refused for files we don't own
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Unreadable("not a regular file")
        if st.st_size > max_bytes:
            raise Unreadable(f"larger than {max_bytes} bytes")
        chunks, size = [], 0
        while chunk := os.read(fd, 1 << 16):
            chunks.append(chunk)
            size += len(chunk)
            if size > max_bytes:
                raise Unreadable(f"larger than {max_bytes} bytes")
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if b"\0" in data[:8192]:
        raise Unreadable("binary")
    return data.decode("utf-8", errors="replace"), st


def describe(exc: BaseException) -> str:
    """A reason for `not_scanned`: fixed text, or the exception class only (an OSError's
    message can quote a path, never content, but other errors could quote anything)."""
    if isinstance(exc, Unreadable):
        return str(exc)
    return f"unreadable ({type(exc).__name__})"


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def walk(root: Path, max_bytes: int = MAX_FILE_BYTES) -> Iterator[TextFile | NotScanned]:
    """Every file under `root` (or `root` itself, if it is a file), in a stable order."""
    real_root = root.resolve()
    if not root.is_dir():
        yield from _one(root, root.name, real_root.parent, max_bytes)
        return
    errors: list[NotScanned] = []

    def on_error(exc: OSError) -> None:
        errors.append(NotScanned(str(exc.filename or root), f"unreadable ({type(exc).__name__})"))

    for dirpath, dirnames, filenames in os.walk(root, onerror=on_error, followlinks=False):
        here = Path(dirpath)
        kept = []
        for d in sorted(dirnames):
            if d == GIT_DIR:
                continue
            if d in SKIP_DIRS:
                yield NotScanned(str(here / d), "dependency or cache directory")
                continue
            if (here / d).is_symlink():
                yield from _symlink(here / d, real_root)
                continue
            kept.append(d)
        dirnames[:] = kept
        for name in sorted(filenames):
            path = here / name
            yield from _one(path, path.relative_to(root).as_posix(), real_root, max_bytes)
    yield from errors


def _symlink(path: Path, real_root: Path) -> Iterator[NotScanned]:
    """A link inside the root is scanned where it points; one leading out is reported."""
    try:
        target = path.resolve(strict=True)
    except (OSError, RuntimeError):
        yield NotScanned(str(path), "broken symlink")
        return
    if not _inside(target, real_root):
        yield NotScanned(str(path), "symlink to outside the scanned root")


def _one(path: Path, rel: str, real_root: Path, max_bytes: int) -> Iterator[TextFile | NotScanned]:
    if path.is_symlink():
        yield from _symlink(path, real_root)
        return
    try:
        text, st = read_text(path, max_bytes)
    except (Unreadable, OSError) as exc:
        yield NotScanned(str(path), describe(exc), rel)
        return
    yield TextFile(path, rel, text, st.st_mtime, st.st_uid)
