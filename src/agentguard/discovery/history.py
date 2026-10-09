"""Read a repo's history for `agentguard scan --history`, without running git.

Running `git` on a repo you don't trust can execute that repo's config: textconv and external
diff drivers, `core.fsmonitor`, a pager, `gpg.program` through `log.showSignature`, hooks. Git
has no switch to ignore a repo's own `.git/config` (docs/phase6-design.md, "Reading history").
So history is read with dulwich, at the object level only:

- `DiskObjectStore` and `DiskRefsContainer`, never a dulwich `Repo`: `.git/config` is never
  read, and no hook, filter, signature or diff driver code is reached.
- Refs are read raw. Symbolic refs (HEAD) aren't followed; the branches they name are read
  directly. Tags are peeled to commits.
- Each commit is compared with its first parent, tree against tree. A blob is scanned once per
  path, attributed to the first commit (oldest first) that introduced it there.

Refused, and reported in `not_scanned`: a `.git` that is a file (a worktree or submodule
pointing elsewhere), `objects/info/alternates` (it reads objects from other paths on disk), and
ref values that aren't SHA-1 ids (e.g. a SHA-256 repo, which would otherwise look empty).

Limits: at most MAX_COMMITS commits (newest first). Blobs over the size cap or binary are
skipped and counted; gitleaks' path-only rules still apply to them. A blob is loaded in full
before its size is known, so a hostile repo can still cost memory. dulwich parses packs with
compiled extensions.
"""

import re
import stat
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from dulwich.diff_tree import tree_changes
from dulwich.object_store import DiskObjectStore
from dulwich.objects import Commit, ObjectID, Tag
from dulwich.refs import DiskRefsContainer
from dulwich.walk import Walker

from agentguard.discovery.files import GIT_DIR, MAX_FILE_BYTES, Unreadable

MAX_COMMITS = 10_000
_SHA1 = re.compile(rb"^[0-9a-f]{40}$")


class HistoryRefused(Unreadable):
    """A repo whose history is deliberately not read. The message is a fixed reason."""


@dataclass(frozen=True)
class HistoryBlob:
    commit: str
    rel: str
    text: str | None  # None: binary or over the size cap (only path rules apply)
    commit_time: int

    def __repr__(self) -> str:  # never show content
        return f"HistoryBlob(commit={self.commit!r}, rel={self.rel!r})"


@dataclass
class HistoryStats:
    commits: int = 0
    truncated: bool = False
    skipped_blobs: int = 0  # binary or over the size cap
    skipped: list[str] = field(default_factory=list)


def git_dir(root: Path) -> Path | None:
    """The repo's git directory: `<root>/.git`, or `root` itself for a bare repo."""
    dotgit = root / GIT_DIR
    if dotgit.is_symlink() or dotgit.is_file():
        raise HistoryRefused(".git is a file or link (a worktree or submodule elsewhere)")
    if dotgit.is_dir():
        return dotgit
    if (root / "objects").is_dir() and (root / "HEAD").is_file():
        return root
    return None


def _heads(refs: DiskRefsContainer) -> list[ObjectID]:
    heads: set[ObjectID] = set()
    for name in refs.allkeys():
        value = refs.read_ref(name)
        if value is None or value.startswith(b"ref: "):
            continue  # a symbolic ref: the branch it names is read on its own
        value = value.strip()
        if not _SHA1.match(value):
            raise HistoryRefused("a ref is not a SHA-1 id (unsupported object format)")
        heads.add(ObjectID(value))
    return sorted(heads)


def _peel(store: DiskObjectStore, sha: ObjectID) -> ObjectID | None:
    obj = store[sha]
    for _ in range(16):
        if not isinstance(obj, Tag):
            break
        obj = store[obj.object[1]]
    return obj.id if isinstance(obj, Commit) else None


def blobs(
    root: Path, stats: HistoryStats, max_bytes: int = MAX_FILE_BYTES
) -> Iterator[HistoryBlob]:
    gitdir = git_dir(root)
    if gitdir is None:
        raise HistoryRefused("not a git repository")
    objects = gitdir / "objects"
    if (objects / "info" / "alternates").exists():
        raise HistoryRefused("uses objects/info/alternates (objects from other paths)")
    store = DiskObjectStore(str(objects))
    refs = DiskRefsContainer(str(gitdir))
    commits = {c for c in (_peel(store, h) for h in _heads(refs)) if c is not None}
    if not commits:
        return
    entries = list(Walker(store, include=sorted(commits), max_entries=MAX_COMMITS + 1))
    stats.truncated = len(entries) > MAX_COMMITS
    entries = entries[:MAX_COMMITS]
    stats.commits = len(entries)
    seen: set[tuple[bytes, bytes]] = set()
    for entry in reversed(entries):  # oldest first: a blob is credited to where it appeared
        commit = entry.commit
        parent_tree = None
        if commit.parents and commit.parents[0] in store:  # absent in a shallow clone
            parent = store[commit.parents[0]]
            parent_tree = parent.tree if isinstance(parent, Commit) else None
        for change in tree_changes(store, parent_tree, commit.tree):
            new = change.new
            if new is None or new.sha is None or new.path is None or new.mode is None:
                continue
            if not stat.S_ISREG(new.mode):  # symlinks and submodules aren't content
                continue
            if (new.sha, new.path) in seen:
                continue
            seen.add((new.sha, new.path))
            _, raw = store.get_raw(new.sha)
            text = None
            if len(raw) > max_bytes or b"\0" in raw[:8192]:
                stats.skipped_blobs += 1
            else:
                text = raw.decode("utf-8", errors="replace")
            path = new.path.decode("utf-8", errors="replace")
            yield HistoryBlob(commit.id.decode(), path, text, commit.commit_time)
