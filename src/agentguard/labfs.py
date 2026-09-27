"""Map agent-visible paths into the lab root.

This is a lab safety harness, not a security control: the files server is
deliberately unrestricted *inside* the lab, but "/" and "~" resolve under
LAB_ROOT so an attack like `delete_file /` can never touch the real host.
"""

import posixpath
import shutil
from pathlib import Path

LAB_HOME = "/home/agent"
SEED_ROOT = Path(__file__).resolve().parents[2] / "lab" / "rootfs"


def normalize(path: str) -> str:
    """The absolute path the files server will act on, as the agent sees the filesystem.

    The gateway authorizes this normalized form, so `/workspace/../home/agent/.ssh`
    is judged as `/home/agent/.ssh`, not as something under /workspace.
    """
    if path == "~" or path.startswith("~/"):
        path = LAB_HOME + path[1:]
    if not path.startswith("/"):
        path = "/workspace/" + path
    # Like a chroot: "/../etc" is "/etc". normpath keeps a leading "//", so strip extras.
    return "/" + posixpath.normpath(path).lstrip("/")


def resolve(lab_root: Path, path: str) -> Path:
    root = lab_root.resolve()
    target = (root / normalize(path).lstrip("/")).resolve()
    if target != root and root not in target.parents:
        raise PermissionError(f"{path!r} resolves outside the lab")  # e.g. via a symlink
    return target


def reset(lab_root: Path, seed: Path = SEED_ROOT) -> None:
    """Restore the lab filesystem from the seed copy in lab/rootfs."""
    if lab_root.exists():
        shutil.rmtree(lab_root)
    shutil.copytree(seed, lab_root)
