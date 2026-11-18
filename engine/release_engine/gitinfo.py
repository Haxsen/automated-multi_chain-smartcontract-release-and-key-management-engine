"""Source provenance: which commit is being released, and is the tree exactly that commit?"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class GitInfo:
    commit: str | None
    dirty: bool | None
    tag: str | None

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def _git(root: Path, *args: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", *args], cwd=root, capture_output=True, text=True, timeout=15, check=True
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return None
    return out.stdout.strip()


def collect(root: Path, env: Mapping[str, str] | None = None) -> GitInfo:
    env = os.environ if env is None else env
    commit = _git(root, "rev-parse", "HEAD") or env.get("GITHUB_SHA")
    status = _git(root, "status", "--porcelain", "--untracked-files=no")
    dirty = None if status is None else bool(status)
    tag = _git(root, "describe", "--tags", "--exact-match", "HEAD") or None
    if tag is None and env.get("GITHUB_REF_TYPE") == "tag":
        tag = env.get("GITHUB_REF_NAME")
    return GitInfo(commit=commit, dirty=dirty, tag=tag)
