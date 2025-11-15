from __future__ import annotations

import os
import shlex
import subprocess
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class GitResult:
    returncode: int
    stdout: str
    stderr: str


class StackManager:
    """Basic stack abstraction backed by a directory (git recommended).

    This manager provides helpers to run git operations, compute diffs, and
    perform rollbacks. It's intentionally small — use a proper deployment
    system for production-grade operations.
    """

    def __init__(self, path: str):
        self.path = os.path.abspath(path)

    def _run(self, cmd: List[str], cwd: Optional[str] = None) -> GitResult:
        proc = subprocess.Popen(cmd, cwd=cwd or self.path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = proc.communicate()
        return GitResult(proc.returncode, out, err)

    def git_status(self) -> GitResult:
        return self._run(["git", "status", "--porcelain"], cwd=self.path)

    def git_diff(self, rev_a: str = "HEAD~1", rev_b: str = "HEAD") -> GitResult:
        return self._run(["git", "diff", "--name-status", rev_a, rev_b], cwd=self.path)

    def git_checkout(self, rev: str) -> GitResult:
        return self._run(["git", "checkout", rev], cwd=self.path)

    def apply_patch_from_git(self, patch_text: str) -> GitResult:
        # apply patch via git apply
        return self._run(["git", "apply", "-"], cwd=self.path)
