from __future__ import annotations

import os
import stat
from typing import Iterable, List, Optional


def _env_allowed_paths() -> List[str]:
    v = os.getenv("SYSTEMMANAGER_ALLOWED_PATHS")
    if not v:
        # safe defaults: cwd, /tmp, user home
        home = os.path.expanduser("~")
        return [os.getcwd(), os.path.join(home), "/tmp"]
    return [p.strip() for p in v.split(",") if p.strip()]


def is_path_allowed(path: str, allowed_paths: Optional[Iterable[str]] = None) -> bool:
    """Return True if `path` is inside any of the allowed_paths roots.

    This is a conservative check (resolves realpath)."""
    if not path:
        return False
    try:
        rp = os.path.realpath(path)
    except Exception:
        return False

    allowed = allowed_paths or _env_allowed_paths()
    for root in allowed:
        try:
            rr = os.path.realpath(root)
        except Exception:
            continue
        if rp == rr or rp.startswith(rr + os.sep):
            return True
    return False


def safe_list_directory(path: str) -> List[str]:
    """List directory only if allowed; raises PermissionError otherwise."""
    if not is_path_allowed(path):
        raise PermissionError(f"Access to path not allowed: {path}")
    return os.listdir(path)


def safe_read_file(path: str, max_bytes: int = 65536, max_lines: Optional[int] = None) -> str:
    """Read file content with size/line caps. Raises PermissionError if path not allowed."""
    if not is_path_allowed(path):
        raise PermissionError(f"Access to path not allowed: {path}")

    st = os.stat(path)
    # don't allow special files
    if stat.S_ISDIR(st.st_mode):
        raise IsADirectoryError(path)

    # Cap by bytes
    to_read = min(max_bytes, st.st_size if st.st_size > 0 else max_bytes)
    out_lines = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        if max_lines is None:
            return f.read(to_read)
        # read up to max_lines but also cap bytes
        total = 0
        for i, line in enumerate(f):
            if i >= max_lines or total >= max_bytes:
                break
            out_lines.append(line)
            total += len(line.encode("utf-8"))
    return "".join(out_lines)


def is_running_as_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows: approximate by checking admin group is complicated; return False
        return False
