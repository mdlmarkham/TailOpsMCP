"""
File system security controls for SystemManager.

Implements path restrictions and size limits to prevent:
- Unauthorized file access
- Directory traversal attacks
- Reading sensitive system files
- Exfiltration of large files
"""

import os
from typing import List, Optional


# Default allowed paths (can be overridden via config)
DEFAULT_ALLOWED_PATHS = [
    "/var/log",
    "/tmp",
    "/opt/systemmanager/logs",
]

# Always deny these paths (security-sensitive)
ALWAYS_DENY_PATTERNS = [
    "**/.ssh/**",
    "**/.aws/**",
    "**/.config/**",
    "**/.kube/**",
    "**/id_*",
    "**/*_rsa*",
    "**/*_ed25519*",
    "**/*.pem",
    "**/*.key",
    "**/secrets/**",
    "**/credentials/**",
    "/etc/shadow",
    "/etc/shadow-",
    "/etc/sudoers",
    "/etc/sudoers.d/**",
    "/root/**",
    "/home/*/.ssh/**",
]

# Maximum file read size (10MB)
MAX_FILE_READ_SIZE = 10 * 1024 * 1024


def is_path_allowed(
    path: str, allowed_paths: Optional[List[str]] = None
) -> tuple[bool, str]:
    """Check if a file path is allowed for access.

    Args:
        path: Path to check
        allowed_paths: List of allowed path prefixes (default: DEFAULT_ALLOWED_PATHS)

    Returns:
        (allowed: bool, reason: str)
    """
    if allowed_paths is None:
        allowed_paths = DEFAULT_ALLOWED_PATHS

    try:
        # Resolve to absolute path and symlinks to prevent traversal
        resolved_path = os.path.realpath(path)  # This resolves symlinks

        # Check against deny patterns first
        from fnmatch import fnmatch

        for pattern in ALWAYS_DENY_PATTERNS:
            if fnmatch(resolved_path, pattern):
                return False, f"Path matches deny pattern: {pattern}"

        # Check if path starts with any allowed prefix (using resolved paths)
        for allowed in allowed_paths:
            allowed_resolved = os.path.realpath(allowed)
            if resolved_path.startswith(allowed_resolved):
                return True, "Path allowed"

        return False, f"Path not in allowed list: {allowed_paths}"

    except Exception as e:
        return False, f"Path validation error: {e}"


def check_file_size(path: str, max_size: int = MAX_FILE_READ_SIZE) -> tuple[bool, str]:
    """Check if file size is within limits.

    Args:
        path: Path to file
        max_size: Maximum allowed size in bytes

    Returns:
        (allowed: bool, reason: str)
    """
    try:
        size = os.path.getsize(path)
        if size > max_size:
            return False, f"File too large: {size} bytes (max: {max_size})"
        return True, "Size OK"
    except Exception as e:
        return False, f"Size check error: {e}"


def sanitize_path(path: str) -> str:
    """Sanitize a file path to prevent traversal attacks.

    Args:
        path: Input path

    Returns:
        Sanitized absolute path
    """
    # Remove null bytes
    path = path.replace("\x00", "")

    # Resolve to absolute path
    return os.path.abspath(path)
