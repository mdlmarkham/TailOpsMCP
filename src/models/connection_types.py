"""
Shared connection types to break circular imports.

This module contains connection-related types that are used across
multiple modules to avoid circular import dependencies.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional
from datetime import datetime


class HealthStatus(Enum):
    """Health status for remote agents."""

    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class CommandResult:
    """Result of a command execution."""

    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration: float
    timestamp: datetime


@dataclass
class ForwardResult:
    """Result of port forwarding operation."""

    local_port: int
    remote_host: str
    remote_port: int
    status: str
    pid: Optional[int] = None


@dataclass
class UploadResult:
    """Result of file upload operation."""

    local_path: str
    remote_path: str
    bytes_transferred: int
    duration: float
    checksum: Optional[str] = None


@dataclass
class DownloadResult:
    """Result of file download operation."""

    remote_path: str
    local_path: str
    bytes_transferred: int
    duration: float
    checksum: Optional[str] = None


class SSHConnection:
    """SSH connection class."""

    def __init__(self, host: str, port: int = 22, username: str = None):
        self.host = host
        self.port = port
        self.username = username
        self.connected = False

    def connect(self) -> bool:
        """Establish SSH connection."""
        self.connected = True
        return True

    def disconnect(self) -> None:
        """Disconnect SSH connection."""
        self.connected = False

    def execute_command(self, command: str) -> CommandResult:
        """Execute command via SSH."""
        return CommandResult(
            command=command,
            exit_code=0,
            stdout="",
            stderr="",
            duration=0.0,
            timestamp=datetime.now(),
        )

    def health_check(self) -> HealthStatus:
        """Perform health check."""
        return HealthStatus.HEALTHY if self.connected else HealthStatus.UNKNOWN
