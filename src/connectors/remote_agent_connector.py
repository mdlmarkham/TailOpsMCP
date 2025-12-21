"""
Remote Agent Connector Base Framework

Provides base class for agent-like remote functionality without requiring
agent installation on target systems. Supports SSH/Tailscale connections.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Optional, Any
from datetime import datetime
from contextlib import asynccontextmanager

from src.models.target_registry import TargetConnection
from src.models.connection_types import (
    SSHConnection,
    CommandResult,
    UploadResult,
    DownloadResult,
    HealthStatus,
)
from src.utils.errors import SystemManagerError


logger = logging.getLogger(__name__)


class RemoteAgentError(SystemManagerError):
    """Base exception for remote agent operations."""

    pass


class ConnectionError(RemoteAgentError):
    """Connection-related errors."""

    pass


class OperationError(RemoteAgentError):
    """Operation execution errors."""

    pass


class SecurityError(RemoteAgentError):
    """Security-related errors."""

    pass


@dataclass
class LogEntry:
    """Represents a log entry from journald or other sources."""

    timestamp: datetime
    level: str
    message: str
    source: str
    metadata: Dict[str, Any] = None


@dataclass
class ServiceStatus:
    """Service status information."""

    name: str
    state: str
    active_since: Optional[datetime]
    memory_usage: Optional[int]
    cpu_usage: Optional[float]
    restart_count: int
    description: str


@dataclass
class DockerContainer:
    """Docker container information."""

    container_id: str
    name: str
    status: str
    image: str
    ports: Dict[str, Any]
    created: datetime
    state: str


@dataclass
class ContainerStats:
    """Docker container statistics."""

    container_id: str
    cpu_usage: float
    memory_usage: int
    memory_limit: int
    network_io: Dict[str, int]
    block_io: Dict[str, int]
    pid: int


@dataclass
class FileInfo:
    """File information."""

    name: str
    path: str
    size: int
    is_directory: bool
    permissions: str
    owner: str
    group: str
    modified: datetime


@dataclass
class FileStats:
    """File statistics."""

    path: str
    size: int
    permissions: str
    owner: str
    group: str
    created: datetime
    modified: datetime
    accessed: datetime


class RemoteAgentConnector(ABC):
    """Base class for agent-like remote functionality.

    Provides common functionality for remote operations via SSH/Tailscale
    without requiring agent installation on target systems.
    """

    def __init__(self, target: TargetConnection, connection: SSHConnection):
        """Initialize remote agent connector.

        Args:
            target: Target connection configuration
            connection: SSH connection instance
        """
        self.target = target
        self.connection = connection
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._capabilities: Dict[str, Any] = {}
        # Initialize secure allowlist for allowed commands
        self._allowed_commands_set = self._build_allowed_commands()

    @abstractmethod
    async def get_capabilities(self) -> Dict[str, Any]:
        """Get available capabilities for this connector.

        Returns:
            Dictionary of available capabilities and their metadata
        """
        pass

    @abstractmethod
    async def validate_target(self) -> bool:
        """Validate that target supports this connector type.

        Returns:
            True if target is valid for this connector
        """
        pass

    async def health_check(self) -> HealthStatus:
        """Perform health check for this connector.

        Returns:
            Health status information
        """
        start_time = datetime.utcnow()
        issues = []

        try:
            # Test basic connectivity
            if not await self.connection.is_connected():
                issues.append("SSH connection not established")

            # Test basic command execution
            result = await self.connection.execute_command(
                "echo 'health_check'", timeout=10
            )
            if result.exit_code != 0:
                issues.append(f"Command execution failed: {result.stderr}")

            # Check connector-specific capabilities
            capabilities = await self.get_capabilities()
            if not capabilities:
                issues.append("No capabilities detected")

        except Exception as e:
            issues.append(f"Health check failed: {str(e)}")

        response_time = (datetime.utcnow() - start_time).total_seconds()

        return HealthStatus(
            target=self.target.host or "unknown",
            healthy=len(issues) == 0,
            response_time=response_time,
            last_check=datetime.utcnow(),
            issues=issues,
        )

    async def execute_command(self, command: str, timeout: int = 30) -> CommandResult:
        """Execute command via SSH connection.

        Args:
            command: Command to execute
            timeout: Command timeout in seconds

        Returns:
            Command execution result

        Raises:
            OperationError: If command execution fails
        """
        start_time = datetime.utcnow()

        try:
            result = await self.connection.execute_command(command, timeout)

            return CommandResult(
                command=command,
                exit_code=result.exit_code,
                stdout=result.stdout,
                stderr=result.stderr,
                execution_time=(datetime.utcnow() - start_time).total_seconds(),
                timestamp=datetime.utcnow(),
            )

        except Exception as e:
            self.logger.error(f"Command execution failed: {command} - {str(e)}")
            raise OperationError(f"Failed to execute command: {str(e)}")

    @asynccontextmanager
    async def port_forward(self, local_port: int, remote_host: str, remote_port: int):
        """Create port forwarding session.

        Args:
            local_port: Local port to bind
            remote_host: Remote host to forward to
            remote_port: Remote port to forward to

        Yields:
            ForwardResult with port forwarding details
        """
        try:
            forward_result = await self.connection.port_forward(
                local_port, remote_host, remote_port
            )
            yield forward_result
        finally:
            if forward_result.connection_id:
                await self.connection.close_port_forward(forward_result.connection_id)

    async def upload_file(self, local_path: str, remote_path: str) -> UploadResult:
        """Upload file to remote target.

        Args:
            local_path: Local file path
            remote_path: Remote file path

        Returns:
            Upload result information

        Raises:
            OperationError: If upload fails
        """
        try:
            return await self.connection.upload_file(local_path, remote_path)
        except Exception as e:
            self.logger.error(
                f"File upload failed: {local_path} -> {remote_path} - {str(e)}"
            )
            raise OperationError(f"Failed to upload file: {str(e)}")

    async def download_file(self, remote_path: str, local_path: str) -> DownloadResult:
        """Download file from remote target.

        Args:
            remote_path: Remote file path
            local_path: Local file path

        Returns:
            Download result information

        Raises:
            OperationError: If download fails
        """
        try:
            return await self.connection.download_file(remote_path, local_path)
        except Exception as e:
            self.logger.error(
                f"File download failed: {remote_path} -> {local_path} - {str(e)}"
            )
            raise OperationError(f"Failed to download file: {str(e)}")

    def _build_allowed_commands(self) -> set:
        """Build set of allowed commands for security."""
        allowed_commands = {
            # System information
            "echo",
            "whoami",
            "hostname",
            "uname",
            "date",
            "uptime",
            # File operations (limited)
            "ls",
            "cat",
            "stat",
            "find",
            "head",
            "tail",
            "wc",
            "grep",
            "sed",
            "awk",
            # Network operations (limited)
            "ping",
            "nc",
            "ss",
            "ip",
            "netstat",
            "nmap",
            # Process operations (limited)
            "ps",
            "pgrep",
            "pidof",
            # Service operations (limited)
            "systemctl",
            "service",
            # Docker operations (limited)
            "docker",
            # Package operations (read-only)
            "dpkg",
            "apt-cache",
            "apt-listchanges",
        }
        return allowed_commands
        """Validate command safety before execution.

        Args:
            command: Command to validate

        Returns:
            True if command is safe to execute

        Raises:
            SecurityError: If command is unsafe
        """
        # Basic safety checks
        dangerous_patterns = [
            r";\s*rm\s+-rf",
            r"&\s*&\s*rm\s+-rf",
            r"\|\|\s*rm\s+-rf",
            r">\s*/etc/",
            r"<\s*/etc/",
            r">>\s*/etc/",
            r">\s*/var/",
            r">>\s*/var/",
        ]

        import re

        for pattern in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                raise SecurityError(f"Command contains dangerous pattern: {pattern}")

        return True

    def _sanitize_file_path(self, path: str) -> str:
        """Sanitize file path for security.

        Args:
            path: File path to sanitize

        Returns:
            Sanitized file path

        Raises:
            SecurityError: If path is unsafe
        """
        # Remove null bytes and control characters
        import re

        sanitized = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", path)

        # Remove directory traversal attempts
        sanitized = re.sub(r"\.\./", "", sanitized)

        # Ensure path doesn't start with absolute paths to sensitive directories
        sensitive_prefixes = ["/etc/", "/var/log/", "/root/", "/home/"]
        for prefix in sensitive_prefixes:
            if sanitized.startswith(prefix) and not self._is_allowed_sensitive_path(
                sanitized
            ):
                raise SecurityError(
                    f"Access to sensitive path not allowed: {sanitized}"
                )

        return sanitized

    def _is_allowed_sensitive_path(self, path: str) -> bool:
        """Check if access to sensitive path is allowed.

        Args:
            path: File path to check

        Returns:
            True if path access is allowed
        """
        # This should be configured based on security policy
        # For now, allow specific paths that are commonly needed
        allowed_paths = [
            "/etc/systemd/system/",
            "/var/log/journal/",
            "/tmp/",
            "/var/tmp/",
        ]

        return any(path.startswith(allowed) for allowed in allowed_paths)

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if hasattr(self, "connection"):
            await self.connection.close()
