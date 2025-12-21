"""
SSH/Tailscale Connection Manager

Manages SSH/Tailscale connections for agent-like operations with connection pooling,
health monitoring, and retry mechanisms.
"""

import asyncio
import logging
import time
import uuid
from typing import Dict, Optional, Any
from datetime import datetime

try:
    import paramiko
except ImportError:
    paramiko = None

from src.models.target_registry import TargetConnection
from src.models.connection_types import (
    SSHConnection,
    CommandResult,
    ForwardResult,
    UploadResult,
    DownloadResult,
    HealthStatus,
)
from src.utils.retry import RetryConfig


logger = logging.getLogger(__name__)


class ConnectionPool:
    """Manages a pool of SSH connections for a specific target."""

    def __init__(self, target_id: str, max_connections: int = 10):
        """Initialize connection pool.

        Args:
            target_id: Unique identifier for the target
            max_connections: Maximum number of connections in pool
        """
        self.target_id = target_id
        self.max_connections = max_connections
        self.connections: Dict[str, SSHConnectionImpl] = {}
        self.in_use: Dict[str, bool] = {}
        self.created_at = datetime.utcnow()
        self.last_used = datetime.utcnow()
        self.logger = logging.getLogger(f"{__name__}.ConnectionPool.{target_id}")

    async def get_connection(self, timeout: int = 30) -> SSHConnection:
        """Get an available connection from pool.

        Args:
            timeout: Timeout for getting connection

        Returns:
            SSH connection instance

        Raises:
            ConnectionError: If no connection available
        """
        start_time = time.time()

        while time.time() - start_time < timeout:
            # Find free connection
            for conn_id, conn in self.connections.items():
                if not self.in_use.get(conn_id, False) and await conn.is_connected():
                    self.in_use[conn_id] = True
                    self.last_used = datetime.utcnow()
                    return conn

            # Create new connection if under limit
            if len(self.connections) < self.max_connections:
                conn_id = str(uuid.uuid4())
                try:
                    conn = await self._create_connection(conn_id)
                    self.connections[conn_id] = conn
                    self.in_use[conn_id] = True
                    self.last_used = datetime.utcnow()
                    return conn
                except Exception as e:
                    self.logger.error(
                        f"Failed to create connection {conn_id}: {str(e)}"
                    )

            await asyncio.sleep(0.1)

        raise ConnectionError(f"Timeout getting connection for {self.target_id}")

    async def return_connection(self, connection: SSHConnection):
        """Return connection to pool.

        Args:
            connection: Connection to return
        """
        for conn_id, conn in self.connections.items():
            if conn is connection:
                self.in_use[conn_id] = False
                break

    async def health_check(self) -> HealthStatus:
        """Perform health check on all connections.

        Returns:
            Health status for the pool
        """
        start_time = time.time()
        issues = []
        healthy_connections = 0

        for conn_id, conn in self.connections.items():
            try:
                if await conn.is_connected():
                    result = await conn.execute_command(
                        "echo 'pool_health_check'", timeout=5
                    )
                    if result.exit_code == 0:
                        healthy_connections += 1
                    else:
                        issues.append(f"Connection {conn_id} command failed")
                else:
                    issues.append(f"Connection {conn_id} not connected")
            except Exception as e:
                issues.append(f"Connection {conn_id} health check failed: {str(e)}")

        response_time = time.time() - start_time

        return HealthStatus(
            target=self.target_id,
            healthy=len(issues) == 0 or healthy_connections > 0,
            response_time=response_time,
            last_check=datetime.utcnow(),
            issues=issues if healthy_connections == 0 else None,
        )

    async def close_all(self):
        """Close all connections in pool."""
        for conn in self.connections.values():
            try:
                await conn.close()
            except Exception as e:
                self.logger.error(f"Error closing connection: {str(e)}")

        self.connections.clear()
        self.in_use.clear()

    async def _create_connection(self, conn_id: str) -> "SSHConnectionImpl":
        """Create a new SSH connection.

        Args:
            conn_id: Unique connection identifier

        Returns:
            SSH connection instance
        """
        # This should be implemented by the subclass
        raise NotImplementedError


class SSHConnectionImpl:
    """SSH connection implementation with enhanced features."""

    def __init__(self, target: TargetConnection, connection_id: str):
        """Initialize SSH connection.

        Args:
            target: Target connection configuration
            connection_id: Unique connection identifier
        """
        self.target = target
        self.connection_id = connection_id
        self.client = None
        self.sftp_client = None
        self.connected = False
        self.last_activity = datetime.utcnow()
        self.logger = logging.getLogger(f"{__name__}.SSHConnection.{connection_id}")
        self._lock = asyncio.Lock()

    async def connect(self) -> bool:
        """Establish SSH connection.

        Returns:
            True if connection successful
        """
        if self.connected:
            return True

        if paramiko is None:
            raise ConnectionError("paramiko not available for SSH connections")

        try:
            self.client = paramiko.SSHClient()

            # Load system host keys for security
            self.client.load_system_host_keys()
            self.client.load_host_keys_from_file(
                os.path.expanduser("~/.ssh/known_hosts")
            )

            # Reject unknown hosts by default
            self.client.set_missing_host_key_policy(paramiko.RejectPolicy())

            # Build connection arguments
            connection_kwargs = {
                "hostname": self.target.host,
                "port": self.target.port or 22,
                "username": self.target.username,
                "timeout": self.target.timeout,
                "allow_agent": False,
                "look_for_keys": False,
            }

            # Add authentication
            if self.target.key_path:
                connection_kwargs["key_filename"] = self.target.key_path
            else:
                # Try SSH agent and default keys
                connection_kwargs["allow_agent"] = True
                connection_kwargs["look_for_keys"] = True

            # Connect
            self.client.connect(**connection_kwargs)

            # Create SFTP client for file operations
            self.sftp_client = self.client.open_sftp()

            self.connected = True
            self.last_activity = datetime.utcnow()
            self.logger.info(f"SSH connection established to {self.target.host}")

            return True

        except Exception as e:
            self.logger.error(f"Failed to establish SSH connection: {str(e)}")
            await self.close()
            raise ConnectionError(f"SSH connection failed: {str(e)}")

    async def is_connected(self) -> bool:
        """Check if connection is active.

        Returns:
            True if connection is active
        """
        if not self.connected or not self.client:
            return False

        try:
            # Test connection with a simple command
            transport = self.client.get_transport()
            if transport and transport.is_active():
                return True
            return False
        except Exception:
            return False

    async def execute_command(self, command: str, timeout: int = 30) -> CommandResult:
        """Execute command via SSH.

        Args:
            command: Command to execute
            timeout: Command timeout

        Returns:
            Command result
        """
        async with self._lock:
            if not await self.connect():
                raise ConnectionError("SSH connection not available")

            start_time = time.time()
            self.last_activity = datetime.utcnow()

            try:
                stdin, stdout, stderr = self.client.exec_command(
                    command, timeout=timeout
                )

                stdout_data = stdout.read().decode("utf-8", errors="replace")
                stderr_data = stderr.read().decode("utf-8", errors="replace")
                exit_status = stdout.channel.recv_exit_status()

                execution_time = time.time() - start_time

                return CommandResult(
                    command=command,
                    exit_code=exit_status,
                    stdout=stdout_data,
                    stderr=stderr_data,
                    execution_time=execution_time,
                    timestamp=datetime.utcnow(),
                )

            except Exception as e:
                self.logger.error(f"Command execution failed: {command} - {str(e)}")
                raise ConnectionError(f"Command execution failed: {str(e)}")

    async def port_forward(
        self, local_port: int, remote_host: str, remote_port: int
    ) -> ForwardResult:
        """Create port forwarding.

        Args:
            local_port: Local port to bind
            remote_host: Remote host to forward to
            remote_port: Remote port to forward to

        Returns:
            Port forwarding result
        """
        if not await self.connect():
            raise ConnectionError("SSH connection not available")

        try:
            forward_id = str(uuid.uuid4())

            # Create port forward
            self.client.get_transport().request_port_forward("", local_port)

            return ForwardResult(
                local_port=local_port,
                remote_host=remote_host,
                remote_port=remote_port,
                status="active",
                connection_id=forward_id,
            )

        except Exception as e:
            self.logger.error(f"Port forward creation failed: {str(e)}")
            raise ConnectionError(f"Port forward creation failed: {str(e)}")

    async def close_port_forward(self, connection_id: str):
        """Close port forwarding.

        Args:
            connection_id: Port forward connection ID
        """
        try:
            # Port forward cleanup is handled by paramiko automatically
            pass
        except Exception as e:
            self.logger.error(f"Port forward cleanup failed: {str(e)}")

    async def upload_file(self, local_path: str, remote_path: str) -> UploadResult:
        """Upload file to remote target.

        Args:
            local_path: Local file path
            remote_path: Remote file path

        Returns:
            Upload result
        """
        if not await self.connect():
            raise ConnectionError("SSH connection not available")

        try:
            import hashlib

            # Calculate local file checksum
            with open(local_path, "rb") as f:
                file_content = f.read()
                checksum = hashlib.sha256(file_content).hexdigest()

            # Upload via SFTP
            sftp = self.sftp_client
            sftp.put(local_path, remote_path)

            return UploadResult(
                local_path=local_path,
                remote_path=remote_path,
                size=len(file_content),
                status="success",
                checksum=checksum,
            )

        except Exception as e:
            self.logger.error(
                f"File upload failed: {local_path} -> {remote_path} - {str(e)}"
            )
            raise ConnectionError(f"File upload failed: {str(e)}")

    async def download_file(self, remote_path: str, local_path: str) -> DownloadResult:
        """Download file from remote target.

        Args:
            remote_path: Remote file path
            local_path: Local file path

        Returns:
            Download result
        """
        if not await self.connect():
            raise ConnectionError("SSH connection not available")

        try:
            import hashlib

            # Download via SFTP
            sftp = self.sftp_client
            sftp.get(remote_path, local_path)

            # Calculate downloaded file checksum
            with open(local_path, "rb") as f:
                file_content = f.read()
                checksum = hashlib.sha256(file_content).hexdigest()

            return DownloadResult(
                remote_path=remote_path,
                local_path=local_path,
                size=len(file_content),
                status="success",
                checksum=checksum,
            )

        except Exception as e:
            self.logger.error(
                f"File download failed: {remote_path} -> {local_path} - {str(e)}"
            )
            raise ConnectionError(f"File download failed: {str(e)}")

    async def close(self):
        """Close SSH connection."""
        try:
            if self.sftp_client:
                self.sftp_client.close()
                self.sftp_client = None

            if self.client:
                self.client.close()
                self.client = None

            self.connected = False
            self.logger.info(f"SSH connection closed: {self.connection_id}")

        except Exception as e:
            self.logger.error(f"Error closing SSH connection: {str(e)}")


class RemoteConnectionManager:
    """Manages SSH/Tailscale connections for agent-like operations."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize connection manager.

        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.connection_pools: Dict[str, ConnectionPool] = {}
        self.logger = logging.getLogger(__name__)

        # Configuration
        self.max_connections = config.get("connection_pool", {}).get(
            "max_connections", 50
        )
        self.connection_timeout = config.get("connection_pool", {}).get(
            "connection_timeout", 30
        )
        self.idle_timeout = config.get("connection_pool", {}).get("idle_timeout", 300)
        self.health_check_interval = config.get("connection_pool", {}).get(
            "health_check_interval", 60
        )

        # Retry configuration
        retry_config = config.get("retry_policy", {})
        self.retry_config = RetryConfig(
            max_retries=retry_config.get("max_retries", 3),
            backoff_multiplier=retry_config.get("backoff_multiplier", 2),
            max_backoff=retry_config.get("max_backoff", 30),
        )

        # Background tasks
        self._health_check_task = None
        self._cleanup_task = None

    async def start(self):
        """Start connection manager background tasks."""
        self._health_check_task = asyncio.create_task(self._health_check_loop())
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        self.logger.info("Connection manager started")

    async def stop(self):
        """Stop connection manager and cleanup connections."""
        if self._health_check_task:
            self._health_check_task.cancel()

        if self._cleanup_task:
            self._cleanup_task.cancel()

        # Close all connection pools
        for pool in self.connection_pools.values():
            await pool.close_all()

        self.connection_pools.clear()
        self.logger.info("Connection manager stopped")

    async def create_connection(self, target: TargetConnection) -> SSHConnection:
        """Create SSH connection for target.

        Args:
            target: Target connection configuration

        Returns:
            SSH connection wrapper
        """
        target_id = self._get_target_id(target)

        # Get or create connection pool
        if target_id not in self.connection_pools:
            self.connection_pools[target_id] = ConnectionPool(
                target_id, self.max_connections
            )

        pool = self.connection_pools[target_id]
        connection = await pool.get_connection(timeout=self.connection_timeout)

        return SSHConnectionImpl(target, connection.connection_id)

    async def get_connection(self, target: TargetConnection) -> SSHConnection:
        """Get existing SSH connection for target.

        Args:
            target: Target connection configuration

        Returns:
            SSH connection wrapper
        """
        target_id = self._get_target_id(target)

        if target_id not in self.connection_pools:
            raise ConnectionError(f"No connection pool found for target {target_id}")

        pool = self.connection_pools[target_id]
        connection = await pool.get_connection(timeout=self.connection_timeout)

        return SSHConnectionImpl(target, connection.connection_id)

    async def health_check(self, target: TargetConnection) -> HealthStatus:
        """Perform health check for target connection.

        Args:
            target: Target connection configuration

        Returns:
            Health status information
        """
        target_id = self._get_target_id(target)

        if target_id not in self.connection_pools:
            return HealthStatus(
                target=target_id,
                healthy=False,
                response_time=0,
                last_check=datetime.utcnow(),
                issues=["No connection pool found"],
            )

        pool = self.connection_pools[target_id]
        return await pool.health_check()

    async def close_connection(self, target: TargetConnection):
        """Close connection for target.

        Args:
            target: Target connection configuration
        """
        target_id = self._get_target_id(target)

        if target_id in self.connection_pools:
            await self.connection_pools[target_id].close_all()
            del self.connection_pools[target_id]

        self.logger.info(f"Closed connection pool for target {target_id}")

    async def get_all_health_status(self) -> Dict[str, HealthStatus]:
        """Get health status for all targets.

        Returns:
            Dictionary of target ID to health status
        """
        health_status = {}

        for target_id, pool in self.connection_pools.items():
            try:
                health_status[target_id] = await pool.health_check()
            except Exception as e:
                health_status[target_id] = HealthStatus(
                    target=target_id,
                    healthy=False,
                    response_time=0,
                    last_check=datetime.utcnow(),
                    issues=[f"Health check failed: {str(e)}"],
                )

        return health_status

    def _get_target_id(self, target: TargetConnection) -> str:
        """Generate unique target ID.

        Args:
            target: Target connection configuration

        Returns:
            Unique target identifier
        """
        return f"{target.host}:{target.port or 22}:{target.username}"

    async def _health_check_loop(self):
        """Background task for periodic health checks."""
        while True:
            try:
                await asyncio.sleep(self.health_check_interval)
                await self._perform_health_checks()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Health check loop error: {str(e)}")

    async def _cleanup_loop(self):
        """Background task for cleaning up idle connections."""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute
                await self._cleanup_idle_connections()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Cleanup loop error: {str(e)}")

    async def _perform_health_checks(self):
        """Perform health checks on all connection pools."""
        for target_id, pool in self.connection_pools.items():
            try:
                health_status = await pool.health_check()

                if not health_status.healthy:
                    self.logger.warning(
                        f"Unhealthy connection pool for {target_id}: {health_status.issues}"
                    )

                # Log health metrics
                self.logger.info(
                    f"Health check for {target_id}: "
                    f"healthy={health_status.healthy}, "
                    f"response_time={health_status.response_time:.2f}s"
                )

            except Exception as e:
                self.logger.error(f"Health check failed for {target_id}: {str(e)}")

    async def _cleanup_idle_connections(self):
        """Cleanup idle connections."""
        current_time = datetime.utcnow()
        targets_to_cleanup = []

        for target_id, pool in self.connection_pools.items():
            idle_time = (current_time - pool.last_used).total_seconds()

            if idle_time > self.idle_timeout and not any(pool.in_use.values()):
                targets_to_cleanup.append(target_id)

        for target_id in targets_to_cleanup:
            self.logger.info(f"Cleaning up idle connection pool for {target_id}")
            await self.connection_pools[target_id].close_all()
            del self.connection_pools[target_id]


# Global connection manager instance
connection_manager: Optional[RemoteConnectionManager] = None


async def get_connection_manager() -> RemoteConnectionManager:
    """Get global connection manager instance.

    Returns:
        Global connection manager
    """
    global connection_manager

    if connection_manager is None:
        config = {
            "connection_pool": {
                "max_connections": 50,
                "connection_timeout": 30,
                "idle_timeout": 300,
                "health_check_interval": 60,
            },
            "retry_policy": {
                "max_retries": 3,
                "backoff_multiplier": 2,
                "max_backoff": 30,
            },
        }

        connection_manager = RemoteConnectionManager(config)
        await connection_manager.start()

    return connection_manager
