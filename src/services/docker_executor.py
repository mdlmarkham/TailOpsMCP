"""
Docker executor implementation for remote target operations.
"""

import logging
import time
from typing import Any, Dict, Optional

import docker

from src.services.executor import Executor, ExecutionResult, ExecutionStatus

logger = logging.getLogger(__name__)


class DockerExecutor(Executor):
    """Docker executor for remote target operations."""

    def __init__(
        self,
        socket_path: Optional[str] = None,
        host: Optional[str] = None,
        timeout: int = 30,
        tls_verify: bool = False,
        cert_path: Optional[str] = None,
        retry_attempts: int = 3,
        retry_delay: float = 1.0,
    ):
        """Initialize Docker executor.

        Args:
            socket_path: Path to Docker socket.
            host: Docker host URL (tcp://host:port).
            timeout: Connection timeout in seconds.
            tls_verify: Whether to verify TLS certificates.
            cert_path: Path to TLS certificate directory.
            retry_attempts: Number of retry attempts for failed operations
            retry_delay: Delay between retries in seconds
        """
        super().__init__(timeout, retry_attempts, retry_delay)
        self.socket_path = socket_path
        self.host = host
        self.tls_verify = tls_verify
        self.cert_path = cert_path
        self.client: Optional[docker.DockerClient] = None

    def connect(self) -> bool:
        """Establish Docker connection to target.

        Returns:
            True if connection successful, False otherwise.
        """
        for attempt in range(self.retry_attempts):
            try:
                if self.socket_path:
                    # Connect via Unix socket
                    self.client = docker.DockerClient(
                        base_url=f"unix://{self.socket_path}", timeout=self.timeout
                    )
                elif self.host:
                    # Connect via TCP
                    tls_config = None
                    if self.tls_verify and self.cert_path:
                        tls_config = docker.tls.TLSConfig(
                            ca_cert=f"{self.cert_path}/ca.pem",
                            client_cert=(
                                f"{self.cert_path}/cert.pem",
                                f"{self.cert_path}/key.pem",
                            ),
                            verify=True,
                        )

                    self.client = docker.DockerClient(
                        base_url=self.host, timeout=self.timeout, tls=tls_config
                    )
                else:
                    # Use default Docker connection
                    self.client = docker.from_env(timeout=self.timeout)

                # Test connection
                self.client.ping()
                self._connected = True
                logger.info("Docker connection established")
                return True

            except (docker.errors.DockerException, ConnectionError) as e:
                logger.warning(
                    f"Docker connection attempt {attempt + 1} failed: {str(e)}"
                )
                self.client = None

                if attempt < self.retry_attempts - 1:
                    time.sleep(self.retry_delay)
                else:
                    logger.error(
                        f"Docker connection failed after {self.retry_attempts} attempts"
                    )
                    return False

        return False

    def disconnect(self) -> None:
        """Close Docker connection."""
        if self.client:
            self.client.close()
            self.client = None
        self._connected = False
        logger.info("Docker connection closed")

    def execute_command(self, command: str, **kwargs) -> ExecutionResult:
        """Execute command in Docker container.

        Args:
            command: Command to execute
            **kwargs: Additional parameters (container_name, timeout, etc.)

        Returns:
            ExecutionResult with standardized output
        """
        if not self._connected:
            return self._create_result(
                status=ExecutionStatus.CONNECTION_ERROR,
                success=False,
                error="Docker connection not established",
            )

        start_time = time.time()

        try:
            # Extract optional parameters
            container_name = kwargs.get("container_name")
            timeout = kwargs.get("timeout", self.timeout)

            if not container_name:
                return self._create_result(
                    status=ExecutionStatus.FAILURE,
                    success=False,
                    error="Container name is required for Docker command execution",
                )

            # Get container
            container = self.client.containers.get(container_name)

            # Execute command
            result = container.exec_run(command, timeout=timeout)

            duration = time.time() - start_time

            return self._create_result(
                status=ExecutionStatus.SUCCESS
                if result.exit_code == 0
                else ExecutionStatus.FAILURE,
                success=result.exit_code == 0,
                exit_code=result.exit_code,
                output=result.output.decode("utf-8") if result.output else None,
                error=None,
                duration=duration,
                metadata={
                    "command": command,
                    "container_name": container_name,
                    "timeout": timeout,
                },
            )

        except docker.errors.NotFound:
            duration = time.time() - start_time
            return self._create_result(
                status=ExecutionStatus.FAILURE,
                success=False,
                duration=duration,
                error=f"Container not found: {container_name}",
                metadata={"command": command, "container_name": container_name},
            )

        except docker.errors.APIError as e:
            duration = time.time() - start_time
            return self._create_result(
                status=ExecutionStatus.FAILURE,
                success=False,
                duration=duration,
                error=str(e),
                metadata={"command": command, "container_name": container_name},
            )

        except Exception as e:
            duration = time.time() - start_time
            return self._create_result(
                status=ExecutionStatus.FAILURE,
                success=False,
                duration=duration,
                error=str(e),
                metadata={"command": command, "container_name": container_name},
            )

    def get_container_info(self, container_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a container.

        Args:
            container_id: Container ID or name.

        Returns:
            Container information dictionary or None if not found.
        """
        if not self.client:
            return None

        try:
            container = self.client.containers.get(container_id)
            return {
                "id": container.id,
                "name": container.name,
                "status": container.status,
                "image": container.image.tags[0] if container.image.tags else "unknown",
                "created": container.attrs["Created"],
                "ports": container.attrs["NetworkSettings"]["Ports"],
                "env": container.attrs["Config"]["Env"],
                "mounts": container.attrs["Mounts"],
                "networks": container.attrs["NetworkSettings"]["Networks"],
            }

        except docker.errors.NotFound:
            logger.warning(f"Container not found: {container_id}")
            return None
        except Exception as e:
            logger.error(f"Failed to get container info: {str(e)}")
            return None

    def execute_container_command(
        self, container_id: str, command: str
    ) -> Dict[str, Any]:
        """Execute command inside a container.

        Args:
            container_id: Container ID or name.
            command: Command to execute.

        Returns:
            Dictionary with command execution results.
        """
        if not self.client:
            return {"success": False, "error": "Docker connection not established"}

        try:
            container = self.client.containers.get(container_id)

            # Execute command
            exec_result = container.exec_run(command)

            return {
                "success": exec_result.exit_code == 0,
                "exit_code": exec_result.exit_code,
                "output": exec_result.output.decode("utf-8").strip()
                if exec_result.output
                else "",
                "command": command,
            }

        except docker.errors.NotFound:
            return {"success": False, "error": f"Container not found: {container_id}"}
        except Exception as e:
            logger.error(f"Container command execution failed: {str(e)}")
            return {"success": False, "error": str(e)}

    def test_connection(self) -> bool:
        """Test Docker connection by pinging the daemon.

        Returns:
            True if connection test successful, False otherwise.
        """
        if not self.client:
            return False

        try:
            self.client.ping()
            return True
        except Exception:
            return False

    def disconnect(self) -> None:
        """Close Docker connection."""
        if self.client:
            self.client.close()
            self.client = None
            logger.info("Docker connection closed")

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
