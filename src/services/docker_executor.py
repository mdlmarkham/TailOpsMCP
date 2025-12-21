"""
Docker executor implementation for remote target operations.
"""

import logging
import time
from typing import Any, Dict, Optional

from src.services.executor import (
    Executor,
    ExecutionResult,
    ExecutionStatus,
    ExecutorConfig,
)

logger = logging.getLogger(__name__)

# Try to import docker, but make it optional
try:
    import docker
except ImportError:
    docker = None


class DockerExecutor(Executor):
    """Docker executor for remote target operations."""

    def __init__(self, config: ExecutorConfig):
        """Initialize Docker executor.

        Args:
            config: Executor configuration
        """
        super().__init__(config)
        self.socket_path = config.socket_path
        self.host = config.host
        self.tls_verify = config.additional_params.get("tls_verify", False)
        self.cert_path = config.additional_params.get("cert_path")
        self.client: Optional[docker.DockerClient] = None

    def is_available(self) -> bool:
        """Check if Docker executor is available.

        Returns:
            True if docker library is available and Docker daemon is running
        """
        if docker is None:
            return False

        # Try to connect and ping Docker daemon
        try:
            if self.socket_path:
                test_client = docker.DockerClient(base_url=f"unix://{self.socket_path}")
            elif self.host:
                test_client = docker.DockerClient(base_url=self.host)
            else:
                test_client = docker.from_env()

            test_client.ping()
            test_client.close()
            return True
        except Exception:
            return False

    def connect(self) -> bool:
        """Establish Docker connection to target.

        Returns:
            True if connection successful, False otherwise.
        """
        if docker is None:
            logger.error("docker library not available")
            return False

        for attempt in range(self.config.retry_attempts):
            try:
                if self.socket_path:
                    # Connect via Unix socket
                    self.client = docker.DockerClient(
                        base_url=f"unix://{self.socket_path}",
                        timeout=self.config.timeout,
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
                        base_url=self.host, timeout=self.config.timeout, tls=tls_config
                    )
                else:
                    # Use default Docker connection
                    self.client = docker.from_env(timeout=self.config.timeout)

                # Test connection
                self.client.ping()
                self._connected = True
                logger.info("Docker connection established")
                return True

            except Exception as e:
                logger.warning(
                    f"Docker connection attempt {attempt + 1} failed: {str(e)}"
                )
                self.client = None

                if attempt < self.config.retry_attempts - 1:
                    time.sleep(self.config.retry_delay)
                else:
                    logger.error(
                        f"Docker connection failed after {self.config.retry_attempts} attempts"
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
        if not self._connected or not self.client:
            return self._create_result(
                status=ExecutionStatus.CONNECTION_ERROR,
                success=False,
                error="Docker connection not established",
            )

        start_time = time.time()

        try:
            # Extract optional parameters
            container_name = kwargs.get("container_name")
            timeout = kwargs.get("timeout", self.config.timeout)

            if not container_name:
                return self._create_result(
                    status=ExecutionStatus.FAILURE,
                    success=False,
                    error="Container name is required for Docker command execution",
                )

            # Get container
            container = self.client.containers.get(container_name)

            # Execute command
            result = container.exec_run(command)

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

        except Exception as e:
            duration = time.time() - start_time
            error_msg = str(e)

            # Handle common Docker errors
            if "NotFound" in error_msg or "not found" in error_msg.lower():
                error_msg = f"Container not found: {container_name}"

            return self._create_result(
                status=ExecutionStatus.FAILURE,
                success=False,
                duration=duration,
                error=error_msg,
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
            image_tags = container.image.tags if container.image.tags else ["unknown"]
            return {
                "id": container.id,
                "name": container.name,
                "status": container.status,
                "image": image_tags[0],
                "created": container.attrs.get("Created"),
                "ports": container.attrs.get("NetworkSettings", {}).get("Ports", {}),
                "env": container.attrs.get("Config", {}).get("Env", []),
                "mounts": container.attrs.get("Mounts", []),
                "networks": container.attrs.get("NetworkSettings", {}).get(
                    "Networks", {}
                ),
            }

        except Exception as e:
            logger.warning(f"Container not found: {container_id}")
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
