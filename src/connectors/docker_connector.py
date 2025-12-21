"""
Docker Connector for Container Operations

Provides comprehensive Docker daemon access via SSH port forwarding without requiring agent installation.
Supports container management, logs, stats, and image operations.
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from datetime import timezone, timezone
from dataclasses import dataclass

from src.connectors.remote_agent_connector import (
    RemoteAgentConnector,
    DockerContainer,
    ContainerStats,
    OperationResult,
)
from src.services.remote_operation_executor import (
    ResilientRemoteOperation,
    resilient_operation,
    OperationType,
)
from src.utils.errors import SystemManagerError


logger = logging.getLogger(__name__)


@dataclass
class DockerImage:
    """Docker image information."""

    repository: str
    tag: str
    image_id: str
    created: datetime
    size: int
    virtual_size: Optional[int]
    architecture: str
    os: str
    docker_version: str


@dataclass
class DockerVolume:
    """Docker volume information."""

    name: str
    driver: str
    mountpoint: str
    created_at: datetime
    status: Dict[str, Any]
    labels: Dict[str, str]
    scope: str


@dataclass
class DockerNetwork:
    """Docker network information."""

    name: str
    id: str
    driver: str
    subnet: Optional[str]
    gateway: Optional[str]
    created: datetime
    ipam: Dict[str, Any]
    containers: List[str]
    options: Dict[str, str]


@dataclass
class ContainerResourceStats:
    """Container resource usage statistics."""

    container_id: str
    cpu_percentage: float
    memory_usage: int
    memory_limit: int
    memory_percentage: float
    network_rx_bytes: int
    network_tx_bytes: int
    block_read_bytes: int
    block_write_bytes: int
    pid: int
    timestamp: datetime


class DockerConnector(RemoteAgentConnector):
    """Docker daemon access via SSH port forwarding.

    Provides agent-like Docker functionality without requiring agent installation.
    Supports container management, logs, stats, and image operations.
    """

    def __init__(self, target, connection):
        """Initialize docker connector.

        Args:
            target: Target connection configuration
            connection: SSH connection instance
        """
        super().__init__(target, connection)
        self.executor = ResilientRemoteOperation()
        self._docker_timeout = 30
        self._docker_port = 2376  # Default Docker TLS port
        self._local_docker_port = 23760  # Local port for SSH tunneling
        self._active_forwarding = {}

    async def get_capabilities(self) -> Dict[str, Any]:
        """Get docker connector capabilities.

        Returns:
            Dictionary of available capabilities
        """
        try:
            # Check if docker is available
            result = await self.execute_command("which docker")
            if result.exit_code != 0:
                return {"available": False, "reason": "docker not found"}

            # Check docker daemon access
            result = await self.execute_command(
                "docker version --format json", timeout=10
            )
            if result.exit_code != 0:
                return {
                    "available": True,
                    "permissions": "limited",
                    "reason": "Limited docker daemon access",
                }

            # Parse docker version info
            version_info = json.loads(result.stdout)
            server_version = version_info.get("Server", {}).get("Version", "unknown")

            return {
                "available": True,
                "permissions": "full",
                "supports_container_management": True,
                "supports_image_operations": True,
                "supports_volume_operations": True,
                "supports_network_operations": True,
                "server_version": server_version,
                "requires_port_forwarding": True,
                "docker_socket": "/var/run/docker.sock",
            }

        except Exception as e:
            return {"available": False, "error": str(e)}

    async def validate_target(self) -> bool:
        """Validate that target supports docker operations.

        Returns:
            True if target is valid for docker operations
        """
        try:
            capabilities = await self.get_capabilities()
            return capabilities.get("available", False)
        except Exception:
            return False

    async def _ensure_port_forwarding(self) -> bool:
        """Ensure Docker port forwarding is active.

        Returns:
            True if port forwarding is established
        """
        if self._local_docker_port in self._active_forwarding:
            return True

        try:
            # Create SSH tunnel to Docker socket
            forward_result = await self.connection.port_forward(
                self._local_docker_port, "localhost", self._docker_port
            )

            self._active_forwarding[self._local_docker_port] = forward_result

            # Wait a moment for tunnel to establish
            await asyncio.sleep(1)

            # Test connection
            test_cmd = (
                f"DOCKER_HOST=tcp://localhost:{self._local_docker_port} docker info"
            )
            result = await self.execute_command(test_cmd, timeout=10)

            return result.exit_code == 0

        except Exception as e:
            logger.error(f"Failed to establish Docker port forwarding: {str(e)}")
            return False

    def _get_docker_command(self) -> str:
        """Get docker command with proper host configuration.

        Returns:
            Docker command with host configuration
        """
        return f"DOCKER_HOST=tcp://localhost:{self._local_docker_port} docker"

    @resilient_operation(
        operation_type=OperationType.CONTAINER_OPERATION,
        operation_name="list_containers",
    )
    async def list_containers(
        self, all_containers: bool = False
    ) -> List[DockerContainer]:
        """List Docker containers.

        Args:
            all_containers: Include stopped containers

        Returns:
            List of Docker containers
        """
        if not await self._ensure_port_forwarding():
            raise SystemManagerError("Failed to establish Docker port forwarding")

        cmd = f"{self._get_docker_command()} ps {'--all' if all_containers else ''} --format json"

        try:
            result = await self.execute_command(cmd, timeout=60)

            if result.exit_code != 0:
                raise SystemManagerError(f"Failed to list containers: {result.stderr}")

            containers = []

            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue

                try:
                    container_data = json.loads(line)

                    # Parse created timestamp
                    created_str = container_data.get("Created", "")
                    created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))

                    containers.append(
                        DockerContainer(
                            container_id=container_data.get("ID", ""),
                            name=container_data.get("Names", "").lstrip("/"),
                            status=container_data.get("Status", ""),
                            image=container_data.get("Image", ""),
                            ports=container_data.get("Ports", []),
                            created=created,
                            state=container_data.get("State", ""),
                        )
                    )

                except Exception as e:
                    logger.warning(f"Failed to parse container data: {str(e)}")
                    continue

            return containers

        except Exception as e:
            logger.error(f"Failed to list containers: {str(e)}")
            raise

    @resilient_operation(
        operation_type=OperationType.CONTAINER_OPERATION,
        operation_name="get_container_logs",
    )
    async def get_container_logs(
        self,
        container_id: str,
        lines: int = 100,
        since: Optional[str] = None,
        tail: Optional[str] = None,
        follow: bool = False,
    ) -> str:
        """Get container logs.

        Args:
            container_id: Container ID or name
            lines: Number of lines to retrieve
            since: Show logs since timestamp
            tail: Show last N lines
            follow: Follow logs in real-time

        Returns:
            Container logs as string
        """
        if not await self._ensure_port_forwarding():
            raise SystemManagerError("Failed to establish Docker port forwarding")

        cmd_parts = [self._get_docker_command(), "logs"]

        if since:
            cmd_parts.extend(["--since", since])

        if tail:
            cmd_parts.extend(["--tail", tail])
        else:
            cmd_parts.extend(["--lines", str(lines)])

        if follow:
            cmd_parts.append("--follow")

        cmd_parts.append(container_id)

        command = " ".join(cmd_parts)

        try:
            result = await self.execute_command(command, timeout=120 if follow else 60)

            if result.exit_code != 0:
                raise SystemManagerError(
                    f"Failed to get container logs: {result.stderr}"
                )

            return result.stdout

        except Exception as e:
            logger.error(f"Failed to get logs for container {container_id}: {str(e)}")
            raise

    @resilient_operation(
        operation_type=OperationType.CONTAINER_OPERATION,
        operation_name="restart_container",
    )
    async def restart_container(
        self, container_id: str, timeout: int = 30
    ) -> OperationResult:
        """Restart a Docker container.

        Args:
            container_id: Container ID or name
            timeout: Restart timeout in seconds

        Returns:
            Operation result
        """
        if not await self._ensure_port_forwarding():
            raise SystemManagerError("Failed to establish Docker port forwarding")

        cmd = f"{self._get_docker_command()} restart {container_id}"

        try:
            result = await self.execute_command(cmd, timeout=timeout)

            if result.exit_code == 0:
                return OperationResult(
                    operation="restart_container",
                    target=container_id,
                    success=True,
                    result="Container restarted successfully",
                    timestamp=datetime.now(timezone.utc),
                )
            else:
                return OperationResult(
                    operation="restart_container",
                    target=container_id,
                    success=False,
                    error=result.stderr,
                    timestamp=datetime.now(timezone.utc),
                )

        except Exception as e:
            return OperationResult(
                operation="restart_container",
                target=container_id,
                success=False,
                error=str(e),
                timestamp=datetime.now(timezone.utc),
            )

    @resilient_operation(
        operation_type=OperationType.CONTAINER_OPERATION,
        operation_name="start_container",
    )
    async def start_container(
        self, container_id: str, timeout: int = 30
    ) -> OperationResult:
        """Start a Docker container.

        Args:
            container_id: Container ID or name
            timeout: Start timeout in seconds

        Returns:
            Operation result
        """
        if not await self._ensure_port_forwarding():
            raise SystemManagerError("Failed to establish Docker port forwarding")

        cmd = f"{self._get_docker_command()} start {container_id}"

        try:
            result = await self.execute_command(cmd, timeout=timeout)

            if result.exit_code == 0:
                return OperationResult(
                    operation="start_container",
                    target=container_id,
                    success=True,
                    result="Container started successfully",
                    timestamp=datetime.now(timezone.utc),
                )
            else:
                return OperationResult(
                    operation="start_container",
                    target=container_id,
                    success=False,
                    error=result.stderr,
                    timestamp=datetime.now(timezone.utc),
                )

        except Exception as e:
            return OperationResult(
                operation="start_container",
                target=container_id,
                success=False,
                error=str(e),
                timestamp=datetime.now(timezone.utc),
            )

    @resilient_operation(
        operation_type=OperationType.CONTAINER_OPERATION,
        operation_name="stop_container",
    )
    async def stop_container(
        self, container_id: str, timeout: int = 30
    ) -> OperationResult:
        """Stop a Docker container.

        Args:
            container_id: Container ID or name
            timeout: Stop timeout in seconds

        Returns:
            Operation result
        """
        if not await self._ensure_port_forwarding():
            raise SystemManagerError("Failed to establish Docker port forwarding")

        cmd = f"{self._get_docker_command()} stop --time {timeout} {container_id}"

        try:
            result = await self.execute_command(cmd, timeout=timeout + 10)

            if result.exit_code == 0:
                return OperationResult(
                    operation="stop_container",
                    target=container_id,
                    success=True,
                    result="Container stopped successfully",
                    timestamp=datetime.now(timezone.utc),
                )
            else:
                return OperationResult(
                    operation="stop_container",
                    target=container_id,
                    success=False,
                    error=result.stderr,
                    timestamp=datetime.now(timezone.utc),
                )

        except Exception as e:
            return OperationResult(
                operation="stop_container",
                target=container_id,
                success=False,
                error=str(e),
                timestamp=datetime.now(timezone.utc),
            )

    @resilient_operation(
        operation_type=OperationType.CONTAINER_OPERATION,
        operation_name="get_container_stats",
    )
    async def get_container_stats(self, container_id: str) -> ContainerStats:
        """Get container statistics.

        Args:
            container_id: Container ID or name

        Returns:
            Container statistics
        """
        if not await self._ensure_port_forwarding():
            raise SystemManagerError("Failed to establish Docker port forwarding")

        cmd = f"{self._get_docker_command()} stats {container_id} --no-stream --format json"

        try:
            result = await self.execute_command(cmd, timeout=30)

            if result.exit_code != 0:
                raise SystemManagerError(
                    f"Failed to get container stats: {result.stderr}"
                )

            # Parse stats JSON
            stats_data = json.loads(result.stdout.strip())

            # Parse network I/O
            network_io = stats_data.get("net_io", {})
            network_rx = int(network_io.get("rx_bytes", 0))
            network_tx = int(network_io.get("tx_bytes", 0))

            # Parse block I/O
            block_io = stats_data.get("blkio", {})
            block_read = int(
                block_io.get("io_service_bytes_recursive", [{}])[0].get("value", 0)
            )
            block_write = int(
                block_io.get("io_service_bytes_recursive", [{}])[1].get("value", 0)
            )

            return ContainerStats(
                container_id=container_id,
                cpu_usage=float(stats_data.get("cpu_percentage", "0").rstrip("%")),
                memory_usage=int(stats_data.get("mem_usage", "0").rstrip("MiB"))
                * 1024
                * 1024,
                memory_limit=int(stats_data.get("mem_limit", "0").rstrip("MiB"))
                * 1024
                * 1024,
                network_io={"rx": network_rx, "tx": network_tx},
                block_io={"read": block_read, "write": block_write},
                pid=int(stats_data.get("pid", 0)),
            )

        except Exception as e:
            logger.error(f"Failed to get stats for container {container_id}: {str(e)}")
            raise

    async def list_images(self) -> List[DockerImage]:
        """List Docker images.

        Returns:
            List of Docker images
        """
        if not await self._ensure_port_forwarding():
            raise SystemManagerError("Failed to establish Docker port forwarding")

        cmd = f"{self._get_docker_command()} images --format json"

        try:
            result = await self.execute_command(cmd, timeout=60)

            if result.exit_code != 0:
                raise SystemManagerError(f"Failed to list images: {result.stderr}")

            images = []

            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue

                try:
                    image_data = json.loads(line)

                    # Parse created timestamp
                    created_str = image_data.get("Created", "")
                    created = datetime.fromtimestamp(int(created_str))

                    images.append(
                        DockerImage(
                            repository=image_data.get("Repository", ""),
                            tag=image_data.get("Tag", ""),
                            image_id=image_data.get("ID", ""),
                            created=created,
                            size=int(image_data.get("Size", "0").rstrip("B")),
                            virtual_size=int(image_data.get("VirtualSize", "0")),
                            architecture=image_data.get("Architecture", "unknown"),
                            os=image_data.get("Os", "unknown"),
                            docker_version=image_data.get("DockerVersion", "unknown"),
                        )
                    )

                except Exception as e:
                    logger.warning(f"Failed to parse image data: {str(e)}")
                    continue

            return images

        except Exception as e:
            logger.error(f"Failed to list images: {str(e)}")
            raise

    async def get_container_resource_stats(
        self, container_id: str
    ) -> ContainerResourceStats:
        """Get detailed container resource statistics.

        Args:
            container_id: Container ID or name

        Returns:
            Container resource statistics
        """
        if not await self._ensure_port_forwarding():
            raise SystemManagerError("Failed to establish Docker port forwarding")

        cmd = f"{self._get_docker_command()} stats {container_id} --no-stream --format json"

        try:
            result = await self.execute_command(cmd, timeout=30)

            if result.exit_code != 0:
                raise SystemManagerError(
                    f"Failed to get container stats: {result.stderr}"
                )

            stats_data = json.loads(result.stdout.strip())

            # Parse memory usage and limit
            mem_usage_str = stats_data.get("mem_usage", "0")
            mem_limit_str = stats_data.get("mem_limit", "0")

            def parse_memory(mem_str):
                if "GiB" in mem_str:
                    return int(float(mem_str.split()[0]) * 1024 * 1024 * 1024)
                elif "MiB" in mem_str:
                    return int(float(mem_str.split()[0]) * 1024 * 1024)
                elif "KiB" in mem_str:
                    return int(float(mem_str.split()[0]) * 1024)
                else:
                    return int(mem_str.split()[0])

            memory_usage = parse_memory(mem_usage_str)
            memory_limit = parse_memory(mem_limit_str)

            # Calculate memory percentage
            memory_percentage = (
                (memory_usage / memory_limit * 100) if memory_limit > 0 else 0
            )

            # Parse network I/O
            network_io = stats_data.get("net_io", {})
            network_rx_bytes = int(network_io.get("rx_bytes", 0))
            network_tx_bytes = int(network_io.get("tx_bytes", 0))

            # Parse block I/O
            block_io = stats_data.get("blkio", {})
            block_read_bytes = 0
            block_write_bytes = 0

            if "io_service_bytes_recursive" in block_io:
                for entry in block_io["io_service_bytes_recursive"]:
                    if entry.get("op") == "Read":
                        block_read_bytes += int(entry.get("value", 0))
                    elif entry.get("op") == "Write":
                        block_write_bytes += int(entry.get("value", 0))

            # Parse CPU usage
            cpu_percentage_str = stats_data.get("cpu_percentage", "0")
            cpu_percentage = float(cpu_percentage_str.rstrip("%"))

            return ContainerResourceStats(
                container_id=container_id,
                cpu_percentage=cpu_percentage,
                memory_usage=memory_usage,
                memory_limit=memory_limit,
                memory_percentage=memory_percentage,
                network_rx_bytes=network_rx_bytes,
                network_tx_bytes=network_tx_bytes,
                block_read_bytes=block_read_bytes,
                block_write_bytes=block_write_bytes,
                pid=int(stats_data.get("pid", 0)),
                timestamp=datetime.now(timezone.utc),
            )

        except Exception as e:
            logger.error(
                f"Failed to get resource stats for container {container_id}: {str(e)}"
            )
            raise

    async def execute_container_command(
        self, container_id: str, command: str, timeout: int = 30
    ) -> str:
        """Execute command in running container.

        Args:
            container_id: Container ID or name
            command: Command to execute
            timeout: Command timeout

        Returns:
            Command output
        """
        if not await self._ensure_port_forwarding():
            raise SystemManagerError("Failed to establish Docker port forwarding")

        cmd = f"{self._get_docker_command()} exec {container_id} {command}"

        try:
            result = await self.execute_command(cmd, timeout=timeout)

            if result.exit_code != 0:
                raise SystemManagerError(
                    f"Failed to execute command in container: {result.stderr}"
                )

            return result.stdout

        except Exception as e:
            logger.error(
                f"Failed to execute command in container {container_id}: {str(e)}"
            )
            raise

    async def cleanup_docker_resources(self) -> Dict[str, Any]:
        """Clean up unused Docker resources.

        Returns:
            Cleanup results
        """
        if not await self._ensure_port_forwarding():
            raise SystemManagerError("Failed to establish Docker port forwarding")

        cleanup_commands = [
            f"{self._get_docker_command()} system prune -f",
            f"{self._get_docker_command()} image prune -f",
            f"{self._get_docker_command()} container prune -f",
            f"{self._get_docker_command()} network prune -f",
        ]

        results = {}

        for cmd in cleanup_commands:
            try:
                result = await self.execute_command(cmd, timeout=120)

                command_name = cmd.split()[-1]  # Get the last part (prune command)
                results[command_name] = {
                    "success": result.exit_code == 0,
                    "output": result.stdout,
                    "error": result.stderr if result.exit_code != 0 else None,
                }

            except Exception as e:
                results[cmd.split()[-1]] = {"success": False, "error": str(e)}

        return results

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Clean up port forwarding on exit."""
        try:
            # Close any active port forwarding
            for port, forward_result in self._active_forwarding.items():
                await self.connection.close_port_forward(forward_result.connection_id)

            self._active_forwarding.clear()

        except Exception as e:
            logger.error(f"Error during Docker connector cleanup: {str(e)}")

        # Call parent exit
        await super().__aexit__(exc_type, exc_val, exc_tb)
