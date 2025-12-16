"""
Mock Executor implementations for testing without external dependencies.
"""

from typing import Any, Dict

from src.services.executor import Executor, ExecutionResult, ExecutionStatus
from src.models.target_registry import ExecutorType


class MockExecutor(Executor):
    """Base mock executor with configurable behavior."""

    def __init__(
        self,
        executor_type: ExecutorType,
        connect_success: bool = True,
        command_success: bool = True,
        output: str = "Mock output",
        error: str = "",
        exit_code: int = 0,
        **kwargs,
    ):
        """Initialize mock executor.

        Args:
            executor_type: Type of executor being mocked
            connect_success: Whether connection should succeed
            command_success: Whether commands should succeed
            output: Default output for successful commands
            error: Default error for failed commands
            exit_code: Default exit code
            **kwargs: Additional configuration
        """
        super().__init__(**kwargs)
        self.executor_type = executor_type
        self.connect_success = connect_success
        self.command_success = command_success
        self.default_output = output
        self.default_error = error
        self.default_exit_code = exit_code
        self.command_history: list = []
        self.connection_attempts = 0

    def connect(self) -> bool:
        """Mock connection attempt."""
        self.connection_attempts += 1
        self._connected = self.connect_success
        return self.connect_success

    def disconnect(self) -> None:
        """Mock disconnection."""
        self._connected = False

    def execute_command(self, command: str, **kwargs) -> ExecutionResult:
        """Mock command execution."""
        self.command_history.append(
            {"command": command, "kwargs": kwargs, "timestamp": self.timestamp}
        )

        if not self._connected:
            return ExecutionResult(
                status=ExecutionStatus.CONNECTION_ERROR,
                success=False,
                error="Not connected",
                duration=0.0,
            )

        if self.command_success:
            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                success=True,
                exit_code=self.default_exit_code,
                output=self.default_output,
                error=self.default_error,
                duration=0.1,
            )
        else:
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                success=False,
                exit_code=1,
                output="",
                error=self.default_error or "Command failed",
                duration=0.1,
            )


class MockSSHExecutor(MockExecutor):
    """Mock SSH executor for testing SSH operations."""

    def __init__(self, host: str = "test.example.com", port: int = 22, **kwargs):
        """Initialize mock SSH executor.

        Args:
            host: Mock hostname
            port: Mock port
            **kwargs: Additional configuration
        """
        super().__init__(ExecutorType.SSH, **kwargs)
        self.host = host
        self.port = port
        self.file_transfers: list = []

    def upload_file(self, local_path: str, remote_path: str) -> ExecutionResult:
        """Mock file upload."""
        self.file_transfers.append(
            {
                "type": "upload",
                "local_path": local_path,
                "remote_path": remote_path,
                "timestamp": self.timestamp,
            }
        )

        return ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            success=True,
            output=f"Uploaded {local_path} to {remote_path}",
            duration=0.1,
        )

    def download_file(self, remote_path: str, local_path: str) -> ExecutionResult:
        """Mock file download."""
        self.file_transfers.append(
            {
                "type": "download",
                "remote_path": remote_path,
                "local_path": local_path,
                "timestamp": self.timestamp,
            }
        )

        return ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            success=True,
            output=f"Downloaded {remote_path} to {local_path}",
            duration=0.1,
        )


class MockDockerExecutor(MockExecutor):
    """Mock Docker executor for testing container operations."""

    def __init__(self, **kwargs):
        """Initialize mock Docker executor."""
        super().__init__(ExecutorType.DOCKER, **kwargs)
        self.containers: Dict[str, Dict] = {}
        self.images: Dict[str, Dict] = {}
        self.networks: Dict[str, Dict] = {}

    def list_containers(self) -> ExecutionResult:
        """Mock container listing."""
        container_list = list(self.containers.keys())
        return ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            success=True,
            output="\n".join(container_list),
            duration=0.1,
        )

    def run_container(self, image: str, **kwargs) -> ExecutionResult:
        """Mock container execution."""
        container_id = f"mock-container-{len(self.containers)}"
        self.containers[container_id] = {
            "image": image,
            "status": "running",
            "kwargs": kwargs,
        }

        return ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            success=True,
            output=container_id,
            duration=0.1,
        )


class MockHTTPExecutor(MockExecutor):
    """Mock HTTP executor for testing API operations."""

    def __init__(self, base_url: str = "http://localhost:8080", **kwargs):
        """Initialize mock HTTP executor.

        Args:
            base_url: Mock base URL
            **kwargs: Additional configuration
        """
        super().__init__(ExecutorType.HTTP, **kwargs)
        self.base_url = base_url
        self.requests: list = []
        self.responses: Dict[str, Any] = {}

    def set_response(self, path: str, method: str, response: Dict[str, Any]):
        """Set mock response for specific endpoint.

        Args:
            path: API path
            method: HTTP method
            response: Mock response data
        """
        key = f"{method}:{path}"
        self.responses[key] = response

    def execute_command(self, command: str, **kwargs) -> ExecutionResult:
        """Mock HTTP request execution."""
        # Parse command as HTTP request
        method = kwargs.get("method", "GET")
        path = kwargs.get("path", "/")

        self.requests.append(
            {
                "method": method,
                "path": path,
                "command": command,
                "kwargs": kwargs,
                "timestamp": self.timestamp,
            }
        )

        # Check for predefined response
        key = f"{method}:{path}"
        if key in self.responses:
            response = self.responses[key]
            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                success=True,
                output=str(response),
                duration=0.1,
            )

        # Default response
        return ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            success=True,
            output=f"Mock HTTP response for {method} {path}",
            duration=0.1,
        )


class MockLocalExecutor(MockExecutor):
    """Mock local executor for testing local operations."""

    def __init__(self, **kwargs):
        """Initialize mock local executor."""
        super().__init__(ExecutorType.LOCAL, **kwargs)
        self.filesystem: Dict[str, str] = {}
        self.processes: list = []

    def read_file(self, path: str) -> ExecutionResult:
        """Mock file reading."""
        if path in self.filesystem:
            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                success=True,
                output=self.filesystem[path],
                duration=0.1,
            )
        else:
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                success=False,
                error=f"File not found: {path}",
                duration=0.1,
            )

    def write_file(self, path: str, content: str) -> ExecutionResult:
        """Mock file writing."""
        self.filesystem[path] = content
        return ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            success=True,
            output=f"Written {len(content)} bytes to {path}",
            duration=0.1,
        )


class MockProxmoxExecutor(MockExecutor):
    """Mock Proxmox executor for testing virtualization operations."""

    def __init__(self, host: str = "proxmox.example.com", **kwargs):
        """Initialize mock Proxmox executor.

        Args:
            host: Mock Proxmox host
            **kwargs: Additional configuration
        """
        super().__init__(ExecutorType.PROXMOX, **kwargs)
        self.host = host
        self.vms: Dict[str, Dict] = {}
        self.containers: Dict[str, Dict] = {}
        self.nodes: list = ["node1", "node2"]

    def list_vms(self) -> ExecutionResult:
        """Mock VM listing."""
        vm_list = list(self.vms.keys())
        return ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            success=True,
            output="\n".join(vm_list),
            duration=0.1,
        )

    def start_vm(self, vm_id: str) -> ExecutionResult:
        """Mock VM start."""
        if vm_id in self.vms:
            self.vms[vm_id]["status"] = "running"
            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                success=True,
                output=f"VM {vm_id} started",
                duration=0.1,
            )
        else:
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                success=False,
                error=f"VM not found: {vm_id}",
                duration=0.1,
            )


def create_mock_executor(executor_type: ExecutorType, **kwargs) -> MockExecutor:
    """Factory function to create mock executors.

    Args:
        executor_type: Type of executor to mock
        **kwargs: Configuration for the mock executor

    Returns:
        Configured mock executor instance
    """
    executor_map = {
        ExecutorType.SSH: MockSSHExecutor,
        ExecutorType.DOCKER: MockDockerExecutor,
        ExecutorType.HTTP: MockHTTPExecutor,
        ExecutorType.LOCAL: MockLocalExecutor,
        ExecutorType.PROXMOX: MockProxmoxExecutor,
    }

    if executor_type not in executor_map:
        raise ValueError(f"Unsupported executor type: {executor_type}")

    return executor_map[executor_type](**kwargs)
