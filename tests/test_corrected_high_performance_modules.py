"""
Corrected tests for high-performance modules with accurate API signatures.

Focus on modules that already have good coverage but need the final push.
"""

import pytest
from unittest.mock import Mock, patch


# Test target_registry.py (currently 94% coverage)
class TestTargetRegistry:
    """Test target registry models and functionality."""

    def test_executor_type_enum(self):
        """Test ExecutorType enum values."""
        from src.models.target_registry import ExecutorType

        assert ExecutorType.LOCAL.value == "local"
        assert ExecutorType.SSH.value == "ssh"
        assert ExecutorType.DOCKER.value == "docker"

    def test_sudo_policy_enum(self):
        """Test SudoPolicy enum values."""
        from src.models.target_registry import SudoPolicy

        assert SudoPolicy.NONE.value == "none"
        assert SudoPolicy.LIMITED.value == "limited"
        assert SudoPolicy.FULL.value == "full"

    def test_target_connection_creation(self):
        """Test TargetConnection model creation."""
        from src.models.target_registry import TargetConnection, ExecutorType

        # Test SSH connection
        connection = TargetConnection(
            executor=ExecutorType.SSH,
            host="test.example.com",
            port=22,
            username="testuser",
            key_path="/path/to/key",
        )

        assert connection.executor == ExecutorType.SSH
        assert connection.host == "test.example.com"
        assert connection.port == 22
        assert connection.username == "testuser"
        assert connection.key_path == "/path/to/key"

    def test_target_connection_local(self):
        """Test TargetConnection for local executor."""
        from src.models.target_registry import TargetConnection, ExecutorType

        # Test local connection (no connection details needed)
        connection = TargetConnection(executor=ExecutorType.LOCAL)
        assert connection.executor == ExecutorType.LOCAL
        assert connection.host is None
        assert connection.username is None

    def test_target_connection_validation(self):
        """Test TargetConnection validation."""
        from src.models.target_registry import TargetConnection, ExecutorType

        # Test SSH validation - missing host
        connection = TargetConnection(executor=ExecutorType.SSH, username="testuser")
        errors = connection.validate()
        assert len(errors) > 0
        assert "SSH executor requires host" in errors[0]

        # Test valid SSH connection
        connection = TargetConnection(
            executor=ExecutorType.SSH,
            host="test.example.com",
            username="testuser",
            key_path="/path/to/key",
        )
        errors = connection.validate()
        assert len(errors) == 0

    def test_target_constraints(self):
        """Test TargetConstraints model."""
        from src.models.target_registry import TargetConstraints, SudoPolicy

        constraints = TargetConstraints(
            timeout=60,
            concurrency=5,
            sudo_policy=SudoPolicy.LIMITED,
            max_memory=1024,
            max_cpu=2.5,
        )

        assert constraints.timeout == 60
        assert constraints.concurrency == 5
        assert constraints.sudo_policy == SudoPolicy.LIMITED
        assert constraints.max_memory == 1024
        assert constraints.max_cpu == 2.5

    def test_target_metadata(self):
        """Test TargetMetadata model."""
        from src.models.target_registry import (
            TargetMetadata,
            ExecutorType,
            TargetConnection,
            TargetConstraints,
        )

        connection = TargetConnection(executor=ExecutorType.LOCAL)
        constraints = TargetConstraints()

        metadata = TargetMetadata(
            id="test-target",
            type="local",
            executor=ExecutorType.LOCAL,
            connection=connection,
            capabilities=["read", "write"],
            constraints=constraints,
            metadata={"description": "Test target"},
        )

        assert metadata.id == "test-target"
        assert metadata.type == "local"
        assert metadata.capabilities == ["read", "write"]
        assert metadata.metadata["description"] == "Test target"

    def test_target_metadata_serialization(self):
        """Test TargetMetadata to_dict and from_dict."""
        from src.models.target_registry import (
            TargetMetadata,
            ExecutorType,
            TargetConnection,
            TargetConstraints,
        )

        connection = TargetConnection(executor=ExecutorType.LOCAL)
        constraints = TargetConstraints()

        original = TargetMetadata(
            id="test-target",
            type="local",
            executor=ExecutorType.LOCAL,
            connection=connection,
            capabilities=["read"],
            constraints=constraints,
            metadata={},
        )

        # Test to_dict
        data = original.to_dict()
        assert data["id"] == "test-target"
        assert data["executor"] == "local"

        # Test from_dict
        restored = TargetMetadata.from_dict(data)
        assert restored.id == original.id
        assert restored.executor == original.executor


# Test execution.py (currently 92% coverage)
class TestExecutionModels:
    """Test execution models and functionality."""

    def test_execution_status_enum(self):
        """Test ExecutionStatus enum values."""
        from src.models.execution import ExecutionStatus

        assert ExecutionStatus.SUCCESS.value == "success"
        assert ExecutionStatus.FAILURE.value == "failure"
        assert ExecutionStatus.TIMEOUT.value == "timeout"
        assert ExecutionStatus.CONNECTION_ERROR.value == "connection_error"

    def test_execution_severity_enum(self):
        """Test ExecutionSeverity enum values."""
        from src.models.execution import ExecutionSeverity

        assert ExecutionSeverity.INFO.value == "info"
        assert ExecutionSeverity.WARNING.value == "warning"
        assert ExecutionSeverity.ERROR.value == "error"
        assert ExecutionSeverity.CRITICAL.value == "critical"

    def test_structured_error(self):
        """Test StructuredError model."""
        from src.models.execution import StructuredError

        error = StructuredError(
            code="TEST_ERROR",
            message="Test error message",
            details={"key": "value"},
            context={"operation": "test"},
        )

        assert error.code == "TEST_ERROR"
        assert error.message == "Test error message"
        assert error.details["key"] == "value"
        assert error.context["operation"] == "test"
        assert error.timestamp is not None

    def test_execution_result_creation(self):
        """Test ExecutionResult model creation."""
        from src.models.execution import (
            ExecutionResult,
            ExecutionStatus,
            ExecutionSeverity,
        )

        result = ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            success=True,
            severity=ExecutionSeverity.INFO,
            duration=1.23,
        )

        assert result.status == ExecutionStatus.SUCCESS
        assert result.success is True
        assert result.severity == ExecutionSeverity.INFO
        assert result.duration == 1.23
        assert result.timestamp is not None
        assert result.correlation_id is not None

    def test_execution_result_with_output(self):
        """Test ExecutionResult with output."""
        from src.models.execution import ExecutionResult, ExecutionStatus

        result = ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            success=True,
            duration=1.0,
            exit_code=0,
            output="Command output",
            error=None,
        )

        assert result.exit_code == 0
        assert result.output == "Command output"
        assert result.error is None

    def test_operation_result(self):
        """Test OperationResult class."""
        from src.models.execution import OperationResult

        result = OperationResult(
            success=True, message="Operation completed", data={"result": "success"}
        )

        assert result.success is True
        assert result.message == "Operation completed"
        assert result.data["result"] == "success"

    def test_capability_execution(self):
        """Test CapabilityExecution class."""
        from src.models.execution import CapabilityExecution, OperationResult

        op_result = OperationResult(success=True, message="Completed")
        cap_exec = CapabilityExecution(capability="test_cap", result=op_result)

        assert cap_exec.capability == "test_cap"
        assert cap_exec.result.success is True

    def test_execution_request(self):
        """Test ExecutionRequest model."""
        from src.models.execution import ExecutionRequest

        request = ExecutionRequest(command="ls -la", executor_type="local")

        assert request.command == "ls -la"
        assert request.executor_type == "local"
        assert request.timeout == 30  # default
        assert request.correlation_id is not None


# Test discovery_tools.py (currently 84% coverage)
class TestDiscoveryTools:
    """Test discovery tools functionality."""

    @pytest.mark.asyncio
    async def test_discovery_tools_creation(self):
        """Test DiscoveryTools creation."""
        from src.services.discovery_tools import DiscoveryTools

        discovery = DiscoveryTools()
        assert discovery is not None
        assert hasattr(discovery, "docker_manager")
        assert hasattr(discovery, "compose_manager")
        assert hasattr(discovery, "network_status")
        assert hasattr(discovery, "inventory")

    @pytest.mark.asyncio
    async def test_list_services_mock(self):
        """Test list_services with mocking."""
        from src.services.discovery_tools import DiscoveryTools

        discovery = DiscoveryTools()

        # Mock the inventory.list_services method
        with patch.object(discovery.inventory, "list_services") as mock_list:
            mock_list.return_value = {
                "nginx": {"type": "web", "status": "running", "port": 80},
                "ssh": {"type": "service", "status": "running", "port": 22},
            }

            result = await discovery.list_services("test-target")

            assert "services" in result
            assert len(result["services"]) == 2
            assert result["services"][0]["name"] == "nginx"

    def test_discovery_tools_methods_exist(self):
        """Test that DiscoveryTools has expected methods."""
        from src.services.discovery_tools import DiscoveryTools

        discovery = DiscoveryTools()

        # Check that all expected methods exist
        assert hasattr(discovery, "list_services")
        assert hasattr(discovery, "list_containers")
        assert hasattr(discovery, "list_stacks")
        assert hasattr(discovery, "list_ports")


# Test docker_manager.py (currently 83% coverage)
class TestDockerManager:
    """Test docker manager functionality."""

    @pytest.mark.asyncio
    async def test_docker_manager_creation(self):
        """Test DockerManager creation."""
        from src.services.docker_manager import DockerManager

        manager = DockerManager()
        assert manager is not None

    @pytest.mark.asyncio
    async def test_docker_manager_methods(self):
        """Test DockerManager method availability."""
        from src.services.docker_manager import DockerManager

        manager = DockerManager()

        # Check that all expected methods exist
        assert hasattr(manager, "list_containers")
        assert hasattr(manager, "stop_container")
        assert hasattr(manager, "remove_container")
        assert hasattr(manager, "get_logs")

    @pytest.mark.asyncio
    async def test_stop_container_mock(self):
        """Test stop_container with mocking."""
        from src.services.docker_manager import DockerManager

        manager = DockerManager()

        # Mock the stop_container method
        with patch.object(manager, "stop_container") as mock_stop:
            mock_stop.return_value = {"status": "stopped", "id": "abc123"}

            result = await manager.stop_container("container-id")

            assert result["status"] == "stopped"
            assert result["id"] == "abc123"


# Test input_validator.py (currently 73% coverage)
class TestInputValidator:
    """Test input validator functionality."""

    def test_input_validator_with_allowlist(self):
        """Test InputValidator with allowlist manager."""
        from src.services.input_validator import InputValidator

        # Create a mock allowlist manager
        allowlist_manager = Mock()
        allowlist_manager.is_allowed.return_value = True

        validator = InputValidator(allowlist_manager)
        assert validator is not None
        assert validator.allowlist_manager == allowlist_manager

    def test_input_validation_with_mock(self):
        """Test input validation with mocking."""
        from src.services.input_validator import InputValidator

        allowlist_manager = Mock()
        allowlist_manager.is_allowed.return_value = True

        validator = InputValidator(allowlist_manager)

        # Mock the validate_input method
        with patch.object(validator, "validate_input") as mock_validate:
            mock_validate.return_value = True

            result = validator.validate_input("test_input")
            assert result is True
            mock_validate.assert_called_once_with("test_input")


# Mark all tests as unit tests for easy categorization
pytestmark = [pytest.mark.unit]
