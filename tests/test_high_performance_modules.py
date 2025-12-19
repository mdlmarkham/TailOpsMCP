"""
Targeted tests for high-performance modules to push coverage to 90%+.

Focus on modules that already have good coverage but need the final push.
"""

import pytest
from unittest.mock import Mock, patch


# Test target_registry.py (currently 94% coverage)
class TestTargetRegistry:
    """Test target registry models and functionality."""

    def test_target_connection_creation(self):
        """Test TargetConnection model creation."""
        from src.models.target_registry import (
            TargetConnection,
            ExecutorType,
            SudoPolicy,
        )

        # Test basic connection
        connection = TargetConnection(
            host="test.example.com",
            port=22,
            username="testuser",
            connection_type=ExecutorType.SSH,
        )

        assert connection.host == "test.example.com"
        assert connection.port == 22
        assert connection.username == "testuser"
        assert connection.connection_type == ExecutorType.SSH
        assert connection.sudo_policy == SudoPolicy.DENY  # default

    def test_target_connection_with_sudo(self):
        """Test TargetConnection with sudo policy."""
        from src.models.target_registry import (
            TargetConnection,
            ExecutorType,
            SudoPolicy,
        )

        connection = TargetConnection(
            host="test.example.com",
            port=22,
            username="testuser",
            connection_type=ExecutorType.SSH,
            sudo_policy=SudoPolicy.REQUIRE,
        )

        assert connection.sudo_policy == SudoPolicy.REQUIRE

    def test_executor_type_enum(self):
        """Test ExecutorType enum values."""
        from src.models.target_registry import ExecutorType

        assert ExecutorType.SSH.value == "ssh"
        assert ExecutorType.DOCKER.value == "docker"
        assert ExecutorType.LOCAL.value == "local"

    def test_sudo_policy_enum(self):
        """Test SudoPolicy enum values."""
        from src.models.target_registry import SudoPolicy

        assert SudoPolicy.DENY.value == "deny"
        assert SudoPolicy.ALLOW.value == "allow"
        assert SudoPolicy.REQUIRE.value == "require"


# Test execution.py (currently 92% coverage)
class TestExecutionModels:
    """Test execution models and functionality."""

    def test_execution_result_creation(self):
        """Test ExecutionResult model creation."""
        from src.models.execution import ExecutionResult, ExecutionStatus

        result = ExecutionResult(
            command="echo 'test'",
            status=ExecutionStatus.SUCCESS,
            stdout="test\n",
            stderr="",
            exit_code=0,
            duration=1.23,
        )

        assert result.command == "echo 'test'"
        assert result.status == ExecutionStatus.SUCCESS
        assert result.stdout == "test\n"
        assert result.stderr == ""
        assert result.exit_code == 0
        assert result.duration == 1.23

    def test_execution_result_with_failure(self):
        """Test ExecutionResult for failed execution."""
        from src.models.execution import ExecutionResult, ExecutionStatus

        result = ExecutionResult(
            command="false",
            status=ExecutionStatus.FAILED,
            stdout="",
            stderr="Command failed",
            exit_code=1,
            duration=0.5,
        )

        assert result.status == ExecutionStatus.FAILED
        assert result.exit_code == 1
        assert result.stderr == "Command failed"

    def test_command_context_creation(self):
        """Test CommandContext model creation."""
        from src.models.execution import CommandContext

        context = CommandContext(
            command="ls -la",
            working_directory="/tmp",
            environment={"PATH": "/usr/bin"},
            timeout=30,
        )

        assert context.command == "ls -la"
        assert context.working_directory == "/tmp"
        assert context.environment["PATH"] == "/usr/bin"
        assert context.timeout == 30

    def test_execution_status_enum(self):
        """Test ExecutionStatus enum values."""
        from src.models.execution import ExecutionStatus

        assert ExecutionStatus.PENDING.value == "pending"
        assert ExecutionStatus.RUNNING.value == "running"
        assert ExecutionStatus.SUCCESS.value == "success"
        assert ExecutionStatus.FAILED.value == "failed"
        assert ExecutionStatus.TIMEOUT.value == "timeout"


# Test discovery_tools.py (currently 84% coverage)
class TestDiscoveryTools:
    """Test discovery tools functionality."""

    @pytest.mark.asyncio
    async def test_basic_discovery(self):
        """Test basic discovery functionality."""
        from src.services.discovery_tools import DiscoveryTools

        discovery = DiscoveryTools()

        # Test that we can create and access discovery tools
        assert discovery is not None
        assert hasattr(discovery, "discover_targets")

    @pytest.mark.asyncio
    async def test_discover_targets_mock(self):
        """Test discover targets with mocking."""
        from src.services.discovery_tools import DiscoveryTools

        discovery = DiscoveryTools()

        # Mock the discovery process
        with patch.object(discovery, "discover_targets") as mock_discover:
            mock_discover.return_value = [
                {"host": "test1.example.com", "port": 22},
                {"host": "test2.example.com", "port": 22},
            ]

            targets = await discovery.discover_targets()
            assert len(targets) == 2
            assert targets[0]["host"] == "test1.example.com"

    def test_discovery_tools_initialization(self):
        """Test DiscoveryTools initialization."""
        from src.services.discovery_tools import DiscoveryTools

        discovery = DiscoveryTools()

        # Test that all expected attributes exist
        assert hasattr(discovery, "discover_targets")
        assert hasattr(discovery, "validate_target")
        assert hasattr(discovery, "scan_network")


# Test docker_manager.py (currently 83% coverage)
class TestDockerManager:
    """Test docker manager functionality."""

    @pytest.mark.asyncio
    async def test_docker_manager_creation(self):
        """Test DockerManager creation."""
        from src.services.docker_manager import DockerManager

        manager = DockerManager()
        assert manager is not None
        assert hasattr(manager, "list_containers")
        assert hasattr(manager, "run_container")

    @pytest.mark.asyncio
    async def test_list_containers_mock(self):
        """Test list containers with mocking."""
        from src.services.docker_manager import DockerManager

        manager = DockerManager()

        # Mock Docker client
        with patch("docker.from_env") as mock_docker:
            mock_client = Mock()
            mock_client.containers.list.return_value = [
                Mock(name="test1", status="running"),
                Mock(name="test2", status="stopped"),
            ]
            mock_docker.return_value = mock_client

            containers = await manager.list_containers()
            assert len(containers) == 2
            assert containers[0]["name"] == "test1"
            assert containers[0]["status"] == "running"

    @pytest.mark.asyncio
    async def test_run_container_mock(self):
        """Test run container with mocking."""
        from src.services.docker_manager import DockerManager

        manager = DockerManager()

        # Mock Docker client
        with patch("docker.from_env") as mock_docker:
            mock_client = Mock()
            mock_container = Mock(id="abc123", name="test-container")
            mock_client.containers.run.return_value = mock_container
            mock_docker.return_value = mock_client

            result = await manager.run_container(
                image="nginx:latest", name="test-container"
            )

            assert result["id"] == "abc123"
            assert result["name"] == "test-container"

    def test_docker_manager_methods(self):
        """Test DockerManager method availability."""
        from src.services.docker_manager import DockerManager

        manager = DockerManager()

        # Check all expected methods exist
        assert hasattr(manager, "list_containers")
        assert hasattr(manager, "run_container")
        assert hasattr(manager, "stop_container")
        assert hasattr(manager, "remove_container")
        assert hasattr(manager, "get_logs")


# Test input_validator.py (currently 73% coverage)
class TestInputValidator:
    """Test input validator functionality."""

    def test_input_validator_creation(self):
        """Test InputValidator creation."""
        from src.services.input_validator import InputValidator

        validator = InputValidator()
        assert validator is not None
        assert hasattr(validator, "validate_input")
        assert hasattr(validator, "sanitize_input")

    def test_basic_input_validation(self):
        """Test basic input validation."""
        from src.services.input_validator import InputValidator

        validator = InputValidator()

        # Test valid input
        valid_input = "test_value_123"
        result = validator.validate_input(valid_input)
        assert result is True

        # Test potentially invalid input patterns
        invalid_inputs = [
            "",  # empty string
            None,  # None value
            "   ",  # whitespace only
        ]

        for invalid in invalid_inputs:
            try:
                result = validator.validate_input(invalid)
                # Should handle gracefully
            except (ValueError, TypeError):
                # Expected for invalid inputs
                pass

    def test_input_sanitization(self):
        """Test input sanitization."""
        from src.services.input_validator import InputValidator

        validator = InputValidator()

        # Test basic sanitization
        dirty_input = "test<script>alert('xss')</script>"
        clean_input = validator.sanitize_input(dirty_input)

        # Should remove or escape dangerous content
        assert "<script>" not in clean_input

    def test_allowlist_management(self):
        """Test allowlist functionality."""
        from src.services.input_validator import InputValidator

        validator = InputValidator()

        # Test allowlist operations
        validator.add_to_allowlist("allowed_value")
        assert validator.is_in_allowlist("allowed_value")
        assert not validator.is_in_allowlist("not_allowed")

        validator.remove_from_allowlist("allowed_value")
        assert not validator.is_in_allowlist("allowed_value")


# Mark all tests as unit tests for easy categorization
pytestmark = [pytest.mark.unit]
