"""
Tests for the execution abstraction layer.
"""

import pytest
from unittest.mock import Mock, patch

from src.services.executor import (
    Executor,
    ExecutionResult,
    ExecutionStatus,
    LocalExecutor,
    SSHExecutor,
    DockerExecutor,
    ExecutorConfig,
    ExecutorType,
    get_executor_factory,
    create_executor,
)


# Create a simple connection mock class like TargetConnection
class TargetConnection:
    """Mock connection for testing."""

    def __init__(
        self,
        executor=None,
        host=None,
        port=None,
        username=None,
        key_path=None,
        socket_path=None,
        timeout=30,
    ):
        self.executor = executor
        self.host = host
        self.port = port
        self.username = username
        self.key_path = key_path
        self.socket_path = socket_path
        self.timeout = timeout


class TestExecutorBase:
    """Test base executor functionality."""

    def test_executor_abstract_methods(self):
        """Test that Executor is abstract and requires implementation."""
        with pytest.raises(TypeError):
            Executor(config=None)

    def test_execution_result_model(self):
        """Test ExecutionResult dataclass."""
        result = ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            success=True,
            output="test output",
            command="test command",
            exit_code=0,
            duration=1.0,
        )

        assert result.status == ExecutionStatus.SUCCESS
        assert result.success is True
        assert result.output == "test output"
        assert result.command == "test command"
        assert result.exit_code == 0


class TestLocalExecutor:
    """Test local executor functionality."""

    def test_local_executor_creation(self):
        """Test creating local executor."""
        config = ExecutorConfig(
            executor_type=ExecutorType.LOCAL, host=None, port=None, username=None
        )
        executor = LocalExecutor(config)

        assert isinstance(executor, LocalExecutor)
        assert executor.is_available() is True

    def test_local_executor_connect(self):
        """Test local executor connection."""
        config = ExecutorConfig(
            executor_type=ExecutorType.LOCAL, host=None, port=None, username=None
        )
        executor = LocalExecutor(config)

        # Local executor should always connect successfully
        assert executor.connect() is True

    @patch("subprocess.run")
    def test_local_executor_execute_command_success(self, mock_run):
        """Test successful command execution."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "test output"
        mock_run.return_value.stderr = ""

        config = ExecutorConfig(
            executor_type=ExecutorType.LOCAL, host=None, port=None, username=None
        )
        executor = LocalExecutor(config)
        executor.connect()

        result = executor.execute_command("echo test")

        assert result.success is True
        assert result.status == ExecutionStatus.SUCCESS
        assert "test" in result.output

    @patch("subprocess.run")
    def test_local_executor_execute_command_failure(self, mock_run):
        """Test failed command execution."""
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = "command failed"

        config = ExecutorConfig(
            executor_type=ExecutorType.LOCAL, host=None, port=None, username=None
        )
        executor = LocalExecutor(config)
        executor.connect()

        result = executor.execute_command("invalid_command")

        assert result.success is False
        assert result.status == ExecutionStatus.FAILURE


class TestSSHExecutor:
    """Test SSH executor functionality."""

    def test_ssh_executor_creation(self):
        """Test creating SSH executor."""
        config = ExecutorConfig(
            executor_type=ExecutorType.SSH,
            host="test.example.com",
            port=22,
            username="testuser",
            key_path="/path/to/key",
        )
        executor = SSHExecutor(config)

        assert isinstance(executor, SSHExecutor)
        assert executor.host == "test.example.com"

    @patch("paramiko.SSHClient")
    def test_ssh_executor_connect_success(self, mock_ssh):
        """Test successful SSH connection."""
        mock_client = Mock()
        mock_ssh.return_value = mock_client

        config = ExecutorConfig(
            executor_type=ExecutorType.SSH,
            host="test.example.com",
            port=22,
            username="testuser",
            key_path="/path/to/key",
        )
        executor = SSHExecutor(config)

        success = executor.connect()
        assert success is True

    @patch("paramiko.SSHClient")
    def test_ssh_executor_connect_failure(self, mock_ssh):
        """Test SSH connection failure."""
        mock_client = Mock()
        mock_ssh.return_value = mock_client
        mock_client.connect.side_effect = Exception("Connection failed")

        config = ExecutorConfig(
            executor_type=ExecutorType.SSH,
            host="test.example.com",
            port=22,
            username="testuser",
            key_path="/path/to/key",
        )
        executor = SSHExecutor(config)

        success = executor.connect()
        assert success is False

    @patch("paramiko.SSHClient")
    def test_ssh_executor_execute_command(self, mock_ssh):
        """Test SSH command execution."""
        mock_client = Mock()
        mock_ssh.return_value = mock_client

        mock_stdout = Mock()
        mock_stdout.read.return_value = b"test output"
        mock_stderr = Mock()
        mock_stderr.read.return_value = b""

        mock_client.exec_command.return_value = (None, mock_stdout, mock_stderr)

        config = ExecutorConfig(
            executor_type=ExecutorType.SSH,
            host="test.example.com",
            port=22,
            username="testuser",
            key_path="/path/to/key",
        )
        executor = SSHExecutor(config)
        executor.connect()

        result = executor.execute_command("echo test")

        assert result.success is True
        assert result.status == ExecutionStatus.SUCCESS


class TestDockerExecutor:
    """Test Docker executor functionality."""

    def test_docker_executor_creation(self):
        """Test creating Docker executor."""
        config = ExecutorConfig(
            executor_type=ExecutorType.DOCKER,
            host=None,
            port=None,
            username=None,
            socket_path="/var/run/docker.sock",
        )
        executor = DockerExecutor(config)

        assert isinstance(executor, DockerExecutor)

    @patch("docker.from_env")
    def test_docker_executor_connect_success(self, mock_docker):
        """Test successful Docker connection."""
        mock_client = Mock()
        mock_docker.return_value = mock_client

        config = ExecutorConfig(
            executor_type=ExecutorType.DOCKER,
            host=None,
            port=None,
            username=None,
            socket_path="/var/run/docker.sock",
        )
        executor = DockerExecutor(config)

        success = executor.connect()
        assert success is True


class TestExecutorFactory:
    """Test executor factory functionality."""

    def test_executor_factory_creation(self):
        """Test creating executor factory."""
        factory = get_executor_factory()
        assert factory is not None

    def test_create_local_executor(self):
        """Test creating local executor."""
        connection = TargetConnection(executor=ExecutorType.LOCAL)
        config = ExecutorConfig(
            executor_type=ExecutorType.LOCAL, host=None, port=None, username=None
        )

        factory = get_executor_factory()
        executor = factory.create_executor(config)

        assert isinstance(executor, LocalExecutor)

    def test_create_ssh_executor(self):
        """Test creating SSH executor."""
        config = ExecutorConfig(
            executor_type=ExecutorType.SSH,
            host="test.example.com",
            port=22,
            username="testuser",
            key_path="/path/to/key",
        )

        factory = get_executor_factory()
        executor = factory.create_executor(config)

        assert isinstance(executor, SSHExecutor)
        assert executor.host == "test.example.com"

    def test_create_docker_executor(self):
        """Test creating Docker executor."""
        config = ExecutorConfig(
            executor_type=ExecutorType.DOCKER, socket_path="/var/run/docker.sock"
        )

        factory = get_executor_factory()
        executor = factory.create_executor(config)

        assert isinstance(executor, DockerExecutor)

    def test_executor_caching(self):
        """Test executor caching functionality."""
        config = ExecutorConfig(
            executor_type=ExecutorType.LOCAL, host=None, port=None, username=None
        )

        factory = get_executor_factory()
        executor1 = factory.create_executor(config)
        executor2 = factory.create_executor(config)

        # Should return same instance for same config
        assert executor1 is executor2

    def test_clear_cache(self):
        """Test clearing executor cache."""
        config = ExecutorConfig(
            executor_type=ExecutorType.LOCAL, host=None, port=None, username=None
        )

        factory = get_executor_factory()
        executor1 = factory.create_executor(config)
        factory.clear_cache()
        executor2 = factory.create_executor(config)

        # Should return different instances after cache clear
        assert executor1 is not executor2
