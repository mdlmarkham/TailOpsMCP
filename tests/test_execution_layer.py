"""
Tests for the execution abstraction layer.
"""

import pytest
from unittest.mock import Mock, patch

from src.services.executor import Executor, ExecutionResult, ExecutionStatus
from src.services.local_executor import LocalExecutor
from src.services.ssh_executor import SSHExecutor
from src.services.docker_executor import DockerExecutor
from src.services.executor_factory import ExecutorFactory
from src.models.target_registry import TargetConnection, ExecutorType


class TestExecutorBase:
    """Test base executor functionality."""
    
    def test_executor_abstract_methods(self):
        """Test that Executor is abstract and requires implementation."""
        with pytest.raises(TypeError):
            Executor()
    
    def test_execution_result_model(self):
        """Test ExecutionResult model creation and serialization."""
        result = ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            success=True,
            exit_code=0,
            output="Test output",
            error=None,
            duration=1.5,
            metadata={"test": "value"}
        )
        
        assert result.success is True
        assert result.status == ExecutionStatus.SUCCESS
        assert result.exit_code == 0
        assert result.output == "Test output"
        assert result.duration == 1.5
        
        # Test dictionary conversion
        result_dict = result.to_dict()
        assert result_dict["success"] is True
        assert result_dict["status"] == "success"


class TestLocalExecutor:
    """Test LocalExecutor functionality."""
    
    def test_local_executor_creation(self):
        """Test LocalExecutor creation."""
        executor = LocalExecutor()
        assert isinstance(executor, Executor)
        assert executor.timeout == 30
    
    def test_local_executor_connect(self):
        """Test LocalExecutor connection."""
        executor = LocalExecutor()
        assert executor.connect() is True
        assert executor.is_connected() is True
    
    @patch('subprocess.run')
    def test_local_executor_execute_command_success(self, mock_run):
        """Test successful command execution."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Success output",
            stderr=""
        )
        
        executor = LocalExecutor()
        executor.connect()
        
        result = executor.execute_command("echo test")
        
        assert result.success is True
        assert result.status == ExecutionStatus.SUCCESS
        assert result.exit_code == 0
        assert result.output == "Success output"
    
    @patch('subprocess.run')
    def test_local_executor_execute_command_failure(self, mock_run):
        """Test failed command execution."""
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="Error occurred"
        )
        
        executor = LocalExecutor()
        executor.connect()
        
        result = executor.execute_command("invalid_command")
        
        assert result.success is False
        assert result.status == ExecutionStatus.FAILURE
        assert result.exit_code == 1
        assert result.error == "Error occurred"


class TestSSHExecutor:
    """Test SSHExecutor functionality."""
    
    def test_ssh_executor_creation(self):
        """Test SSHExecutor creation."""
        executor = SSHExecutor(
            host="test.example.com",
            port=22,
            username="testuser",
            key_path="/path/to/key"
        )
        assert isinstance(executor, Executor)
        assert executor.host == "test.example.com"
    
    @patch('paramiko.SSHClient')
    def test_ssh_executor_connect_success(self, mock_ssh_client):
        """Test successful SSH connection."""
        mock_client = Mock()
        mock_ssh_client.return_value = mock_client
        
        executor = SSHExecutor(
            host="test.example.com",
            port=22,
            username="testuser",
            key_path="/path/to/key"
        )
        
        assert executor.connect() is True
        assert executor.is_connected() is True
    
    @patch('paramiko.SSHClient')
    def test_ssh_executor_execute_command(self, mock_ssh_client):
        """Test SSH command execution."""
        mock_client = Mock()
        mock_stdin = Mock()
        mock_stdout = Mock()
        mock_stderr = Mock()
        mock_channel = Mock()
        
        mock_ssh_client.return_value = mock_client
        mock_client.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_stdout.read.return_value = b"Command output"
        mock_stderr.read.return_value = b""
        
        executor = SSHExecutor(
            host="test.example.com",
            port=22,
            username="testuser",
            key_path="/path/to/key"
        )
        executor.connect()
        
        result = executor.execute_command("ls -la")
        
        assert result.success is True
        assert result.status == ExecutionStatus.SUCCESS
        assert result.output == "Command output"


class TestDockerExecutor:
    """Test DockerExecutor functionality."""
    
    def test_docker_executor_creation(self):
        """Test DockerExecutor creation."""
        executor = DockerExecutor(socket_path="/var/run/docker.sock")
        assert isinstance(executor, Executor)
        assert executor.socket_path == "/var/run/docker.sock"
    
    @patch('docker.DockerClient')
    def test_docker_executor_connect_success(self, mock_docker_client):
        """Test successful Docker connection."""
        mock_client = Mock()
        mock_client.ping.return_value = True
        mock_docker_client.return_value = mock_client
        
        executor = DockerExecutor(socket_path="/var/run/docker.sock")
        
        assert executor.connect() is True
        assert executor.is_connected() is True


class TestExecutorFactory:
    """Test ExecutorFactory functionality."""
    
    def test_executor_factory_creation(self):
        """Test ExecutorFactory creation."""
        factory = ExecutorFactory()
        assert isinstance(factory, ExecutorFactory)
    
    def test_create_local_executor(self):
        """Test creating local executor."""
        factory = ExecutorFactory()
        connection = TargetConnection(executor=ExecutorType.LOCAL)
        
        executor = factory.create_executor(connection)
        
        assert isinstance(executor, LocalExecutor)
    
    def test_create_ssh_executor(self):
        """Test creating SSH executor."""
        factory = ExecutorFactory()
        connection = TargetConnection(
            executor=ExecutorType.SSH,
            host="test.example.com",
            port=22,
            username="testuser",
            key_path="/path/to/key"
        )
        
        executor = factory.create_executor(connection)
        
        assert isinstance(executor, SSHExecutor)
        assert executor.host == "test.example.com"
    
    def test_create_docker_executor(self):
        """Test creating Docker executor."""
        factory = ExecutorFactory()
        connection = TargetConnection(
            executor=ExecutorType.DOCKER,
            socket_path="/var/run/docker.sock"
        )
        
        executor = factory.create_executor(connection)
        
        assert isinstance(executor, DockerExecutor)
        assert executor.socket_path == "/var/run/docker.sock"
    
    def test_executor_caching(self):
        """Test executor caching functionality."""
        factory = ExecutorFactory()
        connection = TargetConnection(executor=ExecutorType.LOCAL)
        
        # Create first executor
        executor1 = factory.create_executor(connection)
        
        # Get cached executor
        executor2 = factory.get_or_create_executor(connection)
        
        # Should be the same instance
        assert executor1 is executor2
    
    def test_clear_cache(self):
        """Test cache clearing functionality."""
        factory = ExecutorFactory()
        connection = TargetConnection(executor=ExecutorType.LOCAL)
        
        # Create and cache executor
        factory.create_executor(connection)
        
        # Clear cache
        factory.clear_cache()
        
        # Should create new executor
        executor = factory.get_or_create_executor(connection)
        assert executor is not None