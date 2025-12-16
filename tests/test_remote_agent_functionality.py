"""
Comprehensive Tests for Remote Agent Functionality

Provides unit tests, integration tests, and mock implementations for
remote agent connectors and tools.
"""

import asyncio
import json
import pytest
from datetime import datetime
from unittest.mock import AsyncMock, patch
import tempfile

# Import modules to test
from src.connectors.remote_agent_connector import (
    RemoteAgentConnector,
    LogEntry,
    CommandResult,
    OperationResult,
)
from src.connectors.journald_connector import JournaldConnector
from src.connectors.service_connector import ServiceConnector
from src.connectors.docker_connector import DockerConnector
from src.connectors.file_connector import FileConnector
from src.services.remote_operation_executor import ResilientRemoteOperation
from src.tools.remote_agent_tools import RemoteAgentTools
from src.services.remote_agent_capabilities import RemoteAgentCapabilities
from src.utils.remote_security import (
    RemoteOperationSecurityManager,
    RemoteOperationAuditor,
    SecurityContext,
    SecurityLevel,
    AccessScope,
)
from src.models.target_registry import TargetConnection, ExecutorType


class MockSSHConnection:
    """Mock SSH connection for testing."""

    def __init__(self):
        self.connected = True
        self.connection_id = "mock_connection_123"
        self.target = None

    async def connect(self):
        self.connected = True
        return True

    async def is_connected(self) -> bool:
        return self.connected

    async def execute_command(self, command: str, timeout: int = 30) -> CommandResult:
        """Mock command execution."""
        # Simulate different command responses
        if "journalctl" in command:
            return await self._mock_journalctl_command(command)
        elif "systemctl" in command:
            return await self._mock_systemctl_command(command)
        elif "docker" in command:
            return await self._mock_docker_command(command)
        elif "cat" in command or "ls" in command or "stat" in command:
            return await self._mock_file_command(command)
        else:
            return CommandResult(
                command=command,
                exit_code=0,
                stdout="Mock command output",
                stderr="",
                execution_time=0.1,
                timestamp=datetime.utcnow(),
            )

    async def _mock_journalctl_command(self, command: str) -> CommandResult:
        """Mock journalctl commands."""
        if "json" in command:
            mock_logs = [
                {
                    "SYSLOG_TIMESTAMP": "2023-12-14T03:44:00.000Z",
                    "PRIORITY": "6",
                    "MESSAGE": "Test log message",
                    "SYSLOG_IDENTIFIER": "test-service",
                    "UNIT": "test.service",
                }
            ]
            return CommandResult(
                command=command,
                exit_code=0,
                stdout=json.dumps(mock_logs[0]),
                stderr="",
                execution_time=0.1,
                timestamp=datetime.utcnow(),
            )
        return CommandResult(
            command=command,
            exit_code=0,
            stdout="mock journalctl output",
            stderr="",
            execution_time=0.1,
            timestamp=datetime.utcnow(),
        )

    async def _mock_systemctl_command(self, command: str) -> CommandResult:
        """Mock systemctl commands."""
        if "show" in command:
            mock_status = {
                "ActiveState": "active",
                "SubState": "running",
                "Description": "Test service description",
            }
            output = "\n".join([f"{k}={v}" for k, v in mock_status.items()])
            return CommandResult(
                command=command,
                exit_code=0,
                stdout=output,
                stderr="",
                execution_time=0.1,
                timestamp=datetime.utcnow(),
            )
        return CommandResult(
            command=command,
            exit_code=0,
            stdout="mock systemctl output",
            stderr="",
            execution_time=0.1,
            timestamp=datetime.utcnow(),
        )

    async def _mock_docker_command(self, command: str) -> CommandResult:
        """Mock docker commands."""
        if "ps" in command and "json" in command:
            mock_containers = [
                {
                    "ID": "abc123",
                    "Names": "test-container",
                    "Status": "running",
                    "Image": "nginx:latest",
                    "Created": "2023-12-14T03:44:00.000Z",
                    "State": "running",
                }
            ]
            return CommandResult(
                command=command,
                exit_code=0,
                stdout=json.dumps(mock_containers[0]),
                stderr="",
                execution_time=0.1,
                timestamp=datetime.utcnow(),
            )
        return CommandResult(
            command=command,
            exit_code=0,
            stdout="mock docker output",
            stderr="",
            execution_time=0.1,
            timestamp=datetime.utcnow(),
        )

    async def _mock_file_command(self, command: str) -> CommandResult:
        """Mock file operations."""
        if "cat" in command:
            return CommandResult(
                command=command,
                exit_code=0,
                stdout="Mock file content",
                stderr="",
                execution_time=0.1,
                timestamp=datetime.utcnow(),
            )
        elif "ls" in command:
            return CommandResult(
                command=command,
                exit_code=0,
                stdout="drwxr-xr-x 2 root root 4096 Dec 14 03:44 /tmp\n-rw-r--r-- 1 root root 123 Dec 14 03:44 test.txt",
                stderr="",
                execution_time=0.1,
                timestamp=datetime.utcnow(),
            )
        elif "stat" in command:
            return CommandResult(
                command=command,
                exit_code=0,
                stdout="123 root root 644 1702535040 1702535040 1702535040",
                stderr="",
                execution_time=0.1,
                timestamp=datetime.utcnow(),
            )
        return CommandResult(
            command=command,
            exit_code=0,
            stdout="mock file output",
            stderr="",
            execution_time=0.1,
            timestamp=datetime.utcnow(),
        )

    async def port_forward(self, local_port: int, remote_host: str, remote_port: int):
        """Mock port forwarding."""
        from src.connectors.remote_agent_connector import ForwardResult

        return ForwardResult(
            local_port=local_port,
            remote_host=remote_host,
            remote_port=remote_port,
            status="active",
            connection_id="mock_forward_123",
        )

    async def upload_file(self, local_path: str, remote_path: str):
        """Mock file upload."""
        from src.connectors.remote_agent_connector import UploadResult

        return UploadResult(
            local_path=local_path,
            remote_path=remote_path,
            size=123,
            status="success",
            checksum="mock_checksum",
        )

    async def download_file(self, remote_path: str, local_path: str):
        """Mock file download."""
        from src.connectors.remote_agent_connector import DownloadResult

        return DownloadResult(
            remote_path=remote_path,
            local_path=local_path,
            size=123,
            status="success",
            checksum="mock_checksum",
        )

    async def close(self):
        self.connected = False

    async def close_port_forward(self, connection_id: str):
        pass


class TestRemoteAgentConnector:
    """Test cases for base remote agent connector."""

    @pytest.fixture
    def mock_target(self):
        """Create mock target connection."""
        return TargetConnection(
            executor=ExecutorType.SSH,
            host="test.example.com",
            port=22,
            username="testuser",
            timeout=30,
        )

    @pytest.fixture
    def mock_connection(self):
        """Create mock SSH connection."""
        return MockSSHConnection()

    @pytest.fixture
    def test_connector(self, mock_target, mock_connection):
        """Create test connector instance."""

        class TestConnector(RemoteAgentConnector):
            async def get_capabilities(self):
                return {"test": True}

            async def validate_target(self):
                return True

        return TestConnector(mock_target, mock_connection)

    @pytest.mark.asyncio
    async def test_connector_initialization(self, test_connector):
        """Test connector initialization."""
        assert test_connector.target.host == "test.example.com"
        assert test_connector.connection.connection_id == "mock_connection_123"
        assert test_connector.logger is not None

    @pytest.mark.asyncio
    async def test_health_check(self, test_connector):
        """Test health check functionality."""
        health_status = await test_connector.health_check()

        assert health_status.target == "test.example.com"
        assert health_status.healthy is True
        assert health_status.response_time >= 0
        assert health_status.last_check is not None

    @pytest.mark.asyncio
    async def test_command_execution(self, test_connector):
        """Test command execution."""
        result = await test_connector.execute_command("echo 'test'")

        assert result.command == "echo 'test'"
        assert result.exit_code == 0
        assert "Mock command output" in result.stdout

    @pytest.mark.asyncio
    async def test_port_forward(self, test_connector):
        """Test port forwarding."""
        async with test_connector.port_forward(8080, "localhost", 80) as forward_result:
            assert forward_result.local_port == 8080
            assert forward_result.remote_host == "localhost"
            assert forward_result.remote_port == 80
            assert forward_result.status == "active"


class TestJournaldConnector:
    """Test cases for journald connector."""

    @pytest.fixture
    def mock_target(self):
        return TargetConnection(executor=ExecutorType.SSH, host="test.example.com")

    @pytest.fixture
    def mock_connection(self):
        return MockSSHConnection()

    @pytest.fixture
    def journald_connector(self, mock_target, mock_connection):
        return JournaldConnector(mock_target, mock_connection)

    @pytest.mark.asyncio
    async def test_get_capabilities(self, journald_connector):
        """Test capabilities detection."""
        capabilities = await journald_connector.get_capabilities()
        assert capabilities["available"] is True

    @pytest.mark.asyncio
    async def test_validate_target(self, journald_connector):
        """Test target validation."""
        is_valid = await journald_connector.validate_target()
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_get_logs(self, journald_connector):
        """Test log retrieval."""
        logs = await journald_connector.get_logs(service="test-service", lines=10)

        assert len(logs) >= 1
        log = logs[0]
        assert log.source == "test-service"
        assert log.message == "Test log message"
        assert log.timestamp is not None

    @pytest.mark.asyncio
    async def test_search_logs(self, journald_connector):
        """Test log search."""
        results = await journald_connector.search_logs("error", service="test-service")
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_get_log_statistics(self, journald_connector):
        """Test log statistics."""
        stats = await journald_connector.get_log_statistics(service="test-service")

        assert "total_entries" in stats
        assert "priority_distribution" in stats
        assert "error_count" in stats
        assert stats["service"] == "test-service"


class TestServiceConnector:
    """Test cases for service connector."""

    @pytest.fixture
    def service_connector(self):
        mock_target = TargetConnection(
            executor=ExecutorType.SSH, host="test.example.com"
        )
        mock_connection = MockSSHConnection()
        return ServiceConnector(mock_target, mock_connection)

    @pytest.mark.asyncio
    async def test_get_capabilities(self, service_connector):
        """Test capabilities detection."""
        capabilities = await service_connector.get_capabilities()
        assert capabilities["available"] is True

    @pytest.mark.asyncio
    async def test_get_service_status(self, service_connector):
        """Test service status retrieval."""
        status = await service_connector.get_service_status("test-service")

        assert status.name == "test-service"
        assert status.state == "active"
        assert status.description == "Test service description"

    @pytest.mark.asyncio
    async def test_restart_service(self, service_connector):
        """Test service restart."""
        result = await service_connector.restart_service("test-service")

        assert result.operation == "restart_service"
        assert result.success is True
        assert "successfully" in result.result

    @pytest.mark.asyncio
    async def test_list_services(self, service_connector):
        """Test service listing."""
        services = await service_connector.list_services()

        assert isinstance(services, list)
        # Should return at least the test service
        service_names = [s.name for s in services]
        assert "test-service" in service_names

    @pytest.mark.asyncio
    async def test_check_service_health(self, service_connector):
        """Test service health check."""
        health = await service_connector.check_service_health("test-service")

        assert health["service"] == "test-service"
        assert "status" in health
        assert "healthy" in health
        assert health["last_check"] is not None


class TestDockerConnector:
    """Test cases for docker connector."""

    @pytest.fixture
    def docker_connector(self):
        mock_target = TargetConnection(
            executor=ExecutorType.SSH, host="test.example.com"
        )
        mock_connection = MockSSHConnection()
        return DockerConnector(mock_target, mock_connection)

    @pytest.mark.asyncio
    async def test_get_capabilities(self, docker_connector):
        """Test capabilities detection."""
        capabilities = await docker_connector.get_capabilities()
        assert capabilities["available"] is True

    @pytest.mark.asyncio
    async def test_list_containers(self, docker_connector):
        """Test container listing."""
        containers = await docker_connector.list_containers()

        assert len(containers) >= 1
        container = containers[0]
        assert container.container_id == "abc123"
        assert container.name == "test-container"
        assert container.status == "running"

    @pytest.mark.asyncio
    async def test_get_container_logs(self, docker_connector):
        """Test container log retrieval."""
        logs = await docker_connector.get_container_logs("abc123", lines=10)

        assert isinstance(logs, str)
        assert len(logs) > 0

    @pytest.mark.asyncio
    async def test_restart_container(self, docker_connector):
        """Test container restart."""
        result = await docker_connector.restart_container("abc123")

        assert result.operation == "restart_container"
        assert result.success is True
        assert "successfully" in result.result

    @pytest.mark.asyncio
    async def test_get_container_stats(self, docker_connector):
        """Test container statistics."""
        stats = await docker_connector.get_container_stats("abc123")

        assert stats.container_id == "abc123"
        assert stats.cpu_usage >= 0
        assert stats.memory_usage >= 0
        assert stats.pid > 0


class TestFileConnector:
    """Test cases for file connector."""

    @pytest.fixture
    def file_connector(self):
        mock_target = TargetConnection(
            executor=ExecutorType.SSH, host="test.example.com"
        )
        mock_connection = MockSSHConnection()
        return FileConnector(mock_target, mock_connection)

    @pytest.mark.asyncio
    async def test_get_capabilities(self, file_connector):
        """Test capabilities detection."""
        capabilities = await file_connector.get_capabilities()
        assert capabilities["available"] is True

    @pytest.mark.asyncio
    async def test_read_file(self, file_connector):
        """Test file reading."""
        content = await file_connector.read_file("/tmp/test.txt")

        assert content == "Mock file content"

    @pytest.mark.asyncio
    async def test_list_directory(self, file_connector):
        """Test directory listing."""
        files = await file_connector.list_directory("/tmp")

        assert len(files) >= 1
        file_info = files[0]
        assert file_info.name == "tmp"
        assert file_info.is_directory is True

    @pytest.mark.asyncio
    async def test_get_file_stats(self, file_connector):
        """Test file statistics."""
        stats = await file_connector.get_file_stats("/tmp/test.txt")

        assert stats.path == "/tmp/test.txt"
        assert stats.size == 123
        assert stats.permissions == "644"
        assert stats.owner == "root"

    @pytest.mark.asyncio
    async def test_write_file(self, file_connector):
        """Test file writing."""
        result = await file_connector.write_file("/tmp/test.txt", "test content")

        assert result.operation == "write_file"
        assert result.success is True
        assert "successfully" in result.result


class TestRemoteOperationExecutor:
    """Test cases for resilient operation executor."""

    @pytest.fixture
    def executor(self):
        return ResilientRemoteOperation()

    @pytest.mark.asyncio
    async def test_execute_with_retry_success(self, executor):
        """Test successful execution with retry."""

        async def successful_operation():
            return OperationResult(
                operation="test",
                target="test-target",
                success=True,
                result="success",
                timestamp=datetime.utcnow(),
            )

        result = await executor.execute_with_retry(
            successful_operation, operation_name="test_op"
        )

        assert result.success is True
        assert result.result == "success"

    @pytest.mark.asyncio
    async def test_execute_with_retry_failure(self, executor):
        """Test failed execution with retry."""

        async def failing_operation():
            raise Exception("Test error")

        result = await executor.execute_with_retry(
            failing_operation, operation_name="test_op"
        )

        assert result.success is False
        assert "Test error" in result.error

    @pytest.mark.asyncio
    async def test_execute_with_timeout(self, executor):
        """Test operation timeout."""

        async def slow_operation():
            await asyncio.sleep(2)
            return "done"

        result = await executor.execute_with_timeout(
            slow_operation, timeout=1, operation_name="test_op"
        )

        assert result.success is False
        assert "timed out" in result.error


class TestRemoteAgentTools:
    """Test cases for remote agent MCP tools."""

    @pytest.fixture
    def tools(self):
        return RemoteAgentTools()

    @pytest.mark.asyncio
    async def test_get_journald_logs(self, tools):
        """Test journald logs tool."""
        # Mock the internal methods
        with (
            patch.object(tools, "_get_target_connection") as mock_target,
            patch.object(tools, "_create_connector") as mock_connector,
        ):
            mock_target.return_value = TargetConnection(
                executor=ExecutorType.SSH, host="test.example.com"
            )

            # Create a mock connector
            mock_journald = AsyncMock()
            mock_journald.get_logs.return_value = [
                LogEntry(
                    timestamp=datetime.utcnow(),
                    level="info",
                    message="Test log",
                    source="test-service",
                )
            ]
            mock_connector.return_value = mock_journald

            result = await tools.get_journald_logs(
                "test.example.com", service="test-service", lines=10
            )

            assert result["success"] is True
            assert result["log_count"] == 1
            assert result["service"] == "test-service"

    @pytest.mark.asyncio
    async def test_restart_remote_service(self, tools):
        """Test service restart tool."""
        with (
            patch.object(tools, "_get_target_connection") as mock_target,
            patch.object(tools, "_create_connector") as mock_connector,
        ):
            mock_target.return_value = TargetConnection(
                executor=ExecutorType.SSH, host="test.example.com"
            )

            mock_service = AsyncMock()
            mock_service.restart_service.return_value = OperationResult(
                operation="restart_service",
                target="test.example.com",
                success=True,
                result="Service restarted successfully",
                timestamp=datetime.utcnow(),
            )
            mock_connector.return_value = mock_service

            result = await tools.restart_remote_service("test.example.com", "nginx")

            assert result["success"] is True
            assert result["service"] == "nginx"

    @pytest.mark.asyncio
    async def test_analyze_service_logs_across_fleet(self, tools):
        """Test fleet log analysis."""
        with patch.object(tools, "get_journald_logs") as mock_get_logs:
            # Mock successful log retrieval
            mock_get_logs.return_value = {
                "success": True,
                "log_count": 5,
                "logs": [
                    {"level": "info", "message": "Test message 1"},
                    {"level": "error", "message": "Test error 1"},
                    {"level": "warning", "message": "Test warning 1"},
                    {"level": "info", "message": "Test message 2"},
                    {
                        "level": "info",
                        "message": "Test message 2",
                    },  # Duplicate for testing
                ],
            }

            result = await tools.analyze_service_logs_across_fleet(
                targets=["server1.example.com", "server2.example.com"],
                service="nginx",
                time_range="1 hour",
            )

            assert result["success"] is True
            analysis = result["analysis"]
            assert analysis["total_targets"] == 2
            assert analysis["successful_targets"] == 2
            assert analysis["total_logs"] == 10
            assert "log_levels" in analysis
            assert "common_messages" in analysis


class TestSecurityControls:
    """Test cases for security controls."""

    @pytest.fixture
    def security_manager(self):
        from src.utils.audit import AuditLogger

        return RemoteOperationSecurityManager(AuditLogger())

    @pytest.fixture
    def auditor(self):
        from src.utils.audit import AuditLogger

        return RemoteOperationAuditor(AuditLogger())

    @pytest.fixture
    def security_context(self):
        return SecurityContext(
            user_id="testuser",
            session_id="test-session-123",
            scopes=[AccessScope.OBSERVE_ONLY],
            security_level=SecurityLevel.MEDIUM,
        )

    def test_validate_operation_security_allowed(
        self, security_manager, security_context
    ):
        """Test allowed operation validation."""
        is_valid, error = security_manager.validate_operation_security(
            "get_journald_logs", {"service": "nginx"}, security_context
        )

        assert is_valid is True
        assert error is None

    def test_validate_operation_security_blocked(
        self, security_manager, security_context
    ):
        """Test blocked operation validation."""
        is_valid, error = security_manager.validate_operation_security(
            "delete_remote_file", {"path": "/etc/passwd"}, security_context
        )

        assert is_valid is False
        assert "Access denied" in error

    def test_command_injection_detection(self, security_manager):
        """Test command injection detection."""
        parameters = {"command": "ls; rm -rf /"}
        has_injection = security_manager._detect_command_injection(
            "test_operation", parameters
        )
        assert has_injection is True

        parameters = {"command": "ls -la"}
        has_injection = security_manager._detect_command_injection(
            "test_operation", parameters
        )
        assert has_injection is False

    def test_file_path_validation(self, security_manager):
        """Test file path validation."""
        # Valid path
        is_valid, error = security_manager._validate_file_path("/tmp/test.txt")
        assert is_valid is True

        # Invalid path (directory traversal)
        is_valid, error = security_manager._validate_file_path("../etc/passwd")
        assert is_valid is False

        # Invalid path (sensitive location)
        is_valid, error = security_manager._validate_file_path("/etc/shadow")
        assert is_valid is False

    def test_rate_limiting(self, security_manager):
        """Test rate limiting."""
        user_id = "testuser"

        # First operation should be allowed
        is_allowed, error = security_manager._check_rate_limit(
            "get_journald_logs", user_id
        )
        assert is_allowed is True

        # Subsequent operations might be rate limited depending on limits
        is_allowed, error = security_manager._check_rate_limit(
            "get_journald_logs", user_id
        )
        # This depends on the rate limits configured
        assert isinstance(is_allowed, bool)

    def test_audit_event_creation(self, auditor, security_context):
        """Test audit event creation."""
        correlation_id = auditor.log_operation_start(
            "get_journald_logs",
            security_context,
            "test.example.com",
            {"service": "nginx"},
        )

        assert correlation_id is not None
        assert len(correlation_id) > 0

        # Log success
        auditor.log_operation_success(correlation_id, {"status": "success"}, 1.5)

        # Check that session data was stored
        session_id = auditor.correlation_ids[correlation_id]
        assert session_id in auditor.session_data


class TestIntegration:
    """Integration test cases."""

    @pytest.mark.asyncio
    async def test_full_workflow(self):
        """Test complete workflow from tools to connectors."""
        # This would be a full integration test
        # For now, we'll test the basic integration points

        from src.models.target_registry import TargetConnection, ExecutorType

        target = TargetConnection(
            executor=ExecutorType.SSH,
            host="test.example.com",
            port=22,
            username="testuser",
        )

        # Test capability execution
        result = await RemoteAgentCapabilities.get_journald_logs(
            target, {"service": "nginx"}
        )

        assert result.operation == "get_journald_logs"
        assert result.target == "test.example.com"
        assert isinstance(result.success, bool)

    @pytest.mark.asyncio
    async def test_fleet_operations(self):
        """Test fleet-wide operations."""
        from src.models.target_registry import TargetConnection, ExecutorType

        targets = [
            TargetConnection(executor=ExecutorType.SSH, host="server1.example.com"),
            TargetConnection(executor=ExecutorType.SSH, host="server2.example.com"),
        ]

        result = await RemoteAgentCapabilities.fleet_operations(
            targets,
            {"operation": "analyze_logs", "service": "nginx", "time_range": "1 hour"},
        )

        assert result.operation == "fleet_analyze_logs"
        assert result.target == "multiple"
        assert isinstance(result.success, bool)


class TestMockSSHConnection:
    """Test the mock SSH connection implementation."""

    @pytest.mark.asyncio
    async def test_connection_lifecycle(self):
        """Test connection establishment and cleanup."""
        conn = MockSSHConnection()

        # Test connection
        await conn.connect()
        assert conn.connected is True

        # Test connection status
        is_connected = await conn.is_connected()
        assert is_connected is True

        # Test command execution
        result = await conn.execute_command("echo 'test'")
        assert result.exit_code == 0
        assert result.command == "echo 'test'"

        # Test cleanup
        await conn.close()
        assert conn.connected is False

    @pytest.mark.asyncio
    async def test_port_forwarding(self):
        """Test port forwarding."""
        conn = MockSSHConnection()
        forward_result = await conn.port_forward(8080, "localhost", 80)

        assert forward_result.local_port == 8080
        assert forward_result.remote_host == "localhost"
        assert forward_result.remote_port == 80
        assert forward_result.status == "active"

    @pytest.mark.asyncio
    async def test_file_operations(self):
        """Test file upload/download."""
        conn = MockSSHConnection()

        # Test upload
        upload_result = await conn.upload_file("/local/test.txt", "/remote/test.txt")
        assert upload_result.status == "success"
        assert upload_result.size == 123

        # Test download
        download_result = await conn.download_file(
            "/remote/test.txt", "/local/test.txt"
        )
        assert download_result.status == "success"
        assert download_result.size == 123


# Test configuration and utilities
def pytest_configure(config):
    """Configure pytest."""
    config.addinivalue_line("markers", "integration: mark test as integration test")
    config.addinivalue_line("markers", "slow: mark test as slow running")


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def temp_dir():
    """Create temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield tmp_dir


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])
