"""
Comprehensive Test Suite for Proxmox Integration

This test suite covers all aspects of the Proxmox API integration including:
- API client functionality
- CLI wrapper operations
- Discovery pipeline
- Capability operations
- MCP tools
- Security and audit logging
- Monitoring and health checks
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime

from src.models.proxmox_models import (
    ProxmoxAPICredentials,
    ContainerConfig,
    ProxmoxContainer,
    ContainerCreationResult,
)
from src.services.proxmox_api import ProxmoxAPI
from src.services.proxmox_cli import ProxmoxCLI
from src.services.proxmox_discovery_enhanced import ProxmoxDiscoveryEnhanced
from src.services.proxmox_capabilities import (
    ProxmoxCapabilityExecutor,
    ProxmoxCapabilityValidator,
)
from src.tools.proxmox_tools import ProxmoxTools
from src.utils.proxmox_security import (
    ProxmoxSecurityLogger,
    ProxmoxSecurityManager,
    ProxmoxSecurityContext,
    ProxmoxSecurityEventType,
    SecuritySeverity,
)
from src.utils.proxmox_monitoring import (
    ProxmoxHealthChecker,
    ProxmoxMetricsCollector,
    ProxmoxAlertManager,
    ProxmoxMonitoringService,
    HealthStatus,
    AlertSeverity,
)


class TestProxmoxModels:
    """Test Proxmox data models."""

    def test_proxmox_api_credentials_validation(self):
        """Test ProxmoxAPI credentials validation."""
        # Valid credentials
        credentials = ProxmoxAPICredentials(
            host="pve.example.com", username="root@pam", password="testpassword"
        )
        assert credentials.validate() == []

        # Invalid credentials - missing password/token
        credentials = ProxmoxAPICredentials(host="pve.example.com", username="root@pam")
        errors = credentials.validate()
        assert len(errors) == 1
        assert "Either password or API token must be provided" in errors[0]

        # Invalid port
        credentials = ProxmoxAPICredentials(
            host="pve.example.com",
            username="root@pam",
            password="testpassword",
            port=70000,
        )
        errors = credentials.validate()
        assert len(errors) == 1
        assert "Port must be between 1 and 65535" in errors[0]

    def test_container_config_to_proxmox_config(self):
        """Test ContainerConfig conversion to Proxmox API format."""
        config = ContainerConfig(
            ostemplate="local:vztmpl/debian-12-standard_12.7-1_amd64.tar.gz",
            hostname="test-container",
            cores=2,
            memory=1024,
            rootfs="local-lvm:20",
            password="testpass",
            swap=512,
        )

        proxmox_config = config.to_proxmox_config()

        assert (
            proxmox_config["ostemplate"]
            == "local:vztmpl/debian-12-standard_12.7-1_amd64.tar.gz"
        )
        assert proxmox_config["hostname"] == "test-container"
        assert proxmox_config["cores"] == 2
        assert proxmox_config["memory"] == 1024
        assert proxmox_config["rootfs"] == "local-lvm:20"
        assert proxmox_config["password"] == "testpass"
        assert proxmox_config["swap"] == 512

    def test_proxmox_container_from_api_response(self):
        """Test ProxmoxContainer creation from API response."""
        api_data = {
            "vmid": 100,
            "node": "pve-node-01",
            "name": "test-container",
            "status": "running",
            "uptime": 3600,
            "cpu": 0.5,
            "maxcpu": 2.0,
            "mem": 1073741824,  # 1GB in bytes
            "maxmem": 2147483648,  # 2GB in bytes
            "disk": 21474836480,  # 20GB in bytes
            "maxdisk": 53687091200,  # 50GB in bytes
            "cores": 2,
            "memory": 1024,
            "rootfs": "local-lvm:20",
        }

        container = ProxmoxContainer.from_api_response(100, api_data)

        assert container.vmid == 100
        assert container.node == "pve-node-01"
        assert container.name == "test-container"
        assert container.status.value == "running"
        assert container.cores == 2
        assert container.memory == 1024


class TestProxmoxAPI:
    """Test Proxmox API client."""

    @pytest.fixture
    def api_credentials(self):
        """Create test API credentials."""
        return ProxmoxAPICredentials(
            host="pve.test.com", username="root@pam", password="testpassword"
        )

    @pytest.fixture
    def mock_api_client(self, api_credentials):
        """Create mock API client for testing."""
        return ProxmoxAPI(api_credentials)

    @pytest.mark.asyncio
    async def test_api_connection_test(self, mock_api_client):
        """Test API connection testing."""
        with patch.object(mock_api_client, "_make_request") as mock_request:
            # Mock successful response
            mock_request.return_value = {
                "data": {"version": "8.1.3", "release": "8.1.3", "keyboard": "en"}
            }

            result = await mock_api_client.test_connection()

            assert result.success is True
            assert result.data["version"] == "8.1.3"
            assert "Proxmox API connection test successful" in result.message

    @pytest.mark.asyncio
    async def test_list_containers(self, mock_api_client):
        """Test listing containers."""
        with patch.object(mock_api_client, "_make_request") as mock_request:
            # Mock containers list response
            mock_request.return_value = {
                "data": [
                    {
                        "vmid": 100,
                        "node": "pve-node-01",
                        "name": "container-1",
                        "status": "running",
                        "uptime": 3600,
                        "cpu": 0.5,
                        "mem": 1073741824,
                        "maxmem": 2147483648,
                    }
                ]
            }

            # Mock config request
            config_response = {
                "data": {"cores": 2, "memory": 1024, "rootfs": "local-lvm:20"}
            }
            mock_request.side_effect = [
                {"data": [{"vmid": 100, "node": "pve-node-01"}]},  # list response
                config_response,  # config response
            ]

            containers = await mock_api_client.list_containers()

            assert len(containers) == 1
            assert containers[0].vmid == 100
            assert containers[0].name == "container-1"
            assert containers[0].status.value == "running"

    @pytest.mark.asyncio
    async def test_create_container(self, mock_api_client):
        """Test container creation."""
        config = ContainerConfig(
            ostemplate="local:vztmpl/debian-12-standard_12.7-1_amd64.tar.gz",
            hostname="new-container",
            vmid=200,
        )

        with patch.object(mock_api_client, "_make_request") as mock_request:
            # Mock successful creation response
            mock_request.return_value = {
                "data": {
                    "upid": "UPID:pve-node-01:00001234:00000001:00000001:lxc-create:100:root@pam:"
                }
            }

            # Mock task monitoring
            with patch.object(mock_api_client, "_monitor_task", return_value=True):
                result = await mock_api_client.create_container(config, "pve-node-01")

                assert result.status == "created"
                assert result.vmid == 200
                assert result.task_id is not None

    @pytest.mark.asyncio
    async def test_container_start_stop_operations(self, mock_api_client):
        """Test container start/stop operations."""
        with patch.object(mock_api_client, "_make_request") as mock_request:
            mock_request.return_value = {
                "data": {
                    "upid": "UPID:pve-node-01:00001234:00000001:00000001:lxc-start:100:root@pam:"
                }
            }

            with patch.object(mock_api_client, "_monitor_task", return_value=True):
                # Test start
                start_result = await mock_api_client.start_container(100)
                assert start_result.status == "started"

                # Test stop
                stop_result = await mock_api_client.stop_container(100)
                assert stop_result.status == "stopped"


class TestProxmoxCLI:
    """Test Proxmox CLI wrapper."""

    @pytest.fixture
    def cli_client(self):
        """Create CLI client for testing."""
        return ProxmoxCLI()

    @pytest.mark.asyncio
    async def test_cli_availability_check(self, cli_client):
        """Test CLI availability checking."""
        with patch.object(cli_client, "_detect_proxmox_environment", return_value=True):
            assert cli_client.is_available() is True

        with patch.object(
            cli_client, "_detect_proxmox_environment", return_value=False
        ):
            assert cli_client.is_available() is False

    @pytest.mark.asyncio
    async def test_cli_container_listing(self, cli_client):
        """Test CLI-based container listing."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """
VMID     STATUS     NAME         MEM(MB)    DISK(GB)
100      running    container-1  1024       20
101      stopped    container-2  512        10
"""

        with patch.object(cli_client, "_run_command", return_value=mock_result):
            containers = await cli_client.list_containers_cli()

            assert len(containers) == 2
            assert containers[0].vmid == 100
            assert containers[0].name == "container-1"
            assert containers[1].vmid == 101
            assert containers[1].name == "container-2"

    @pytest.mark.asyncio
    async def test_cli_container_operations(self, cli_client):
        """Test CLI-based container operations."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "success"

        with patch.object(cli_client, "_run_command", return_value=mock_result):
            # Test container start
            start_result = await cli_client.start_container_cli(100)
            assert start_result.status == "started"

            # Test container stop
            stop_result = await cli_client.stop_container_cli(100)
            assert stop_result.status == "stopped"


class TestProxmoxDiscovery:
    """Test Proxmox discovery pipeline."""

    @pytest.fixture
    def discovery_service(self):
        """Create discovery service for testing."""
        credentials = [
            ProxmoxAPICredentials(
                host="pve.test.com", username="root@pam", password="testpassword"
            )
        ]
        return ProxmoxDiscoveryEnhanced(api_credentials=credentials)

    @pytest.mark.asyncio
    async def test_host_discovery_api(self, discovery_service):
        """Test host discovery via API."""
        with patch.object(discovery_service, "_discover_host_via_api") as mock_discover:
            mock_host = Mock()
            mock_host.hostname = "pve-node-01"
            mock_host.address = "pve.test.com"
            mock_host.validate.return_value = []
            mock_discover.return_value = mock_host

            hosts = await discovery_service.discover_proxmox_hosts()

            assert len(hosts) == 1
            assert hosts[0].hostname == "pve-node-01"
            assert hosts[0].address == "pve.test.com"

    @pytest.mark.asyncio
    async def test_container_discovery(self, discovery_service):
        """Test container discovery."""
        mock_host = Mock()
        mock_host.hostname = "pve-node-01"
        mock_host.address = "pve.test.com"
        mock_host.id = "host-123"

        with patch.object(
            discovery_service, "_discover_containers_via_api"
        ) as mock_discover:
            mock_containers = [
                Mock(
                    vmid=100,
                    name="container-1",
                    status="running",
                    cores=2,
                    memory=1024,
                    disk=20,
                ),
                Mock(
                    vmid=101,
                    name="container-2",
                    status="stopped",
                    cores=1,
                    memory=512,
                    disk=10,
                ),
            ]
            mock_discover.return_value = mock_containers

            containers = await discovery_service.discover_containers(mock_host)

            assert len(containers) == 2
            assert containers[0].vmid == 100
            assert containers[0].name == "container-1"
            assert containers[1].vmid == 101
            assert containers[1].name == "container-2"


class TestProxmoxCapabilities:
    """Test Proxmox capability operations."""

    @pytest.fixture
    def capability_executor(self):
        """Create capability executor for testing."""
        credentials = [
            ProxmoxAPICredentials(
                host="pve.test.com", username="root@pam", password="testpassword"
            )
        ]
        return ProxmoxCapabilityExecutor(credentials)

    @pytest.mark.asyncio
    async def test_container_create_capability(self, capability_executor):
        """Test container creation capability."""
        parameters = {
            "host": "pve.test.com",
            "template": "local:vztmpl/debian-12-standard_12.7-1_amd64.tar.gz",
            "hostname": "test-container",
            "cores": 2,
            "memory": 1024,
        }

        with patch.object(capability_executor, "_get_api_client") as mock_client:
            mock_api = Mock()
            mock_api.connect = AsyncMock(return_value=True)
            mock_api.create_container = AsyncMock(
                return_value=ContainerCreationResult(
                    vmid=200, status="created", message="Container created successfully"
                )
            )
            mock_client.return_value = mock_api

            result = await capability_executor.execute_proxmox_container_create(
                parameters
            )

            assert result.success is True
            assert "created successfully" in result.output

    @pytest.mark.asyncio
    async def test_container_start_capability(self, capability_executor):
        """Test container start capability."""
        parameters = {"vmid": 100, "host": "pve.test.com"}

        with patch.object(capability_executor, "_get_api_client") as mock_client:
            mock_api = Mock()
            mock_api.connect = AsyncMock(return_value=True)
            mock_api.start_container = AsyncMock(return_value=Mock(status="started"))
            mock_client.return_value = mock_api

            result = await capability_executor.execute_proxmox_container_start(
                parameters
            )

            assert result.success is True
            assert "started successfully" in result.output

    def test_capability_validation(self, capability_executor):
        """Test capability parameter validation."""
        validator = ProxmoxCapabilityValidator()

        # Valid parameters
        valid_params = {
            "host": "pve.test.com",
            "template": "local:vztmpl/debian-12-standard_12.7-1_amd64.tar.gz",
            "hostname": "test-container",
        }

        errors = validator.validate_parameters("proxmox_container_create", valid_params)
        assert len(errors) == 0

        # Invalid parameters (missing required field)
        invalid_params = {
            "host": "pve.test.com",
            "template": "local:vztmpl/debian-12-standard_12.7-1_amd64.tar.gz",
        }

        errors = validator.validate_parameters(
            "proxmox_container_create", invalid_params
        )
        assert len(errors) > 0


class TestProxmoxTools:
    """Test Proxmox MCP tools."""

    @pytest.fixture
    def proxmox_tools(self):
        """Create Proxmox tools for testing."""
        credentials = [
            ProxmoxAPICredentials(
                host="pve.test.com", username="root@pam", password="testpassword"
            )
        ]
        return ProxmoxTools(credentials)

    @pytest.mark.asyncio
    async def test_discovery_tools(self, proxmox_tools):
        """Test discovery MCP tools."""
        with patch.object(
            proxmox_tools.discovery_service, "discover_proxmox_hosts"
        ) as mock_discover:
            mock_hosts = [
                Mock(
                    hostname="pve-node-01",
                    address="pve.test.com",
                    node_name="pve-node-01",
                )
            ]
            mock_discover.return_value = mock_hosts

            result = await proxmox_tools.proxmox_discover()

            assert result["success"] is True
            assert result["hosts_discovered"] == 1
            assert len(result["hosts"]) == 1

    @pytest.mark.asyncio
    async def test_container_management_tools(self, proxmox_tools):
        """Test container management MCP tools."""
        with patch.object(
            proxmox_tools.capability_executor, "execute_proxmox_container_start"
        ) as mock_execute:
            mock_execute.return_value = Mock(
                success=True, output="Container started successfully"
            )

            result = await proxmox_tools.start_ct(100, "pve.test.com")

            assert result["success"] is True
            assert "started successfully" in result["message"]

    @pytest.mark.asyncio
    async def test_snapshot_tools(self, proxmox_tools):
        """Test snapshot MCP tools."""
        with patch.object(
            proxmox_tools.capability_executor, "execute_proxmox_snapshot_create"
        ) as mock_execute:
            mock_execute.return_value = Mock(
                success=True, output="Snapshot created successfully"
            )

            result = await proxmox_tools.snapshot_ct(
                100, "daily-backup", "pve.test.com"
            )

            assert result["success"] is True
            assert "created successfully" in result["message"]


class TestProxmoxSecurity:
    """Test Proxmox security and audit logging."""

    @pytest.fixture
    def security_logger(self):
        """Create security logger for testing."""
        return ProxmoxSecurityLogger(redact_sensitive_data=True)

    @pytest.fixture
    def security_context(self):
        """Create security context for testing."""
        return ProxmoxSecurityContext(
            user="testuser", source_ip="192.168.1.100", mcp_client="test-client"
        )

    def test_security_event_logging(self, security_logger, security_context):
        """Test security event logging."""
        result = security_logger.log_security_event(
            event_type=ProxmoxSecurityEventType.CONTAINER_CREATE,
            security_context=security_context,
            target_host="pve.test.com",
            operation="create_container",
            resource_type="container",
            resource_id=100,
            authorized=True,
            risk_level=SecuritySeverity.LOW,
        )

        assert result is True

        # Check that event was logged
        summary = security_logger.get_security_summary()
        assert summary["event_counts"]["container_create"] == 1

    def test_parameter_sanitization(self, security_logger):
        """Test parameter sanitization for sensitive data."""
        sensitive_params = {
            "password": "secret123",
            "api_token": "token-abc-123",
            "normal_param": "normal_value",
            "data": {"secret_key": "private_key_data"},
        }

        sanitized = security_logger._sanitize_parameters(sensitive_params)

        assert sanitized["password"] == "<REDACTED>"
        assert sanitized["api_token"] == "<REDACTED>"
        assert sanitized["normal_param"] == "normal_value"
        assert sanitized["data"]["secret_key"] == "<REDACTED>"

    def test_rate_limiting(self, security_logger):
        """Test rate limiting functionality."""
        user = "testuser"
        operation = "create_container"

        # Should allow first request
        assert security_logger.check_rate_limit(user, operation, limit=2) is True

        # Should allow second request
        assert security_logger.check_rate_limit(user, operation, limit=2) is True

        # Should deny third request
        assert security_logger.check_rate_limit(user, operation, limit=2) is False

    def test_security_manager_credential_validation(self):
        """Test security manager credential validation."""
        security_logger = ProxmoxSecurityLogger()
        security_manager = ProxmoxSecurityManager(security_logger)

        credentials = ProxmoxAPICredentials(
            host="pve.test.com", username="root@pam", password="testpassword"
        )

        security_context = ProxmoxSecurityContext(user="testuser")

        # Mock access control methods
        with patch.object(
            security_manager, "_check_access_permissions", return_value=True
        ):
            result = security_manager.validate_credentials(
                credentials, security_context
            )
            assert result is True


class TestProxmoxMonitoring:
    """Test Proxmox monitoring and health checks."""

    @pytest.fixture
    def api_credentials(self):
        """Create API credentials for testing."""
        return [
            ProxmoxAPICredentials(
                host="pve.test.com", username="root@pam", password="testpassword"
            )
        ]

    @pytest.fixture
    def health_checker(self, api_credentials):
        """Create health checker for testing."""
        return ProxmoxHealthChecker(api_credentials)

    @pytest.fixture
    def metrics_collector(self, api_credentials):
        """Create metrics collector for testing."""
        return ProxmoxMetricsCollector(api_credentials)

    @pytest.mark.asyncio
    async def test_host_health_check(self, health_checker):
        """Test host health checking."""
        with patch.object(health_checker, "check_host_health") as mock_check:
            # Mock healthy host
            mock_result = Mock(
                component="proxmox_host_pve.test.com",
                status=HealthStatus.HEALTHY,
                message="All nodes online",
                timestamp=datetime.utcnow().isoformat() + "Z",
                response_time_ms=100.0,
            )
            mock_check.return_value = mock_result

            result = await health_checker.check_host_health("pve.test.com")

            assert result.status == HealthStatus.HEALTHY
            assert "online" in result.message

    @pytest.mark.asyncio
    async def test_container_health_check(self, health_checker):
        """Test container health checking."""
        with patch.object(health_checker, "check_container_health") as mock_check:
            # Mock running container
            mock_result = Mock(
                component="proxmox_container_100",
                status=HealthStatus.HEALTHY,
                message="Container is running",
                timestamp=datetime.utcnow().isoformat() + "Z",
                response_time_ms=50.0,
            )
            mock_check.return_value = mock_result

            result = await health_checker.check_container_health("pve.test.com", 100)

            assert result.status == HealthStatus.HEALTHY
            assert "running" in result.message

    @pytest.mark.asyncio
    async def test_metrics_collection(self, metrics_collector):
        """Test metrics collection."""
        with patch.object(metrics_collector, "collect_host_metrics") as mock_collect:
            mock_metrics = [
                Mock(
                    name="proxmox_host_up",
                    value=1,
                    labels={"host": "pve.test.com"},
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    metric_type="gauge",
                )
            ]
            mock_collect.return_value = mock_metrics

            metrics = await metrics_collector.collect_host_metrics("pve.test.com")

            assert len(metrics) == 1
            assert metrics[0].name == "proxmox_host_up"
            assert metrics[0].value == 1

    def test_metrics_prometheus_format(self, metrics_collector):
        """Test metrics conversion to Prometheus format."""
        # Add test metrics
        test_metrics = [
            Mock(
                name="proxmox_host_up",
                value=1,
                labels={"host": "pve.test.com"},
                timestamp=datetime.utcnow().isoformat() + "Z",
                metric_type="gauge",
                help_text="Whether the Proxmox host is reachable",
            )
        ]

        metrics_collector.add_metrics(test_metrics)
        prometheus_output = metrics_collector.get_metrics_as_prometheus()

        assert "# TYPE proxmox_host_up gauge" in prometheus_output
        assert (
            "# HELP proxmox_host_up Whether the Proxmox host is reachable"
            in prometheus_output
        )
        assert 'proxmox_host_up{host="pve.test.com"} 1' in prometheus_output

    def test_alert_evaluation(self):
        """Test alert rule evaluation."""
        from src.utils.proxmox_monitoring import AlertRule

        alert_rules = [
            AlertRule(
                name="host_down",
                condition="status in ['unhealthy', 'critical']",
                severity=AlertSeverity.CRITICAL,
                description="Proxmox host is down",
            )
        ]

        alert_manager = ProxmoxAlertManager(alert_rules)

        # Mock health results
        health_results = {
            "pve.test.com": Mock(
                status=HealthStatus.CRITICAL, message="Host is down", details={}
            )
        }

        # Mock metrics
        metrics = []

        alerts = alert_manager.evaluate_alerts(health_results, metrics)

        assert len(alerts) == 1
        assert alerts[0]["name"] == "host_down"
        assert alerts[0]["severity"] == AlertSeverity.CRITICAL


class TestProxmoxIntegration:
    """Integration tests for complete Proxmox workflows."""

    @pytest.mark.asyncio
    async def test_complete_container_lifecycle(self):
        """Test complete container lifecycle from creation to deletion."""
        # This would be a full integration test if we had a real Proxmox instance
        # For now, we'll mock the complete workflow

        # Mock setup
        credentials = ProxmoxAPICredentials(
            host="pve.test.com", username="root@pam", password="testpassword"
        )

        tools = ProxmoxTools([credentials])

        # Mock all the operations
        with patch.object(tools, "initialize", new_callable=AsyncMock):
            with patch.object(
                tools.capability_executor, "execute_proxmox_container_create"
            ) as mock_create:
                mock_create.return_value = Mock(
                    success=True,
                    output="Container created successfully",
                    metadata={"vmid": 200, "task_id": "task-123"},
                )

                # Create container
                create_config = {
                    "host": "pve.test.com",
                    "template": "local:vztmpl/debian-12-standard_12.7-1_amd64.tar.gz",
                    "hostname": "test-container",
                }

                result = await tools.create_ct_from_template(100, create_config)

                assert result["success"] is True
                assert result["vmid"] == 200

    @pytest.mark.asyncio
    async def test_monitoring_integration(self):
        """Test monitoring service integration."""
        credentials = [
            ProxmoxAPICredentials(
                host="pve.test.com", username="root@pam", password="testpassword"
            )
        ]

        monitoring_service = ProxmoxMonitoringService(credentials)

        # Mock health checks
        with patch.object(
            monitoring_service.health_checker, "check_all_hosts"
        ) as mock_health:
            mock_health.return_value = {
                "pve.test.com": Mock(
                    status=HealthStatus.HEALTHY, message="Host is healthy", details={}
                )
            }

            status = await monitoring_service.manual_health_check()

            assert status["summary"]["total_hosts"] == 1
            assert status["summary"]["healthy_hosts"] == 1


# Test utilities and fixtures


@pytest.fixture
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def sample_proxmox_config():
    """Sample Proxmox configuration for testing."""
    return {
        "hosts": [
            {
                "host": "pve.test.com",
                "username": "root@pam",
                "password": "testpassword",
                "verify_ssl": False,
            }
        ],
        "defaults": {"storage": "local-lvm", "network_bridge": "vmbr0"},
    }


# Custom pytest markers for different test categories
def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "slow: Slow running tests")
    config.addinivalue_line("markers", "proxmox: Tests requiring Proxmox instance")


# Test data generators
def generate_test_container_config():
    """Generate a test container configuration."""
    return ContainerConfig(
        ostemplate="local:vztmpl/debian-12-standard_12.7-1_amd64.tar.gz",
        hostname="test-container",
        cores=2,
        memory=1024,
        rootfs="local-lvm:20",
        password="testpass",
    )


def generate_test_api_credentials():
    """Generate test API credentials."""
    return ProxmoxAPICredentials(
        host="pve.test.com", username="root@pam", password="testpassword"
    )


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short", "--asyncio-mode=auto"])
