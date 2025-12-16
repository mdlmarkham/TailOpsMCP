"""Comprehensive pytest fixtures and configuration for TailOpsMCP testing."""

import sys
import asyncio
import uuid
from pathlib import Path

# Add the project root to Python path to enable 'src' imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import pytest
import os
import json
from unittest.mock import Mock, AsyncMock
from datetime import datetime, timedelta
from src.auth.token_auth import TokenClaims


# =============================================================================
# Authentication and Authorization Fixtures
# =============================================================================


@pytest.fixture
def admin_claims():
    """Token claims with admin privileges for testing."""
    return TokenClaims(agent="test-admin", scopes=["admin"], host_tags=[], expiry=None)


@pytest.fixture
def readonly_claims():
    """Token claims with readonly privileges for testing."""
    return TokenClaims(
        agent="test-readonly", scopes=["readonly"], host_tags=[], expiry=None
    )


@pytest.fixture
def operator_claims():
    """Token claims with operator privileges for testing."""
    return TokenClaims(
        agent="test-operator",
        scopes=["fleet.read", "fleet.control"],
        host_tags=[],
        expiry=None,
    )


@pytest.fixture
def security_claims():
    """Token claims with security privileges for testing."""
    return TokenClaims(
        agent="test-security",
        scopes=["security.audit", "security.monitor"],
        host_tags=[],
        expiry=None,
    )


# =============================================================================
# Mock Service and Component Fixtures
# =============================================================================


@pytest.fixture
def mock_docker_client():
    """Mock Docker client for testing."""
    client = Mock()

    # Mock container
    mock_container = Mock()
    mock_container.id = "abc123456789"
    mock_container.name = "test-container"
    mock_container.status = "running"
    mock_container.image = Mock()
    mock_container.image.tags = ["nginx:latest"]
    mock_container.image.id = "img123456789"
    mock_container.attrs = {
        "Created": "2024-01-01T00:00:00Z",
        "State": {
            "StartedAt": "2024-01-01T00:00:00Z",
            "FinishedAt": "0001-01-01T00:00:00Z",
        },
        "HostConfig": {
            "PortBindings": {"80/tcp": [{"HostPort": "8080"}]},
            "Binds": ["/data:/app/data"],
            "NetworkMode": "bridge",
            "RestartPolicy": {"Name": "unless-stopped"},
        },
        "Config": {"Image": "nginx:latest", "Env": ["PATH=/usr/bin"], "Labels": {}},
        "NetworkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.2"}}},
    }
    mock_container.logs.return_value = b"Log line 1\nLog line 2\n"
    mock_container.start = Mock()
    mock_container.stop = Mock()
    mock_container.restart = Mock()
    mock_container.remove = Mock()

    # Mock image
    mock_image = Mock()
    mock_image.id = "img123456789"
    mock_image.tags = ["nginx:latest"]
    mock_image.attrs = {"Size": 142000000, "Created": "2024-01-01T00:00:00Z"}

    # Configure client mocks
    client.containers.list.return_value = [mock_container]
    client.containers.get.return_value = mock_container
    client.containers.run.return_value = mock_container
    client.images.pull.return_value = mock_image
    client.images.list.return_value = [mock_image]

    return client


@pytest.fixture
def mock_git_repo():
    """Mock Git repository for testing."""
    repo = Mock()
    repo.clone_from = Mock(return_value=repo)
    repo.remotes.origin.pull = Mock()
    repo.head.commit.hexsha = "abc1234567890def"
    repo.is_dirty.return_value = False
    return repo


@pytest.fixture
def mock_tsidp_server(requests_mock):
    """Mock TSIDP OAuth server responses."""
    # Mock OAuth discovery endpoint
    requests_mock.get(
        "https://tsidp.example.ts.net/.well-known/openid-configuration",
        json={
            "authorization_endpoint": "https://tsidp.example.ts.net/authorize",
            "token_endpoint": "https://tsidp.example.ts.net/oauth/token",
            "introspection_endpoint": "https://tsidp.example.ts.net/api/v2/oauth/introspect",
            "issuer": "https://tsidp.example.ts.net",
        },
    )

    # Mock token endpoint
    requests_mock.post(
        "https://tsidp.example.ts.net/oauth/token",
        json={
            "access_token": "test_access_token_12345",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "test_refresh_token_67890",
        },
    )

    # Mock introspection endpoint
    requests_mock.post(
        "https://tsidp.example.ts.net/api/v2/oauth/introspect",
        json={
            "active": True,
            "scope": "openid profile email",
            "client_id": "test-client-id",
            "username": "test-user",
            "token_type": "Bearer",
            "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
            "aud": ["http://localhost:8080"],
        },
    )

    return requests_mock


@pytest.fixture
def mock_mcp_client():
    """Mock MCP client with sampling support."""
    client = AsyncMock()

    # Mock create_message response for AI analysis
    client.create_message.return_value = Mock(
        content=[
            Mock(
                text='{"summary": "Test summary", "errors": [], "root_cause": "Test cause", "recommendations": ["Fix test"]}'
            )
        ]
    )

    return client


# =============================================================================
# Test Data and Configuration Fixtures
# =============================================================================


@pytest.fixture
def temp_test_dir(tmp_path):
    """Create a temporary directory for tests."""
    test_dir = tmp_path / "test_data"
    test_dir.mkdir()
    return test_dir


@pytest.fixture
def temp_config_file(temp_test_dir):
    """Create a temporary configuration file for tests."""
    config_file = temp_test_dir / "test_config.json"
    config_data = {
        "database": {"url": "sqlite:///test.db", "pool_size": 5},
        "security": {"require_authentication": True, "token_expiry": 3600},
        "logging": {"level": "DEBUG", "format": "json"},
    }

    with open(config_file, "w") as f:
        json.dump(config_data, f)

    return config_file


@pytest.fixture
def mock_subprocess():
    """Mock subprocess for command execution tests."""
    mock = Mock()
    mock.run = Mock(return_value=Mock(returncode=0, stdout="Success", stderr=""))
    return mock


@pytest.fixture
def mock_docker_compose():
    """Mock Docker Compose operations."""
    compose = Mock()
    compose.up = Mock(return_value={"success": True})
    compose.down = Mock(return_value={"success": True})
    compose.ps = Mock(return_value=[{"name": "service1", "state": "running"}])
    return compose


# =============================================================================
# Inventory and Fleet Management Fixtures
# =============================================================================


@pytest.fixture
def sample_inventory_data():
    """Sample inventory data for testing."""
    return {
        "system": {
            "hostname": "test-host",
            "container_id": "101",
            "container_type": "lxc",
            "mcp_server_name": "test-host-101",
        },
        "applications": [
            {
                "name": "nginx",
                "app_type": "web-server",
                "version": "1.21.0",
                "port": 80,
                "service_name": "nginx",
                "config_path": "/etc/nginx",
            }
        ],
        "stacks": [],
    }


@pytest.fixture
def enhanced_inventory_data():
    """Enhanced inventory data for comprehensive testing."""
    return {
        "gateway": {
            "id": "gateway-001",
            "hostname": "test-gateway",
            "role": "gateway",
            "ip_address": "192.168.1.1",
            "status": "healthy",
            "services": [
                {
                    "id": "service-001",
                    "name": "TailOpsMCP",
                    "type": "management",
                    "status": "running",
                    "port": 8080,
                    "version": "1.0.0",
                }
            ],
            "stacks": [],
            "last_seen": datetime.utcnow().isoformat(),
            "metadata": {"os": "Ubuntu 20.04", "architecture": "x86_64"},
        },
        "proxmox_hosts": [
            {
                "id": "proxmox-001",
                "hostname": "test-proxmox",
                "role": "proxmox_host",
                "ip_address": "192.168.1.10",
                "status": "healthy",
                "containers": ["container-101", "container-102"],
                "services": [
                    {
                        "id": "pve-service",
                        "name": "Proxmox VE",
                        "type": "virtualization",
                        "status": "running",
                        "port": 8006,
                        "version": "7.4-1",
                    }
                ],
                "stacks": [
                    {
                        "id": "stack-001",
                        "name": "web-stack",
                        "type": "web",
                        "services": ["nginx", "app", "database"],
                        "status": "running",
                    }
                ],
                "last_seen": datetime.utcnow().isoformat(),
                "metadata": {"cpu_cores": 16, "memory_gb": 64, "storage_gb": 1000},
            }
        ],
        "containers": [
            {
                "id": "container-101",
                "hostname": "web-container",
                "role": "container",
                "ip_address": "192.168.1.101",
                "status": "healthy",
                "parent_id": "proxmox-001",
                "services": [
                    {
                        "id": "nginx-service",
                        "name": "Nginx",
                        "type": "web-server",
                        "status": "running",
                        "port": 80,
                        "version": "1.18.0",
                    }
                ],
                "stacks": [],
                "last_seen": datetime.utcnow().isoformat(),
                "metadata": {
                    "image": "nginx:1.18",
                    "cpu_limit": "2",
                    "memory_limit": "1GB",
                },
            }
        ],
    }


# =============================================================================
# Workflow and Policy Fixtures
# =============================================================================


@pytest.fixture
def sample_workflow_blueprint():
    """Sample workflow blueprint for testing."""
    return {
        "id": str(uuid.uuid4()),
        "name": "Test Workflow",
        "description": "Test workflow for unit testing",
        "version": "1.0",
        "steps": [
            {
                "id": "step1",
                "name": "Initialize",
                "type": "action",
                "action": "initialize",
                "parameters": {},
            },
            {
                "id": "step2",
                "name": "Execute",
                "type": "action",
                "action": "execute",
                "parameters": {},
            },
        ],
        "triggers": [],
        "approvals_required": [],
        "timeout": 3600,
        "created_by": "test",
    }


@pytest.fixture
def sample_policy_config():
    """Sample policy configuration for testing."""
    return {
        "version": "1.0",
        "policy_name": "test_fleet_management",
        "default_tier": "observe",
        "operations": {
            "fleet_discover": {
                "tier": "observe",
                "description": "Run fleet discovery",
                "allowed_targets": ["gateway"],
            },
            "fleet_inventory_get": {
                "tier": "observe",
                "description": "Retrieve fleet inventory",
                "allowed_targets": ["gateway"],
            },
            "plan_update_packages": {
                "tier": "control",
                "description": "Plan package update",
                "allowed_targets": ["*"],
                "parameters": {"update_only": [True, False], "upgrade": [True, False]},
            },
        },
        "security_constraints": {
            "deny_by_default": True,
            "require_approval": ["control", "execute"],
            "audit_all_operations": True,
        },
    }


# =============================================================================
# Event and Observability Fixtures
# =============================================================================


@pytest.fixture
def sample_events():
    """Sample events for testing."""
    return [
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "system_alert",
            "severity": "info",
            "source": "test-system",
            "message": "Test event 1",
            "metadata": {},
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "security_alert",
            "severity": "warning",
            "source": "security-monitor",
            "message": "Test event 2",
            "metadata": {},
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "performance_alert",
            "severity": "critical",
            "source": "performance-monitor",
            "message": "Test event 3",
            "metadata": {},
        },
    ]


# =============================================================================
# Performance and Load Testing Fixtures
# =============================================================================


@pytest.fixture
def performance_test_config():
    """Performance test configuration."""
    return {
        "target_counts": [10, 50, 100, 500],
        "concurrent_users": [1, 5, 10, 25, 50],
        "response_time_threshold": 5.0,  # seconds
        "throughput_threshold": 10,  # ops per second
        "memory_limit_mb": 2048,
        "cpu_limit_percent": 80,
    }


@pytest.fixture
def load_test_scenarios():
    """Load test scenarios for different components."""
    return {
        "inventory_load": {
            "target_counts": [100, 500, 1000, 5000],
            "operations": ["discovery", "query", "update", "delete"],
            "concurrent_users": [1, 5, 10, 25, 50],
        },
        "workflow_load": {
            "workflow_counts": [10, 50, 100, 500],
            "workflow_types": ["provisioning", "backup", "deployment"],
            "concurrent_executions": [1, 5, 10, 25],
        },
        "event_load": {
            "event_counts": [100, 500, 1000, 5000],
            "event_types": ["alert", "log", "metric", "audit"],
            "processing_modes": ["sync", "async", "batch"],
        },
    }


# =============================================================================
# Security Testing Fixtures
# =============================================================================


@pytest.fixture
def security_test_data():
    """Security test data for various attack scenarios."""
    return {
        "malicious_tokens": [
            "invalid_token_format",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.payload",
            "Bearer null",
            "Bearer ..",
        ],
        "injection_patterns": [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1' UNION SELECT * FROM users --",
            "<script>alert('xss')</script>",
            "../../../etc/passwd",
        ],
        "privilege_escalation": [
            {"user_role": "user", "requested_role": "admin"},
            {"user_role": "guest", "requested_role": "super_admin"},
            {"user_role": None, "requested_role": "admin"},
        ],
    }


# =============================================================================
# Environment and Setup Fixtures
# =============================================================================


@pytest.fixture(autouse=True)
def reset_env_vars():
    """Reset environment variables between tests."""
    # Save original environment
    original_env = os.environ.copy()

    # Set test environment variables
    os.environ.update(
        {
            "TAILOPS_TEST_MODE": "true",
            "TAILOPS_TEST_DATABASE": ":memory:",
            "TAILOPS_TEST_LOG_LEVEL": "DEBUG",
            "TAILOPS_MOCK_EXTERNAL_SERVICES": "true",
        }
    )

    yield

    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def test_database():
    """Create a test database for integration tests."""
    # This would create a test database in a real implementation
    # For now, return a mock database connection
    db = Mock()
    db.connect = Mock(return_value=True)
    db.execute = Mock(return_value=Mock(rowcount=1))
    db.close = Mock(return_value=True)
    return db


@pytest.fixture
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# =============================================================================
# Mock Service Factory Fixtures
# =============================================================================


@pytest.fixture
def mock_service_factory():
    """Factory for creating mock services."""

    class MockServiceFactory:
        @staticmethod
        def create_inventory_service():
            service = Mock()
            service.run_full_discovery = AsyncMock(return_value={"targets": []})
            service.get_inventory = AsyncMock(return_value={})
            service.detect_changes = AsyncMock(return_value={})
            return service

        @staticmethod
        def create_policy_engine():
            engine = Mock()
            engine.evaluate_policy = AsyncMock(return_value={"allowed": True})
            engine.enforce_policy = AsyncMock(return_value=True)
            return engine

        @staticmethod
        def create_workflow_engine():
            engine = Mock()
            engine.execute_workflow = AsyncMock(return_value="execution-123")
            engine.get_execution_status = AsyncMock(return_value={"status": "running"})
            return engine

        @staticmethod
        def create_event_processor():
            processor = Mock()
            processor.process_event = AsyncMock(return_value=True)
            processor.get_event_stats = AsyncMock(return_value={})
            return processor

        @staticmethod
        def create_access_control():
            access_control = Mock()
            access_control.check_permission = AsyncMock(return_value=True)
            access_control.get_user_permissions = AsyncMock(return_value=[])
            return access_control

    return MockServiceFactory()


# =============================================================================
# Cleanup and Validation Fixtures
# =============================================================================


@pytest.fixture
def test_cleanup():
    """Cleanup fixture for test resources."""
    resources = []

    def add_resource(resource, cleanup_func):
        resources.append((resource, cleanup_func))

    yield add_resource

    # Cleanup all resources
    for resource, cleanup_func in resources:
        try:
            cleanup_func(resource)
        except Exception as e:
            print(f"Cleanup error: {e}")


@pytest.fixture
def validate_test_environment():
    """Validate test environment setup."""

    def _validate():
        # Validate required environment variables
        required_vars = ["TAILOPS_TEST_MODE"]
        for var in required_vars:
            assert os.getenv(var) is not None, (
                f"Required environment variable {var} not set"
            )

        # Validate Python version
        import sys

        assert sys.version_info >= (3, 8), "Python 3.8+ required"

        return True

    return _validate
