"""Shared pytest fixtures and configuration for all tests."""

import sys
from pathlib import Path

# Add the project root to Python path to enable 'src' imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import pytest
import os
from unittest.mock import Mock, MagicMock, AsyncMock
from datetime import datetime, timedelta
from src.auth.token_auth import TokenClaims


@pytest.fixture
def admin_claims():
    """Token claims with admin privileges for testing."""
    return TokenClaims(
        agent="test-admin",
        scopes=["admin"],
        host_tags=[],
        expiry=None
    )


@pytest.fixture
def readonly_claims():
    """Token claims with readonly privileges for testing."""
    return TokenClaims(
        agent="test-readonly",
        scopes=["readonly"],
        host_tags=[],
        expiry=None
    )


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
            "FinishedAt": "0001-01-01T00:00:00Z"
        },
        "HostConfig": {
            "PortBindings": {"80/tcp": [{"HostPort": "8080"}]},
            "Binds": ["/data:/app/data"],
            "NetworkMode": "bridge",
            "RestartPolicy": {"Name": "unless-stopped"}
        },
        "Config": {
            "Image": "nginx:latest",
            "Env": ["PATH=/usr/bin"],
            "Labels": {}
        },
        "NetworkSettings": {
            "Networks": {
                "bridge": {"IPAddress": "172.17.0.2"}
            }
        }
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
    mock_image.attrs = {
        "Size": 142000000,
        "Created": "2024-01-01T00:00:00Z"
    }

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
            "issuer": "https://tsidp.example.ts.net"
        }
    )

    # Mock token endpoint
    requests_mock.post(
        "https://tsidp.example.ts.net/oauth/token",
        json={
            "access_token": "test_access_token_12345",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "test_refresh_token_67890"
        }
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
            "aud": ["http://localhost:8080"]
        }
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


@pytest.fixture
def temp_test_dir(tmp_path):
    """Create a temporary directory for tests."""
    test_dir = tmp_path / "test_data"
    test_dir.mkdir()
    return test_dir


@pytest.fixture
def mock_subprocess():
    """Mock subprocess for command execution tests."""
    mock = Mock()
    mock.run = Mock(return_value=Mock(
        returncode=0,
        stdout="Success",
        stderr=""
    ))
    return mock


@pytest.fixture(autouse=True)
def reset_env_vars():
    """Reset environment variables between tests."""
    # Save original environment
    original_env = os.environ.copy()

    yield

    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def mock_docker_compose():
    """Mock Docker Compose operations."""
    compose = Mock()
    compose.up = Mock(return_value={"success": True})
    compose.down = Mock(return_value={"success": True})
    compose.ps = Mock(return_value=[{"name": "service1", "state": "running"}])
    return compose


@pytest.fixture
def sample_inventory_data():
    """Sample inventory data for testing."""
    return {
        "system": {
            "hostname": "test-host",
            "container_id": "101",
            "container_type": "lxc",
            "mcp_server_name": "test-host-101"
        },
        "applications": [
            {
                "name": "nginx",
                "app_type": "web-server",
                "version": "1.21.0",
                "port": 80,
                "service_name": "nginx",
                "config_path": "/etc/nginx"
            }
        ],
        "stacks": []
    }
