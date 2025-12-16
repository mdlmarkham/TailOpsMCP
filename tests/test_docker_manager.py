"""Tests for Docker Manager service (docker_manager.py)."""

import pytest
from unittest.mock import Mock, patch
import docker.errors
from src.services.docker_manager import DockerManager


@pytest.fixture
def docker_manager(mock_docker_client):
    """Create DockerManager with mocked Docker client."""
    with patch("docker.from_env", return_value=mock_docker_client):
        manager = DockerManager()
        manager.client = mock_docker_client
        return manager


@pytest.fixture
def docker_manager_no_client():
    """Create DockerManager without Docker client (simulating Docker not available)."""
    with patch("docker.from_env", side_effect=Exception("Docker not available")):
        manager = DockerManager()
        return manager


class TestDockerManagerInitialization:
    """Test Docker Manager initialization."""

    def test_init_with_docker_available(self, mock_docker_client):
        """Test initialization when Docker is available."""
        with patch("docker.from_env", return_value=mock_docker_client):
            manager = DockerManager()
            assert manager.client is not None

    def test_init_without_docker_available(self):
        """Test initialization when Docker is not available."""
        with patch("docker.from_env", side_effect=Exception("Docker not available")):
            manager = DockerManager()
            assert manager.client is None


class TestListContainers:
    """Test listing Docker containers."""

    @pytest.mark.asyncio
    async def test_list_containers_success(self, docker_manager, mock_docker_client):
        """Test successfully listing containers."""
        result = await docker_manager.list_containers()

        assert result["success"] is True
        assert "data" in result
        assert len(result["data"]) > 0
        assert result["data"][0]["name"] == "test-container"
        assert result["data"][0]["status"] == "running"

    @pytest.mark.asyncio
    async def test_list_containers_show_all(self, docker_manager, mock_docker_client):
        """Test listing all containers including stopped ones."""
        result = await docker_manager.list_containers(show_all=True)

        assert result["success"] is True
        mock_docker_client.containers.list.assert_called_with(all=True)

    @pytest.mark.asyncio
    async def test_list_containers_no_client(self, docker_manager_no_client):
        """Test listing containers without Docker client."""
        result = await docker_manager_no_client.list_containers()

        assert result["success"] is False
        assert "Docker client not available" in result["error"]

    @pytest.mark.asyncio
    async def test_list_containers_api_error(self, docker_manager, mock_docker_client):
        """Test handling API errors when listing containers."""
        mock_docker_client.containers.list.side_effect = Exception("API Error")

        result = await docker_manager.list_containers()

        assert result["success"] is False
        assert "error" in result


class TestGetContainerInfo:
    """Test getting container information."""

    @pytest.mark.asyncio
    async def test_get_container_info_success(self, docker_manager, mock_docker_client):
        """Test successfully getting container info."""
        result = await docker_manager.get_container_info("test-container")

        assert result["success"] is True
        assert "data" in result
        assert result["data"]["name"] == "test-container"
        assert result["data"]["status"] == "running"
        assert "ports" in result["data"]
        assert "environment" in result["data"]

    @pytest.mark.asyncio
    async def test_get_container_info_not_found(
        self, docker_manager, mock_docker_client
    ):
        """Test getting info for non-existent container."""
        mock_docker_client.containers.get.side_effect = docker.errors.NotFound(
            "Container not found"
        )

        result = await docker_manager.get_container_info("nonexistent")

        assert result["success"] is False
        assert "not found" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_get_container_info_no_client(self, docker_manager_no_client):
        """Test getting container info without Docker client."""
        result = await docker_manager_no_client.get_container_info("test")

        assert result["success"] is False
        assert "Docker client not available" in result["error"]


class TestStartContainer:
    """Test starting containers."""

    @pytest.mark.asyncio
    async def test_start_container_success(self, docker_manager, mock_docker_client):
        """Test successfully starting a container."""
        result = await docker_manager.start_container("test-container")

        assert result["success"] is True
        assert "started" in result["message"].lower()
        mock_docker_client.containers.get.return_value.start.assert_called_once()

    @pytest.mark.asyncio
    async def test_start_container_not_found(self, docker_manager, mock_docker_client):
        """Test starting non-existent container."""
        mock_docker_client.containers.get.side_effect = docker.errors.NotFound(
            "Not found"
        )

        result = await docker_manager.start_container("nonexistent")

        assert result["success"] is False
        assert "not found" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_start_container_no_client(self, docker_manager_no_client):
        """Test starting container without Docker client."""
        result = await docker_manager_no_client.start_container("test")

        assert result["success"] is False


class TestStopContainer:
    """Test stopping containers."""

    @pytest.mark.asyncio
    async def test_stop_container_success(self, docker_manager, mock_docker_client):
        """Test successfully stopping a container."""
        result = await docker_manager.stop_container("test-container")

        assert result["success"] is True
        assert "stopped" in result["message"].lower()
        mock_docker_client.containers.get.return_value.stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_container_not_found(self, docker_manager, mock_docker_client):
        """Test stopping non-existent container."""
        mock_docker_client.containers.get.side_effect = docker.errors.NotFound(
            "Not found"
        )

        result = await docker_manager.stop_container("nonexistent")

        assert result["success"] is False


class TestRestartContainer:
    """Test restarting containers."""

    @pytest.mark.asyncio
    async def test_restart_container_success(self, docker_manager, mock_docker_client):
        """Test successfully restarting a container."""
        result = await docker_manager.restart_container("test-container")

        assert result["success"] is True
        assert "restarted" in result["message"].lower()
        mock_docker_client.containers.get.return_value.restart.assert_called_once()

    @pytest.mark.asyncio
    async def test_restart_container_not_found(
        self, docker_manager, mock_docker_client
    ):
        """Test restarting non-existent container."""
        mock_docker_client.containers.get.side_effect = docker.errors.NotFound(
            "Not found"
        )

        result = await docker_manager.restart_container("nonexistent")

        assert result["success"] is False


class TestGetContainerLogs:
    """Test retrieving container logs."""

    @pytest.mark.asyncio
    async def test_get_container_logs_success(self, docker_manager, mock_docker_client):
        """Test successfully getting container logs."""
        result = await docker_manager.get_container_logs("test-container")

        assert result["success"] is True
        assert "data" in result
        assert "Log line 1" in result["data"]

    @pytest.mark.asyncio
    async def test_get_container_logs_custom_tail(
        self, docker_manager, mock_docker_client
    ):
        """Test getting logs with custom tail parameter."""
        result = await docker_manager.get_container_logs("test-container", tail=50)

        assert result["success"] is True
        mock_docker_client.containers.get.return_value.logs.assert_called_with(tail=50)

    @pytest.mark.asyncio
    async def test_get_container_logs_not_found(
        self, docker_manager, mock_docker_client
    ):
        """Test getting logs for non-existent container."""
        mock_docker_client.containers.get.side_effect = docker.errors.NotFound(
            "Not found"
        )

        result = await docker_manager.get_container_logs("nonexistent")

        assert result["success"] is False


class TestPullImage:
    """Test pulling Docker images."""

    @pytest.mark.asyncio
    async def test_pull_image_success(self, docker_manager, mock_docker_client):
        """Test successfully pulling an image."""
        result = await docker_manager.pull_image("nginx", "latest")

        assert result["success"] is True
        assert result["image"] == "nginx:latest"
        assert "image_id" in result
        assert "tags" in result

    @pytest.mark.asyncio
    async def test_pull_image_default_tag(self, docker_manager, mock_docker_client):
        """Test pulling image with default latest tag."""
        result = await docker_manager.pull_image("nginx")

        assert result["success"] is True
        assert result["image"] == "nginx:latest"

    @pytest.mark.asyncio
    async def test_pull_image_api_error(self, docker_manager, mock_docker_client):
        """Test handling API error during pull."""
        mock_docker_client.images.pull.side_effect = docker.errors.APIError(
            "Pull failed"
        )

        result = await docker_manager.pull_image("invalid-image")

        assert result["success"] is False
        assert "Docker API error" in result["error"]

    @pytest.mark.asyncio
    async def test_pull_image_no_client(self, docker_manager_no_client):
        """Test pulling image without Docker client."""
        result = await docker_manager_no_client.pull_image("nginx")

        assert result["success"] is False


class TestListImages:
    """Test listing Docker images."""

    @pytest.mark.asyncio
    async def test_list_images_success(self, docker_manager, mock_docker_client):
        """Test successfully listing images."""
        result = await docker_manager.list_images()

        assert result["success"] is True
        assert "data" in result
        assert "count" in result
        assert len(result["data"]) > 0

    @pytest.mark.asyncio
    async def test_list_images_no_client(self, docker_manager_no_client):
        """Test listing images without Docker client."""
        result = await docker_manager_no_client.list_images()

        assert result["success"] is False


class TestUpdateContainer:
    """Test updating containers with new images."""

    @pytest.mark.asyncio
    async def test_update_container_with_new_image(
        self, docker_manager, mock_docker_client
    ):
        """Test updating container when new image is available."""
        # Mock different image IDs to simulate update
        old_container = mock_docker_client.containers.get.return_value
        old_container.image.id = "oldimg12345"

        new_image = Mock()
        new_image.id = "newimg67890"
        new_image.tags = ["nginx:latest"]
        new_image.attrs = {"Size": 150000000}
        mock_docker_client.images.pull.return_value = new_image

        result = await docker_manager.update_container(
            "test-container", pull_latest=True
        )

        assert result["success"] is True
        assert result["updated"] is True
        assert result["old_image_id"] == "oldimg12345"
        assert result["new_image_id"][:6] == "newimg"

    @pytest.mark.asyncio
    async def test_update_container_no_new_image(
        self, docker_manager, mock_docker_client
    ):
        """Test updating container when already on latest image."""
        # Mock same image ID
        container = mock_docker_client.containers.get.return_value
        container.image.id = "img123456789"

        image = Mock()
        image.id = "img123456789"
        image.attrs = {"Size": 142000000}
        mock_docker_client.images.pull.return_value = image

        result = await docker_manager.update_container(
            "test-container", pull_latest=True
        )

        assert result["success"] is True
        assert result["updated"] is False
        assert "already using latest" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_update_container_without_pull(
        self, docker_manager, mock_docker_client
    ):
        """Test updating container without pulling new image."""
        container = mock_docker_client.containers.get.return_value

        result = await docker_manager.update_container(
            "test-container", pull_latest=False
        )

        assert result["success"] is True
        assert result["updated"] is False

    @pytest.mark.asyncio
    async def test_update_container_host_network_mode(
        self, docker_manager, mock_docker_client
    ):
        """Test updating container with host network mode (no port bindings)."""
        # Setup container with host network
        container = mock_docker_client.containers.get.return_value
        container.attrs["HostConfig"]["NetworkMode"] = "host"
        container.image.id = "oldimg123"

        new_image = Mock()
        new_image.id = "newimg456"
        new_image.attrs = {"Size": 150000000}
        mock_docker_client.images.pull.return_value = new_image

        result = await docker_manager.update_container(
            "test-container", pull_latest=True
        )

        assert result["success"] is True
        # Verify ports were not added for host network
        run_call = mock_docker_client.containers.run.call_args
        assert "ports" not in run_call.kwargs

    @pytest.mark.asyncio
    async def test_update_container_bridge_network_with_ports(
        self, docker_manager, mock_docker_client
    ):
        """Test updating container with bridge network mode (includes port bindings)."""
        container = mock_docker_client.containers.get.return_value
        container.attrs["HostConfig"]["NetworkMode"] = "bridge"
        container.image.id = "oldimg123"

        new_image = Mock()
        new_image.id = "newimg456"
        new_image.attrs = {"Size": 150000000}
        mock_docker_client.images.pull.return_value = new_image

        result = await docker_manager.update_container(
            "test-container", pull_latest=True
        )

        assert result["success"] is True
        # Verify ports were added for bridge network
        run_call = mock_docker_client.containers.run.call_args
        assert "ports" in run_call.kwargs

    @pytest.mark.asyncio
    async def test_update_container_preserves_config(
        self, docker_manager, mock_docker_client
    ):
        """Test update preserves container configuration."""
        container = mock_docker_client.containers.get.return_value
        container.image.id = "oldimg123"

        new_image = Mock()
        new_image.id = "newimg456"
        new_image.attrs = {"Size": 150000000}
        mock_docker_client.images.pull.return_value = new_image

        result = await docker_manager.update_container(
            "test-container", pull_latest=True
        )

        # Verify configuration was preserved
        run_call = mock_docker_client.containers.run.call_args
        assert run_call.kwargs["name"] == "test-container"
        assert run_call.kwargs["environment"] == ["PATH=/usr/bin"]
        assert run_call.kwargs["volumes"] == ["/data:/app/data"]

    @pytest.mark.asyncio
    async def test_update_container_not_found(self, docker_manager, mock_docker_client):
        """Test updating non-existent container."""
        mock_docker_client.containers.get.side_effect = docker.errors.NotFound(
            "Not found"
        )

        result = await docker_manager.update_container("nonexistent")

        assert result["success"] is False
        assert "not found" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_update_container_pull_fails(
        self, docker_manager, mock_docker_client
    ):
        """Test update when image pull fails."""
        mock_docker_client.images.pull.side_effect = docker.errors.APIError(
            "Pull failed"
        )

        result = await docker_manager.update_container("test-container")

        assert result["success"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_update_container_no_client(self, docker_manager_no_client):
        """Test updating container without Docker client."""
        result = await docker_manager_no_client.update_container("test")

        assert result["success"] is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
