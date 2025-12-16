"""
Integration tests for Target Registry implementation.
"""

import tempfile
import os

from src.models.target_registry import (
    TargetMetadata,
    TargetConnection,
    TargetConstraints,
    ExecutorType,
)
from src.services.target_registry import TargetRegistry


class TestTargetRegistry:
    """Test Target Registry functionality."""

    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.temp_dir, "targets.yaml")

    def teardown_method(self):
        """Clean up test environment."""
        import shutil

        shutil.rmtree(self.temp_dir)

    def create_test_config(self, config_content: str):
        """Create test configuration file."""
        with open(self.config_path, "w") as f:
            f.write(config_content)

    def test_load_valid_config(self):
        """Test loading valid configuration."""
        config = """
version: "1.0"
targets:
  local:
    id: "local"
    type: "local"
    executor: "local"
    capabilities: ["system:read", "container:read"]
    constraints:
      timeout: 30
      concurrency: 5
      sudo_policy: "none"
    metadata:
      hostname: "test-host"
      platform: "test-platform"
"""
        self.create_test_config(config)

        registry = TargetRegistry(self.config_path)
        assert registry.load() == True
        assert len(registry.get_errors()) == 0
        assert "local" in registry.list_targets()

    def test_load_invalid_config(self):
        """Test loading invalid configuration."""
        config = """
version: "1.0"
targets:
  invalid-target:
    id: ""
    type: "invalid"
    executor: "invalid"
    capabilities: ["invalid:scope"]
    constraints:
      timeout: -1
      concurrency: 0
    metadata: {}
"""
        self.create_test_config(config)

        registry = TargetRegistry(self.config_path)
        assert registry.load() == False
        assert len(registry.get_errors()) > 0

    def test_add_remove_target(self):
        """Test adding and removing targets."""
        registry = TargetRegistry(self.config_path)

        # Create test target
        connection = TargetConnection(
            executor=ExecutorType.SSH,
            host="test-host",
            port=22,
            username="test-user",
            key_path="${TEST_KEY}",
        )
        constraints = TargetConstraints(timeout=60, concurrency=2)

        target = TargetMetadata(
            id="test-target",
            type="remote",
            executor=ExecutorType.SSH,
            connection=connection,
            capabilities=["system:read", "network:read"],
            constraints=constraints,
            metadata={"hostname": "test-host", "platform": "test-platform"},
        )

        # Add target
        assert registry.add_target(target) == True
        assert "test-target" in registry.list_targets()

        # Remove target
        assert registry.remove_target("test-target") == True
        assert "test-target" not in registry.list_targets()

    def test_get_target_by_type(self):
        """Test filtering targets by type."""
        config = """
version: "1.0"
targets:
  local:
    id: "local"
    type: "local"
    executor: "local"
    capabilities: ["system:read"]
    constraints: {timeout: 30, concurrency: 5}
    metadata: {hostname: "local-host"}

  remote-ssh:
    id: "remote-ssh"
    type: "remote"
    executor: "ssh"
    capabilities: ["system:read"]
    constraints: {timeout: 60, concurrency: 2}
    metadata: {hostname: "remote-host"}
"""
        self.create_test_config(config)

        registry = TargetRegistry(self.config_path)
        registry.load()

        local_targets = registry.get_targets_by_type("local")
        assert len(local_targets) == 1
        assert "local" in local_targets

        remote_targets = registry.get_targets_by_type("remote")
        assert len(remote_targets) == 1
        assert "remote-ssh" in remote_targets

    def test_get_target_by_executor(self):
        """Test filtering targets by executor."""
        config = """
version: "1.0"
targets:
  local:
    id: "local"
    type: "local"
    executor: "local"
    capabilities: ["system:read"]
    constraints: {timeout: 30, concurrency: 5}
    metadata: {hostname: "local-host"}

  docker-target:
    id: "docker-target"
    type: "remote"
    executor: "docker"
    capabilities: ["container:read"]
    constraints: {timeout: 90, concurrency: 3}
    metadata: {hostname: "docker-host"}
"""
        self.create_test_config(config)

        registry = TargetRegistry(self.config_path)
        registry.load()

        docker_targets = registry.get_targets_by_executor("docker")
        assert len(docker_targets) == 1
        assert "docker-target" in docker_targets

    def test_save_config(self):
        """Test saving configuration."""
        registry = TargetRegistry(self.config_path)

        # Add a target
        connection = TargetConnection(executor=ExecutorType.LOCAL)
        constraints = TargetConstraints()

        target = TargetMetadata(
            id="test-save",
            type="local",
            executor=ExecutorType.LOCAL,
            connection=connection,
            capabilities=["system:read"],
            constraints=constraints,
            metadata={"hostname": "test-save-host"},
        )

        registry.add_target(target)
        assert registry.save() == True

        # Verify file was created
        assert os.path.exists(self.config_path)

    def test_target_validation(self):
        """Test target validation."""
        # Test valid target
        connection = TargetConnection(executor=ExecutorType.LOCAL)
        constraints = TargetConstraints(timeout=30, concurrency=5)

        target = TargetMetadata(
            id="valid-target",
            type="local",
            executor=ExecutorType.LOCAL,
            connection=connection,
            capabilities=["system:read"],
            constraints=constraints,
            metadata={"hostname": "test-host"},
        )

        errors = target.validate()
        assert len(errors) == 0

        # Test invalid target
        invalid_connection = TargetConnection(
            executor=ExecutorType.SSH
        )  # Missing required fields
        invalid_target = TargetMetadata(
            id="",  # Empty ID
            type="invalid",
            executor=ExecutorType.SSH,
            connection=invalid_connection,
            capabilities=["invalid:scope"],
            constraints=TargetConstraints(timeout=-1),  # Invalid timeout
            metadata={},
        )

        errors = invalid_target.validate()
        assert len(errors) > 0

    def test_has_capability(self):
        """Test capability checking."""
        from src.auth.scopes import Scope

        connection = TargetConnection(executor=ExecutorType.LOCAL)
        constraints = TargetConstraints()

        target = TargetMetadata(
            id="capability-test",
            type="local",
            executor=ExecutorType.LOCAL,
            connection=connection,
            capabilities=["system:read", "network:read"],
            constraints=constraints,
            metadata={"hostname": "test-host"},
        )

        assert target.has_capability(Scope.SYSTEM_READ) == True
        assert target.has_capability(Scope.NETWORK_READ) == True
        assert target.has_capability(Scope.CONTAINER_WRITE) == False
