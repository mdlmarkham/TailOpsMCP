"""
Enhanced test suite for target registry with comprehensive coverage.
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch

from src.services.target_registry import TargetRegistry
from src.models.target_registry import TargetMetadata, TargetConnection, TargetConstraints
from src.auth.scopes import Scope

from tests.fixtures.target_registry_fixtures import (
    TEST_TARGETS_CONFIG,
    INVALID_TARGETS_CONFIG,
    MINIMAL_TARGET_CONFIG,
    TargetRegistryFixtures,
    assert_target_metadata_equal
)


class TestTargetRegistry:
    """Comprehensive tests for Target Registry functionality."""
    
    def test_load_valid_configuration(self):
        """Test loading valid target configuration."""
        registry = TargetRegistryFixtures.create_target_registry_with_config(TEST_TARGETS_CONFIG)
        
        assert registry is not None
        assert len(registry.get_all_targets()) == 5
        assert registry.get_errors() == []
    
    def test_load_invalid_configuration(self):
        """Test loading invalid target configuration."""
        registry = TargetRegistryFixtures.create_target_registry_with_config(INVALID_TARGETS_CONFIG)
        
        assert registry is not None
        assert len(registry.get_errors()) > 0
    
    def test_load_minimal_configuration(self):
        """Test loading minimal target configuration."""
        registry = TargetRegistryFixtures.create_target_registry_with_config(MINIMAL_TARGET_CONFIG)
        
        assert registry is not None
        targets = registry.get_all_targets()
        assert len(targets) == 1
        
        target = targets["minimal-target"]
        assert target.id == "minimal-target"
        assert target.type == "local"
        assert target.executor.value == "local"
    
    def test_get_target_by_id(self):
        """Test retrieving target by identifier."""
        registry = TargetRegistryFixtures.create_target_registry_with_config(TEST_TARGETS_CONFIG)
        
        target = registry.get_target("local-host")
        assert target is not None
        assert target.id == "local-host"
        assert target.type == "local"
    
    def test_get_nonexistent_target(self):
        """Test retrieving non-existent target."""
        registry = TargetRegistryFixtures.create_target_registry_with_config(TEST_TARGETS_CONFIG)
        
        target = registry.get_target("nonexistent-target")
        assert target is None
    
    def test_target_capabilities(self):
        """Test target capability validation."""
        registry = TargetRegistryFixtures.create_target_registry_with_config(TEST_TARGETS_CONFIG)
        
        target = registry.get_target("local-host")
        assert target is not None
        
        # Check specific capabilities
        assert Scope.CONTAINER_READ.value in target.capabilities
        assert Scope.CONTAINER_WRITE.value in target.capabilities
        assert Scope.SYSTEM_READ.value in target.capabilities
        assert Scope.SYSTEM_WRITE.value in target.capabilities
    
    def test_target_constraints(self):
        """Test target constraint validation."""
        registry = TargetRegistryFixtures.create_target_registry_with_config(TEST_TARGETS_CONFIG)
        
        target = registry.get_target("ssh-server")
        assert target is not None
        
        constraints = target.constraints
        assert constraints is not None
        assert "docker" in constraints.allowed_commands
        assert "systemctl" in constraints.allowed_commands
        assert "/opt" in constraints.allowed_paths
        assert constraints.max_concurrent == 3
    
    def test_target_metadata(self):
        """Test target metadata extraction."""
        registry = TargetRegistryFixtures.create_target_registry_with_config(TEST_TARGETS_CONFIG)
        
        target = registry.get_target("docker-host")
        assert target is not None
        
        metadata = target.metadata
        assert metadata is not None
        assert metadata["docker_version"] == "20.10"
        assert metadata["storage_driver"] == "overlay2"
    
    def test_connection_configuration(self):
        """Test target connection configuration."""
        registry = TargetRegistryFixtures.create_target_registry_with_config(TEST_TARGETS_CONFIG)
        
        target = registry.get_target("ssh-server")
        assert target is not None
        
        connection = target.connection
        assert connection is not None
        assert connection.executor.value == "ssh"
        assert connection.host == "test.example.com"
        assert connection.port == 22
        assert connection.username == "testuser"
        assert connection.key_path == "/path/to/key"
    
    def test_validate_target_success(self):
        """Test successful target validation."""
        registry = TargetRegistryFixtures.create_target_registry_with_config(TEST_TARGETS_CONFIG)
        
        target = registry.get_target("local-host")
        assert target is not None
        
        # This should not raise an exception for valid target
        assert registry.validate_target(target) is True
    
    def test_reload_configuration(self):
        """Test reloading configuration."""
        # Create initial configuration
        initial_config = {
            "targets": {
                "target-1": {
                    "id": "target-1",
                    "type": "local",
                    "executor": "local",
                    "connection": {"executor": "local"}
                }
            }
        }
        
        registry = TargetRegistryFixtures.create_target_registry_with_config(initial_config)
        assert len(registry.get_all_targets()) == 1
        
        # Simulate configuration change
        updated_config = {
            "targets": {
                "target-1": {
                    "id": "target-1",
                    "type": "local",
                    "executor": "local",
                    "connection": {"executor": "local"}
                },
                "target-2": {
                    "id": "target-2",
                    "type": "ssh",
                    "executor": "ssh",
                    "connection": {
                        "executor": "ssh",
                        "host": "test.example.com",
                        "port": 22
                    }
                }
            }
        }
        
        # Create new registry with updated config
        updated_registry = TargetRegistryFixtures.create_target_registry_with_config(updated_config)
        assert len(updated_registry.get_all_targets()) == 2


class TestTargetRegistryEdgeCases:
    """Tests for edge cases and error conditions."""
    
    def test_missing_configuration_file(self):
        """Test behavior when configuration file is missing."""
        # Create registry with non-existent file
        registry = TargetRegistry(config_path="/nonexistent/path/targets.yaml")
        
        assert len(registry.get_errors()) > 0
        assert "not found" in registry.get_errors()[0]
    
    def test_malformed_yaml(self):
        """Test behavior with malformed YAML configuration."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("invalid: yaml: [content")
            config_path = f.name
        
        try:
            registry = TargetRegistry(config_path=config_path)
            assert len(registry.get_errors()) > 0
        finally:
            os.unlink(config_path)
    
    def test_empty_configuration(self):
        """Test behavior with empty configuration."""
        empty_config = {"targets": {}}
        registry = TargetRegistryFixtures.create_target_registry_with_config(empty_config)
        
        assert len(registry.get_all_targets()) == 0
        assert registry.get_errors() == []
    
    def test_duplicate_target_ids(self):
        """Test behavior with duplicate target IDs."""
        duplicate_config = {
            "targets": {
                "duplicate-target": {
                    "id": "duplicate-target",
                    "type": "local",
                    "executor": "local",
                    "connection": {"executor": "local"}
                },
                "another-target": {
                    "id": "duplicate-target",  # Duplicate ID
                    "type": "ssh",
                    "executor": "ssh",
                    "connection": {"executor": "ssh"}
                }
            }
        }
        
        registry = TargetRegistryFixtures.create_target_registry_with_config(duplicate_config)
        
        # Should only load one target with the duplicate ID
        targets = registry.get_all_targets()
        assert len(targets) == 1
        assert "duplicate-target" in targets


class TestTargetRegistryPerformance:
    """Performance tests for Target Registry."""
    
    def test_load_large_configuration(self):
        """Test loading configuration with many targets."""
        import time
        
        # Create configuration with 100 targets
        large_config = {"targets": {}}
        for i in range(100):
            large_config["targets"][f"target-{i}"] = {
                "id": f"target-{i}",
                "type": "local",
                "executor": "local",
                "connection": {"executor": "local"},
                "capabilities": ["container:read", "system:read"],
                "constraints": {
                    "allowed_commands": ["docker", "systemctl"],
                    "max_concurrent": 5
                }
            }
        
        start_time = time.time()
        registry = TargetRegistryFixtures.create_target_registry_with_config(large_config)
        load_time = time.time() - start_time
        
        assert registry is not None
        assert len(registry.get_all_targets()) == 100
        
        # Assert reasonable load time (less than 1 second for 100 targets)
        assert load_time < 1.0, f"Load time {load_time}s exceeds threshold"
    
    def test_get_target_performance(self):
        """Test performance of target retrieval."""
        import time
        
        registry = TargetRegistryFixtures.create_target_registry_with_config(TEST_TARGETS_CONFIG)
        
        # Measure time to retrieve target
        start_time = time.time()
        for _ in range(1000):
            target = registry.get_target("local-host")
            assert target is not None
        end_time = time.time()
        
        retrieval_time = (end_time - start_time) / 1000
        
        # Assert reasonable retrieval time (less than 1ms per retrieval)
        assert retrieval_time < 0.001, f"Retrieval time {retrieval_time}s exceeds threshold"


# Test fixtures for parameterized testing
@pytest.fixture
def basic_target_registry():
    """Fixture providing a basic target registry."""
    return TargetRegistryFixtures.create_target_registry_with_config(TEST_TARGETS_CONFIG)


@pytest.fixture
def mock_target_registry():
    """Fixture providing a mock target registry."""
    return TargetRegistryFixtures.create_mock_target_registry()


# Parameterized tests for different target types
@pytest.mark.parametrize("target_id,expected_type,expected_executor", [
    ("local-host", "local", "local"),
    ("ssh-server", "remote", "ssh"),
    ("docker-host", "docker", "docker"),
    ("proxmox-node", "proxmox", "proxmox"),
    ("api-endpoint", "api", "http")
])
def test_target_types(basic_target_registry, target_id, expected_type, expected_executor):
    """Test different target types and executors."""
    target = basic_target_registry.get_target(target_id)
    assert target is not None
    assert target.type == expected_type
    assert target.executor.value == expected_executor


# Test class for integration with other components
class TestTargetRegistryIntegration:
    """Integration tests for Target Registry with other components."""
    
    def test_integration_with_policy_gate(self):
        """Test integration with Policy Gate component."""
        from tests.mock_policy_gate import MockPolicyGate
        
        registry = TargetRegistryFixtures.create_target_registry_with_config(TEST_TARGETS_CONFIG)
        policy_gate = MockPolicyGate()
        
        # Verify components can work together
        target = registry.get_target("local-host")
        assert target is not None
        
        # Policy gate should be able to use target metadata
        from tests.test_utils import TestDataGenerators
        claims = TestDataGenerators.generate_token_claims()
        
        auth_result = policy_gate.authorize_operation(
            "get_container_status", target, claims, {}
        )
        
        assert auth_result is not None
        assert "authorized" in auth_result
    
    def test_integration_with_execution_service(self):
        """Test integration with Execution Service."""
        from tests.mock_executors import create_mock_executor
        from src.services.execution_service import ExecutionService
        
        registry = TargetRegistryFixtures.create_target_registry_with_config(TEST_TARGETS_CONFIG)
        
        # Create mock policy gate and audit logger
        from tests.mock_policy_gate import MockPolicyGate
        from unittest.mock import Mock
        
        policy_gate = MockPolicyGate()
        audit_logger = Mock()
        
        execution_service = ExecutionService(registry, policy_gate, audit_logger)
        
        # Verify execution service can use target registry
        target = registry.get_target("local-host")
        assert target is not None
        
        # Execution service should be able to create executors for targets
        # This is a simplified test - actual executor creation would be more complex
        assert execution_service.target_registry == registry