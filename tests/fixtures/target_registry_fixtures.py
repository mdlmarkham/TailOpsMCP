"""
Test fixtures and utilities for target registry testing.
"""

import json
import tempfile
import os
from pathlib import Path
from typing import Dict, List, Any

from src.models.target_registry import (
    TargetMetadata, 
    TargetConnection, 
    TargetConstraints,
    ExecutorType
)
from src.auth.scopes import Scope


# Test target configurations
TEST_TARGETS_CONFIG = {
    "targets": {
        "local-host": {
            "id": "local-host",
            "type": "local",
            "executor": "local",
            "connection": {
                "executor": "local"
            },
            "capabilities": [
                "container:read",
                "container:write", 
                "system:read",
                "system:write"
            ],
            "constraints": {
                "allowed_commands": ["docker", "systemctl", "apt"],
                "allowed_paths": ["/opt", "/var/lib"],
                "max_concurrent": 5
            },
            "metadata": {
                "hostname": "localhost",
                "os": "linux",
                "arch": "x86_64"
            }
        },
        "ssh-server": {
            "id": "ssh-server",
            "type": "remote",
            "executor": "ssh",
            "connection": {
                "executor": "ssh",
                "host": "test.example.com",
                "port": 22,
                "username": "testuser",
                "key_path": "/path/to/key"
            },
            "capabilities": [
                "container:read",
                "system:read"
            ],
            "constraints": {
                "allowed_commands": ["docker", "systemctl"],
                "allowed_paths": ["/opt"],
                "max_concurrent": 3
            },
            "metadata": {
                "hostname": "test.example.com",
                "os": "ubuntu",
                "arch": "x86_64"
            }
        },
        "docker-host": {
            "id": "docker-host",
            "type": "docker",
            "executor": "docker",
            "connection": {
                "executor": "docker"
            },
            "capabilities": [
                "container:read",
                "container:write",
                "image:read",
                "image:write"
            ],
            "constraints": {
                "allowed_commands": ["docker"],
                "allowed_images": ["nginx", "redis", "postgres"],
                "max_concurrent": 10
            },
            "metadata": {
                "docker_version": "20.10",
                "storage_driver": "overlay2"
            }
        },
        "proxmox-node": {
            "id": "proxmox-node",
            "type": "proxmox",
            "executor": "proxmox",
            "connection": {
                "executor": "proxmox",
                "host": "proxmox.example.com",
                "username": "root@pam",
                "password": "testpass"
            },
            "capabilities": [
                "vm:read",
                "vm:write",
                "container:read",
                "container:write"
            ],
            "constraints": {
                "allowed_nodes": ["node1", "node2"],
                "max_vms": 50,
                "max_containers": 100
            },
            "metadata": {
                "proxmox_version": "7.4",
                "cluster_name": "test-cluster"
            }
        },
        "api-endpoint": {
            "id": "api-endpoint",
            "type": "api",
            "executor": "http",
            "connection": {
                "executor": "http",
                "base_url": "http://api.example.com",
                "headers": {
                    "Authorization": "Bearer test-token"
                }
            },
            "capabilities": [
                "api:read",
                "api:write"
            ],
            "constraints": {
                "allowed_endpoints": ["/v1/containers", "/v1/system"],
                "rate_limit": 100
            },
            "metadata": {
                "api_version": "v1",
                "provider": "custom"
            }
        }
    }
}


# Invalid target configurations for testing validation
INVALID_TARGETS_CONFIG = {
    "targets": {
        "missing-required": {
            "id": "missing-required",
            # Missing type and executor
            "connection": {"executor": "local"}
        },
        "invalid-executor": {
            "id": "invalid-executor",
            "type": "local",
            "executor": "invalid-executor-type",
            "connection": {"executor": "local"}
        },
        "malformed-connection": {
            "id": "malformed-connection",
            "type": "ssh",
            "executor": "ssh",
            "connection": {
                "executor": "ssh"
                # Missing required SSH connection fields
            }
        }
    }
}


# Minimal target configuration
MINIMAL_TARGET_CONFIG = {
    "targets": {
        "minimal-target": {
            "id": "minimal-target",
            "type": "local",
            "executor": "local",
            "connection": {
                "executor": "local"
            }
        }
    }
}


class TargetRegistryFixtures:
    """Factory class for creating target registry test fixtures."""
    
    @staticmethod
    def create_temp_config_file(config_data: Dict[str, Any]) -> str:
        """Create a temporary configuration file for testing.
        
        Args:
            config_data: Configuration data to write
            
        Returns:
            Path to temporary configuration file
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(config_data, f)
            return f.name
    
    @staticmethod
    def create_test_target(target_id: str = "test-target", 
                          target_type: str = "local",
                          executor_type: ExecutorType = ExecutorType.LOCAL,
                          capabilities: List[str] = None,
                          constraints: Dict[str, Any] = None) -> TargetMetadata:
        """Create a test target metadata object.
        
        Args:
            target_id: Target identifier
            target_type: Target type
            executor_type: Executor type
            capabilities: List of capabilities
            constraints: Target constraints
            
        Returns:
            Configured TargetMetadata instance
        """
        if capabilities is None:
            capabilities = [Scope.CONTAINER_READ.value, Scope.SYSTEM_READ.value]
        
        if constraints is None:
            constraints = {
                "timeout": 60,
                "concurrency": 1,
                "sudo_policy": "none"
            }
        
        return TargetMetadata(
            id=target_id,
            type=target_type,
            executor=executor_type,
            connection=TargetConnection(executor=executor_type),
            capabilities=capabilities,
            constraints=TargetConstraints(**constraints),
            metadata={"test": "true"}
        )
    
    @staticmethod
    def create_mock_target_registry(targets: List[TargetMetadata] = None) -> Any:
        """Create a mock target registry for testing.
        
        Args:
            targets: List of target metadata objects
            
        Returns:
            Mock TargetRegistry instance
        """
        from unittest.mock import Mock
        
        if targets is None:
            targets = [
                TargetRegistryFixtures.create_test_target("target-1"),
                TargetRegistryFixtures.create_test_target("target-2")
            ]
        
        mock_registry = Mock()
        mock_registry.get_target.return_value = None
        mock_registry.get_all_targets.return_value = {t.id: t for t in targets}
        mock_registry.validate_target.return_value = True
        mock_registry.get_errors.return_value = []
        
        # Configure get_target to return specific targets
        def get_target_side_effect(target_id):
            for target in targets:
                if target.id == target_id:
                    return target
            return None
        
        mock_registry.get_target.side_effect = get_target_side_effect
        
        return mock_registry


# Predefined test targets for common scenarios
TEST_TARGETS = {
    "readonly-target": TargetRegistryFixtures.create_test_target(
        "readonly-target",
        capabilities=[Scope.CONTAINER_READ.value, Scope.SYSTEM_READ.value]
    ),
    "write-target": TargetRegistryFixtures.create_test_target(
        "write-target",
        capabilities=[Scope.CONTAINER_READ.value, Scope.CONTAINER_WRITE.value,
                     Scope.SYSTEM_READ.value, Scope.FILE_WRITE.value]
    ),
    "admin-target": TargetRegistryFixtures.create_test_target(
        "admin-target",
        capabilities=["admin"]  # All capabilities
    ),
    "restricted-target": TargetRegistryFixtures.create_test_target(
        "restricted-target",
        capabilities=[Scope.CONTAINER_READ.value],
        constraints={
            "timeout": 30,
            "concurrency": 1,
            "sudo_policy": "none"
        }
    )
}


def create_target_registry_with_config(config_data: Dict[str, Any]) -> Any:
    """Create a TargetRegistry instance with the given configuration.
    
    Args:
        config_data: Configuration data
        
    Returns:
        TargetRegistry instance
    """
    from src.services.target_registry import TargetRegistry
    
    config_file = TargetRegistryFixtures.create_temp_config_file(config_data)
    
    try:
        registry = TargetRegistry(config_path=config_file)
        return registry
    finally:
        # Clean up temporary file
        os.unlink(config_file)


def assert_target_metadata_equal(actual: TargetMetadata, expected: TargetMetadata):
    """Assert that two target metadata objects are equal.
    
    Args:
        actual: Actual target metadata
        expected: Expected target metadata
    """
    assert actual.id == expected.id
    assert actual.type == expected.type
    assert actual.executor == expected.executor
    assert actual.capabilities == expected.capabilities
    
    # Check constraints
    if expected.constraints:
        assert actual.constraints.allowed_commands == expected.constraints.allowed_commands
        assert actual.constraints.allowed_paths == expected.constraints.allowed_paths
        assert actual.constraints.max_concurrent == expected.constraints.max_concurrent
    
    # Check metadata
    if expected.metadata:
        assert actual.metadata == expected.metadata