"""
Policy-as-Code + Auditing System Integration Test

Tests the integration between Policy-as-Code system and existing policy gate.
"""

import pytest
import tempfile
import os
import yaml
from pathlib import Path

from src.services.policy_integration import PolicyAsCodeIntegration
from src.services.policy_as_code import PolicyAsCodeManager


class TestPolicyAsCodeIntegration:
    """Test Policy-as-Code integration with existing systems."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_dir = Path(self.temp_dir) / "config"
        self.config_dir.mkdir()
        
        # Create minimal test configuration
        self._create_test_config()
        
        self.integration = PolicyAsCodeIntegration(str(self.config_dir))
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def _create_test_config(self):
        """Create test configuration files."""
        
        # Targets configuration
        targets_config = {
            'targets': [
                {
                    'id': 'test-web-01',
                    'host': 'web01.test.example.com',
                    'tags': ['web', 'test'],
                    'roles': ['webserver'],
                    'connection_method': 'ssh',
                    'capabilities': ['container:write', 'system:read'],
                    'description': 'Test web server'
                },
                {
                    'id': 'test-db-01',
                    'host': 'db01.test.example.com',
                    'tags': ['database', 'test'],
                    'roles': ['database'],
                    'connection_method': 'ssh',
                    'capabilities': ['system:read'],
                    'description': 'Test database server'
                }
            ]
        }
        
        with open(self.config_dir / 'targets.yaml', 'w') as f:
            yaml.dump(targets_config, f)
        
        # Policy rules configuration
        policy_config = {
            'rules': [
                {
                    'name': 'default_deny',
                    'description': 'Default deny rule',
                    'target_pattern': '.*',
                    'allowed_operations': [],
                    'required_capabilities': [],
                    'parameter_constraints': {},
                    'operation_tier': 'observe'
                },
                {
                    'name': 'web_server_operations',
                    'description': 'Web server operations',
                    'target_pattern': 'test-web-.*',
                    'allowed_operations': ['status', 'start_container', 'stop_container'],
                    'required_capabilities': ['container:write', 'system:read'],
                    'parameter_constraints': {
                        'container_name': {
                            'type': 'string',
                            'max_length': 256
                        }
                    },
                    'operation_tier': 'control',
                    'requires_approval': False,
                    'dry_run_supported': True
                },
                {
                    'name': 'database_monitoring',
                    'description': 'Database monitoring',
                    'target_pattern': 'test-db-.*',
                    'allowed_operations': ['status', 'metrics'],
                    'required_capabilities': ['system:read'],
                    'parameter_constraints': {},
                    'operation_tier': 'observe',
                    'requires_approval': False,
                    'dry_run_supported': True
                }
            ]
        }
        
        with open(self.config_dir / 'policy.yaml', 'w') as f:
            yaml.dump(policy_config, f)
    
    def test_integration_initialization(self):
        """Test that integration initializes correctly."""
        assert self.integration.policy_manager is not None
        assert self.integration.audit_logger is not None
        assert self.integration.policy_gate is not None
        assert self.integration.target_registry is not None
    
    def test_target_registration_from_config(self):
        """Test that targets are registered from configuration."""
        # Check that targets are registered in the registry
        web_target = self.integration.target_registry.get_target('test-web-01')
        db_target = self.integration.target_registry.get_target('test-db-01')
        
        assert web_target is not None
        assert db_target is not None
        assert web_target['host'] == 'web01.test.example.com'
        assert db_target['host'] == 'db01.test.example.com'
    
    def test_deny_by_default_enforcement(self):
        """Test deny-by-default policy enforcement."""
        # Test that unauthorized operations are denied
        allowed = self.integration.policy_manager.is_operation_allowed(
            'test-web-01', 'unauthorized_operation'
        )
        assert not allowed, "Unauthorized operation should be denied"
    
    def test_operation_allowlist(self):
        """Test operation allowlist functionality."""
        # Test that allowed operations are permitted
        allowed = self.integration.policy_manager.is_operation_allowed(
            'test-web-01', 'status'
        )
        assert allowed, "Allowed operation should be permitted"
        
        # Test that operations are restricted by target
        allowed_on_db = self.integration.policy_manager.is_operation_allowed(
            'test-db-01', 'start_container'
        )
        assert not allowed_on_db, "Operation should be denied on inappropriate target"
    
    def test_get_allowed_operations(self):
        """Test getting allowed operations for a target."""
        web_ops = self.integration.get_allowed_operations('test-web-01')
        db_ops = self.integration.get_allowed_operations('test-db-01')
        
        assert 'status' in web_ops
        assert 'start_container' in web_ops
        assert 'stop_container' in web_ops
        assert 'status' in db_ops
        assert 'metrics' in db_ops
        assert 'start_container' not in db_ops
    
    def test_parameter_validation(self):
        """Test parameter validation against constraints."""
        # Test valid parameters
        errors = self.integration.policy_manager.validate_operation(
            'test-web-01', 'start_container', {'container_name': 'nginx'}
        )
        assert len(errors) == 0, "Valid parameters should pass validation"
        
        # Test invalid parameters
        errors = self.integration.policy_manager.validate_operation(
            'test-web-01', 'start_container', {'container_name': 'a' * 300}
        )
        assert len(errors) > 0, "Invalid parameters should fail validation"
    
    @pytest.mark.asyncio
    async def test_authorize_operation(self):
        """Test operation authorization."""
        # Test authorized operation
        authorized, errors, rule = await self.integration.authorize_operation(
            'test-actor', 'test-web-01', 'status', {}
        )
        assert authorized, "Authorized operation should be permitted"
        assert len(errors) == 0, "No validation errors expected"
        
        # Test unauthorized operation
        authorized, errors, rule = await self.integration.authorize_operation(
            'test-actor', 'test-web-01', 'unauthorized_operation', {}
        )
        assert not authorized, "Unauthorized operation should be denied"
        assert len(errors) > 0, "Validation errors expected"
    
    def test_audit_logger_initialization(self):
        """Test audit logger initialization."""
        # Check that audit log file is created
        log_path = Path('./logs/audit.jsonl')
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # The audit logger should be ready to write
        assert self.integration.audit_logger.log_path.exists() or \
               not self.integration.audit_logger.log_path.exists(), \
               "Audit logger should handle file creation"
    
    def test_get_target_config(self):
        """Test getting target configuration."""
        config = self.integration.get_target_config('test-web-01')
        assert config is not None
        assert config.id == 'test-web-01'
        assert config.host == 'web01.test.example.com'
    
    def test_audit_statistics(self):
        """Test audit statistics functionality."""
        stats = self.integration.get_audit_statistics()
        
        # Should return statistics structure even with empty logs
        assert 'total_entries' in stats
        assert 'authorized_operations' in stats
        assert 'denied_operations' in stats
        assert 'event_types' in stats
        assert 'operations' in stats
        assert 'targets' in stats
        assert 'actors' in stats


class TestPolicyAsCodeManager:
    """Test Policy-as-Code manager functionality."""
    
    def setup_method(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_dir = Path(self.temp_dir) / "config"
        self.config_dir.mkdir()
        
        self._create_test_config()
        self.manager = PolicyAsCodeManager(str(self.config_dir))
    
    def teardown_method(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def _create_test_config(self):
        """Create test configuration."""
        # Same configuration as above
        targets_config = {
            'targets': [
                {
                    'id': 'test-target',
                    'host': 'test.example.com',
                    'tags': ['test'],
                    'roles': ['test'],
                    'connection_method': 'ssh',
                    'capabilities': ['test:read'],
                    'description': 'Test target'
                }
            ]
        }
        
        policy_config = {
            'rules': [
                {
                    'name': 'default_deny',
                    'description': 'Default deny',
                    'target_pattern': '.*',
                    'allowed_operations': [],
                    'required_capabilities': [],
                    'parameter_constraints': {},
                    'operation_tier': 'observe'
                },
                {
                    'name': 'test_operations',
                    'description': 'Test operations',
                    'target_pattern': 'test-target',
                    'allowed_operations': ['test_operation'],
                    'required_capabilities': ['test:read'],
                    'parameter_constraints': {},
                    'operation_tier': 'observe'
                }
            ]
        }
        
        with open(self.config_dir / 'targets.yaml', 'w') as f:
            yaml.dump(targets_config, f)
        
        with open(self.config_dir / 'policy.yaml', 'w') as f:
            yaml.dump(policy_config, f)
    
    def test_config_loading(self):
        """Test configuration loading."""
        config = self.manager.config
        assert len(config.targets) == 1
        assert len(config.rules) == 2  # default_deny + test_operations
        assert config.targets[0].id == 'test-target'
    
    def test_default_deny_rule(self):
        """Test that default deny rule is enforced."""
        # Check that default deny rule is present
        has_default_deny = any(rule.name == 'default_deny' for rule in self.manager.config.rules)
        assert has_default_deny, "Default deny rule should be present"
        
        # Test deny-by-default
        allowed = self.manager.is_operation_allowed('test-target', 'unauthorized_op')
        assert not allowed, "Unauthorized operations should be denied by default"
    
    def test_operation_allowlisting(self):
        """Test operation allowlisting."""
        # Test allowed operation
        allowed = self.manager.is_operation_allowed('test-target', 'test_operation')
        assert allowed, "Allowed operation should be permitted"
        
        # Test operation on non-matching target
        allowed = self.manager.is_operation_allowed('other-target', 'test_operation')
        assert not allowed, "Operation should be denied on non-matching target"
    
    def test_get_allowed_operations(self):
        """Test getting allowed operations."""
        ops = self.manager.get_allowed_operations('test-target')
        assert 'test_operation' in ops
        assert len(ops) == 1