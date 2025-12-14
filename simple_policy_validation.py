#!/usr/bin/env python3
"""
Simple validation script for the Policy-Driven Execution System

Tests basic functionality of the policy engine and capability executor
without requiring external dependencies.
"""

import sys
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any

# Add src to path for imports
sys.path.insert(0, 'src')

from src.models.policy_models import (
    PolicyConfig, PolicyRule, CapabilityOperation, OperationType, TargetRole, 
    PolicyContext, create_default_policy_config, validate_policy_config
)
from src.services.policy_engine import PolicyEngine
from src.services.capability_executor import CapabilityExecutor
from src.services.execution_factory import ExecutionBackendFactory
from src.utils.audit import AuditLogger


class MockAuditLogger:
    """Mock audit logger for testing."""
    
    async def log_event(self, event_type: str, event_data: Dict[str, Any], severity: str = "info"):
        """Mock audit log event."""
        print(f"[AUDIT] {severity.upper()}: {event_type} - {event_data}")


async def test_policy_engine():
    """Test basic policy engine functionality."""
    print("Testing Policy Engine...")
    
    # Create mock audit logger
    audit_logger = MockAuditLogger()
    
    # Create policy engine with default configuration
    policy_engine = PolicyEngine(
        config_path=None,  # Use default configuration
        audit_logger=audit_logger,
        enable_caching=True
    )
    
    # Test policy status
    status = policy_engine.get_policy_status()
    print(f"Policy Status: {status['status']}")
    print(f"Policy Name: {status.get('name', 'N/A')}")
    print(f"Total Rules: {status.get('total_rules', 0)}")
    
    # Test allowed operations
    dev_operations = policy_engine.list_allowed_operations(TargetRole.DEVELOPMENT)
    print(f"Development Allowed Operations: {len(dev_operations)}")
    
    prod_operations = policy_engine.list_allowed_operations(TargetRole.PRODUCTION)
    print(f"Production Allowed Operations: {len(prod_operations)}")
    
    # Test policy simulation
    operation = CapabilityOperation(
        name="test_service_restart",
        capability=OperationType.SERVICE_RESTART,
        description="Test service restart operation",
        parameters={"service_name": "nginx"},
        target_id="test-target",
        target_role=TargetRole.DEVELOPMENT,
        requested_by="test@example.com",
        request_reason="Testing policy system"
    )
    
    context = PolicyContext(
        operation=operation,
        target_role=TargetRole.DEVELOPMENT,
        user_id="test@example.com",
        current_time=datetime.now(timezone.utc)
    )
    
    evaluation = await policy_engine.evaluate_operation(operation, context)
    print(f"Policy Evaluation: {evaluation.decision.value}")
    print(f"Policy Reason: {evaluation.reason}")
    
    return True


async def test_capability_validator():
    """Test capability parameter validation."""
    print("\nTesting Capability Validator...")
    
    from src.services.capability_executor import CapabilityValidator
    
    validator = CapabilityValidator()
    
    # Test valid parameters
    valid_params = {"service_name": "nginx", "timeout": 60}
    is_valid, errors = validator.validate_parameters(OperationType.SERVICE_RESTART, valid_params)
    print(f"Valid parameters test: {is_valid}")
    if not is_valid:
        print(f"Errors: {errors}")
    
    # Test invalid parameters
    invalid_params = {"service_name": "", "timeout": 999}  # Empty name, invalid timeout
    is_valid, errors = validator.validate_parameters(OperationType.SERVICE_RESTART, invalid_params)
    print(f"Invalid parameters test: {is_valid}")
    print(f"Errors: {errors}")
    
    return True


async def test_execution_backend_factory():
    """Test execution backend factory."""
    print("\nTesting Execution Backend Factory...")
    
    factory = ExecutionBackendFactory()
    
    # Test backend registration
    print(f"Registered backends: {len(factory.backend_registry)}")
    
    # Test capability matrix
    matrix = factory.get_supported_capabilities_matrix()
    print(f"Capability matrix entries: {len(matrix)}")
    
    for backend_type, capabilities in matrix.items():
        print(f"  {backend_type}: {len(capabilities)} capabilities")
    
    # Test backend statistics
    stats = factory.get_backend_statistics()
    print(f"Factory statistics: {stats}")
    
    return True


async def test_policy_configuration():
    """Test policy configuration validation."""
    print("\nTesting Policy Configuration...")
    
    # Test default configuration
    default_config = create_default_policy_config()
    print(f"Default config name: {default_config.name}")
    print(f"Default config rules: {len(default_config.global_policies)}")
    
    # Test configuration validation
    validation_result = validate_policy_config(default_config)
    print(f"Configuration valid: {validation_result.is_valid}")
    
    if validation_result.errors:
        print(f"Configuration errors: {validation_result.errors}")
    if validation_result.warnings:
        print(f"Configuration warnings: {validation_result.warnings}")
    
    return True


async def test_operation_creation():
    """Test operation creation helpers."""
    print("\nTesting Operation Creation...")
    
    from src.services.capability_executor import create_service_restart_operation
    
    # Test service restart operation creation
    operation = await create_service_restart_operation(
        service_name="nginx",
        target_id="test-server",
        requested_by="admin@example.com",
        timeout=60
    )
    
    print(f"Operation name: {operation.name}")
    print(f"Operation capability: {operation.capability.value}")
    print(f"Operation parameters: {operation.parameters}")
    print(f"Operation target: {operation.target_id}")
    
    return True


async def main():
    """Run all validation tests."""
    print("Policy-Driven Execution System Validation")
    print("=" * 50)
    
    tests = [
        test_policy_configuration,
        test_policy_engine,
        test_capability_validator,
        test_execution_backend_factory,
        test_operation_creation
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            result = await test()
            if result:
                passed += 1
                print("✓ Test passed")
            else:
                failed += 1
                print("✗ Test failed")
        except Exception as e:
            failed += 1
            print(f"✗ Test failed with exception: {e}")
    
    print(f"\nTest Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("\n🎉 All tests passed! Policy-Driven Execution System is ready.")
        return True
    else:
        print(f"\n⚠️  {failed} tests failed. Please review the implementation.")
        return False


if __name__ == "__main__":
    # Run validation
    success = asyncio.run(main())
    sys.exit(0 if success else 1)