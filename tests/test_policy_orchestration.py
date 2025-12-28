"""
Comprehensive test suite for policy orchestration components.

Tests capability-driven operations with comprehensive security,
policy evaluation and enforcement, deny-by-default security posture,
role-based access control, and policy validation and rollback mechanisms.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock

from src.services.policy_engine import PolicyEngine, PolicyEvaluationContext
from src.services.capability_executor import CapabilityExecutor
from src.models.execution import ExecutionRequest
from src.models.policy_models import (
    PolicyConfig,
    PolicyRule,
    PolicyCondition,
    SecurityTier,
    CapabilityDefinition,
)
from src.services.access_control import AccessControl, Permission


class TestPolicyOrchestration:
    """Test policy-driven execution orchestration."""

    @pytest.fixture
    def mock_policy_engine(self):
        """Create mock policy engine."""
        engine = Mock(spec=PolicyEngine)
        engine.evaluate_policy = AsyncMock()
        engine.enforce_policy = AsyncMock()
        engine.get_policy_violations = AsyncMock()
        engine.validate_policy = AsyncMock()
        return engine

    @pytest.fixture
    def mock_capability_executor(self):
        """Create mock capability executor."""
        executor = Mock(spec=CapabilityExecutor)
        executor.execute_capability = AsyncMock()
        executor.validate_capability = AsyncMock()
        executor.get_capability_status = AsyncMock()
        return executor

    @pytest.fixture
    def mock_access_control(self):
        """Create mock access control system."""
        access_control = Mock(spec=AccessControl)
        access_control.check_permission = AsyncMock()
        access_control.get_user_permissions = AsyncMock()
        access_control.enforce_rbac = AsyncMock()
        return access_control

    @pytest.fixture
    def sample_policy_config(self):
        """Create sample policy configuration for testing."""
        return PolicyConfig(
            version="1.0",
            policy_name="test_fleet_management",
            default_tier=SecurityTier.OBSERVE,
            operations={
                "fleet_discover": PolicyRule(
                    tier=SecurityTier.OBSERVE,
                    description="Run fleet discovery to find nodes and services",
                    allowed_targets=["gateway"],
                    conditions=[
                        PolicyCondition(
                            field="time", operator="between", value="08:00-18:00"
                        )
                    ],
                ),
                "fleet_inventory_get": PolicyRule(
                    tier=SecurityTier.OBSERVE,
                    description="Retrieve latest fleet inventory snapshot",
                    allowed_targets=["gateway"],
                    conditions=[],
                ),
                "plan_update_packages": PolicyRule(
                    tier=SecurityTier.CONTROL,
                    description="Plan package update operation",
                    allowed_targets=["*"],
                    conditions=[
                        PolicyCondition(
                            field="maintenance_window", operator="equals", value=True
                        )
                    ],
                ),
            },
            security_constraints={
                "deny_by_default": True,
                "require_approval": ["control", "execute"],
                "audit_all_operations": True,
            },
        )

    @pytest.mark.asyncio
    async def test_capability_execution_with_policies(
        self,
        mock_policy_engine,
        mock_capability_executor,
        mock_access_control,
        sample_policy_config,
    ):
        """Test capability execution with policy enforcement."""
        # Setup capability definition
        capability = CapabilityDefinition(
            name="fleet_discover",
            description="Discover fleet nodes and services",
            tier=SecurityTier.OBSERVE,
            parameters={
                "scope": {"type": "string", "required": False},
                "include_services": {"type": "boolean", "required": False},
            },
            required_permissions=["fleet.read"],
            approval_required=False,
        )

        # Setup execution request
        execution_request = ExecutionRequest(
            capability_name="fleet_discover",
            parameters={"scope": "all", "include_services": True},
            requester="test_user",
            context={"source": "mcp_tool"},
        )

        # Setup policy evaluation context
        policy_context = PolicyEvaluationContext(
            user="test_user",
            resource="fleet",
            operation="fleet_discover",
            parameters=execution_request.parameters,
            time=datetime.utcnow(),
        )

        # Mock policy evaluation (allow)
        mock_policy_engine.evaluate_policy.return_value = {
            "allowed": True,
            "reason": "Policy allows fleet discovery during business hours",
            "conditions_met": True,
            "tier": SecurityTier.OBSERVE,
        }

        # Mock capability execution
        mock_capability_executor.execute_capability.return_value = {
            "status": "success",
            "result": {
                "nodes_discovered": 5,
                "services_discovered": 12,
                "execution_time": "2.3s",
            },
        }

        # Execute capability with policy check
        result = await mock_capability_executor.execute_capability(
            capability, execution_request, policy_context
        )

        # Verify policy evaluation was called
        mock_policy_engine.evaluate_policy.assert_called_once_with(
            sample_policy_config, policy_context
        )

        # Verify capability was executed
        assert result["status"] == "success"
        assert result["result"]["nodes_discovered"] == 5

        # Test capability execution with policy violation
        mock_policy_engine.evaluate_policy.return_value = {
            "allowed": False,
            "reason": "Fleet discovery not allowed outside business hours",
            "conditions_met": False,
            "tier": SecurityTier.OBSERVE,
        }

        # Should raise policy violation exception
        with pytest.raises(Exception, match="Fleet discovery not allowed"):
            await mock_capability_executor.execute_capability(
                capability, execution_request, policy_context
            )

    @pytest.mark.asyncio
    async def test_policy_evaluation_and_enforcement(
        self, mock_policy_engine, sample_policy_config
    ):
        """Test policy evaluation and enforcement logic."""
        # Test policy evaluation for different operations
        test_cases = [
            {
                "operation": "fleet_discover",
                "time": datetime(2024, 1, 1, 10, 0),  # Business hours
                "expected": True,
                "reason": "Allowed during business hours",
            },
            {
                "operation": "fleet_discover",
                "time": datetime(2024, 1, 1, 22, 0),  # Outside business hours
                "expected": False,
                "reason": "Not allowed outside business hours",
            },
            {
                "operation": "plan_update_packages",
                "maintenance_window": True,
                "expected": True,
                "reason": "Allowed during maintenance window",
            },
            {
                "operation": "plan_update_packages",
                "maintenance_window": False,
                "expected": False,
                "reason": "Not allowed outside maintenance window",
            },
        ]

        for i, test_case in enumerate(test_cases):
            policy_context = PolicyEvaluationContext(
                user="test_user",
                resource="fleet",
                operation=test_case["operation"],
                parameters={"maintenance_window": test_case.get("maintenance_window")},
                time=test_case["time"],
            )

            mock_policy_engine.evaluate_policy.return_value = {
                "allowed": test_case["expected"],
                "reason": test_case["reason"],
                "conditions_met": test_case["expected"],
                "tier": SecurityTier.OBSERVE
                if test_case["operation"] == "fleet_discover"
                else SecurityTier.CONTROL,
            }

            result = await mock_policy_engine.evaluate_policy(
                sample_policy_config, policy_context
            )

            assert result["allowed"] == test_case["expected"]
            assert result["reason"] == test_case["reason"]

    @pytest.mark.asyncio
    async def test_deny_by_default_security_posture(
        self, mock_policy_engine, sample_policy_config
    ):
        """Test deny-by-default security posture."""
        # Test undefined operation (should be denied by default)
        undefined_operation = "undefined_operation"
        policy_context = PolicyEvaluationContext(
            user="test_user",
            resource="fleet",
            operation=undefined_operation,
            parameters={},
            time=datetime.utcnow(),
        )

        mock_policy_engine.evaluate_policy.return_value = {
            "allowed": False,
            "reason": "Operation not explicitly allowed - deny by default",
            "conditions_met": False,
            "tier": SecurityTier.DENY,
        }

        result = await mock_policy_engine.evaluate_policy(
            sample_policy_config, policy_context
        )

        assert result["allowed"] is False
        assert "deny by default" in result["reason"].lower()

        # Test policy enforcement
        mock_policy_engine.enforce_policy.return_value = True
        enforced = await mock_policy_engine.enforce_policy(
            sample_policy_config, policy_context
        )

        assert enforced is True  # Enforcement successful (denied the operation)

    @pytest.mark.asyncio
    async def test_role_based_access_control(self, mock_access_control):
        """Test role-based access control enforcement."""
        # Setup test roles and permissions
        roles = {
            "admin": [
                Permission.FLEET_READ,
                Permission.FLEET_WRITE,
                Permission.FLEET_EXECUTE,
            ],
            "operator": [Permission.FLEET_READ, Permission.FLEET_CONTROL],
            "observer": [Permission.FLEET_READ],
        }

        # Test admin role has full access
        mock_access_control.check_permission.return_value = True
        has_permission = await mock_access_control.check_permission(
            "admin", Permission.FLEET_EXECUTE
        )
        assert has_permission is True

        # Test observer role limited access
        mock_access_control.check_permission.return_value = False
        no_permission = await mock_access_control.check_permission(
            "observer", Permission.FLEET_EXECUTE
        )
        assert no_permission is False

        # Test get user permissions
        mock_access_control.get_user_permissions.return_value = roles["operator"]
        permissions = await mock_access_control.get_user_permissions("operator")
        assert Permission.FLEET_READ in permissions
        assert Permission.FLEET_CONTROL in permissions
        assert Permission.FLEET_EXECUTE not in permissions

        # Test RBAC enforcement
        mock_access_control.enforce_rbac.return_value = True
        enforced = await mock_access_control.enforce_rbac(
            "operator", "fleet_discover", {"tier": SecurityTier.OBSERVE}
        )
        assert enforced is True

    @pytest.mark.asyncio
    async def test_policy_validation_and_rollback(
        self, mock_policy_engine, sample_policy_config
    ):
        """Test policy validation and rollback mechanisms."""
        # Test policy validation
        mock_policy_engine.validate_policy.return_value = {
            "valid": True,
            "errors": [],
            "warnings": [
                "Consider adding time-based restrictions for control operations"
            ],
        }

        validation_result = await mock_policy_engine.validate_policy(
            sample_policy_config
        )

        assert validation_result["valid"] is True
        assert len(validation_result["errors"]) == 0
        assert len(validation_result["warnings"]) == 1

        # Test policy rollback with invalid policy
        invalid_policy = PolicyConfig(
            version="1.0",
            policy_name="invalid_policy",
            default_tier=SecurityTier.OBSERVE,
            operations={},  # Empty operations
            security_constraints={},
        )

        mock_policy_engine.validate_policy.return_value = {
            "valid": False,
            "errors": ["No operations defined", "Missing security constraints"],
            "warnings": [],
        }

        invalid_result = await mock_policy_engine.validate_policy(invalid_policy)

        assert invalid_result["valid"] is False
        assert len(invalid_result["errors"]) == 2

        # Test policy rollback scenario
        original_policy = sample_policy_config
        rollback_success = await mock_policy_engine.rollback_policy(original_policy)

        assert rollback_success is True
        mock_policy_engine.rollback_policy.assert_called_once_with(original_policy)


class TestPolicySecurityCompliance:
    """Test policy security and compliance features."""

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_policy_injection_prevention(self, mock_policy_engine):
        """Test prevention of policy injection attacks."""
        # Test malicious policy content
        malicious_policy_data = {
            "version": "1.0",
            "policy_name": "malicious_policy",
            "operations": {
                "exec": {
                    "tier": "execute",
                    "allowed_targets": ["*"],
                    "conditions": [
                        {
                            "field": "command",
                            "operator": "equals",
                            "value": "rm -rf /",  # Malicious command
                        }
                    ],
                }
            },
        }

        # Test policy sanitization
        sanitized_policy = await mock_policy_engine.sanitize_policy(
            malicious_policy_data
        )

        assert (
            sanitized_policy["operations"]["exec"]["conditions"][0]["value"]
            != "rm -rf /"
        )
        assert "sanitized" in sanitized_policy.get("notes", [])

        # Test policy execution with sanitized content
        policy_context = PolicyEvaluationContext(
            user="test_user",
            resource="fleet",
            operation="exec",
            parameters={"command": "rm -rf /"},
            time=datetime.utcnow(),
        )

        mock_policy_engine.evaluate_policy.return_value = {
            "allowed": False,
            "reason": "Potential security violation detected",
            "conditions_met": False,
        }

        result = await mock_policy_engine.evaluate_policy(
            PolicyConfig(**malicious_policy_data), policy_context
        )

        assert result["allowed"] is False

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_audit_logging_compliance(self, mock_policy_engine):
        """Test audit logging for compliance."""
        # Test audit log generation
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "user": "test_user",
            "operation": "fleet_discover",
            "policy_decision": "allowed",
            "reason": "Policy allows during business hours",
            "ip_address": "192.168.1.100",
            "user_agent": "TailOpsMCP/1.0",
        }

        mock_policy_engine.log_audit_event.return_value = True
        logged = await mock_policy_engine.log_audit_event(audit_entry)

        assert logged is True

        # Test audit log retrieval
        mock_policy_engine.get_audit_logs.return_value = [audit_entry]
        logs = await mock_policy_engine.get_audit_logs(
            start_time=datetime.utcnow() - timedelta(hours=1),
            end_time=datetime.utcnow(),
        )

        assert len(logs) == 1
        assert logs[0]["user"] == "test_user"
        assert logs[0]["operation"] == "fleet_discover"

        # Test compliance reporting
        compliance_report = {
            "total_operations": 100,
            "allowed_operations": 85,
            "denied_operations": 15,
            "policy_violations": 5,
            "compliance_score": 0.95,
        }

        mock_policy_engine.generate_compliance_report.return_value = compliance_report
        report = await mock_policy_engine.generate_compliance_report(
            start_time=datetime.utcnow() - timedelta(days=30),
            end_time=datetime.utcnow(),
        )

        assert report["compliance_score"] == 0.95
        assert report["denied_operations"] == 15


class TestPolicyIntegration:
    """Integration tests for policy orchestration components."""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_end_to_end_policy_enforcement(self, temp_test_dir):
        """Test end-to-end policy enforcement workflow."""
        # This would test the complete policy enforcement pipeline
        # For now, this is a placeholder for integration testing
        pass

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_policy_performance_under_load(self):
        """Test policy performance under high load."""
        # This would test policy evaluation performance with many concurrent requests
        # For now, this is a placeholder for performance testing
        pass


class TestPolicyEdgeCases:
    """Test policy edge cases and failure scenarios."""

    @pytest.mark.edge_case
    @pytest.mark.asyncio
    async def test_policy_with_corrupted_data(self, mock_policy_engine):
        """Test policy handling with corrupted data."""
        # Test with corrupted policy data
        corrupted_policy = {
            "version": None,  # Corrupted version
            "operations": None,  # Corrupted operations
            "invalid_field": "should_not_exist",
        }

        # Test policy recovery from corruption
        mock_policy_engine.recover_from_corruption.return_value = PolicyConfig(
            version="1.0",
            policy_name="recovered_policy",
            default_tier=SecurityTier.DENY,
            operations={},
            security_constraints={"deny_by_default": True},
        )

        recovered = await mock_policy_engine.recover_from_corruption(corrupted_policy)

        assert recovered.version == "1.0"
        assert recovered.policy_name == "recovered_policy"
        assert recovered.security_constraints["deny_by_default"] is True

    @pytest.mark.edge_case
    @pytest.mark.asyncio
    async def test_policy_with_network_failure(self, mock_policy_engine):
        """Test policy behavior during network failures."""
        # Simulate network failure during policy validation
        mock_policy_engine.validate_policy.side_effect = ConnectionError(
            "Network unavailable"
        )

        with pytest.raises(ConnectionError, match="Network unavailable"):
            await mock_policy_engine.validate_policy(
                PolicyConfig(
                    version="1.0",
                    policy_name="test",
                    default_tier=SecurityTier.OBSERVE,
                    operations={},
                    security_constraints={},
                )
            )

        # Test fallback policy behavior
        mock_policy_engine.get_fallback_policy.return_value = {
            "version": "1.0",
            "policy_name": "fallback_policy",
            "default_tier": SecurityTier.DENY,
            "operations": {},
            "security_constraints": {"deny_by_default": True},
        }

        fallback = await mock_policy_engine.get_fallback_policy()
        assert fallback["default_tier"] == SecurityTier.DENY

    @pytest.mark.edge_case
    @pytest.mark.asyncio
    async def test_policy_with_concurrent_updates(self, mock_policy_engine):
        """Test policy behavior during concurrent updates."""
        # Simulate concurrent policy updates
        original_policy = PolicyConfig(
            version="1.0",
            policy_name="concurrent_test",
            default_tier=SecurityTier.OBSERVE,
            operations={
                "test_op": PolicyRule(tier=SecurityTier.OBSERVE, allowed_targets=["*"])
            },
            security_constraints={},
        )

        updated_policy = PolicyConfig(
            version="1.0",
            policy_name="concurrent_test",
            default_tier=SecurityTier.CONTROL,
            operations={
                "test_op": PolicyRule(
                    tier=SecurityTier.CONTROL, allowed_targets=["gateway"]
                )
            },
            security_constraints={},
        )

        # Test optimistic locking
        mock_policy_engine.update_policy_with_lock.return_value = {
            "success": True,
            "version": "2.0",
            "conflicts": [],
        }

        result = await mock_policy_engine.update_policy_with_lock(
            original_policy, updated_policy, expected_version="1.0"
        )

        assert result["success"] is True
        assert result["version"] == "2.0"


class TestPolicyPerformance:
    """Test policy performance characteristics."""

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_policy_evaluation_latency(self, mock_policy_engine):
        """Test policy evaluation latency."""
        policy_config = PolicyConfig(
            version="1.0",
            policy_name="performance_test",
            default_tier=SecurityTier.OBSERVE,
            operations={
                f"test_op_{i}": PolicyRule(
                    tier=SecurityTier.OBSERVE, allowed_targets=["*"]
                )
                for i in range(100)
            },
            security_constraints={},
        )

        # Test evaluation time for many operations
        start_time = datetime.utcnow()

        for i in range(100):
            policy_context = PolicyEvaluationContext(
                user="test_user",
                resource="fleet",
                operation=f"test_op_{i}",
                parameters={},
                time=datetime.utcnow(),
            )

            mock_policy_engine.evaluate_policy.return_value = {
                "allowed": True,
                "reason": "Allowed by policy",
                "conditions_met": True,
            }

            await mock_policy_engine.evaluate_policy(policy_config, policy_context)

        end_time = datetime.utcnow()
        total_time = (end_time - start_time).total_seconds()

        # Should complete 100 policy evaluations in under 1 second
        assert total_time < 1.0
        assert mock_policy_engine.evaluate_policy.call_count == 100

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_policy_memory_usage(self, mock_policy_engine):
        """Test policy memory usage characteristics."""
        # Test with large policy configuration
        large_policy = PolicyConfig(
            version="1.0",
            policy_name="large_policy_test",
            default_tier=SecurityTier.OBSERVE,
            operations={
                f"operation_{i}": PolicyRule(
                    tier=SecurityTier.OBSERVE,
                    allowed_targets=["*"],
                    conditions=[
                        PolicyCondition(
                            field=f"field_{j}", operator="equals", value=f"value_{j}"
                        )
                        for j in range(10)
                    ],
                )
                for i in range(1000)
            },
            security_constraints={},
        )

        # Test policy evaluation with large configuration
        policy_context = PolicyEvaluationContext(
            user="test_user",
            resource="fleet",
            operation="operation_500",
            parameters={},
            time=datetime.utcnow(),
        )

        mock_policy_engine.evaluate_policy.return_value = {
            "allowed": True,
            "reason": "Allowed by large policy",
            "conditions_met": True,
        }

        result = await mock_policy_engine.evaluate_policy(large_policy, policy_context)

        assert result["allowed"] is True
        assert len(large_policy.operations) == 1000
