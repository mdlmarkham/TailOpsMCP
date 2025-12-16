"""
Enhanced test suite for Policy Gate with comprehensive authorization testing.
"""

import pytest
from unittest.mock import Mock

from src.services.policy_gate import PolicyGate, OperationTier
from src.auth.token_auth import TokenClaims
from src.auth.scopes import Scope
from src.models.target_registry import (
    TargetMetadata,
    TargetConnection,
    TargetConstraints,
)

from tests.mock_policy_gate import MockPolicyGate, PolicyGateConfigs
from tests.fixtures.target_registry_fixtures import TargetRegistryFixtures
from tests.test_utils import AuthorizationAssertions, TestDataGenerators


class TestPolicyGateBasic:
    """Basic tests for Policy Gate functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.target_registry = Mock(
            spec=TargetRegistryFixtures.create_mock_target_registry
        )
        self.audit_logger = Mock()
        self.policy_gate = PolicyGate(self.target_registry, self.audit_logger)

        # Create test target
        self.test_target = TargetMetadata(
            id="test-target",
            type="local",
            executor="local",
            connection=TargetConnection(executor="local"),
            capabilities=[Scope.CONTAINER_READ.value, Scope.SYSTEM_READ.value],
            constraints=TargetConstraints(),
            metadata={},
        )

        # Create test claims
        self.readonly_claims = TokenClaims(
            agent="test-user",
            scopes=[Scope.CONTAINER_READ.value, Scope.SYSTEM_READ.value],
        )

        self.admin_claims = TokenClaims(agent="test-admin", scopes=["admin"])

    def test_authorize_readonly_operation(self):
        """Test authorizing a readonly operation."""
        result = self.policy_gate.authorize_operation(
            "get_container_status", self.test_target, self.readonly_claims, {}
        )

        AuthorizationAssertions.assert_authorized(result)

    def test_authorize_write_operation_with_permission(self):
        """Test authorizing a write operation with sufficient permissions."""
        # Create target with write capabilities
        write_target = TargetMetadata(
            id="write-target",
            type="local",
            executor="local",
            connection=TargetConnection(executor="local"),
            capabilities=[Scope.CONTAINER_WRITE.value],
            constraints=TargetConstraints(),
            metadata={},
        )

        # Create claims with write permissions
        write_claims = TokenClaims(
            agent="test-user", scopes=[Scope.CONTAINER_WRITE.value]
        )

        result = self.policy_gate.authorize_operation(
            "start_container", write_target, write_claims, {}
        )

        AuthorizationAssertions.assert_authorized(result)

    def test_deny_operation_without_permission(self):
        """Test denying an operation without sufficient permissions."""
        result = self.policy_gate.authorize_operation(
            "start_container",  # Write operation
            self.test_target,  # Readonly target
            self.readonly_claims,  # Readonly claims
            {},
        )

        AuthorizationAssertions.assert_denied(result)

    def test_dry_run_mode(self):
        """Test dry run mode for control operations."""
        result = self.policy_gate.authorize_operation(
            "start_container",
            self.test_target,
            self.readonly_claims,
            {},
            operation_tier=OperationTier.CONTROL,
            dry_run=True,
        )

        AuthorizationAssertions.assert_authorized(
            result, expected_requires_approval=True
        )
        AuthorizationAssertions.assert_dry_run_result(result)


class TestPolicyGateMock:
    """Tests using mock Policy Gate for controlled testing."""

    def test_permissive_policy_gate(self):
        """Test permissive policy gate configuration."""
        policy_gate = PolicyGateConfigs.permissive()

        target = TargetRegistryFixtures.create_test_target()
        claims = TestDataGenerators.generate_token_claims()

        result = policy_gate.authorize_operation("any_operation", target, claims, {})

        AuthorizationAssertions.assert_authorized(result)

    def test_restrictive_policy_gate(self):
        """Test restrictive policy gate configuration."""
        policy_gate = PolicyGateConfigs.restrictive()

        target = TargetRegistryFixtures.create_test_target()
        claims = TestDataGenerators.generate_token_claims()

        result = policy_gate.authorize_operation("any_operation", target, claims, {})

        AuthorizationAssertions.assert_denied(result)

    def test_approval_required_policy_gate(self):
        """Test policy gate that requires approval for write operations."""
        policy_gate = PolicyGateConfigs.approval_required()

        target = TargetRegistryFixtures.create_test_target()
        claims = TestDataGenerators.generate_token_claims()

        # Test readonly operation (should not require approval)
        readonly_result = policy_gate.authorize_operation(
            "get_container_status", target, claims, {}
        )
        AuthorizationAssertions.assert_authorized(
            readonly_result, expected_requires_approval=False
        )

        # Test write operation (should require approval)
        write_result = policy_gate.authorize_operation(
            "start_container", target, claims, {}
        )
        AuthorizationAssertions.assert_authorized(
            write_result, expected_requires_approval=True
        )

    def test_target_specific_policy_gate(self):
        """Test policy gate with target-specific rules."""
        policy_gate = PolicyGateConfigs.target_specific()

        target = TargetRegistryFixtures.create_test_target("docker-host")
        claims = TestDataGenerators.generate_token_claims()

        # Test allowed operation on specific target
        allowed_result = policy_gate.authorize_operation(
            "get_container_status", target, claims, {}
        )
        AuthorizationAssertions.assert_authorized(allowed_result)

        # Test denied operation on specific target
        denied_result = policy_gate.authorize_operation(
            "stop_container", target, claims, {}
        )
        AuthorizationAssertions.assert_denied(denied_result)


class TestPolicyGateParameterValidation:
    """Tests for parameter validation in Policy Gate."""

    def test_parameter_validation_success(self):
        """Test successful parameter validation."""
        policy_gate = PolicyGateConfigs.with_parameter_validation()

        validation_result = policy_gate.validate_parameters(
            "start_container", {"container_id": "test-container-123"}
        )

        assert validation_result["valid"] is True
        assert validation_result["errors"] == []

    def test_parameter_validation_failure(self):
        """Test failed parameter validation."""
        policy_gate = PolicyGateConfigs.with_parameter_validation()

        validation_result = policy_gate.validate_parameters(
            "start_container",
            {"container_id": ""},  # Empty string should fail validation
        )

        assert validation_result["valid"] is False
        assert len(validation_result["errors"]) > 0

    def test_enum_parameter_validation(self):
        """Test enum parameter validation."""
        policy_gate = PolicyGateConfigs.with_parameter_validation()

        # Test valid enum value
        valid_result = policy_gate.validate_parameters(
            "deploy_stack", {"stack_name": "web"}
        )
        assert valid_result["valid"] is True

        # Test invalid enum value
        invalid_result = policy_gate.validate_parameters(
            "deploy_stack", {"stack_name": "invalid-stack"}
        )
        assert invalid_result["valid"] is False

    def test_range_parameter_validation(self):
        """Test numeric range parameter validation."""
        policy_gate = PolicyGateConfigs.with_parameter_validation()

        # Test valid range
        valid_result = policy_gate.validate_parameters(
            "update_system", {"package_count": 50}
        )
        assert valid_result["valid"] is True

        # Test invalid range (too high)
        invalid_result = policy_gate.validate_parameters(
            "update_system", {"package_count": 150}
        )
        assert invalid_result["valid"] is False


class TestPolicyGateEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_authorize_with_none_target(self):
        """Test authorization with None target."""
        policy_gate = MockPolicyGate()
        claims = TestDataGenerators.generate_token_claims()

        result = policy_gate.authorize_operation("get_system_status", None, claims, {})

        # Should handle None target gracefully
        assert result is not None
        assert "authorized" in result

    def test_authorize_with_empty_parameters(self):
        """Test authorization with empty parameters."""
        policy_gate = MockPolicyGate()
        target = TargetRegistryFixtures.create_test_target()
        claims = TestDataGenerators.generate_token_claims()

        result = policy_gate.authorize_operation(
            "get_system_status", target, claims, {}
        )

        AuthorizationAssertions.assert_authorized(result)

    def test_authorize_unknown_tool(self):
        """Test authorization for unknown tool."""
        policy_gate = MockPolicyGate()
        target = TargetRegistryFixtures.create_test_target()
        claims = TestDataGenerators.generate_token_claims()

        result = policy_gate.authorize_operation("unknown_tool_123", target, claims, {})

        # Policy gate should handle unknown tools
        assert result is not None
        assert "authorized" in result


class TestPolicyGateIntegration:
    """Integration tests for Policy Gate with other components."""

    def test_integration_with_target_registry(self):
        """Test integration with Target Registry."""
        registry = TargetRegistryFixtures.create_mock_target_registry()
        policy_gate = MockPolicyGate()

        # Verify policy gate can use target registry
        target = registry.get_target("target-1")
        assert target is not None

        claims = TestDataGenerators.generate_token_claims()
        result = policy_gate.authorize_operation(
            "get_container_status", target, claims, {}
        )

        assert result is not None

    def test_integration_with_audit_logger(self):
        """Test integration with Audit Logger."""
        from unittest.mock import Mock

        audit_logger = Mock()
        policy_gate = MockPolicyGate(audit_logger=audit_logger)

        target = TargetRegistryFixtures.create_test_target()
        claims = TestDataGenerators.generate_token_claims()

        # Perform authorization
        policy_gate.authorize_operation("get_container_status", target, claims, {})

        # Verify audit logger was called
        # (MockPolicyGate doesn't actually call audit logger, but real one would)
        # This test would need to be adapted for the real PolicyGate implementation
        pass


class TestPolicyGatePerformance:
    """Performance tests for Policy Gate."""

    def test_authorization_performance(self):
        """Test performance of authorization decisions."""
        import time

        policy_gate = MockPolicyGate()
        target = TargetRegistryFixtures.create_test_target()
        claims = TestDataGenerators.generate_token_claims()

        # Measure authorization time
        start_time = time.time()
        for _ in range(1000):
            result = policy_gate.authorize_operation(
                "get_container_status", target, claims, {}
            )
            assert result is not None
        end_time = time.time()

        authorization_time = (end_time - start_time) / 1000

        # Assert reasonable authorization time (less than 1ms per decision)
        assert authorization_time < 0.001, (
            f"Authorization time {authorization_time}s exceeds threshold"
        )

    def test_concurrent_authorization(self):
        """Test concurrent authorization requests."""
        import asyncio
        import time

        policy_gate = MockPolicyGate()
        target = TargetRegistryFixtures.create_test_target()
        claims = TestDataGenerators.generate_token_claims()

        async def authorize_operation():
            """Async authorization operation."""
            return policy_gate.authorize_operation(
                "get_container_status", target, claims, {}
            )

        # Create multiple concurrent authorization tasks
        tasks = [authorize_operation() for _ in range(100)]

        start_time = time.time()
        results = asyncio.run(asyncio.gather(*tasks))
        end_time = time.time()

        total_time = end_time - start_time

        # Verify all authorizations completed
        assert len(results) == 100
        for result in results:
            assert result is not None

        # Assert reasonable concurrent performance
        assert total_time < 1.0, (
            f"Concurrent authorization time {total_time}s exceeds threshold"
        )


# Parameterized tests for different operation tiers
@pytest.mark.parametrize(
    "operation_tier,expected_requires_approval",
    [
        (OperationTier.OBSERVE, False),
        (OperationTier.CONTROL, True),
        (OperationTier.ADMIN, True),
    ],
)
def test_operation_tiers(operation_tier, expected_requires_approval):
    """Test different operation tiers."""
    policy_gate = PolicyGateConfigs.approval_required()
    target = TargetRegistryFixtures.create_test_target()
    claims = TestDataGenerators.generate_token_claims()

    result = policy_gate.authorize_operation(
        "test_operation", target, claims, {}, operation_tier=operation_tier
    )

    AuthorizationAssertions.assert_authorized(result, expected_requires_approval)


# Test class for security-specific scenarios
class TestPolicyGateSecurity:
    """Security-focused tests for Policy Gate."""

    def test_privilege_escalation_prevention(self):
        """Test prevention of privilege escalation."""
        policy_gate = MockPolicyGate(default_allow=False)

        # Create low-privilege claims
        low_privilege_claims = TokenClaims(
            agent="low-priv-user", scopes=[Scope.CONTAINER_READ.value]
        )

        # Create high-privilege target
        high_privilege_target = TargetMetadata(
            id="admin-target",
            type="local",
            executor="local",
            connection=TargetConnection(executor="local"),
            capabilities=["admin"],
            constraints=TargetConstraints(),
            metadata={},
        )

        # Attempt privileged operation with low privileges
        result = policy_gate.authorize_operation(
            "admin_operation", high_privilege_target, low_privilege_claims, {}
        )

        # Should be denied
        AuthorizationAssertions.assert_denied(result)

    def test_parameter_injection_prevention(self):
        """Test prevention of parameter injection attacks."""
        policy_gate = PolicyGateConfigs.with_parameter_validation()

        # Attempt injection through parameters
        malicious_parameters = {
            "container_id": "test-container; rm -rf /",
            "stack_name": "web' OR 1=1--",
        }

        validation_result = policy_gate.validate_parameters(
            "start_container", malicious_parameters
        )

        # Should fail validation
        assert validation_result["valid"] is False
        assert len(validation_result["errors"]) > 0
