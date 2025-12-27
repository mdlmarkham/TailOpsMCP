"""
Test file for Policy Gate implementation.

Tests the comprehensive authorization layer for enforcing security policies.
"""

import pytest
from unittest.mock import Mock, patch

from src.services.policy_gate import (
    PolicyGate,
    OperationTier,
    ValidationMode,
    PolicyRule,
    PolicyConfig,
)
from src.auth.token_auth import TokenClaims
from src.models.target_registry import (
    TargetMetadata,
    TargetConnection,
    TargetConstraints,
    ExecutorType,
)
from src.services.target_registry import TargetRegistry
from src.utils.audit import AuditLogger
from src.auth.scopes import Scope


class TestPolicyGate:
    """Test Policy Gate functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.target_registry = Mock(spec=TargetRegistry)
        self.audit_logger = Mock(spec=AuditLogger)
        self.policy_gate = PolicyGate(self.target_registry, self.audit_logger)

        # Mock target
        self.target = TargetMetadata(
            id="test-target",
            type="local",
            executor=ExecutorType.LOCAL,
            connection=TargetConnection(executor=ExecutorType.LOCAL),
            capabilities=[Scope.CONTAINER_WRITE.value, Scope.SYSTEM_READ.value],
            constraints=TargetConstraints(),
            metadata={},
        )

        # Mock claims
        self.claims = TokenClaims(
            agent="test-user",
            scopes=[Scope.CONTAINER_WRITE.value, Scope.SYSTEM_READ.value],
        )

    def test_validate_target_existence_success(self):
        """Test successful target existence validation."""
        self.target_registry.get_target.return_value = self.target

        result = self.policy_gate.validate_target_existence("test-target")

        assert result == self.target
        self.target_registry.get_target.assert_called_once_with("test-target")

    def test_validate_target_existence_failure(self):
        """Test target existence validation failure."""
        self.target_registry.get_target.return_value = None

        with pytest.raises(Exception) as exc_info:
            self.policy_gate.validate_target_existence("nonexistent-target")

        assert "Target not found" in str(exc_info.value)

    def test_validate_capabilities_success(self):
        """Test successful capability validation."""
        required_capabilities = [Scope.CONTAINER_WRITE.value]

        # Should not raise an exception
        self.policy_gate.validate_capabilities(self.target, required_capabilities)

    def test_validate_capabilities_failure(self):
        """Test capability validation failure."""
        required_capabilities = [Scope.DOCKER_ADMIN.value]  # Target doesn't have this

        with pytest.raises(Exception) as exc_info:
            self.policy_gate.validate_capabilities(self.target, required_capabilities)

        assert "lacks required capabilities" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_validate_parameters_success(self):
        """Test successful parameter validation."""
        parameters = {"container_name": "nginx", "timeout": 30}
        constraints = {
            "container_name": {"type": "string", "max_length": 256},
            "timeout": {"type": "int", "min": 1, "max": 300},
        }

        errors = await self.policy_gate.validate_parameters(
            "test_operation", parameters, constraints
        )

        assert len(errors) == 0

    @pytest.mark.asyncio
    async def test_validate_parameters_failure(self):
        """Test parameter validation failure."""
        parameters = {"container_name": "x" * 300, "timeout": 0}  # Invalid values
        constraints = {
            "container_name": {"type": "string", "max_length": 256},
            "timeout": {"type": "int", "min": 1, "max": 300},
        }

        errors = await self.policy_gate.validate_parameters(
            "test_operation", parameters, constraints
        )

        assert len(errors) == 2

    @pytest.mark.asyncio
    async def test_enforce_policy_success(self):
        """Test successful policy enforcement."""
        self.target_registry.get_target.return_value = self.target

        # Mock check_authorization to return True
        with patch("src.auth.scopes.check_authorization") as mock_check:
            mock_check.return_value = (True, "Authorized")

            authorized, errors = await self.policy_gate.enforce_policy(
                tool_name="test_tool",
                target_id="test-target",
                operation="start",
                parameters={"container_name": "nginx"},
                claims=self.claims,
            )

            assert authorized is True
            assert len(errors) == 0

    @pytest.mark.asyncio
    async def test_enforce_policy_authorization_failure(self):
        """Test policy enforcement with authorization failure."""
        self.target_registry.get_target.return_value = self.target

        # Mock check_authorization to return False
        with patch("src.auth.scopes.check_authorization") as mock_check:
            mock_check.return_value = (False, "Missing required scope")

            authorized, errors = await self.policy_gate.enforce_policy(
                tool_name="test_tool",
                target_id="test-target",
                operation="start",
                parameters={"container_name": "nginx"},
                claims=self.claims,
            )

            assert authorized is False
            assert "User authorization failed" in errors[0]

    @pytest.mark.asyncio
    async def test_enforce_policy_dry_run(self):
        """Test policy enforcement in dry-run mode."""
        self.target_registry.get_target.return_value = self.target

        with patch("src.auth.scopes.check_authorization") as mock_check:
            mock_check.return_value = (True, "Authorized")

            authorized, errors = await self.policy_gate.enforce_policy(
                tool_name="test_tool",
                target_id="test-target",
                operation="start",
                parameters={"container_name": "nginx"},
                claims=self.claims,
                dry_run=True,
            )

            assert authorized is True
            assert len(errors) == 0

    async def test_validate_parameters_failure(self):
        """Test parameter validation failure."""
        parameters = {"container_name": "x" * 300, "timeout": 0}  # Invalid values
        constraints = {
            "container_name": {"type": "string", "max_length": 256},
            "timeout": {"type": "int", "min": 1, "max": 300},
        }

        errors = await self.policy_gate.validate_parameters(
            "test_operation", parameters, constraints
        )

        assert len(errors) == 2
        assert "exceeds max length" in errors[0]
        assert "below minimum" in errors[1]

    async def test_enforce_policy_success(self):
        """Test successful policy enforcement."""
        self.target_registry.get_target.return_value = self.target

        # Mock check_authorization to return True
        with patch("src.auth.scopes.check_authorization") as mock_check:
            mock_check.return_value = (True, "Authorized")

            authorized, errors = await self.policy_gate.enforce_policy(
                tool_name="test_tool",
                target_id="test-target",
                operation="start",
                parameters={"container_name": "nginx"},
                claims=self.claims,
            )

            assert authorized is True
            assert len(errors) == 0

    async def test_enforce_policy_authorization_failure(self):
        """Test policy enforcement with authorization failure."""
        self.target_registry.get_target.return_value = self.target

        # Mock check_authorization to return False
        with patch("src.auth.scopes.check_authorization") as mock_check:
            mock_check.return_value = (False, "Missing required scope")

            authorized, errors = await self.policy_gate.enforce_policy(
                tool_name="test_tool",
                target_id="test-target",
                operation="start",
                parameters={"container_name": "nginx"},
                claims=self.claims,
            )

            assert authorized is False
            assert "User authorization failed" in errors[0]

    async def test_enforce_policy_dry_run(self):
        """Test policy enforcement in dry-run mode."""
        self.target_registry.get_target.return_value = self.target

        with patch("src.auth.scopes.check_authorization") as mock_check:
            mock_check.return_value = (True, "Authorized")

            authorized, errors = await self.policy_gate.enforce_policy(
                tool_name="test_tool",
                target_id="test-target",
                operation="start",
                parameters={"container_name": "nginx"},
                claims=self.claims,
                dry_run=True,
            )

            assert authorized is True
            assert len(errors) == 0

    def test_audit_policy_decision(self):
        """Test policy decision auditing."""
        self.policy_gate.audit_policy_decision(
            tool_name="test_tool",
            target_id="test-target",
            operation="start",
            parameters={"container_name": "nginx", "auth_token": "secret"},
            claims=self.claims,
            authorized=True,
            validation_errors=[],
            dry_run=False,
        )

        # Verify audit logger was called
        self.audit_logger.log.assert_called_once()

        # Check that sensitive parameters were sanitized
        call_args = self.audit_logger.log.call_args
        audit_data = call_args[1]["args"]
        assert audit_data["parameters"]["auth_token"] == "<REDACTED>"


class TestPolicyConfig:
    """Test Policy Configuration functionality."""

    def test_policy_rule_creation(self):
        """Test PolicyRule creation."""
        rule = PolicyRule(
            name="test_rule",
            description="Test rule description",
            target_pattern=".*",
            allowed_operations=["start", "stop"],
            required_capabilities=[Scope.CONTAINER_WRITE.value],
            parameter_constraints={"timeout": {"type": "int", "min": 1, "max": 300}},
            operation_tier=OperationTier.CONTROL,
        )

        assert rule.name == "test_rule"
        assert rule.operation_tier == OperationTier.CONTROL
        assert not rule.requires_approval

    def test_policy_config_creation(self):
        """Test PolicyConfig creation."""
        rule = PolicyRule(
            name="test_rule",
            description="Test rule description",
            target_pattern=".*",
            allowed_operations=["start", "stop"],
            required_capabilities=[Scope.CONTAINER_WRITE.value],
            parameter_constraints={"timeout": {"type": "int", "min": 1, "max": 300}},
            operation_tier=OperationTier.CONTROL,
        )

        config = PolicyConfig(rules=[rule])

        assert len(config.rules) == 1
        assert config.default_validation_mode == ValidationMode.STRICT
        assert config.enable_dry_run is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
