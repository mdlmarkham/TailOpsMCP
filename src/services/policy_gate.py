"""
Policy Gate - Comprehensive authorization layer for enforcing security policies.

Provides defense-in-depth security controls:
1. Target registry validation and capability checking
2. Parameter validation against allowed ranges
3. Operation tier management (observe/control/admin)
4. Dry-run mode support for control/admin operations
5. Integration with existing scope-based authorization
6. Comprehensive audit logging for compliance tracking
"""

import os
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass

from src.auth.scopes import Scope, check_authorization
from src.auth.token_auth import TokenClaims
from src.models.target_registry import TargetMetadata
from src.services.target_registry import TargetRegistry
from src.services.input_validator import InputValidator, AllowlistManager, ParameterType
from src.models.validation import ValidationMode
from src.services.discovery_tools import DiscoveryTools
from src.utils.audit import AuditLogger
from src.utils.errors import ErrorCategory, SystemManagerError


logger = logging.getLogger(__name__)


class OperationTier(str, Enum):
    """Operation tiers for policy enforcement."""

    OBSERVE = "observe"  # Read-only operations
    CONTROL = "control"  # Start/stop operations
    ADMIN = "admin"  # Administrative operations


@dataclass
class PolicyRule:
    """Individual policy rule definition."""

    name: str
    description: str
    target_pattern: str  # Regex pattern for target matching
    allowed_operations: List[str]
    required_capabilities: List[str]
    parameter_constraints: Dict[str, Any]
    operation_tier: OperationTier
    requires_approval: bool = False
    dry_run_supported: bool = True


@dataclass
class PolicyConfig:
    """Policy configuration container."""

    rules: List[PolicyRule]
    default_validation_mode: ValidationMode = ValidationMode.STRICT
    enable_dry_run: bool = True
    maintenance_windows: List[Dict[str, str]] = None
    lockout_periods: List[Dict[str, str]] = None


class PolicyGate:
    """Comprehensive policy enforcement layer for security controls."""

    def __init__(self, target_registry: TargetRegistry, audit_logger: AuditLogger):
        """Initialize PolicyGate with dependencies.

        Args:
            target_registry: Target registry for validation
            audit_logger: Audit logger for policy decisions
        """
        self.target_registry = target_registry
        self.audit_logger = audit_logger
        self.policy_config = self._load_policy_config()
        self.validation_mode = ValidationMode(
            os.getenv("SYSTEMMANAGER_POLICY_MODE", "strict").lower()
        )
        self.enable_dry_run = (
            os.getenv("SYSTEMMANAGER_ENABLE_DRY_RUN", "true").lower() == "true"
        )

        # Initialize input validation system
        self.allowlist_manager = AllowlistManager()
        self.discovery_tools = DiscoveryTools()
        self.input_validator = InputValidator(self.allowlist_manager)

        # Register discovery tools with allowlist manager
        self._register_discovery_tools()

    def _register_discovery_tools(self):
        """Register discovery tools with allowlist manager."""
        self.allowlist_manager.register_discovery_tool(
            "list_services", self.discovery_tools.list_services
        )
        self.allowlist_manager.register_discovery_tool(
            "list_containers", self.discovery_tools.list_containers
        )
        self.allowlist_manager.register_discovery_tool(
            "list_stacks", self.discovery_tools.list_stacks
        )
        self.allowlist_manager.register_discovery_tool(
            "list_ports", self.discovery_tools.list_ports
        )

    def _load_policy_config(self) -> PolicyConfig:
        """Load policy configuration from environment or defaults."""
        # Default policy rules - can be extended via configuration
        default_rules = [
            PolicyRule(
                name="docker_container_operations",
                description="Docker container management operations",
                target_pattern=".*",
                allowed_operations=["start", "stop", "restart", "inspect"],
                required_capabilities=[Scope.CONTAINER_WRITE.value],
                parameter_constraints={
                    "container_name": {"type": "string", "max_length": 256},
                    "timeout": {"type": "int", "min": 1, "max": 300},
                },
                operation_tier=OperationTier.CONTROL,
            ),
            PolicyRule(
                name="docker_image_operations",
                description="Docker image management operations",
                target_pattern=".*",
                allowed_operations=["pull", "list", "remove"],
                required_capabilities=[Scope.DOCKER_ADMIN.value],
                parameter_constraints={
                    "image_name": {"type": "string", "max_length": 512},
                    "tag": {"type": "string", "max_length": 128},
                },
                operation_tier=OperationTier.ADMIN,
                requires_approval=True,
            ),
            PolicyRule(
                name="system_monitoring",
                description="System monitoring and status operations",
                target_pattern=".*",
                allowed_operations=["status", "metrics", "processes"],
                required_capabilities=[Scope.SYSTEM_READ.value],
                parameter_constraints={},
                operation_tier=OperationTier.OBSERVE,
            ),
            PolicyRule(
                name="network_operations",
                description="Network management operations",
                target_pattern=".*",
                allowed_operations=["status", "scan", "test"],
                required_capabilities=[Scope.NETWORK_READ.value],
                parameter_constraints={
                    "port": {"type": "int", "min": 1, "max": 65535},
                    "host": {"type": "string", "max_length": 253},
                },
                operation_tier=OperationTier.OBSERVE,
            ),
        ]

        return PolicyConfig(rules=default_rules)

    def validate_target_existence(self, target_id: str) -> TargetMetadata:
        """Validate that target exists in registry.

        Args:
            target_id: Target identifier

        Returns:
            TargetMetadata if target exists

        Raises:
            SystemManagerError: If target not found
        """
        target = self.target_registry.get_target(target_id)
        if not target:
            raise SystemManagerError(
                f"Target not found: {target_id}", category=ErrorCategory.VALIDATION
            )
        return target

    def validate_capabilities(
        self, target: TargetMetadata, required_capabilities: List[str]
    ) -> None:
        """Validate target has required capabilities.

        Args:
            target: Target metadata
            required_capabilities: List of required capability strings

        Raises:
            SystemManagerError: If target lacks required capabilities
        """
        missing_capabilities = []
        for capability in required_capabilities:
            if capability not in target.capabilities:
                missing_capabilities.append(capability)

        if missing_capabilities:
            raise SystemManagerError(
                f"Target {target.id} lacks required capabilities: {missing_capabilities}",
                category=ErrorCategory.FORBIDDEN,
            )

    async def validate_parameters(
        self,
        operation: str,
        parameters: Dict[str, Any],
        constraints: Dict[str, Any],
        target: Optional[str] = None,
    ) -> List[str]:
        """Validate operation parameters against constraints with enhanced validation.

        Args:
            operation: Operation name
            parameters: Operation parameters
            constraints: Parameter constraints from policy rule
            target: Target system for allowlist validation

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Map parameter names to validation types
        param_type_mapping = self._get_parameter_type_mapping(operation)

        # Validate each parameter
        for param_name, constraint in constraints.items():
            if param_name not in parameters:
                # Optional parameters are allowed to be missing
                continue

            value = parameters[param_name]

            # Enhanced validation using input validator
            if param_name in param_type_mapping:
                param_type = param_type_mapping[param_name]
                validation_errors = await self.input_validator.validate_parameter(
                    param_type, value, target, self.validation_mode
                )
                errors.extend(validation_errors)
            else:
                # Fallback to basic validation
                errors.extend(
                    self._basic_parameter_validation(param_name, value, constraint)
                )

        return errors

    def _get_parameter_type_mapping(self, operation: str) -> Dict[str, ParameterType]:
        """Map parameter names to validation types based on operation."""
        # Define parameter type mappings for common operations
        mappings = {
            "start_container": {
                "container": ParameterType.CONTAINER_NAME,
                "timeout": ParameterType.TIMEOUT,
            },
            "stop_container": {
                "container": ParameterType.CONTAINER_NAME,
                "timeout": ParameterType.TIMEOUT,
            },
            "restart_container": {
                "container": ParameterType.CONTAINER_NAME,
                "timeout": ParameterType.TIMEOUT,
            },
            "inspect_container": {"container": ParameterType.CONTAINER_NAME},
            "deploy_stack": {
                "stack": ParameterType.STACK_NAME,
                "timeout": ParameterType.TIMEOUT,
            },
            "pull_stack": {
                "stack": ParameterType.STACK_NAME,
                "timeout": ParameterType.TIMEOUT,
            },
            "restart_stack": {
                "stack": ParameterType.STACK_NAME,
                "timeout": ParameterType.TIMEOUT,
            },
            "restart_service": {
                "service": ParameterType.SERVICE_NAME,
                "timeout": ParameterType.TIMEOUT,
            },
            "read_file": {"path": ParameterType.FILE_PATH},
            "list_directory": {"path": ParameterType.FILE_PATH},
            "test_connectivity": {
                "host": ParameterType.HOSTNAME,
                "port": ParameterType.PORT_NUMBER,
            },
            "scan_ports": {
                "host": ParameterType.HOSTNAME,
                "port_range": ParameterType.PORT_NUMBER,
            },
        }

        return mappings.get(operation, {})

    def _basic_parameter_validation(
        self, param_name: str, value: Any, constraint: Dict[str, Any]
    ) -> List[str]:
        """Basic parameter validation as fallback."""
        errors = []

        # Type validation
        if constraint.get("type") == "string":
            if not isinstance(value, str):
                errors.append(f"Parameter {param_name} must be string")
            elif "max_length" in constraint and len(value) > constraint["max_length"]:
                errors.append(
                    f"Parameter {param_name} exceeds max length {constraint['max_length']}"
                )

        elif constraint.get("type") == "int":
            if not isinstance(value, int):
                errors.append(f"Parameter {param_name} must be integer")
            else:
                if "min" in constraint and value < constraint["min"]:
                    errors.append(
                        f"Parameter {param_name} below minimum {constraint['min']}"
                    )
                if "max" in constraint and value > constraint["max"]:
                    errors.append(
                        f"Parameter {param_name} above maximum {constraint['max']}"
                    )

        elif constraint.get("type") == "list":
            if not isinstance(value, list):
                errors.append(f"Parameter {param_name} must be list")
            elif "max_items" in constraint and len(value) > constraint["max_items"]:
                errors.append(
                    f"Parameter {param_name} exceeds max items {constraint['max_items']}"
                )

        return errors

    def get_matching_policy_rule(
        self, tool_name: str, target_id: str, operation: str
    ) -> Optional[PolicyRule]:
        """Find policy rule matching the operation.

        Args:
            tool_name: Tool name
            target_id: Target identifier
            operation: Operation name

        Returns:
            Matching PolicyRule or None if no match
        """
        for rule in self.policy_config.rules:
            # Check if operation is allowed
            if operation not in rule.allowed_operations:
                continue

            # Check if target matches pattern
            if not re.match(rule.target_pattern, target_id):
                continue

            return rule

        return None

    async def enforce_policy(
        self,
        tool_name: str,
        target_id: str,
        operation: str,
        parameters: Dict[str, Any],
        claims: TokenClaims,
        dry_run: bool = False,
    ) -> Tuple[bool, List[str]]:
        """Enforce security policy for an operation with proper async/sync consistency.

        Args:
            tool_name: Tool name
            target_id: Target identifier
            operation: Operation name
            parameters: Operation parameters
            claims: User token claims
            dry_run: Whether this is a dry-run operation

        Returns:
            (authorized: bool, validation_errors: List[str])
        """
        validation_errors = []

        try:
            # Step 1: Validate target existence (fixed async method)
            target = await self.validate_target_existence(target_id)

            # Step 2: Find matching policy rule
            policy_rule = self.get_matching_policy_rule(tool_name, target_id, operation)
            if not policy_rule:
                validation_errors.append(
                    f"No policy rule found for operation {operation} on target {target_id}"
                )
                return False, validation_errors

            # Step 3: Validate user authorization
            authorized, reason = check_authorization(tool_name, claims.scopes or [])
            if not authorized:
                validation_errors.append(f"User authorization failed: {reason}")
                return False, validation_errors

            # Step 4: Validate target capabilities (fixed async method)
            cap_errors = await self.validate_capabilities(
                target, policy_rule.required_capabilities
            )
            validation_errors.extend(cap_errors)

            # Step 5: Validate parameters (properly awaited)
            param_errors = await self.validate_parameters(
                operation, parameters, policy_rule.parameter_constraints, target_id
            )
            validation_errors.extend(param_errors)

            # Step 6: Check operation tier restrictions
            if policy_rule.operation_tier == OperationTier.ADMIN and not dry_run:
                if policy_rule.requires_approval and not self._check_approval(
                    tool_name, parameters
                ):
                    validation_errors.append("Admin operation requires approval")
                    return False, validation_errors

            # Step 7: Handle dry-run mode
            if dry_run:
                if not policy_rule.dry_run_supported:
                    validation_errors.append("Dry-run not supported for this operation")
                    return False, validation_errors
                # Dry-run operations are always authorized for validation purposes
                return True, validation_errors

            # Step 8: Handle validation mode
            if validation_errors and self.validation_mode == ValidationMode.STRICT:
                return False, validation_errors
            elif validation_errors and self.validation_mode == ValidationMode.WARN:
                logger.warning(
                    f"Policy validation warnings for {tool_name}: {validation_errors}"
                )
                return True, validation_errors

            return True, validation_errors

        except SystemManagerError as e:
            validation_errors.append(str(e))
            return False, validation_errors
        except Exception as e:
            logger.error(f"Policy enforcement error: {e}")
            validation_errors.append(f"Policy enforcement error: {e}")
            return False, validation_errors

    async def validate_target_existence(self, target_id: str) -> TargetMetadata:
        """Validate target existence in registry.

        Args:
            target_id: Target identifier

        Returns:
            TargetMetadata if found

        Raises:
            SystemManagerError: If target not found
        """
        try:
            target = await self.target_registry.get_target(target_id)
            if not target:
                raise SystemManagerError(
                    f"Target {target_id} not found in registry",
                    ErrorCategory.VALIDATION_ERROR,
                )
            return target
        except Exception as e:
            if isinstance(e, SystemManagerError):
                raise
            raise SystemManagerError(
                f"Error validating target {target_id}: {str(e)}",
                ErrorCategory.VALIDATION_ERROR,
            )

    async def validate_capabilities(
        self, target: TargetMetadata, required_capabilities: List[str]
    ) -> List[str]:
        """Validate target capabilities against required capabilities.

        Args:
            target: Target metadata
            required_capabilities: List of required capabilities

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        try:
            target_capabilities = target.capabilities or []

            for capability in required_capabilities:
                if capability not in target_capabilities:
                    errors.append(
                        f"Target {target.id} missing required capability: {capability}"
                    )

            if errors:
                logger.warning(
                    f"Capability validation failed for target {target.id}: {errors}"
                )

            return errors

        except Exception as e:
            error_msg = (
                f"Error validating capabilities for target {target.id}: {str(e)}"
            )
            logger.error(error_msg)
            return [error_msg]

    def _check_approval(self, tool_name: str, parameters: Dict[str, Any]) -> bool:
        """Check if operation has approval (placeholder implementation).

        Args:
            tool_name: Tool name
            parameters: Operation parameters

        Returns:
            True if approved (or approval not required)
        """
        # TODO: Implement actual approval workflow
        # For now, return True to allow development
        return True

    def audit_policy_decision(
        self,
        tool_name: str,
        target_id: str,
        operation: str,
        parameters: Dict[str, Any],
        claims: TokenClaims,
        authorized: bool,
        validation_errors: List[str],
        dry_run: bool = False,
    ) -> None:
        """Audit policy decision for compliance tracking.

        Args:
            tool_name: Tool name
            target_id: Target identifier
            operation: Operation name
            parameters: Operation parameters
            claims: User token claims
            authorized: Whether operation was authorized
            validation_errors: List of validation errors
            dry_run: Whether this was a dry-run operation
        """
        audit_data = {
            "tool": tool_name,
            "target": target_id,
            "operation": operation,
            "parameters": self._sanitize_parameters(parameters),
            "subject": claims.agent,
            "scopes": claims.scopes or [],
            "authorized": authorized,
            "validation_errors": validation_errors,
            "dry_run": dry_run,
            "policy_mode": self.validation_mode.value,
        }

        self.audit_logger.log(
            tool="policy_gate",
            args=audit_data,
            result={"success": authorized, "errors": validation_errors},
        )

    def _sanitize_parameters(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize parameters for audit logging."""
        sanitized = {}
        for key, value in parameters.items():
            if (
                "token" in key.lower()
                or "password" in key.lower()
                or "secret" in key.lower()
            ):
                sanitized[key] = "<REDACTED>"
            else:
                sanitized[key] = value
        return sanitized


# Capability definitions for common operations
CAPABILITY_DEFINITIONS = {
    "docker_container_operations": {
        "description": "Docker container management operations",
        "required_capabilities": [Scope.CONTAINER_WRITE.value],
        "allowed_operations": ["start", "stop", "restart", "inspect"],
        "parameter_constraints": {
            "container_name": {"type": "string", "max_length": 256},
            "timeout": {"type": "int", "min": 1, "max": 300},
        },
        "operation_tier": OperationTier.CONTROL,
    },
    "docker_image_operations": {
        "description": "Docker image management operations",
        "required_capabilities": [Scope.DOCKER_ADMIN.value],
        "allowed_operations": ["pull", "list", "remove"],
        "parameter_constraints": {
            "image_name": {"type": "string", "max_length": 512},
            "tag": {"type": "string", "max_length": 128},
        },
        "operation_tier": OperationTier.ADMIN,
        "requires_approval": True,
    },
    "system_monitoring": {
        "description": "System monitoring and status operations",
        "required_capabilities": [Scope.SYSTEM_READ.value],
        "allowed_operations": ["status", "metrics", "processes"],
        "parameter_constraints": {},
        "operation_tier": OperationTier.OBSERVE,
    },
    "network_operations": {
        "description": "Network management operations",
        "required_capabilities": [Scope.NETWORK_READ.value],
        "allowed_operations": ["status", "scan", "test"],
        "parameter_constraints": {
            "port": {"type": "int", "min": 1, "max": 65535},
            "host": {"type": "string", "max_length": 253},
        },
        "operation_tier": OperationTier.OBSERVE,
    },
}


# Parameter validation rules for common patterns
PARAMETER_VALIDATION_RULES = {
    "service_name": {
        "type": "string",
        "max_length": 64,
        "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$",
    },
    "container_name": {
        "type": "string",
        "max_length": 256,
        "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$",
    },
    "stack_name": {
        "type": "string",
        "max_length": 64,
        "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$",
    },
    "port": {"type": "int", "min": 1, "max": 65535},
    "timeout": {"type": "int", "min": 1, "max": 3600},
    "output_limit": {
        "type": "int",
        "min": 1,
        "max": 10485760,  # 10MB
    },
}
