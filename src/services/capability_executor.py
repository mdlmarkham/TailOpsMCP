"""
Capability-Driven Execution Engine

Provides structured capability-driven operations that replace free-text commands
with typed, validated, and policy-enforced operations.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone
import json
import re

from src.models.policy_models import (
    CapabilityOperation,
    OperationType,
    TargetRole,
    PolicyContext,
    PolicyEvaluation,
    PolicyDecision,
)
from src.models.execution import ExecutionResult, ExecutionStatus, ExecutionSeverity
from src.services.policy_engine import PolicyEngine
from src.services.execution_factory import ExecutionBackendFactory
from src.utils.audit import AuditLogger


logger = logging.getLogger(__name__)


class CapabilityValidator:
    """Validates capability parameters against schemas and constraints."""

    def __init__(self):
        """Initialize capability validator."""
        self.parameter_schemas = self._load_parameter_schemas()
        self.validation_patterns = self._load_validation_patterns()

    def _load_parameter_schemas(self) -> Dict[OperationType, Dict[str, Any]]:
        """Load parameter schemas for all operations."""
        return {
            OperationType.SERVICE_RESTART: {
                "service_name": {
                    "type": "string",
                    "required": True,
                    "max_length": 64,
                    "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$",
                    "description": "Name of the service to restart",
                },
                "timeout": {
                    "type": "int",
                    "required": False,
                    "min": 1,
                    "max": 300,
                    "default": 60,
                    "description": "Timeout in seconds",
                },
            },
            OperationType.SERVICE_START: {
                "service_name": {
                    "type": "string",
                    "required": True,
                    "max_length": 64,
                    "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$",
                },
                "timeout": {
                    "type": "int",
                    "required": False,
                    "min": 1,
                    "max": 300,
                    "default": 60,
                },
            },
            OperationType.SERVICE_STOP: {
                "service_name": {
                    "type": "string",
                    "required": True,
                    "max_length": 64,
                    "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$",
                },
                "timeout": {
                    "type": "int",
                    "required": False,
                    "min": 1,
                    "max": 300,
                    "default": 30,
                },
            },
            OperationType.CONTAINER_CREATE: {
                "template": {
                    "type": "string",
                    "required": True,
                    "max_length": 128,
                    "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$",
                    "description": "Container template or image name",
                },
                "name": {
                    "type": "string",
                    "required": True,
                    "max_length": 64,
                    "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$",
                    "description": "Name for the new container",
                },
                "config": {
                    "type": "dict",
                    "required": False,
                    "default": {},
                    "description": "Container configuration options",
                },
            },
            OperationType.CONTAINER_DELETE: {
                "container_name": {
                    "type": "string",
                    "required": True,
                    "max_length": 64,
                    "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$",
                },
                "force": {
                    "type": "bool",
                    "required": False,
                    "default": False,
                    "description": "Force deletion even if container is running",
                },
            },
            OperationType.STACK_DEPLOY: {
                "stack_name": {
                    "type": "string",
                    "required": True,
                    "max_length": 64,
                    "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$",
                },
                "config": {
                    "type": "dict",
                    "required": True,
                    "description": "Stack configuration",
                },
                "force": {"type": "bool", "required": False, "default": False},
            },
            OperationType.BACKUP_CREATE: {
                "backup_id": {
                    "type": "string",
                    "required": True,
                    "max_length": 64,
                    "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$",
                },
                "target_path": {
                    "type": "string",
                    "required": True,
                    "max_length": 1024,
                    "description": "Path to backup",
                },
                "backup_type": {
                    "type": "string",
                    "required": False,
                    "default": "full",
                    "allowed_values": ["full", "incremental", "differential"],
                },
            },
            OperationType.SNAPSHOT_CREATE: {
                "container_id": {
                    "type": "string",
                    "required": True,
                    "max_length": 64,
                    "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$",
                },
                "snapshot_name": {
                    "type": "string",
                    "required": True,
                    "max_length": 64,
                    "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$",
                },
                "description": {"type": "string", "required": False, "max_length": 256},
            },
            OperationType.FILE_READ: {
                "file_path": {
                    "type": "string",
                    "required": True,
                    "max_length": 1024,
                    "pattern": r"^[^<>:\"|?*]+$",
                    "description": "Path to file to read",
                },
                "encoding": {
                    "type": "string",
                    "required": False,
                    "default": "utf-8",
                    "allowed_values": ["utf-8", "ascii", "latin-1"],
                },
            },
            OperationType.FILE_WRITE: {
                "file_path": {
                    "type": "string",
                    "required": True,
                    "max_length": 1024,
                    "pattern": r"^[^<>:\"|?*]+$",
                },
                "content": {
                    "type": "string",
                    "required": True,
                    "max_length": 1048576,  # 1MB
                    "description": "Content to write",
                },
                "encoding": {"type": "string", "required": False, "default": "utf-8"},
            },
        }

    def _load_validation_patterns(self) -> Dict[str, str]:
        """Load common validation patterns."""
        return {
            "hostname": r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
            "ip_address": r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
            "port": r"^(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$",
            "email": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
            "uuid": r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            "safe_filename": r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$",
        }

    def validate_parameters(
        self, operation_type: OperationType, parameters: Dict[str, Any]
    ) -> Tuple[bool, List[str]]:
        """Validate operation parameters against schema.

        Args:
            operation_type: Type of operation
            parameters: Parameters to validate

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        if operation_type not in self.parameter_schemas:
            errors.append(
                f"No parameter schema defined for operation: {operation_type}"
            )
            return False, errors

        schema = self.parameter_schemas[operation_type]

        # Check required parameters
        for param_name, param_schema in schema.items():
            if param_schema.get("required", False) and param_name not in parameters:
                errors.append(f"Required parameter missing: {param_name}")
                continue

            if param_name in parameters:
                param_value = parameters[param_name]

                # Type validation
                if not self._validate_type(
                    param_value, param_schema.get("type", "string")
                ):
                    errors.append(
                        f"Parameter {param_name}: invalid type, expected {param_schema.get('type')}"
                    )
                    continue

                # String validations
                if param_schema.get("type") == "string":
                    if (
                        "max_length" in param_schema
                        and len(str(param_value)) > param_schema["max_length"]
                    ):
                        errors.append(
                            f"Parameter {param_name}: exceeds maximum length of {param_schema['max_length']}"
                        )

                    if "pattern" in param_schema:
                        if not re.match(param_schema["pattern"], str(param_value)):
                            errors.append(
                                f"Parameter {param_name}: does not match required pattern"
                            )

                # Numeric validations
                elif param_schema.get("type") in ["int", "float"]:
                    if "min" in param_schema and param_value < param_schema["min"]:
                        errors.append(
                            f"Parameter {param_name}: below minimum value of {param_schema['min']}"
                        )
                    if "max" in param_schema and param_value > param_schema["max"]:
                        errors.append(
                            f"Parameter {param_name}: exceeds maximum value of {param_schema['max']}"
                        )

                # List validations
                elif param_schema.get("type") == "list":
                    if (
                        "allowed_values" in param_schema
                        and param_value not in param_schema["allowed_values"]
                    ):
                        errors.append(
                            f"Parameter {param_name}: value not in allowed list: {param_schema['allowed_values']}"
                        )

        return len(errors) == 0, errors

    def _validate_type(self, value: Any, expected_type: str) -> bool:
        """Validate value type."""
        type_map = {
            "string": str,
            "int": int,
            "float": float,
            "bool": bool,
            "list": list,
            "dict": dict,
        }

        expected_python_type = type_map.get(expected_type, str)
        return isinstance(value, expected_python_type)


class CapabilityExecutor:
    """Main capability executor that orchestrates policy-driven operations."""

    def __init__(
        self,
        policy_engine: PolicyEngine,
        execution_factory: ExecutionBackendFactory,
        audit_logger: AuditLogger,
        inventory: Optional[Any] = None,
    ):
        """Initialize capability executor.

        Args:
            policy_engine: Policy engine for enforcement
            execution_factory: Factory for execution backends
            audit_logger: Audit logger for operations
            inventory: Fleet inventory for target information
        """
        self.policy_engine = policy_engine
        self.execution_factory = execution_factory
        self.audit_logger = audit_logger
        self.inventory = inventory
        self.validator = CapabilityValidator()

        # Register default capabilities
        self._register_default_capabilities()

    def _register_default_capabilities(self):
        """Register default capability implementations."""
        # This would typically be done through a registry pattern
        # For now, we'll implement inline
        pass

    async def execute_operation(
        self, operation: CapabilityOperation, dry_run: bool = False
    ) -> ExecutionResult:
        """Execute a capability operation with full policy enforcement.

        Args:
            operation: The capability operation to execute
            dry_run: Whether to perform a dry run (no actual execution)

        Returns:
            Execution result with comprehensive status and audit information
        """
        start_time = datetime.now(timezone.utc)
        correlation_id = operation.correlation_id

        logger.info(
            f"Starting capability operation: {operation.name} (ID: {correlation_id})"
        )

        try:
            # 1. Validate operation parameters
            is_valid, validation_errors = self.validator.validate_parameters(
                operation.capability, operation.parameters
            )

            if not is_valid:
                return self._create_error_result(
                    ExecutionStatus.VALIDATION_ERROR,
                    f"Parameter validation failed: {', '.join(validation_errors)}",
                    start_time,
                    operation,
                )

            # 2. Get target information
            target_info = await self._get_target_info(operation.target_id)
            if not target_info:
                return self._create_error_result(
                    ExecutionStatus.CONFIGURATION_ERROR,
                    f"Target not found: {operation.target_id}",
                    start_time,
                    operation,
                )

            # 3. Create policy context
            policy_context = self._create_policy_context(operation, target_info)

            # 4. Evaluate policy
            policy_result = await self.policy_engine.evaluate_operation(
                operation, policy_context
            )

            # 5. Handle policy decision
            if policy_result.decision == PolicyDecision.DENY:
                return self._create_error_result(
                    ExecutionStatus.PERMISSION_ERROR,
                    f"Policy denied operation: {policy_result.reason}",
                    start_time,
                    operation,
                    structured_error_details={
                        "policy_decision": policy_result.decision.value,
                        "reason": policy_result.reason,
                    },
                )

            if policy_result.decision == PolicyDecision.REQUIRE_APPROVAL:
                # In a real implementation, this would trigger an approval workflow
                return self._create_error_result(
                    ExecutionStatus.PERMISSION_ERROR,
                    f"Operation requires approval: {policy_result.reason}",
                    start_time,
                    operation,
                    structured_error_details={
                        "policy_decision": policy_result.decision.value,
                        "reason": policy_result.reason,
                    },
                )

            if policy_result.decision == PolicyDecision.DRY_RUN_ONLY and not dry_run:
                return self._create_error_result(
                    ExecutionStatus.PERMISSION_ERROR,
                    f"Operation restricted to dry-run only: {policy_result.reason}",
                    start_time,
                    operation,
                    structured_error_details={
                        "policy_decision": policy_result.decision.value,
                        "reason": policy_result.reason,
                    },
                )

            # 6. Execute the operation (if not dry run)
            if dry_run:
                result = await self._execute_dry_run(
                    operation, target_info, policy_result
                )
            else:
                result = await self._execute_capability(
                    operation, target_info, policy_result
                )

            # 7. Audit the operation
            await self._audit_operation(operation, result, policy_result)

            return result

        except Exception as e:
            logger.error(
                f"Unexpected error in capability execution: {e}", exc_info=True
            )
            return self._create_error_result(
                ExecutionStatus.EXECUTION_ERROR,
                f"Unexpected error: {str(e)}",
                start_time,
                operation,
            )

    async def _execute_capability(
        self,
        operation: CapabilityOperation,
        target_info: Dict[str, Any],
        policy_result: PolicyEvaluation,
    ) -> ExecutionResult:
        """Execute the actual capability operation."""

        start_time = datetime.now(timezone.utc)

        try:
            # Select appropriate execution backend
            backend = self.execution_factory.get_backend(
                target_info["connection"], operation.capability
            )

            if not backend:
                return self._create_error_result(
                    ExecutionStatus.CONFIGURATION_ERROR,
                    f"No suitable execution backend for target {operation.target_id}",
                    start_time,
                    operation,
                )

            # Execute the capability
            result = await backend.execute_capability(
                operation.capability, operation.parameters, target_info
            )

            # Enhance result with policy context
            result.metadata["policy_decision"] = policy_result.decision.value
            result.metadata["matched_policies"] = policy_result.matched_rules
            result.metadata["capability_operation_id"] = operation.id

            return result

        except Exception as e:
            return self._create_error_result(
                ExecutionStatus.EXECUTION_ERROR,
                f"Capability execution failed: {str(e)}",
                start_time,
                operation,
            )

    async def _execute_dry_run(
        self,
        operation: CapabilityOperation,
        target_info: Dict[str, Any],
        policy_result: PolicyEvaluation,
    ) -> ExecutionResult:
        """Execute a dry run of the capability operation."""

        start_time = datetime.now(timezone.utc)

        # Simulate operation execution
        dry_run_output = {
            "operation": operation.capability.value,
            "target": operation.target_id,
            "parameters": operation.parameters,
            "estimated_duration": "30 seconds",  # This would be calculated based on operation type
            "resources_required": ["cpu: 0.1", "memory: 64MB"],
            "risk_assessment": "Low",
            "rollback_plan": "Available",
        }

        duration = (datetime.now(timezone.utc) - start_time).total_seconds()

        return ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            success=True,
            severity=ExecutionSeverity.INFO,
            output=json.dumps(dry_run_output, indent=2),
            duration=duration,
            timestamp=start_time,
            correlation_id=operation.correlation_id,
            operation_id=operation.id,
            target_id=operation.target_id,
            capability=operation.capability.value,
            dry_run=True,
            metadata={
                "dry_run": True,
                "policy_decision": policy_result.decision.value,
                "matched_policies": policy_result.matched_rules,
                "capability_operation_id": operation.id,
            },
        )

    async def _get_target_info(self, target_id: str) -> Optional[Dict[str, Any]]:
        """Get target information from inventory."""
        if not self.inventory:
            # Return mock target info if no inventory available
            return {
                "id": target_id,
                "role": TargetRole.DEVELOPMENT,
                "connection": {"type": "local", "host": "localhost"},
                "metadata": {},
            }

        # In real implementation, look up target in inventory
        target = await self.inventory.get_target(target_id)
        if target:
            return {
                "id": target.id,
                "role": target.role,
                "connection": target.connection.dict(),
                "metadata": target.metadata,
            }

        return None

    def _create_policy_context(
        self, operation: CapabilityOperation, target_info: Dict[str, Any]
    ) -> PolicyContext:
        """Create policy evaluation context."""
        return PolicyContext(
            operation=operation,
            target_role=target_info["role"],
            target_metadata=target_info["metadata"],
            user_id=operation.requested_by,
            user_roles=[],  # Would be populated from user management system
            environment="production",  # Would be determined from target info
            current_time=datetime.now(timezone.utc),
        )

    async def _audit_operation(
        self,
        operation: CapabilityOperation,
        result: ExecutionResult,
        policy_result: PolicyEvaluation,
    ):
        """Audit the operation execution."""
        audit_entry = {
            "operation_id": operation.id,
            "operation_type": operation.capability.value,
            "target_id": operation.target_id,
            "requested_by": operation.requested_by,
            "result_status": result.status.value,
            "success": result.success,
            "duration": result.duration,
            "policy_decision": policy_result.decision.value,
            "matched_policies": policy_result.matched_rules,
            "correlation_id": operation.correlation_id,
            "dry_run": result.dry_run,
        }

        await self.audit_logger.log_event(
            event_type="capability_operation",
            event_data=audit_entry,
            severity=ExecutionSeverity.INFO
            if result.success
            else ExecutionSeverity.ERROR,
        )

    def _create_error_result(
        self,
        status: ExecutionStatus,
        error_message: str,
        start_time: datetime,
        operation: CapabilityOperation,
        structured_error_details: Optional[Dict[str, Any]] = None,
    ) -> ExecutionResult:
        """Create an error execution result."""

        duration = (datetime.now(timezone.utc) - start_time).total_seconds()

        structured_error = None
        if structured_error_details:
            from src.models.execution import StructuredError

            structured_error = StructuredError(
                code=status.value,
                message=error_message,
                details=structured_error_details,
                context={
                    "operation_id": operation.id,
                    "target_id": operation.target_id,
                },
            )

        return ExecutionResult(
            status=status,
            success=False,
            severity=ExecutionSeverity.ERROR,
            error=error_message,
            structured_error=structured_error,
            duration=duration,
            timestamp=start_time,
            correlation_id=operation.correlation_id,
            operation_id=operation.id,
            target_id=operation.target_id,
            capability=operation.capability.value,
            metadata={"capability_operation_id": operation.id},
        )


# Convenience functions for common operations


async def create_service_restart_operation(
    service_name: str, target_id: str, requested_by: str, timeout: int = 60
) -> CapabilityOperation:
    """Create a service restart operation."""
    return CapabilityOperation(
        name=f"restart_service_{service_name}",
        capability=OperationType.SERVICE_RESTART,
        description=f"Restart service {service_name}",
        parameters={"service_name": service_name, "timeout": timeout},
        target_id=target_id,
        target_role=TargetRole.DEVELOPMENT,  # Would be determined from target lookup
        timeout=timeout,
        requested_by=requested_by,
        request_reason=f"Service restart requested for {service_name}",
    )


async def create_container_operation(
    operation_type: OperationType,
    container_name: str,
    target_id: str,
    requested_by: str,
    **kwargs,
) -> CapabilityOperation:
    """Create a container operation."""
    parameters = {"container_name": container_name}
    parameters.update(kwargs)

    return CapabilityOperation(
        name=f"{operation_type.value}_{container_name}",
        capability=operation_type,
        description=f"{operation_type.value.replace('_', ' ').title()} container {container_name}",
        parameters=parameters,
        target_id=target_id,
        target_role=TargetRole.DEVELOPMENT,
        requested_by=requested_by,
        request_reason=f"{operation_type.value} operation for container {container_name}",
    )


async def create_backup_operation(
    operation_type: OperationType,
    backup_id: str,
    target_path: str,
    target_id: str,
    requested_by: str,
    **kwargs,
) -> CapabilityOperation:
    """Create a backup operation."""
    parameters = {"backup_id": backup_id, "target_path": target_path}
    parameters.update(kwargs)

    return CapabilityOperation(
        name=f"{operation_type.value}_{backup_id}",
        capability=operation_type,
        description=f"{operation_type.value.replace('_', ' ').title()} backup {backup_id}",
        parameters=parameters,
        target_id=target_id,
        target_role=TargetRole.PRODUCTION,
        timeout=1800,  # 30 minutes for backup operations
        requested_by=requested_by,
        request_reason=f"{operation_type.value} backup operation for {target_path}",
    )
