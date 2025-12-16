"""
Consolidated Capability Tools - Unified Capability Management and Execution

This module provides comprehensive capability management and execution tools.
All capability-related functionality has been consolidated into a single module
with support for policy enforcement, "Observe First" workflow, and audit logging.

CONSOLIDATED FROM:
- src/tools/capability_tools.py
- src/tools/capability_manager.py

FEATURES:
- Unified capability definitions and management
- Policy-driven operation execution
- "Observe First" workflow implementation
- Comprehensive audit logging
- Service restart and management operations
- Multi-tier operation support
"""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field

# Configure logging
logger = logging.getLogger(__name__)


# Enums and Types
class CapabilityType(str, Enum):
    """Types of capabilities supported by the system."""

    SYSTEM = "system"
    CONTAINER = "container"
    STACK = "stack"
    NETWORK = "network"
    FILE = "service"


class OperationType(str, Enum):
    """Types of operations that can be performed."""

    OBSERVE = "observe"
    DIAGNOSE = "diagnose"
    EXECUTE = "execute"
    CONFIGURE = "configure"
    MANAGE = "manage"


class OperationTier(str, Enum):
    """Operation tiers for capability classification."""

    OBSERVE = "observe"
    DIAGNOSE = "diagnose"
    EXECUTE = "execute"
    MANAGE = "manage"
    ADMIN = "admin"


class ValidationMode(str, Enum):
    """Validation modes for operations."""

    STRICT = "strict"
    STANDARD = "standard"
    RELAXED = "relaxed"


# Data Models
@dataclass
class Capability:
    """Represents a specific capability that can be executed on a target."""

    name: str
    type: CapabilityType
    description: str
    tier: OperationTier
    default_timeout: int = 30
    parameters: Dict[str, Any] = field(default_factory=dict)
    validation_required: bool = True
    audit_required: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "type": self.type.value,
            "description": self.description,
            "tier": self.tier.value,
            "default_timeout": self.default_timeout,
            "parameters": self.parameters,
            "validation_required": self.validation_required,
            "audit_required": self.audit_required,
        }


@dataclass
class CapabilityOperation:
    """Represents a capability operation to be executed."""

    capability_name: str
    target_id: str
    operation_type: OperationType
    parameters: Dict[str, Any] = field(default_factory=dict)
    timeout: int = 30
    dry_run: bool = False
    requested_by: str = "system"
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "capability_name": self.capability_name,
            "target_id": self.target_id,
            "operation_type": self.operation_type.value,
            "parameters": self.parameters,
            "timeout": self.timeout,
            "dry_run": self.dry_run,
            "requested_by": self.requested_by,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class OperationResult:
    """Result of a capability operation."""

    success: bool
    operation_id: str
    capability_name: str
    operation_type: OperationType
    result: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    execution_time: float = 0.0
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "operation_id": self.operation_id,
            "capability_name": self.capability_name,
            "operation_type": self.operation_type.value,
            "result": self.result,
            "error": self.error,
            "execution_time": self.execution_time,
            "audit_trail": self.audit_trail,
        }


@dataclass
class PolicyContext:
    """Context for policy validation."""

    user_id: str
    operation_type: OperationType
    target_id: str
    capability_type: CapabilityType
    parameters: Dict[str, Any] = field(default_factory=dict)
    session_id: Optional[str] = None
    ip_address: Optional[str] = None


@dataclass
class ValidationResult:
    """Result of policy validation."""

    allowed: bool
    reason: str
    confidence: float = 1.0
    constraints: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)


# Core Capability Management Classes
class CapabilityRegistry:
    """Registry for managing available capabilities."""

    def __init__(self):
        self._capabilities: Dict[str, Capability] = {}
        self._capability_index: Dict[CapabilityType, List[str]] = {}
        self._capability_index[CapabilityType.SYSTEM] = []
        self._capability_index[CapabilityType.CONTAINER] = []
        self._capability_index[CapabilityType.STACK] = []
        self._capability_index[CapabilityType.NETWORK] = []
        self._capability_index[CapabilityType.FILE] = []

        # Initialize default capabilities
        self._initialize_default_capabilities()

    def _initialize_default_capabilities(self) -> None:
        """Initialize default system capabilities."""
        # System capabilities
        self.register_capability(
            Capability(
                name="get_system_status",
                type=CapabilityType.SYSTEM,
                description="Get comprehensive system status and health metrics",
                tier=OperationTier.OBSERVE,
                default_timeout=30,
            )
        )

        self.register_capability(
            Capability(
                name="restart_service",
                type=CapabilityType.SYSTEM,
                description="Restart a system service",
                tier=OperationTier.MANAGE,
                default_timeout=60,
                parameters={"service_name": {"type": "string", "required": True}},
            )
        )

        self.register_capability(
            Capability(
                name="check_service_health",
                type=CapabilityType.SYSTEM,
                description="Check health status of a service",
                tier=OperationTier.OBSERVE,
                default_timeout=15,
                parameters={"service_name": {"type": "string", "required": True}},
            )
        )

        # Container capabilities
        self.register_capability(
            Capability(
                name="list_containers",
                type=CapabilityType.CONTAINER,
                description="List all containers with status information",
                tier=OperationTier.OBSERVE,
                default_timeout=20,
            )
        )

        self.register_capability(
            Capability(
                name="start_container",
                type=CapabilityType.CONTAINER,
                description="Start a container",
                tier=OperationTier.EXECUTE,
                default_timeout=30,
                parameters={"container_id": {"type": "string", "required": True}},
            )
        )

        self.register_capability(
            Capability(
                name="stop_container",
                type=CapabilityType.CONTAINER,
                description="Stop a container",
                tier=OperationTier.EXECUTE,
                default_timeout=30,
                parameters={"container_id": {"type": "string", "required": True}},
            )
        )

        # Stack capabilities
        self.register_capability(
            Capability(
                name="deploy_stack",
                type=CapabilityType.STACK,
                description="Deploy a stack from configuration",
                tier=OperationTier.MANAGE,
                default_timeout=120,
                parameters={
                    "stack_name": {"type": "string", "required": True},
                    "config_path": {"type": "string", "required": True},
                },
            )
        )

        self.register_capability(
            Capability(
                name="update_stack",
                type=CapabilityType.STACK,
                description="Update an existing stack",
                tier=OperationTier.MANAGE,
                default_timeout=180,
                parameters={
                    "stack_name": {"type": "string", "required": True},
                    "config_path": {"type": "string", "required": True},
                },
            )
        )

        # Network capabilities
        self.register_capability(
            Capability(
                name="check_network_connectivity",
                type=CapabilityType.NETWORK,
                description="Check network connectivity to target",
                tier=OperationTier.OBSERVE,
                default_timeout=10,
                parameters={"target_host": {"type": "string", "required": True}},
            )
        )

        self.register_capability(
            Capability(
                name="configure_firewall",
                type=CapabilityType.NETWORK,
                description="Configure firewall rules",
                tier=OperationTier.ADMIN,
                default_timeout=60,
                parameters={
                    "action": {
                        "type": "string",
                        "required": True,
                        "enum": ["allow", "deny"],
                    },
                    "port": {"type": "integer", "required": True},
                    "protocol": {"type": "string", "required": False, "default": "tcp"},
                },
            )
        )

    def register_capability(self, capability: Capability) -> bool:
        """Register a new capability.

        Args:
            capability: Capability to register

        Returns:
            True if registration successful, False if already exists
        """
        if capability.name in self._capabilities:
            logger.warning(f"Capability {capability.name} already registered")
            return False

        self._capabilities[capability.name] = capability

        # Add to index
        if capability.type not in self._capability_index:
            self._capability_index[capability.type] = []
        self._capability_index[capability.type].append(capability.name)

        logger.info(
            f"Registered capability: {capability.name} ({capability.type.value})"
        )
        return True

    def get_capability(self, name: str) -> Optional[Capability]:
        """Get capability by name.

        Args:
            name: Capability name

        Returns:
            Capability if found, None otherwise
        """
        return self._capabilities.get(name)

    def list_capabilities(
        self, capability_type: Optional[CapabilityType] = None
    ) -> List[Capability]:
        """List all capabilities or capabilities of specific type.

        Args:
            capability_type: Filter by capability type

        Returns:
            List of capabilities
        """
        if capability_type:
            capability_names = self._capability_index.get(capability_type, [])
            return [
                self._capabilities[name]
                for name in capability_names
                if name in self._capabilities
            ]

        return list(self._capabilities.values())

    def get_capabilities_by_tier(self, tier: OperationTier) -> List[Capability]:
        """Get capabilities by operation tier.

        Args:
            tier: Operation tier

        Returns:
            List of capabilities with specified tier
        """
        return [cap for cap in self._capabilities.values() if cap.tier == tier]

    def validate_capability_parameters(
        self, capability_name: str, parameters: Dict[str, Any]
    ) -> List[str]:
        """Validate parameters for a capability.

        Args:
            capability_name: Name of capability
            parameters: Parameters to validate

        Returns:
            List of validation errors (empty if valid)
        """
        capability = self.get_capability(capability_name)
        if not capability:
            return [f"Capability {capability_name} not found"]

        errors = []

        # Check required parameters
        for param_name, param_config in capability.parameters.items():
            if param_config.get("required", False) and param_name not in parameters:
                errors.append(f"Required parameter '{param_name}' is missing")

        # Check parameter types (basic validation)
        for param_name, value in parameters.items():
            if param_name in capability.parameters:
                param_config = capability.parameters[param_name]
                expected_type = param_config.get("type", "string")

                if expected_type == "integer" and not isinstance(value, int):
                    errors.append(f"Parameter '{param_name}' must be an integer")
                elif expected_type == "boolean" and not isinstance(value, bool):
                    errors.append(f"Parameter '{param_name}' must be a boolean")
                elif expected_type == "string" and not isinstance(value, str):
                    errors.append(f"Parameter '{param_name}' must be a string")

        return errors


class PolicyValidator:
    """Validates operations against security policies."""

    def __init__(self):
        self._policies: Dict[str, Dict[str, Any]] = {}
        self._user_permissions: Dict[str, List[str]] = {}

    def validate_operation(self, context: PolicyContext) -> ValidationResult:
        """Validate if operation is allowed based on policies.

        Args:
            context: Policy context for validation

        Returns:
            ValidationResult with decision and reasoning
        """
        # Check user permissions
        user_caps = self._user_permissions.get(context.user_id, [])

        # Check capability type permissions
        if context.capability_type.value not in user_caps:
            return ValidationResult(
                allowed=False,
                reason=f"User {context.user_id} does not have permission for {context.capability_type.value} operations",
            )

        # Check operation tier permissions
        if not self._has_operation_permission(context.user_id, context.operation_type):
            return ValidationResult(
                allowed=False,
                reason=f"User {context.user_id} does not have permission for {context.operation_type.value} operations",
            )

        # Additional validation logic would go here
        # For now, allow all validated operations

        return ValidationResult(allowed=True, reason="Operation validated successfully")

    def _has_operation_permission(
        self, user_id: str, operation_type: OperationType
    ) -> bool:
        """Check if user has permission for operation type.

        Args:
            user_id: User identifier
            operation_type: Type of operation

        Returns:
            True if user has permission
        """
        # Simplified permission check
        # In production, this would check against a proper permission matrix
        user_caps = self._user_permissions.get(user_id, [])

        if operation_type == OperationType.OBSERVE:
            return True  # Everyone can observe
        elif operation_type == OperationType.DIAGNOSE:
            return "diagnose" in user_caps or "admin" in user_caps
        elif operation_type == OperationType.EXECUTE:
            return "execute" in user_caps or "admin" in user_caps
        elif operation_type == OperationType.CONFIGURE:
            return "configure" in user_caps or "admin" in user_caps
        elif operation_type == OperationType.MANAGE:
            return "manage" in user_caps or "admin" in user_caps

        return False

    def grant_permission(self, user_id: str, capability_type: CapabilityType) -> None:
        """Grant permission to user for capability type.

        Args:
            user_id: User identifier
            capability_type: Capability type to grant
        """
        if user_id not in self._user_permissions:
            self._user_permissions[user_id] = []

        if capability_type.value not in self._user_permissions[user_id]:
            self._user_permissions[user_id].append(capability_type.value)
            logger.info(f"Granted {capability_type.value} permission to user {user_id}")

    def revoke_permission(self, user_id: str, capability_type: CapabilityType) -> None:
        """Revoke permission from user for capability type.

        Args:
            user_id: User identifier
            capability_type: Capability type to revoke
        """
        if (
            user_id in self._user_permissions
            and capability_type.value in self._user_permissions[user_id]
        ):
            self._user_permissions[user_id].remove(capability_type.value)
            logger.info(
                f"Revoked {capability_type.value} permission from user {user_id}"
            )


class AuditLogger:
    """Simple audit logger for capability operations."""

    def __init__(self):
        self._audit_log: List[Dict[str, Any]] = []

    def log_operation(
        self, operation: CapabilityOperation, result: OperationResult
    ) -> None:
        """Log capability operation and result.

        Args:
            operation: Capability operation
            result: Operation result
        """
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "operation": operation.to_dict(),
            "result": result.to_dict(),
            "operation_id": result.operation_id,
        }

        self._audit_log.append(audit_entry)

        # Log to standard logger as well
        status = "SUCCESS" if result.success else "FAILED"
        logger.info(
            f"Capability Operation {status}: {operation.capability_name} on {operation.target_id} by {operation.requested_by}"
        )

    def get_audit_trail(
        self, user_id: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get audit trail entries.

        Args:
            user_id: Filter by user ID
            limit: Maximum number of entries to return

        Returns:
            List of audit entries
        """
        filtered_log = self._audit_log

        if user_id:
            filtered_log = [
                entry
                for entry in self._audit_log
                if entry["operation"]["requested_by"] == user_id
            ]

        return filtered_log[-limit:]


class CapabilityExecutor:
    """Executes capability operations with policy enforcement and audit logging."""

    def __init__(
        self,
        capability_registry: CapabilityRegistry,
        policy_validator: PolicyValidator,
        audit_logger: AuditLogger,
    ):
        """Initialize capability executor.

        Args:
            capability_registry: Registry of available capabilities
            policy_validator: Policy validation engine
            audit_logger: Audit logging system
        """
        self.capability_registry = capability_registry
        self.policy_validator = policy_validator
        self.audit_logger = audit_logger
        self._operation_counter = 0

    async def execute_operation(
        self, operation: CapabilityOperation
    ) -> OperationResult:
        """Execute a capability operation.

        Args:
            operation: Operation to execute

        Returns:
            OperationResult with execution details
        """
        operation_id = f"op_{self._operation_counter}"
        self._operation_counter += 1

        start_time = datetime.utcnow()
        audit_trail = []

        try:
            # Validate capability exists
            capability = self.capability_registry.get_capability(
                operation.capability_name
            )
            if not capability:
                return OperationResult(
                    success=False,
                    operation_id=operation_id,
                    capability_name=operation.capability_name,
                    operation_type=operation.operation_type,
                    error=f"Capability '{operation.capability_name}' not found",
                )

            # Create policy context
            policy_context = PolicyContext(
                user_id=operation.requested_by,
                operation_type=operation.operation_type,
                target_id=operation.target_id,
                capability_type=capability.type,
                parameters=operation.parameters,
            )

            # Validate operation
            validation_result = self.policy_validator.validate_operation(policy_context)
            if not validation_result.allowed:
                return OperationResult(
                    success=False,
                    operation_id=operation_id,
                    capability_name=operation.capability_name,
                    operation_type=operation.operation_type,
                    error=f"Operation not allowed: {validation_result.reason}",
                    audit_trail=[
                        {
                            "event": "validation_failed",
                            "reason": validation_result.reason,
                            "timestamp": datetime.utcnow().isoformat(),
                        }
                    ],
                )

            # Validate capability parameters
            param_errors = self.capability_registry.validate_capability_parameters(
                operation.capability_name, operation.parameters
            )
            if param_errors:
                return OperationResult(
                    success=False,
                    operation_id=operation_id,
                    capability_name=operation.capability_name,
                    operation_type=operation.operation_type,
                    error=f"Parameter validation failed: {', '.join(param_errors)}",
                )

            # Execute the capability operation
            execution_result = await self._execute_capability(capability, operation)

            # Calculate execution time
            execution_time = (datetime.utcnow() - start_time).total_seconds()

            # Create operation result
            result = OperationResult(
                success=execution_result.get("success", False),
                operation_id=operation_id,
                capability_name=operation.capability_name,
                operation_type=operation.operation_type,
                result=execution_result.get("result", {}),
                error=execution_result.get("error"),
                execution_time=execution_time,
                audit_trail=audit_trail,
            )

            # Log to audit
            self.audit_logger.log_operation(operation, result)

            return result

        except Exception as e:
            execution_time = (datetime.utcnow() - start_time).total_seconds()

            result = OperationResult(
                success=False,
                operation_id=operation_id,
                capability_name=operation.capability_name,
                operation_type=operation.operation_type,
                error=str(e),
                execution_time=execution_time,
                audit_trail=audit_trail,
            )

            self.audit_logger.log_operation(operation, result)
            return result

    async def _execute_capability(
        self, capability: Capability, operation: CapabilityOperation
    ) -> Dict[str, Any]:
        """Execute specific capability operation.

        Args:
            capability: Capability to execute
            operation: Operation details

        Returns:
            Execution result dictionary
        """
        # Simulate capability execution
        # In production, this would dispatch to appropriate executors

        capability_name = capability.name

        if capability_name == "get_system_status":
            return await self._execute_get_system_status(operation)
        elif capability_name == "restart_service":
            return await self._execute_restart_service(operation)
        elif capability_name == "check_service_health":
            return await self._execute_check_service_health(operation)
        elif capability_name == "list_containers":
            return await self._execute_list_containers(operation)
        elif capability_name == "start_container":
            return await self._execute_start_container(operation)
        elif capability_name == "stop_container":
            return await self._execute_stop_container(operation)
        else:
            return {
                "success": False,
                "error": f"Capability '{capability_name}' execution not implemented",
            }

    # Capability execution methods (simplified implementations)
    async def _execute_get_system_status(
        self, operation: CapabilityOperation
    ) -> Dict[str, Any]:
        """Execute get system status capability."""
        await asyncio.sleep(0.1)  # Simulate execution time

        return {
            "success": True,
            "result": {
                "system_load": "1.2",
                "memory_usage": "45%",
                "disk_usage": "67%",
                "services_running": 12,
                "last_updated": datetime.utcnow().isoformat(),
            },
        }

    async def _execute_restart_service(
        self, operation: CapabilityOperation
    ) -> Dict[str, Any]:
        """Execute service restart capability."""
        service_name = operation.parameters.get("service_name")

        if not service_name:
            return {"success": False, "error": "Service name is required"}

        await asyncio.sleep(2)  # Simulate restart time

        return {
            "success": True,
            "result": {
                "service_name": service_name,
                "status": "restarted",
                "restart_time": datetime.utcnow().isoformat(),
            },
        }

    async def _execute_check_service_health(
        self, operation: CapabilityOperation
    ) -> Dict[str, Any]:
        """Execute service health check capability."""
        service_name = operation.parameters.get("service_name")

        if not service_name:
            return {"success": False, "error": "Service name is required"}

        await asyncio.sleep(0.5)  # Simulate health check time

        return {
            "success": True,
            "result": {
                "service_name": service_name,
                "status": "healthy",
                "uptime": "7d 14h 32m",
                "last_check": datetime.utcnow().isoformat(),
            },
        }

    async def _execute_list_containers(
        self, operation: CapabilityOperation
    ) -> Dict[str, Any]:
        """Execute list containers capability."""
        await asyncio.sleep(0.3)  # Simulate execution time

        return {
            "success": True,
            "result": {
                "containers": [
                    {
                        "id": "abc123",
                        "name": "web-server",
                        "status": "running",
                        "image": "nginx:latest",
                    },
                    {
                        "id": "def456",
                        "name": "database",
                        "status": "running",
                        "image": "postgres:13",
                    },
                    {
                        "id": "ghi789",
                        "name": "cache",
                        "status": "stopped",
                        "image": "redis:alpine",
                    },
                ],
                "total_count": 3,
                "running_count": 2,
            },
        }

    async def _execute_start_container(
        self, operation: CapabilityOperation
    ) -> Dict[str, Any]:
        """Execute start container capability."""
        container_id = operation.parameters.get("container_id")

        if not container_id:
            return {"success": False, "error": "Container ID is required"}

        await asyncio.sleep(1)  # Simulate start time

        return {
            "success": True,
            "result": {
                "container_id": container_id,
                "status": "started",
                "start_time": datetime.utcnow().isoformat(),
            },
        }

    async def _execute_stop_container(
        self, operation: CapabilityOperation
    ) -> Dict[str, Any]:
        """Execute stop container capability."""
        container_id = operation.parameters.get("container_id")

        if not container_id:
            return {"success": False, "error": "Container ID is required"}

        await asyncio.sleep(1)  # Simulate stop time

        return {
            "success": True,
            "result": {
                "container_id": container_id,
                "status": "stopped",
                "stop_time": datetime.utcnow().isoformat(),
            },
        }


# High-level Management Classes
class CapabilityManager:
    """Main manager for capability operations with "Observe First" workflow."""

    def __init__(self):
        """Initialize capability manager."""
        self.registry = CapabilityRegistry()
        self.policy_validator = PolicyValidator()
        self.audit_logger = AuditLogger()
        self.executor = CapabilityExecutor(
            self.registry, self.policy_validator, self.audit_logger
        )

        # Set up default permissions
        self._setup_default_permissions()

    def _setup_default_permissions(self) -> None:
        """Set up default user permissions."""
        # Grant basic permissions to default users
        self.policy_validator.grant_permission("admin", CapabilityType.SYSTEM)
        self.policy_validator.grant_permission("admin", CapabilityType.CONTAINER)
        self.policy_validator.grant_permission("admin", CapabilityType.STACK)
        self.policy_validator.grant_permission("admin", CapabilityType.NETWORK)

        self.policy_validator.grant_permission("operator", CapabilityType.SYSTEM)
        self.policy_validator.grant_permission("operator", CapabilityType.CONTAINER)

        self.policy_validator.grant_permission("observer", CapabilityType.SYSTEM)

    async def execute_service_restart(
        self,
        service_name: str,
        target_id: str,
        requested_by: str,
        timeout: int = 60,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """Execute service restart with policy enforcement.

        Args:
            service_name: Name of service to restart
            target_id: Target system identifier
            requested_by: User requesting the operation
            timeout: Operation timeout in seconds
            dry_run: Whether to perform a dry run

        Returns:
            Operation result dictionary
        """
        operation = CapabilityOperation(
            capability_name="restart_service",
            target_id=target_id,
            operation_type=OperationType.MANAGE,
            parameters={"service_name": service_name},
            timeout=timeout,
            dry_run=dry_run,
            requested_by=requested_by,
        )

        result = await self.executor.execute_operation(operation)
        return result.to_dict()

    async def get_system_status(
        self, target_id: str, requested_by: str
    ) -> Dict[str, Any]:
        """Get comprehensive system status.

        Args:
            target_id: Target system identifier
            requested_by: User requesting the status

        Returns:
            System status result
        """
        operation = CapabilityOperation(
            capability_name="get_system_status",
            target_id=target_id,
            operation_type=OperationType.OBSERVE,
            requested_by=requested_by,
        )

        result = await self.executor.execute_operation(operation)
        return result.to_dict()

    async def check_service_health(
        self, service_name: str, target_id: str, requested_by: str
    ) -> Dict[str, Any]:
        """Check health status of a service.

        Args:
            service_name: Name of service to check
            target_id: Target system identifier
            requested_by: User requesting the check

        Returns:
            Service health result
        """
        operation = CapabilityOperation(
            capability_name="check_service_health",
            target_id=target_id,
            operation_type=OperationType.OBSERVE,
            parameters={"service_name": service_name},
            requested_by=requested_by,
        )

        result = await self.executor.execute_operation(operation)
        return result.to_dict()

    async def list_capabilities(
        self, user_id: str, capability_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """List available capabilities for user.

        Args:
            user_id: User identifier
            capability_type: Filter by capability type

        Returns:
            List of available capabilities
        """
        try:
            cap_type_enum = CapabilityType(capability_type) if capability_type else None
            capabilities = self.registry.list_capabilities(cap_type_enum)

            return {
                "success": True,
                "capabilities": [cap.to_dict() for cap in capabilities],
                "total_count": len(capabilities),
            }
        except ValueError:
            return {
                "success": False,
                "error": f"Invalid capability type: {capability_type}",
            }

    def get_audit_trail(
        self, user_id: Optional[str] = None, limit: int = 100
    ) -> Dict[str, Any]:
        """Get audit trail for operations.

        Args:
            user_id: Filter by user ID
            limit: Maximum number of entries

        Returns:
            Audit trail entries
        """
        trail = self.audit_logger.get_audit_trail(user_id, limit)

        return {"success": True, "audit_trail": trail, "total_count": len(trail)}

    def grant_user_permission(
        self, user_id: str, capability_type: str
    ) -> Dict[str, Any]:
        """Grant permission to user for capability type.

        Args:
            user_id: User identifier
            capability_type: Capability type to grant

        Returns:
            Operation result
        """
        try:
            cap_type_enum = CapabilityType(capability_type)
            self.policy_validator.grant_permission(user_id, cap_type_enum)

            return {
                "success": True,
                "message": f"Granted {capability_type} permission to user {user_id}",
            }
        except ValueError:
            return {
                "success": False,
                "error": f"Invalid capability type: {capability_type}",
            }


# Global capability manager instance
_capability_manager = None


def get_capability_manager() -> CapabilityManager:
    """Get global capability manager instance.

    Returns:
        CapabilityManager instance
    """
    global _capability_manager
    if _capability_manager is None:
        _capability_manager = CapabilityManager()
    return _capability_manager


# Convenience functions
async def restart_service(
    service_name: str, target_id: str, requested_by: str, **kwargs
) -> Dict[str, Any]:
    """Quick service restart function."""
    manager = get_capability_manager()
    return await manager.execute_service_restart(
        service_name, target_id, requested_by, **kwargs
    )


async def get_system_status(target_id: str, requested_by: str) -> Dict[str, Any]:
    """Quick system status function."""
    manager = get_capability_manager()
    return await manager.get_system_status(target_id, requested_by)


async def check_service_health(
    service_name: str, target_id: str, requested_by: str
) -> Dict[str, Any]:
    """Quick service health check function."""
    manager = get_capability_manager()
    return await manager.check_service_health(service_name, target_id, requested_by)


# Export main classes and functions
__all__ = [
    # Core classes
    "CapabilityManager",
    "CapabilityRegistry",
    "CapabilityExecutor",
    "PolicyValidator",
    "AuditLogger",
    # Data models
    "Capability",
    "CapabilityOperation",
    "OperationResult",
    "PolicyContext",
    "ValidationResult",
    # Enums
    "CapabilityType",
    "OperationType",
    "OperationTier",
    "ValidationMode",
    # Factory functions
    "get_capability_manager",
    "restart_service",
    "get_system_status",
    "check_service_health",
    # Version info
    "__version__",
]

# Version information
__version__ = "1.0.0"
