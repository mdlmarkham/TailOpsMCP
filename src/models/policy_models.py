"""
Policy Models for Policy-Driven Execution System

Defines comprehensive policy models for capability-driven operations with
deny-by-default security posture, role-based access control, and policy versioning.
"""

import json
from datetime import datetime
from datetime import timezone, timezone
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from uuid import uuid4
from dataclasses import dataclass
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

from pydantic import BaseModel, Field, validator


class PolicyVersion(str, Enum):
    """Policy configuration versions."""

    V1 = "v1"
    V2 = "v2"


class OperationType(str, Enum):
    """Types of operations that can be performed."""

    # System operations
    SERVICE_RESTART = "service_restart"
    SERVICE_STOP = "service_stop"
    SERVICE_START = "service_start"
    SERVICE_STATUS = "service_status"

    # Package operations
    PACKAGE_UPDATE = "package_update"
    PACKAGE_INSTALL = "package_install"
    PACKAGE_REMOVE = "package_remove"
    PACKAGE_LIST = "package_list"

    # Container operations
    CONTAINER_CREATE = "container_create"
    CONTAINER_DELETE = "container_delete"
    CONTAINER_START = "container_start"
    CONTAINER_STOP = "container_stop"
    CONTAINER_RESTART = "container_restart"
    CONTAINER_INSPECT = "container_inspect"

    # Stack operations
    STACK_DEPLOY = "stack_deploy"
    STACK_REMOVE = "stack_remove"
    STACK_UPDATE = "stack_update"
    STACK_ROLLBACK = "stack_rollback"

    # Backup/Restore operations
    BACKUP_CREATE = "backup_create"
    BACKUP_RESTORE = "backup_restore"
    BACKUP_LIST = "backup_list"
    BACKUP_DELETE = "backup_delete"

    # Snapshot operations
    SNAPSHOT_CREATE = "snapshot_create"
    SNAPSHOT_DELETE = "snapshot_delete"
    SNAPSHOT_RESTORE = "snapshot_restore"
    SNAPSHOT_LIST = "snapshot_list"

    # File operations
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    FILE_COPY = "file_copy"

    # Network operations
    NETWORK_SCAN = "network_scan"
    NETWORK_TEST = "network_test"
    NETWORK_STATUS = "network_status"


class TargetRole(str, Enum):
    """Target roles for policy inheritance."""

    GATEWAY = "gateway"
    PRODUCTION = "production"
    DEVELOPMENT = "development"
    STAGING = "staging"
    TESTING = "testing"
    MAINTENANCE = "maintenance"


class TimeRestriction(str, Enum):
    """Time-based restriction types."""

    BUSINESS_HOURS_ONLY = "business_hours_only"
    MAINTENANCE_WINDOW = "maintenance_window"
    HOLIDAY_RESTRICTION = "holiday_restriction"
    CUSTOM_SCHEDULE = "custom_schedule"


class PolicyDecision(str, Enum):
    """Policy evaluation decisions."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    DRY_RUN_ONLY = "dry_run_only"


@dataclass
class TimeConstraint:
    """Time-based constraint definition."""

    start_time: str = Field(..., description="Start time in HH:MM format")
    end_time: str = Field(..., description="End time in HH:MM format")
    days_of_week: List[int] = Field(
        ..., description="Days of week (0=Monday, 6=Sunday)"
    )
    timezone: str = Field(default="UTC", description="Timezone for the constraint")

    @validator("start_time", "end_time")
    def validate_time_format(cls, v):
        """Validate time format (HH:MM)."""
        if not isinstance(v, str) or len(v) != 5 or v[2] != ":":
            raise ValueError("Time must be in HH:MM format")
        try:
            hour, minute = map(int, v.split(":"))
            if not (0 <= hour <= 23 and 0 <= minute <= 59):
                raise ValueError("Invalid time values")
        except ValueError as e:
            raise ValueError(f"Invalid time format: {e}")
        return v

    @validator("days_of_week")
    def validate_days_of_week(cls, v):
        """Validate days of week are valid."""
        if not isinstance(v, list) or not all(isinstance(day, int) for day in v):
            raise ValueError("Days of week must be a list of integers")
        if not all(0 <= day <= 6 for day in v):
            raise ValueError("Days of week must be between 0-6")
        return v


@dataclass
class ParameterConstraint:
    """Parameter constraint definition."""

    type: str = Field(..., description="Parameter type (string, int, bool, list)")
    required: bool = Field(default=True, description="Whether parameter is required")
    min_value: Optional[Union[int, float]] = Field(
        None, description="Minimum value for numeric types"
    )
    max_value: Optional[Union[int, float]] = Field(
        None, description="Maximum value for numeric types"
    )
    max_length: Optional[int] = Field(
        None, description="Maximum length for string types"
    )
    pattern: Optional[str] = Field(
        None, description="Regex pattern for string validation"
    )
    allowed_values: Optional[List[str]] = Field(
        None, description="Allowed values for the parameter"
    )
    allowlist_source: Optional[str] = Field(
        None, description="Source for dynamic allowlist"
    )


class PolicyRule(BaseModel):
    """Individual policy rule definition."""

    id: str = Field(
        default_factory=lambda: str(uuid4()), description="Unique rule identifier"
    )
    name: str = Field(..., description="Human-readable rule name")
    description: str = Field(..., description="Rule description")
    enabled: bool = Field(default=True, description="Whether rule is enabled")

    # Operation specifications
    operations: List[OperationType] = Field(
        ..., description="Operations this rule applies to"
    )
    target_roles: List[TargetRole] = Field(
        ..., description="Target roles this rule applies to"
    )
    target_patterns: Optional[List[str]] = Field(
        None, description="Regex patterns for target matching"
    )

    # Access control
    allowed: bool = Field(default=True, description="Whether operations are allowed")
    requires_approval: bool = Field(
        default=False, description="Whether operations require approval"
    )
    approval_timeout: Optional[int] = Field(
        None, description="Approval timeout in minutes"
    )

    # Time-based restrictions
    time_restrictions: Optional[List[TimeConstraint]] = Field(
        None, description="Time-based constraints"
    )
    maintenance_windows_only: bool = Field(
        default=False, description="Only during maintenance windows"
    )

    # Parameter constraints
    parameter_constraints: Dict[str, ParameterConstraint] = Field(
        default_factory=dict, description="Parameter validation rules"
    )

    # Resource limits
    max_concurrent_operations: Optional[int] = Field(
        None, description="Maximum concurrent operations"
    )
    operation_timeout: Optional[int] = Field(
        default=300, description="Default operation timeout in seconds"
    )

    # Metadata
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Rule creation timestamp"
    )
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")
    created_by: Optional[str] = Field(None, description="Rule creator")
    version: str = Field(default="v1", description="Rule version")

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class PolicyConfig(BaseModel):
    """Comprehensive policy configuration."""

    # Policy metadata
    id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Policy configuration identifier",
    )
    name: str = Field(..., description="Policy configuration name")
    description: str = Field(..., description="Policy configuration description")
    version: PolicyVersion = Field(
        default=PolicyVersion.V2, description="Policy configuration version"
    )
    enabled: bool = Field(default=True, description="Whether policy is enabled")

    # Global settings
    deny_by_default: bool = Field(
        default=True, description="Deny operations not explicitly allowed"
    )
    enable_dry_run: bool = Field(default=True, description="Enable dry-run mode")
    require_approval_for_admin: bool = Field(
        default=True, description="Require approval for admin operations"
    )
    audit_all_operations: bool = Field(default=True, description="Audit all operations")

    # Inheritance settings
    enable_policy_inheritance: bool = Field(
        default=True, description="Enable policy inheritance"
    )
    parent_policies: List[str] = Field(
        default_factory=list, description="Parent policy IDs"
    )

    # Role-based policies
    role_policies: Dict[TargetRole, List[PolicyRule]] = Field(
        default_factory=dict, description="Policies by target role"
    )

    # Global policies (apply to all targets)
    global_policies: List[PolicyRule] = Field(
        default_factory=list, description="Global policy rules"
    )

    # Emergency policies
    emergency_policies: List[PolicyRule] = Field(
        default_factory=list, description="Emergency override policies"
    )

    # Maintenance windows
    maintenance_windows: List[Dict[str, Any]] = Field(
        default_factory=list, description="Scheduled maintenance windows"
    )

    # Policy lifecycle
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Configuration creation timestamp"
    )
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")
    created_by: Optional[str] = Field(None, description="Configuration creator")
    effective_from: Optional[datetime] = Field(
        None, description="Policy effective date"
    )
    expires_at: Optional[datetime] = Field(None, description="Policy expiration date")

    # Validation
    validation_errors: List[str] = Field(
        default_factory=list, description="Configuration validation errors"
    )
    validation_warnings: List[str] = Field(
        default_factory=list, description="Configuration validation warnings"
    )

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class PolicyEvaluation(BaseModel):
    """Policy evaluation result."""

    decision: PolicyDecision = Field(..., description="Policy decision")
    reason: str = Field(..., description="Reason for the decision")
    matched_rules: List[str] = Field(
        default_factory=list, description="IDs of matched policy rules"
    )
    required_approvals: List[str] = Field(
        default_factory=list, description="Required approval sources"
    )
    time_constraints: List[TimeConstraint] = Field(
        default_factory=list, description="Applicable time constraints"
    )
    parameter_validations: Dict[str, Any] = Field(
        default_factory=dict, description="Parameter validation results"
    )
    audit_context: Dict[str, Any] = Field(
        default_factory=dict, description="Audit context"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Evaluation timestamp"
    )


class PolicyHistory(BaseModel):
    """Policy change history."""

    id: str = Field(
        default_factory=lambda: str(uuid4()), description="History entry identifier"
    )
    policy_id: str = Field(..., description="Policy configuration ID")
    change_type: str = Field(
        ..., description="Type of change (create, update, delete, activate, deactivate)"
    )
    changes: Dict[str, Any] = Field(
        ..., description="Changed fields and their old/new values"
    )
    changed_by: str = Field(..., description="User who made the change")
    changed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Change timestamp"
    )
    change_reason: Optional[str] = Field(None, description="Reason for the change")
    rollback_data: Optional[Dict[str, Any]] = Field(
        None, description="Data needed for rollback"
    )

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class CapabilityOperation(BaseModel):
    """Capability-driven operation definition."""

    id: str = Field(
        default_factory=lambda: str(uuid4()), description="Operation identifier"
    )
    name: str = Field(..., description="Operation name")
    capability: OperationType = Field(..., description="Capability type")
    description: str = Field(..., description="Operation description")

    # Operation parameters
    parameters: Dict[str, Any] = Field(
        default_factory=dict, description="Operation parameters"
    )
    parameter_schema: Dict[str, Any] = Field(
        default_factory=dict, description="Parameter validation schema"
    )

    # Target specification
    target_id: str = Field(..., description="Target identifier")
    target_role: TargetRole = Field(..., description="Target role")

    # Execution context
    timeout: int = Field(default=300, description="Operation timeout in seconds")
    dry_run: bool = Field(default=False, description="Whether this is a dry run")
    priority: str = Field(default="normal", description="Operation priority")

    # Audit context
    requested_by: str = Field(..., description="User who requested the operation")
    request_reason: Optional[str] = Field(None, description="Reason for the operation")
    correlation_id: str = Field(
        default_factory=lambda: str(uuid4()), description="Correlation ID for tracking"
    )

    # Timestamps
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Operation creation timestamp"
    )
    scheduled_at: Optional[datetime] = Field(
        None, description="Scheduled execution time"
    )

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class PolicyValidationResult(BaseModel):
    """Policy configuration validation result."""

    is_valid: bool = Field(..., description="Whether configuration is valid")
    errors: List[str] = Field(default_factory=list, description="Validation errors")
    warnings: List[str] = Field(default_factory=list, description="Validation warnings")
    suggestions: List[str] = Field(
        default_factory=list, description="Improvement suggestions"
    )

    # Detailed validation results
    rule_validations: Dict[str, Dict[str, Any]] = Field(
        default_factory=dict, description="Individual rule validation results"
    )
    dependency_checks: Dict[str, Any] = Field(
        default_factory=dict, description="Dependency validation results"
    )
    conflict_checks: List[Dict[str, Any]] = Field(
        default_factory=list, description="Policy conflict results"
    )


class PolicyContext(BaseModel):
    """Context for policy evaluation."""

    # Operation context
    operation: CapabilityOperation = Field(..., description="Operation being evaluated")

    # Target context
    target_role: TargetRole = Field(..., description="Target role")
    target_metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Target metadata"
    )

    # User context
    user_id: str = Field(..., description="User requesting the operation")
    user_roles: List[str] = Field(
        default_factory=list, description="User roles and permissions"
    )

    # System context
    system_state: Dict[str, Any] = Field(
        default_factory=dict, description="Current system state"
    )
    maintenance_mode: bool = Field(
        default=False, description="Whether system is in maintenance mode"
    )
    emergency_mode: bool = Field(
        default=False, description="Whether emergency mode is active"
    )

    # Environment context
    environment: str = Field(default="production", description="Environment type")
    compliance_mode: str = Field(
        default="standard", description="Compliance mode level"
    )

    # Time context
    current_time: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Current time for evaluation"
    )

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class PolicyStatus(BaseModel):
    """Policy execution status and state tracking."""

    # Status information
    id: str = Field(
        default_factory=lambda: str(uuid4()), description="Status identifier"
    )
    policy_id: str = Field(..., description="Associated policy configuration ID")
    operation_id: Optional[str] = Field(None, description="Associated operation ID")

    # Current state
    status: PolicyDecision = Field(..., description="Current policy decision status")
    state: str = Field(..., description="Current execution state")
    phase: str = Field(default="initialization", description="Current execution phase")

    # Progress tracking
    progress_percentage: int = Field(
        default=0, ge=0, le=100, description="Execution progress percentage"
    )
    steps_completed: List[str] = Field(
        default_factory=list, description="Completed execution steps"
    )
    current_step: Optional[str] = Field(None, description="Currently executing step")

    # Results and outcomes
    result: Optional[Dict[str, Any]] = Field(None, description="Execution results")
    error_message: Optional[str] = Field(None, description="Error details if failed")
    warnings: List[str] = Field(default_factory=list, description="Execution warnings")

    # Timing information
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Execution start time"
    )
    completed_at: Optional[datetime] = Field(
        None, description="Execution completion time"
    )
    estimated_completion: Optional[datetime] = Field(
        None, description="Estimated completion time"
    )

    # Metadata
    execution_context: Dict[str, Any] = Field(
        default_factory=dict, description="Execution context data"
    )
    audit_trail: List[Dict[str, Any]] = Field(
        default_factory=list, description="Audit trail entries"
    )

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


# Utility functions for policy management


def create_default_policy_config() -> PolicyConfig:
    """Create a default policy configuration with sensible defaults."""

    # Default global allow rules for basic operations
    global_allow_rules = [
        PolicyRule(
            name="system_observation",
            description="Allow system status and monitoring operations",
            operations=[OperationType.SERVICE_STATUS, OperationType.NETWORK_STATUS],
            target_roles=[
                TargetRole.GATEWAY,
                TargetRole.PRODUCTION,
                TargetRole.DEVELOPMENT,
            ],
            allowed=True,
            requires_approval=False,
        ),
        PolicyRule(
            name="safe_container_operations",
            description="Allow safe container operations with restrictions",
            operations=[
                OperationType.CONTAINER_START,
                OperationType.CONTAINER_STOP,
                OperationType.CONTAINER_INSPECT,
            ],
            target_roles=[TargetRole.DEVELOPMENT, TargetRole.STAGING],
            allowed=True,
            requires_approval=False,
            parameter_constraints={
                "container_name": ParameterConstraint(
                    type="string",
                    required=True,
                    max_length=64,
                    pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$",
                )
            },
        ),
    ]

    # Default production rules (more restrictive)
    production_rules = [
        PolicyRule(
            name="production_service_management",
            description="Production service management with approval",
            operations=[
                OperationType.SERVICE_RESTART,
                OperationType.SERVICE_START,
                OperationType.SERVICE_STOP,
            ],
            target_roles=[TargetRole.PRODUCTION],
            allowed=True,
            requires_approval=True,
            approval_timeout=30,
            time_restrictions=[
                TimeConstraint(
                    start_time="08:00",
                    end_time="18:00",
                    days_of_week=list(range(5)),  # Monday to Friday
                    timezone="UTC",
                )
            ],
        )
    ]

    # Default development rules (more permissive)
    development_rules = [
        PolicyRule(
            name="development_full_access",
            description="Development environment full access",
            operations=[op for op in OperationType],
            target_roles=[TargetRole.DEVELOPMENT],
            allowed=True,
            requires_approval=False,
            operation_timeout=600,
        )
    ]

    role_policies = {
        TargetRole.PRODUCTION: production_rules,
        TargetRole.DEVELOPMENT: development_rules,
    }

    return PolicyConfig(
        name="Default Policy Configuration",
        description="Default deny-by-default policy with role-based access control",
        version=PolicyVersion.V2,
        deny_by_default=True,
        enable_dry_run=True,
        role_policies=role_policies,
        global_policies=global_allow_rules,
    )


def validate_policy_config(config: PolicyConfig) -> PolicyValidationResult:
    """Validate a policy configuration."""

    errors = []
    warnings = []
    suggestions = []
    rule_validations = {}

    # Basic configuration validation
    if not config.name.strip():
        errors.append("Policy name cannot be empty")

    if not config.global_policies and not config.role_policies:
        errors.append("Policy configuration must have at least one rule")

    # Validate rules
    all_rule_names = set()
    for role, rules in config.role_policies.items():
        for rule in rules:
            # Check for duplicate rule names
            if rule.name in all_rule_names:
                errors.append(f"Duplicate rule name: {rule.name}")
            all_rule_names.add(rule.name)

            # Validate rule configuration
            rule_validation = validate_policy_rule(rule)
            rule_validations[rule.id] = rule_validation

            if not rule_validation["valid"]:
                errors.extend(rule_validation["errors"])
            warnings.extend(rule_validation["warnings"])

    # Check for conflicts
    conflicts = check_policy_conflicts(config)
    if conflicts:
        warnings.extend([f"Potential conflict: {conflict}" for conflict in conflicts])

    # Generate suggestions
    if config.deny_by_default:
        suggestions.append(
            "Consider documenting the rationale for deny-by-default policy"
        )

    if not config.audit_all_operations:
        suggestions.append(
            "Consider enabling audit_all_operations for better compliance tracking"
        )

    return PolicyValidationResult(
        is_valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
        suggestions=suggestions,
        rule_validations=rule_validations,
    )


def validate_policy_rule(rule: PolicyRule) -> Dict[str, Any]:
    """Validate an individual policy rule."""

    errors = []
    warnings = []

    # Basic validation
    if not rule.name.strip():
        errors.append("Rule name cannot be empty")

    if not rule.operations:
        errors.append("Rule must specify at least one operation")

    if not rule.target_roles:
        errors.append("Rule must specify at least one target role")

    # Parameter constraint validation
    for param_name, constraint in rule.parameter_constraints.items():
        if not constraint.type:
            errors.append(f"Parameter {param_name} must have a type")

        if constraint.type in ["int", "float"]:
            if constraint.min_value is not None and constraint.max_value is not None:
                if constraint.min_value >= constraint.max_value:
                    errors.append(
                        f"Parameter {param_name} has invalid min/max value range"
                    )

    # Time constraint validation
    for time_constraint in rule.time_restrictions or []:
        if time_constraint.start_time >= time_constraint.end_time:
            errors.append("Time constraint has invalid start/end time range")

    return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings}


def check_policy_conflicts(config: PolicyConfig) -> List[str]:
    """Check for policy conflicts."""

    conflicts = []

    # Check for overlapping rules that might conflict
    all_rules = []
    all_rules.extend(config.global_policies)
    for rules in config.role_policies.values():
        all_rules.extend(rules)

    # Simple conflict detection (can be enhanced)
    for i, rule1 in enumerate(all_rules):
        for j, rule2 in enumerate(all_rules[i + 1 :], i + 1):
            # Check for exact same operations and roles with different allow settings
            if (
                set(rule1.operations) & set(rule2.operations)
                and set(rule1.target_roles) & set(rule2.target_roles)
                and rule1.allowed != rule2.allowed
            ):
                conflicts.append(
                    f"Rules '{rule1.name}' and '{rule2.name}' have conflicting allow settings"
                )

    return conflicts


def save_policy_config(config: PolicyConfig, file_path: Union[str, Path]) -> None:
    """Save policy configuration to file."""

    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    with open(file_path, "w") as f:
        if file_path.suffix.lower() in [".yaml", ".yml"]:
            if yaml:
                yaml.dump(config.dict(), f, default_flow_style=False, indent=2)
            else:
                raise ImportError("PyYAML not available for YAML file saving")
        else:
            json.dump(config.dict(), f, indent=2)


def load_policy_config(file_path: Union[str, Path]) -> PolicyConfig:
    """Load policy configuration from file."""

    file_path = Path(file_path)

    with open(file_path, "r") as f:
        if file_path.suffix.lower() in [".yaml", ".yml"]:
            if yaml:
                data = yaml.safe_load(f)
            else:
                raise ImportError("PyYAML not available for YAML file loading")
        else:
            data = json.load(f)

    return PolicyConfig(**data)
