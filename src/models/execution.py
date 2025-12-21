"""
Execution models for standardized execution results, logging, and auditing.
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class ExecutionStatus(str, Enum):
    """Execution result status with comprehensive error types."""

    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"
    AUTHENTICATION_ERROR = "authentication_error"
    PERMISSION_ERROR = "permission_error"
    VALIDATION_ERROR = "validation_error"
    RESOURCE_ERROR = "resource_error"
    CONFIGURATION_ERROR = "configuration_error"
    NETWORK_ERROR = "network_error"
    EXECUTION_ERROR = "execution_error"


class ExecutionSeverity(str, Enum):
    """Execution severity levels for logging and monitoring."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class StructuredError(BaseModel):
    """Structured error model for detailed error reporting."""

    code: str = Field(..., description="Error code identifier")
    message: str = Field(..., description="Human-readable error message")
    details: Optional[Dict[str, Any]] = Field(
        None, description="Additional error details"
    )
    context: Optional[Dict[str, Any]] = Field(
        None, description="Error context information"
    )
    timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="Error timestamp"
    )

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class ExecutionResult(BaseModel):
    """Comprehensive standardized execution result model."""

    # Core execution status
    status: ExecutionStatus = Field(..., description="Execution status")
    success: bool = Field(..., description="Whether execution was successful")
    severity: ExecutionSeverity = Field(
        ExecutionSeverity.INFO, description="Execution severity level"
    )

    # Execution details
    exit_code: Optional[int] = Field(None, description="Process exit code")
    output: Optional[str] = Field(None, description="Standard output")
    error: Optional[str] = Field(None, description="Error output")
    structured_error: Optional[StructuredError] = Field(
        None, description="Structured error details"
    )
    duration: float = Field(..., description="Execution duration in seconds")

    # Timing and identification
    timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="Execution timestamp"
    )
    correlation_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Correlation ID for traceability",
    )
    operation_id: Optional[str] = Field(None, description="Operation identifier")

    # Target and capability context
    target_id: Optional[str] = Field(None, description="Target identifier")
    capability: Optional[str] = Field(None, description="Capability being executed")
    executor_type: Optional[str] = Field(None, description="Type of executor used")

    # Audit and monitoring
    dry_run: bool = Field(False, description="Whether this was a dry run")
    audit_trail: List[Dict[str, Any]] = Field(
        default_factory=list, description="Audit trail entries"
    )
    metrics: Dict[str, Union[int, float, str]] = Field(
        default_factory=dict, description="Execution metrics"
    )

    # Additional metadata
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Additional metadata"
    )

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}

    @property
    def message(self) -> Optional[str]:
        """Backward-compatible message alias."""
        # Prefer structured_error.message if present, else error or output
        if self.structured_error and self.structured_error.message:
            return self.structured_error.message
        if self.error:
            return self.error
        return self.output

    @property
    def data(self) -> Dict[str, Any]:
        """Backward-compatible data alias (metrics + metadata)."""
        return {**self.metrics, **({} if self.metadata is None else self.metadata)}


class OperationResult:
    """Result of an operation."""

    def __init__(self, success: bool, message: str = "", data: Any = None):
        self.success = success
        self.message = message
        self.data = data
        # Backwards-compatible aliases used across the codebase
        self.error = message
        self.output = None


class CapabilityExecution:
    """Capability execution result."""

    def __init__(self, capability: str, result: OperationResult):
        self.capability = capability
        self.result = result

    def add_audit_entry(self, entry: Dict[str, Any]) -> None:
        """Add an entry to the audit trail."""
        self.audit_trail.append({"timestamp": datetime.utcnow().isoformat(), **entry})

    def add_metric(self, key: str, value: Union[int, float, str]) -> None:
        """Add a metric to the execution result."""
        self.metrics[key] = value

    def set_structured_error(
        self,
        code: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Set a structured error on the execution result."""
        self.structured_error = StructuredError(
            code=code, message=message, details=details, context=context
        )


class ExecutionRequest(BaseModel):
    """Enhanced execution request model with comprehensive context."""

    # Core execution parameters
    command: str = Field(..., description="Command to execute")
    executor_type: str = Field(..., description="Type of executor to use")
    target_id: Optional[str] = Field(None, description="Target identifier")
    capability: Optional[str] = Field(None, description="Capability being executed")

    # Execution control
    timeout: int = Field(30, description="Execution timeout in seconds")
    parameters: Dict[str, Any] = Field(
        default_factory=dict, description="Execution parameters"
    )
    dry_run: bool = Field(False, description="Whether to perform dry run")

    # Traceability and monitoring
    correlation_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Correlation ID for traceability",
    )
    operation_id: Optional[str] = Field(None, description="Operation identifier")

    # Security and audit context
    scopes: List[str] = Field(
        default_factory=list, description="Required authorization scopes"
    )
    risk_level: Optional[str] = Field(None, description="Risk level of the operation")

    # Metrics and monitoring
    collect_metrics: bool = Field(
        True, description="Whether to collect execution metrics"
    )

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class ExecutionBatchResult(BaseModel):
    """Enhanced batch execution result model with comprehensive metrics."""

    results: Dict[str, ExecutionResult] = Field(
        ..., description="Individual execution results"
    )
    total_duration: float = Field(..., description="Total execution duration")
    success_count: int = Field(..., description="Number of successful executions")
    failure_count: int = Field(..., description="Number of failed executions")
    timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="Batch execution timestamp"
    )

    # Batch-level metrics
    correlation_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()), description="Batch correlation ID"
    )
    metrics: Dict[str, Union[int, float, str]] = Field(
        default_factory=dict, description="Batch-level metrics"
    )

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}

    def calculate_metrics(self) -> None:
        """Calculate batch-level metrics from individual results."""
        self.metrics = {
            "total_operations": len(self.results),
            "success_rate": (self.success_count / len(self.results)) * 100
            if self.results
            else 0,
            "average_duration": self.total_duration / len(self.results)
            if self.results
            else 0,
            "max_duration": max((r.duration for r in self.results.values()), default=0),
            "min_duration": min((r.duration for r in self.results.values()), default=0),
        }


class AuditLogEntry(BaseModel):
    """Standardized audit log entry model."""

    timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="Event timestamp"
    )
    correlation_id: str = Field(..., description="Correlation ID for traceability")
    operation: str = Field(..., description="Operation name")
    target: Optional[str] = Field(None, description="Target identifier")
    capability: Optional[str] = Field(None, description="Capability being executed")

    # Execution context
    executor_type: Optional[str] = Field(None, description="Executor type")
    parameters: Dict[str, Any] = Field(
        default_factory=dict, description="Operation parameters"
    )

    # Result and status
    status: ExecutionStatus = Field(..., description="Operation status")
    success: bool = Field(..., description="Whether operation succeeded")
    duration: Optional[float] = Field(None, description="Operation duration")

    # Security context
    subject: Optional[str] = Field(None, description="Subject performing the operation")
    scopes: List[str] = Field(
        default_factory=list, description="Authorization scopes used"
    )
    risk_level: Optional[str] = Field(None, description="Risk level")
    approved: Optional[bool] = Field(None, description="Whether operation was approved")

    # Error information
    error: Optional[str] = Field(None, description="Error message")
    structured_error: Optional[StructuredError] = Field(
        None, description="Structured error details"
    )

    # Additional context
    dry_run: bool = Field(False, description="Whether this was a dry run")
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Additional metadata"
    )

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}
