"""
Enhanced audit logging utilities for comprehensive system auditing.

Provides structured audit logging with event types, context tracking,
and compliance reporting capabilities.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from uuid import uuid4
import json


class AuditEventType(str, Enum):
    """Types of audit events."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    OPERATION = "operation"
    POLICY_EVALUATION = "policy_evaluation"
    POLICY_CHANGE = "policy_change"
    SYSTEM_ACCESS = "system_access"
    DATA_ACCESS = "data_access"
    CONFIGURATION = "configuration"
    SECURITY_EVENT = "security_event"
    ERROR = "error"
    BACKUP = "backup"
    RESTORE = "restore"
    DEPLOYMENT = "deployment"
    MONITORING = "monitoring"


class AuditLevel(str, Enum):
    """Audit event severity levels."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    SECURITY = "security"


@dataclass
class AuditContext:
    """Context information for audit events."""

    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    correlation_id: Optional[str] = None
    request_id: Optional[str] = None
    source_system: Optional[str] = None
    target_resource: Optional[str] = None
    environment: str = "production"
    additional_context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditEvent:
    """Individual audit event."""

    id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    event_type: AuditEventType = AuditEventType.OPERATION
    level: AuditLevel = AuditLevel.INFO
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    context: AuditContext = field(default_factory=AuditContext)

    # Operation details
    operation: Optional[str] = None
    resource: Optional[str] = None
    outcome: str = "success"  # success, failure, warning
    duration_ms: Optional[float] = None

    # Compliance fields
    compliance_tags: List[str] = field(default_factory=list)
    retention_category: str = "standard"


class StructuredAuditLogger:
    """Enhanced structured audit logger with multiple output formats."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the structured audit logger."""
        self.config = config or {}
        self.events: List[AuditEvent] = []
        self.output_formats = self.config.get("output_formats", ["json", "structured"])

    def log_event(
        self,
        event_type: AuditEventType,
        message: str,
        level: AuditLevel = AuditLevel.INFO,
        context: Optional[AuditContext] = None,
        operation: Optional[str] = None,
        resource: Optional[str] = None,
        outcome: str = "success",
        details: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> AuditEvent:
        """Log a structured audit event."""

        audit_context = context or AuditContext()
        event_details = details or {}

        # Add any additional kwargs to details
        event_details.update(kwargs)

        event = AuditEvent(
            event_type=event_type,
            level=level,
            message=message,
            context=audit_context,
            operation=operation,
            resource=resource,
            outcome=outcome,
            details=event_details,
        )

        self.events.append(event)

        # In a real implementation, this would write to various outputs
        # (files, databases, log aggregators, etc.)
        self._write_event(event)

        return event

    def log_structured(
        self,
        event_type: AuditEventType,
        message: str,
        level: AuditLevel = AuditLevel.INFO,
        **kwargs,
    ) -> AuditEvent:
        """Log a structured event with flexible parameters."""

        context = AuditContext(
            **{
                k: v
                for k, v in kwargs.items()
                if k
                in [
                    "user_id",
                    "session_id",
                    "ip_address",
                    "user_agent",
                    "correlation_id",
                    "request_id",
                    "source_system",
                    "target_resource",
                    "environment",
                ]
            }
        )

        operation = kwargs.get("operation")
        resource = kwargs.get("resource")
        outcome = kwargs.get("outcome", "success")
        details = {
            k: v
            for k, v in kwargs.items()
            if k
            not in [
                "user_id",
                "session_id",
                "ip_address",
                "user_agent",
                "correlation_id",
                "request_id",
                "source_system",
                "target_resource",
                "environment",
                "operation",
                "resource",
                "outcome",
            ]
        }

        return self.log_event(
            event_type=event_type,
            message=message,
            level=level,
            context=context,
            operation=operation,
            resource=resource,
            outcome=outcome,
            details=details,
        )

    def _write_event(self, event: AuditEvent):
        """Write audit event to configured outputs."""

        for format_type in self.output_formats:
            if format_type == "json":
                self._write_json_event(event)
            elif format_type == "structured":
                self._write_structured_event(event)

    def _write_json_event(self, event: AuditEvent):
        """Write event as JSON."""
        # In a real implementation, this would write to JSON files/databases
        event_json = {
            "id": event.id,
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type,
            "level": event.level,
            "message": event.message,
            "context": {
                "user_id": event.context.user_id,
                "session_id": event.context.session_id,
                "ip_address": event.context.ip_address,
                "correlation_id": event.context.correlation_id,
            },
            "operation": event.operation,
            "resource": event.resource,
            "outcome": event.outcome,
            "details": event.details,
        }
        # JSON writing logic would go here

    def _write_structured_event(self, event: AuditEvent):
        """Write event in structured format."""
        # Structured logging format (e.g., for log aggregators)
        structured_log = {
            "audit.event_id": event.id,
            "audit.timestamp": event.timestamp.isoformat(),
            "audit.type": event.event_type,
            "audit.level": event.level,
            "audit.message": event.message,
            "audit.user_id": event.context.user_id,
            "audit.operation": event.operation,
            "audit.resource": event.resource,
            "audit.outcome": event.outcome,
        }
        # Structured logging logic would go here

    def get_events(
        self,
        event_type: Optional[AuditEventType] = None,
        level: Optional[AuditLevel] = None,
        user_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[AuditEvent]:
        """Retrieve audit events with filtering."""

        filtered_events = self.events

        if event_type:
            filtered_events = [e for e in filtered_events if e.event_type == event_type]

        if level:
            filtered_events = [e for e in filtered_events if e.level == level]

        if user_id:
            filtered_events = [
                e for e in filtered_events if e.context.user_id == user_id
            ]

        if start_time:
            filtered_events = [e for e in filtered_events if e.timestamp >= start_time]

        if end_time:
            filtered_events = [e for e in filtered_events if e.timestamp <= end_time]

        return filtered_events

    def export_events(self, format_type: str = "json") -> str:
        """Export all events in specified format."""

        if format_type == "json":
            return json.dumps(
                [
                    {
                        "id": event.id,
                        "timestamp": event.timestamp.isoformat(),
                        "event_type": event.event_type,
                        "level": event.level,
                        "message": event.message,
                        "context": event.context.__dict__,
                        "operation": event.operation,
                        "resource": event.resource,
                        "outcome": event.outcome,
                        "details": event.details,
                    }
                    for event in self.events
                ],
                indent=2,
            )

        return str(self.events)


# Global audit logger instance
_default_logger = StructuredAuditLogger()


def get_audit_logger() -> StructuredAuditLogger:
    """Get the default audit logger instance."""
    return _default_logger


def log_audit_event(
    event_type: AuditEventType,
    message: str,
    level: AuditLevel = AuditLevel.INFO,
    **kwargs,
) -> AuditEvent:
    """Convenience function to log audit events."""
    return _default_logger.log_structured(event_type, message, level, **kwargs)
