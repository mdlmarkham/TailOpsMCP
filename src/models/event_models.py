"""
Comprehensive event models for the TailOpsMCP observability system.

This module defines the normalized event schema that captures all system signals
including health checks, operations, security events, and lifecycle events.
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field, asdict


class EventType(Enum):
    """Types of events that can occur in the system."""

    # Basic events
    INFO = "info"

    # Health signals
    HEALTH_CHECK = "health_check"
    SERVICE_STATUS = "service_status"
    RESOURCE_THRESHOLD = "resource_threshold"

    # Errors & anomalies
    ERROR = "error"
    WARNING = "warning"
    ANOMALY = "anomaly"
    FAILURE = "failure"

    # Lifecycle events
    CONTAINER_CREATED = "container_created"
    CONTAINER_DELETED = "container_deleted"
    SERVICE_DEPLOYED = "service_deployed"
    BACKUP_CREATED = "backup_created"
    SNAPSHOT_CREATED = "snapshot_created"

    # Security events
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    POLICY_VIOLATION = "policy_violation"
    SECURITY_ALERT = "security_alert"

    # Operational events
    OPERATION_STARTED = "operation_started"
    OPERATION_COMPLETED = "operation_completed"
    OPERATION_FAILED = "operation_failed"
    MAINTENANCE_MODE = "maintenance_mode"

    # Discovery events
    DISCOVERY_STARTED = "discovery_started"
    DISCOVERY_COMPLETED = "discovery_completed"
    DISCOVERY_FAILED = "discovery_failed"
    TARGET_DISCOVERED = "target_discovered"

    # Fleet events
    FLEET_UPDATED = "fleet_updated"
    TARGET_ADDED = "target_added"
    TARGET_REMOVED = "target_removed"
    HEALTH_SCORE_CHANGED = "health_score_changed"


class HealthReport:
    """Health report for system monitoring."""

    def __init__(self, status: str, metrics: Dict[str, Any] = None):
        self.status = status
        self.metrics = metrics or {}


class Alert:
    """System alert."""

    def __init__(self, level: str, message: str, details: Dict[str, Any] = None):
        self.level = level
        self.message = message
        self.details = details or {}


class SecurityEvent:
    """Security event."""

    def __init__(
        self,
        event_type: str,
        severity: str,
        description: str,
        details: Dict[str, Any] = None,
    ):
        self.event_type = event_type
        self.severity = severity
        self.description = description
        self.details = details or {}


class EventSeverity(Enum):
    """Severity levels for events."""

    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    DEBUG = "debug"


class EventSource(Enum):
    """Sources of events in the system."""

    FLEET_INVENTORY = "fleet_inventory"
    POLICY_ENGINE = "policy_engine"
    REMOTE_AGENT = "remote_agent"
    PROXMOX_API = "proxmox_api"
    SECURITY_AUDIT = "security_audit"
    CONTAINER_MANAGER = "container_manager"
    DISCOVERY_PIPELINE = "discovery_pipeline"
    MCP_SERVER = "mcp_server"
    USER_OPERATION = "user_operation"
    SYSTEM = "system"
    EXTERNAL = "external"


class EventCategory(Enum):
    """Categories for organizing events."""

    HEALTH = "health"
    SECURITY = "security"
    OPERATIONS = "operations"
    LIFECYCLE = "lifecycle"
    DISCOVERY = "discovery"
    FLEET_MANAGEMENT = "fleet_management"
    PERFORMANCE = "performance"
    COMPLIANCE = "compliance"


class EventStatus(Enum):
    """Status of events."""

    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    ESCALATED = "escalated"


@dataclass
class ResourceUsage:
    """Resource usage metrics."""

    cpu_percent: Optional[float] = None
    memory_percent: Optional[float] = None
    disk_percent: Optional[float] = None
    network_io: Optional[Dict[str, float]] = None
    custom_metrics: Dict[str, float] = field(default_factory=dict)


@dataclass
class EventMetadata:
    """Metadata for events."""

    correlation_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    trace_id: Optional[str] = None
    parent_span_id: Optional[str] = None
    span_id: Optional[str] = None


@dataclass
class SystemEvent:
    """Unified event model for all system signals."""

    # Core event information
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    event_type: EventType = EventType.INFO
    severity: EventSeverity = EventSeverity.INFO
    source: EventSource = EventSource.SYSTEM
    target: Optional[str] = None
    category: EventCategory = EventCategory.OPERATIONS
    status: EventStatus = EventStatus.ACTIVE

    # Event content
    title: str = ""
    description: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    # Health and performance metrics
    health_score: Optional[float] = None
    resource_usage: Optional[ResourceUsage] = None

    # Metadata
    metadata: EventMetadata = field(default_factory=EventMetadata)

    # Additional context
    location: Optional[str] = None  # File path or component location
    component: Optional[str] = None  # Specific component name

    def __post_init__(self):
        """Validate event data after initialization."""
        if not self.title:
            self.title = f"{self.event_type.value} event"

        # Auto-generate correlation ID if not provided
        if not self.metadata.correlation_id:
            self.metadata.correlation_id = str(uuid.uuid4())

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization."""
        result = asdict(self)
        # Convert enums to their values
        result["event_type"] = self.event_type.value
        result["severity"] = self.severity.value
        result["source"] = self.source.value
        result["category"] = self.category.value
        result["status"] = self.status.value
        result["timestamp"] = self.timestamp.isoformat()
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SystemEvent":
        """Create event from dictionary."""
        # Convert string values back to enums
        data["event_type"] = EventType(data["event_type"])
        data["severity"] = EventSeverity(data["severity"])
        data["source"] = EventSource(data["source"])
        data["category"] = EventCategory(data["category"])
        data["status"] = EventStatus(data["status"])

        # Convert timestamp back to datetime
        if isinstance(data.get("timestamp"), str):
            data["timestamp"] = datetime.fromisoformat(
                data["timestamp"].replace("Z", "+00:00")
            )

        # Handle nested objects
        if "resource_usage" in data and data["resource_usage"]:
            data["resource_usage"] = ResourceUsage(**data["resource_usage"])

        if "metadata" in data and data["metadata"]:
            data["metadata"] = EventMetadata(**data["metadata"])

        return cls(**data)

    def add_tag(self, tag: str) -> None:
        """Add a tag to the event."""
        if tag not in self.metadata.tags:
            self.metadata.tags.append(tag)

    def remove_tag(self, tag: str) -> None:
        """Remove a tag from the event."""
        if tag in self.metadata.tags:
            self.metadata.tags.remove(tag)

    def set_health_score(self, score: float) -> None:
        """Set health score with validation."""
        if not 0.0 <= score <= 100.0:
            raise ValueError("Health score must be between 0.0 and 100.0")
        self.health_score = score

    def is_critical(self) -> bool:
        """Check if event is critical."""
        return self.severity == EventSeverity.CRITICAL

    def is_error(self) -> bool:
        """Check if event represents an error."""
        return self.severity in [EventSeverity.CRITICAL, EventSeverity.ERROR]

    def is_warning(self) -> bool:
        """Check if event is a warning."""
        return self.severity == EventSeverity.WARNING

    def is_operational(self) -> bool:
        """Check if event is operational."""
        return self.category == EventCategory.OPERATIONS

    def is_security_related(self) -> bool:
        """Check if event is security-related."""
        return self.category == EventCategory.SECURITY

    def is_health_related(self) -> bool:
        """Check if event is health-related."""
        return self.category == EventCategory.HEALTH

    def get_age_minutes(self) -> float:
        """Get age of event in minutes."""
        return (datetime.utcnow() - self.timestamp).total_seconds() / 60.0


# Event filtering and querying models


@dataclass
class EventFilters:
    """Filters for querying events."""

    event_types: Optional[List[EventType]] = None
    severities: Optional[List[EventSeverity]] = None
    sources: Optional[List[EventSource]] = None
    categories: Optional[List[EventCategory]] = None
    targets: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    status: Optional[List[EventStatus]] = None

    # Time range filters
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    # Content filters
    search_text: Optional[str] = None
    min_health_score: Optional[float] = None
    max_health_score: Optional[float] = None

    # Pagination
    limit: Optional[int] = 100
    offset: Optional[int] = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert filters to dictionary."""
        result = asdict(self)

        # Convert enums to their values
        if result["event_types"]:
            result["event_types"] = [et.value for et in result["event_types"]]
        if result["severities"]:
            result["severities"] = [es.value for es in result["severities"]]
        if result["sources"]:
            result["sources"] = [es.value for es in result["sources"]]
        if result["categories"]:
            result["categories"] = [ec.value for ec in result["categories"]]
        if result["status"]:
            result["status"] = [es.value for es in result["status"]]

        # Convert datetime objects
        if result.get("start_time"):
            result["start_time"] = result["start_time"].isoformat()
        if result.get("end_time"):
            result["end_time"] = result["end_time"].isoformat()

        return result


@dataclass
class EventStatistics:
    """Statistics about events."""

    total_events: int = 0
    events_by_type: Dict[EventType, int] = field(default_factory=dict)
    events_by_severity: Dict[EventSeverity, int] = field(default_factory=dict)
    events_by_source: Dict[EventSource, int] = field(default_factory=dict)
    events_by_category: Dict[EventCategory, int] = field(default_factory=dict)

    # Time-based statistics
    events_per_hour: Dict[str, int] = field(default_factory=dict)
    events_per_day: Dict[str, int] = field(default_factory=dict)

    # Severity distribution
    critical_events: int = 0
    error_events: int = 0
    warning_events: int = 0
    info_events: int = 0
    debug_events: int = 0

    # Health statistics
    avg_health_score: Optional[float] = None
    min_health_score: Optional[float] = None
    max_health_score: Optional[float] = None

    # Unique counts
    unique_sources: int = 0
    unique_targets: int = 0
    unique_users: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert statistics to dictionary."""
        result = asdict(self)

        # Convert enum keys to strings
        result["events_by_type"] = {k.value: v for k, v in self.events_by_type.items()}
        result["events_by_severity"] = {
            k.value: v for k, v in self.events_by_severity.items()
        }
        result["events_by_source"] = {
            k.value: v for k, v in self.events_by_source.items()
        }
        result["events_by_category"] = {
            k.value: v for k, v in self.events_by_category.items()
        }

        return result


# Event building utilities


class EventBuilder:
    """Builder for creating events with fluent interface."""

    def __init__(self):
        self._event = SystemEvent()

    def event_type(self, event_type: EventType) -> "EventBuilder":
        """Set event type."""
        self._event.event_type = event_type
        return self

    def severity(self, severity: EventSeverity) -> "EventBuilder":
        """Set severity."""
        self._event.severity = severity
        return self

    def source(self, source: EventSource) -> "EventBuilder":
        """Set source."""
        self._event.source = source
        return self

    def target(self, target: str) -> "EventBuilder":
        """Set target."""
        self._event.target = target
        return self

    def category(self, category: EventCategory) -> "EventBuilder":
        """Set category."""
        self._event.category = category
        return self

    def title(self, title: str) -> "EventBuilder":
        """Set title."""
        self._event.title = title
        return self

    def description(self, description: str) -> "EventBuilder":
        """Set description."""
        self._event.description = description
        return self

    def details(self, details: Dict[str, Any]) -> "EventBuilder":
        """Set details."""
        self._event.details = details
        return self

    def health_score(self, score: float) -> "EventBuilder":
        """Set health score."""
        self._event.set_health_score(score)
        return self

    def resource_usage(self, usage: ResourceUsage) -> "EventBuilder":
        """Set resource usage."""
        self._event.resource_usage = usage
        return self

    def add_tag(self, tag: str) -> "EventBuilder":
        """Add a tag."""
        self._event.add_tag(tag)
        return self

    def correlation_id(self, correlation_id: str) -> "EventBuilder":
        """Set correlation ID."""
        self._event.metadata.correlation_id = correlation_id
        return self

    def user_id(self, user_id: str) -> "EventBuilder":
        """Set user ID."""
        self._event.metadata.user_id = user_id
        return self

    def location(self, location: str) -> "EventBuilder":
        """Set location."""
        self._event.location = location
        return self

    def component(self, component: str) -> "EventBuilder":
        """Set component."""
        self._event.component = component
        return self

    def build(self) -> SystemEvent:
        """Build the event."""
        return self._event

    @staticmethod
    def health_check(
        source: EventSource, target: str, status: str, details: Dict[str, Any] = None
    ) -> SystemEvent:
        """Create a health check event."""
        severity = EventSeverity.ERROR if status == "failed" else EventSeverity.INFO
        return (
            EventBuilder()
            .event_type(EventType.HEALTH_CHECK)
            .severity(severity)
            .source(source)
            .target(target)
            .category(EventCategory.HEALTH)
            .title(f"Health check {status}")
            .description(f"Health check for {target} {status}")
            .details(details or {})
            .build()
        )

    @staticmethod
    def error(
        source: EventSource,
        title: str,
        description: str,
        details: Dict[str, Any] = None,
    ) -> SystemEvent:
        """Create an error event."""
        return (
            EventBuilder()
            .event_type(EventType.ERROR)
            .severity(EventSeverity.ERROR)
            .source(source)
            .category(EventCategory.OPERATIONS)
            .title(title)
            .description(description)
            .details(details or {})
            .build()
        )

    @staticmethod
    def security_alert(
        source: EventSource,
        title: str,
        description: str,
        severity: EventSeverity = EventSeverity.WARNING,
    ) -> SystemEvent:
        """Create a security alert event."""
        return (
            EventBuilder()
            .event_type(EventType.SECURITY_ALERT)
            .severity(severity)
            .source(source)
            .category(EventCategory.SECURITY)
            .title(title)
            .description(description)
            .add_tag("security")
            .build()
        )

    @staticmethod
    def operation_completed(
        source: EventSource, operation: str, target: str = None, duration: float = None
    ) -> SystemEvent:
        """Create an operation completed event."""
        details = {}
        if duration is not None:
            details["duration"] = duration

        return (
            EventBuilder()
            .event_type(EventType.OPERATION_COMPLETED)
            .source(source)
            .target(target)
            .category(EventCategory.OPERATIONS)
            .title(f"Operation completed: {operation}")
            .description(f"Operation '{operation}' completed successfully")
            .details(details)
            .build()
        )


# Event factory functions


def create_health_event(
    source: EventSource,
    target: str,
    status: str,
    health_score: Optional[float] = None,
    details: Optional[Dict[str, Any]] = None,
) -> SystemEvent:
    """Create a health-related event."""
    event = EventBuilder.health_check(source, target, status, details)
    if health_score is not None:
        event.set_health_score(health_score)
    return event


def create_security_event(
    source: EventSource,
    event_type: EventType,
    title: str,
    description: str,
    severity: EventSeverity = EventSeverity.WARNING,
    details: Optional[Dict[str, Any]] = None,
) -> SystemEvent:
    """Create a security-related event."""
    return EventBuilder.security_alert(source, title, description, severity)


def create_operation_event(
    source: EventSource,
    event_type: EventType,
    operation: str,
    target: Optional[str] = None,
    success: bool = True,
    duration: Optional[float] = None,
    error: Optional[str] = None,
) -> SystemEvent:
    """Create an operation-related event."""
    severity = EventSeverity.ERROR if not success else EventSeverity.INFO

    details = {}
    if duration is not None:
        details["duration"] = duration
    if error:
        details["error"] = error

    return (
        EventBuilder()
        .event_type(event_type)
        .severity(severity)
        .source(source)
        .target(target)
        .category(EventCategory.OPERATIONS)
        .title(f"Operation {operation}")
        .description(f"Operation '{operation}' {'completed' if success else 'failed'}")
        .details(details)
        .build()
    )
