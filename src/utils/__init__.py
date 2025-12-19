"""Utilities package for SystemManager."""

from .errors import SystemManagerError, ErrorCategory
from .retry import retry_with_backoff
from .audit import StructuredAuditLogger
from .logging_config import SystemLogger, get_logger, metrics_collector, health_checker
from .observability_config import (
    AuditLogConfig,
    ObservabilityConfig,
    generate_correlation_id,
    validate_correlation_id,
)
from .monitoring_integration import MonitoringManager, DashboardExporter
from .observability_integration import (
    ObservabilityIntegration,
    LegacyAuditLoggerAdapter,
    ToolIntegration,
)

AuditLogger = StructuredAuditLogger  # Alias for backward compatibility


# Mock classes for compatibility
class LogLevel:
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class LogFormatter:
    pass


class LogSinkType:
    FILE = "file"
    CONSOLE = "console"


__all__ = [
    "SystemManagerError",
    "ErrorCategory",
    "retry_with_backoff",
    "AuditLogger",
    "LogLevel",
    "LogFormatter",
    "LogSinkType",
    "SystemLogger",
    "get_logger",
    "metrics_collector",
    "health_checker",
    "AuditLogConfig",
    "ObservabilityConfig",
    "generate_correlation_id",
    "validate_correlation_id",
    "MonitoringManager",
    "DashboardExporter",
    "ObservabilityIntegration",
    "LegacyAuditLoggerAdapter",
    "ToolIntegration",
]
