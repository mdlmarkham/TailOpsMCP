"""
Enhanced audit logging system with standardized formats, correlation IDs, and multiple sinks.
"""

import json
import logging
import os
import sys
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pathlib import Path

from src.models.execution import AuditLogEntry, ExecutionResult, ExecutionStatus


class LogLevel(str, Enum):
    """Standardized log levels for consistent logging across the system."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class LogSinkType(str, Enum):
    """Types of log sinks supported by the system."""
    FILE = "file"
    JSONL = "jsonl"
    CONSOLE = "console"
    DATABASE = "database"
    SYSLOG = "syslog"
    HTTP = "http"


class LogFormatter:
    """Standardized log formatter for consistent log formats."""
    
    @staticmethod
    def format_structured_log(
        level: LogLevel,
        message: str,
        correlation_id: str,
        operation: Optional[str] = None,
        target: Optional[str] = None,
        capability: Optional[str] = None,
        duration: Optional[float] = None,
        metrics: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Format a structured log entry."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": level.value,
            "message": message,
            "correlation_id": correlation_id,
        }
        
        if operation:
            log_entry["operation"] = operation
        if target:
            log_entry["target"] = target
        if capability:
            log_entry["capability"] = capability
        if duration is not None:
            log_entry["duration"] = duration
        if metrics:
            log_entry["metrics"] = metrics
        
        # Add any additional context
        log_entry.update(kwargs)
        
        return log_entry
    
    @staticmethod
    def format_audit_log(audit_entry: AuditLogEntry) -> Dict[str, Any]:
        """Format an audit log entry for output."""
        return audit_entry.dict()
    
    @staticmethod
    def format_execution_log(execution_result: ExecutionResult) -> Dict[str, Any]:
        """Format an execution result for logging."""
        return {
            "timestamp": execution_result.timestamp.isoformat(),
            "correlation_id": execution_result.correlation_id,
            "operation_id": execution_result.operation_id,
            "target_id": execution_result.target_id,
            "capability": execution_result.capability,
            "executor_type": execution_result.executor_type,
            "status": execution_result.status.value,
            "success": execution_result.success,
            "severity": execution_result.severity.value,
            "duration": execution_result.duration,
            "dry_run": execution_result.dry_run,
            "metrics": execution_result.metrics,
            "error": execution_result.error,
            "structured_error": execution_result.structured_error.dict() if execution_result.structured_error else None,
        }


class LogSink:
    """Base class for log sinks."""
    
    def __init__(self, sink_type: LogSinkType, config: Dict[str, Any]):
        self.sink_type = sink_type
        self.config = config
        self.enabled = config.get("enabled", True)
    
    def write(self, log_entry: Dict[str, Any]) -> bool:
        """Write a log entry to the sink."""
        raise NotImplementedError
    
    def close(self) -> None:
        """Close the sink."""
        pass


class FileSink(LogSink):
    """File-based log sink with rotation support."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(LogSinkType.FILE, config)
        self.path = config["path"]
        self.max_size = config.get("max_size", 10 * 1024 * 1024)  # 10MB default
        self.backup_count = config.get("backup_count", 5)
        self.encoding = config.get("encoding", "utf-8")
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        
        self._file = None
        self._open_file()
    
    def _open_file(self) -> None:
        """Open the log file."""
        if self._file is not None:
            self._file.close()
        
        self._file = open(self.path, "a", encoding=self.encoding)
    
    def _should_rotate(self) -> bool:
        """Check if the log file should be rotated."""
        try:
            return os.path.getsize(self.path) >= self.max_size
        except OSError:
            return False
    
    def _rotate_file(self) -> None:
        """Rotate the log file."""
        if not os.path.exists(self.path):
            return
        
        # Create backup files
        for i in range(self.backup_count - 1, 0, -1):
            src = f"{self.path}.{i}"
            dst = f"{self.path}.{i + 1}"
            if os.path.exists(src):
                if os.path.exists(dst):
                    os.remove(dst)
                os.rename(src, dst)
        
        # Rotate current file
        if os.path.exists(self.path):
            os.rename(self.path, f"{self.path}.1")
        
        self._open_file()
    
    def write(self, log_entry: Dict[str, Any]) -> bool:
        """Write a log entry to the file."""
        if not self.enabled:
            return False
        
        try:
            if self._should_rotate():
                self._rotate_file()
            
            log_line = json.dumps(log_entry, separators=(",", ":"), ensure_ascii=False)
            self._file.write(log_line + "\n")
            self._file.flush()
            return True
        except Exception as e:
            print(f"Error writing to file sink: {e}", file=sys.stderr)
            return False
    
    def close(self) -> None:
        """Close the file."""
        if self._file is not None:
            self._file.close()
            self._file = None


class ConsoleSink(LogSink):
    """Console output log sink."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(LogSinkType.CONSOLE, config)
        self.format = config.get("format", "structured")  # structured or human
    
    def write(self, log_entry: Dict[str, Any]) -> bool:
        """Write a log entry to the console."""
        if not self.enabled:
            return False
        
        try:
            if self.format == "human":
                timestamp = log_entry.get("timestamp", "")
                level = log_entry.get("level", "INFO").upper()
                message = log_entry.get("message", "")
                correlation_id = log_entry.get("correlation_id", "")
                
                print(f"{timestamp} [{level}] {message} (cid: {correlation_id})")
            else:
                print(json.dumps(log_entry, separators=(",", ":"), ensure_ascii=False))
            
            return True
        except Exception as e:
            print(f"Error writing to console sink: {e}", file=sys.stderr)
            return False


class AuditLogger:
    """Enhanced audit logging system with multiple sinks and standardized formats."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.sinks: List[LogSink] = []
        self.formatter = LogFormatter()
        self._setup_sinks()
    
    def _setup_sinks(self) -> None:
        """Set up log sinks based on configuration."""
        sinks_config = self.config.get("sinks", [
            {
                "type": "file",
                "enabled": True,
                "path": os.getenv("SYSTEMMANAGER_AUDIT_LOG", "./logs/audit.log"),
                "max_size": 10 * 1024 * 1024,  # 10MB
                "backup_count": 5
            },
            {
                "type": "console",
                "enabled": os.getenv("SYSTEMMANAGER_LOG_CONSOLE", "true").lower() == "true",
                "format": "human"
            }
        ])
        
        for sink_config in sinks_config:
            sink_type = sink_config["type"]
            
            if sink_type == "file":
                self.sinks.append(FileSink(sink_config))
            elif sink_type == "console":
                self.sinks.append(ConsoleSink(sink_config))
            # Add other sink types as needed
    
    def log_operation(
        self,
        operation: str,
        correlation_id: str,
        target: Optional[str] = None,
        capability: Optional[str] = None,
        executor_type: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        status: ExecutionStatus = ExecutionStatus.SUCCESS,
        success: bool = True,
        duration: Optional[float] = None,
        subject: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        risk_level: Optional[str] = None,
        approved: Optional[bool] = None,
        error: Optional[str] = None,
        structured_error: Optional[Dict[str, Any]] = None,
        dry_run: bool = False,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log an operation with comprehensive context."""
        audit_entry = AuditLogEntry(
            timestamp=datetime.utcnow(),
            correlation_id=correlation_id,
            operation=operation,
            target=target,
            capability=capability,
            executor_type=executor_type,
            parameters=parameters or {},
            status=status,
            success=success,
            duration=duration,
            subject=subject,
            scopes=scopes or [],
            risk_level=risk_level,
            approved=approved,
            error=error,
            structured_error=structured_error,
            dry_run=dry_run,
            metadata=metadata or {}
        )
        
        self._write_to_sinks(self.formatter.format_audit_log(audit_entry))
    
    def log_execution_result(self, execution_result: ExecutionResult) -> None:
        """Log an execution result."""
        self._write_to_sinks(self.formatter.format_execution_log(execution_result))
    
    def log_structured(
        self,
        level: LogLevel,
        message: str,
        correlation_id: str,
        operation: Optional[str] = None,
        target: Optional[str] = None,
        capability: Optional[str] = None,
        duration: Optional[float] = None,
        metrics: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> None:
        """Log a structured message."""
        log_entry = self.formatter.format_structured_log(
            level=level,
            message=message,
            correlation_id=correlation_id,
            operation=operation,
            target=target,
            capability=capability,
            duration=duration,
            metrics=metrics,
            **kwargs
        )
        
        self._write_to_sinks(log_entry)
    
    def _write_to_sinks(self, log_entry: Dict[str, Any]) -> None:
        """Write log entry to all configured sinks."""
        for sink in self.sinks:
            try:
                sink.write(log_entry)
            except Exception as e:
                print(f"Error writing to sink {sink.sink_type}: {e}", file=sys.stderr)
    
    def close(self) -> None:
        """Close all log sinks."""
        for sink in self.sinks:
            try:
                sink.close()
            except Exception as e:
                print(f"Error closing sink {sink.sink_type}: {e}", file=sys.stderr)


# Global audit logger instance
audit_logger = AuditLogger()


def setup_logging_config() -> None:
    """Set up standardized logging configuration for the entire system."""
    
    # Configure Python logging
    log_level = os.getenv("SYSTEMMANAGER_LOG_LEVEL", "INFO").upper()
    log_format = os.getenv("SYSTEMMANAGER_LOG_FORMAT", "structured")
    
    # Basic logging configuration
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s' if log_format == "human" else None,
        handlers=[]
    )
    
    # Remove default handlers
    logging.getLogger().handlers.clear()
    
    # Add structured logging handler if configured
    if log_format == "structured":
        class StructuredLogHandler(logging.Handler):
            def emit(self, record):
                try:
                    log_entry = {
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "level": record.levelname.lower(),
                        "logger": record.name,
                        "message": record.getMessage(),
                        "correlation_id": getattr(record, 'correlation_id', 'unknown'),
                    }
                    
                    # Add extra fields if present
                    if hasattr(record, 'extra') and record.extra:
                        log_entry.update(record.extra)
                    
                    print(json.dumps(log_entry, separators=(",", ":"), ensure_ascii=False))
                except Exception:
                    self.handleError(record)
        
        handler = StructuredLogHandler()
        logging.getLogger().addHandler(handler)


# Initialize logging configuration when module is imported
setup_logging_config()