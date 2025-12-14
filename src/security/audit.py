"""
Security Audit Module - Consolidated Audit Logging and Compliance

This module provides comprehensive audit logging capabilities including:
- Structured security event logging
- Compliance audit trail maintenance
- Security monitoring integration
- Audit trail search and analysis
- Regulatory compliance reporting

CONSOLIDATED FROM:
- src/utils/audit.py
- src/utils/audit_enhanced.py
- src/services/security_audit_logger.py
- src/services/security_event_integration.py
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
import uuid
import gzip
import shutil

from ..models.security_models import (
    SecurityEvent, AuditLog, ComplianceRequirement,
    SecurityAction, UserAction, SystemAction, AccessAction
)

# Audit Log Configuration
@dataclass
class AuditConfig:
    """Configuration for audit logging."""
    
    # Log settings
    audit_enabled: bool = True
    log_level: str = "INFO"
    log_format: str = "structured"  # structured, json, text
    
    # Log destinations
    log_to_file: bool = True
    log_to_console: bool = False
    log_to_syslog: bool = False
    log_to_database: bool = True
    
    # File settings
    log_file_path: str = "logs/security_audit.log"
    log_rotation: bool = True
    max_log_size_mb: int = 100
    backup_count: int = 5
    compress_backups: bool = True
    
    # Database settings
    database_url: str = "sqlite:///logs/audit.db"
    log_retention_days: int = 365
    batch_insert_size: int = 100
    
    # Filtering and masking
    mask_sensitive_data: bool = True
    exclude_fields: Set[str] = field(default_factory=lambda: {
        'password', 'token', 'secret', 'key', 'private_key'
    })
    
    # Real-time processing
    enable_real_time_processing: bool = True
    real_time_buffer_size: int = 1000
    processing_threads: int = 2
    
    # Compliance settings
    compliance_mode: bool = True
    strict_timestamp_format: bool = True
    immutable_logging: bool = False
    cryptographic_signing: bool = False


class AuditSeverity(Enum):
    """Audit event severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AuditEventType(Enum):
    """Types of audit events."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    ACCESS = "access"
    MODIFICATION = "modification"
    DELETION = "deletion"
    CONFIGURATION = "configuration"
    SYSTEM = "system"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    ERROR = "error"


@dataclass
class AuditEvent:
    """Individual audit event record."""
    
    # Core identification
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    event_type: AuditEventType = AuditEventType.SYSTEM
    severity: AuditSeverity = AuditSeverity.INFO
    
    # Actor information
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    source: str = "system"
    
    # Action details
    action: str = ""
    resource: str = ""
    resource_type: str = ""
    outcome: str = "success"  # success, failure, error
    status_code: Optional[int] = None
    
    # Context information
    details: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)
    
    # Security context
    risk_level: str = "low"
    compliance_tags: Set[str] = field(default_factory=set)
    regulatory_framework: str = ""
    
    # Technical details
    module: str = ""
    function: str = ""
    file_path: str = ""
    line_number: Optional[int] = None
    
    # Correlation and tracking
    correlation_id: Optional[str] = None
    parent_event_id: Optional[str] = None
    chain_id: Optional[str] = None
    
    # Integrity and verification
    hash_signature: Optional[str] = None
    previous_hash: Optional[str] = None
    
    def __post_init__(self):
        """Generate hash signature if needed."""
        if not self.hash_signature:
            self.hash_signature = self._generate_hash()
    
    def _generate_hash(self) -> str:
        """Generate cryptographic hash of event."""
        event_data = {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'user_id': self.user_id,
            'action': self.action,
            'resource': self.resource,
            'outcome': self.outcome
        }
        
        content = json.dumps(event_data, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()


@dataclass
class AuditQuery:
    """Query parameters for audit log search."""
    
    # Time range
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    # Filtering
    event_types: Optional[Set[AuditEventType]] = None
    severities: Optional[Set[AuditSeverity]] = None
    users: Optional[Set[str]] = None
    resources: Optional[Set[str]] = None
    actions: Optional[Set[str]] = None
    outcomes: Optional[Set[str]] = None
    
    # Search criteria
    search_text: Optional[str] = None
    tags: Optional[Set[str]] = None
    correlation_id: Optional[str] = None
    
    # Pagination
    limit: int = 1000
    offset: int = 0
    
    # Sorting
    sort_by: str = "timestamp"
    sort_order: str = "desc"  # asc, desc


class AuditLogger:
    """Comprehensive audit logging system."""
    
    def __init__(self, config: Optional[AuditConfig] = None):
        self.config = config or AuditConfig()
        self._logger = None
        self._log_handlers = []
        self._event_buffer = []
        self._buffer_lock = threading.Lock()
        self._processing_threads = []
        self._shutdown = False
        
        self._initialize_logging()
        self._start_processing_threads()
    
    def _initialize_logging(self) -> None:
        """Initialize logging configuration."""
        # Create logger
        self._logger = logging.getLogger("security.audit")
        self._logger.setLevel(getattr(logging, self.config.log_level.upper()))
        
        # Clear existing handlers
        self._logger.handlers.clear()
        
        # File handler
        if self.config.log_to_file:
            self._setup_file_logging()
        
        # Console handler
        if self.config.log_to_console:
            self._setup_console_logging()
        
        # Database handler
        if self.config.log_to_database:
            self._setup_database_logging()
    
    def _setup_file_logging(self) -> None:
        """Setup file-based logging."""
        try:
            # Create logs directory
            log_dir = Path(self.config.log_file_path).parent
            log_dir.mkdir(parents=True, exist_ok=True)
            
            # Setup rotation if enabled
            if self.config.log_rotation:
                from logging.handlers import RotatingFileHandler
                
                max_bytes = self.config.max_log_size_mb * 1024 * 1024
                backup_count = self.config.backup_count
                
                handler = RotatingFileHandler(
                    self.config.log_file_path,
                    maxBytes=max_bytes,
                    backupCount=backup_count
                )
            else:
                handler = logging.FileHandler(self.config.log_file_path)
            
            # Set formatter
            if self.config.log_format == "structured":
                formatter = self._create_structured_formatter()
            elif self.config.log_format == "json":
                formatter = self._create_json_formatter()
            else:
                formatter = self._create_text_formatter()
            
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)
            self._log_handlers.append(handler)
            
        except Exception as e:
            print(f"Failed to setup file logging: {e}")
    
    def _setup_console_logging(self) -> None:
        """Setup console logging."""
        try:
            handler = logging.StreamHandler()
            formatter = self._create_text_formatter()
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)
            self._log_handlers.append(handler)
        except Exception as e:
            print(f"Failed to setup console logging: {e}")
    
    def _setup_database_logging(self) -> None:
        """Setup database logging."""
        try:
            # Initialize database connection and table
            self._initialize_database()
        except Exception as e:
            print(f"Failed to setup database logging: {e}")
    
    def _create_structured_formatter(self) -> logging.Formatter:
        """Create structured log formatter."""
        return logging.Formatter(
            fmt='%(asctime)s | %(levelname)s | %(name)s | %(message)s | %(module)s.%(funcName)s:%(lineno)d',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    def _create_json_formatter(self) -> logging.Formatter:
        """Create JSON log formatter."""
        import json
        
        class JSONFormatter(logging.Formatter):
            def format(self, record):
                log_entry = {
                    'timestamp': datetime.fromtimestamp(record.created).isoformat(),
                    'level': record.levelname,
                    'logger': record.name,
                    'message': record.getMessage(),
                    'module': record.module,
                    'function': record.funcName,
                    'line': record.lineno,
                    'thread': record.thread,
                    'process': record.process
                }
                return json.dumps(log_entry, default=str)
        
        return JSONFormatter()
    
    def _create_text_formatter(self) -> logging.Formatter:
        """Create text log formatter."""
        return logging.Formatter(
            fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    def _initialize_database(self) -> None:
        """Initialize audit database."""
        # Placeholder for database initialization
        # In production, implement with proper database connection
        pass
    
    def _start_processing_threads(self) -> None:
        """Start background processing threads."""
        if not self.config.enable_real_time_processing:
            return
        
        for i in range(self.config.processing_threads):
            thread = threading.Thread(
                target=self._process_event_buffer,
                name=f"AuditProcessor-{i}"
            )
            thread.daemon = True
            thread.start()
            self._processing_threads.append(thread)
    
    def log_event(self, event: AuditEvent) -> None:
        """Log audit event."""
        if not self.config.audit_enabled:
            return
        
        # Mask sensitive data if configured
        if self.config.mask_sensitive_data:
            event = self._mask_sensitive_data(event)
        
        # Add to buffer for processing
        if self.config.enable_real_time_processing:
            with self._buffer_lock:
                self._event_buffer.append(event)
                
                # Process buffer if full
                if len(self._event_buffer) >= self.config.real_time_buffer_size:
                    self._flush_buffer()
        else:
            # Process immediately
            self._process_event(event)
    
    def log_authentication(self, user_id: str, action: str, outcome: str, 
                          ip_address: str = None, user_agent: str = None,
                          details: Dict[str, Any] = None) -> None:
        """Log authentication event."""
        event = AuditEvent(
            event_type=AuditEventType.AUTHENTICATION,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            action=action,
            outcome=outcome,
            details=details or {},
            severity=self._determine_severity(outcome),
            module="auth",
            tags={"authentication", action.lower()}
        )
        self.log_event(event)
    
    def log_authorization(self, user_id: str, action: str, resource: str,
                         outcome: str, reason: str = None,
                         details: Dict[str, Any] = None) -> None:
        """Log authorization event."""
        event = AuditEvent(
            event_type=AuditEventType.AUTHORIZATION,
            user_id=user_id,
            action=action,
            resource=resource,
            outcome=outcome,
            details=details or {},
            severity=self._determine_severity(outcome),
            module="auth",
            tags={"authorization", action.lower()}
        )
        if reason:
            event.details["reason"] = reason
        self.log_event(event)
    
    def log_access(self, user_id: str, action: str, resource: str,
                  outcome: str, ip_address: str = None,
                  details: Dict[str, Any] = None) -> None:
        """Log resource access event."""
        event = AuditEvent(
            event_type=AuditEventType.ACCESS,
            user_id=user_id,
            action=action,
            resource=resource,
            outcome=outcome,
            ip_address=ip_address,
            details=details or {},
            severity=self._determine_severity(outcome),
            tags={"access", action.lower()}
        )
        self.log_event(event)
    
    def log_modification(self, user_id: str, action: str, resource: str,
                        before: Any = None, after: Any = None,
                        details: Dict[str, Any] = None) -> None:
        """Log resource modification event."""
        event = AuditEvent(
            event_type=AuditEventType.MODIFICATION,
            user_id=user_id,
            action=action,
            resource=resource,
            outcome="success",
            details=details or {},
            severity=AuditSeverity.MEDIUM,
            tags={"modification", action.lower()}
        )
        
        if before is not None:
            event.details["before"] = self._serialize_for_log(before)
        if after is not None:
            event.details["after"] = self._serialize_for_log(after)
        
        self.log_event(event)
    
    def log_system(self, action: str, outcome: str, details: Dict[str, Any] = None,
                  severity: AuditSeverity = AuditSeverity.INFO) -> None:
        """Log system event."""
        event = AuditEvent(
            event_type=AuditEventType.SYSTEM,
            action=action,
            outcome=outcome,
            details=details or {},
            severity=severity,
            module="system",
            tags={"system", action.lower()}
        )
        self.log_event(event)
    
    def log_security_event(self, event_type: str, severity: AuditSeverity,
                          description: str, user_id: str = None,
                          resource: str = None, details: Dict[str, Any] = None) -> None:
        """Log security-related event."""
        event = AuditEvent(
            event_type=AuditEventType.SECURITY,
            action=event_type,
            user_id=user_id,
            resource=resource,
            outcome="event",
            details=details or {},
            severity=severity,
            module="security",
            tags={"security", event_type.lower(), severity.value}
        )
        event.details["description"] = description
        self.log_event(event)
    
    def log_compliance_event(self, requirement: str, compliance_status: str,
                           details: Dict[str, Any] = None) -> None:
        """Log compliance-related event."""
        event = AuditEvent(
            event_type=AuditEventType.COMPLIANCE,
            action="compliance_check",
            outcome=compliance_status,
            details=details or {},
            severity=AuditSeverity.MEDIUM,
            module="compliance",
            tags={"compliance", compliance_status.lower()}
        )
        event.details["requirement"] = requirement
        self.log_event(event)
    
    def search_audit_log(self, query: AuditQuery) -> List[AuditEvent]:
        """Search audit log for events matching criteria."""
        # Placeholder implementation
        # In production, implement database query or log file parsing
        return []
    
    def get_audit_statistics(self, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Get audit log statistics for time period."""
        # Placeholder implementation
        return {
            "total_events": 0,
            "events_by_type": {},
            "events_by_severity": {},
            "events_by_outcome": {},
            "unique_users": 0,
            "unique_resources": 0
        }
    
    def export_audit_log(self, output_path: str, query: AuditQuery) -> None:
        """Export audit log to file."""
        events = self.search_audit_log(query)
        
        # Format as JSON
        export_data = {
            "export_timestamp": datetime.now().isoformat(),
            "query": asdict(query),
            "total_events": len(events),
            "events": [asdict(event) for event in events]
        }
        
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
    
    def rotate_logs(self) -> None:
        """Manually rotate log files."""
        for handler in self._log_handlers:
            if hasattr(handler, 'doRollover'):
                handler.doRollover()
    
    def cleanup_old_logs(self, retention_days: Optional[int] = None) -> None:
        """Clean up old log files."""
        retention_days = retention_days or self.config.log_retention_days
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        log_dir = Path(self.config.log_file_path).parent
        log_files = list(log_dir.glob("security_audit.log*"))
        
        for log_file in log_files:
            try:
                # Check file modification time
                if log_file.stat().st_mtime < cutoff_date.timestamp():
                    if self.config.compress_backups and not log_file.name.endswith('.gz'):
                        # Compress before deleting
                        compressed_file = str(log_file) + '.gz'
                        with open(log_file, 'rb') as f_in:
                            with gzip.open(compressed_file, 'wb') as f_out:
                                shutil.copyfileobj(f_in, f_out)
                        log_file.unlink()
                    else:
                        log_file.unlink()
            except Exception as e:
                print(f"Error cleaning up log file {log_file}: {e}")
    
    def shutdown(self) -> None:
        """Shutdown audit logger and processing threads."""
        self._shutdown = True
        
        # Wait for processing threads to finish
        for thread in self._processing_threads:
            thread.join(timeout=5)
        
        # Flush any remaining events
        self._flush_buffer()
        
        # Close handlers
        for handler in self._log_handlers:
            handler.close()
    
    def _process_event_buffer(self) -> None:
        """Background thread to process event buffer."""
        while not self._shutdown:
            try:
                # Process events in batch
                batch = []
                with self._buffer_lock:
                    if self._event_buffer:
                        batch = self._event_buffer[:self.config.batch_insert_size]
                        self._event_buffer = self._event_buffer[self.config.batch_insert_size:]
                
                # Process batch
                for event in batch:
                    self._process_event(event)
                
                # Sleep if no events
                if not batch:
                    time.sleep(1)
                    
            except Exception as e:
                print(f"Error in audit processing thread: {e}")
                time.sleep(5)
    
    def _process_event(self, event: AuditEvent) -> None:
        """Process individual audit event."""
        try:
            # Log to file
            if self.config.log_to_file:
                self._log_to_file(event)
            
            # Log to database
            if self.config.log_to_database:
                self._log_to_database(event)
            
            # Handle real-time alerts
            if event.severity in [AuditSeverity.CRITICAL, AuditSeverity.HIGH]:
                self._handle_high_priority_event(event)
                
        except Exception as e:
            print(f"Error processing audit event: {e}")
    
    def _log_to_file(self, event: AuditEvent) -> None:
        """Log event to file."""
        if self.config.log_format == "json":
            log_message = json.dumps(asdict(event), default=str)
        else:
            log_message = str(event)
        
        self._logger.info(log_message)
    
    def _log_to_database(self, event: AuditEvent) -> None:
        """Log event to database."""
        # Placeholder for database logging
        # In production, implement with proper database connection
        pass
    
    def _handle_high_priority_event(self, event: AuditEvent) -> None:
        """Handle high-priority security events."""
        # Send alerts, notifications, etc.
        if event.severity == AuditSeverity.CRITICAL:
            self._send_critical_alert(event)
        elif event.severity == AuditSeverity.HIGH:
            self._send_high_priority_alert(event)
    
    def _send_critical_alert(self, event: AuditEvent) -> None:
        """Send critical security alert."""
        # Placeholder for critical alert mechanism
        print(f"CRITICAL SECURITY ALERT: {event}")
    
    def _send_high_priority_alert(self, event: AuditEvent) -> None:
        """Send high priority alert."""
        # Placeholder for high priority alert mechanism
        print(f"HIGH PRIORITY SECURITY ALERT: {event}")
    
    def _flush_buffer(self) -> None:
        """Flush event buffer to processing."""
        with self._buffer_lock:
            events = self._event_buffer.copy()
            self._event_buffer.clear()
        
        # Process events immediately if buffer is full
        for event in events:
            self._process_event(event)
    
    def _mask_sensitive_data(self, event: AuditEvent) -> AuditEvent:
        """Mask sensitive data in event."""
        # Create a copy to avoid modifying original
        masked_event = AuditEvent(**asdict(event))
        
        # Mask sensitive fields
        for field_name in self.config.exclude_fields:
            if field_name in masked_event.details:
                masked_event.details[field_name] = "***MASKED***"
        
        return masked_event
    
    def _serialize_for_log(self, obj: Any) -> Any:
        """Serialize object for logging."""
        try:
            return json.dumps(obj, default=str)
        except Exception:
            return str(obj)
    
    def _determine_severity(self, outcome: str) -> AuditSeverity:
        """Determine event severity based on outcome."""
        if outcome.lower() in ["failure", "error", "denied", "unauthorized"]:
            return AuditSeverity.HIGH
        elif outcome.lower() in ["success", "granted", "allowed"]:
            return AuditSeverity.LOW
        else:
            return AuditSeverity.INFO


# Global audit logger instance
_audit_logger = None


def get_audit_logger(config: Optional[AuditConfig] = None) -> AuditLogger:
    """Get global audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger(config)
    return _audit_logger


# Convenience logging functions
def log_auth(user_id: str, action: str, outcome: str, **kwargs) -> None:
    """Log authentication event."""
    get_audit_logger().log_authentication(user_id, action, outcome, **kwargs)


def log_authz(user_id: str, action: str, resource: str, outcome: str, **kwargs) -> None:
    """Log authorization event."""
    get_audit_logger().log_authorization(user_id, action, resource, outcome, **kwargs)


def log_access(user_id: str, action: str, resource: str, outcome: str, **kwargs) -> None:
    """Log access event."""
    get_audit_logger().log_access(user_id, action, resource, outcome, **kwargs)


def log_modification(user_id: str, action: str, resource: str, **kwargs) -> None:
    """Log modification event."""
    get_audit_logger().log_modification(user_id, action, resource, **kwargs)


def log_security_event(event_type: str, severity: str, description: str, **kwargs) -> None:
    """Log security event."""
    severity_enum = AuditSeverity(severity.lower())
    get_audit_logger().log_security_event(event_type, severity_enum, description, **kwargs)


# Export main classes and functions
__all__ = [
    'AuditLogger',
    'AuditEvent',
    'AuditConfig',
    'AuditQuery',
    'AuditSeverity',
    'AuditEventType',
    'get_audit_logger',
    'log_auth',
    'log_authz',
    'log_access',
    'log_modification',
    'log_security_event'
]