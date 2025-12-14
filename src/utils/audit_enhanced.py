"""
Enhanced Audit Logger for Policy-as-Code System

Provides structured JSON lines audit logging with result hashing, duration tracking,
and log rotation capabilities.
"""

import json
import os
import hashlib
import time
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger(__name__)


class AuditEventType(str, Enum):
    """Types of audit events."""
    POLICY_DECISION = "policy_decision"
    REMOTE_OPERATION = "remote_operation"
    TARGET_ACCESS = "target_access"
    CREDENTIAL_ACCESS = "credential_access"
    CONFIG_CHANGE = "config_change"


@dataclass
class AuditLogEntry:
    """Structured audit log entry."""
    timestamp: str
    event_type: AuditEventType
    actor: str  # Client/agent identifier
    target: str  # Target system identifier
    operation: str  # Operation performed
    parameters: Dict[str, Any]  # Operation parameters (sanitized)
    result_hash: str  # Hash of operation result
    duration_ms: float  # Operation duration in milliseconds
    authorized: bool  # Whether operation was authorized
    policy_rule: Optional[str] = None  # Policy rule that authorized/denied
    validation_errors: List[str] = None  # Validation errors if any
    
    def __post_init__(self):
        if self.validation_errors is None:
            self.validation_errors = []


class StructuredAuditLogger:
    """Enhanced audit logger with JSON lines format and rotation."""
    
    def __init__(self, log_path: str = "./logs/audit.jsonl", 
                 rotation_size: int = 100 * 1024 * 1024,  # 100MB
                 rotation_count: int = 10):
        self.log_path = Path(log_path)
        self.rotation_size = rotation_size
        self.rotation_count = rotation_count
        
        # Ensure log directory exists
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize log file
        self._ensure_log_file()
    
    def _ensure_log_file(self):
        """Ensure log file exists and is ready for writing."""
        if not self.log_path.exists():
            self.log_path.touch()
    
    def _rotate_if_needed(self):
        """Rotate log file if it exceeds size limit."""
        if self.log_path.stat().st_size >= self.rotation_size:
            self._rotate_log()
    
    def _rotate_log(self):
        """Rotate the audit log file."""
        # Remove oldest log file if we have too many
        log_files = sorted(self.log_path.parent.glob("audit*.jsonl"))
        if len(log_files) >= self.rotation_count:
            oldest_file = log_files[0]
            oldest_file.unlink()
        
        # Rename current log file with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        rotated_path = self.log_path.parent / f"audit_{timestamp}.jsonl"
        self.log_path.rename(rotated_path)
        
        # Create new log file
        self.log_path.touch()
    
    def _sanitize_parameters(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize parameters to remove sensitive data."""
        sanitized = {}
        
        for key, value in parameters.items():
            # Redact sensitive fields
            if any(sensitive in key.lower() for sensitive in [
                'token', 'password', 'secret', 'key', 'credential'
            ]):
                sanitized[key] = "<REDACTED>"
            else:
                # Ensure value is JSON serializable
                try:
                    json.dumps(value)
                    sanitized[key] = value
                except (TypeError, ValueError):
                    sanitized[key] = str(value)
        
        return sanitized
    
    def _hash_result(self, result: Any) -> str:
        """Create a hash of the operation result for integrity verification."""
        result_str = json.dumps(result, sort_keys=True, default=str)
        return hashlib.sha256(result_str.encode()).hexdigest()
    
    def log_remote_operation(self, 
                           actor: str, 
                           target: str, 
                           operation: str, 
                           parameters: Dict[str, Any], 
                           result: Any, 
                           duration_ms: float, 
                           authorized: bool,
                           policy_rule: Optional[str] = None,
                           validation_errors: List[str] = None) -> None:
        """Log a remote operation with full audit details."""
        
        entry = AuditLogEntry(
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_type=AuditEventType.REMOTE_OPERATION,
            actor=actor,
            target=target,
            operation=operation,
            parameters=self._sanitize_parameters(parameters),
            result_hash=self._hash_result(result),
            duration_ms=duration_ms,
            authorized=authorized,
            policy_rule=policy_rule,
            validation_errors=validation_errors or []
        )
        
        self._write_entry(entry)
    
    def log_policy_decision(self,
                          actor: str,
                          target: str,
                          operation: str,
                          parameters: Dict[str, Any],
                          authorized: bool,
                          policy_rule: str,
                          validation_errors: List[str] = None) -> None:
        """Log a policy decision."""
        
        entry = AuditLogEntry(
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_type=AuditEventType.POLICY_DECISION,
            actor=actor,
            target=target,
            operation=operation,
            parameters=self._sanitize_parameters(parameters),
            result_hash="",  # No result for policy decisions
            duration_ms=0.0,
            authorized=authorized,
            policy_rule=policy_rule,
            validation_errors=validation_errors or []
        )
        
        self._write_entry(entry)
    
    def log_target_access(self, 
                        actor: str, 
                        target: str, 
                        operation: str,
                        authorized: bool) -> None:
        """Log target access events."""
        
        entry = AuditLogEntry(
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_type=AuditEventType.TARGET_ACCESS,
            actor=actor,
            target=target,
            operation=operation,
            parameters={},
            result_hash="",
            duration_ms=0.0,
            authorized=authorized
        )
        
        self._write_entry(entry)
    
    def _write_entry(self, entry: AuditLogEntry):
        """Write audit entry to log file."""
        try:
            self._rotate_if_needed()
            
            with open(self.log_path, 'a', encoding='utf-8') as f:
                # Convert to dict and write as JSON line
                entry_dict = asdict(entry)
                f.write(json.dumps(entry_dict, separators=(',', ':'), ensure_ascii=False) + '\n')
                
        except Exception as e:
            logger.error(f"Failed to write audit log entry: {e}")
    
    def search_audit_logs(self, 
                         start_time: Optional[datetime] = None,
                         end_time: Optional[datetime] = None,
                         actor: Optional[str] = None,
                         target: Optional[str] = None,
                         operation: Optional[str] = None,
                         event_type: Optional[AuditEventType] = None,
                         authorized: Optional[bool] = None) -> List[AuditLogEntry]:
        """Search audit logs with filtering capabilities."""
        
        entries = []
        
        # Read all log files
        log_files = sorted(self.log_path.parent.glob("audit*.jsonl"))
        
        for log_file in log_files:
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        if not line.strip():
                            continue
                        
                        try:
                            data = json.loads(line)
                            
                            # Convert timestamp to datetime for filtering
                            entry_time = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
                            
                            # Apply filters
                            if start_time and entry_time < start_time:
                                continue
                            if end_time and entry_time > end_time:
                                continue
                            if actor and data.get('actor') != actor:
                                continue
                            if target and data.get('target') != target:
                                continue
                            if operation and data.get('operation') != operation:
                                continue
                            if event_type and data.get('event_type') != event_type.value:
                                continue
                            if authorized is not None and data.get('authorized') != authorized:
                                continue
                            
                            # Create AuditLogEntry object
                            entry = AuditLogEntry(
                                timestamp=data['timestamp'],
                                event_type=AuditEventType(data['event_type']),
                                actor=data['actor'],
                                target=data['target'],
                                operation=data['operation'],
                                parameters=data['parameters'],
                                result_hash=data['result_hash'],
                                duration_ms=data['duration_ms'],
                                authorized=data['authorized'],
                                policy_rule=data.get('policy_rule'),
                                validation_errors=data.get('validation_errors', [])
                            )
                            
                            entries.append(entry)
                            
                        except (json.JSONDecodeError, KeyError) as e:
                            logger.warning(f"Invalid audit log entry: {e}")
                            continue
                            
            except Exception as e:
                logger.error(f"Error reading audit log file {log_file}: {e}")
                continue
        
        return entries
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get audit log statistics."""
        
        stats = {
            'total_entries': 0,
            'authorized_operations': 0,
            'denied_operations': 0,
            'event_types': {},
            'operations': {},
            'targets': {},
            'actors': {}
        }
        
        entries = self.search_audit_logs()
        
        for entry in entries:
            stats['total_entries'] += 1
            
            if entry.authorized:
                stats['authorized_operations'] += 1
            else:
                stats['denied_operations'] += 1
            
            # Count by event type
            event_type = entry.event_type.value
            stats['event_types'][event_type] = stats['event_types'].get(event_type, 0) + 1
            
            # Count by operation
            operation = entry.operation
            stats['operations'][operation] = stats['operations'].get(operation, 0) + 1
            
            # Count by target
            target = entry.target
            stats['targets'][target] = stats['targets'].get(target, 0) + 1
            
            # Count by actor
            actor = entry.actor
            stats['actors'][actor] = stats['actors'].get(actor, 0) + 1
        
        return stats