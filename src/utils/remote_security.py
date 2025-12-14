"""
Security Controls and Audit Logging for Remote Operations

Provides comprehensive security controls, access validation, and detailed audit logging
for all remote agent operations. Implements security-first approach with thorough
monitoring and compliance features.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path

from src.utils.audit import AuditLogger
from src.connectors.remote_agent_connector import RemoteAgentError, SecurityError
from src.models.target_registry import TargetConnection, TargetConstraints


logger = logging.getLogger(__name__)


class SecurityLevel(str, Enum):
    """Security levels for operations."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AccessScope(str, Enum):
    """Access scopes for remote operations."""
    OBSERVE_ONLY = "observe_only"  # Read-only operations
    LIMITED_CONTROL = "limited_control"  # Safe control operations
    FULL_CONTROL = "full_control"  # All control operations
    ADMIN = "admin"  # Administrative access


class AuditEventType(str, Enum):
    """Types of audit events."""
    CONNECTION_ESTABLISHED = "connection_established"
    CONNECTION_FAILED = "connection_failed"
    OPERATION_EXECUTED = "operation_executed"
    OPERATION_FAILED = "operation_failed"
    SECURITY_VIOLATION = "security_violation"
    ACCESS_DENIED = "access_denied"
    COMMAND_BLOCKED = "command_blocked"
    FILE_ACCESS = "file_access"
    SERVICE_CONTROL = "service_control"
    CONTAINER_CONTROL = "container_control"
    SYSTEM_ACCESS = "system_access"


@dataclass
class SecurityContext:
    """Security context for operations."""
    user_id: str
    session_id: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    scopes: List[AccessScope] = None
    security_level: SecurityLevel = SecurityLevel.MEDIUM
    operation_tier: Optional[str] = None
    
    def __post_init__(self):
        if self.scopes is None:
            self.scopes = [AccessScope.OBSERVE_ONLY]


@dataclass
class AuditEvent:
    """Audit event for remote operations."""
    event_type: AuditEventType
    timestamp: datetime
    security_context: SecurityContext
    target: str
    operation: str
    parameters: Dict[str, Any]
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    risk_level: SecurityLevel = SecurityLevel.MEDIUM
    compliance_flags: Set[str] = None
    correlation_id: Optional[str] = None
    
    def __post_init__(self):
        if self.compliance_flags is None:
            self.compliance_flags = set()


class RemoteOperationSecurityManager:
    """Security manager for remote agent operations."""
    
    def __init__(self, audit_logger: AuditLogger):
        """Initialize security manager.
        
        Args:
            audit_logger: Audit logger instance
        """
        self.audit_logger = audit_logger
        self.blocked_commands: Set[str] = set()
        self.blocked_paths: Set[str] = set()
        self.rate_limits: Dict[str, Dict[str, Any]] = {}
        self.security_policies: Dict[str, Dict[str, Any]] = {}
        self._setup_default_policies()
    
    def _setup_default_policies(self):
        """Setup default security policies."""
        
        # Block dangerous commands
        dangerous_commands = {
            'rm -rf', 'del /s', 'format', 'dd if=', 'mkfs', 'fdisk',
            '> /etc/passwd', '> /etc/shadow', 'chmod 777', 'chown root',
            'sudo -i', 'su -', 'exec', 'eval', 'system', 'passthru',
            'shell_exec', 'popen', 'proc_open'
        }
        self.blocked_commands.update(dangerous_commands)
        
        # Block sensitive paths
        sensitive_paths = {
            '/etc/shadow', '/etc/passwd', '/etc/group', '/etc/sudoers',
            '/etc/ssh/ssh_host_', '/root/', '/.ssh/', '/.aws/',
            '/.docker/', '/.kube/', '/var/lib/dpkg/', '/var/lib/apt/',
            '/proc/', '/sys/', '/dev/', '/run/systemd/', '/boot/'
        }
        self.blocked_paths.update(sensitive_paths)
        
        # Setup rate limiting policies
        self.rate_limits = {
            "command_execution": {"max_per_hour": 100, "max_per_minute": 10},
            "file_access": {"max_per_hour": 50, "max_per_minute": 5},
            "service_control": {"max_per_hour": 20, "max_per_minute": 3},
            "container_control": {"max_per_hour": 30, "max_per_minute": 5}
        }
    
    def validate_operation_security(self, 
                                   operation: str,
                                   parameters: Dict[str, Any],
                                   security_context: SecurityContext) -> Tuple[bool, Optional[str]]:
        """Validate operation security.
        
        Args:
            operation: Operation name
            parameters: Operation parameters
            security_context: Security context
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # Check access scope
            if not self._validate_access_scope(operation, security_context.scopes):
                return False, f"Access denied: insufficient scope for operation {operation}"
            
            # Check rate limits
            rate_limit_check = self._check_rate_limit(operation, security_context.user_id)
            if not rate_limit_check[0]:
                return False, f"Rate limit exceeded: {rate_limit_check[1]}"
            
            # Validate operation-specific parameters
            validation_result = self._validate_operation_parameters(operation, parameters)
            if not validation_result[0]:
                return False, validation_result[1]
            
            # Check for command injection patterns
            if self._detect_command_injection(operation, parameters):
                return False, "Potential command injection detected"
            
            # Validate file paths if applicable
            if "path" in parameters:
                path_validation = self._validate_file_path(parameters["path"])
                if not path_validation[0]:
                    return False, path_validation[1]
            
            return True, None
            
        except Exception as e:
            logger.error(f"Security validation error: {str(e)}")
            return False, f"Security validation failed: {str(e)}"
    
    def _validate_access_scope(self, operation: str, scopes: List[AccessScope]) -> bool:
        """Validate if operation is allowed for given scopes.
        
        Args:
            operation: Operation name
            scopes: User access scopes
            
        Returns:
            True if operation is allowed
        """
        # Define operation scope requirements
        scope_requirements = {
            "observe_operations": [
                "get_journald_logs", "get_service_status", "list_remote_services",
                "get_remote_docker_containers", "get_container_logs_remote",
                "read_remote_file", "list_remote_directory", "get_remote_system_status",
                "analyze_service_logs_across_fleet", "check_fleet_service_health"
            ],
            "control_operations": [
                "restart_remote_service", "restart_remote_container",
                "write_remote_file"
            ],
            "admin_operations": [
                "start_remote_service", "stop_remote_service",
                "start_remote_container", "stop_remote_container",
                "delete_remote_file", "execute_remote_command"
            ]
        }
        
        # Check if user has required scope
        has_observe = AccessScope.OBSERVE_ONLY in scopes
        has_limited = AccessScope.LIMITED_CONTROL in scopes
        has_full = AccessScope.FULL_CONTROL in scopes
        has_admin = AccessScope.ADMIN in scopes
        
        # Validate based on operation type
        if operation in scope_requirements["observe_operations"]:
            return has_observe
        elif operation in scope_requirements["control_operations"]:
            return has_limited or has_full or has_admin
        elif operation in scope_requirements["admin_operations"]:
            return has_admin
        
        # Default to observe for unknown operations
        return has_observe
    
    def _check_rate_limit(self, operation: str, user_id: str) -> Tuple[bool, Optional[str]]:
        """Check rate limits for operation.
        
        Args:
            operation: Operation name
            user_id: User identifier
            
        Returns:
            Tuple of (is_allowed, error_message)
        """
        # Determine operation category
        if "file" in operation.lower():
            category = "file_access"
        elif "service" in operation.lower():
            category = "service_control"
        elif "container" in operation.lower() or "docker" in operation.lower():
            category = "container_control"
        else:
            category = "command_execution"
        
        limits = self.rate_limits.get(category, {})
        if not limits:
            return True, None
        
        current_time = datetime.utcnow()
        hour_key = current_time.strftime("%Y%m%d_%H")
        minute_key = current_time.strftime("%Y%m%d_%H%M")
        
        user_key = f"{user_id}:{operation}"
        
        # Initialize counters if needed
        if user_key not in self.security_policies:
            self.security_policies[user_key] = {
                "hourly_count": 0,
                "minute_count": 0,
                "hour_reset": current_time.replace(minute=0, second=0, microsecond=0),
                "minute_reset": current_time.replace(second=0, microsecond=0)
            }
        
        user_policy = self.security_policies[user_key]
        
        # Reset counters if needed
        if current_time >= user_policy["hour_reset"] + timedelta(hours=1):
            user_policy["hourly_count"] = 0
            user_policy["hour_reset"] = current_time.replace(minute=0, second=0, microsecond=0)
        
        if current_time >= user_policy["minute_reset"] + timedelta(minutes=1):
            user_policy["minute_count"] = 0
            user_policy["minute_reset"] = current_time.replace(second=0, microsecond=0)
        
        # Check limits
        if user_policy["hourly_count"] >= limits.get("max_per_hour", 1000):
            return False, f"Hourly rate limit exceeded for {operation}"
        
        if user_policy["minute_count"] >= limits.get("max_per_minute", 100):
            return False, f"Minute rate limit exceeded for {operation}"
        
        # Increment counters
        user_policy["hourly_count"] += 1
        user_policy["minute_count"] += 1
        
        return True, None
    
    def _validate_operation_parameters(self, operation: str, parameters: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate operation parameters for security.
        
        Args:
            operation: Operation name
            parameters: Operation parameters
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Operation-specific parameter validation
        if operation == "read_remote_file" or operation == "write_remote_file":
            return self._validate_file_path(parameters.get("path", ""))
        
        if operation == "restart_remote_service" or operation == "service_control":
            service_name = parameters.get("service", "")
            if not service_name or not self._is_valid_service_name(service_name):
                return False, f"Invalid service name: {service_name}"
        
        if operation == "docker_container_restart" or operation == "container_control":
            container_id = parameters.get("container_id", "")
            if not container_id or not self._is_valid_container_id(container_id):
                return False, f"Invalid container ID: {container_id}"
        
        return True, None
    
    def _validate_file_path(self, path: str) -> Tuple[bool, Optional[str]]:
        """Validate file path for security.
        
        Args:
            path: File path to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not path:
            return False, "File path cannot be empty"
        
        # Check for null bytes and control characters
        if any(ord(c) < 32 and c not in '\t\n' for c in path):
            return False, "Path contains invalid characters"
        
        # Check for directory traversal
        if ".." in path or path.startswith(".."):
            return False, "Directory traversal not allowed"
        
        # Check for absolute paths to sensitive locations
        if os.path.isabs(path):
            if any(path.startswith(blocked) for blocked in self.blocked_paths):
                return False, f"Access to sensitive path not allowed: {path}"
        
        # Check for dangerous patterns
        dangerous_patterns = [
            "/etc/shadow", "/etc/passwd", "/etc/group", "/etc/sudoers",
            "/root/", "/.ssh/", "/.aws/", "/.kube/", "/proc/", "/sys/"
        ]
        
        for pattern in dangerous_patterns:
            if pattern in path:
                return False, f"Dangerous path pattern detected: {pattern}"
        
        return True, None
    
    def _detect_command_injection(self, operation: str, parameters: Dict[str, Any]) -> bool:
        """Detect potential command injection attempts.
        
        Args:
            operation: Operation name
            parameters: Operation parameters
            
        Returns:
            True if command injection detected
        """
        # Check all parameter values for injection patterns
        for value in parameters.values():
            if isinstance(value, str):
                # Common injection patterns
                injection_patterns = [
                    r';\s*(rm|del|format|dd|mkfs|fdisk)',
                    r'&\s*&\s*(rm|del|format)',
                    r'\|\|\s*(rm|del|format)',
                    r'>\s*/etc/',
                    r'<\s*/etc/',
                    r'>>\s*/etc/',
                    r'>\s*/var/',
                    r'>>\s*/var/',
                    r'`[^`]*`',
                    r'\$\([^)]*\)',
                    r'\$\{[^}]*\}',
                    r'eval\s*\(',
                    r'system\s*\(',
                    r'shell_exec\s*\(',
                    r'passthru\s*\('
                ]
                
                import re
                for pattern in injection_patterns:
                    if re.search(pattern, value, re.IGNORECASE):
                        return True
        
        return False
    
    def _is_valid_service_name(self, service_name: str) -> bool:
        """Validate service name.
        
        Args:
            service_name: Service name to validate
            
        Returns:
            True if service name is valid
        """
        if not service_name:
            return False
        
        # Check for valid service name pattern
        import re
        pattern = r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$'
        return bool(re.match(pattern, service_name))
    
    def _is_valid_container_id(self, container_id: str) -> bool:
        """Validate container ID.
        
        Args:
            container_id: Container ID to validate
            
        Returns:
            True if container ID is valid
        """
        if not container_id:
            return False
        
        # Check for valid container ID pattern (64 hex characters or container name)
        import re
        hex_pattern = r'^[a-f0-9]{64}$'
        name_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$'
        
        return bool(re.match(hex_pattern, container_id) or re.match(name_pattern, container_id))


class RemoteOperationAuditor:
    """Comprehensive audit logging for remote operations."""
    
    def __init__(self, audit_logger: AuditLogger):
        """Initialize remote operation auditor.
        
        Args:
            audit_logger: Base audit logger
        """
        self.audit_logger = audit_logger
        self.correlation_ids: Dict[str, str] = {}
        self.session_data: Dict[str, Dict[str, Any]] = {}
    
    def log_operation_start(self, 
                           operation: str,
                           security_context: SecurityContext,
                           target: str,
                           parameters: Dict[str, Any],
                           correlation_id: Optional[str] = None) -> str:
        """Log operation start.
        
        Args:
            operation: Operation name
            security_context: Security context
            target: Target identifier
            parameters: Operation parameters
            correlation_id: Optional correlation ID
            
        Returns:
            Generated correlation ID
        """
        if not correlation_id:
            correlation_id = self._generate_correlation_id()
        
        event = AuditEvent(
            event_type=AuditEventType.OPERATION_EXECUTED,
            timestamp=datetime.utcnow(),
            security_context=security_context,
            target=target,
            operation=operation,
            parameters=self._sanitize_parameters(parameters),
            correlation_id=correlation_id,
            risk_level=self._calculate_risk_level(operation, parameters)
        )
        
        self._write_audit_event(event, "operation_start")
        return correlation_id
    
    def log_operation_success(self, 
                             correlation_id: str,
                             result: Dict[str, Any],
                             execution_time: float):
        """Log successful operation completion.
        
        Args:
            correlation_id: Operation correlation ID
            result: Operation result
            execution_time: Operation execution time
        """
        if correlation_id in self.correlation_ids:
            session_data = self.session_data.get(self.correlation_ids[correlation_id], {})
            
            event = AuditEvent(
                event_type=AuditEventType.OPERATION_EXECUTED,
                timestamp=datetime.utcnow(),
                security_context=session_data.get("security_context"),
                target=session_data.get("target"),
                operation=session_data.get("operation"),
                parameters=session_data.get("parameters"),
                result=self._sanitize_result(result),
                correlation_id=correlation_id,
                risk_level=self._calculate_risk_level(
                    session_data.get("operation", ""), 
                    session_data.get("parameters", {})
                )
            )
            
            # Add performance metrics
            event.compliance_flags.add(f"execution_time_{execution_time:.2f}s")
            
            self._write_audit_event(event, "operation_success")
    
    def log_operation_failure(self, 
                             correlation_id: str,
                             error: str,
                             execution_time: Optional[float] = None):
        """Log failed operation.
        
        Args:
            correlation_id: Operation correlation ID
            error: Error message
            execution_time: Operation execution time
        """
        if correlation_id in self.correlation_ids:
            session_data = self.session_data.get(self.correlation_ids[correlation_id], {})
            
            event = AuditEvent(
                event_type=AuditEventType.OPERATION_FAILED,
                timestamp=datetime.utcnow(),
                security_context=session_data.get("security_context"),
                target=session_data.get("target"),
                operation=session_data.get("operation"),
                parameters=session_data.get("parameters"),
                error=error,
                correlation_id=correlation_id,
                risk_level=SecurityLevel.HIGH  # Failures are higher risk
            )
            
            if execution_time:
                event.compliance_flags.add(f"execution_time_{execution_time:.2f}s")
            
            self._write_audit_event(event, "operation_failure")
    
    def log_security_violation(self, 
                              operation: str,
                              security_context: SecurityContext,
                              target: str,
                              violation_type: str,
                              details: str):
        """Log security violation.
        
        Args:
            operation: Operation that was blocked
            security_context: Security context
            target: Target identifier
            violation_type: Type of violation
            details: Violation details
        """
        event = AuditEvent(
            event_type=AuditEventType.SECURITY_VIOLATION,
            timestamp=datetime.utcnow(),
            security_context=security_context,
            target=target,
            operation=operation,
            parameters={"violation_type": violation_type, "details": details},
            error=details,
            risk_level=SecurityLevel.CRITICAL
        )
        
        self._write_audit_event(event, "security_violation")
    
    def log_access_denied(self, 
                         operation: str,
                         security_context: SecurityContext,
                         target: str,
                         reason: str):
        """Log access denied event.
        
        Args:
            operation: Operation that was denied
            security_context: Security context
            target: Target identifier
            reason: Denial reason
        """
        event = AuditEvent(
            event_type=AuditEventType.ACCESS_DENIED,
            timestamp=datetime.utcnow(),
            security_context=security_context,
            target=target,
            operation=operation,
            parameters={"reason": reason},
            error=reason,
            risk_level=SecurityLevel.HIGH
        )
        
        self._write_audit_event(event, "access_denied")
    
    def log_connection_event(self, 
                            event_type: AuditEventType,
                            security_context: SecurityContext,
                            target: str,
                            connection_info: Dict[str, Any]):
        """Log connection-related events.
        
        Args:
            event_type: Type of connection event
            security_context: Security context
            target: Target identifier
            connection_info: Connection information
        """
        event = AuditEvent(
            event_type=event_type,
            timestamp=datetime.utcnow(),
            security_context=security_context,
            target=target,
            operation="connection_management",
            parameters=connection_info,
            risk_level=SecurityLevel.MEDIUM
        )
        
        self._write_audit_event(event, "connection_event")
    
    def _generate_correlation_id(self) -> str:
        """Generate unique correlation ID.
        
        Returns:
            Correlation ID string
        """
        import uuid
        return str(uuid.uuid4())
    
    def _calculate_risk_level(self, operation: str, parameters: Dict[str, Any]) -> SecurityLevel:
        """Calculate risk level for operation.
        
        Args:
            operation: Operation name
            parameters: Operation parameters
            
        Returns:
            Security level
        """
        # High-risk operations
        high_risk_operations = {
            "restart_remote_service", "stop_remote_service", "write_remote_file",
            "docker_container_restart", "stop_remote_container"
        }
        
        # Critical-risk operations
        critical_risk_operations = {
            "delete_remote_file", "start_remote_service", "stop_remote_service",
            "start_remote_container", "stop_remote_container", "execute_remote_command"
        }
        
        if operation in critical_risk_operations:
            return SecurityLevel.CRITICAL
        elif operation in high_risk_operations:
            return SecurityLevel.HIGH
        elif "read" in operation.lower() or "list" in operation.lower():
            return SecurityLevel.LOW
        else:
            return SecurityLevel.MEDIUM
    
    def _sanitize_parameters(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize parameters for audit logging.
        
        Args:
            parameters: Raw parameters
            
        Returns:
            Sanitized parameters
        """
        sanitized = {}
        sensitive_keys = {"password", "token", "key", "secret", "auth", "credential"}
        
        for key, value in parameters.items():
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = "<REDACTED>"
            elif isinstance(value, str) and len(value) > 1000:
                sanitized[key] = f"<TRUNCATED: {len(value)} chars>"
            else:
                try:
                    json.dumps(value)
                    sanitized[key] = value
                except Exception:
                    sanitized[key] = str(type(value))
        
        return sanitized
    
    def _sanitize_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize result for audit logging.
        
        Args:
            result: Raw result
            
        Returns:
            Sanitized result
        """
        # Similar to parameter sanitization
        return self._sanitize_parameters(result)
    
    def _write_audit_event(self, event: AuditEvent, log_type: str):
        """Write audit event to log.
        
        Args:
            event: Audit event
            log_type: Type of log entry
        """
        try:
            # Store session data for correlation
            if event.correlation_id:
                self.correlation_ids[event.correlation_id] = event.security_context.session_id
                
                if event.security_context.session_id not in self.session_data:
                    self.session_data[event.security_context.session_id] = {}
                
                self.session_data[event.security_context.session_id].update({
                    "security_context": event.security_context,
                    "target": event.target,
                    "operation": event.operation,
                    "parameters": event.parameters
                })
            
            # Convert event to audit log format
            audit_data = {
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type.value,
                "log_type": log_type,
                "user_id": event.security_context.user_id,
                "session_id": event.security_context.session_id,
                "target": event.target,
                "operation": event.operation,
                "parameters": event.parameters,
                "result": event.result,
                "error": event.error,
                "risk_level": event.risk_level.value,
                "compliance_flags": list(event.compliance_flags),
                "correlation_id": event.correlation_id,
                "security_level": event.security_context.security_level.value,
                "scopes": [scope.value for scope in event.security_context.scopes]
            }
            
            # Write to audit log
            self.audit_logger.log(
                tool=f"remote_agent_{event.operation}",
                args=audit_data,
                result={"audit_event": True},
                subject=event.security_context.user_id,
                risk_level=event.risk_level.value
            )
            
        except Exception as e:
            logger.error(f"Failed to write audit event: {str(e)}")


# Global instances
_audit_logger = None
_security_manager = None
_auditor = None


def get_remote_security_manager() -> RemoteOperationSecurityManager:
    """Get global security manager instance."""
    global _security_manager, _audit_logger
    
    if _security_manager is None:
        if _audit_logger is None:
            _audit_logger = AuditLogger()
        _security_manager = RemoteOperationSecurityManager(_audit_logger)
    
    return _security_manager


def get_remote_operation_auditor() -> RemoteOperationAuditor:
    """Get global auditor instance."""
    global _auditor, _audit_logger
    
    if _auditor is None:
        if _audit_logger is None:
            _audit_logger = AuditLogger()
        _auditor = RemoteOperationAuditor(_audit_logger)
    
    return _auditor


def create_security_context(user_id: str, 
                           session_id: str,
                           scopes: Optional[List[AccessScope]] = None,
                           security_level: SecurityLevel = SecurityLevel.MEDIUM) -> SecurityContext:
    """Create security context for operation.
    
    Args:
        user_id: User identifier
        session_id: Session identifier
        scopes: Access scopes
        security_level: Security level
        
    Returns:
        Security context
    """
    return SecurityContext(
        user_id=user_id,
        session_id=session_id,
        scopes=scopes or [AccessScope.OBSERVE_ONLY],
        security_level=security_level
    )