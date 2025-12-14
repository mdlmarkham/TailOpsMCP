"""
Proxmox Security Integration and Audit Logging

Provides comprehensive security integration for Proxmox operations including:
- Secure credential management
- Access control integration
- Comprehensive audit logging for all Proxmox operations
- Secure logging with sensitive data redaction
- Policy enforcement integration
"""

import logging
import json
import hashlib
import time
import os
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Union
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum

from src.utils.audit_enhanced import StructuredAuditLogger, AuditEventType, AuditLogEntry
from src.models.proxmox_models import ProxmoxAPICredentials
from src.models.execution import ExecutionResult, ExecutionStatus, ExecutionSeverity

logger = logging.getLogger(__name__)


class ProxmoxSecurityEventType(str, Enum):
    """Proxmox-specific security event types."""
    CONTAINER_CREATE = "container_create"
    CONTAINER_DELETE = "container_delete"
    CONTAINER_START = "container_start"
    CONTAINER_STOP = "container_stop"
    CONTAINER_REBOOT = "container_reboot"
    CONTAINER_CLONE = "container_clone"
    CONTAINER_MIGRATE = "container_migrate"
    
    VM_CREATE = "vm_create"
    VM_DELETE = "vm_delete"
    VM_START = "vm_start"
    VM_STOP = "vm_stop"
    VM_REBOOT = "vm_reboot"
    VM_CLONE = "vm_clone"
    VM_MIGRATE = "vm_migrate"
    
    SNAPSHOT_CREATE = "snapshot_create"
    SNAPSHOT_DELETE = "snapshot_delete"
    SNAPSHOT_RESTORE = "snapshot_restore"
    
    BACKUP_CREATE = "backup_create"
    BACKUP_RESTORE = "backup_restore"
    BACKUP_DELETE = "backup_delete"
    
    DISCOVERY_OPERATION = "discovery_operation"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    POLICY_VIOLATION = "policy_violation"
    SECURITY_EVENT = "security_event"


class SecuritySeverity(str, Enum):
    """Security event severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ProxmoxSecurityContext:
    """Proxmox security context for operations."""
    user: str
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    mcp_client: Optional[str] = None
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []


@dataclass
class ProxmoxAuditEntry:
    """Proxmox-specific audit log entry."""
    timestamp: str
    event_type: ProxmoxSecurityEventType
    security_context: ProxmoxSecurityContext
    target_host: str
    operation: str
    resource_type: str  # container, vm, snapshot, backup, etc.
    resource_id: Optional[Union[int, str]] = None
    parameters: Dict[str, Any] = None
    result: Dict[str, Any] = None
    duration_ms: float = 0.0
    authorized: bool = True
    policy_decision: Optional[str] = None
    risk_level: SecuritySeverity = SecuritySeverity.LOW
    compliance_tags: List[str] = None
    error_details: Optional[str] = None
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = {}
        if self.result is None:
            self.result = {}
        if self.compliance_tags is None:
            self.compliance_tags = []
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat() + "Z"


class ProxmoxSecurityLogger:
    """Proxmox security logger with comprehensive audit trail."""
    
    def __init__(self, 
                 log_path: str = "./logs/proxmox-security.jsonl",
                 audit_logger: Optional[StructuredAuditLogger] = None,
                 redact_sensitive_data: bool = True):
        """Initialize Proxmox security logger.
        
        Args:
            log_path: Path to security log file
            audit_logger: Existing audit logger to integrate with
            redact_sensitive_data: Whether to redact sensitive data
        """
        self.log_path = Path(log_path)
        self.audit_logger = audit_logger
        self.redact_sensitive_data = redact_sensitive_data
        
        # Ensure log directory exists
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Security event counters
        self.event_counters = {
            event_type.value: 0 
            for event_type in ProxmoxSecurityEventType
        }
        
        # Rate limiting
        self.rate_limits = {}
        
        logger.info(f"Proxmox security logger initialized: {log_path}")
    
    def log_security_event(self, 
                          event_type: ProxmoxSecurityEventType,
                          security_context: ProxmoxSecurityContext,
                          target_host: str,
                          operation: str,
                          resource_type: str,
                          resource_id: Optional[Union[int, str]] = None,
                          parameters: Optional[Dict[str, Any]] = None,
                          result: Optional[Dict[str, Any]] = None,
                          duration_ms: float = 0.0,
                          authorized: bool = True,
                          policy_decision: Optional[str] = None,
                          risk_level: SecuritySeverity = SecuritySeverity.LOW,
                          compliance_tags: Optional[List[str]] = None,
                          error_details: Optional[str] = None) -> bool:
        """Log a security event.
        
        Args:
            event_type: Type of security event
            security_context: Security context information
            target_host: Proxmox host being operated on
            operation: Operation being performed
            resource_type: Type of resource (container, vm, etc.)
            resource_id: ID of the resource
            parameters: Operation parameters
            result: Operation result
            duration_ms: Operation duration
            authorized: Whether operation was authorized
            policy_decision: Policy decision that led to this result
            risk_level: Risk level of the operation
            compliance_tags: Compliance-related tags
            error_details: Error details if operation failed
            
        Returns:
            True if event was logged successfully
        """
        try:
            # Create audit entry
            entry = ProxmoxAuditEntry(
                event_type=event_type,
                security_context=security_context,
                target_host=target_host,
                operation=operation,
                resource_type=resource_type,
                resource_id=resource_id,
                parameters=parameters or {},
                result=result or {},
                duration_ms=duration_ms,
                authorized=authorized,
                policy_decision=policy_decision,
                risk_level=risk_level,
                compliance_tags=compliance_tags or [],
                error_details=error_details
            )
            
            # Sanitize sensitive data
            if self.redact_sensitive_data:
                entry = self._sanitize_entry(entry)
            
            # Write to security log
            success = self._write_security_log(entry)
            
            # Write to audit logger if available
            if self.audit_logger and success:
                self._write_audit_log(entry)
            
            # Update counters
            self.event_counters[event_type.value] += 1
            
            # Log to console for high-severity events
            if risk_level in [SecuritySeverity.HIGH, SecuritySeverity.CRITICAL]:
                logger.warning(f"High-risk Proxmox operation: {operation} on {target_host}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")
            return False
    
    def _sanitize_entry(self, entry: ProxmoxAuditEntry) -> ProxmoxAuditEntry:
        """Sanitize audit entry to remove sensitive data.
        
        Args:
            entry: Original audit entry
            
        Returns:
            Sanitized audit entry
        """
        # Create a copy to avoid modifying the original
        sanitized = ProxmoxAuditEntry(
            timestamp=entry.timestamp,
            event_type=entry.event_type,
            security_context=entry.security_context,
            target_host=entry.target_host,
            operation=entry.operation,
            resource_type=entry.resource_type,
            resource_id=entry.resource_id,
            parameters=self._sanitize_parameters(entry.parameters),
            result=self._sanitize_parameters(entry.result),
            duration_ms=entry.duration_ms,
            authorized=entry.authorized,
            policy_decision=entry.policy_decision,
            risk_level=entry.risk_level,
            compliance_tags=entry.compliance_tags.copy(),
            error_details=entry.error_details
        )
        
        return sanitized
    
    def _sanitize_parameters(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize parameters to remove sensitive data.
        
        Args:
            parameters: Parameters to sanitize
            
        Returns:
            Sanitized parameters
        """
        if not parameters:
            return {}
        
        sanitized = {}
        
        # Sensitive field patterns
        sensitive_patterns = [
            'password', 'passwd', 'pwd',
            'token', 'api_token', 'auth_token',
            'secret', 'key', 'private_key',
            'credential', 'auth', 'login',
            'ssn', 'credit_card', 'bank'
        ]
        
        for key, value in parameters.items():
            key_lower = key.lower()
            
            # Check if key contains sensitive pattern
            if any(pattern in key_lower for pattern in sensitive_patterns):
                sanitized[key] = "<REDACTED>"
            elif isinstance(value, str):
                # Check string values for sensitive patterns
                if any(pattern in value.lower() for pattern in sensitive_patterns):
                    sanitized[key] = "<REDACTED>"
                elif len(value) > 100:  # Truncate long strings
                    sanitized[key] = value[:50] + "..."
                else:
                    sanitized[key] = value
            else:
                # For non-string values, keep as-is unless they're very large
                try:
                    value_str = json.dumps(value)
                    if len(value_str) > 1000:
                        sanitized[key] = f"<LARGE_DATA:{type(value).__name__}>"
                    else:
                        sanitized[key] = value
                except Exception:
                    sanitized[key] = f"<{type(value).__name__}>"
        
        return sanitized
    
    def _write_security_log(self, entry: ProxmoxAuditEntry) -> bool:
        """Write entry to security log file.
        
        Args:
            entry: Audit entry to write
            
        Returns:
            True if write successful
        """
        try:
            # Convert to JSON
            log_data = asdict(entry)
            log_line = json.dumps(log_data, default=str) + "\n"
            
            # Write to file
            with open(self.log_path, 'a', encoding='utf-8') as f:
                f.write(log_line)
            
            return True
        
        except Exception as e:
            logger.error(f"Failed to write security log: {e}")
            return False
    
    def _write_audit_log(self, entry: ProxmoxAuditEntry):
        """Write entry to structured audit logger.
        
        Args:
            entry: Audit entry to write
        """
        try:
            # Map Proxmox event types to general audit event types
            event_type_mapping = {
                ProxmoxSecurityEventType.CONTAINER_CREATE: AuditEventType.REMOTE_OPERATION,
                ProxmoxSecurityEventType.CONTAINER_DELETE: AuditEventType.REMOTE_OPERATION,
                ProxmoxSecurityEventType.CONTAINER_START: AuditEventType.REMOTE_OPERATION,
                ProxmoxSecurityEventType.CONTAINER_STOP: AuditEventType.REMOTE_OPERATION,
                ProxmoxSecurityEventType.VM_CREATE: AuditEventType.REMOTE_OPERATION,
                ProxmoxSecurityEventType.VM_DELETE: AuditEventType.REMOTE_OPERATION,
                ProxmoxSecurityEventType.AUTHENTICATION: AuditEventType.CREDENTIAL_ACCESS,
                ProxmoxSecurityEventType.AUTHORIZATION: AuditEventType.POLICY_DECISION,
                ProxmoxSecurityEventType.POLICY_VIOLATION: AuditEventType.POLICY_DECISION,
            }
            
            audit_event_type = event_type_mapping.get(
                entry.event_type, 
                AuditEventType.REMOTE_OPERATION
            )
            
            # Create audit log entry
            audit_entry = AuditLogEntry(
                timestamp=entry.timestamp,
                event_type=audit_event_type,
                actor=entry.security_context.user,
                target=f"proxmox://{entry.target_host}",
                operation=entry.operation,
                parameters=entry.parameters,
                result_hash=self._hash_result(entry.result),
                duration_ms=entry.duration_ms,
                authorized=entry.authorized,
                policy_rule=entry.policy_decision
            )
            
            self.audit_logger.log_entry(audit_entry)
        
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
    
    def _hash_result(self, result: Dict[str, Any]) -> str:
        """Create hash of result for integrity verification.
        
        Args:
            result: Result data to hash
            
        Returns:
            SHA-256 hash of the result
        """
        try:
            result_str = json.dumps(result, sort_keys=True, default=str)
            return hashlib.sha256(result_str.encode()).hexdigest()
        except Exception:
            return hashlib.sha256(str(result).encode()).hexdigest()
    
    def check_rate_limit(self, 
                        user: str, 
                        operation: str, 
                        limit: int = 60, 
                        window: int = 3600) -> bool:
        """Check if operation is within rate limits.
        
        Args:
            user: User performing the operation
            operation: Operation being performed
            limit: Maximum operations allowed
            window: Time window in seconds
            
        Returns:
            True if within rate limit, False if exceeded
        """
        current_time = time.time()
        key = f"{user}:{operation}"
        
        # Get or create rate limit tracker
        if key not in self.rate_limits:
            self.rate_limits[key] = []
        
        # Clean old entries
        cutoff_time = current_time - window
        self.rate_limits[key] = [
            timestamp for timestamp in self.rate_limits[key] 
            if timestamp > cutoff_time
        ]
        
        # Check if limit exceeded
        if len(self.rate_limits[key]) >= limit:
            return False
        
        # Add current operation
        self.rate_limits[key].append(current_time)
        return True
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get security summary statistics.
        
        Returns:
            Dictionary with security statistics
        """
        return {
            "event_counts": self.event_counters.copy(),
            "total_events": sum(self.event_counters.values()),
            "log_file": str(self.log_path),
            "last_updated": datetime.utcnow().isoformat() + "Z"
        }


class ProxmoxSecurityManager:
    """Proxmox security manager for credential and access control."""
    
    def __init__(self, security_logger: ProxmoxSecurityLogger):
        """Initialize Proxmox security manager.
        
        Args:
            security_logger: Security logger instance
        """
        self.security_logger = security_logger
        self.credentials_cache: Dict[str, ProxmoxAPICredentials] = {}
        self.access_control_rules: Dict[str, Any] = {}
        
        logger.info("Proxmox security manager initialized")
    
    def validate_credentials(self, 
                           credentials: ProxmoxAPICredentials,
                           security_context: ProxmoxSecurityContext) -> bool:
        """Validate Proxmox credentials with security checks.
        
        Args:
            credentials: Credentials to validate
            security_context: Security context
            
        Returns:
            True if credentials are valid and authorized
        """
        try:
            # Validate credential format
            validation_errors = credentials.validate()
            if validation_errors:
                self.security_logger.log_security_event(
                    event_type=ProxmoxSecurityEventType.AUTHENTICATION,
                    security_context=security_context,
                    target_host=credentials.host,
                    operation="validate_credentials",
                    resource_type="credentials",
                    authorized=False,
                    risk_level=SecuritySeverity.HIGH,
                    error_details=f"Validation errors: {validation_errors}"
                )
                return False
            
            # Check access permissions
            if not self._check_access_permissions(credentials, security_context):
                self.security_logger.log_security_event(
                    event_type=ProxmoxSecurityEventType.AUTHORIZATION,
                    security_context=security_context,
                    target_host=credentials.host,
                    operation="validate_credentials",
                    resource_type="credentials",
                    authorized=False,
                    risk_level=SecuritySeverity.HIGH,
                    error_details="Access denied by policy"
                )
                return False
            
            # Log successful validation
            self.security_logger.log_security_event(
                event_type=ProxmoxSecurityEventType.AUTHENTICATION,
                security_context=security_context,
                target_host=credentials.host,
                operation="validate_credentials",
                resource_type="credentials",
                authorized=True,
                risk_level=SecuritySeverity.LOW
            )
            
            return True
        
        except Exception as e:
            logger.error(f"Credential validation error: {e}")
            return False
    
    def _check_access_permissions(self, 
                                credentials: ProxmoxAPICredentials,
                                security_context: ProxmoxSecurityContext) -> bool:
        """Check if user has access permissions for the credentials.
        
        Args:
            credentials: Credentials to check
            security_context: Security context
            
        Returns:
            True if access is allowed
        """
        # This would integrate with your access control system
        # For now, implement basic checks
        
        # Check if user is allowed to access this host
        allowed_hosts = self._get_allowed_hosts(security_context.user)
        if allowed_hosts and credentials.host not in allowed_hosts:
            return False
        
        # Check if user has required permissions
        required_permissions = ["proxmox:read", "proxmox:write"]
        user_permissions = self._get_user_permissions(security_context.user)
        
        if not any(perm in user_permissions for perm in required_permissions):
            return False
        
        return True
    
    def _get_allowed_hosts(self, user: str) -> List[str]:
        """Get list of hosts user is allowed to access.
        
        Args:
            user: User to check
            
        Returns:
            List of allowed host addresses
        """
        # This would query your access control system
        # For now, return empty list (deny all)
        return []
    
    def _get_user_permissions(self, user: str) -> List[str]:
        """Get permissions for a user.
        
        Args:
            user: User to check
            
        Returns:
            List of user permissions
        """
        # This would query your access control system
        # For now, return basic permissions
        return ["proxmox:read", "proxmox:write"]
    
    def cache_credentials(self, 
                         credentials: ProxmoxAPICredentials,
                         security_context: ProxmoxSecurityContext) -> bool:
        """Securely cache credentials.
        
        Args:
            credentials: Credentials to cache
            security_context: Security context
            
        Returns:
            True if cached successfully
        """
        try:
            # Create cache key
            cache_key = f"{credentials.host}:{credentials.username}"
            
            # Store in memory cache (in production, use secure storage)
            self.credentials_cache[cache_key] = credentials
            
            # Log credential caching
            self.security_logger.log_security_event(
                event_type=ProxmoxSecurityEventType.AUTHENTICATION,
                security_context=security_context,
                target_host=credentials.host,
                operation="cache_credentials",
                resource_type="credentials",
                authorized=True,
                risk_level=SecuritySeverity.MEDIUM
            )
            
            return True
        
        except Exception as e:
            logger.error(f"Failed to cache credentials: {e}")
            return False
    
    def get_cached_credentials(self, 
                             host: str, 
                             username: str) -> Optional[ProxmoxAPICredentials]:
        """Get cached credentials.
        
        Args:
            host: Host address
            username: Username
            
        Returns:
            Cached credentials or None
        """
        cache_key = f"{host}:{username}"
        return self.credentials_cache.get(cache_key)
    
    def clear_credentials_cache(self, security_context: ProxmoxSecurityContext):
        """Clear credentials cache.
        
        Args:
            security_context: Security context
        """
        try:
            cache_size = len(self.credentials_cache)
            self.credentials_cache.clear()
            
            # Log cache clearing
            self.security_logger.log_security_event(
                event_type=ProxmoxSecurityEventType.SECURITY_EVENT,
                security_context=security_context,
                target_host="cache",
                operation="clear_credentials_cache",
                resource_type="cache",
                authorized=True,
                risk_level=SecuritySeverity.MEDIUM,
                parameters={"cache_size": cache_size}
            )
        
        except Exception as e:
            logger.error(f"Failed to clear credentials cache: {e}")


# Audit operation decorators for easy integration

def audit_proxmox_operation(event_type: ProxmoxSecurityEventType,
                          resource_type: str,
                          risk_level: SecuritySeverity = SecuritySeverity.LOW,
                          compliance_tags: Optional[List[str]] = None):
    """Decorator to automatically audit Proxmox operations.
    
    Args:
        event_type: Type of security event
        resource_type: Type of resource being operated on
        risk_level: Risk level of the operation
        compliance_tags: Compliance-related tags
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Extract security context from arguments
            security_context = None
            target_host = None
            resource_id = None
            
            # Look for security context in arguments
            for arg in args:
                if isinstance(arg, ProxmoxSecurityContext):
                    security_context = arg
                    break
            
            # Look for host and resource ID in keyword arguments
            target_host = kwargs.get('host') or kwargs.get('target_host')
            resource_id = kwargs.get('vmid') or kwargs.get('container_id') or kwargs.get('resource_id')
            
            # Default security context if not provided
            if not security_context:
                security_context = ProxmoxSecurityContext(user="system")
            
            # Default target host if not provided
            if not target_host:
                target_host = "unknown"
            
            # Create security logger
            security_logger = getattr(wrapper, '_security_logger', None)
            if not security_logger:
                security_logger = ProxmoxSecurityLogger()
                wrapper._security_logger = security_logger
            
            # Start timing
            start_time = time.time()
            
            try:
                # Execute the function
                result = await func(*args, **kwargs)
                duration_ms = (time.time() - start_time) * 1000
                
                # Log successful operation
                security_logger.log_security_event(
                    event_type=event_type,
                    security_context=security_context,
                    target_host=target_host,
                    operation=func.__name__,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    result={"status": "success", "data": result},
                    duration_ms=duration_ms,
                    authorized=True,
                    risk_level=risk_level,
                    compliance_tags=compliance_tags or []
                )
                
                return result
            
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                
                # Log failed operation
                security_logger.log_security_event(
                    event_type=event_type,
                    security_context=security_context,
                    target_host=target_host,
                    operation=func.__name__,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    duration_ms=duration_ms,
                    authorized=False,
                    risk_level=risk_level,
                    error_details=str(e)
                )
                
                raise
        
        return wrapper
    return decorator


# Integration functions

def create_proxmox_security_logger(config: Optional[Dict[str, Any]] = None) -> ProxmoxSecurityLogger:
    """Create Proxmox security logger with configuration.
    
    Args:
        config: Security configuration
        
    Returns:
        Configured ProxmoxSecurityLogger
    """
    config = config or {}
    
    log_path = config.get("log_path", "./logs/proxmox-security.jsonl")
    redact_sensitive = config.get("redact_sensitive_data", True)
    
    return ProxmoxSecurityLogger(
        log_path=log_path,
        redact_sensitive_data=redact_sensitive
    )


def create_proxmox_security_manager(security_logger: ProxmoxSecurityLogger) -> ProxmoxSecurityManager:
    """Create Proxmox security manager.
    
    Args:
        security_logger: Security logger instance
        
    Returns:
        Configured ProxmoxSecurityManager
    """
    return ProxmoxSecurityManager(security_logger)