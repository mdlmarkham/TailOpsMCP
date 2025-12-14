"""
Comprehensive security audit logging system for complete security trace.

This module provides enhanced audit logging capabilities that capture:
- Complete security operation traces
- Identity events and authentication flows
- Policy decisions and enforcement
- Security violations and threats
- Access control decisions
- Compliance evidence
"""

import datetime
import json
import logging
import os
import threading
from typing import Any, Dict, List, Optional, Union
from dataclasses import asdict
import sqlite3
import hashlib

from src.models.security_models import (
    SecurityOperation, OperationOutcome, IdentityEvent, PolicyDecision,
    SecurityViolation, AccessAttempt, SecurityAlert, InitiatorType,
    AlertSeverity, AlertType, RiskLevel, AccessDecision
)
from src.utils.audit import AuditLogger as BaseAuditLogger


logger = logging.getLogger(__name__)


class SecurityAuditLogger:
    """Enhanced audit logging for complete security trace."""
    
    def __init__(self, db_path: Optional[str] = None, enable_real_time: bool = True):
        """Initialize the security audit logger.
        
        Args:
            db_path: Path to SQLite database for structured audit data
            enable_real_time: Enable real-time processing and correlation
        """
        self.enable_real_time = enable_real_time
        self.db_path = db_path or os.getenv("SECURITY_AUDIT_DB", "./logs/security_audit.db")
        self.operation_cache: Dict[str, SecurityOperation] = {}
        self.correlation_cache: Dict[str, List[str]] = {}
        
        # Initialize base audit logger for backward compatibility
        self.base_logger = BaseAuditLogger(
            path=os.getenv("SECURITY_AUDIT_LOG", "./logs/security_audit.log")
        )
        
        # Ensure directories exist
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        os.makedirs(os.path.dirname(self.base_logger.path), exist_ok=True)
        
        # Initialize database
        self._init_database()
        
        # Thread lock for thread-safe operations
        self._lock = threading.RLock()
        
        logger.info(f"Security audit logger initialized with database: {self.db_path}")

    def _init_database(self) -> None:
        """Initialize SQLite database for structured audit data."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_audit_logs (
                    id TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL,
                    timestamp DATETIME NOT NULL,
                    initiator_type TEXT NOT NULL,
                    initiator_identity TEXT,
                    operation_type TEXT NOT NULL,
                    target_resources TEXT NOT NULL,
                    operation_parameters TEXT,
                    risk_level TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    outcome_details TEXT,
                    correlation_id TEXT,
                    session_id TEXT,
                    source_ip TEXT,
                    user_agent TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS identity_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp DATETIME NOT NULL,
                    event_type TEXT NOT NULL,
                    identity TEXT NOT NULL,
                    event_details TEXT,
                    source_ip TEXT,
                    user_agent TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS policy_decisions (
                    decision_id TEXT PRIMARY KEY,
                    timestamp DATETIME NOT NULL,
                    policy_name TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    policy_context TEXT,
                    enforcement_details TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_violations (
                    violation_id TEXT PRIMARY KEY,
                    timestamp DATETIME NOT NULL,
                    violation_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    affected_resources TEXT,
                    implicated_identities TEXT,
                    violation_details TEXT,
                    automated_response TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS access_attempts (
                    attempt_id TEXT PRIMARY KEY,
                    timestamp DATETIME NOT NULL,
                    identity TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    action TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    decision_reason TEXT,
                    risk_score REAL,
                    enforcement_details TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp DATETIME NOT NULL,
                    severity TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    affected_resources TEXT,
                    implicated_identities TEXT,
                    status TEXT NOT NULL,
                    assigned_to TEXT,
                    resolved_at DATETIME,
                    resolution_details TEXT,
                    recommended_actions TEXT,
                    automated_response TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for better query performance
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_operation_correlation 
                ON security_audit_logs(correlation_id)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_identity_events_timestamp 
                ON identity_events(timestamp)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_violations_severity 
                ON security_violations(severity)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_status 
                ON security_alerts(status)
            """)

    async def log_operation_initiated(self, operation: SecurityOperation) -> str:
        """Log that a security operation has been initiated.
        
        Args:
            operation: The security operation that was initiated
            
        Returns:
            Operation ID for correlation
        """
        with self._lock:
            try:
                # Cache operation for outcome logging
                self.operation_cache[operation.operation_id] = operation
                
                # Add to correlation cache
                if operation.correlation_id:
                    if operation.correlation_id not in self.correlation_cache:
                        self.correlation_cache[operation.correlation_id] = []
                    self.correlation_cache[operation.correlation_id].append(operation.operation_id)
                
                # Store in database
                await self._store_operation_initiated(operation)
                
                # Also log to base audit logger for backward compatibility
                await self._log_to_base_audit(operation, "initiated")
                
                # Real-time correlation if enabled
                if self.enable_real_time:
                    await self._correlate_operations(operation)
                
                logger.debug(f"Logged operation initiated: {operation.operation_id}")
                return operation.operation_id
                
            except Exception as e:
                logger.error(f"Failed to log operation initiated: {e}")
                raise

    async def log_operation_outcome(self, operation_id: str, outcome: OperationOutcome) -> None:
        """Log the outcome of a security operation.
        
        Args:
            operation_id: ID of the operation
            outcome: Outcome of the operation
        """
        with self._lock:
            try:
                # Get cached operation
                operation = self.operation_cache.get(operation_id)
                if not operation:
                    logger.warning(f"Operation not found in cache: {operation_id}")
                    return
                
                # Update operation with outcome
                operation.outcome = outcome
                
                # Store outcome in database
                await self._store_operation_outcome(operation_id, outcome)
                
                # Update base audit log
                await self._log_to_base_audit(operation, "completed", outcome)
                
                # Real-time correlation
                if self.enable_real_time:
                    await self._correlate_outcome(operation, outcome)
                
                # Clean up cache
                del self.operation_cache[operation_id]
                
                logger.debug(f"Logged operation outcome: {operation_id}")
                
            except Exception as e:
                logger.error(f"Failed to log operation outcome: {e}")
                raise

    async def log_identity_event(self, identity_event: IdentityEvent) -> None:
        """Log an identity-related event.
        
        Args:
            identity_event: The identity event to log
        """
        with self._lock:
            try:
                # Store in database
                await self._store_identity_event(identity_event)
                
                # Also log to base audit logger
                base_record = {
                    "timestamp": identity_event.timestamp.isoformat(),
                    "event_type": "identity_event",
                    "event_subtype": identity_event.event_type,
                    "identity": identity_event.identity.to_dict(),
                    "event_details": identity_event.event_details,
                    "source_ip": identity_event.source_ip,
                    "user_agent": identity_event.user_agent
                }
                
                with open(self.base_logger.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(base_record, separators=(",", ":")) + "\n")
                
                # Real-time monitoring
                if self.enable_real_time:
                    await self._monitor_identity_event(identity_event)
                
                logger.debug(f"Logged identity event: {identity_event.event_id}")
                
            except Exception as e:
                logger.error(f"Failed to log identity event: {e}")
                raise

    async def log_policy_decision(self, policy_decision: PolicyDecision) -> None:
        """Log a policy decision.
        
        Args:
            policy_decision: The policy decision to log
        """
        with self._lock:
            try:
                # Store in database
                await self._store_policy_decision(policy_decision)
                
                # Also log to base audit logger
                base_record = {
                    "timestamp": policy_decision.timestamp.isoformat(),
                    "event_type": "policy_decision",
                    "policy_name": policy_decision.policy_name,
                    "decision": policy_decision.decision,
                    "reason": policy_decision.reason,
                    "policy_context": policy_decision.policy_context,
                    "enforcement_details": policy_decision.enforcement_details
                }
                
                with open(self.base_logger.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(base_record, separators=(",", ":")) + "\n")
                
                # Real-time monitoring
                if self.enable_real_time:
                    await self._monitor_policy_decision(policy_decision)
                
                logger.debug(f"Logged policy decision: {policy_decision.decision_id}")
                
            except Exception as e:
                logger.error(f"Failed to log policy decision: {e}")
                raise

    async def log_security_violation(self, violation: SecurityViolation) -> None:
        """Log a security violation.
        
        Args:
            violation: The security violation to log
        """
        with self._lock:
            try:
                # Store in database
                await self._store_security_violation(violation)
                
                # Create security alert for high-severity violations
                if violation.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
                    alert = SecurityAlert(
                        alert_id=violation.violation_id,
                        timestamp=violation.timestamp,
                        severity=violation.severity,
                        alert_type=AlertType.POLICY_VIOLATION,
                        description=f"Security violation: {violation.description}",
                        affected_resources=violation.affected_resources,
                        implicated_identities=violation.implicated_identities,
                        recommended_actions=[
                            "Investigate violation immediately",
                            "Review access controls",
                            "Consider temporary access restrictions"
                        ]
                    )
                    await self.log_security_alert(alert)
                
                # Also log to base audit logger
                base_record = {
                    "timestamp": violation.timestamp.isoformat(),
                    "event_type": "security_violation",
                    "violation_type": violation.violation_type,
                    "severity": violation.severity.value,
                    "description": violation.description,
                    "affected_resources": violation.affected_resources,
                    "implicated_identities": violation.implicated_identities,
                    "violation_details": violation.violation_details,
                    "automated_response": violation.automated_response
                }
                
                with open(self.base_logger.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(base_record, separators=(",", ":")) + "\n")
                
                # Real-time monitoring
                if self.enable_real_time:
                    await self._monitor_security_violation(violation)
                
                logger.warning(f"Logged security violation: {violation.violation_id}")
                
            except Exception as e:
                logger.error(f"Failed to log security violation: {e}")
                raise

    async def log_access_attempt(self, access_attempt: AccessAttempt) -> None:
        """Log an access attempt.
        
        Args:
            access_attempt: The access attempt to log
        """
        with self._lock:
            try:
                # Store in database
                await self._store_access_attempt(access_attempt)
                
                # Also log to base audit logger
                base_record = {
                    "timestamp": access_attempt.timestamp.isoformat(),
                    "event_type": "access_attempt",
                    "identity": access_attempt.identity.to_dict(),
                    "resource": access_attempt.resource.to_dict(),
                    "action": access_attempt.action,
                    "decision": access_attempt.decision.value,
                    "decision_reason": access_attempt.decision_reason,
                    "risk_score": access_attempt.risk_score,
                    "enforcement_details": access_attempt.enforcement_details
                }
                
                with open(self.base_logger.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(base_record, separators=(",", ":")) + "\n")
                
                # Real-time monitoring
                if self.enable_real_time:
                    await self._monitor_access_attempt(access_attempt)
                
                logger.debug(f"Logged access attempt: {access_attempt.attempt_id}")
                
            except Exception as e:
                logger.error(f"Failed to log access attempt: {e}")
                raise

    async def log_security_alert(self, alert: SecurityAlert) -> None:
        """Log a security alert.
        
        Args:
            alert: The security alert to log
        """
        with self._lock:
            try:
                # Store in database
                await self._store_security_alert(alert)
                
                # Also log to base audit logger
                base_record = {
                    "timestamp": alert.timestamp.isoformat(),
                    "event_type": "security_alert",
                    "alert_id": alert.alert_id,
                    "severity": alert.severity.value,
                    "alert_type": alert.alert_type.value,
                    "description": alert.description,
                    "affected_resources": alert.affected_resources,
                    "implicated_identities": alert.implicated_identities,
                    "status": alert.status,
                    "assigned_to": alert.assigned_to,
                    "recommended_actions": alert.recommended_actions,
                    "automated_response": alert.automated_response
                }
                
                with open(self.base_logger.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(base_record, separators=(",", ":")) + "\n")
                
                logger.info(f"Logged security alert: {alert.alert_id}")
                
            except Exception as e:
                logger.error(f"Failed to log security alert: {e}")
                raise

    # Database storage methods
    async def _store_operation_initiated(self, operation: SecurityOperation) -> None:
        """Store operation initiation in database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO security_audit_logs (
                    id, operation_id, timestamp, initiator_type, initiator_identity,
                    operation_type, target_resources, operation_parameters, risk_level,
                    outcome, correlation_id, session_id, source_ip, user_agent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                operation.operation_id,
                operation.operation_id,
                operation.timestamp.isoformat(),
                operation.initiator_type.value,
                json.dumps(operation.initiator_identity.to_dict()) if operation.initiator_identity else None,
                operation.operation_type,
                json.dumps([r.to_dict() for r in operation.target_resources]),
                json.dumps(operation.operation_parameters),
                operation.risk_level.value,
                "initiated",
                operation.correlation_id,
                operation.session_id,
                operation.source_ip,
                operation.user_agent
            ))

    async def _store_operation_outcome(self, operation_id: str, outcome: OperationOutcome) -> None:
        """Store operation outcome in database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE security_audit_logs 
                SET outcome = ?, outcome_details = ?
                WHERE operation_id = ?
            """, (
                outcome.outcome,
                json.dumps(outcome.to_dict()),
                operation_id
            ))

    async def _store_identity_event(self, event: IdentityEvent) -> None:
        """Store identity event in database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO identity_events (
                    event_id, timestamp, event_type, identity, event_details,
                    source_ip, user_agent
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                event.event_id,
                event.timestamp.isoformat(),
                event.event_type,
                json.dumps(event.identity.to_dict()),
                json.dumps(event.event_details),
                event.source_ip,
                event.user_agent
            ))

    async def _store_policy_decision(self, decision: PolicyDecision) -> None:
        """Store policy decision in database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO policy_decisions (
                    decision_id, timestamp, policy_name, decision, reason,
                    policy_context, enforcement_details
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                decision.decision_id,
                decision.timestamp.isoformat(),
                decision.policy_name,
                decision.decision,
                decision.reason,
                json.dumps(decision.policy_context),
                json.dumps(decision.enforcement_details)
            ))

    async def _store_security_violation(self, violation: SecurityViolation) -> None:
        """Store security violation in database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO security_violations (
                    violation_id, timestamp, violation_type, severity, description,
                    affected_resources, implicated_identities, violation_details,
                    automated_response
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                violation.violation_id,
                violation.timestamp.isoformat(),
                violation.violation_type,
                violation.severity.value,
                violation.description,
                json.dumps(violation.affected_resources),
                json.dumps(violation.implicated_identities),
                json.dumps(violation.violation_details),
                violation.automated_response
            ))

    async def _store_access_attempt(self, attempt: AccessAttempt) -> None:
        """Store access attempt in database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO access_attempts (
                    attempt_id, timestamp, identity, resource, action,
                    decision, decision_reason, risk_score, enforcement_details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                attempt.attempt_id,
                attempt.timestamp.isoformat(),
                json.dumps(attempt.identity.to_dict()),
                json.dumps(attempt.resource.to_dict()),
                attempt.action,
                attempt.decision.value,
                attempt.decision_reason,
                attempt.risk_score,
                json.dumps(attempt.enforcement_details)
            ))

    async def _store_security_alert(self, alert: SecurityAlert) -> None:
        """Store security alert in database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO security_alerts (
                    alert_id, timestamp, severity, alert_type, description,
                    affected_resources, implicated_identities, status, assigned_to,
                    resolved_at, resolution_details, recommended_actions,
                    automated_response
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.alert_id,
                alert.timestamp.isoformat(),
                alert.severity.value,
                alert.alert_type.value,
                alert.description,
                json.dumps(alert.affected_resources),
                json.dumps(alert.implicated_identities),
                alert.status,
                alert.assigned_to,
                alert.resolved_at.isoformat() if alert.resolved_at else None,
                alert.resolution_details,
                json.dumps(alert.recommended_actions),
                alert.automated_response
            ))

    # Base audit logging compatibility
    async def _log_to_base_audit(self, operation: SecurityOperation, status: str, outcome: Optional[OperationOutcome] = None) -> None:
        """Log to base audit logger for backward compatibility."""
        result = {
            "success": outcome.outcome == "success" if outcome else True,
            "status": status,
            "outcome": outcome.outcome if outcome else "initiated",
            "error": outcome.error_message if outcome else None
        }
        
        args = operation.operation_parameters.copy()
        args.update({
            "operation_id": operation.operation_id,
            "correlation_id": operation.correlation_id,
            "risk_level": operation.risk_level.value
        })
        
        self.base_logger.log(
            tool=operation.operation_type,
            args=args,
            result=result,
            subject=operation.initiator_identity.username if operation.initiator_identity else "system",
            scopes=operation.initiator_identity.permissions if operation.initiator_identity else [],
            risk_level=operation.risk_level.value,
            approved=True  # Assume approved for now
        )

    # Real-time monitoring and correlation methods
    async def _correlate_operations(self, operation: SecurityOperation) -> None:
        """Correlate operations in real-time."""
        # Check for suspicious patterns
        correlation_id = operation.correlation_id
        if correlation_id and correlation_id in self.correlation_cache:
            # Multiple operations with same correlation ID
            operation_count = len(self.correlation_cache[correlation_id])
            if operation_count > 10:
                logger.warning(f"High operation count for correlation {correlation_id}: {operation_count}")

    async def _correlate_outcome(self, operation: SecurityOperation, outcome: OperationOutcome) -> None:
        """Correlate operation outcome with patterns."""
        # Check for rapid failures
        if outcome.outcome == "failure" and operation.initiator_identity:
            # This would trigger more sophisticated monitoring
            pass

    async def _monitor_identity_event(self, event: IdentityEvent) -> None:
        """Monitor identity events for anomalies."""
        if event.event_type == "failed_login":
            # This would trigger brute force detection
            pass

    async def _monitor_policy_decision(self, decision: PolicyDecision) -> None:
        """Monitor policy decisions for patterns."""
        if decision.decision == "deny":
            # Monitor denied operations
            pass

    async def _monitor_security_violation(self, violation: SecurityViolation) -> None:
        """Monitor security violations."""
        # Real-time alerting for critical violations
        if violation.severity == AlertSeverity.CRITICAL:
            # Send immediate alerts
            pass

    async def _monitor_access_attempt(self, attempt: AccessAttempt) -> None:
        """Monitor access attempts for threats."""
        if attempt.decision == AccessDecision.DENY:
            # Monitor denied access attempts
            pass

    # Query methods for compliance and analysis
    def get_audit_logs(self, filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get audit logs based on filters."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            query = "SELECT * FROM security_audit_logs WHERE 1=1"
            params = []
            
            for key, value in filters.items():
                if key == "start_date":
                    query += " AND timestamp >= ?"
                    params.append(value)
                elif key == "end_date":
                    query += " AND timestamp <= ?"
                    params.append(value)
                elif key == "initiator_type":
                    query += " AND initiator_type = ?"
                    params.append(value)
                elif key == "operation_type":
                    query += " AND operation_type = ?"
                    params.append(value)
                elif key == "risk_level":
                    query += " AND risk_level = ?"
                    params.append(value)
            
            query += " ORDER BY timestamp DESC LIMIT 1000"
            
            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_security_alerts(self, status: Optional[str] = None, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get security alerts based on filters."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            query = "SELECT * FROM security_alerts WHERE 1=1"
            params = []
            
            if status:
                query += " AND status = ?"
                params.append(status)
            
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            
            query += " ORDER BY timestamp DESC"
            
            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_violations_by_time_range(self, start_date: str, end_date: str) -> List[Dict[str, Any]]:
        """Get security violations within time range."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            cursor = conn.execute("""
                SELECT * FROM security_violations 
                WHERE timestamp BETWEEN ? AND ?
                ORDER BY timestamp DESC
            """, (start_date, end_date))
            
            return [dict(row) for row in cursor.fetchall()]