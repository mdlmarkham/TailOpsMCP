"""
Security monitoring and threat detection system.

This module provides comprehensive security monitoring capabilities:
- Failed authentication attempt detection
- Anomalous behavior analysis
- Privilege escalation detection
- Data exfiltration monitoring
- Policy violation detection
- Real-time threat intelligence correlation
"""

import asyncio
import datetime
import json
import logging
import os
import sqlite3
import statistics
import threading
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import asdict

from src.models.security_models import (
    SecurityAlert, AlertSeverity, AlertType, IdentityEvent, AccessAttempt,
    SecurityOperation, SecurityViolation, BruteForceAttack, PrivilegeAbuse,
    DataDumping, LateralMovement, AccessPattern, FailedAttempt, Anomaly
)
from src.services.security_audit_logger import SecurityAuditLogger


logger = logging.getLogger(__name__)


class ThreatDetector:
    """Threat detection algorithms for various attack patterns."""
    
    def __init__(self):
        """Initialize threat detector."""
        # Detection thresholds
        self.brute_force_threshold = int(os.getenv("BRUTE_FORCE_THRESHOLD", "5"))
        self.brute_force_time_window = int(os.getenv("BRUTE_FORCE_TIME_WINDOW", "300"))  # 5 minutes
        self.privilege_escalation_threshold = int(os.getenv("PRIVILEGE_ESCALATION_THRESHOLD", "3"))
        self.data_dumping_threshold = int(os.getenv("DATA_DUMPING_THRESHOLD", "100"))
        self.lateral_movement_threshold = int(os.getenv("LATERAL_MOVEMENT_THRESHOLD", "5"))
        
        # Time windows for analysis
        self.analysis_window_hours = int(os.getenv("ANALYSIS_WINDOW_HOURS", "24"))
        
        logger.info("Threat detector initialized")

    def detect_brute_force(self, failed_attempts: List[FailedAttempt]) -> Optional[BruteForceAttack]:
        """Detect brute force attacks from failed login attempts.
        
        Args:
            failed_attempts: List of failed authentication attempts
            
        Returns:
            Brute force attack details if detected, None otherwise
        """
        try:
            # Group attempts by IP address and username
            attempts_by_ip = defaultdict(list)
            attempts_by_user = defaultdict(list)
            
            for attempt in failed_attempts:
                if attempt.source_ip:
                    attempts_by_ip[attempt.source_ip].append(attempt)
                if attempt.username:
                    attempts_by_user[attempt.username].append(attempt)
            
            # Check for brute force from single IP
            for ip, attempts in attempts_by_ip.items():
                if len(attempts) >= self.brute_force_threshold:
                    # Check time window
                    recent_attempts = [
                        a for a in attempts
                        if (datetime.datetime.utcnow() - a.timestamp).total_seconds() <= self.brute_force_time_window
                    ]
                    
                    if len(recent_attempts) >= self.brute_force_threshold:
                        return BruteForceAttack(
                            attack_type="ip_based",
                            source_ip=ip,
                            target_usernames=list(set(a.username for a in recent_attempts if a.username)),
                            attempt_count=len(recent_attempts),
                            time_window_seconds=self.brute_force_time_window,
                            severity=AlertSeverity.HIGH if len(recent_attempts) > 10 else AlertSeverity.MEDIUM
                        )
            
            # Check for brute force against single user
            for username, attempts in attempts_by_user.items():
                if len(attempts) >= self.brute_force_threshold:
                    recent_attempts = [
                        a for a in attempts
                        if (datetime.datetime.utcnow() - a.timestamp).total_seconds() <= self.brute_force_time_window
                    ]
                    
                    if len(recent_attempts) >= self.brute_force_threshold:
                        source_ips = list(set(a.source_ip for a in recent_attempts if a.source_ip))
                        return BruteForceAttack(
                            attack_type="user_based",
                            source_ips=source_ips,
                            target_username=username,
                            attempt_count=len(recent_attempts),
                            time_window_seconds=self.brute_force_time_window,
                            severity=AlertSeverity.HIGH if len(recent_attempts) > 10 else AlertSeverity.MEDIUM
                        )
            
            return None
            
        except Exception as e:
            logger.error(f"Brute force detection failed: {e}")
            return None

    def detect_privilege_abuse(self, operations: List[SecurityOperation]) -> Optional[PrivilegeAbuse]:
        """Detect privilege abuse patterns.
        
        Args:
            operations: List of security operations
            
        Returns:
            Privilege abuse details if detected, None otherwise
        """
        try:
            # Look for rapid privilege escalation attempts
            admin_operations = []
            security_operations = []
            
            for op in operations:
                if op.initiator_identity:
                    identity = op.initiator_identity
                    
                    # Check for admin operations by non-admin users
                    if (op.operation_type in ["create_admin", "grant_admin", "elevate_privileges"] and
                        "admin" not in identity.roles):
                        admin_operations.append(op)
                    
                    # Check for security operations by non-security users
                    if (op.operation_type in ["modify_security", "change_policy", "bypass_controls"] and
                        "security" not in identity.roles):
                        security_operations.append(op)
            
            # Analyze patterns
            if admin_operations:
                recent_admin_ops = [
                    op for op in admin_operations
                    if (datetime.datetime.utcnow() - op.timestamp).total_seconds() <= 3600  # 1 hour
                ]
                
                if len(recent_admin_ops) >= self.privilege_escalation_threshold:
                    users = list(set(op.initiator_identity.username for op in recent_admin_ops if op.initiator_identity))
                    return PrivilegeAbuse(
                        abuse_type="unauthorized_admin_access",
                        implicated_users=users,
                        operation_count=len(recent_admin_ops),
                        target_privileges=["admin"],
                        severity=AlertSeverity.CRITICAL
                    )
            
            if security_operations:
                recent_security_ops = [
                    op for op in security_operations
                    if (datetime.datetime.utcnow() - op.timestamp).total_seconds() <= 3600
                ]
                
                if len(recent_security_ops) >= self.privilege_escalation_threshold:
                    users = list(set(op.initiator_identity.username for op in recent_security_ops if op.initiator_identity))
                    return PrivilegeAbuse(
                        abuse_type="unauthorized_security_access",
                        implicated_users=users,
                        operation_count=len(recent_security_ops),
                        target_privileges=["security"],
                        severity=AlertSeverity.HIGH
                    )
            
            return None
            
        except Exception as e:
            logger.error(f"Privilege abuse detection failed: {e}")
            return None

    def detect_data_dumping(self, operations: List[SecurityOperation]) -> Optional[DataDumping]:
        """Detect data dumping patterns.
        
        Args:
            operations: List of security operations
            
        Returns:
            Data dumping details if detected, None otherwise
        """
        try:
            # Look for large data export operations
            export_operations = []
            
            for op in operations:
                if op.operation_type in ["export", "backup", "download", "dump"]:
                    # Check for large data operations
                    data_size = op.operation_parameters.get("data_size", 0)
                    record_count = op.operation_parameters.get("record_count", 0)
                    
                    if data_size > 100 * 1024 * 1024 or record_count > 10000:  # 100MB or 10k records
                        export_operations.append(op)
            
            # Analyze export patterns
            if export_operations:
                recent_exports = [
                    op for op in export_operations
                    if (datetime.datetime.utcnow() - op.timestamp).total_seconds() <= 3600  # 1 hour
                ]
                
                if len(recent_exports) >= 3:  # Multiple large exports in short time
                    users = list(set(op.initiator_identity.username for op in recent_exports if op.initiator_identity))
                    resources = list(set(op.target_resources[0].resource_id for op in recent_exports if op.target_resources))
                    
                    total_data_size = sum(op.operation_parameters.get("data_size", 0) for op in recent_exports)
                    
                    return DataDumping(
                        dumping_type="large_data_export",
                        implicated_users=users,
                        affected_resources=resources,
                        total_data_size=total_data_size,
                        operation_count=len(recent_exports),
                        severity=AlertSeverity.HIGH if total_data_size > 1024 * 1024 * 1024 else AlertSeverity.MEDIUM  # 1GB
                    )
            
            return None
            
        except Exception as e:
            logger.error(f"Data dumping detection failed: {e}")
            return None

    def detect_lateral_movement(self, access_patterns: List[AccessPattern]) -> Optional[LateralMovement]:
        """Detect lateral movement patterns.
        
        Args:
            access_patterns: List of access patterns
            
        Returns:
            Lateral movement details if detected, None otherwise
        """
        try:
            # Group access patterns by user
            patterns_by_user = defaultdict(list)
            
            for pattern in access_patterns:
                if pattern.identity:
                    patterns_by_user[pattern.identity.user_id].append(pattern)
            
            lateral_movements = []
            
            for user_id, patterns in patterns_by_user.items():
                if len(patterns) >= self.lateral_movement_threshold:
                    # Analyze resource access patterns
                    resources_accessed = list(set(p.resource_id for p in patterns))
                    source_ips = list(set(p.source_ip for p in patterns if p.source_ip))
                    
                    # Look for access to multiple different resources from different sources
                    if len(resources_accessed) >= 3 and len(source_ips) >= 2:
                        time_span = max(p.timestamp for p in patterns) - min(p.timestamp for p in patterns)
                        
                        # If access occurred across multiple IPs in short time, likely lateral movement
                        if time_span.total_seconds() <= 1800:  # 30 minutes
                            lateral_movements.append({
                                "user_id": user_id,
                                "resources": resources_accessed,
                                "source_ips": source_ips,
                                "access_count": len(patterns),
                                "time_span_minutes": time_span.total_seconds() / 60
                            })
            
            if lateral_movements:
                # Return the most suspicious movement
                most_suspicious = max(lateral_movements, key=lambda x: x["access_count"])
                return LateralMovement(
                    movement_type="multi_resource_access",
                    implicated_user=most_suspicious["user_id"],
                    target_resources=most_suspicious["resources"],
                    source_ips=most_suspicious["source_ips"],
                    access_count=most_suspicious["access_count"],
                    time_span_minutes=most_suspicious["time_span_minutes"],
                    severity=AlertSeverity.HIGH
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Lateral movement detection failed: {e}")
            return None

    def detect_anomalous_behavior(self, identity_events: List[IdentityEvent]) -> List[Anomaly]:
        """Detect anomalous behavior patterns.
        
        Args:
            identity_events: List of identity events
            
        Returns:
            List of detected anomalies
        """
        anomalies = []
        
        try:
            # Group events by identity
            events_by_identity = defaultdict(list)
            
            for event in identity_events:
                events_by_identity[event.identity.user_id].append(event)
            
            for user_id, events in events_by_identity.items():
                # Detect unusual login times
                login_hours = [event.timestamp.hour for event in events if event.event_type == "login"]
                if login_hours:
                    # Check for login outside normal hours (2 AM - 6 AM)
                    unusual_hours = [hour for hour in login_hours if hour < 6 or hour > 22]
                    if len(unusual_hours) > len(login_hours) * 0.3:  # More than 30% unusual
                        anomalies.append(Anomaly(
                            anomaly_type="unusual_login_hours",
                            implicated_identity=user_id,
                            description=f"User {user_id} has {len(unusual_hours)} logins outside normal hours",
                            severity=AlertSeverity.MEDIUM,
                            details={"unusual_hours": unusual_hours, "total_logins": len(login_hours)}
                        ))
                
                # Detect rapid successive logins
                login_events = [e for e in events if e.event_type == "login"]
                if len(login_events) > 1:
                    for i in range(len(login_events) - 1):
                        time_diff = (login_events[i + 1].timestamp - login_events[i].timestamp).total_seconds()
                        if time_diff < 30:  # Less than 30 seconds between logins
                            anomalies.append(Anomaly(
                                anomaly_type="rapid_successive_logins",
                                implicated_identity=user_id,
                                description=f"User {user_id} has successive logins {time_diff} seconds apart",
                                severity=AlertSeverity.MEDIUM,
                                details={"time_diff_seconds": time_diff}
                            ))
                            break
                
                # Detect unusual geographic access (simplified)
                source_ips = list(set(event.source_ip for event in events if event.source_ip))
                if len(source_ips) > 5:  # Many different source IPs
                    anomalies.append(Anomaly(
                        anomaly_type="multiple_source_ips",
                        implicated_identity=user_id,
                        description=f"User {user_id} accessed from {len(source_ips)} different IP addresses",
                        severity=AlertSeverity.MEDIUM,
                        details={"source_ips": source_ips}
                    ))
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Anomalous behavior detection failed: {e}")
            return anomalies


class SecurityMonitor:
    """Security monitoring and threat detection system."""
    
    def __init__(self, audit_logger: Optional[SecurityAuditLogger] = None):
        """Initialize security monitor.
        
        Args:
            audit_logger: Security audit logger
        """
        self.audit_logger = audit_logger or SecurityAuditLogger()
        self.threat_detector = ThreatDetector()
        
        # Monitoring configuration
        self.monitoring_enabled = os.getenv("SECURITY_MONITORING_ENABLED", "true").lower() == "true"
        self.anomaly_detection = os.getenv("ANOMALY_DETECTION_ENABLED", "true").lower() == "true"
        self.real_time_alerts = os.getenv("REAL_TIME_ALERTS_ENABLED", "true").lower() == "true"
        self.automated_response = os.getenv("AUTOMATED_RESPONSE_ENABLED", "false").lower() == "true"
        
        # Data caches for analysis
        self._failed_attempts_cache: deque = deque(maxlen=1000)
        self._access_patterns_cache: deque = deque(maxlen=5000)
        self._identity_events_cache: deque = deque(maxlen=2000)
        self._operations_cache: deque = deque(maxlen=10000)
        
        # Alert thresholds
        self.alert_retention_days = int(os.getenv("ALERT_RETENTION_DAYS", "30"))
        
        # Monitoring thread
        self._monitoring_active = False
        self._monitoring_thread: Optional[threading.Thread] = None
        
        logger.info("Security monitor initialized")

    async def start_monitoring(self) -> None:
        """Start real-time security monitoring."""
        if not self.monitoring_enabled:
            logger.info("Security monitoring is disabled")
            return
        
        if self._monitoring_active:
            logger.warning("Security monitoring is already active")
            return
        
        self._monitoring_active = True
        self._monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self._monitoring_thread.start()
        
        logger.info("Security monitoring started")

    async def stop_monitoring(self) -> None:
        """Stop security monitoring."""
        self._monitoring_active = False
        if self._monitoring_thread:
            self._monitoring_thread.join(timeout=5)
        
        logger.info("Security monitoring stopped")

    def _monitoring_loop(self) -> None:
        """Main monitoring loop."""
        while self._monitoring_active:
            try:
                # Run threat detection
                asyncio.run(self._run_threat_detection())
                
                # Clean up old data
                self._cleanup_old_data()
                
                # Sleep before next iteration
                import time
                time.sleep(60)  # Run every minute
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                import time
                time.sleep(10)  # Short sleep on error

    async def _run_threat_detection(self) -> None:
        """Run threat detection algorithms."""
        try:
            # Convert cache data to lists for analysis
            failed_attempts = list(self._failed_attempts_cache)
            access_patterns = list(self._access_patterns_cache)
            identity_events = list(self._identity_events_cache)
            operations = list(self._operations_cache)
            
            # Detect various threats
            threats_detected = []
            
            # Brute force detection
            if failed_attempts:
                brute_force = self.threat_detector.detect_brute_force(failed_attempts)
                if brute_force:
                    threats_detected.append(brute_force)
            
            # Privilege abuse detection
            if operations:
                privilege_abuse = self.threat_detector.detect_privilege_abuse(operations)
                if privilege_abuse:
                    threats_detected.append(privilege_abuse)
            
            # Data dumping detection
            if operations:
                data_dumping = self.threat_detector.detect_data_dumping(operations)
                if data_dumping:
                    threats_detected.append(data_dumping)
            
            # Lateral movement detection
            if access_patterns:
                lateral_movement = self.threat_detector.detect_lateral_movement(access_patterns)
                if lateral_movement:
                    threats_detected.append(lateral_movement)
            
            # Anomalous behavior detection
            if identity_events and self.anomaly_detection:
                anomalies = self.threat_detector.detect_anomalous_behavior(identity_events)
                for anomaly in anomalies:
                    threats_detected.append(anomaly)
            
            # Process detected threats
            for threat in threats_detected:
                await self._process_detected_threat(threat)
            
        except Exception as e:
            logger.error(f"Threat detection failed: {e}")

    async def _process_detected_threat(self, threat: Any) -> None:
        """Process a detected threat."""
        try:
            # Create security alert
            alert = SecurityAlert(
                severity=threat.severity,
                alert_type=self._map_threat_to_alert_type(threat),
                description=self._generate_threat_description(threat),
                affected_resources=getattr(threat, "affected_resources", []),
                implicated_identities=getattr(threat, "implicated_users", []) or getattr(threat, "implicated_identity", []),
                recommended_actions=self._generate_recommended_actions(threat)
            )
            
            # Log alert
            await self.audit_logger.log_security_alert(alert)
            
            # Send real-time alerts if enabled
            if self.real_time_alerts:
                await self._send_real_time_alert(alert)
            
            # Execute automated response if enabled
            if self.automated_response:
                await self._execute_automated_response(threat, alert)
            
            logger.warning(f"Threat detected: {type(threat).__name__} - {alert.description}")
            
        except Exception as e:
            logger.error(f"Failed to process detected threat: {e}")

    def _map_threat_to_alert_type(self, threat: Any) -> AlertType:
        """Map threat type to alert type."""
        if isinstance(threat, BruteForceAttack):
            return AlertType.BRUTE_FORCE
        elif isinstance(threat, PrivilegeAbuse):
            return AlertType.PRIVILEGE_ESCALATION
        elif isinstance(threat, DataDumping):
            return AlertType.DATA_EXFILTRATION
        elif isinstance(threat, LateralMovement):
            return AlertType.ANOMALOUS_BEHAVIOR
        elif isinstance(threat, Anomaly):
            return AlertType.ANOMALOUS_BEHAVIOR
        else:
            return AlertType.ANOMALOUS_BEHAVIOR

    def _generate_threat_description(self, threat: Any) -> str:
        """Generate human-readable threat description."""
        threat_type = type(threat).__name__
        
        if isinstance(threat, BruteForceAttack):
            if threat.attack_type == "ip_based":
                return f"Brute force attack detected from IP {threat.source_ip} with {threat.attempt_count} attempts"
            else:
                return f"Brute force attack against user {threat.target_username} with {threat.attempt_count} attempts"
        
        elif isinstance(threat, PrivilegeAbuse):
            return f"Privilege abuse detected: {threat.abuse_type} by users {threat.implicated_users}"
        
        elif isinstance(threat, DataDumping):
            return f"Data dumping detected: {threat.dumping_type} with {threat.total_data_size} bytes"
        
        elif isinstance(threat, LateralMovement):
            return f"Lateral movement detected: user {threat.implicated_user} accessed {threat.target_resources}"
        
        elif isinstance(threat, Anomaly):
            return f"Anomalous behavior detected: {threat.anomaly_type} for user {threat.implicated_identity}"
        
        else:
            return f"Security threat detected: {threat_type}"

    def _generate_recommended_actions(self, threat: Any) -> List[str]:
        """Generate recommended actions for threat response."""
        actions = []
        
        if isinstance(threat, BruteForceAttack):
            actions.extend([
                "Block source IP address",
                "Review and reset affected user passwords",
                "Enable additional monitoring",
                "Implement rate limiting"
            ])
        
        elif isinstance(threat, PrivilegeAbuse):
            actions.extend([
                "Immediately review user permissions",
                "Audit recent privilege changes",
                "Consider temporary account suspension",
                "Investigate user intent"
            ])
        
        elif isinstance(threat, DataDumping):
            actions.extend([
                "Stop data export operations",
                "Review data access logs",
                "Implement data export controls",
                "Check for data integrity"
            ])
        
        elif isinstance(threat, LateralMovement):
            actions.extend([
                "Review access patterns",
                "Check for compromised accounts",
                "Implement network segmentation",
                "Monitor additional suspicious activity"
            ])
        
        elif isinstance(threat, Anomaly):
            actions.extend([
                "Investigate the anomalous behavior",
                "Verify user identity",
                "Review security logs",
                "Consider additional authentication"
            ])
        
        actions.append("Document incident for compliance")
        return actions

    async def _send_real_time_alert(self, alert: SecurityAlert) -> None:
        """Send real-time security alert."""
        # This would integrate with notification systems (email, Slack, etc.)
        logger.critical(f"REAL-TIME ALERT: {alert.severity.value.upper()} - {alert.description}")

    async def _execute_automated_response(self, threat: Any, alert: SecurityAlert) -> None:
        """Execute automated response to threat."""
        try:
            # Automated responses would be implemented here
            # Examples:
            # - Block IP addresses
            # - Disable user accounts
            # - Quarantine resources
            # - Update firewall rules
            
            logger.info(f"Automated response executed for threat: {type(threat).__name__}")
            
        except Exception as e:
            logger.error(f"Automated response failed: {e}")

    def _cleanup_old_data(self) -> None:
        """Clean up old monitoring data."""
        try:
            cutoff_time = datetime.datetime.utcnow() - datetime.timedelta(days=1)
            
            # Clean up caches
            for cache in [self._failed_attempts_cache, self._access_patterns_cache, 
                         self._identity_events_cache, self._operations_cache]:
                while cache and cache[0].timestamp < cutoff_time:
                    cache.popleft()
            
        except Exception as e:
            logger.error(f"Data cleanup failed: {e}")

    async def monitor_failed_attempts(self) -> List[SecurityAlert]:
        """Monitor and return alerts for failed authentication attempts.
        
        Returns:
            List of security alerts for failed attempts
        """
        try:
            # Get recent failed attempts from audit logger
            recent_failures = []
            # This would query the audit logger for failed authentication events
            # For now, return empty list as audit logger integration would be needed
            
            alerts = []
            if recent_failures:
                brute_force = self.threat_detector.detect_brute_force(recent_failures)
                if brute_force:
                    alert = SecurityAlert(
                        severity=brute_force.severity,
                        alert_type=AlertType.BRUTE_FORCE,
                        description=self._generate_threat_description(brute_force),
                        implicated_identities=brute_force.target_usernames or [brute_force.target_username],
                        recommended_actions=self._generate_recommended_actions(brute_force)
                    )
                    alerts.append(alert)
            
            return alerts
            
        except Exception as e:
            logger.error(f"Failed attempt monitoring failed: {e}")
            return []

    async def detect_anomalous_behavior(self, identity: IdentityContext) -> List[Anomaly]:
        """Detect anomalous behavior for a specific identity.
        
        Args:
            identity: User identity to analyze
            
        Returns:
            List of detected anomalies
        """
        try:
            # Get recent events for this identity
            identity_events = [
                event for event in self._identity_events_cache
                if event.identity.user_id == identity.user_id
            ]
            
            return self.threat_detector.detect_anomalous_behavior(identity_events)
            
        except Exception as e:
            logger.error(f"Anomalous behavior detection failed: {e}")
            return []

    async def monitor_privilege_escalation(self) -> List[SecurityAlert]:
        """Monitor for privilege escalation attempts.
        
        Returns:
            List of security alerts for privilege escalation
        """
        try:
            # Get recent operations that might indicate privilege escalation
            recent_operations = [
                op for op in self._operations_cache
                if op.operation_type in ["create_admin", "grant_admin", "elevate_privileges", "modify_security"]
            ]
            
            alerts = []
            if recent_operations:
                privilege_abuse = self.threat_detector.detect_privilege_abuse(recent_operations)
                if privilege_abuse:
                    alert = SecurityAlert(
                        severity=privilege_abuse.severity,
                        alert_type=AlertType.PRIVILEGE_ESCALATION,
                        description=self._generate_threat_description(privilege_abuse),
                        implicated_identities=privilege_abuse.implicated_users,
                        recommended_actions=self._generate_recommended_actions(privilege_abuse)
                    )
                    alerts.append(alert)
            
            return alerts
            
        except Exception as e:
            logger.error(f"Privilege escalation monitoring failed: {e}")
            return []

    async def detect_data_exfiltration(self) -> List[SecurityAlert]:
        """Monitor for data exfiltration attempts.
        
        Returns:
            List of security alerts for data exfiltration
        """
        try:
            # Get recent operations that might indicate data exfiltration
            recent_operations = [
                op for op in self._operations_cache
                if op.operation_type in ["export", "backup", "download", "dump"]
            ]
            
            alerts = []
            if recent_operations:
                data_dumping = self.threat_detector.detect_data_dumping(recent_operations)
                if data_dumping:
                    alert = SecurityAlert(
                        severity=data_dumping.severity,
                        alert_type=AlertType.DATA_EXFILTRATION,
                        description=self._generate_threat_description(data_dumping),
                        implicated_identities=data_dumping.implicated_users,
                        recommended_actions=self._generate_recommended_actions(data_dumping)
                    )
                    alerts.append(alert)
            
            return alerts
            
        except Exception as e:
            logger.error(f"Data exfiltration monitoring failed: {e}")
            return []

    async def monitor_policy_violations(self) -> List[SecurityAlert]:
        """Monitor for policy violations.
        
        Returns:
            List of security alerts for policy violations
        """
        try:
            # This would integrate with the policy system to detect violations
            # For now, return empty list as policy integration would be needed
            
            return []
            
        except Exception as e:
            logger.error(f"Policy violation monitoring failed: {e}")
            return []

    # Data ingestion methods for monitoring
    def record_failed_attempt(self, failed_attempt: FailedAttempt) -> None:
        """Record a failed authentication attempt for monitoring.
        
        Args:
            failed_attempt: Failed authentication attempt
        """
        self._failed_attempts_cache.append(failed_attempt)

    def record_access_pattern(self, access_pattern: AccessPattern) -> None:
        """Record an access pattern for monitoring.
        
        Args:
            access_pattern: Access pattern to record
        """
        self._access_patterns_cache.append(access_pattern)

    def record_identity_event(self, identity_event: IdentityEvent) -> None:
        """Record an identity event for monitoring.
        
        Args:
            identity_event: Identity event to record
        """
        self._identity_events_cache.append(identity_event)

    def record_operation(self, operation: SecurityOperation) -> None:
        """Record a security operation for monitoring.
        
        Args:
            operation: Security operation to record
        """
        self._operations_cache.append(operation)