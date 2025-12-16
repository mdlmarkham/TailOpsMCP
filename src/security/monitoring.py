"""
Security Monitoring Module - Consolidated Security Monitoring & Alerting

This module provides comprehensive security monitoring including:
- Real-time security event monitoring
- Security metrics collection and analysis
- Automated alerting and notification
- Security dashboard and reporting
- Threat detection and response automation

CONSOLIDATED FROM:
- src/services/security_monitor.py
- src/utils/secure_logging.py
- src/utils/sandbox.py
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union, Callable
from dataclasses import dataclass, field
from collections import defaultdict, deque

from .audit import AuditLogger, AuditEvent
from .access_control import AccessControlEngine
from ..models.security_models import SecurityAlert, SecurityMetric

logger = logging.getLogger(__name__)


# Security Monitoring Enums
class AlertSeverity(Enum):
    """Security alert severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(Enum):
    """Security alert status."""

    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class ThreatLevel(Enum):
    """Threat severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class MonitoringType(Enum):
    """Types of security monitoring."""

    REAL_TIME = "real_time"
    SCHEDULED = "scheduled"
    EVENT_DRIVEN = "event_driven"
    BATCH = "batch"


@dataclass
class SecurityAlert:
    """Security alert definition."""

    # Core identification
    alert_id: str = field(default_factory=lambda: f"alert_{int(time.time() * 1000)}")
    title: str = ""
    description: str = ""
    severity: AlertSeverity = AlertSeverity.MEDIUM
    category: str = "security"

    # Event details
    source: str = ""
    source_ip: Optional[str] = None
    user_id: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None

    # Alert data
    event_count: int = 1
    first_occurrence: datetime = field(default_factory=datetime.now)
    last_occurrence: datetime = field(default_factory=datetime.now)

    # Context and metadata
    context: Dict[str, Any] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)
    correlation_id: Optional[str] = None

    # Status tracking
    status: AlertStatus = AlertStatus.NEW
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None

    # Response
    response_actions: List[str] = field(default_factory=list)
    escalation_rules: Dict[str, Any] = field(default_factory=dict)

    # Audit trail
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


@dataclass
class SecurityMetric:
    """Security metric definition."""

    # Identification
    metric_name: str
    metric_type: str  # counter, gauge, histogram, summary
    value: Union[int, float, str]
    unit: Optional[str] = None

    # Context
    timestamp: datetime = field(default_factory=datetime.now)
    source: str = ""
    labels: Dict[str, str] = field(default_factory=dict)

    # Security context
    category: str = "security"
    severity: Optional[AlertSeverity] = None

    # Metadata
    description: Optional[str] = None
    tags: Set[str] = field(default_factory=set)


@dataclass
class MonitoringRule:
    """Security monitoring rule."""

    # Identification
    rule_id: str
    name: str
    description: str

    # Rule definition
    rule_type: str = "threshold"  # threshold, pattern, anomaly, correlation
    conditions: Dict[str, Any] = field(default_factory=dict)
    thresholds: Dict[str, Any] = field(default_factory=dict)

    # Alert configuration
    severity: AlertSeverity = AlertSeverity.MEDIUM
    alert_title: str = ""
    alert_description: str = ""

    # Execution
    enabled: bool = True
    monitoring_type: MonitoringType = MonitoringType.REAL_TIME
    check_interval: int = 60  # seconds

    # Response actions
    auto_response: bool = False
    response_actions: List[str] = field(default_factory=list)
    notification_channels: List[str] = field(default_factory=list)

    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    last_triggered: Optional[datetime] = None
    trigger_count: int = 0


class SecurityMonitor:
    """Comprehensive security monitoring system."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

        # Core components
        self.audit_logger = AuditLogger()
        self.access_engine = AccessControlEngine()

        # Monitoring data
        self._metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self._alerts: Dict[str, SecurityAlert] = {}
        self._rules: Dict[str, MonitoringRule] = {}
        self._thresholds: Dict[str, Dict[str, Any]] = {}

        # Monitoring state
        self._monitoring_active = False
        self._monitoring_threads: List[threading.Thread] = []
        self._alert_callbacks: List[Callable] = []

        # Real-time processing
        self._event_buffer: deque = deque(maxlen=1000)
        self._processing_lock = threading.Lock()

        # Initialize default rules
        self._initialize_default_rules()

        # Start monitoring
        self.start_monitoring()

    def _initialize_default_rules(self) -> None:
        """Initialize default security monitoring rules."""
        default_rules = [
            MonitoringRule(
                rule_id="failed_login_threshold",
                name="Failed Login Threshold",
                description="Alert on excessive failed login attempts",
                rule_type="threshold",
                conditions={"metric": "failed_logins", "window": "5m"},
                thresholds={"max_count": 10, "time_window": 300},
                severity=AlertSeverity.HIGH,
                alert_title="Excessive Failed Login Attempts",
                alert_description="More than 10 failed login attempts in 5 minutes",
                auto_response=True,
                response_actions=["block_ip", "notify_security"],
                notification_channels=["email", "slack"],
            ),
            MonitoringRule(
                rule_id="privilege_escalation",
                name="Privilege Escalation Detection",
                description="Detect privilege escalation attempts",
                rule_type="pattern",
                conditions={"event_type": "authorization", "action": "escalate"},
                severity=AlertSeverity.CRITICAL,
                alert_title="Privilege Escalation Attempt",
                alert_description="User attempted to escalate privileges",
                auto_response=True,
                response_actions=["audit_user", "notify_security"],
                notification_channels=["email", "slack", "sms"],
            ),
            MonitoringRule(
                rule_id="unusual_access_pattern",
                name="Unusual Access Pattern",
                description="Detect unusual access patterns",
                rule_type="anomaly",
                conditions={"metric": "access_patterns", "threshold": "3std"},
                severity=AlertSeverity.MEDIUM,
                alert_title="Unusual Access Pattern Detected",
                alert_description="User access pattern deviates from normal behavior",
                auto_response=False,
                response_actions=["investigate"],
                notification_channels=["email"],
            ),
            MonitoringRule(
                rule_id="security_violation",
                name="Security Policy Violation",
                description="Alert on security policy violations",
                rule_type="pattern",
                conditions={"event_type": "security", "severity": "high"},
                severity=AlertSeverity.HIGH,
                alert_title="Security Policy Violation",
                alert_description="Security policy violation detected",
                auto_response=True,
                response_actions=["audit_event", "notify_security"],
                notification_channels=["email", "slack"],
            ),
        ]

        for rule in default_rules:
            self._rules[rule.rule_id] = rule

    def start_monitoring(self) -> None:
        """Start security monitoring."""
        if self._monitoring_active:
            return

        self._monitoring_active = True

        # Start monitoring threads
        self._start_monitoring_threads()

        logger.info("Security monitoring started")

    def stop_monitoring(self) -> None:
        """Stop security monitoring."""
        self._monitoring_active = False

        # Wait for threads to finish
        for thread in self._monitoring_threads:
            if thread.is_alive():
                thread.join(timeout=5)

        self._monitoring_threads.clear()

        logger.info("Security monitoring stopped")

    def _start_monitoring_threads(self) -> None:
        """Start monitoring threads."""
        # Real-time event processing thread
        realtime_thread = threading.Thread(
            target=self._process_realtime_events, name="SecurityRealtimeMonitor"
        )
        realtime_thread.daemon = True
        realtime_thread.start()
        self._monitoring_threads.append(realtime_thread)

        # Metrics collection thread
        metrics_thread = threading.Thread(
            target=self._collect_metrics, name="SecurityMetricsCollector"
        )
        metrics_thread.daemon = True
        metrics_thread.start()
        self._monitoring_threads.append(metrics_thread)

        # Rule evaluation thread
        rules_thread = threading.Thread(
            target=self._evaluate_rules, name="SecurityRulesEvaluator"
        )
        rules_thread.daemon = True
        rules_thread.start()
        self._monitoring_threads.append(rules_thread)

        # Alert processing thread
        alert_thread = threading.Thread(
            target=self._process_alerts, name="SecurityAlertProcessor"
        )
        alert_thread.daemon = True
        alert_thread.start()
        self._monitoring_threads.append(alert_thread)

    def record_metric(self, metric: SecurityMetric) -> None:
        """Record security metric."""
        self._metrics[metric.metric_name].append(metric)

        # Log metric if significant
        if metric.severity and metric.severity in [
            AlertSeverity.HIGH,
            AlertSeverity.CRITICAL,
        ]:
            logger.warning(
                f"Security metric recorded: {metric.metric_name} = {metric.value}"
            )

    def record_event(self, event: AuditEvent) -> None:
        """Record security event."""
        with self._processing_lock:
            self._event_buffer.append(event)

    def create_alert(
        self, rule: MonitoringRule, context: Dict[str, Any]
    ) -> SecurityAlert:
        """Create security alert from rule."""
        alert = SecurityAlert(
            title=rule.alert_title,
            description=rule.alert_description,
            severity=rule.severity,
            category="rule_violation",
            source="monitoring_system",
            context=context,
            tags={rule.rule_id, "automated"},
        )

        # Add alert to collection
        self._alerts[alert.alert_id] = alert

        # Log alert creation
        logger.warning(
            f"Security alert created: {alert.title} (Severity: {alert.severity.value})"
        )

        # Execute auto-response if enabled
        if rule.auto_response and rule.response_actions:
            self._execute_response_actions(alert, rule.response_actions)

        # Trigger callbacks
        self._trigger_alert_callbacks(alert)

        return alert

    def acknowledge_alert(self, alert_id: str, user_id: str) -> bool:
        """Acknowledge security alert."""
        if alert_id not in self._alerts:
            return False

        alert = self._alerts[alert_id]
        alert.status = AlertStatus.ACKNOWLEDGED
        alert.acknowledged_by = user_id
        alert.acknowledged_at = datetime.now()
        alert.updated_at = datetime.now()

        logger.info(f"Alert {alert_id} acknowledged by {user_id}")
        return True

    def resolve_alert(
        self, alert_id: str, user_id: str, resolution_notes: str = ""
    ) -> bool:
        """Resolve security alert."""
        if alert_id not in self._alerts:
            return False

        alert = self._alerts[alert_id]
        alert.status = AlertStatus.RESOLVED
        alert.resolved_by = user_id
        alert.resolved_at = datetime.now()
        alert.updated_at = datetime.now()

        if resolution_notes:
            alert.context["resolution_notes"] = resolution_notes

        logger.info(f"Alert {alert_id} resolved by {user_id}")
        return True

    def get_alerts(
        self,
        status: Optional[AlertStatus] = None,
        severity: Optional[AlertSeverity] = None,
    ) -> List[SecurityAlert]:
        """Get security alerts with optional filtering."""
        alerts = list(self._alerts.values())

        if status:
            alerts = [a for a in alerts if a.status == status]

        if severity:
            alerts = [a for a in alerts if a.severity == severity]

        # Sort by severity and timestamp
        severity_order = {
            AlertSeverity.CRITICAL: 0,
            AlertSeverity.HIGH: 1,
            AlertSeverity.MEDIUM: 2,
            AlertSeverity.LOW: 3,
            AlertSeverity.INFO: 4,
        }

        alerts.sort(
            key=lambda a: (severity_order.get(a.severity, 5), a.created_at),
            reverse=True,
        )

        return alerts

    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get security dashboard data."""
        now = datetime.now()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)

        # Alert statistics
        all_alerts = list(self._alerts.values())
        active_alerts = [
            a
            for a in all_alerts
            if a.status not in [AlertStatus.RESOLVED, AlertStatus.DISMISSED]
        ]

        # Recent metrics (last 24 hours)
        recent_metrics = {}
        for metric_name, metric_deque in self._metrics.items():
            recent_metrics[metric_name] = [
                m for m in metric_deque if m.timestamp > last_24h
            ]

        # Key security metrics
        failed_logins = len([m for m in recent_metrics.get("failed_logins", [])])
        successful_logins = len(
            [m for m in recent_metrics.get("successful_logins", [])]
        )
        security_violations = len(
            [m for m in recent_metrics.get("security_violations", [])]
        )

        return {
            "dashboard_metadata": {
                "generated_at": now.isoformat(),
                "time_range": "24h",
            },
            "alert_summary": {
                "total": len(all_alerts),
                "active": len(active_alerts),
                "critical": len(
                    [a for a in active_alerts if a.severity == AlertSeverity.CRITICAL]
                ),
                "high": len(
                    [a for a in active_alerts if a.severity == AlertSeverity.HIGH]
                ),
                "medium": len(
                    [a for a in active_alerts if a.severity == AlertSeverity.MEDIUM]
                ),
            },
            "metrics_summary": {
                "failed_logins_24h": failed_logins,
                "successful_logins_24h": successful_logins,
                "security_violations_24h": security_violations,
                "login_success_rate": successful_logins
                / (successful_logins + failed_logins)
                if (successful_logins + failed_logins) > 0
                else 0,
            },
            "recent_alerts": [
                {
                    "alert_id": a.alert_id,
                    "title": a.title,
                    "severity": a.severity.value,
                    "status": a.status.value,
                    "created_at": a.created_at.isoformat(),
                    "last_occurrence": a.last_occurrence.isoformat(),
                }
                for a in sorted(all_alerts, key=lambda x: x.created_at, reverse=True)[
                    :10
                ]
            ],
            "metric_trends": {
                metric_name: [
                    {
                        "timestamp": m.timestamp.isoformat(),
                        "value": m.value,
                        "labels": m.labels,
                    }
                    for m in metrics[-100:]  # Last 100 data points
                ]
                for metric_name, metrics in recent_metrics.items()
                if metrics
            },
        }

    def add_monitoring_rule(self, rule: MonitoringRule) -> bool:
        """Add custom monitoring rule."""
        if rule.rule_id in self._rules:
            logger.warning(f"Monitoring rule {rule.rule_id} already exists")
            return False

        self._rules[rule.rule_id] = rule
        logger.info(f"Added monitoring rule: {rule.name}")
        return True

    def remove_monitoring_rule(self, rule_id: str) -> bool:
        """Remove monitoring rule."""
        if rule_id not in self._rules:
            return False

        del self._rules[rule_id]
        logger.info(f"Removed monitoring rule: {rule_id}")
        return True

    def register_alert_callback(
        self, callback: Callable[[SecurityAlert], None]
    ) -> None:
        """Register alert callback function."""
        self._alert_callbacks.append(callback)

    # Background processing methods
    def _process_realtime_events(self) -> None:
        """Process events in real-time."""
        while self._monitoring_active:
            try:
                # Process events from buffer
                events_to_process = []
                with self._processing_lock:
                    while self._event_buffer:
                        events_to_process.append(self._event_buffer.popleft())

                # Process each event
                for event in events_to_process:
                    self._process_single_event(event)

                # Sleep if no events
                if not events_to_process:
                    time.sleep(1)

            except Exception as e:
                logger.error(f"Error in real-time event processing: {e}")
                time.sleep(5)

    def _process_single_event(self, event: AuditEvent) -> None:
        """Process individual security event."""
        # Record metrics based on event type
        if event.event_type.value == "authentication":
            if event.outcome == "failure":
                self.record_metric(
                    SecurityMetric(
                        metric_name="failed_logins",
                        metric_type="counter",
                        value=1,
                        source=event.source,
                        severity=AlertSeverity.MEDIUM,
                    )
                )
            else:
                self.record_metric(
                    SecurityMetric(
                        metric_name="successful_logins",
                        metric_type="counter",
                        value=1,
                        source=event.source,
                    )
                )

        elif event.event_type.value == "security":
            self.record_metric(
                SecurityMetric(
                    metric_name="security_violations",
                    metric_type="counter",
                    value=1,
                    source=event.source,
                    severity=AlertSeverity.HIGH,
                )
            )

        # Check against monitoring rules
        self._evaluate_event_rules(event)

    def _evaluate_event_rules(self, event: AuditEvent) -> None:
        """Evaluate monitoring rules against event."""
        for rule in self._rules.values():
            if not rule.enabled:
                continue

            if rule.monitoring_type != MonitoringType.EVENT_DRIVEN:
                continue

            # Check if rule conditions match event
            if self._rule_matches_event(rule, event):
                context = {
                    "event": event,
                    "event_type": event.event_type.value,
                    "user_id": event.user_id,
                    "source_ip": event.source_ip,
                    "action": event.action,
                    "outcome": event.outcome,
                }

                alert = self.create_alert(rule, context)

                # Update rule trigger statistics
                rule.last_triggered = datetime.now()
                rule.trigger_count += 1

    def _rule_matches_event(self, rule: MonitoringRule, event: AuditEvent) -> bool:
        """Check if monitoring rule matches event."""
        conditions = rule.conditions

        # Event type matching
        if "event_type" in conditions:
            if event.event_type.value != conditions["event_type"]:
                return False

        # Action matching
        if "action" in conditions:
            if event.action != conditions["action"]:
                return False

        # User matching
        if "user_id" in conditions:
            if event.user_id != conditions["user_id"]:
                return False

        # Severity matching
        if "severity" in conditions:
            if event.severity.value != conditions["severity"]:
                return False

        return True

    def _collect_metrics(self) -> None:
        """Collect security metrics periodically."""
        while self._monitoring_active:
            try:
                # Collect system metrics
                self._collect_system_metrics()

                # Collect application metrics
                self._collect_application_metrics()

                # Sleep for collection interval
                time.sleep(60)  # Collect every minute

            except Exception as e:
                logger.error(f"Error collecting metrics: {e}")
                time.sleep(60)

    def _collect_system_metrics(self) -> None:
        """Collect system-level security metrics."""
        try:
            import psutil

            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self.record_metric(
                SecurityMetric(
                    metric_name="cpu_usage",
                    metric_type="gauge",
                    value=cpu_percent,
                    unit="percent",
                    source="system",
                )
            )

            # Memory usage
            memory = psutil.virtual_memory()
            self.record_metric(
                SecurityMetric(
                    metric_name="memory_usage",
                    metric_type="gauge",
                    value=memory.percent,
                    unit="percent",
                    source="system",
                )
            )

            # Disk usage
            disk = psutil.disk_usage("/")
            disk_percent = (disk.used / disk.total) * 100
            self.record_metric(
                SecurityMetric(
                    metric_name="disk_usage",
                    metric_type="gauge",
                    value=disk_percent,
                    unit="percent",
                    source="system",
                )
            )

        except ImportError:
            logger.warning("psutil not available for system metrics collection")
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")

    def _collect_application_metrics(self) -> None:
        """Collect application-level security metrics."""
        try:
            # Get active alerts count
            active_alerts = len(
                [
                    a
                    for a in self._alerts.values()
                    if a.status not in [AlertStatus.RESOLVED, AlertStatus.DISMISSED]
                ]
            )
            self.record_metric(
                SecurityMetric(
                    metric_name="active_alerts",
                    metric_type="gauge",
                    value=active_alerts,
                    source="application",
                )
            )

            # Get rule trigger counts
            for rule_id, rule in self._rules.items():
                self.record_metric(
                    SecurityMetric(
                        metric_name=f"rule_triggers_{rule_id}",
                        metric_type="counter",
                        value=rule.trigger_count,
                        source="monitoring_rules",
                        labels={"rule_id": rule_id, "rule_name": rule.name},
                    )
                )

        except Exception as e:
            logger.error(f"Error collecting application metrics: {e}")

    def _evaluate_rules(self) -> None:
        """Evaluate threshold-based monitoring rules."""
        while self._monitoring_active:
            try:
                for rule in self._rules.values():
                    if not rule.enabled:
                        continue

                    if rule.monitoring_type not in [
                        MonitoringType.SCHEDULED,
                        MonitoringType.BATCH,
                    ]:
                        continue

                    # Check if it's time to evaluate
                    if (
                        rule.last_triggered is None
                        or datetime.now() - rule.last_triggered
                        > timedelta(seconds=rule.check_interval)
                    ):
                        if self._evaluate_threshold_rule(rule):
                            context = {"rule_id": rule.rule_id, "rule_name": rule.name}
                            self.create_alert(rule, context)

                            rule.last_triggered = datetime.now()
                            rule.trigger_count += 1

                # Sleep before next evaluation cycle
                time.sleep(30)

            except Exception as e:
                logger.error(f"Error evaluating monitoring rules: {e}")
                time.sleep(30)

    def _evaluate_threshold_rule(self, rule: MonitoringRule) -> bool:
        """Evaluate threshold-based monitoring rule."""
        conditions = rule.conditions
        thresholds = rule.thresholds

        if "metric" not in conditions or "max_count" not in thresholds:
            return False

        metric_name = conditions["metric"]
        max_count = thresholds["max_count"]
        time_window = thresholds.get("time_window", 300)  # 5 minutes default

        # Get metrics for the specified time window
        cutoff_time = datetime.now() - timedelta(seconds=time_window)
        recent_metrics = [
            m for m in self._metrics.get(metric_name, []) if m.timestamp > cutoff_time
        ]

        # Count metric occurrences
        count = len(recent_metrics)

        logger.debug(
            f"Rule {rule.rule_id}: {count} occurrences of {metric_name} in {time_window}s (threshold: {max_count})"
        )

        return count > max_count

    def _process_alerts(self) -> None:
        """Process security alerts."""
        while self._monitoring_active:
            try:
                # Process escalation rules
                self._process_alert_escalations()

                # Process notification channels
                self._process_alert_notifications()

                # Sleep before next processing cycle
                time.sleep(30)

            except Exception as e:
                logger.error(f"Error processing alerts: {e}")
                time.sleep(30)

    def _process_alert_escalations(self) -> None:
        """Process alert escalation rules."""
        now = datetime.now()

        for alert in self._alerts.values():
            if alert.status in [AlertStatus.RESOLVED, AlertStatus.DISMISSED]:
                continue

            # Check escalation conditions
            time_since_creation = now - alert.created_at

            # Escalate critical alerts after 1 hour
            if (
                alert.severity == AlertSeverity.CRITICAL
                and time_since_creation > timedelta(hours=1)
                and alert.status == AlertStatus.NEW
            ):
                alert.status = AlertStatus.INVESTIGATING
                alert.updated_at = now
                logger.warning(f"Alert {alert.alert_id} escalated to investigation")

            # Escalate high alerts after 4 hours
            elif (
                alert.severity == AlertSeverity.HIGH
                and time_since_creation > timedelta(hours=4)
                and alert.status == AlertStatus.NEW
            ):
                alert.status = AlertStatus.INVESTIGATING
                alert.updated_at = now
                logger.warning(f"Alert {alert.alert_id} escalated to investigation")

    def _process_alert_notifications(self) -> None:
        """Process alert notifications."""
        # This would integrate with notification systems
        # For now, just log critical and high severity alerts
        for alert in self._alerts.values():
            if alert.status == AlertStatus.NEW and alert.severity in [
                AlertSeverity.CRITICAL,
                AlertSeverity.HIGH,
            ]:
                logger.critical(
                    f"NEW SECURITY ALERT [{alert.severity.value.upper()}]: {alert.title}"
                )
                logger.critical(f"Description: {alert.description}")
                if alert.user_id:
                    logger.critical(f"User: {alert.user_id}")
                if alert.source_ip:
                    logger.critical(f"Source IP: {alert.source_ip}")

    def _execute_response_actions(
        self, alert: SecurityAlert, actions: List[str]
    ) -> None:
        """Execute automated response actions."""
        for action in actions:
            try:
                if action == "block_ip" and alert.source_ip:
                    self._block_ip_address(alert.source_ip)
                elif action == "audit_user" and alert.user_id:
                    self._audit_user_account(alert.user_id)
                elif action == "audit_event":
                    self._audit_security_event(alert)
                elif action == "notify_security":
                    self._notify_security_team(alert)
                else:
                    logger.warning(f"Unknown response action: {action}")

            except Exception as e:
                logger.error(f"Error executing response action {action}: {e}")

    def _trigger_alert_callbacks(self, alert: SecurityAlert) -> None:
        """Trigger registered alert callbacks."""
        for callback in self._alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")

    # Response action implementations
    def _block_ip_address(self, ip_address: str) -> None:
        """Block IP address (placeholder implementation)."""
        logger.warning(f"Would block IP address: {ip_address}")
        # In production, integrate with firewall/iptables

    def _audit_user_account(self, user_id: str) -> None:
        """Audit user account (placeholder implementation)."""
        logger.warning(f"Would audit user account: {user_id}")
        # In production, perform account audit

    def _audit_security_event(self, alert: SecurityAlert) -> None:
        """Audit security event (placeholder implementation)."""
        logger.warning(f"Would audit security event: {alert.alert_id}")
        # In production, perform detailed event audit

    def _notify_security_team(self, alert: SecurityAlert) -> None:
        """Notify security team (placeholder implementation)."""
        logger.warning(f"Would notify security team of alert: {alert.alert_id}")
        # In production, send notifications via email, Slack, etc.

    def export_monitoring_data(self, output_path: str, format: str = "json") -> None:
        """Export monitoring data."""
        export_data = {
            "export_metadata": {
                "generated_at": datetime.now().isoformat(),
                "export_format": format,
            },
            "alerts": [self._alert_to_dict(alert) for alert in self._alerts.values()],
            "metrics": {
                metric_name: [
                    {
                        "timestamp": m.timestamp.isoformat(),
                        "value": m.value,
                        "labels": m.labels,
                        "source": m.source,
                    }
                    for m in metrics
                ]
                for metric_name, metrics in self._metrics.items()
            },
            "rules": [
                {
                    "rule_id": r.rule_id,
                    "name": r.name,
                    "description": r.description,
                    "enabled": r.enabled,
                    "trigger_count": r.trigger_count,
                    "last_triggered": r.last_triggered.isoformat()
                    if r.last_triggered
                    else None,
                }
                for r in self._rules.values()
            ],
        }

        if format.lower() == "json":
            with open(output_path, "w") as f:
                json.dump(export_data, f, indent=2, default=str)
        else:
            # Add YAML export support if needed
            import yaml

            with open(output_path, "w") as f:
                yaml.dump(export_data, f, default_flow_style=False)

    def _alert_to_dict(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return {
            "alert_id": alert.alert_id,
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity.value,
            "category": alert.category,
            "status": alert.status.value,
            "source": alert.source,
            "source_ip": alert.source_ip,
            "user_id": alert.user_id,
            "resource": alert.resource,
            "action": alert.action,
            "event_count": alert.event_count,
            "first_occurrence": alert.first_occurrence.isoformat(),
            "last_occurrence": alert.last_occurrence.isoformat(),
            "created_at": alert.created_at.isoformat(),
            "updated_at": alert.updated_at.isoformat(),
            "acknowledged_by": alert.acknowledged_by,
            "acknowledged_at": alert.acknowledged_at.isoformat()
            if alert.acknowledged_at
            else None,
            "resolved_by": alert.resolved_by,
            "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
            "context": alert.context,
            "tags": list(alert.tags),
        }


# Global security monitor instance
_security_monitor = None


def get_security_monitor(config: Optional[Dict[str, Any]] = None) -> SecurityMonitor:
    """Get global security monitor instance."""
    global _security_monitor
    if _security_monitor is None:
        _security_monitor = SecurityMonitor(config)
    return _security_monitor


# Convenience functions
def record_security_metric(name: str, value: Union[int, float], **kwargs) -> None:
    """Record security metric."""
    metric = SecurityMetric(metric_name=name, value=value, **kwargs)
    get_security_monitor().record_metric(metric)


def create_security_alert(
    title: str, description: str, severity: str = "medium"
) -> SecurityAlert:
    """Create security alert."""
    rule = MonitoringRule(
        rule_id=f"manual_{int(time.time())}",
        name="Manual Alert",
        description="Manually created alert",
        severity=AlertSeverity(severity.lower()),
        alert_title=title,
        alert_description=description,
    )

    context = {"manual": True, "created_by": "user"}
    return get_security_monitor().create_alert(rule, context)


def get_security_dashboard() -> Dict[str, Any]:
    """Get security dashboard data."""
    return get_security_monitor().get_dashboard_data()


# Export main classes and functions
__all__ = [
    "SecurityMonitor",
    "SecurityAlert",
    "SecurityMetric",
    "MonitoringRule",
    "AlertSeverity",
    "AlertStatus",
    "ThreatLevel",
    "MonitoringType",
    "get_security_monitor",
    "record_security_metric",
    "create_security_alert",
    "get_security_dashboard",
]
