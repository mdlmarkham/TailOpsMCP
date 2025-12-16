"""
Event alerting and notification system for TailOpsMCP observability.

This module provides comprehensive alerting capabilities including configurable rules,
escalation policies, notification channels, and alert management.
"""

import smtplib
import os
from datetime import datetime, timedelta
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

from src.models.event_models import (
    SystemEvent,
    EventType,
    EventSeverity,
    EventSource,
    EventCategory,
)
from src.utils.logging_config import get_logger


class AlertStatus(Enum):
    """Alert status enumeration."""

    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    ESCALATED = "escalated"
    EXPIRED = "expired"


class NotificationChannel(Enum):
    """Available notification channels."""

    EMAIL = "email"
    WEBHOOK = "webhook"
    SLACK = "slack"
    TEAMS = "teams"
    SMS = "sms"
    CONSOLE = "console"
    FILE = "file"
    DATABASE = "database"


@dataclass
class AlertRule:
    """Configurable alert rule."""

    name: str
    description: str
    condition: str  # Python expression for condition evaluation
    severity: EventSeverity
    enabled: bool = True
    priority: int = 0

    # Notification settings
    channels: List[NotificationChannel] = field(default_factory=list)
    recipients: List[str] = field(default_factory=list)

    # Timing settings
    evaluation_interval: int = 60  # seconds
    suppression_duration: int = 300  # seconds (5 minutes)
    escalation_rules: List["EscalationRule"] = field(default_factory=list)

    # Thresholds
    threshold_count: int = 1  # Number of events needed to trigger
    threshold_time_window: int = 60  # Time window in seconds

    # Additional settings
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def evaluate(self, events: List[SystemEvent]) -> bool:
        """Evaluate if the rule should trigger based on events."""
        if not self.enabled or not events:
            return False

        # Filter events based on condition
        filtered_events = []
        for event in events:
            if self._evaluate_condition(event):
                filtered_events.append(event)

        # Check threshold
        if len(filtered_events) >= self.threshold_count:
            # Check time window if needed
            if self.threshold_time_window > 0 and len(filtered_events) > 1:
                time_span = max(e.timestamp for e in filtered_events) - min(
                    e.timestamp for e in filtered_events
                )
                return time_span.total_seconds() <= self.threshold_time_window

            return True

        return False

    def _evaluate_condition(self, event: SystemEvent) -> bool:
        """Evaluate condition against a single event."""
        try:
            # Simple condition evaluation (in production, use a safe expression evaluator)
            # This is a simplified implementation
            condition_parts = self.condition.split()

            # Check event type
            if "event_type" in self.condition:
                for part in condition_parts:
                    if hasattr(EventType, part.upper()):
                        if event.event_type.value == part:
                            return True

            # Check severity
            if "severity" in self.condition:
                for part in condition_parts:
                    if hasattr(EventSeverity, part.upper()):
                        if event.severity.value == part:
                            return True

            # Check source
            if "source" in self.condition:
                for part in condition_parts:
                    if hasattr(EventSource, part.upper()):
                        if event.source.value == part:
                            return True

            # Check category
            if "category" in self.condition:
                for part in condition_parts:
                    if hasattr(EventCategory, part.upper()):
                        if event.category.value == part:
                            return True

            # Default: no match
            return False

        except Exception as e:
            get_logger("alert_rule").error(
                f"Error evaluating condition for {self.name}: {e}"
            )
            return False


@dataclass
class EscalationRule:
    """Alert escalation rule."""

    name: str
    delay_minutes: int  # Delay before escalation
    new_severity: EventSeverity
    additional_recipients: List[str] = field(default_factory=list)
    additional_channels: List[NotificationChannel] = field(default_factory=list)
    condition: Optional[str] = None  # Optional additional condition


@dataclass
class Alert:
    """Alert object."""

    id: str
    rule_name: str
    title: str
    description: str
    severity: EventSeverity
    status: AlertStatus = AlertStatus.ACTIVE
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    # Event information
    triggering_events: List[SystemEvent] = field(default_factory=list)
    event_count: int = 0

    # Escalation
    escalation_level: int = 0
    escalation_history: List[Dict[str, Any]] = field(default_factory=list)

    # Acknowledgment
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    acknowledgment_note: Optional[str] = None

    # Resolution
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    resolution_note: Optional[str] = None

    # Suppression
    suppressed_until: Optional[datetime] = None
    suppression_reason: Optional[str] = None

    # Metadata
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def acknowledge(self, user_id: str, note: Optional[str] = None) -> None:
        """Acknowledge the alert."""
        self.status = AlertStatus.ACKNOWLEDGED
        self.acknowledged_at = datetime.utcnow()
        self.acknowledged_by = user_id
        self.acknowledgment_note = note
        self.updated_at = datetime.utcnow()

    def resolve(self, user_id: str, note: Optional[str] = None) -> None:
        """Resolve the alert."""
        self.status = AlertStatus.RESOLVED
        self.resolved_at = datetime.utcnow()
        self.resolved_by = user_id
        self.resolution_note = note
        self.updated_at = datetime.utcnow()

    def suppress(self, duration_minutes: int, reason: str) -> None:
        """Suppress the alert."""
        self.status = AlertStatus.SUPPRESSED
        self.suppressed_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
        self.suppression_reason = reason
        self.updated_at = datetime.utcnow()

    def escalate(
        self,
        new_severity: EventSeverity,
        level: int,
        additional_info: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Escalate the alert."""
        self.escalation_level = level
        self.severity = new_severity
        self.status = AlertStatus.ESCALATED

        escalation_record = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": level,
            "new_severity": new_severity.value,
            "additional_info": additional_info or {},
        }
        self.escalation_history.append(escalation_record)
        self.updated_at = datetime.utcnow()

    def is_expired(self) -> bool:
        """Check if alert is expired."""
        return self.suppressed_until and datetime.utcnow() > self.suppressed_until

    def needs_escalation(self) -> bool:
        """Check if alert needs escalation."""
        return (
            self.status in [AlertStatus.ACTIVE, AlertStatus.ACKNOWLEDGED]
            and self.escalation_level >= 0
        )


@dataclass
class NotificationConfig:
    """Configuration for notification channels."""

    # Email settings
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_use_tls: bool = True

    # Webhook settings
    webhook_urls: Dict[str, str] = field(default_factory=dict)  # channel_name -> URL

    # Slack settings
    slack_webhook_url: Optional[str] = None
    slack_token: Optional[str] = None

    # Teams settings
    teams_webhook_url: Optional[str] = None

    # SMS settings (placeholder)
    sms_api_key: Optional[str] = None
    sms_from_number: Optional[str] = None

    # File settings
    alert_log_file: Optional[str] = None


class NotificationService:
    """Service for sending notifications through various channels."""

    def __init__(self, config: NotificationConfig):
        self.config = config
        self.logger = get_logger("notification_service")

    async def send_notification(
        self, channel: NotificationChannel, alert: Alert, recipients: List[str]
    ) -> bool:
        """Send notification through specified channel."""
        try:
            if channel == NotificationChannel.EMAIL:
                return await self._send_email(alert, recipients)
            elif channel == NotificationChannel.WEBHOOK:
                return await self._send_webhook(alert, recipients)
            elif channel == NotificationChannel.SLACK:
                return await self._send_slack(alert, recipients)
            elif channel == NotificationChannel.TEAMS:
                return await self._send_teams(alert, recipients)
            elif channel == NotificationChannel.CONSOLE:
                return await self._send_console(alert, recipients)
            elif channel == NotificationChannel.FILE:
                return await self._send_file(alert, recipients)
            else:
                self.logger.warning(f"Unsupported notification channel: {channel}")
                return False

        except Exception as e:
            self.logger.error(f"Failed to send notification via {channel}: {e}")
            return False

    async def _send_email(self, alert: Alert, recipients: List[str]) -> bool:
        """Send email notification."""
        if not self.config.smtp_host:
            self.logger.error("SMTP host not configured")
            return False

        try:
            # Create email message
            msg = MimeMultipart()
            msg["From"] = self.config.smtp_username
            msg["To"] = ", ".join(recipients)
            msg["Subject"] = f"[{alert.severity.value.upper()}] {alert.title}"

            # Email body
            body = self._format_alert_message(alert)
            msg.attach(MimeText(body, "plain"))

            # Send email
            with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port) as server:
                if self.config.smtp_use_tls:
                    server.starttls()
                if self.config.smtp_username and self.config.smtp_password:
                    server.login(self.config.smtp_username, self.config.smtp_password)
                server.send_message(msg)

            self.logger.info(f"Email notification sent to {recipients}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to send email: {e}")
            return False

    async def _send_webhook(self, alert: Alert, recipients: List[str]) -> bool:
        """Send webhook notification."""
        import requests

        try:
            payload = {
                "alert_id": alert.id,
                "title": alert.title,
                "description": alert.description,
                "severity": alert.severity.value,
                "status": alert.status.value,
                "created_at": alert.created_at.isoformat(),
                "event_count": alert.event_count,
                "triggering_events": [e.to_dict() for e in alert.triggering_events],
            }

            # Send to each webhook URL
            success_count = 0
            for recipient in recipients:
                if recipient in self.config.webhook_urls:
                    url = self.config.webhook_urls[recipient]
                    response = requests.post(url, json=payload, timeout=10)
                    if response.status_code == 200:
                        success_count += 1

            return success_count > 0

        except Exception as e:
            self.logger.error(f"Failed to send webhook: {e}")
            return False

    async def _send_slack(self, alert: Alert, recipients: List[str]) -> bool:
        """Send Slack notification."""
        try:
            import requests

            if not self.config.slack_webhook_url:
                self.logger.error("Slack webhook URL not configured")
                return False

            # Format message for Slack
            color = self._get_severity_color(alert.severity)
            message = {
                "attachments": [
                    {
                        "color": color,
                        "title": alert.title,
                        "text": alert.description,
                        "fields": [
                            {
                                "title": "Severity",
                                "value": alert.severity.value,
                                "short": True,
                            },
                            {
                                "title": "Status",
                                "value": alert.status.value,
                                "short": True,
                            },
                            {
                                "title": "Events",
                                "value": str(alert.event_count),
                                "short": True,
                            },
                            {
                                "title": "Created",
                                "value": alert.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                                "short": True,
                            },
                        ],
                    }
                ]
            }

            response = requests.post(
                self.config.slack_webhook_url, json=message, timeout=10
            )
            return response.status_code == 200

        except Exception as e:
            self.logger.error(f"Failed to send Slack notification: {e}")
            return False

    async def _send_teams(self, alert: Alert, recipients: List[str]) -> bool:
        """Send Microsoft Teams notification."""
        try:
            import requests

            if not self.config.teams_webhook_url:
                self.logger.error("Teams webhook URL not configured")
                return False

            # Format message for Teams
            message = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": self._get_severity_color(alert.severity),
                "summary": alert.title,
                "sections": [
                    {
                        "activityTitle": alert.title,
                        "activitySubtitle": alert.description,
                        "facts": [
                            {"name": "Severity", "value": alert.severity.value},
                            {"name": "Status", "value": alert.status.value},
                            {"name": "Events", "value": str(alert.event_count)},
                            {
                                "name": "Created",
                                "value": alert.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                            },
                        ],
                    }
                ],
            }

            response = requests.post(
                self.config.teams_webhook_url, json=message, timeout=10
            )
            return response.status_code == 200

        except Exception as e:
            self.logger.error(f"Failed to send Teams notification: {e}")
            return False

    async def _send_console(self, alert: Alert, recipients: List[str]) -> bool:
        """Send console notification."""
        try:
            message = self._format_alert_message(alert)
            print(
                f"\n{'=' * 60}\nALERT NOTIFICATION\n{'=' * 60}\n{message}\n{'=' * 60}\n"
            )
            return True
        except Exception as e:
            self.logger.error(f"Failed to send console notification: {e}")
            return False

    async def _send_file(self, alert: Alert, recipients: List[str]) -> bool:
        """Send file notification."""
        try:
            if not self.config.alert_log_file:
                return False

            message = self._format_alert_message(alert)
            timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

            with open(self.config.alert_log_file, "a") as f:
                f.write(f"[{timestamp}] ALERT: {message}\n")

            return True
        except Exception as e:
            self.logger.error(f"Failed to send file notification: {e}")
            return False

    def _format_alert_message(self, alert: Alert) -> str:
        """Format alert message for notification."""
        lines = [
            f"Alert ID: {alert.id}",
            f"Rule: {alert.rule_name}",
            f"Title: {alert.title}",
            f"Description: {alert.description}",
            f"Severity: {alert.severity.value}",
            f"Status: {alert.status.value}",
            f"Created: {alert.created_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Events: {alert.event_count}",
        ]

        if alert.triggering_events:
            lines.append(f"Latest Event: {alert.triggering_events[-1].title}")
            lines.append(
                f"Latest Event Time: {alert.triggering_events[-1].timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
            )

        return "\n".join(lines)

    def _get_severity_color(self, severity: EventSeverity) -> str:
        """Get color code for severity level."""
        color_map = {
            EventSeverity.CRITICAL: "danger",
            EventSeverity.ERROR: "warning",
            EventSeverity.WARNING: "#ff9500",
            EventSeverity.INFO: "#36a64f",
            EventSeverity.DEBUG: "#808080",
        }
        return color_map.get(severity, "#808080")


class EventAlerting:
    """Event alerting system for managing alerts and notifications."""

    def __init__(self, notification_config: Optional[NotificationConfig] = None):
        self.notification_config = (
            notification_config or self._load_notification_config()
        )
        self.notification_service = NotificationService(self.notification_config)

        self.logger = get_logger("event_alerting")

        # Alert management
        self.alert_rules: List[AlertRule] = []
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: List[Alert] = []

        # Suppression rules
        self.suppression_rules: List[AlertRule] = []

        # Statistics
        self.stats = {
            "alerts_created": 0,
            "alerts_resolved": 0,
            "alerts_escalated": 0,
            "notifications_sent": 0,
            "evaluation_cycles": 0,
        }

    def _load_notification_config(self) -> NotificationConfig:
        """Load notification configuration from environment variables."""
        return NotificationConfig(
            smtp_host=os.getenv("SMTP_HOST"),
            smtp_port=int(os.getenv("SMTP_PORT", "587")),
            smtp_username=os.getenv("SMTP_USERNAME"),
            smtp_password=os.getenv("SMTP_PASSWORD"),
            slack_webhook_url=os.getenv("SLACK_WEBHOOK_URL"),
            teams_webhook_url=os.getenv("TEAMS_WEBHOOK_URL"),
            alert_log_file=os.getenv("ALERT_LOG_FILE", "./logs/alerts.log"),
        )

    async def add_alert_rule(self, rule: AlertRule) -> None:
        """Add an alert rule."""
        self.alert_rules.append(rule)
        self.logger.info(f"Added alert rule: {rule.name}")

    async def remove_alert_rule(self, rule_name: str) -> bool:
        """Remove an alert rule."""
        original_length = len(self.alert_rules)
        self.alert_rules = [rule for rule in self.alert_rules if rule.name != rule_name]
        removed = len(self.alert_rules) < original_length

        if removed:
            self.logger.info(f"Removed alert rule: {rule_name}")

        return removed

    async def evaluate_alert_rules(self, events: List[SystemEvent]) -> List[Alert]:
        """Evaluate all alert rules against events."""
        self.stats["evaluation_cycles"] += 1
        new_alerts = []

        for rule in self.alert_rules:
            try:
                if rule.evaluate(events):
                    alert = await self._create_alert_from_rule(rule, events)
                    new_alerts.append(alert)

            except Exception as e:
                self.logger.error(f"Error evaluating rule {rule.name}: {e}")

        return new_alerts

    async def _create_alert_from_rule(
        self, rule: AlertRule, events: List[SystemEvent]
    ) -> Alert:
        """Create an alert from a rule evaluation."""
        import uuid

        # Filter events that triggered this rule
        triggering_events = []
        for event in events:
            if rule._evaluate_condition(event):
                triggering_events.append(event)

        # Create alert
        alert = Alert(
            id=str(uuid.uuid4()),
            rule_name=rule.name,
            title=f"Alert: {rule.name}",
            description=f"Rule '{rule.name}' triggered by {len(triggering_events)} events",
            severity=rule.severity,
            triggering_events=triggering_events,
            event_count=len(triggering_events),
            tags=rule.tags.copy(),
            metadata=rule.metadata.copy(),
        )

        # Add to active alerts
        self.active_alerts[alert.id] = alert
        self.alert_history.append(alert)
        self.stats["alerts_created"] += 1

        # Send notifications
        await self._send_alert_notifications(alert, rule)

        # Check for escalation
        await self._check_escalation(alert, rule)

        self.logger.info(f"Created alert {alert.id} from rule {rule.name}")
        return alert

    async def _send_alert_notifications(self, alert: Alert, rule: AlertRule) -> None:
        """Send notifications for an alert."""
        success_count = 0

        for channel in rule.channels:
            if await self.notification_service.send_notification(
                channel, alert, rule.recipients
            ):
                success_count += 1

        if success_count > 0:
            self.stats["notifications_sent"] += 1
            self.logger.info(f"Sent {success_count} notifications for alert {alert.id}")

    async def _check_escalation(self, alert: Alert, rule: AlertRule) -> None:
        """Check if alert needs escalation."""
        for escalation_rule in rule.escalation_rules:
            if (
                alert.created_at + timedelta(minutes=escalation_rule.delay_minutes)
                <= datetime.utcnow()
            ):
                # Time to escalate
                alert.escalate(
                    escalation_rule.new_severity,
                    alert.escalation_level + 1,
                    {"escalation_rule": escalation_rule.name},
                )

                # Send escalation notifications
                additional_recipients = (
                    rule.recipients + escalation_rule.additional_recipients
                )
                additional_channels = (
                    rule.channels + escalation_rule.additional_channels
                )

                for channel in additional_channels:
                    await self.notification_service.send_notification(
                        channel, alert, additional_recipients
                    )

                self.stats["alerts_escalated"] += 1
                self.logger.info(
                    f"Escalated alert {alert.id} to level {alert.escalation_level}"
                )
                break  # Only escalate once per check

    async def acknowledge_alert(
        self, alert_id: str, user_id: str, note: Optional[str] = None
    ) -> bool:
        """Acknowledge an alert."""
        alert = self.active_alerts.get(alert_id)
        if alert:
            alert.acknowledge(user_id, note)
            self.logger.info(f"Acknowledged alert {alert_id} by {user_id}")
            return True
        return False

    async def resolve_alert(
        self, alert_id: str, user_id: str, note: Optional[str] = None
    ) -> bool:
        """Resolve an alert."""
        alert = self.active_alerts.get(alert_id)
        if alert:
            alert.resolve(user_id, note)
            self.stats["alerts_resolved"] += 1

            # Move to history
            if alert_id in self.active_alerts:
                del self.active_alerts[alert_id]

            self.logger.info(f"Resolved alert {alert_id} by {user_id}")
            return True
        return False

    async def suppress_alert(
        self, alert_id: str, duration_minutes: int, reason: str
    ) -> bool:
        """Suppress an alert."""
        alert = self.active_alerts.get(alert_id)
        if alert:
            alert.suppress(duration_minutes, reason)
            self.logger.info(
                f"Suppressed alert {alert_id} for {duration_minutes} minutes"
            )
            return True
        return False

    async def get_active_alerts(
        self, severity: Optional[EventSeverity] = None
    ) -> List[Alert]:
        """Get active alerts, optionally filtered by severity."""
        alerts = list(self.active_alerts.values())

        # Filter by severity if specified
        if severity:
            alerts = [alert for alert in alerts if alert.severity == severity]

        # Filter out suppressed/expired alerts
        alerts = [alert for alert in alerts if not alert.is_expired()]

        return sorted(alerts, key=lambda a: a.created_at, reverse=True)

    async def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert system statistics."""
        active_count = len(
            [a for a in self.active_alerts.values() if not a.is_expired()]
        )

        # Count by severity
        severity_counts = {}
        for severity in EventSeverity:
            severity_counts[severity.value] = len(
                [
                    a
                    for a in self.active_alerts.values()
                    if a.severity == severity and not a.is_expired()
                ]
            )

        return {
            "total_alerts_created": self.stats["alerts_created"],
            "active_alerts": active_count,
            "resolved_alerts": self.stats["alerts_resolved"],
            "escalated_alerts": self.stats["alerts_escalated"],
            "notifications_sent": self.stats["notifications_sent"],
            "evaluation_cycles": self.stats["evaluation_cycles"],
            "alerts_by_severity": severity_counts,
            "alert_rules_count": len(self.alert_rules),
        }

    async def cleanup_expired_alerts(self) -> int:
        """Clean up expired alerts."""
        expired_count = 0
        expired_alerts = []

        for alert_id, alert in self.active_alerts.items():
            if alert.is_expired():
                expired_alerts.append(alert_id)

        for alert_id in expired_alerts:
            del self.active_alerts[alert_id]
            expired_count += 1

        if expired_count > 0:
            self.logger.info(f"Cleaned up {expired_count} expired alerts")

        return expired_count


# Default alert rules
def create_default_alert_rules() -> List[AlertRule]:
    """Create default alert rules."""
    return [
        AlertRule(
            name="critical_system_error",
            description="Alert on critical system errors",
            condition="severity == 'critical'",
            severity=EventSeverity.CRITICAL,
            channels=[NotificationChannel.EMAIL, NotificationChannel.CONSOLE],
            recipients=["admin@example.com"],
            escalation_rules=[
                EscalationRule(
                    name="escalate_critical",
                    delay_minutes=15,
                    new_severity=EventSeverity.CRITICAL,
                    additional_recipients=["ops-team@example.com"],
                )
            ],
        ),
        AlertRule(
            name="service_down",
            description="Alert when services go down",
            condition="event_type == 'service_status' and details.get('state') == 'failed'",
            severity=EventSeverity.ERROR,
            channels=[NotificationChannel.SLACK, NotificationChannel.CONSOLE],
            recipients=["ops"],
            threshold_count=1,
            suppression_duration=300,
        ),
        AlertRule(
            name="high_resource_usage",
            description="Alert on high resource usage",
            condition="event_type == 'resource_threshold' and resource_usage.cpu_percent > 90",
            severity=EventSeverity.WARNING,
            channels=[NotificationChannel.CONSOLE],
            recipients=["ops"],
            threshold_count=3,
            threshold_time_window=300,
        ),
        AlertRule(
            name="security_violation",
            description="Alert on security violations",
            condition="category == 'security' and severity in ['error', 'critical']",
            severity=EventSeverity.ERROR,
            channels=[NotificationChannel.EMAIL, NotificationChannel.SLACK],
            recipients=["security@example.com"],
            escalation_rules=[
                EscalationRule(
                    name="escalate_security",
                    delay_minutes=5,
                    new_severity=EventSeverity.CRITICAL,
                    additional_recipients=["security-lead@example.com"],
                )
            ],
        ),
    ]


# Global instances
_event_alerting_instance = None


def get_event_alerting() -> EventAlerting:
    """Get the global event alerting instance."""
    global _event_alerting_instance
    if _event_alerting_instance is None:
        _event_alerting_instance = EventAlerting()
    return _event_alerting_instance


async def initialize_alerting_system() -> EventAlerting:
    """Initialize the alerting system with default rules."""
    alerting = get_event_alerting()

    # Add default alert rules
    default_rules = create_default_alert_rules()
    for rule in default_rules:
        await alerting.add_alert_rule(rule)

    get_logger("alerting_system").info(
        f"Initialized alerting system with {len(default_rules)} default rules"
    )
    return alerting
