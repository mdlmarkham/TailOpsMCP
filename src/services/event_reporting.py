"""
Event reporting and dashboard system for TailOpsMCP observability.

This module provides comprehensive reporting capabilities including health reports,
security reports, operational reports, and customizable dashboards.
"""

import json
import os
from datetime import datetime
from datetime import timezone, timezone, timezone, timedelta
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field, asdict

from src.models.event_models import (
    SystemEvent,
    EventType,
    EventSeverity,
    EventSource,
    EventCategory,
)
from src.services.event_store import get_event_store
from src.services.event_analyzer import get_event_analyzer
from src.services.event_alerting import get_event_alerting
from src.utils.logging_config import get_logger


@dataclass
class TimeRange:
    """Represents a time range for reporting."""

    start_time: datetime
    end_time: datetime

    def __post_init__(self):
        if self.start_time >= self.end_time:
            raise ValueError("Start time must be before end time")

    @classmethod
    def from_hours(cls, hours: int) -> "TimeRange":
        """Create time range from hours ago."""
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours)
        return cls(start_time, end_time)

    @classmethod
    def from_days(cls, days: int) -> "TimeRange":
        """Create time range from days ago."""
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=days)
        return cls(start_time, end_time)

    @classmethod
    def last_hour(cls) -> "TimeRange":
        """Create time range for last hour."""
        return cls.from_hours(1)

    @classmethod
    def last_24_hours(cls) -> "TimeRange":
        """Create time range for last 24 hours."""
        return cls.from_hours(24)

    @classmethod
    def last_week(cls) -> "TimeRange":
        """Create time range for last week."""
        return cls.from_days(7)

    @classmethod
    def last_month(cls) -> "TimeRange":
        """Create time range for last month."""
        return cls.from_days(30)


@dataclass
class HealthReport:
    """Health report containing system health information."""

    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    time_range: TimeRange = field(default_factory=TimeRange.last_24_hours)

    # Overall health
    fleet_health_score: float = 0.0
    system_health_status: str = "unknown"

    # Health metrics
    total_systems: int = 0
    healthy_systems: int = 0
    unhealthy_systems: int = 0
    critical_systems: int = 0

    # Health trends
    health_trends: List[Dict[str, Any]] = field(default_factory=list)
    health_improvements: List[str] = field(default_factory=list)
    health_degradations: List[str] = field(default_factory=list)

    # Critical issues
    critical_issues: List[SystemEvent] = field(default_factory=list)
    recent_failures: List[SystemEvent] = field(default_factory=list)

    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    action_items: List[Dict[str, str]] = field(default_factory=list)

    # Supporting data
    health_events: List[SystemEvent] = field(default_factory=list)
    system_details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = asdict(self)
        result["generated_at"] = self.generated_at.isoformat()
        result["time_range"] = {
            "start_time": self.time_range.start_time.isoformat(),
            "end_time": self.time_range.end_time.isoformat(),
        }
        return result


@dataclass
class SecurityReport:
    """Security report containing security-related information."""

    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    time_range: TimeRange = field(default_factory=TimeRange.last_24_hours)

    # Security overview
    security_score: float = 0.0
    security_status: str = "unknown"

    # Security events
    total_security_events: int = 0
    critical_security_events: int = 0
    security_violations: int = 0
    policy_violations: int = 0

    # Security categories
    authentication_events: int = 0
    authorization_events: int = 0
    policy_events: int = 0
    anomaly_events: int = 0

    # Threat analysis
    security_trends: List[Dict[str, Any]] = field(default_factory=list)
    threat_patterns: List[Dict[str, Any]] = field(default_factory=list)

    # Critical security issues
    critical_security_issues: List[SystemEvent] = field(default_factory=list)
    policy_violation_events: List[SystemEvent] = field(default_factory=list)

    # Recommendations
    security_recommendations: List[str] = field(default_factory=list)
    compliance_issues: List[str] = field(default_factory=list)

    # Supporting data
    security_events: List[SystemEvent] = field(default_factory=list)
    risk_assessment: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = asdict(self)
        result["generated_at"] = self.generated_at.isoformat()
        result["time_range"] = {
            "start_time": self.time_range.start_time.isoformat(),
            "end_time": self.time_range.end_time.isoformat(),
        }
        return result


@dataclass
class OperationalReport:
    """Operational report containing operational metrics and insights."""

    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    time_range: TimeRange = field(default_factory=TimeRange.last_24_hours)

    # Operational overview
    operational_score: float = 0.0
    operational_status: str = "unknown"

    # Operational metrics
    total_operations: int = 0
    successful_operations: int = 0
    failed_operations: int = 0
    operation_success_rate: float = 0.0

    # Performance metrics
    average_operation_duration: float = 0.0
    performance_trends: List[Dict[str, Any]] = field(default_factory=list)
    resource_usage_trends: List[Dict[str, Any]] = field(default_factory=list)

    # Operational insights
    operational_trends: List[Dict[str, Any]] = field(default_factory=list)
    performance_insights: List[Dict[str, Any]] = field(default_factory=list)

    # Critical operational issues
    critical_operational_issues: List[SystemEvent] = field(default_factory=list)
    performance_issues: List[SystemEvent] = field(default_factory=list)

    # Recommendations
    operational_recommendations: List[str] = field(default_factory=list)
    optimization_opportunities: List[str] = field(default_factory=list)

    # Supporting data
    operational_events: List[SystemEvent] = field(default_factory=list)
    performance_metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = asdict(self)
        result["generated_at"] = self.generated_at.isoformat()
        result["time_range"] = {
            "start_time": self.time_range.start_time.isoformat(),
            "end_time": self.time_range.end_time.isoformat(),
        }
        return result


@dataclass
class ComplianceReport:
    """Compliance report containing compliance and audit information."""

    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    time_range: TimeRange = field(default_factory=TimeRange.last_24_hours)

    # Compliance overview
    compliance_score: float = 0.0
    compliance_status: str = "unknown"

    # Compliance metrics
    total_compliance_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    compliance_rate: float = 0.0

    # Audit events
    total_audit_events: int = 0
    policy_compliance_events: int = 0
    security_compliance_events: int = 0
    operational_compliance_events: int = 0

    # Compliance trends
    compliance_trends: List[Dict[str, Any]] = field(default_factory=list)
    audit_trends: List[Dict[str, Any]] = field(default_factory=list)

    # Compliance issues
    compliance_violations: List[SystemEvent] = field(default_factory=list)
    audit_findings: List[SystemEvent] = field(default_factory=list)

    # Recommendations
    compliance_recommendations: List[str] = field(default_factory=list)
    audit_recommendations: List[str] = field(default_factory=list)

    # Supporting data
    compliance_events: List[SystemEvent] = field(default_factory=list)
    audit_events: List[SystemEvent] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = asdict(self)
        result["generated_at"] = self.generated_at.isoformat()
        result["time_range"] = {
            "start_time": self.time_range.start_time.isoformat(),
            "end_time": self.time_range.end_time.isoformat(),
        }
        return result


@dataclass
class Dashboard:
    """Dashboard configuration and data."""

    name: str
    description: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Dashboard widgets
    widgets: List[Dict[str, Any]] = field(default_factory=list)

    # Filters and configuration
    default_filters: Dict[str, Any] = field(default_factory=dict)
    refresh_interval: int = 60  # seconds

    # Data sources
    data_sources: List[str] = field(default_factory=list)

    # Layout and styling
    layout: Dict[str, Any] = field(default_factory=dict)
    theme: str = "default"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = asdict(self)
        result["created_at"] = self.created_at.isoformat()
        result["updated_at"] = self.updated_at.isoformat()
        return result


class EventReporting:
    """Generate event reports and dashboards."""

    def __init__(self):
        self.logger = get_logger("event_reporting")
        self.event_store = get_event_store()
        self.event_analyzer = get_event_analyzer()
        self.event_alerting = get_event_alerting()

    async def generate_health_report(self, time_range: TimeRange) -> HealthReport:
        """Generate comprehensive health report."""
        self.logger.info(
            f"Generating health report for {time_range.start_time} to {time_range.end_time}"
        )

        # Get events in time range
        from src.models.event_models import EventFilters

        filters = EventFilters(
            start_time=time_range.start_time,
            end_time=time_range.end_time,
            categories=[EventCategory.HEALTH],
        )

        health_events = await self.event_store.get_events(filters)

        # Analyze health events
        health_report = HealthReport(time_range=time_range)

        if health_events:
            # Calculate health metrics
            health_scores = [
                e.health_score for e in health_events if e.health_score is not None
            ]

            if health_scores:
                health_report.fleet_health_score = sum(health_scores) / len(
                    health_scores
                )

                # Categorize systems
                healthy_count = len([s for s in health_scores if s >= 80])
                unhealthy_count = len([s for s in health_scores if s < 50])
                critical_count = len([s for s in health_scores if s < 20])

                health_report.total_systems = len(health_scores)
                health_report.healthy_systems = healthy_count
                health_report.unhealthy_systems = unhealthy_count
                health_report.critical_systems = critical_count

            # Identify critical issues
            critical_events = [
                e
                for e in health_events
                if e.severity in [EventSeverity.CRITICAL, EventSeverity.ERROR]
            ]
            health_report.critical_issues = critical_events[:10]  # Top 10

            # Identify recent failures
            recent_failures = [
                e for e in health_events if e.event_type == EventType.SERVICE_STATUS
            ]
            health_report.recent_failures = recent_failures[-10:]  # Last 10

            # Generate health trends
            trends = await self.event_analyzer.detect_trends(health_events)
            health_report.health_trends = [
                trend.__dict__ for trend in trends if "health" in trend.name.lower()
            ]

            # Generate recommendations
            if health_report.critical_systems > 0:
                health_report.recommendations.extend(
                    [
                        "Investigate systems with critical health scores",
                        "Review system dependencies and connections",
                        "Check recent changes and deployments",
                    ]
                )

            if health_report.unhealthy_systems > health_report.healthy_systems:
                health_report.recommendations.append(
                    "Consider system capacity planning"
                )

            health_report.health_events = health_events

        # Determine overall status
        if health_report.fleet_health_score >= 80:
            health_report.system_health_status = "healthy"
        elif health_report.fleet_health_score >= 50:
            health_report.system_health_status = "degraded"
        else:
            health_report.system_health_status = "critical"

        return health_report

    async def generate_security_report(self, time_range: TimeRange) -> SecurityReport:
        """Generate comprehensive security report."""
        self.logger.info(
            f"Generating security report for {time_range.start_time} to {time_range.end_time}"
        )

        # Get security events
        from src.models.event_models import EventFilters

        filters = EventFilters(
            start_time=time_range.start_time,
            end_time=time_range.end_time,
            categories=[EventCategory.SECURITY],
        )

        security_events = await self.event_store.get_events(filters)

        # Analyze security events
        security_report = SecurityReport(time_range=time_range)

        if security_events:
            # Calculate security metrics
            security_report.total_security_events = len(security_events)
            security_report.critical_security_events = len(
                [e for e in security_events if e.severity == EventSeverity.CRITICAL]
            )

            # Categorize by event type
            policy_events = [
                e for e in security_events if e.event_type == EventType.POLICY_VIOLATION
            ]
            security_report.policy_violations = len(policy_events)

            auth_events = [
                e for e in security_events if e.event_type == EventType.AUTHENTICATION
            ]
            security_report.authentication_events = len(auth_events)

            authz_events = [
                e for e in security_events if e.event_type == EventType.AUTHORIZATION
            ]
            security_report.authorization_events = len(authz_events)

            # Identify critical security issues
            critical_security = [
                e for e in security_events if e.severity == EventSeverity.CRITICAL
            ]
            security_report.critical_security_issues = critical_security[:10]

            security_report.policy_violation_events = policy_events[-10:]  # Last 10

            # Generate security trends
            trends = await self.event_analyzer.detect_trends(security_events)
            security_report.security_trends = [trend.__dict__ for trend in trends]

            # Generate recommendations
            if security_report.critical_security_events > 0:
                security_report.security_recommendations.extend(
                    [
                        "Investigate critical security events immediately",
                        "Review security policies and access controls",
                        "Check for potential security breaches",
                    ]
                )

            if security_report.policy_violations > 0:
                security_report.security_recommendations.append(
                    "Review and update security policies"
                )

            security_report.security_events = security_events

            # Calculate security score
            if security_events:
                security_report.security_score = max(
                    0, 100 - (security_report.critical_security_events * 20)
                )

        # Determine overall status
        if security_report.security_score >= 80:
            security_report.security_status = "secure"
        elif security_report.security_score >= 60:
            security_report.security_status = "moderate_risk"
        else:
            security_report.security_status = "high_risk"

        return security_report

    async def generate_operational_report(
        self, time_range: TimeRange
    ) -> OperationalReport:
        """Generate comprehensive operational report."""
        self.logger.info(
            f"Generating operational report for {time_range.start_time} to {time_range.end_time}"
        )

        # Get operational events
        from src.models.event_models import EventFilters

        filters = EventFilters(
            start_time=time_range.start_time,
            end_time=time_range.end_time,
            categories=[EventCategory.OPERATIONS, EventCategory.PERFORMANCE],
        )

        operational_events = await self.event_store.get_events(filters)

        # Analyze operational events
        operational_report = OperationalReport(time_range=time_range)

        if operational_events:
            # Calculate operational metrics
            operation_events = [
                e
                for e in operational_events
                if e.event_type
                in [EventType.OPERATION_COMPLETED, EventType.OPERATION_FAILED]
            ]

            operational_report.total_operations = len(operation_events)
            successful_ops = len(
                [
                    e
                    for e in operation_events
                    if e.event_type == EventType.OPERATION_COMPLETED
                ]
            )
            failed_ops = len(
                [
                    e
                    for e in operation_events
                    if e.event_type == EventType.OPERATION_FAILED
                ]
            )

            operational_report.successful_operations = successful_ops
            operational_report.failed_operations = failed_ops

            if operational_report.total_operations > 0:
                operational_report.operation_success_rate = (
                    successful_ops / operational_report.total_operations * 100
                )

            # Calculate average duration from event details
            durations = []
            for event in operation_events:
                if "duration" in event.details:
                    durations.append(event.details["duration"])

            if durations:
                operational_report.average_operation_duration = sum(durations) / len(
                    durations
                )

            # Identify critical operational issues
            critical_ops = [
                e for e in operational_events if e.severity == EventSeverity.CRITICAL
            ]
            operational_report.critical_operational_issues = critical_ops[:10]

            # Identify performance issues
            perf_events = [
                e
                for e in operational_events
                if e.event_type == EventType.RESOURCE_THRESHOLD
            ]
            operational_report.performance_issues = perf_events[-10:]

            # Generate operational trends
            trends = await self.event_analyzer.detect_trends(operational_events)
            operational_report.operational_trends = [trend.__dict__ for trend in trends]

            # Generate recommendations
            if operational_report.operation_success_rate < 80:
                operational_report.operational_recommendations.extend(
                    [
                        "Review failed operations and identify root causes",
                        "Check system resources and capacity",
                        "Verify target system availability",
                    ]
                )

            if operational_report.average_operation_duration > 30:  # 30 seconds
                operational_report.operational_recommendations.append(
                    "Optimize operation performance"
                )

            operational_report.operational_events = operational_events

            # Calculate operational score
            if operational_events:
                score = operational_report.operation_success_rate
                if operational_report.average_operation_duration > 30:
                    score -= 20
                if len(operational_report.critical_operational_issues) > 0:
                    score -= 30

                operational_report.operational_score = max(0, min(100, score))

        # Determine overall status
        if operational_report.operational_score >= 80:
            operational_report.operational_status = "operational"
        elif operational_report.operational_score >= 60:
            operational_report.operational_status = "degraded"
        else:
            operational_report.operational_status = "critical"

        return operational_report

    async def generate_compliance_report(
        self, time_range: TimeRange
    ) -> ComplianceReport:
        """Generate comprehensive compliance report."""
        self.logger.info(
            f"Generating compliance report for {time_range.start_time} to {time_range.end_time}"
        )

        # Get audit and compliance events
        from src.models.event_models import EventFilters

        filters = EventFilters(
            start_time=time_range.start_time,
            end_time=time_range.end_time,
            sources=[EventSource.SECURITY_AUDIT, EventSource.POLICY_ENGINE],
        )

        compliance_events = await self.event_store.get_events(filters)

        # Analyze compliance events
        compliance_report = ComplianceReport(time_range=time_range)

        if compliance_events:
            # Calculate compliance metrics
            compliance_report.total_compliance_checks = len(compliance_events)

            # Categorize by event type
            policy_compliance = [
                e
                for e in compliance_events
                if e.event_type == EventType.POLICY_VIOLATION
            ]
            security_compliance = [
                e for e in compliance_events if e.category == EventCategory.SECURITY
            ]

            compliance_report.policy_compliance_events = len(policy_compliance)
            compliance_report.security_compliance_events = len(security_compliance)

            # Assume successful compliance events are those without violations
            compliance_report.passed_checks = len(compliance_events) - len(
                policy_compliance
            )
            compliance_report.failed_checks = len(policy_compliance)

            if compliance_report.total_compliance_checks > 0:
                compliance_report.compliance_rate = (
                    compliance_report.passed_checks
                    / compliance_report.total_compliance_checks
                    * 100
                )

            # Identify compliance violations
            compliance_report.compliance_violations = policy_compliance[:10]

            # Generate compliance trends
            trends = await self.event_analyzer.detect_trends(compliance_events)
            compliance_report.compliance_trends = [trend.__dict__ for trend in trends]

            # Generate recommendations
            if compliance_report.failed_checks > 0:
                compliance_report.compliance_recommendations.extend(
                    [
                        "Review and address compliance violations",
                        "Update policies and procedures",
                        "Conduct compliance training",
                    ]
                )

            compliance_report.compliance_events = compliance_events

            # Calculate compliance score
            compliance_report.compliance_score = compliance_report.compliance_rate

        # Determine overall status
        if compliance_report.compliance_score >= 95:
            compliance_report.compliance_status = "compliant"
        elif compliance_report.compliance_score >= 80:
            compliance_report.compliance_status = "mostly_compliant"
        else:
            compliance_report.compliance_status = "non_compliant"

        return compliance_report

    async def create_event_dashboard(
        self, filters: Optional[Dict[str, Any]] = None
    ) -> Dashboard:
        """Create a customizable event dashboard."""
        dashboard = Dashboard(
            name="Event Overview Dashboard",
            description="Comprehensive view of system events and metrics",
            data_sources=["events", "alerts", "metrics"],
            default_filters=filters or {},
        )

        # Add default widgets
        dashboard.widgets = [
            {
                "type": "event_count",
                "title": "Total Events",
                "position": {"x": 0, "y": 0, "w": 6, "h": 4},
                "config": {"time_range": "24h"},
            },
            {
                "type": "event_severity_chart",
                "title": "Events by Severity",
                "position": {"x": 6, "y": 0, "w": 6, "h": 4},
                "config": {"time_range": "24h"},
            },
            {
                "type": "event_source_chart",
                "title": "Events by Source",
                "position": {"x": 0, "y": 4, "w": 6, "h": 4},
                "config": {"time_range": "24h"},
            },
            {
                "type": "alert_summary",
                "title": "Active Alerts",
                "position": {"x": 6, "y": 4, "w": 6, "h": 4},
                "config": {},
            },
            {
                "type": "health_score",
                "title": "System Health",
                "position": {"x": 0, "y": 8, "w": 12, "h": 4},
                "config": {"time_range": "24h"},
            },
        ]

        # Add default layout
        dashboard.layout = {"columns": 12, "rowHeight": 100, "margin": [10, 10]}

        return dashboard

    async def get_dashboard_data(self, dashboard: Dashboard) -> Dict[str, Any]:
        """Get data for a dashboard."""
        data = {
            "dashboard_info": dashboard.to_dict(),
            "widgets_data": {},
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        # Generate data for each widget
        for widget in dashboard.widgets:
            widget_type = widget["type"]
            widget_config = widget.get("config", {})

            try:
                if widget_type == "event_count":
                    time_range = self._get_time_range_from_config(widget_config)
                    stats = await self.event_store.get_statistics(
                        int(
                            (
                                time_range.end_time - time_range.start_time
                            ).total_seconds()
                            / 3600
                        )
                    )
                    data["widgets_data"][widget["title"]] = stats.to_dict()

                elif widget_type == "event_severity_chart":
                    time_range = self._get_time_range_from_config(widget_config)
                    from src.models.event_models import EventFilters

                    filters = EventFilters(
                        start_time=time_range.start_time, end_time=time_range.end_time
                    )
                    events = await self.event_store.get_events(filters, limit=1000)

                    severity_counts = {}
                    for event in events:
                        severity = event.severity.value
                        severity_counts[severity] = severity_counts.get(severity, 0) + 1

                    data["widgets_data"][widget["title"]] = {
                        "severity_distribution": severity_counts
                    }

                elif widget_type == "alert_summary":
                    alerts = await self.event_alerting.get_active_alerts()
                    data["widgets_data"][widget["title"]] = {
                        "active_alerts": len(alerts),
                        "alerts_by_severity": {
                            alert.severity.value: len(
                                [a for a in alerts if a.severity == alert.severity]
                            )
                            for alert in alerts
                        },
                    }

                elif widget_type == "health_score":
                    time_range = self._get_time_range_from_config(widget_config)
                    health_report = await self.generate_health_report(time_range)
                    data["widgets_data"][widget["title"]] = {
                        "health_score": health_report.fleet_health_score,
                        "health_status": health_report.system_health_status,
                        "healthy_systems": health_report.healthy_systems,
                        "total_systems": health_report.total_systems,
                    }

            except Exception as e:
                self.logger.error(
                    f"Error generating data for widget {widget['title']}: {e}"
                )
                data["widgets_data"][widget["title"]] = {"error": str(e)}

        return data

    def _get_time_range_from_config(self, config: Dict[str, Any]) -> TimeRange:
        """Get time range from widget configuration."""
        time_range_str = config.get("time_range", "24h")

        if time_range_str.endswith("h"):
            hours = int(time_range_str[:-1])
            return TimeRange.from_hours(hours)
        elif time_range_str.endswith("d"):
            days = int(time_range_str[:-1])
            return TimeRange.from_days(days)
        else:
            return TimeRange.last_24_hours()

    async def export_report(
        self, report: Any, format: str = "json", output_path: Optional[str] = None
    ) -> str:
        """Export report to file."""
        if not output_path:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            report_type = type(report).__name__.lower().replace("report", "")
            output_path = f"./reports/{report_type}_report_{timestamp}.{format}"

        # Ensure directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        if format == "json":
            with open(output_path, "w") as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
        elif format == "html":
            await self._export_html_report(report, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")

        self.logger.info(f"Report exported to {output_path}")
        return output_path

    async def _export_html_report(self, report: Any, output_path: str) -> None:
        """Export report as HTML."""
        report_data = report.to_dict()

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{type(report).__name__}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .metric {{ display: inline-block; margin: 10px; padding: 10px; background-color: #f9f9f9; }}
                .critical {{ color: red; }}
                .warning {{ color: orange; }}
                .success {{ color: green; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{type(report).__name__}</h1>
                <p>Generated: {report_data.get("generated_at", "Unknown")}</p>
                <p>Time Range: {report_data.get("time_range", {}).get("start_time", "Unknown")} to {report_data.get("time_range", {}).get("end_time", "Unknown")}</p>
            </div>

            <div class="section">
                <h2>Summary</h2>
                <div class="metric">Status: {getattr(report, f"{type(report).__name__.lower().replace('report', '')}_status", "Unknown")}</div>
                <div class="metric">Score: {getattr(report, f"{type(report).__name__.lower().replace('report', '')}_score", "N/A")}</div>
            </div>

            <div class="section">
                <h2>Details</h2>
                <pre>{json.dumps(report_data, indent=2, default=str)}</pre>
            </div>
        </body>
        </html>
        """

        with open(output_path, "w") as f:
            f.write(html_content)


# Global instances
_event_reporting_instance = None


def get_event_reporting() -> EventReporting:
    """Get the global event reporting instance."""
    global _event_reporting_instance
    if _event_reporting_instance is None:
        _event_reporting_instance = EventReporting()
    return _event_reporting_instance


async def generate_comprehensive_report(time_range: TimeRange) -> Dict[str, Any]:
    """Generate a comprehensive report with all components."""
    reporting = get_event_reporting()

    # Generate all report types
    health_report = await reporting.generate_health_report(time_range)
    security_report = await reporting.generate_security_report(time_range)
    operational_report = await reporting.generate_operational_report(time_range)
    compliance_report = await reporting.generate_compliance_report(time_range)

    # Create dashboard
    dashboard = await reporting.create_event_dashboard()
    dashboard_data = await reporting.get_dashboard_data(dashboard)

    return {
        "health_report": health_report.to_dict(),
        "security_report": security_report.to_dict(),
        "operational_report": operational_report.to_dict(),
        "compliance_report": compliance_report.to_dict(),
        "dashboard_data": dashboard_data,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "time_range": {
            "start_time": time_range.start_time.isoformat(),
            "end_time": time_range.end_time.isoformat(),
        },
    }
