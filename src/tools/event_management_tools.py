"""
MCP Event Management Tools for TailOpsMCP observability system.

This module provides high-level MCP tools for event management, monitoring,
alerting, and reporting functionality.
"""

from datetime import datetime, timedelta
from typing import Any, Dict

from src.models.event_models import (
    EventType,
    EventSeverity,
    EventSource,
    EventCategory,
    EventFilters,
)
from src.services.event_collector import EventCollector, EventAggregator
from src.services.event_store import get_event_store, get_event_index
from src.services.event_analyzer import get_event_analyzer
from src.services.event_alerting import get_event_alerting
from src.services.event_reporting import (
    get_event_reporting,
    generate_comprehensive_report,
    TimeRange,
)
from src.services.event_processor import (
    get_event_stream_processor,
    create_default_filter_rules,
)
from src.utils.logging_config import get_logger


class EventManagementTools:
    """High-level MCP tools for event management."""

    def __init__(self):
        self.logger = get_logger("event_management_tools")
        self.event_collector = EventCollector()
        self.event_aggregator = EventAggregator()
        self.event_store = get_event_store()
        self.event_index = get_event_index()
        self.event_analyzer = get_event_analyzer()
        self.event_alerting = get_event_alerting()
        self.event_reporting = get_event_reporting()
        self.event_stream_processor = get_event_stream_processor()

    async def get_recent_events(
        self, hours: int = 24, event_type: str = None
    ) -> Dict[str, Any]:
        """Get recent events from the last N hours."""
        try:
            # Calculate time range
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=hours)

            # Build filters
            filters = EventFilters(start_time=start_time, end_time=end_time, limit=1000)

            # Add event type filter if specified
            if event_type:
                try:
                    filters.event_types = [EventType(event_type)]
                except ValueError:
                    return {
                        "error": f"Invalid event_type: {event_type}",
                        "valid_types": [et.value for et in EventType],
                    }

            # Get events
            events = await self.event_store.get_events(filters)

            # Convert to dictionaries
            events_data = [event.to_dict() for event in events]

            return {
                "success": True,
                "events": events_data,
                "total_count": len(events_data),
                "time_range": {
                    "start_time": start_time.isoformat(),
                    "end_time": end_time.isoformat(),
                    "hours": hours,
                },
                "filters_applied": {"event_type": event_type, "limit": 1000},
            }

        except Exception as e:
            self.logger.error(f"Error getting recent events: {e}")
            return {"success": False, "error": str(e)}

    async def get_events_by_source(
        self, source: str, hours: int = 24
    ) -> Dict[str, Any]:
        """Get events from a specific source within time range."""
        try:
            # Validate source
            try:
                event_source = EventSource(source)
            except ValueError:
                return {
                    "error": f"Invalid source: {source}",
                    "valid_sources": [es.value for es in EventSource],
                }

            # Get events
            events = await self.event_store.get_events_by_source(source, hours)

            # Convert to dictionaries
            events_data = [event.to_dict() for event in events]

            # Group by event type for summary
            type_summary = {}
            for event in events:
                event_type = event.event_type.value
                if event_type not in type_summary:
                    type_summary[event_type] = 0
                type_summary[event_type] += 1

            return {
                "success": True,
                "source": source,
                "events": events_data,
                "total_count": len(events_data),
                "event_type_summary": type_summary,
                "time_range": {
                    "hours": hours,
                    "start_time": (
                        datetime.utcnow() - timedelta(hours=hours)
                    ).isoformat(),
                    "end_time": datetime.utcnow().isoformat(),
                },
            }

        except Exception as e:
            self.logger.error(f"Error getting events by source: {e}")
            return {"success": False, "error": str(e)}

    async def get_events_by_target(
        self, target: str, hours: int = 24
    ) -> Dict[str, Any]:
        """Get events for a specific target within time range."""
        try:
            # Get events
            events = await self.event_store.get_events_by_target(target, hours)

            # Convert to dictionaries
            events_data = [event.to_dict() for event in events]

            # Calculate severity summary
            severity_summary = {}
            for event in events:
                severity = event.severity.value
                if severity not in severity_summary:
                    severity_summary[severity] = 0
                severity_summary[severity] += 1

            # Calculate health score statistics
            health_scores = [
                event.health_score for event in events if event.health_score is not None
            ]
            health_stats = {}
            if health_scores:
                health_stats = {
                    "average": sum(health_scores) / len(health_scores),
                    "min": min(health_scores),
                    "max": max(health_scores),
                    "count": len(health_scores),
                }

            return {
                "success": True,
                "target": target,
                "events": events_data,
                "total_count": len(events_data),
                "severity_summary": severity_summary,
                "health_statistics": health_stats,
                "time_range": {
                    "hours": hours,
                    "start_time": (
                        datetime.utcnow() - timedelta(hours=hours)
                    ).isoformat(),
                    "end_time": datetime.utcnow().isoformat(),
                },
            }

        except Exception as e:
            self.logger.error(f"Error getting events by target: {e}")
            return {"success": False, "error": str(e)}

    async def get_health_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get health summary for the system."""
        try:
            # Generate health report
            time_range = TimeRange.from_hours(hours)
            health_report = await self.event_reporting.generate_health_report(
                time_range
            )

            # Get additional health events
            filters = EventFilters(
                start_time=time_range.start_time,
                end_time=time_range.end_time,
                categories=[EventCategory.HEALTH],
            )
            health_events = await self.event_store.get_events(filters, limit=100)

            # Calculate health trends
            health_trends = []
            if len(health_events) >= 5:
                trends = await self.event_analyzer.detect_trends(health_events)
                health_trends = [
                    trend.__dict__ for trend in trends if "health" in trend.name.lower()
                ]

            return {
                "success": True,
                "health_summary": {
                    "fleet_health_score": health_report.fleet_health_score,
                    "health_status": health_report.system_health_status,
                    "total_systems": health_report.total_systems,
                    "healthy_systems": health_report.healthy_systems,
                    "unhealthy_systems": health_report.unhealthy_systems,
                    "critical_systems": health_report.critical_systems,
                    "critical_issues_count": len(health_report.critical_issues),
                    "recent_failures_count": len(health_report.recent_failures),
                    "recommendations_count": len(health_report.recommendations),
                },
                "health_trends": health_trends,
                "critical_issues": [
                    event.to_dict() for event in health_report.critical_issues[:10]
                ],
                "recent_failures": [
                    event.to_dict() for event in health_report.recent_failures[:10]
                ],
                "recommendations": health_report.recommendations,
                "time_range": {
                    "hours": hours,
                    "start_time": time_range.start_time.isoformat(),
                    "end_time": time_range.end_time.isoformat(),
                },
            }

        except Exception as e:
            self.logger.error(f"Error getting health summary: {e}")
            return {"success": False, "error": str(e)}

    async def get_error_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get error summary for the system."""
        try:
            # Calculate time range
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=hours)

            # Get error events
            filters = EventFilters(
                start_time=start_time,
                end_time=end_time,
                severities=[EventSeverity.ERROR, EventSeverity.CRITICAL],
                limit=1000,
            )
            error_events = await self.event_store.get_events(filters)

            # Convert to dictionaries
            error_events_data = [event.to_dict() for event in error_events]

            # Calculate error statistics
            error_stats = {
                "total_errors": len(error_events_data),
                "critical_errors": len(
                    [e for e in error_events if e.severity == EventSeverity.CRITICAL]
                ),
                "error_events": len(
                    [e for e in error_events if e.severity == EventSeverity.ERROR]
                ),
            }

            # Group by source
            source_summary = {}
            for event in error_events:
                source = event.source.value
                if source not in source_summary:
                    source_summary[source] = 0
                source_summary[source] += 1

            # Group by event type
            type_summary = {}
            for event in error_events:
                event_type = event.event_type.value
                if event_type not in type_summary:
                    type_summary[event_type] = 0
                type_summary[event_type] += 1

            # Get recent error patterns
            recent_errors = (
                error_events[-20:] if len(error_events) > 20 else error_events
            )

            return {
                "success": True,
                "error_summary": error_stats,
                "source_summary": source_summary,
                "type_summary": type_summary,
                "error_events": error_events_data,
                "recent_errors": [event.to_dict() for event in recent_errors],
                "time_range": {
                    "hours": hours,
                    "start_time": start_time.isoformat(),
                    "end_time": end_time.isoformat(),
                },
            }

        except Exception as e:
            self.logger.error(f"Error getting error summary: {e}")
            return {"success": False, "error": str(e)}

    async def get_security_events(self, hours: int = 24) -> Dict[str, Any]:
        """Get security events for the system."""
        try:
            # Generate security report
            time_range = TimeRange.from_hours(hours)
            security_report = await self.event_reporting.generate_security_report(
                time_range
            )

            # Get security events
            filters = EventFilters(
                start_time=time_range.start_time,
                end_time=time_range.end_time,
                categories=[EventCategory.SECURITY],
            )
            security_events = await self.event_store.get_events(filters, limit=500)

            # Convert to dictionaries
            security_events_data = [event.to_dict() for event in security_events]

            # Calculate security trends
            security_trends = []
            if len(security_events) >= 3:
                trends = await self.event_analyzer.detect_trends(security_events)
                security_trends = [trend.__dict__ for trend in trends]

            # Get security insights
            security_insights = []
            if len(security_events) >= 5:
                insights = await self.event_analyzer.generate_insights(security_events)
                security_insights = [
                    insight.__dict__
                    for insight in insights
                    if insight.insight_type == "security"
                ]

            return {
                "success": True,
                "security_summary": {
                    "total_security_events": security_report.total_security_events,
                    "critical_security_events": security_report.critical_security_events,
                    "security_violations": security_report.security_violations,
                    "policy_violations": security_report.policy_violations,
                    "authentication_events": security_report.authentication_events,
                    "authorization_events": security_report.authorization_events,
                    "security_score": security_report.security_score,
                    "security_status": security_report.security_status,
                },
                "security_events": security_events_data,
                "critical_issues": [
                    event.to_dict()
                    for event in security_report.critical_security_issues[:10]
                ],
                "policy_violations": [
                    event.to_dict()
                    for event in security_report.policy_violation_events[:10]
                ],
                "security_trends": security_trends,
                "security_insights": security_insights,
                "recommendations": security_report.security_recommendations,
                "time_range": {
                    "hours": hours,
                    "start_time": time_range.start_time.isoformat(),
                    "end_time": time_range.end_time.isoformat(),
                },
            }

        except Exception as e:
            self.logger.error(f"Error getting security events: {e}")
            return {"success": False, "error": str(e)}

    async def get_operation_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get operational summary for the system."""
        try:
            # Generate operational report
            time_range = TimeRange.from_hours(hours)
            operational_report = await self.event_reporting.generate_operational_report(
                time_range
            )

            # Get operational events
            filters = EventFilters(
                start_time=time_range.start_time,
                end_time=time_range.end_time,
                categories=[EventCategory.OPERATIONS],
            )
            operational_events = await self.event_store.get_events(filters, limit=1000)

            # Convert to dictionaries
            operational_events_data = [event.to_dict() for event in operational_events]

            # Calculate performance insights
            performance_insights = []
            if len(operational_events) >= 5:
                insights = await self.event_analyzer.generate_insights(
                    operational_events
                )
                performance_insights = [
                    insight.__dict__
                    for insight in insights
                    if insight.insight_type == "performance"
                ]

            # Get operation-specific events
            operation_events = [
                e
                for e in operational_events
                if e.event_type
                in [EventType.OPERATION_COMPLETED, EventType.OPERATION_FAILED]
            ]

            # Calculate average duration
            durations = []
            for event in operation_events:
                if "duration" in event.details:
                    durations.append(event.details["duration"])

            avg_duration = sum(durations) / len(durations) if durations else 0

            return {
                "success": True,
                "operational_summary": {
                    "total_operations": operational_report.total_operations,
                    "successful_operations": operational_report.successful_operations,
                    "failed_operations": operational_report.failed_operations,
                    "operation_success_rate": operational_report.operation_success_rate,
                    "average_operation_duration": avg_duration,
                    "operational_score": operational_report.operational_score,
                    "operational_status": operational_report.operational_status,
                    "critical_issues_count": len(
                        operational_report.critical_operational_issues
                    ),
                },
                "operational_events": operational_events_data,
                "performance_insights": performance_insights,
                "critical_issues": [
                    event.to_dict()
                    for event in operational_report.critical_operational_issues[:10]
                ],
                "recommendations": operational_report.operational_recommendations,
                "time_range": {
                    "hours": hours,
                    "start_time": time_range.start_time.isoformat(),
                    "end_time": time_range.end_time.isoformat(),
                },
            }

        except Exception as e:
            self.logger.error(f"Error getting operation summary: {e}")
            return {"success": False, "error": str(e)}

    async def get_event_trends(self, days: int = 7) -> Dict[str, Any]:
        """Get event trends analysis."""
        try:
            # Calculate time range
            time_range = TimeRange.from_days(days)

            # Get all events in time range
            filters = EventFilters(
                start_time=time_range.start_time,
                end_time=time_range.end_time,
                limit=10000,
            )
            events = await self.event_store.get_events(filters)

            # Analyze trends
            trends = await self.event_analyzer.detect_trends(events)
            patterns = await self.event_analyzer.detect_patterns(events)
            insights = await self.event_analyzer.generate_insights(events)

            # Convert to dictionaries
            trends_data = [trend.__dict__ for trend in trends]
            patterns_data = [pattern.__dict__ for pattern in patterns]
            insights_data = [insight.__dict__ for insight in insights]

            # Calculate trend summary
            trend_summary = {
                "total_trends": len(trends_data),
                "increasing_trends": len(
                    [t for t in trends_data if t["direction"] == "increasing"]
                ),
                "decreasing_trends": len(
                    [t for t in trends_data if t["direction"] == "decreasing"]
                ),
                "high_confidence_trends": len(
                    [t for t in trends_data if t["confidence"] > 0.7]
                ),
                "total_patterns": len(patterns_data),
                "total_insights": len(insights_data),
            }

            return {
                "success": True,
                "trend_summary": trend_summary,
                "trends": trends_data,
                "patterns": patterns_data,
                "insights": insights_data,
                "time_range": {
                    "days": days,
                    "start_time": time_range.start_time.isoformat(),
                    "end_time": time_range.end_time.isoformat(),
                },
                "total_events_analyzed": len(events),
            }

        except Exception as e:
            self.logger.error(f"Error getting event trends: {e}")
            return {"success": False, "error": str(e)}

    async def search_events(self, query: str, hours: int = 24) -> Dict[str, Any]:
        """Search events using full-text search."""
        try:
            # Search events
            events = await self.event_store.search_events(query, hours)

            # Convert to dictionaries
            events_data = [event.to_dict() for event in events]

            # Calculate search summary
            search_summary = {
                "total_results": len(events_data),
                "query": query,
                "hours_searched": hours,
            }

            # Group results by severity
            severity_summary = {}
            for event in events:
                severity = event.severity.value
                if severity not in severity_summary:
                    severity_summary[severity] = 0
                severity_summary[severity] += 1

            return {
                "success": True,
                "search_summary": search_summary,
                "severity_summary": severity_summary,
                "events": events_data,
                "time_range": {
                    "hours": hours,
                    "start_time": (
                        datetime.utcnow() - timedelta(hours=hours)
                    ).isoformat(),
                    "end_time": datetime.utcnow().isoformat(),
                },
            }

        except Exception as e:
            self.logger.error(f"Error searching events: {e}")
            return {"success": False, "error": str(e)}

    async def get_event_statistics(self, time_range: str) -> Dict[str, Any]:
        """Get event statistics for specified time range."""
        try:
            # Parse time range
            if time_range.endswith("h"):
                hours = int(time_range[:-1])
                stats = await self.event_store.get_statistics(hours)
            elif time_range.endswith("d"):
                days = int(time_range[:-1])
                stats = await self.event_store.get_statistics(days * 24)
            else:
                return {
                    "error": "Invalid time range format. Use format like '24h', '7d'",
                    "valid_formats": ["1h", "24h", "7d", "30d"],
                }

            # Convert to dictionary
            stats_data = stats.to_dict()

            # Add processing statistics
            processor_stats = self.event_stream_processor.get_stats()
            buffer_status = self.event_stream_processor.get_buffer_status()

            return {
                "success": True,
                "event_statistics": stats_data,
                "processing_statistics": processor_stats,
                "buffer_status": buffer_status,
                "time_range": time_range,
            }

        except Exception as e:
            self.logger.error(f"Error getting event statistics: {e}")
            return {"success": False, "error": str(e)}

    async def get_active_alerts(self) -> Dict[str, Any]:
        """Get active alerts."""
        try:
            alerts = await self.event_alerting.get_active_alerts()
            alert_stats = await self.event_alerting.get_alert_statistics()

            # Convert alerts to dictionaries
            alerts_data = []
            for alert in alerts:
                alert_dict = {
                    "id": alert.id,
                    "rule_name": alert.rule_name,
                    "title": alert.title,
                    "description": alert.description,
                    "severity": alert.severity.value,
                    "status": alert.status.value,
                    "created_at": alert.created_at.isoformat(),
                    "updated_at": alert.updated_at.isoformat(),
                    "event_count": alert.event_count,
                    "escalation_level": alert.escalation_level,
                    "tags": alert.tags,
                    "triggering_events": [
                        event.to_dict() for event in alert.triggering_events[:5]
                    ],  # Limit to first 5
                }
                alerts_data.append(alert_dict)

            return {
                "success": True,
                "active_alerts": alerts_data,
                "alert_statistics": alert_stats,
                "total_active_alerts": len(alerts),
            }

        except Exception as e:
            self.logger.error(f"Error getting active alerts: {e}")
            return {"success": False, "error": str(e)}

    async def acknowledge_alert(
        self, alert_id: str, user_id: str, note: str = None
    ) -> Dict[str, Any]:
        """Acknowledge an alert."""
        try:
            success = await self.event_alerting.acknowledge_alert(
                alert_id, user_id, note
            )

            if success:
                return {
                    "success": True,
                    "message": f"Alert {alert_id} acknowledged by {user_id}",
                    "alert_id": alert_id,
                    "user_id": user_id,
                    "note": note,
                }
            else:
                return {
                    "success": False,
                    "error": f"Alert {alert_id} not found or already resolved",
                }

        except Exception as e:
            self.logger.error(f"Error acknowledging alert: {e}")
            return {"success": False, "error": str(e)}

    async def resolve_alert(
        self, alert_id: str, user_id: str, note: str = None
    ) -> Dict[str, Any]:
        """Resolve an alert."""
        try:
            success = await self.event_alerting.resolve_alert(alert_id, user_id, note)

            if success:
                return {
                    "success": True,
                    "message": f"Alert {alert_id} resolved by {user_id}",
                    "alert_id": alert_id,
                    "user_id": user_id,
                    "note": note,
                }
            else:
                return {"success": False, "error": f"Alert {alert_id} not found"}

        except Exception as e:
            self.logger.error(f"Error resolving alert: {e}")
            return {"success": False, "error": str(e)}

    async def generate_comprehensive_report(
        self, time_range: str = "24h"
    ) -> Dict[str, Any]:
        """Generate comprehensive report."""
        try:
            # Parse time range
            if time_range.endswith("h"):
                hours = int(time_range[:-1])
                tr = TimeRange.from_hours(hours)
            elif time_range.endswith("d"):
                days = int(time_range[:-1])
                tr = TimeRange.from_days(days)
            else:
                return {
                    "error": "Invalid time range format. Use format like '24h', '7d'",
                    "valid_formats": ["1h", "24h", "7d", "30d"],
                }

            # Generate comprehensive report
            report = await generate_comprehensive_report(tr)

            return {"success": True, "comprehensive_report": report}

        except Exception as e:
            self.logger.error(f"Error generating comprehensive report: {e}")
            return {"success": False, "error": str(e)}

    async def export_report(
        self, report_type: str, time_range: str = "24h", format: str = "json"
    ) -> Dict[str, Any]:
        """Export a specific report."""
        try:
            # Parse time range
            if time_range.endswith("h"):
                hours = int(time_range[:-1])
                tr = TimeRange.from_hours(hours)
            elif time_range.endswith("d"):
                days = int(time_range[:-1])
                tr = TimeRange.from_days(days)
            else:
                return {
                    "error": "Invalid time range format. Use format like '24h', '7d'",
                    "valid_formats": ["1h", "24h", "7d", "30d"],
                }

            # Generate specific report
            if report_type == "health":
                report = await self.event_reporting.generate_health_report(tr)
            elif report_type == "security":
                report = await self.event_reporting.generate_security_report(tr)
            elif report_type == "operational":
                report = await self.event_reporting.generate_operational_report(tr)
            elif report_type == "compliance":
                report = await self.event_reporting.generate_compliance_report(tr)
            else:
                return {
                    "error": f"Invalid report type: {report_type}",
                    "valid_types": ["health", "security", "operational", "compliance"],
                }

            # Export report
            output_path = await self.event_reporting.export_report(report, format)

            return {
                "success": True,
                "report_type": report_type,
                "time_range": time_range,
                "format": format,
                "output_path": output_path,
                "message": f"Report exported to {output_path}",
            }

        except Exception as e:
            self.logger.error(f"Error exporting report: {e}")
            return {"success": False, "error": str(e)}

    async def start_event_monitoring(self) -> Dict[str, Any]:
        """Start real-time event monitoring."""
        try:
            # Add default filter rules
            filter_rules = create_default_filter_rules()
            for rule in filter_rules:
                self.event_stream_processor.add_filter_rule(rule)

            # Start the event stream processor
            processor = self.event_stream_processor

            return {
                "success": True,
                "message": "Event monitoring started",
                "websocket_port": processor.config.websocket_port,
                "buffer_size": processor.config.buffer_size,
                "filter_rules_added": len(filter_rules),
            }

        except Exception as e:
            self.logger.error(f"Error starting event monitoring: {e}")
            return {"success": False, "error": str(e)}

    async def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status."""
        try:
            # Get basic statistics
            event_stats = await self.event_store.get_statistics(24)
            alert_stats = await self.event_alerting.get_alert_statistics()
            processor_stats = self.event_stream_processor.get_stats()
            buffer_status = self.event_stream_processor.get_buffer_status()

            # Calculate overall system health
            health_score = 100.0
            issues = []

            # Check alerts
            if alert_stats.get("active_alerts", 0) > 0:
                health_score -= alert_stats["active_alerts"] * 5
                issues.append(f"{alert_stats['active_alerts']} active alerts")

            # Check error rate
            error_rate = 0
            if event_stats.total_events > 0:
                error_rate = (
                    event_stats.error_events + event_stats.critical_events
                ) / event_stats.total_events
                if error_rate > 0.1:  # 10% error rate
                    health_score -= 20
                    issues.append(f"High error rate: {error_rate:.1%}")

            # Determine status
            if health_score >= 80:
                status = "healthy"
            elif health_score >= 60:
                status = "degraded"
            else:
                status = "critical"

            return {
                "success": True,
                "system_status": {
                    "overall_status": status,
                    "health_score": health_score,
                    "active_alerts": alert_stats.get("active_alerts", 0),
                    "error_rate": error_rate,
                    "issues": issues,
                    "total_events_24h": event_stats.total_events,
                    "critical_events_24h": event_stats.critical_events,
                    "processing_rate": processor_stats.get("events_processed", 0),
                    "websocket_clients": buffer_status.get("websocket_clients", 0),
                },
                "component_status": {
                    "event_collection": "active",
                    "event_storage": "active",
                    "event_analysis": "active",
                    "alerting_system": "active",
                    "event_streaming": "active"
                    if buffer_status.get("websocket_clients", 0) > 0
                    else "inactive",
                },
            }

        except Exception as e:
            self.logger.error(f"Error getting system status: {e}")
            return {"success": False, "error": str(e)}


# Global instance
_event_management_tools_instance = None


def get_event_management_tools() -> EventManagementTools:
    """Get the global event management tools instance."""
    global _event_management_tools_instance
    if _event_management_tools_instance is None:
        _event_management_tools_instance = EventManagementTools()
    return _event_management_tools_instance


# MCP Tool Functions
async def mcp_get_recent_events(
    hours: int = 24, event_type: str = None
) -> Dict[str, Any]:
    """Get recent events from the last N hours."""
    tools = get_event_management_tools()
    return await tools.get_recent_events(hours, event_type)


async def mcp_get_events_by_source(source: str, hours: int = 24) -> Dict[str, Any]:
    """Get events from a specific source within time range."""
    tools = get_event_management_tools()
    return await tools.get_events_by_source(source, hours)


async def mcp_get_events_by_target(target: str, hours: int = 24) -> Dict[str, Any]:
    """Get events for a specific target within time range."""
    tools = get_event_management_tools()
    return await tools.get_events_by_target(target, hours)


async def mcp_get_health_summary(hours: int = 24) -> Dict[str, Any]:
    """Get health summary for the system."""
    tools = get_event_management_tools()
    return await tools.get_health_summary(hours)


async def mcp_get_error_summary(hours: int = 24) -> Dict[str, Any]:
    """Get error summary for the system."""
    tools = get_event_management_tools()
    return await tools.get_error_summary(hours)


async def mcp_get_security_events(hours: int = 24) -> Dict[str, Any]:
    """Get security events for the system."""
    tools = get_event_management_tools()
    return await tools.get_security_events(hours)


async def mcp_get_operation_summary(hours: int = 24) -> Dict[str, Any]:
    """Get operational summary for the system."""
    tools = get_event_management_tools()
    return await tools.get_operation_summary(hours)


async def mcp_get_event_trends(days: int = 7) -> Dict[str, Any]:
    """Get event trends analysis."""
    tools = get_event_management_tools()
    return await tools.get_event_trends(days)


async def mcp_search_events(query: str, hours: int = 24) -> Dict[str, Any]:
    """Search events using full-text search."""
    tools = get_event_management_tools()
    return await tools.search_events(query, hours)


async def mcp_get_event_statistics(time_range: str) -> Dict[str, Any]:
    """Get event statistics for specified time range."""
    tools = get_event_management_tools()
    return await tools.get_event_statistics(time_range)


async def mcp_get_active_alerts() -> Dict[str, Any]:
    """Get active alerts."""
    tools = get_event_management_tools()
    return await tools.get_active_alerts()


async def mcp_acknowledge_alert(
    alert_id: str, user_id: str, note: str = None
) -> Dict[str, Any]:
    """Acknowledge an alert."""
    tools = get_event_management_tools()
    return await tools.acknowledge_alert(alert_id, user_id, note)


async def mcp_resolve_alert(
    alert_id: str, user_id: str, note: str = None
) -> Dict[str, Any]:
    """Resolve an alert."""
    tools = get_event_management_tools()
    return await tools.resolve_alert(alert_id, user_id, note)


async def mcp_generate_comprehensive_report(time_range: str = "24h") -> Dict[str, Any]:
    """Generate comprehensive report."""
    tools = get_event_management_tools()
    return await tools.generate_comprehensive_report(time_range)


async def mcp_export_report(
    report_type: str, time_range: str = "24h", format: str = "json"
) -> Dict[str, Any]:
    """Export a specific report."""
    tools = get_event_management_tools()
    return await tools.export_report(report_type, time_range, format)


async def mcp_start_event_monitoring() -> Dict[str, Any]:
    """Start real-time event monitoring."""
    tools = get_event_management_tools()
    return await tools.start_event_monitoring()


async def mcp_get_system_status() -> Dict[str, Any]:
    """Get overall system status."""
    tools = get_event_management_tools()
    return await tools.get_system_status()
