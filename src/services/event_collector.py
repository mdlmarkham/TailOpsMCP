"""
Event collection system for the TailOpsMCP observability platform.

This module provides comprehensive event collection from all system components
including fleet inventory, policy engine, security audit, remote agents, and more.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Set, Tuple

from src.models.event_models import (
    SystemEvent,
    EventType,
    EventSeverity,
    EventSource,
    EventCategory,
    ResourceUsage,
    EventBuilder,
)
from src.models.execution import ExecutionResult
from src.utils.audit import AuditLogger, LogLevel
from src.utils.logging_config import get_logger


class EventCollector:
    """Collects events from all system components."""

    def __init__(self):
        self.logger = get_logger("event_collector")
        self.audit_logger = AuditLogger()
        self._collection_sources: Set[str] = set()

    async def collect_fleet_health_events(self) -> List[SystemEvent]:
        """Collect health events from fleet inventory."""
        events = []

        try:
            # Import inventory service
            from src.tools.enhanced_inventory_tools import EnhancedInventoryTools

            inventory_tools = EnhancedInventoryTools()

            # Get fleet status
            fleet_data = await inventory_tools.get_fleet_status()

            if fleet_data and "targets" in fleet_data:
                for target_name, target_data in fleet_data["targets"].items():
                    # Check target health
                    health_status = target_data.get("health_status", "unknown")
                    health_score = target_data.get("health_score")

                    if health_status != "healthy":
                        severity = (
                            EventSeverity.ERROR
                            if health_status == "failed"
                            else EventSeverity.WARNING
                        )

                        event = EventBuilder.health_check(
                            source=EventSource.FLEET_INVENTORY,
                            target=target_name,
                            status=health_status,
                            details={
                                "target_data": target_data,
                                "last_seen": target_data.get("last_seen"),
                                "connection_status": target_data.get(
                                    "connection_status"
                                ),
                            },
                        )
                        event.severity = severity

                        if health_score is not None:
                            event.set_health_score(health_score)

                        events.append(event)

                    # Check for resource threshold breaches
                    if "resources" in target_data:
                        resources = target_data["resources"]
                        if resources.get("cpu_percent", 0) > 80:
                            events.append(
                                self._create_resource_threshold_event(
                                    target_name, "cpu", resources["cpu_percent"]
                                )
                            )
                        if resources.get("memory_percent", 0) > 80:
                            events.append(
                                self._create_resource_threshold_event(
                                    target_name, "memory", resources["memory_percent"]
                                )
                            )

        except Exception as e:
            self.logger.error(f"Failed to collect fleet health events: {e}")
            events.append(
                EventBuilder.error(
                    EventSource.FLEET_INVENTORY,
                    "Fleet health collection failed",
                    str(e),
                    {"collection_source": "fleet_health"},
                )
            )

        return events

    async def collect_operation_events(
        self, operation_results: List[ExecutionResult]
    ) -> List[SystemEvent]:
        """Collect events from operation execution results."""
        events = []

        for result in operation_results:
            try:
                if result.success:
                    event_type = EventType.OPERATION_COMPLETED
                    severity = EventSeverity.INFO
                else:
                    event_type = EventType.OPERATION_FAILED
                    severity = EventSeverity.ERROR

                event = EventBuilder()
                event.event_type = event_type
                event.severity = severity
                event.source = EventSource.SYSTEM
                event.target = result.target_id
                event.category = EventCategory.OPERATIONS
                event.title = f"Operation {result.capability or 'unknown'} {'completed' if result.success else 'failed'}"
                event.description = result.output or "No output"
                event.metadata.correlation_id = result.correlation_id

                details = {
                    "capability": result.capability,
                    "executor_type": result.executor_type,
                    "exit_code": result.exit_code,
                    "dry_run": result.dry_run,
                }

                if result.duration is not None:
                    details["duration"] = result.duration

                if result.error:
                    details["error"] = result.error

                event.details = details

                if result.duration is not None:
                    event.resource_usage = ResourceUsage()

                events.append(event.build())

            except Exception as e:
                self.logger.error(f"Failed to process operation result: {e}")

        return events

    async def collect_security_events(self) -> List[SystemEvent]:
        """Collect security-related events."""
        events = []

        try:
            # Check for policy violations
            from src.tools.fleet_policy import FleetPolicyTools

            policy_tools = FleetPolicyTools()

            # Get recent policy violations
            violations = await policy_tools.get_recent_violations()

            for violation in violations:
                event = EventBuilder.security_alert(
                    EventSource.POLICY_ENGINE,
                    f"Policy violation: {violation.operation}",
                    violation.reason,
                    EventSeverity.ERROR,
                )
                event.target = violation.target
                event.details = {
                    "operation": violation.operation,
                    "policy_name": violation.policy_name,
                    "violation_type": violation.violation_type,
                    "severity": violation.severity.value
                    if hasattr(violation.severity, "value")
                    else str(violation.severity),
                }
                event.add_tag("policy_violation")

                events.append(event.build())

        except Exception as e:
            self.logger.error(f"Failed to collect security events: {e}")
            events.append(
                EventBuilder.error(
                    EventSource.POLICY_ENGINE,
                    "Security event collection failed",
                    str(e),
                    {"collection_source": "security"},
                )
            )

        return events

    async def collect_lifecycle_events(self) -> List[SystemEvent]:
        """Collect container and service lifecycle events."""
        events = []

        try:
            # Check container status
            from src.tools.container_tools import ContainerTools

            container_tools = ContainerTools()

            containers = await container_tools.list_containers()

            for container in containers:
                if container.get("state") == "running":
                    # Container is running normally
                    continue
                elif container.get("state") == "exited":
                    # Container exited unexpectedly
                    event = EventBuilder()
                    event.event_type = EventType.SERVICE_STATUS
                    event.severity = EventSeverity.WARNING
                    event.source = EventSource.CONTAINER_MANAGER
                    event.target = container.get("name", "unknown")
                    event.category = EventCategory.LIFECYCLE
                    event.title = f"Container {container.get('name')} exited"
                    event.description = f"Container exited with code {container.get('exit_code', 'unknown')}"
                    event.details = {
                        "container_id": container.get("id"),
                        "image": container.get("image"),
                        "exit_code": container.get("exit_code"),
                        "state": container.get("state"),
                    }

                    events.append(event.build())

        except Exception as e:
            self.logger.error(f"Failed to collect lifecycle events: {e}")
            events.append(
                EventBuilder.error(
                    EventSource.CONTAINER_MANAGER,
                    "Lifecycle event collection failed",
                    str(e),
                    {"collection_source": "lifecycle"},
                )
            )

        return events

    async def collect_resource_events(self) -> List[SystemEvent]:
        """Collect resource usage and threshold events."""
        events = []

        try:
            # Check system-wide resource usage
            import psutil

            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 80:
                events.append(
                    self._create_system_resource_event("cpu", cpu_percent, "system")
                )

            # Memory usage
            memory = psutil.virtual_memory()
            if memory.percent > 80:
                events.append(
                    self._create_system_resource_event(
                        "memory", memory.percent, "system"
                    )
                )

            # Disk usage
            disk = psutil.disk_usage("/")
            disk_percent = (disk.used / disk.total) * 100
            if disk_percent > 80:
                events.append(
                    self._create_system_resource_event("disk", disk_percent, "system")
                )

        except Exception as e:
            self.logger.error(f"Failed to collect resource events: {e}")
            events.append(
                EventBuilder.error(
                    EventSource.SYSTEM,
                    "Resource event collection failed",
                    str(e),
                    {"collection_source": "resource"},
                )
            )

        return events

    async def collect_discovery_events(self) -> List[SystemEvent]:
        """Collect discovery pipeline events."""
        events = []

        try:
            # Check discovery pipeline status
            from src.services.discovery_pipeline import DiscoveryPipeline

            pipeline = DiscoveryPipeline()

            # Get pipeline status
            status = await pipeline.get_status()

            if status.get("errors"):
                for error in status["errors"]:
                    event = EventBuilder.error(
                        EventSource.DISCOVERY_PIPELINE,
                        "Discovery pipeline error",
                        error,
                        {
                            "pipeline_id": status.get("pipeline_id"),
                            "discovery_type": status.get("discovery_type"),
                        },
                    )
                    event.category = EventCategory.DISCOVERY
                    events.append(event.build())

            if status.get("targets_discovered", 0) > 0:
                event = EventBuilder()
                event.event_type = EventType.TARGET_DISCOVERED
                event.severity = EventSeverity.INFO
                event.source = EventSource.DISCOVERY_PIPELINE
                event.category = EventCategory.DISCOVERY
                event.title = f"Discovered {status['targets_discovered']} new targets"
                event.description = f"Discovery pipeline found {status['targets_discovered']} new targets"
                event.details = {
                    "targets_discovered": status["targets_discovered"],
                    "discovery_type": status.get("discovery_type"),
                    "discovery_duration": status.get("duration"),
                }

                events.append(event.build())

        except Exception as e:
            self.logger.error(f"Failed to collect discovery events: {e}")
            events.append(
                EventBuilder.error(
                    EventSource.DISCOVERY_PIPELINE,
                    "Discovery event collection failed",
                    str(e),
                    {"collection_source": "discovery"},
                )
            )

        return events

    async def collect_audit_events(self) -> List[SystemEvent]:
        """Collect events from audit logs."""
        events = []

        try:
            # Get recent audit events
            audit_events = await self.audit_logger.get_recent_events(hours=24)

            for audit_event in audit_events:
                # Convert audit events to system events
                severity = EventSeverity.INFO
                if audit_event.level == LogLevel.ERROR:
                    severity = EventSeverity.ERROR
                elif audit_event.level == LogLevel.WARNING:
                    severity = EventSeverity.WARNING

                event = EventBuilder()
                event.event_type = EventType.OPERATION_COMPLETED
                event.severity = severity
                event.source = EventSource.SECURITY_AUDIT
                event.category = EventCategory.SECURITY
                event.title = f"Audit: {audit_event.operation}"
                event.description = audit_event.message
                event.metadata.correlation_id = audit_event.correlation_id
                event.details = {
                    "operation": audit_event.operation,
                    "level": audit_event.level.value,
                    "subject": audit_event.subject,
                    "success": audit_event.success,
                    "risk_level": audit_event.risk_level,
                }

                events.append(event.build())

        except Exception as e:
            self.logger.error(f"Failed to collect audit events: {e}")

        return events

    async def collect_all_events(self) -> List[SystemEvent]:
        """Collect events from all sources."""
        self.logger.info("Starting comprehensive event collection")

        # Collect from all sources concurrently
        tasks = [
            self.collect_fleet_health_events(),
            self.collect_resource_events(),
            self.collect_security_events(),
            self.collect_lifecycle_events(),
            self.collect_discovery_events(),
            self.collect_audit_events(),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_events = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.logger.error(f"Collection task {i} failed: {result}")
            else:
                all_events.extend(result)

        self.logger.info(f"Collected {len(all_events)} events from all sources")
        return all_events

    def _create_resource_threshold_event(
        self, target: str, resource_type: str, usage_percent: float
    ) -> SystemEvent:
        """Create a resource threshold breach event."""
        event = EventBuilder()
        event.event_type = EventType.RESOURCE_THRESHOLD
        event.severity = EventSeverity.WARNING
        event.source = EventSource.FLEET_INVENTORY
        event.target = target
        event.category = EventCategory.PERFORMANCE
        event.title = f"{resource_type.capitalize()} usage high"
        event.description = (
            f"{resource_type.capitalize()} usage at {usage_percent:.1f}% on {target}"
        )
        event.details = {
            "resource_type": resource_type,
            "usage_percent": usage_percent,
            "threshold": 80.0,
        }
        event.add_tag("resource_threshold")

        # Set resource usage
        usage = ResourceUsage()
        if resource_type == "cpu":
            usage.cpu_percent = usage_percent
        elif resource_type == "memory":
            usage.memory_percent = usage_percent
        elif resource_type == "disk":
            usage.disk_percent = usage_percent

        event.resource_usage = usage

        return event.build()

    def _create_system_resource_event(
        self, resource_type: str, usage_percent: float, target: str
    ) -> SystemEvent:
        """Create a system resource event."""
        event = EventBuilder()
        event.event_type = EventType.RESOURCE_THRESHOLD
        event.severity = EventSeverity.WARNING
        event.source = EventSource.SYSTEM
        event.target = target
        event.category = EventCategory.PERFORMANCE
        event.title = f"System {resource_type} usage high"
        event.description = f"System {resource_type} usage at {usage_percent:.1f}%"
        event.details = {
            "resource_type": resource_type,
            "usage_percent": usage_percent,
            "threshold": 80.0,
        }
        event.add_tag("system_resource")

        # Set resource usage
        usage = ResourceUsage()
        if resource_type == "cpu":
            usage.cpu_percent = usage_percent
        elif resource_type == "memory":
            usage.memory_percent = usage_percent
        elif resource_type == "disk":
            usage.disk_percent = usage_percent

        event.resource_usage = usage

        return event.build()


class EventAggregator:
    """Aggregates and correlates events."""

    def __init__(self):
        self.logger = get_logger("event_aggregator")

    async def correlate_events(self, events: List[SystemEvent]) -> List[SystemEvent]:
        """Correlate related events and remove duplicates."""
        if not events:
            return events

        # Group events by correlation ID and target
        correlated_events = []
        seen_combinations = set()

        for event in events:
            # Create a unique key for deduplication
            key = (
                event.event_type.value,
                event.source.value,
                event.target or "none",
                event.title,
                event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            )

            if key not in seen_combinations:
                seen_combinations.add(key)
                correlated_events.append(event)

        self.logger.info(
            f"Correlated {len(events)} events into {len(correlated_events)} unique events"
        )
        return correlated_events

    async def detect_anomalies(self, events: List[SystemEvent]) -> List[SystemEvent]:
        """Detect anomalous events."""
        anomaly_events = []

        try:
            # Analyze event patterns for anomalies
            event_counts = {}
            for event in events:
                key = (event.event_type.value, event.source.value)
                event_counts[key] = event_counts.get(key, 0) + 1

            # Detect events with unusually high frequency
            threshold = 10  # events in short time window
            for (event_type, source), count in event_counts.items():
                if count > threshold:
                    anomaly_events.append(
                        EventBuilder.error(
                            EventSource.SYSTEM,
                            "High event frequency anomaly",
                            f"Detected {count} {event_type} events from {source} in short time window",
                            {
                                "anomaly_type": "high_frequency",
                                "event_type": event_type,
                                "source": source,
                                "count": count,
                                "threshold": threshold,
                            },
                        )
                    )

        except Exception as e:
            self.logger.error(f"Failed to detect anomalies: {e}")

        return anomaly_events

    async def aggregate_metrics(self, events: List[SystemEvent]) -> Dict[str, Any]:
        """Aggregate metrics from events."""
        if not events:
            return {}

        # Calculate basic statistics
        total_events = len(events)
        events_by_type = {}
        events_by_severity = {}
        events_by_source = {}

        health_scores = []
        resource_usage = {
            "cpu_avg": 0,
            "memory_avg": 0,
            "disk_avg": 0,
            "cpu_samples": 0,
            "memory_samples": 0,
            "disk_samples": 0,
        }

        for event in events:
            # Count by type
            event_type = event.event_type.value
            events_by_type[event_type] = events_by_type.get(event_type, 0) + 1

            # Count by severity
            severity = event.severity.value
            events_by_severity[severity] = events_by_severity.get(severity, 0) + 1

            # Count by source
            source = event.source.value
            events_by_source[source] = events_by_source.get(source, 0) + 1

            # Collect health scores
            if event.health_score is not None:
                health_scores.append(event.health_score)

            # Collect resource usage
            if event.resource_usage:
                if event.resource_usage.cpu_percent is not None:
                    resource_usage["cpu_avg"] += event.resource_usage.cpu_percent
                    resource_usage["cpu_samples"] += 1
                if event.resource_usage.memory_percent is not None:
                    resource_usage["memory_avg"] += event.resource_usage.memory_percent
                    resource_usage["memory_samples"] += 1
                if event.resource_usage.disk_percent is not None:
                    resource_usage["disk_avg"] += event.resource_usage.disk_percent
                    resource_usage["disk_samples"] += 1

        # Calculate averages
        if resource_usage["cpu_samples"] > 0:
            resource_usage["cpu_avg"] /= resource_usage["cpu_samples"]
        if resource_usage["memory_samples"] > 0:
            resource_usage["memory_avg"] /= resource_usage["memory_samples"]
        if resource_usage["disk_samples"] > 0:
            resource_usage["disk_avg"] /= resource_usage["disk_samples"]

        # Calculate health score statistics
        health_stats = {}
        if health_scores:
            health_stats = {
                "avg": sum(health_scores) / len(health_scores),
                "min": min(health_scores),
                "max": max(health_scores),
                "count": len(health_scores),
            }

        return {
            "total_events": total_events,
            "events_by_type": events_by_type,
            "events_by_severity": events_by_severity,
            "events_by_source": events_by_source,
            "health_statistics": health_stats,
            "resource_usage": resource_usage,
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def generate_health_score(self, events: List[SystemEvent]) -> float:
        """Generate overall health score based on events."""
        if not events:
            return 100.0  # Perfect health if no events

        # Calculate health score based on event severity
        score = 100.0
        total_events = len(events)

        for event in events:
            if event.severity == EventSeverity.CRITICAL:
                score -= 20.0
            elif event.severity == EventSeverity.ERROR:
                score -= 10.0
            elif event.severity == EventSeverity.WARNING:
                score -= 5.0
            elif event.severity == EventSeverity.DEBUG:
                score -= 0.5

        # Ensure score stays within bounds
        score = max(0.0, min(100.0, score))

        return score


# Global instances
event_collector = EventCollector()
event_aggregator = EventAggregator()


async def collect_and_aggregate_events() -> Tuple[List[SystemEvent], Dict[str, Any]]:
    """Collect events from all sources and aggregate metrics."""
    # Collect events
    events = await event_collector.collect_all_events()

    # Correlate and filter
    correlated_events = await event_aggregator.correlate_events(events)

    # Detect anomalies
    anomalies = await event_aggregator.detect_anomalies(correlated_events)

    # Combine all events
    all_events = correlated_events + anomalies

    # Aggregate metrics
    metrics = await event_aggregator.aggregate_metrics(all_events)

    return all_events, metrics
