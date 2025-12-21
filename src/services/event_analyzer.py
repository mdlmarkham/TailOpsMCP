"""
Event analysis and insights system for TailOpsMCP observability.

This module provides comprehensive event analysis including trend detection,
pattern recognition, anomaly detection, and predictive analytics.
"""

import statistics
from collections import defaultdict, Counter
from dataclasses import dataclass
from datetime import datetime
from datetime import timezone, timezone
from typing import Any, Dict, List, Tuple

from src.models.event_models import SystemEvent, EventType, EventSeverity, EventSource
from src.services.event_store import get_event_store, get_event_index
from src.utils.logging_config import get_logger


@dataclass
class Trend:
    """Represents a trend in event data."""

    name: str
    direction: str  # 'increasing', 'decreasing', 'stable'
    confidence: float  # 0.0 to 1.0
    description: str
    affected_metrics: List[str]
    time_period: str
    impact: str  # 'high', 'medium', 'low'
    data_points: List[Tuple[datetime, float]]


@dataclass
class Pattern:
    """Represents a detected pattern in events."""

    name: str
    pattern_type: str  # 'recurring', 'sequential', 'correlation', 'anomaly'
    description: str
    frequency: int  # How often this pattern occurs
    confidence: float
    events_involved: List[str]  # Event IDs involved
    time_range: Tuple[datetime, datetime]
    characteristics: Dict[str, Any]


@dataclass
class Insight:
    """Represents an insight derived from event analysis."""

    title: str
    description: str
    insight_type: str  # 'operational', 'security', 'performance', 'health'
    priority: str  # 'high', 'medium', 'low'
    recommendations: List[str]
    supporting_evidence: List[str]
    timestamp: datetime
    related_events: List[str]


@dataclass
class Prediction:
    """Represents a prediction about future events."""

    prediction_type: str  # 'failure', 'capacity', 'security', 'health'
    description: str
    probability: float  # 0.0 to 1.0
    time_horizon: str  # '1h', '24h', '7d', '30d'
    affected_targets: List[str]
    risk_level: str  # 'high', 'medium', 'low'
    confidence: float
    recommendations: List[str]


class EventAnalyzer:
    """Analyzes events for patterns and insights."""

    def __init__(self):
        self.logger = get_logger("event_analyzer")
        self.event_store = get_event_store()
        self.event_index = get_event_index()

    async def detect_trends(self, events: List[SystemEvent]) -> List[Trend]:
        """Detect trends in event data."""
        trends = []

        if len(events) < 10:
            return trends

        try:
            # Group events by time intervals
            time_grouped = self._group_events_by_time_interval(events, "hour")

            # Analyze trends by different metrics
            trends.extend(await self._analyze_event_frequency_trends(time_grouped))
            trends.extend(await self._analyze_severity_trends(time_grouped))
            trends.extend(await self._analyze_source_trends(time_grouped))
            trends.extend(await self._analyze_health_score_trends(events))
            trends.extend(await self._analyze_resource_usage_trends(events))

            self.logger.info(f"Detected {len(trends)} trends")
            return trends

        except Exception as e:
            self.logger.error(f"Failed to detect trends: {e}")
            return []

    def _group_events_by_time_interval(
        self, events: List[SystemEvent], interval: str
    ) -> Dict[str, List[SystemEvent]]:
        """Group events by time intervals."""
        grouped = defaultdict(list)

        for event in events:
            if interval == "hour":
                key = event.timestamp.strftime("%Y-%m-%d %H:00:00")
            elif interval == "day":
                key = event.timestamp.strftime("%Y-%m-%d")
            else:
                key = event.timestamp.strftime("%Y-%m-%d %H:00:00")

            grouped[key].append(event)

        return dict(grouped)

    async def _analyze_event_frequency_trends(
        self, time_grouped: Dict[str, List[SystemEvent]]
    ) -> List[Trend]:
        """Analyze trends in event frequency."""
        trends = []

        # Calculate event counts over time
        time_points = sorted(time_grouped.keys())
        counts = [len(time_grouped[time_point]) for time_point in time_points]

        if len(counts) < 3:
            return trends

        # Calculate trend direction
        first_half_avg = statistics.mean(counts[: len(counts) // 2])
        second_half_avg = statistics.mean(counts[len(counts) // 2 :])

        change_ratio = (
            (second_half_avg - first_half_avg) / first_half_avg
            if first_half_avg > 0
            else 0
        )

        if abs(change_ratio) > 0.2:  # 20% change threshold
            direction = "increasing" if change_ratio > 0 else "decreasing"
            confidence = min(abs(change_ratio), 1.0)

            trend = Trend(
                name="Event Frequency Trend",
                direction=direction,
                confidence=confidence,
                description=f"Event frequency is {direction} by {abs(change_ratio) * 100:.1f}%",
                affected_metrics=["event_count"],
                time_period=f"{len(time_points)} hours",
                impact="medium",
                data_points=[
                    (datetime.fromisoformat(tp), c)
                    for tp, c in zip(time_points, counts)
                ],
            )
            trends.append(trend)

        return trends

    async def _analyze_severity_trends(
        self, time_grouped: Dict[str, List[SystemEvent]]
    ) -> List[Trend]:
        """Analyze trends in event severity."""
        trends = []

        severity_scores = []
        time_points = sorted(time_grouped.keys())

        for time_point in time_points:
            events = time_grouped[time_point]
            # Calculate average severity score (CRITICAL=4, ERROR=3, WARNING=2, INFO=1, DEBUG=0)
            severity_mapping = {
                EventSeverity.CRITICAL: 4,
                EventSeverity.ERROR: 3,
                EventSeverity.WARNING: 2,
                EventSeverity.INFO: 1,
                EventSeverity.DEBUG: 0,
            }

            if events:
                avg_severity = sum(
                    severity_mapping.get(e.severity, 0) for e in events
                ) / len(events)
                severity_scores.append(avg_severity)
            else:
                severity_scores.append(0)

        if len(severity_scores) < 3:
            return trends

        # Analyze severity trend
        first_half_avg = statistics.mean(severity_scores[: len(severity_scores) // 2])
        second_half_avg = statistics.mean(severity_scores[len(severity_scores) // 2 :])

        change = second_half_avg - first_half_avg

        if abs(change) > 0.5:  # Significant severity change
            direction = "increasing" if change > 0 else "decreasing"
            confidence = min(abs(change) / 2.0, 1.0)  # Normalize to 0-1

            trend = Trend(
                name="Event Severity Trend",
                direction=direction,
                confidence=confidence,
                description=f"Event severity is {direction}",
                affected_metrics=["severity_score"],
                time_period=f"{len(time_points)} hours",
                impact="high" if abs(change) > 1.0 else "medium",
                data_points=[
                    (datetime.fromisoformat(tp), s)
                    for tp, s in zip(time_points, severity_scores)
                ],
            )
            trends.append(trend)

        return trends

    async def _analyze_source_trends(
        self, time_grouped: Dict[str, List[SystemEvent]]
    ) -> List[Trend]:
        """Analyze trends in event sources."""
        trends = []

        source_counts = defaultdict(list)
        time_points = sorted(time_grouped.keys())

        # Collect counts per source over time
        for time_point in time_points:
            events = time_grouped[time_point]
            source_counter = Counter(event.source.value for event in events)

            for source in EventSource:
                source_counts[source.value].append(source_counter.get(source.value, 0))

        # Analyze trends for each source
        for source, counts in source_counts.items():
            if len(counts) < 3:
                continue

            first_half_avg = statistics.mean(counts[: len(counts) // 2])
            second_half_avg = statistics.mean(counts[len(counts) // 2 :])

            if first_half_avg > 0:
                change_ratio = (second_half_avg - first_half_avg) / first_half_avg

                if abs(change_ratio) > 0.5:  # 50% change threshold
                    direction = "increasing" if change_ratio > 0 else "decreasing"
                    confidence = min(abs(change_ratio), 1.0)

                    trend = Trend(
                        name=f"{source} Activity Trend",
                        direction=direction,
                        confidence=confidence,
                        description=f"Activity from {source} is {direction} by {abs(change_ratio) * 100:.1f}%",
                        affected_metrics=[f"{source}_event_count"],
                        time_period=f"{len(time_points)} hours",
                        impact="medium",
                        data_points=[
                            (datetime.fromisoformat(tp), c)
                            for tp, c in zip(time_points, counts)
                        ],
                    )
                    trends.append(trend)

        return trends

    async def _analyze_health_score_trends(
        self, events: List[SystemEvent]
    ) -> List[Trend]:
        """Analyze trends in health scores."""
        trends = []

        # Filter events with health scores
        health_events = [e for e in events if e.health_score is not None]

        if len(health_events) < 5:
            return trends

        # Sort by timestamp
        health_events.sort(key=lambda x: x.timestamp)

        # Group by time intervals
        time_grouped = self._group_events_by_time_interval(health_events, "hour")

        health_scores = []
        time_points = sorted(time_grouped.keys())

        for time_point in time_points:
            events_in_period = time_grouped[time_point]
            avg_score = statistics.mean(
                e.health_score for e in events_in_period if e.health_score is not None
            )
            health_scores.append(avg_score)

        if len(health_scores) < 3:
            return trends

        # Analyze health score trend
        first_half_avg = statistics.mean(health_scores[: len(health_scores) // 2])
        second_half_avg = statistics.mean(health_scores[len(health_scores) // 2 :])

        change = second_half_avg - first_half_avg

        if abs(change) > 5:  # 5-point change threshold
            direction = "improving" if change > 0 else "declining"
            confidence = min(abs(change) / 20.0, 1.0)

            trend = Trend(
                name="Health Score Trend",
                direction=direction,
                confidence=confidence,
                description=f"Health scores are {direction} by {abs(change):.1f} points",
                affected_metrics=["health_score"],
                time_period=f"{len(time_points)} hours",
                impact="high",
                data_points=[
                    (datetime.fromisoformat(tp), s)
                    for tp, s in zip(time_points, health_scores)
                ],
            )
            trends.append(trend)

        return trends

    async def _analyze_resource_usage_trends(
        self, events: List[SystemEvent]
    ) -> List[Trend]:
        """Analyze trends in resource usage."""
        trends = []

        # Filter events with resource usage
        resource_events = [e for e in events if e.resource_usage]

        if len(resource_events) < 5:
            return trends

        # Group by time intervals
        time_grouped = self._group_events_by_time_interval(resource_events, "hour")

        time_points = sorted(time_grouped.keys())

        # Analyze each resource type
        for resource_type in ["cpu", "memory", "disk"]:
            usage_values = []

            for time_point in time_points:
                events_in_period = time_grouped[time_point]
                usage_values_period = []

                for event in events_in_period:
                    if event.resource_usage:
                        if (
                            resource_type == "cpu"
                            and event.resource_usage.cpu_percent is not None
                        ):
                            usage_values_period.append(event.resource_usage.cpu_percent)
                        elif (
                            resource_type == "memory"
                            and event.resource_usage.memory_percent is not None
                        ):
                            usage_values_period.append(
                                event.resource_usage.memory_percent
                            )
                        elif (
                            resource_type == "disk"
                            and event.resource_usage.disk_percent is not None
                        ):
                            usage_values_period.append(
                                event.resource_usage.disk_percent
                            )

                if usage_values_period:
                    usage_values.append(statistics.mean(usage_values_period))
                else:
                    usage_values.append(None)

            # Filter out None values
            valid_points = [
                (tp, uv) for tp, uv in zip(time_points, usage_values) if uv is not None
            ]

            if len(valid_points) < 3:
                continue

            _, usage_vals = zip(*valid_points)

            # Analyze trend
            first_half_avg = statistics.mean(usage_vals[: len(usage_vals) // 2])
            second_half_avg = statistics.mean(usage_vals[len(usage_vals) // 2 :])

            change = second_half_avg - first_half_avg

            if abs(change) > 5:  # 5% change threshold
                direction = "increasing" if change > 0 else "decreasing"
                confidence = min(abs(change) / 20.0, 1.0)

                trend = Trend(
                    name=f"{resource_type.capitalize()} Usage Trend",
                    direction=direction,
                    confidence=confidence,
                    description=f"{resource_type.capitalize()} usage is {direction} by {abs(change):.1f}%",
                    affected_metrics=[f"{resource_type}_usage"],
                    time_period=f"{len(valid_points)} hours",
                    impact="high" if abs(change) > 15 else "medium",
                    data_points=valid_points,
                )
                trends.append(trend)

        return trends

    async def detect_patterns(self, events: List[SystemEvent]) -> List[Pattern]:
        """Detect patterns in event data."""
        patterns = []

        if len(events) < 5:
            return patterns

        try:
            # Detect recurring patterns
            patterns.extend(await self._detect_recurring_patterns(events))

            # Detect sequential patterns
            patterns.extend(await self._detect_sequential_patterns(events))

            # Detect correlation patterns
            patterns.extend(await self._detect_correlation_patterns(events))

            # Detect anomaly patterns
            patterns.extend(await self._detect_anomaly_patterns(events))

            self.logger.info(f"Detected {len(patterns)} patterns")
            return patterns

        except Exception as e:
            self.logger.error(f"Failed to detect patterns: {e}")
            return []

    async def _detect_recurring_patterns(
        self, events: List[SystemEvent]
    ) -> List[Pattern]:
        """Detect recurring event patterns."""
        patterns = []

        # Group events by type and source
        event_groups = defaultdict(list)
        for event in events:
            key = (event.event_type.value, event.source.value)
            event_groups[key].append(event)

        # Look for recurring combinations
        for (event_type, source), group_events in event_groups.items():
            if len(group_events) >= 3:
                # Check if events occur at regular intervals
                timestamps = [e.timestamp for e in group_events]
                timestamps.sort()

                intervals = []
                for i in range(1, len(timestamps)):
                    interval = (
                        timestamps[i] - timestamps[i - 1]
                    ).total_seconds() / 3600  # hours
                    intervals.append(interval)

                if intervals:
                    avg_interval = statistics.mean(intervals)
                    std_interval = (
                        statistics.stdev(intervals) if len(intervals) > 1 else 0
                    )

                    # Check if intervals are consistent (low standard deviation)
                    if (
                        avg_interval > 0 and std_interval / avg_interval < 0.3
                    ):  # CV < 30%
                        pattern = Pattern(
                            name=f"Recurring {event_type} from {source}",
                            pattern_type="recurring",
                            description=f"{event_type} events from {source} occur regularly every {avg_interval:.1f} hours",
                            frequency=len(group_events),
                            confidence=min(1.0 - (std_interval / avg_interval), 1.0),
                            events_involved=[e.event_id for e in group_events],
                            time_range=(min(timestamps), max(timestamps)),
                            characteristics={
                                "average_interval_hours": avg_interval,
                                "std_interval_hours": std_interval,
                                "event_type": event_type,
                                "source": source,
                            },
                        )
                        patterns.append(pattern)

        return patterns

    async def _detect_sequential_patterns(
        self, events: List[SystemEvent]
    ) -> List[Pattern]:
        """Detect sequential event patterns."""
        patterns = []

        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda x: x.timestamp)

        # Look for event sequences
        sequence_length = 3
        for i in range(len(sorted_events) - sequence_length + 1):
            sequence = sorted_events[i : i + sequence_length]

            # Check if this sequence repeats
            sequence_signature = [
                (e.event_type.value, e.source.value) for e in sequence
            ]

            # Count occurrences of this sequence
            occurrence_count = 1
            for j in range(i + 1, len(sorted_events) - sequence_length + 1):
                comparison_sequence = sorted_events[j : j + sequence_length]
                comparison_signature = [
                    (e.event_type.value, e.source.value) for e in comparison_sequence
                ]

                if sequence_signature == comparison_signature:
                    occurrence_count += 1

            # If sequence occurs multiple times, it's a pattern
            if occurrence_count >= 2:
                pattern = Pattern(
                    name=f"Sequential pattern {i}",
                    pattern_type="sequential",
                    description=f"Sequence of {sequence_length} events repeats {occurrence_count} times",
                    frequency=occurrence_count,
                    confidence=min(occurrence_count / 5.0, 1.0),
                    events_involved=[e.event_id for e in sequence],
                    time_range=(sequence[0].timestamp, sequence[-1].timestamp),
                    characteristics={
                        "sequence_length": sequence_length,
                        "event_types": [e.event_type.value for e in sequence],
                        "sources": [e.source.value for e in sequence],
                    },
                )
                patterns.append(pattern)
                break  # Avoid duplicates

        return patterns

    async def _detect_correlation_patterns(
        self, events: List[SystemEvent]
    ) -> List[Pattern]:
        """Detect correlation patterns between different event types."""
        patterns = []

        # Group events by target
        target_groups = defaultdict(list)
        for event in events:
            if event.target:
                target_groups[event.target].append(event)

        # Look for correlations within targets
        for target, target_events in target_groups.items():
            if len(target_events) < 5:
                continue

            # Count event types for this target
            event_type_counts = Counter(e.event_type.value for e in target_events)

            # Check for dominant event types
            total_events = len(target_events)
            for event_type, count in event_type_counts.items():
                ratio = count / total_events

                if ratio > 0.3:  # Event type represents > 30% of events for this target
                    pattern = Pattern(
                        name=f"{event_type} dominance on {target}",
                        pattern_type="correlation",
                        description=f"{event_type} events dominate {target} ({ratio * 100:.1f}% of events)",
                        frequency=count,
                        confidence=ratio,
                        events_involved=[
                            e.event_id
                            for e in target_events
                            if e.event_type.value == event_type
                        ],
                        time_range=(
                            min(e.timestamp for e in target_events),
                            max(e.timestamp for e in target_events),
                        ),
                        characteristics={
                            "target": target,
                            "dominant_event_type": event_type,
                            "dominance_ratio": ratio,
                            "total_events": total_events,
                        },
                    )
                    patterns.append(pattern)

        return patterns

    async def _detect_anomaly_patterns(
        self, events: List[SystemEvent]
    ) -> List[Pattern]:
        """Detect anomalous event patterns."""
        patterns = []

        # Detect unusual event frequency bursts
        time_grouped = self._group_events_by_time_interval(events, "hour")

        if len(time_grouped) >= 3:
            counts = [
                len(events_in_period) for events_in_period in time_grouped.values()
            ]
            avg_count = statistics.mean(counts)
            std_count = statistics.stdev(counts) if len(counts) > 1 else 0

            # Find time periods with unusually high or low event counts
            for time_period, period_events in time_grouped.items():
                count = len(period_events)
                z_score = (count - avg_count) / std_count if std_count > 0 else 0

                if abs(z_score) > 2:  # More than 2 standard deviations
                    pattern_type = "high_activity" if z_score > 0 else "low_activity"
                    confidence = min(abs(z_score) / 3.0, 1.0)

                    pattern = Pattern(
                        name=f"{pattern_type.replace('_', ' ').title()} Anomaly",
                        pattern_type="anomaly",
                        description=f"Unusual {pattern_type.replace('_', ' ')} detected at {time_period}",
                        frequency=count,
                        confidence=confidence,
                        events_involved=[e.event_id for e in period_events],
                        time_range=(
                            min(e.timestamp for e in period_events),
                            max(e.timestamp for e in period_events),
                        ),
                        characteristics={
                            "time_period": time_period,
                            "event_count": count,
                            "expected_count": avg_count,
                            "z_score": z_score,
                            "anomaly_type": pattern_type,
                        },
                    )
                    patterns.append(pattern)

        return patterns

    async def generate_insights(self, events: List[SystemEvent]) -> List[Insight]:
        """Generate insights from event analysis."""
        insights = []

        try:
            # Generate operational insights
            insights.extend(await self._generate_operational_insights(events))

            # Generate security insights
            insights.extend(await self._generate_security_insights(events))

            # Generate performance insights
            insights.extend(await self._generate_performance_insights(events))

            # Generate health insights
            insights.extend(await self._generate_health_insights(events))

            self.logger.info(f"Generated {len(insights)} insights")
            return insights

        except Exception as e:
            self.logger.error(f"Failed to generate insights: {e}")
            return []

    async def _generate_operational_insights(
        self, events: List[SystemEvent]
    ) -> List[Insight]:
        """Generate operational insights."""
        insights = []

        # Analyze operation completion rates
        operation_events = [
            e
            for e in events
            if e.event_type
            in [EventType.OPERATION_COMPLETED, EventType.OPERATION_FAILED]
        ]

        if operation_events:
            completed = len(
                [
                    e
                    for e in operation_events
                    if e.event_type == EventType.OPERATION_COMPLETED
                ]
            )
            failed = len(
                [
                    e
                    for e in operation_events
                    if e.event_type == EventType.OPERATION_FAILED
                ]
            )
            total = len(operation_events)

            success_rate = completed / total if total > 0 else 0

            if success_rate < 0.8:  # Less than 80% success rate
                insight = Insight(
                    title="Low Operation Success Rate",
                    description=f"Operation success rate is {success_rate * 100:.1f}% ({completed}/{total})",
                    insight_type="operational",
                    priority="high" if success_rate < 0.6 else "medium",
                    recommendations=[
                        "Review recent failed operations",
                        "Check system resources and capacity",
                        "Verify target system availability",
                        "Review operation parameters and configurations",
                    ],
                    supporting_evidence=[
                        f"{failed} failed operations out of {total} total"
                    ],
                    timestamp=datetime.now(timezone.utc),
                    related_events=[e.event_id for e in operation_events],
                )
                insights.append(insight)

        return insights

    async def _generate_security_insights(
        self, events: List[SystemEvent]
    ) -> List[Insight]:
        """Generate security insights."""
        insights = []

        # Analyze security events
        security_events = [e for e in events if e.category.value == "security"]

        if security_events:
            critical_security = len(
                [e for e in security_events if e.severity == EventSeverity.CRITICAL]
            )

            if critical_security > 0:
                insight = Insight(
                    title="Critical Security Events Detected",
                    description=f"{critical_security} critical security events require immediate attention",
                    insight_type="security",
                    priority="high",
                    recommendations=[
                        "Investigate critical security events immediately",
                        "Review security policies and access controls",
                        "Check for potential security breaches",
                        "Update security monitoring rules",
                    ],
                    supporting_evidence=[
                        f"{len(security_events)} total security events"
                    ],
                    timestamp=datetime.now(timezone.utc),
                    related_events=[e.event_id for e in security_events],
                )
                insights.append(insight)

        return insights

    async def _generate_performance_insights(
        self, events: List[SystemEvent]
    ) -> List[Insight]:
        """Generate performance insights."""
        insights = []

        # Analyze resource usage events
        resource_events = [
            e for e in events if e.event_type == EventType.RESOURCE_THRESHOLD
        ]

        if resource_events:
            high_resource_events = [e for e in resource_events if e.resource_usage]

            for event in high_resource_events:
                if event.resource_usage:
                    if (
                        event.resource_usage.cpu_percent
                        and event.resource_usage.cpu_percent > 90
                    ):
                        insight = Insight(
                            title="Critical CPU Usage Detected",
                            description=f"CPU usage at {event.resource_usage.cpu_percent:.1f}% on {event.target}",
                            insight_type="performance",
                            priority="high",
                            recommendations=[
                                "Scale CPU resources",
                                "Optimize CPU-intensive processes",
                                "Review resource allocation",
                                "Consider load balancing",
                            ],
                            supporting_evidence=[
                                f"CPU usage: {event.resource_usage.cpu_percent}%"
                            ],
                            timestamp=datetime.now(timezone.utc),
                            related_events=[event.event_id],
                        )
                        insights.append(insight)

                    elif (
                        event.resource_usage.memory_percent
                        and event.resource_usage.memory_percent > 90
                    ):
                        insight = Insight(
                            title="Critical Memory Usage Detected",
                            description=f"Memory usage at {event.resource_usage.memory_percent:.1f}% on {event.target}",
                            insight_type="performance",
                            priority="high",
                            recommendations=[
                                "Increase memory allocation",
                                "Optimize memory usage",
                                "Review memory leaks",
                                "Scale memory resources",
                            ],
                            supporting_evidence=[
                                f"Memory usage: {event.resource_usage.memory_percent}%"
                            ],
                            timestamp=datetime.now(timezone.utc),
                            related_events=[event.event_id],
                        )
                        insights.append(insight)

        return insights

    async def _generate_health_insights(
        self, events: List[SystemEvent]
    ) -> List[Insight]:
        """Generate health insights."""
        insights = []

        # Analyze health scores
        health_events = [e for e in events if e.health_score is not None]

        if health_events:
            low_health_events = [e for e in health_events if e.health_score < 50]

            if low_health_events:
                avg_low_health = statistics.mean(
                    e.health_score for e in low_health_events
                )
                insight = Insight(
                    title="Poor System Health Detected",
                    description=f"Average health score of {avg_low_health:.1f} for {len(low_health_events)} systems",
                    insight_type="health",
                    priority="high" if avg_low_health < 30 else "medium",
                    recommendations=[
                        "Investigate systems with low health scores",
                        "Check system dependencies and connections",
                        "Review recent changes and deployments",
                        "Implement health improvement measures",
                    ],
                    supporting_evidence=[
                        f"Systems with health score < 50: {len(low_health_events)}"
                    ],
                    timestamp=datetime.now(timezone.utc),
                    related_events=[e.event_id for e in low_health_events],
                )
                insights.append(insight)

        return insights

    async def predict_issues(self, events: List[SystemEvent]) -> List[Prediction]:
        """Predict future issues based on event patterns."""
        predictions = []

        try:
            # Generate capacity predictions
            predictions.extend(await self._predict_capacity_issues(events))

            # Generate failure predictions
            predictions.extend(await self._predict_failure_risks(events))

            # Generate security predictions
            predictions.extend(await self._predict_security_risks(events))

            # Generate health predictions
            predictions.extend(await self._predict_health_risks(events))

            self.logger.info(f"Generated {len(predictions)} predictions")
            return predictions

        except Exception as e:
            self.logger.error(f"Failed to predict issues: {e}")
            return []

    async def _predict_capacity_issues(
        self, events: List[SystemEvent]
    ) -> List[Prediction]:
        """Predict capacity-related issues."""
        predictions = []

        # Analyze resource usage trends
        resource_events = [
            e for e in events if e.event_type == EventType.RESOURCE_THRESHOLD
        ]

        if len(resource_events) >= 3:
            # Group by target and resource type
            resource_trends = defaultdict(list)

            for event in resource_events:
                if event.resource_usage and event.target:
                    if event.resource_usage.cpu_percent:
                        resource_trends[(event.target, "cpu")].append(
                            event.resource_usage.cpu_percent
                        )
                    if event.resource_usage.memory_percent:
                        resource_trends[(event.target, "memory")].append(
                            event.resource_usage.memory_percent
                        )

            for (target, resource_type), usage_values in resource_trends.items():
                if len(usage_values) >= 2:
                    # Check if usage is increasing
                    usage_values.sort()
                    recent_usage = statistics.mean(
                        usage_values[-2:]
                    )  # Average of last 2 values

                    if recent_usage > 85:  # High usage threshold
                        trend_direction = (
                            "increasing"
                            if len(usage_values) > 2
                            and usage_values[-1] > usage_values[-2]
                            else "stable"
                        )

                        if trend_direction == "increasing":
                            prediction = Prediction(
                                prediction_type="capacity",
                                description=f"{resource_type.capitalize()} capacity issues predicted for {target}",
                                probability=0.7,
                                time_horizon="24h",
                                affected_targets=[target],
                                risk_level="medium" if recent_usage < 95 else "high",
                                confidence=0.6,
                                recommendations=[
                                    f"Plan {resource_type} capacity scaling for {target}",
                                    "Monitor resource usage trends",
                                    "Prepare scaling procedures",
                                    "Consider proactive resource allocation",
                                ],
                            )
                            predictions.append(prediction)

        return predictions

    async def _predict_failure_risks(
        self, events: List[SystemEvent]
    ) -> List[Prediction]:
        """Predict system failure risks."""
        predictions = []

        # Analyze error patterns
        error_events = [
            e
            for e in events
            if e.severity in [EventSeverity.ERROR, EventSeverity.CRITICAL]
        ]

        if len(error_events) >= 5:
            # Group by target
            target_errors = defaultdict(list)

            for event in error_events:
                if event.target:
                    target_errors[event.target].append(event)

            for target, target_error_events in target_errors.items():
                if len(target_error_events) >= 3:
                    # Check if errors are increasing
                    target_error_events.sort(key=lambda x: x.timestamp)
                    recent_errors = target_error_events[-3:]

                    # Check time span of recent errors
                    time_span = (
                        recent_errors[-1].timestamp - recent_errors[0].timestamp
                    ).total_seconds() / 3600  # hours

                    if time_span < 2:  # 3 errors within 2 hours
                        prediction = Prediction(
                            prediction_type="failure",
                            description=f"High failure risk detected for {target}",
                            probability=0.8,
                            time_horizon="4h",
                            affected_targets=[target],
                            risk_level="high",
                            confidence=0.7,
                            recommendations=[
                                f"Investigate {target} immediately",
                                "Check system logs and diagnostics",
                                "Prepare recovery procedures",
                                "Consider failover planning",
                            ],
                        )
                        predictions.append(prediction)

        return predictions

    async def _predict_security_risks(
        self, events: List[SystemEvent]
    ) -> List[Prediction]:
        """Predict security risks."""
        predictions = []

        # Analyze security event patterns
        security_events = [e for e in events if e.category.value == "security"]

        if len(security_events) >= 3:
            # Look for increasing security event frequency
            time_grouped = self._group_events_by_time_interval(security_events, "day")

            if len(time_grouped) >= 2:
                daily_counts = [
                    len(events_in_day) for events_in_day in time_grouped.values()
                ]
                daily_counts.sort()

                if (
                    len(daily_counts) >= 2 and daily_counts[-1] > daily_counts[0] * 2
                ):  # Doubled in frequency
                    prediction = Prediction(
                        prediction_type="security",
                        description="Increasing security event frequency detected",
                        probability=0.6,
                        time_horizon="7d",
                        affected_targets=["multiple"],
                        risk_level="medium",
                        confidence=0.5,
                        recommendations=[
                            "Review security policies",
                            "Increase security monitoring",
                            "Check for new attack vectors",
                            "Update security configurations",
                        ],
                    )
                    predictions.append(prediction)

        return predictions

    async def _predict_health_risks(
        self, events: List[SystemEvent]
    ) -> List[Prediction]:
        """Predict health-related risks."""
        predictions = []

        # Analyze health score trends
        health_events = [e for e in events if e.health_score is not None]

        if len(health_events) >= 5:
            # Group by target
            target_health = defaultdict(list)

            for event in health_events:
                if event.target:
                    target_health[event.target].append(event)

            for target, target_health_events in target_health.items():
                if len(target_health_events) >= 3:
                    # Sort by timestamp
                    target_health_events.sort(key=lambda x: x.timestamp)

                    # Check for declining health trend
                    health_scores = [e.health_score for e in target_health_events]

                    if len(health_scores) >= 3:
                        recent_avg = statistics.mean(
                            health_scores[-2:]
                        )  # Average of last 2 scores

                        if recent_avg < 60:  # Poor health threshold
                            # Check if trend is declining
                            declining_trend = (
                                len(health_scores) > 2
                                and health_scores[-1] < health_scores[-2]
                            )

                            if declining_trend:
                                prediction = Prediction(
                                    prediction_type="health",
                                    description=f"Health decline predicted for {target}",
                                    probability=0.7,
                                    time_horizon="24h",
                                    affected_targets=[target],
                                    risk_level="medium",
                                    confidence=0.6,
                                    recommendations=[
                                        f"Investigate health issues for {target}",
                                        "Check system dependencies",
                                        "Review recent changes",
                                        "Implement health monitoring",
                                    ],
                                )
                                predictions.append(prediction)

        return predictions


# Global instances
_event_analyzer_instance = None


def get_event_analyzer() -> EventAnalyzer:
    """Get the global event analyzer instance."""
    global _event_analyzer_instance
    if _event_analyzer_instance is None:
        _event_analyzer_instance = EventAnalyzer()
    return _event_analyzer_instance


async def analyze_events_comprehensive(events: List[SystemEvent]) -> Dict[str, Any]:
    """Perform comprehensive event analysis."""
    analyzer = get_event_analyzer()

    # Perform all analysis types
    trends = await analyzer.detect_trends(events)
    patterns = await analyzer.detect_patterns(events)
    insights = await analyzer.generate_insights(events)
    predictions = await analyzer.predict_issues(events)

    return {
        "trends": [trend.__dict__ for trend in trends],
        "patterns": [pattern.__dict__ for pattern in patterns],
        "insights": [insight.__dict__ for insight in insights],
        "predictions": [prediction.__dict__ for prediction in predictions],
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_events_analyzed": len(events),
    }
