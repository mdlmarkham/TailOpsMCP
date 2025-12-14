"""
Specialized TOON Serializers for TailOpsMCP Components

This module provides specialized serializers for all TailOpsMCP data types,
implementing smart compression, priority-based content organization, and
LLM-optimized formatting for each component type.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass
from enum import Enum
import logging

from src.integration.toon_enhanced import (
    TOONDocument, TOONEnhancedSerializer, ContentPriority,
    TOONDocumentCache, TOONCacheEntry
)
from src.models.fleet_inventory import FleetInventory, ProxmoxHost, Node, Service, Snapshot, Event
from src.models.event_models import SystemEvent, HealthReport, Alert, SecurityEvent, EventSeverity
from src.models.execution import OperationResult, CapabilityExecution
from src.models.policy_models import PolicyStatus, PolicyViolation
from src.models.enhanced_fleet_inventory import EnhancedFleetInventory
from src.models.inventory_snapshot import InventorySnapshot
from src.utils.toon import _compact_json, _to_toon_tabular


logger = logging.getLogger(__name__)


class TOONInventorySerializer(TOONEnhancedSerializer):
    """Specialized serializer for fleet inventory data."""
    
    def serialize_fleet_inventory(self, inventory: FleetInventory) -> TOONDocument:
        """Enhanced fleet inventory serialization with smart prioritization."""
        doc = super().serialize_fleet_inventory(inventory)
        
        # Add inventory-specific sections
        if isinstance(inventory, EnhancedFleetInventory):
            doc.add_section("discovery_status", inventory.discovery_status, ContentPriority.IMPORTANT)
            doc.add_section("capabilities", inventory.capabilities, ContentPriority.INFO)
            doc.add_section("last_discovery", inventory.last_discovery, ContentPriority.INFO)
        
        # Add health scoring
        health_scores = self._calculate_health_scores(inventory)
        doc.add_section("health_scores", health_scores, ContentPriority.IMPORTANT)
        
        # Add resource utilization
        resource_util = self._calculate_resource_utilization(inventory)
        doc.add_section("resource_utilization", resource_util, ContentPriority.INFO)
        
        # Add change detection summary
        if hasattr(inventory, 'change_detector'):
            changes = inventory.change_detector.get_recent_changes()
            doc.add_section("recent_changes", changes, ContentPriority.IMPORTANT)
        
        return doc
    
    def serialize_inventory_snapshot(self, snapshot: InventorySnapshot) -> TOONDocument:
        """Serialize inventory snapshot with time-based context."""
        doc = TOONDocument(
            document_type="inventory_snapshot",
            metadata={
                "snapshot_id": snapshot.snapshot_id,
                "created_at": snapshot.created_at,
                "inventory_hash": snapshot.inventory_hash,
                "total_targets": snapshot.total_targets
            }
        )
        
        # Snapshot summary
        summary = {
            "id": snapshot.snapshot_id,
            "created_at": snapshot.created_at,
            "total_targets": snapshot.total_targets,
            "discovery_duration": snapshot.discovery_duration,
            "inventory_hash": snapshot.inventory_hash
        }
        doc.add_section("snapshot_summary", summary, ContentPriority.IMPORTANT)
        
        # Target summary by type
        target_types = {}
        for target in snapshot.targets:
            target_type = target.get('type', 'unknown')
            target_types[target_type] = target_types.get(target_type, 0) + 1
        
        doc.add_section("target_types", target_types, ContentPriority.INFO)
        
        # Recent discoveries
        if hasattr(snapshot, 'recent_discoveries'):
            doc.add_section("recent_discoveries", snapshot.recent_discoveries, ContentPriority.IMPORTANT)
        
        # Performance metrics
        perf_metrics = {
            "discovery_time": snapshot.discovery_duration,
            "targets_per_minute": snapshot.total_targets / max(snapshot.discovery_duration / 60, 1),
            "success_rate": getattr(snapshot, 'success_rate', 1.0)
        }
        doc.add_section("performance_metrics", perf_metrics, ContentPriority.INFO)
        
        return doc
    
    def serialize_fleet_health(self, health_data: Dict[str, Any]) -> TOONDocument:
        """Serialize fleet health data with trend analysis."""
        doc = TOONDocument(
            document_type="fleet_health",
            metadata={
                "report_time": datetime.now(),
                "data_sources": health_data.get("data_sources", [])
            }
        )
        
        # Overall health score
        overall_score = health_data.get("overall_score", 0.0)
        health_status = "healthy" if overall_score > 0.8 else "degraded" if overall_score > 0.5 else "unhealthy"
        
        health_summary = {
            "overall_score": overall_score,
            "status": health_status,
            "total_targets": health_data.get("total_targets", 0),
            "healthy_targets": health_data.get("healthy_targets", 0),
            "unhealthy_targets": health_data.get("unhealthy_targets", 0),
            "critical_issues": len(health_data.get("critical_issues", [])),
            "warnings": len(health_data.get("warnings", []))
        }
        doc.add_section("health_summary", health_summary, ContentPriority.CRITICAL)
        
        # Critical issues
        critical_issues = health_data.get("critical_issues", [])
        if critical_issues:
            doc.add_section("critical_issues", critical_issues, ContentPriority.CRITICAL)
        
        # Resource alerts
        resource_alerts = health_data.get("resource_alerts", [])
        if resource_alerts:
            doc.add_section("resource_alerts", resource_alerts, ContentPriority.IMPORTANT)
        
        # Health trends (if historical data available)
        if "health_trends" in health_data:
            doc.add_section("health_trends", health_data["health_trends"], ContentPriority.INFO)
        
        return doc
    
    def _calculate_health_scores(self, inventory: FleetInventory) -> Dict[str, Any]:
        """Calculate health scores for inventory components."""
        health_scores = {
            "hosts": {},
            "nodes": {},
            "services": {},
            "overall": 0.0
        }
        
        # Calculate host health
        total_hosts = len(inventory.proxmox_hosts)
        healthy_hosts = len([h for h in inventory.proxmox_hosts.values() if h.is_active])
        host_score = healthy_hosts / max(total_hosts, 1)
        health_scores["hosts"]["score"] = host_score
        health_scores["hosts"]["healthy_count"] = healthy_hosts
        health_scores["hosts"]["total_count"] = total_hosts
        
        # Calculate node health
        total_nodes = len(inventory.nodes)
        managed_nodes = len([n for n in inventory.nodes.values() if n.is_managed])
        node_score = managed_nodes / max(total_nodes, 1)
        health_scores["nodes"]["score"] = node_score
        health_scores["nodes"]["managed_count"] = managed_nodes
        health_scores["nodes"]["total_count"] = total_nodes
        
        # Calculate service health
        total_services = len(inventory.services)
        running_services = len([s for s in inventory.services.values() if s.status.value == "running"])
        service_score = running_services / max(total_services, 1)
        health_scores["services"]["score"] = service_score
        health_scores["services"]["running_count"] = running_services
        health_scores["services"]["total_count"] = total_services
        
        # Calculate overall score
        health_scores["overall"] = (host_score + node_score + service_score) / 3.0
        
        return health_scores
    
    def _calculate_resource_utilization(self, inventory: FleetInventory) -> Dict[str, Any]:
        """Calculate resource utilization across the fleet."""
        utilization = {
            "cpu": {"total": 0, "available": 0, "utilization_percent": 0},
            "memory": {"total": 0, "available": 0, "utilization_percent": 0},
            "storage": {"total": 0, "available": 0, "utilization_percent": 0}
        }
        
        total_cpu = 0
        total_memory = 0
        total_storage = 0
        
        for host in inventory.proxmox_hosts.values():
            total_cpu += host.cpu_cores
            total_memory += host.memory_mb
            total_storage += host.storage_gb
        
        # Calculate utilization (simplified - would need actual usage data)
        utilization["cpu"]["total"] = total_cpu
        utilization["memory"]["total"] = total_memory
        utilization["storage"]["total"] = total_storage
        
        # Placeholder utilization percentages (would need real monitoring data)
        utilization["cpu"]["utilization_percent"] = 45.0
        utilization["memory"]["utilization_percent"] = 62.0
        utilization["storage"]["utilization_percent"] = 38.0
        
        return utilization


class TOONEventsSerializer(TOONEnhancedSerializer):
    """Specialized serializer for events and monitoring data."""
    
    def serialize_events_summary(self, events: List[SystemEvent], time_range: str = "24h") -> TOONDocument:
        """Enhanced events summary with trend analysis and insights."""
        doc = super().serialize_events_summary(events, time_range)
        
        # Event trends analysis
        trends = self._analyze_event_trends(events)
        doc.add_section("event_trends", trends, ContentPriority.IMPORTANT)
        
        # Top event sources with details
        source_details = self._get_detailed_event_sources(events)
        doc.add_section("event_sources", source_details, ContentPriority.INFO)
        
        # Actionable insights
        insights = self._generate_actionable_insights(events)
        doc.add_section("actionable_insights", insights, ContentPriority.IMPORTANT)
        
        # Pattern detection
        patterns = self._detect_event_patterns(events)
        if patterns:
            doc.add_section("event_patterns", patterns, ContentPriority.INFO)
        
        return doc
    
    def serialize_health_report(self, report: HealthReport) -> TOONDocument:
        """Enhanced health report with detailed analysis."""
        doc = super().serialize_health_report(report)
        
        # Add trend analysis if historical data available
        if hasattr(report, 'historical_scores'):
            trend_analysis = self._analyze_health_trends(report.historical_scores)
            doc.add_section("health_trends", trend_analysis, ContentPriority.INFO)
        
        # Add detailed component analysis
        if hasattr(report, 'component_analysis'):
            doc.add_section("component_analysis", report.component_analysis, ContentPriority.IMPORTANT)
        
        # Add predictive insights
        if hasattr(report, 'predictions'):
            doc.add_section("predictions", report.predictions, ContentPriority.INFO)
        
        return doc
    
    def serialize_alert_summary(self, alerts: List[Alert]) -> TOONDocument:
        """Serialize alert summary with prioritization."""
        doc = TOONDocument(
            document_type="alert_summary",
            metadata={
                "total_alerts": len(alerts),
                "generated_at": datetime.now()
            }
        )
        
        # Alert statistics
        critical_alerts = [a for a in alerts if a.severity == EventSeverity.CRITICAL]
        warning_alerts = [a for a in alerts if a.severity == EventSeverity.WARNING]
        info_alerts = [a for a in alerts if a.severity == EventSeverity.INFO]
        
        alert_stats = {
            "total": len(alerts),
            "critical": len(critical_alerts),
            "warning": len(warning_alerts),
            "info": len(info_alerts),
            "acknowledged": len([a for a in alerts if getattr(a, 'acknowledged', False)]),
            "unacknowledged": len([a for a in alerts if not getattr(a, 'acknowledged', False)])
        }
        doc.add_section("alert_statistics", alert_stats, ContentPriority.CRITICAL)
        
        # Critical alerts
        if critical_alerts:
            critical_data = [
                {
                    "id": alert.id,
                    "title": getattr(alert, 'title', 'Unknown Alert'),
                    "source": alert.source,
                    "message": alert.message,
                    "timestamp": alert.timestamp,
                    "acknowledged": getattr(alert, 'acknowledged', False)
                }
                for alert in critical_alerts[:10]  # Limit to first 10
            ]
            doc.add_section("critical_alerts", critical_data, ContentPriority.CRITICAL)
        
        # Active alerts (unacknowledged)
        active_alerts = [
            {
                "id": alert.id,
                "severity": alert.severity.value,
                "source": alert.source,
                "message": alert.message,
                "timestamp": alert.timestamp,
                "age_hours": (datetime.now() - alert.timestamp).total_seconds() / 3600
            }
            for alert in alerts if not getattr(alert, 'acknowledged', False)
        ][:20]  # Limit to first 20
        
        if active_alerts:
            doc.add_section("active_alerts", active_alerts, ContentPriority.IMPORTANT)
        
        # Alert resolution recommendations
        recommendations = self._generate_alert_recommendations(alerts)
        doc.add_section("recommendations", recommendations, ContentPriority.IMPORTANT)
        
        return doc
    
    def serialize_security_events(self, events: List[SecurityEvent]) -> TOONDocument:
        """Serialize security events with threat analysis."""
        doc = TOONDocument(
            document_type="security_events",
            metadata={
                "total_events": len(events),
                "analysis_time": datetime.now(),
                "threat_level": self._assess_threat_level(events)
            }
        )
        
        # Security event summary
        security_summary = {
            "total_events": len(events),
            "threat_level": self._assess_threat_level(events),
            "authentication_events": len([e for e in events if e.event_type.value == "authentication"]),
            "authorization_events": len([e for e in events if e.event_type.value == "authorization"]),
            "system_events": len([e for e in events if e.event_type.value == "system"]),
            "network_events": len([e for e in events if e.event_type.value == "network"])
        }
        doc.add_section("security_summary", security_summary, ContentPriority.CRITICAL)
        
        # High-priority security events
        high_priority = [
            {
                "id": event.id,
                "type": event.event_type.value,
                "severity": event.severity.value,
                "source": event.source,
                "message": event.message,
                "timestamp": event.timestamp,
                "indicators": getattr(event, 'threat_indicators', [])
            }
            for event in events if event.severity.value in ["critical", "high"]
        ][:15]  # Limit to first 15
        
        if high_priority:
            doc.add_section("high_priority_events", high_priority, ContentPriority.CRITICAL)
        
        # Security recommendations
        recommendations = self._generate_security_recommendations(events)
        doc.add_section("security_recommendations", recommendations, ContentPriority.IMPORTANT)
        
        return doc
    
    def _analyze_event_trends(self, events: List[SystemEvent]) -> Dict[str, Any]:
        """Analyze trends in event data."""
        if not events:
            return {"trend": "no_data"}
        
        # Group events by hour
        hourly_counts = {}
        for event in events:
            hour = event.timestamp.replace(minute=0, second=0, microsecond=0)
            hourly_counts[hour] = hourly_counts.get(hour, 0) + 1
        
        # Calculate trend
        sorted_hours = sorted(hourly_counts.keys())
        if len(sorted_hours) < 2:
            trend = "insufficient_data"
        else:
            recent_avg = sum(hourly_counts[h] for h in sorted_hours[-3:]) / min(3, len(sorted_hours))
            earlier_avg = sum(hourly_counts[h] for h in sorted_hours[:3]) / min(3, len(sorted_hours))
            
            if recent_avg > earlier_avg * 1.2:
                trend = "increasing"
            elif recent_avg < earlier_avg * 0.8:
                trend = "decreasing"
            else:
                trend = "stable"
        
        return {
            "trend": trend,
            "hourly_distribution": dict(sorted(hourly_counts.items())),
            "peak_hour": max(hourly_counts.items(), key=lambda x: x[1])[0] if hourly_counts else None,
            "total_hours": len(hourly_counts)
        }
    
    def _get_detailed_event_sources(self, events: List[SystemEvent]) -> Dict[str, Any]:
        """Get detailed information about event sources."""
        source_info = {}
        for event in events:
            source = event.source
            if source not in source_info:
                source_info[source] = {
                    "count": 0,
                    "severities": {},
                    "latest_event": None
                }
            
            source_info[source]["count"] += 1
            
            severity = event.severity.value
            source_info[source]["severities"][severity] = source_info[source]["severities"].get(severity, 0) + 1
            
            if not source_info[source]["latest_event"] or event.timestamp > source_info[source]["latest_event"]["timestamp"]:
                source_info[source]["latest_event"] = {
                    "timestamp": event.timestamp,
                    "message": event.message,
                    "severity": severity
                }
        
        return source_info
    
    def _generate_actionable_insights(self, events: List[SystemEvent]) -> List[str]:
        """Generate actionable insights from events."""
        insights = []
        
        if not events:
            return ["No events detected in the specified time range."]
        
        # Check for high error rates
        error_events = [e for e in events if e.severity.value == "error"]
        if len(error_events) > 10:
            insights.append(f"High error rate detected: {len(error_events)} errors in the time range. Investigate error patterns.")
        
        # Check for critical events
        critical_events = [e for e in events if e.severity.value == "critical"]
        if critical_events:
            insights.append(f"Critical events detected: {len(critical_events)} require immediate attention.")
        
        # Check for specific patterns
        sources = {}
        for event in events:
            sources[event.source] = sources.get(event.source, 0) + 1
        
        frequent_source = max(sources.items(), key=lambda x: x[1])
        if frequent_source[1] > len(events) * 0.3:
            insights.append(f"High activity from source '{frequent_source[0]}': {frequent_source[1]} events. Monitor for anomalies.")
        
        return insights
    
    def _detect_event_patterns(self, events: List[SystemEvent]) -> Dict[str, Any]:
        """Detect patterns in event data."""
        patterns = {}
        
        # Time-based patterns
        hourly_distribution = {}
        for event in events:
            hour = event.timestamp.hour
            hourly_distribution[hour] = hourly_distribution.get(hour, 0) + 1
        
        # Find peak hours
        if hourly_distribution:
            peak_hour = max(hourly_distribution.items(), key=lambda x: x[1])
            patterns["peak_activity_hour"] = peak_hour[0]
        
        # Source-based patterns
        source_counts = {}
        for event in events:
            source_counts[event.source] = source_counts.get(event.source, 0) + 1
        
        # Identify dominant sources
        if source_counts:
            sorted_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)
            patterns["top_sources"] = sorted_sources[:5]
        
        return patterns
    
    def _analyze_health_trends(self, historical_scores: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze health score trends."""
        if len(historical_scores) < 2:
            return {"trend": "insufficient_data"}
        
        recent_scores = [s["score"] for s in historical_scores[-7:]]  # Last 7 data points
        trend_direction = "stable"
        
        if len(recent_scores) >= 2:
            if recent_scores[-1] > recent_scores[0] * 1.1:
                trend_direction = "improving"
            elif recent_scores[-1] < recent_scores[0] * 0.9:
                trend_direction = "declining"
        
        return {
            "trend": trend_direction,
            "recent_scores": recent_scores,
            "score_change": recent_scores[-1] - recent_scores[0] if len(recent_scores) >= 2 else 0,
            "volatility": self._calculate_volatility(recent_scores)
        }
    
    def _calculate_volatility(self, scores: List[float]) -> float:
        """Calculate score volatility."""
        if len(scores) < 2:
            return 0.0
        
        mean_score = sum(scores) / len(scores)
        variance = sum((score - mean_score) ** 2 for score in scores) / len(scores)
        return variance ** 0.5
    
    def _assess_threat_level(self, events: List[SecurityEvent]) -> str:
        """Assess overall threat level from security events."""
        if not events:
            return "low"
        
        critical_count = len([e for e in events if e.severity.value == "critical"])
        high_count = len([e for e in events if e.severity.value == "high"])
        
        if critical_count > 0:
            return "critical"
        elif high_count > 5:
            return "high"
        elif high_count > 0:
            return "medium"
        else:
            return "low"
    
    def _generate_alert_recommendations(self, alerts: List[Alert]) -> List[str]:
        """Generate recommendations based on alert analysis."""
        recommendations = []
        
        # Check for unacknowledged critical alerts
        critical_unack = [a for a in alerts if a.severity == EventSeverity.CRITICAL and not getattr(a, 'acknowledged', False)]
        if critical_unack:
            recommendations.append(f"Acknowledge or resolve {len(critical_unack)} critical alerts immediately.")
        
        # Check for alert patterns
        source_counts = {}
        for alert in alerts:
            source_counts[alert.source] = source_counts.get(alert.source, 0) + 1
        
        frequent_sources = [s for s, count in source_counts.items() if count > 5]
        if frequent_sources:
            recommendations.append(f"Investigate recurring alerts from: {', '.join(frequent_sources)}")
        
        return recommendations
    
    def _generate_security_recommendations(self, events: List[SecurityEvent]) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        # Check for authentication failures
        auth_failures = [e for e in events if e.event_type.value == "authentication" and "failure" in e.message.lower()]
        if len(auth_failures) > 10:
            recommendations.append("High number of authentication failures detected. Consider reviewing access controls.")
        
        # Check for critical security events
        critical_events = [e for e in events if e.severity.value == "critical"]
        if critical_events:
            recommendations.append("Critical security events detected. Immediate investigation required.")
        
        return recommendations


class TOONOperationsSerializer(TOONEnhancedSerializer):
    """Specialized serializer for operation and execution data."""
    
    def serialize_operation_result(self, result: OperationResult) -> TOONDocument:
        """Enhanced operation result serialization with performance analysis."""
        doc = super().serialize_operation_result(result)
        
        # Add performance metrics
        if hasattr(result, 'performance_metrics'):
            doc.add_section("performance_metrics", result.performance_metrics, ContentPriority.INFO)
        
        # Add execution timeline
        if hasattr(result, 'execution_timeline'):
            doc.add_section("execution_timeline", result.execution_timeline, ContentPriority.INFO)
        
        # Add resource usage
        if hasattr(result, 'resource_usage'):
            doc.add_section("resource_usage", result.resource_usage, ContentPriority.INFO)
        
        return doc
    
    def serialize_capability_execution(self, execution: CapabilityExecution) -> TOONDocument:
        """Serialize capability execution with detailed analysis."""
        doc = TOONDocument(
            document_type="capability_execution",
            metadata={
                "capability_id": execution.capability_id,
                "execution_id": getattr(execution, 'execution_id', 'unknown'),
                "status": getattr(execution, 'status', 'unknown')
            }
        )
        
        # Execution summary
        summary = {
            "capability_id": execution.capability_id,
            "started_at": getattr(execution, 'started_at', None),
            "completed_at": getattr(execution, 'completed_at', None),
            "duration": getattr(execution, 'duration', None),
            "status": getattr(execution, 'status', 'unknown'),
            "success": getattr(execution, 'success', False)
        }
        doc.add_section("execution_summary", summary, ContentPriority.CRITICAL)
        
        # Input parameters
        if hasattr(execution, 'input_parameters'):
            doc.add_section("input_parameters", execution.input_parameters, ContentPriority.INFO)
        
        # Output results
        if hasattr(execution, 'output_results'):
            doc.add_section("output_results", execution.output_results, ContentPriority.IMPORTANT)
        
        # Error details
        if hasattr(execution, 'error_details') and execution.error_details:
            doc.add_section("error_details", execution.error_details, ContentPriority.CRITICAL)
        
        return doc


class TOONPolicySerializer(TOONEnhancedSerializer):
    """Specialized serializer for policy and compliance data."""
    
    def serialize_policy_status(self, policy_status: PolicyStatus) -> TOONDocument:
        """Enhanced policy status with compliance analysis."""
        doc = super().serialize_policy_status(policy_status)
        
        # Add compliance trends
        if hasattr(policy_status, 'compliance_history'):
            trends = self._analyze_compliance_trends(policy_status.compliance_history)
            doc.add_section("compliance_trends", trends, ContentPriority.INFO)
        
        # Add policy details
        if hasattr(policy_status, 'policy_details'):
            doc.add_section("policy_details", policy_status.policy_details, ContentPriority.INFO)
        
        # Add remediation suggestions
        if hasattr(policy_status, 'remediation_suggestions'):
            doc.add_section("remediation_suggestions", policy_status.remediation_suggestions, ContentPriority.IMPORTANT)
        
        return doc
    
    def serialize_policy_violations(self, violations: List[PolicyViolation]) -> TOONDocument:
        """Serialize policy violations with prioritization and impact analysis."""
        doc = TOONDocument(
            document_type="policy_violations",
            metadata={
                "total_violations": len(violations),
                "analysis_time": datetime.now()
            }
        )
        
        # Violation summary
        critical_violations = [v for v in violations if getattr(v, 'severity', 'medium') == 'critical']
        high_violations = [v for v in violations if getattr(v, 'severity', 'medium') == 'high']
        medium_violations = [v for v in violations if getattr(v, 'severity', 'medium') == 'medium']
        
        violation_summary = {
            "total": len(violations),
            "critical": len(critical_violations),
            "high": len(high_violations),
            "medium": len(medium_violations),
            "auto_remediable": len([v for v in violations if getattr(v, 'auto_remediable', False)])
        }
        doc.add_section("violation_summary", violation_summary, ContentPriority.CRITICAL)
        
        # Critical violations
        if critical_violations:
            critical_data = [
                {
                    "id": violation.id,
                    "policy": violation.policy_name,
                    "description": violation.description,
                    "resource": getattr(violation, 'resource', 'unknown'),
                    "timestamp": violation.timestamp,
                    "impact": getattr(violation, 'impact', 'unknown')
                }
                for violation in critical_violations[:10]  # Limit to first 10
            ]
            doc.add_section("critical_violations", critical_data, ContentPriority.CRITICAL)
        
        # Violation trends
        trends = self._analyze_violation_trends(violations)
        doc.add_section("violation_trends", trends, ContentPriority.IMPORTANT)
        
        # Remediation plan
        remediation_plan = self._generate_remediation_plan(violations)
        doc.add_section("remediation_plan", remediation_plan, ContentPriority.IMPORTANT)
        
        return doc
    
    def _analyze_compliance_trends(self, history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze compliance trends over time."""
        if len(history) < 2:
            return {"trend": "insufficient_data"}
        
        recent_compliance = [h["compliance_score"] for h in history[-7:]]  # Last 7 entries
        trend = "stable"
        
        if recent_compliance[-1] > recent_compliance[0] * 1.05:
            trend = "improving"
        elif recent_compliance[-1] < recent_compliance[0] * 0.95:
            trend = "declining"
        
        return {
            "trend": trend,
            "recent_scores": recent_compliance,
            "score_change": recent_compliance[-1] - recent_compliance[0] if len(recent_compliance) >= 2 else 0
        }
    
    def _analyze_violation_trends(self, violations: List[PolicyViolation]) -> Dict[str, Any]:
        """Analyze violation patterns and trends."""
        # Group by policy
        policy_violations = {}
        for violation in violations:
            policy = violation.policy_name
            policy_violations[policy] = policy_violations.get(policy, 0) + 1
        
        # Find most violated policies
        top_policies = sorted(policy_violations.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            "total_policies_violated": len(policy_violations),
            "most_violated_policies": top_policies,
            "violation_distribution": policy_violations
        }
    
    def _generate_remediation_plan(self, violations: List[PolicyViolation]) -> List[str]:
        """Generate remediation plan for violations."""
        plan = []
        
        # Critical violations first
        critical_violations = [v for v in violations if getattr(v, 'severity', 'medium') == 'critical']
        if critical_violations:
            plan.append(f"Address {len(critical_violations)} critical violations immediately.")
        
        # Auto-remediable violations
        auto_remediable = [v for v in violations if getattr(v, 'auto_remediable', False)]
        if auto_remediable:
            plan.append(f"Apply automatic remediation to {len(auto_remediable)} violations.")
        
        # Policy-specific recommendations
        policy_counts = {}
        for violation in violations:
            policy_counts[violation.policy_name] = policy_counts.get(violation.policy_name, 0) + 1
        
        top_policy = max(policy_counts.items(), key=lambda x: x[1])
        if top_policy[1] > 3:
            plan.append(f"Review and update policy '{top_policy[0]}' due to {top_policy[1]} violations.")
        
        return plan


# Global specialized serializers
_inventory_serializer = TOONInventorySerializer()
_events_serializer = TOONEventsSerializer()
_operations_serializer = TOONOperationsSerializer()
_policy_serializer = TOONPolicySerializer()


def get_inventory_serializer() -> TOONInventorySerializer:
    """Get the inventory-specific TOON serializer."""
    return _inventory_serializer


def get_events_serializer() -> TOONEventsSerializer:
    """Get the events-specific TOON serializer."""
    return _events_serializer


def get_operations_serializer() -> TOONOperationsSerializer:
    """Get the operations-specific TOON serializer."""
    return _operations_serializer


def get_policy_serializer() -> TOONPolicySerializer:
    """Get the policy-specific TOON serializer."""
    return _policy_serializer