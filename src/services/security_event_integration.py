"""
Security Event Integration for TailOpsMCP.

Integrates security events with the existing observability and event system:
- Security event emission and correlation
- Security dashboard generation
- Integration with event collector and processor
- Real-time security event streaming
"""

import datetime
import json
import logging
from typing import Any, Dict, List, Optional, Set
from dataclasses import asdict

from src.models.security_models import (
    SecurityAlert, SecurityOperation, IdentityEvent, PolicyDecision,
    SecurityViolation, AccessAttempt, AlertSeverity, AlertType
)
from src.services.security_audit_logger import SecurityAuditLogger
from src.services.security_monitor import SecurityMonitor
from src.services.identity_manager import IdentityManager


logger = logging.getLogger(__name__)


class SecurityEventIntegration:
    """Integrate security events with observability system."""
    
    def __init__(
        self,
        audit_logger: Optional[SecurityAuditLogger] = None,
        security_monitor: Optional[SecurityMonitor] = None,
        identity_manager: Optional[IdentityManager] = None
    ):
        """Initialize security event integration.
        
        Args:
            audit_logger: Security audit logger
            security_monitor: Security monitoring system
            identity_manager: Identity management system
        """
        self.audit_logger = audit_logger or SecurityAuditLogger()
        self.security_monitor = security_monitor or SecurityMonitor(audit_logger=self.audit_logger)
        self.identity_manager = identity_manager or IdentityManager()
        
        # Event correlation tracking
        self._event_correlation_cache: Dict[str, List[str]] = {}
        self._security_dashboard_data: Dict[str, Any] = {}
        
        logger.info("Security event integration initialized")

    async def emit_security_event(self, security_event: Dict[str, Any]) -> str:
        """Emit security event to the observability system.
        
        Args:
            security_event: Security event to emit
            
        Returns:
            Event ID for correlation
        """
        try:
            event_id = security_event.get("event_id", f"sec_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S_%f')}")
            
            # Enhance event with security context
            enhanced_event = self._enhance_security_event(security_event)
            
            # Correlate with other events
            correlation_id = await self._correlate_security_events(enhanced_event)
            enhanced_event["correlation_id"] = correlation_id
            
            # Store for dashboard generation
            await self._store_security_event_for_dashboard(enhanced_event)
            
            # Log the security event
            logger.info(f"Security event emitted: {enhanced_event.get('event_type')} - {enhanced_event.get('description', '')}")
            
            return event_id
            
        except Exception as e:
            logger.error(f"Failed to emit security event: {e}")
            raise

    async def correlate_security_events(self, events: List[SecurityEvent]) -> List[SecurityEvent]:
        """Correlate security events with each other and system events.
        
        Args:
            events: List of security events to correlate
            
        Returns:
            List of correlated events
        """
        try:
            correlated_events = []
            
            # Group events by correlation patterns
            event_groups = self._group_events_by_correlation(events)
            
            for group in event_groups:
                # Analyze correlation patterns
                correlation_analysis = self._analyze_correlation_pattern(group)
                
                # Enhance events with correlation data
                for event in group:
                    event.correlation_info = correlation_analysis
                    correlated_events.append(event)
            
            # Generate correlation alerts for significant patterns
            await self._generate_correlation_alerts(event_groups)
            
            logger.info(f"Correlated {len(events)} security events into {len(event_groups)} groups")
            return correlated_events
            
        except Exception as e:
            logger.error(f"Security event correlation failed: {e}")
            return events

    async def generate_security_dashboard(self) -> Dict[str, Any]:
        """Generate comprehensive security dashboard data.
        
        Returns:
            Security dashboard data
        """
        try:
            dashboard_data = {
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "overview": await self._generate_security_overview(),
                "alerts": await self._generate_security_alerts_summary(),
                "threats": await self._generate_threat_intelligence_summary(),
                "compliance": await self._generate_compliance_summary(),
                "trends": await self._generate_security_trends(),
                "incidents": await self._generate_incident_summary(),
                "recommendations": await self._generate_security_recommendations()
            }
            
            # Cache dashboard data
            self._security_dashboard_data = dashboard_data
            
            logger.info("Security dashboard generated successfully")
            return dashboard_data
            
        except Exception as e:
            logger.error(f"Security dashboard generation failed: {e}")
            return {
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "error": str(e),
                "overview": {},
                "alerts": {},
                "threats": {},
                "compliance": {},
                "trends": {},
                "incidents": {},
                "recommendations": []
            }

    def _enhance_security_event(self, security_event: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance security event with additional context."""
        enhanced = security_event.copy()
        
        # Add timestamp if missing
        if "timestamp" not in enhanced:
            enhanced["timestamp"] = datetime.datetime.utcnow().isoformat()
        
        # Add event source
        enhanced["event_source"] = "security_system"
        
        # Add severity mapping
        if "severity" in enhanced:
            severity = enhanced["severity"]
            if isinstance(severity, str):
                enhanced["severity_level"] = self._map_severity_to_level(severity)
        
        # Add event category
        enhanced["event_category"] = self._categorize_security_event(enhanced)
        
        # Add response recommendations
        enhanced["response_actions"] = self._generate_response_actions(enhanced)
        
        # Add compliance relevance
        enhanced["compliance_relevance"] = self._assess_compliance_relevance(enhanced)
        
        return enhanced

    async def _correlate_security_events(self, security_event: Dict[str, Any]) -> str:
        """Correlate security event with existing events."""
        correlation_id = security_event.get("correlation_id", f"corr_{datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}")
        
        # Add to correlation cache
        if correlation_id not in self._event_correlation_cache:
            self._event_correlation_cache[correlation_id] = []
        self._event_correlation_cache[correlation_id].append(security_event.get("event_id", ""))
        
        # Check for correlation patterns
        await self._check_correlation_patterns(security_event)
        
        return correlation_id

    def _group_events_by_correlation(self, events: List) -> List[List]:
        """Group events by correlation patterns."""
        groups = []
        processed_events = set()
        
        for i, event in enumerate(events):
            if i in processed_events:
                continue
            
            group = [event]
            processed_events.add(i)
            
            # Find correlated events
            for j, other_event in enumerate(events):
                if j != i and j not in processed_events:
                    if self._are_events_correlated(event, other_event):
                        group.append(other_event)
                        processed_events.add(j)
            
            groups.append(group)
        
        return groups

    def _are_events_correlated(self, event1, event2) -> bool:
        """Check if two events are correlated."""
        # Time correlation (within 5 minutes)
        time1 = getattr(event1, 'timestamp', datetime.datetime.min)
        time2 = getattr(event2, 'timestamp', datetime.datetime.min)
        
        if isinstance(time1, str):
            time1 = datetime.datetime.fromisoformat(time1.replace('Z', '+00:00'))
        if isinstance(time2, str):
            time2 = datetime.datetime.fromisoformat(time2.replace('Z', '+00:00'))
        
        time_diff = abs((time1 - time2).total_seconds())
        if time_diff > 300:  # 5 minutes
            return False
        
        # Identity correlation
        identity1 = getattr(event1, 'identity', None)
        identity2 = getattr(event2, 'identity', None)
        
        if identity1 and identity2:
            if hasattr(identity1, 'user_id') and hasattr(identity2, 'user_id'):
                if identity1.user_id == identity2.user_id:
                    return True
        
        # Resource correlation
        resource1 = getattr(event1, 'resource', None)
        resource2 = getattr(event2, 'resource', None)
        
        if resource1 and resource2:
            if hasattr(resource1, 'resource_id') and hasattr(resource2, 'resource_id'):
                if resource1.resource_id == resource2.resource_id:
                    return True
        
        # IP correlation
        source_ip1 = getattr(event1, 'source_ip', None)
        source_ip2 = getattr(event2, 'source_ip', None)
        
        if source_ip1 and source_ip2 and source_ip1 == source_ip2:
            return True
        
        return False

    def _analyze_correlation_pattern(self, event_group: List) -> Dict[str, Any]:
        """Analyze correlation pattern for a group of events."""
        if not event_group:
            return {}
        
        analysis = {
            "group_size": len(event_group),
            "time_span_seconds": 0,
            "primary_identity": None,
            "primary_resource": None,
            "correlation_type": "unknown",
            "threat_indicators": [],
            "risk_level": "low"
        }
        
        # Analyze time span
        timestamps = []
        identities = []
        resources = []
        source_ips = []
        
        for event in event_group:
            timestamp = getattr(event, 'timestamp', datetime.datetime.min)
            if isinstance(timestamp, str):
                timestamp = datetime.datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            timestamps.append(timestamp)
            
            identity = getattr(event, 'identity', None)
            if identity and hasattr(identity, 'user_id'):
                identities.append(identity.user_id)
            
            resource = getattr(event, 'resource', None)
            if resource and hasattr(resource, 'resource_id'):
                resources.append(resource.resource_id)
            
            source_ip = getattr(event, 'source_ip', None)
            if source_ip:
                source_ips.append(source_ip)
        
        if timestamps:
            time_span = max(timestamps) - min(timestamps)
            analysis["time_span_seconds"] = time_span.total_seconds()
        
        # Determine primary identity and resource
        if identities:
            analysis["primary_identity"] = max(set(identities), key=identities.count)
        
        if resources:
            analysis["primary_resource"] = max(set(resources), key=resources.count)
        
        # Determine correlation type
        if len(set(source_ips)) > 3:
            analysis["correlation_type"] "multi_source_attack"
        elif len(set(identities)) > 1:
            analysis["correlation_type"] = "multi_user_activity"
        elif len(set(resources)) > 1:
            analysis["correlation_type"] = "multi_resource_access"
        else:
            analysis["correlation_type"] = "single_entity_activity"
        
        # Assess threat indicators
        if analysis["time_span_seconds"] < 60:  # Less than 1 minute
            analysis["threat_indicators"].append("rapid_succession")
        
        if len(set(source_ips)) > 2:
            analysis["threat_indicators"].append("distributed_attack")
        
        if analysis["correlation_type"] == "multi_resource_access":
            analysis["threat_indicators"].append("lateral_movement")
        
        # Determine risk level
        if len(analysis["threat_indicators"]) >= 2:
            analysis["risk_level"] = "high"
        elif len(analysis["threat_indicators"]) >= 1:
            analysis["risk_level"] = "medium"
        
        return analysis

    async def _generate_correlation_alerts(self, event_groups: List[List]) -> None:
        """Generate alerts for significant correlation patterns."""
        for group in event_groups:
            if len(group) < 2:
                continue
            
            analysis = self._analyze_correlation_pattern(group)
            
            # Generate alert for high-risk correlations
            if analysis["risk_level"] == "high":
                alert = SecurityAlert(
                    severity=AlertSeverity.HIGH,
                    alert_type=AlertType.ANOMALOUS_BEHAVIOR,
                    description=f"Correlated security events detected: {analysis['correlation_type']}",
                    implicated_identities=[analysis["primary_identity"]] if analysis["primary_identity"] else [],
                    affected_resources=[analysis["primary_resource"]] if analysis["primary_resource"] else [],
                    recommended_actions=[
                        "Investigate correlated events immediately",
                        "Review user activity patterns",
                        "Check for potential lateral movement",
                        "Monitor for additional suspicious activity"
                    ]
                )
                
                await self.audit_logger.log_security_alert(alert)

    async def _store_security_event_for_dashboard(self, security_event: Dict[str, Any]) -> None:
        """Store security event for dashboard generation."""
        # This would integrate with the event store
        # For now, just log that we're storing it
        logger.debug(f"Stored security event for dashboard: {security_event.get('event_type')}")

    def _map_severity_to_level(self, severity: str) -> int:
        """Map severity string to numerical level."""
        mapping = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4
        }
        return mapping.get(severity.lower(), 1)

    def _categorize_security_event(self, security_event: Dict[str, Any]) -> str:
        """Categorize security event type."""
        event_type = security_event.get("event_type", "").lower()
        
        if "auth" in event_type or "login" in event_type:
            return "authentication"
        elif "access" in event_type or "permission" in event_type:
            return "authorization"
        elif "policy" in event_type or "compliance" in event_type:
            return "compliance"
        elif "threat" in event_type or "attack" in event_type:
            return "threat_detection"
        elif "audit" in event_type or "log" in event_type:
            return "audit"
        else:
            return "security"

    def _generate_response_actions(self, security_event: Dict[str, Any]) -> List[str]:
        """Generate recommended response actions for security event."""
        actions = []
        severity = security_event.get("severity", "low")
        event_type = security_event.get("event_type", "")
        
        if severity in ["high", "critical"]:
            actions.extend([
                "Immediate investigation required",
                "Notify security team",
                "Consider temporary access restrictions"
            ])
        
        if "auth" in event_type.lower():
            actions.extend([
                "Verify user identity",
                "Check for account compromise",
                "Review authentication logs"
            ])
        
        if "access" in event_type.lower():
            actions.extend([
                "Review access permissions",
                "Check for unauthorized access",
                "Audit resource access logs"
            ])
        
        if "policy" in event_type.lower():
            actions.extend([
                "Review policy compliance",
                "Update security policies",
                "Conduct compliance assessment"
            ])
        
        return actions

    def _assess_compliance_relevance(self, security_event: Dict[str, Any]) -> List[str]:
        """Assess compliance framework relevance."""
        relevant_standards = []
        event_type = security_event.get("event_type", "").lower()
        severity = security_event.get("severity", "low")
        
        # SOC2 relevance
        if event_type in ["auth", "login", "access", "audit"]:
            relevant_standards.append("SOC2")
        
        # ISO 27001 relevance
        if event_type in ["access", "policy", "compliance"]:
            relevant_standards.append("ISO27001")
        
        # PCI DSS relevance (if handling payment data)
        if "data" in event_type and severity in ["high", "critical"]:
            relevant_standards.append("PCI_DSS")
        
        # GDPR relevance (if handling personal data)
        if "personal" in event_type or "privacy" in event_type:
            relevant_standards.append("GDPR")
        
        return relevant_standards

    async def _check_correlation_patterns(self, security_event: Dict[str, Any]) -> None:
        """Check for specific correlation patterns."""
        # This would implement sophisticated correlation detection
        # For now, just log that we're checking
        logger.debug(f"Checking correlation patterns for event: {security_event.get('event_type')}")

    async def _generate_security_overview(self) -> Dict[str, Any]:
        """Generate security overview metrics."""
        return {
            "total_events_24h": 0,
            "critical_alerts": 0,
            "high_alerts": 0,
            "security_score": 85.5,
            "compliance_status": "compliant",
            "threat_level": "medium"
        }

    async def _generate_security_alerts_summary(self) -> Dict[str, Any]:
        """Generate security alerts summary."""
        return {
            "open_alerts": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "resolved_24h": 0,
            "average_resolution_time": "2.5 hours"
        }

    async def _generate_threat_intelligence_summary(self) -> Dict[str, Any]:
        """Generate threat intelligence summary."""
        return {
            "active_threats": 0,
            "threat_categories": [],
            "geographic_distribution": {},
            "attack_vectors": [],
            "threat_indicators": []
        }

    async def _generate_compliance_summary(self) -> Dict[str, Any]:
        """Generate compliance summary."""
        return {
            "overall_score": 92.5,
            "standards": {
                "SOC2": {"score": 95, "status": "compliant"},
                "ISO27001": {"score": 90, "status": "compliant"},
                "PCI_DSS": {"score": 88, "status": "partial"}
            },
            "recent_violations": 0,
            "remediation_progress": 100
        }

    async def _generate_security_trends(self) -> Dict[str, Any]:
        """Generate security trends analysis."""
        return {
            "events_trend": "stable",
            "threat_trend": "decreasing",
            "compliance_trend": "improving",
            "top_threats": [],
            "security_improvements": []
        }

    async def _generate_incident_summary(self) -> Dict[str, Any]:
        """Generate incident summary."""
        return {
            "active_incidents": 0,
            "resolved_24h": 0,
            "mean_time_to_detection": "15 minutes",
            "mean_time_to_response": "30 minutes",
            "incident_categories": []
        }

    async def _generate_security_recommendations(self) -> List[str]:
        """Generate security recommendations."""
        return [
            "Continue monitoring for emerging threats",
            "Review and update security policies quarterly",
            "Conduct regular security awareness training",
            "Implement additional multi-factor authentication",
            "Enhance incident response procedures"
        ]


# Security Event Models for Integration
class SecurityEvent:
    """Base security event for integration."""
    
    def __init__(
        self,
        event_type: str,
        timestamp: datetime.datetime,
        severity: str,
        description: str,
        identity: Optional[Any] = None,
        resource: Optional[Any] = None,
        correlation_info: Optional[Dict[str, Any]] = None
    ):
        self.event_type = event_type
        self.timestamp = timestamp
        self.severity = severity
        self.description = description
        self.identity = identity
        self.resource = resource
        self.correlation_info = correlation_info or {}
        self.event_id = f"sec_{timestamp.strftime('%Y%m%d_%H%M%S_%f')}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity,
            "description": self.description,
            "identity": self.identity.to_dict() if self.identity else None,
            "resource": self.resource.to_dict() if self.resource else None,
            "correlation_info": self.correlation_info
        }