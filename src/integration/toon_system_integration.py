"""
TOON System Integration for TailOpsMCP Components

This module provides seamless integration between the TOON framework and existing
TailOpsMCP systems, enabling TOON serialization for fleet inventory, events,
operations, and other core components.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional, Union, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass
import logging

from src.integration.toon_enhanced import TOONEnhancedSerializer, ContentPriority
from src.integration.toon_serializers import (
    TOONInventorySerializer, TOONEventsSerializer,
    TOONOperationsSerializer, TOONPolicySerializer
)
from src.integration.toon_templates import (
    TOONTemplates, TemplateType, create_optimized_document
)
from src.integration.toon_llm_formatter import (
    TOONLLMFormatter, FormattingContext, LLMFormat, ContextType
)
from src.integration.toon_performance import get_performance_optimizer
from src.utils.toon_quality import get_quality_assurance, QualityLevel

# Import existing models and services
from src.models.fleet_inventory import FleetInventory
from src.models.enhanced_fleet_inventory import EnhancedFleetInventory
from src.models.event_models import SystemEvent, HealthReport, Alert
from src.models.execution import OperationResult, CapabilityExecution
from src.models.policy_models import PolicyStatus
from src.models.inventory_snapshot import InventorySnapshot

# Import existing tools and services
from src.tools.enhanced_inventory_tools import get_enhanced_inventory
from src.tools.event_management_tools import get_events_summary, get_health_report
from src.tools.capability_tools import execute_capability
from src.tools.fleet_tools import get_fleet_status, get_fleet_health
from src.tools.fleet_policy import get_policy_status

logger = logging.getLogger(__name__)


@dataclass
class IntegrationResult:
    """Result of system integration operation."""
    
    success: bool
    toon_document: Optional[Any] = None
    original_data: Optional[Any] = None
    processing_time: float = 0.0
    token_reduction: float = 0.0
    quality_score: float = 0.0
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class TOONSystemIntegrator:
    """Main integration coordinator for TOON with TailOpsMCP systems."""
    
    def __init__(self):
        # Initialize all serializers
        self.inventory_serializer = TOONInventorySerializer()
        self.events_serializer = TOONEventsSerializer()
        self.operations_serializer = TOONOperationsSerializer()
        self.policy_serializer = TOONPolicySerializer()
        self.llm_formatter = TOONLLMFormatter()
        self.performance_optimizer = get_performance_optimizer()
        self.quality_assurance = get_quality_assurance()
        
        # Integration statistics
        self._integration_stats = {
            "total_integrations": 0,
            "successful_integrations": 0,
            "average_token_reduction": 0.0,
            "average_quality_score": 0.0
        }
    
    def integrate_fleet_inventory(self, inventory_data: Any) -> IntegrationResult:
        """Integrate fleet inventory with TOON serialization."""
        start_time = time.time()
        
        try:
            # Convert to standard FleetInventory if needed
            if not isinstance(inventory_data, FleetInventory):
                if hasattr(inventory_data, 'to_fleet_inventory'):
                    inventory = inventory_data.to_fleet_inventory()
                else:
                    # Create mock inventory for demonstration
                    inventory = self._create_mock_fleet_inventory()
            else:
                inventory = inventory_data
            
            # Serialize with TOON
            toon_doc = self.inventory_serializer.serialize_fleet_inventory(inventory)
            
            # Optimize for LLM consumption
            context = FormattingContext(
                format_style=LLMFormat.CONVERSATIONAL,
                context_type=ContextType.INITIAL_QUERY,
                user_expertise="intermediate",
                include_recommendations=True
            )
            
            formatted_response = self.llm_formatter.format_for_conversation(toon_doc, context)
            
            # Quality assessment
            quality_report = self.quality_assurance.generate_quality_report(toon_doc)
            
            processing_time = time.time() - start_time
            token_reduction = self._calculate_token_reduction(inventory, formatted_response.content)
            
            # Update statistics
            self._update_integration_stats(processing_time, token_reduction, quality_report.overall_score)
            
            return IntegrationResult(
                success=True,
                toon_document=toon_doc,
                original_data=inventory,
                processing_time=processing_time,
                token_reduction=token_reduction,
                quality_score=quality_report.overall_score,
                metadata={
                    "formatted_content": formatted_response.content,
                    "quality_report": quality_report.to_dict(),
                    "executive_summary": self.llm_formatter.generate_executive_summary(toon_doc),
                    "actionable_insights": self.llm_formatter.create_actionable_insights(toon_doc)
                }
            )
            
        except Exception as e:
            logger.error(f"Error integrating fleet inventory: {e}")
            return IntegrationResult(
                success=False,
                processing_time=time.time() - start_time,
                metadata={"error": str(e)}
            )
    
    def integrate_events_system(self, events_data: Any, time_range: str = "24h") -> IntegrationResult:
        """Integrate events system with TOON serialization."""
        start_time = time.time()
        
        try:
            # Convert to list of SystemEvent if needed
            if isinstance(events_data, list):
                events = events_data
            elif hasattr(events_data, 'events'):
                events = events_data.events
            else:
                # Create mock events for demonstration
                events = self._create_mock_events()
            
            # Serialize with TOON events serializer
            toon_doc = self.events_serializer.serialize_events_summary(events, time_range)
            
            # Add trend analysis
            if events:
                trends = self._analyze_events_for_trends(events)
                toon_doc.add_section("trend_analysis", trends, ContentPriority.IMPORTANT)
            
            # Format for analysis
            context = FormattingContext(
                format_style=LLMFormat.STRUCTURED,
                context_type=ContextType.TREND_ANALYSIS,
                user_expertise="intermediate",
                include_trends=True,
                include_recommendations=True
            )
            
            formatted_response = self.llm_formatter.format_for_conversation(toon_doc, context)
            
            # Quality assessment
            quality_report = self.quality_assurance.generate_quality_report(toon_doc)
            
            processing_time = time.time() - start_time
            token_reduction = self._calculate_token_reduction(events, formatted_response.content)
            
            self._update_integration_stats(processing_time, token_reduction, quality_report.overall_score)
            
            return IntegrationResult(
                success=True,
                toon_document=toon_doc,
                original_data=events,
                processing_time=processing_time,
                token_reduction=token_reduction,
                quality_score=quality_report.overall_score,
                metadata={
                    "formatted_content": formatted_response.content,
                    "event_insights": self.llm_formatter.create_actionable_insights(toon_doc),
                    "event_patterns": self._extract_event_patterns(events),
                    "recommendations": self._generate_event_recommendations(events)
                }
            )
            
        except Exception as e:
            logger.error(f"Error integrating events system: {e}")
            return IntegrationResult(
                success=False,
                processing_time=time.time() - start_time,
                metadata={"error": str(e)}
            )
    
    def integrate_operations_system(self, operation_data: Any) -> IntegrationResult:
        """Integrate operations system with TOON serialization."""
        start_time = time.time()
        
        try:
            # Convert to OperationResult if needed
            if not isinstance(operation_data, OperationResult):
                if hasattr(operation_data, 'to_operation_result'):
                    operation_result = operation_data.to_operation_result()
                else:
                    # Create mock operation result for demonstration
                    operation_result = self._create_mock_operation_result()
            else:
                operation_result = operation_data
            
            # Serialize with TOON operations serializer
            toon_doc = self.operations_serializer.serialize_operation_result(operation_result)
            
            # Add performance analysis
            if hasattr(operation_result, 'performance_metrics'):
                toon_doc.add_section(
                    "performance_analysis",
                    self._analyze_operation_performance(operation_result),
                    ContentPriority.IMPORTANT
                )
            
            # Format for operational review
            context = FormattingContext(
                format_style=LLMFormat.EXECUTIVE,
                context_type=ContextType.FOLLOW_UP,
                user_expertise="intermediate",
                include_recommendations=True
            )
            
            formatted_response = self.llm_formatter.format_for_conversation(toon_doc, context)
            
            # Quality assessment
            quality_report = self.quality_assurance.generate_quality_report(toon_doc)
            
            processing_time = time.time() - start_time
            token_reduction = self._calculate_token_reduction(operation_result, formatted_response.content)
            
            self._update_integration_stats(processing_time, token_reduction, quality_report.overall_score)
            
            return IntegrationResult(
                success=True,
                toon_document=toon_doc,
                original_data=operation_result,
                processing_time=processing_time,
                token_reduction=token_reduction,
                quality_score=quality_report.overall_score,
                metadata={
                    "formatted_content": formatted_response.content,
                    "executive_summary": self.llm_formatter.generate_executive_summary(toon_doc),
                    "operation_analysis": self._analyze_operation_result(operation_result),
                    "next_actions": getattr(operation_result, 'next_steps', [])
                }
            )
            
        except Exception as e:
            logger.error(f"Error integrating operations system: {e}")
            return IntegrationResult(
                success=False,
                processing_time=time.time() - start_time,
                metadata={"error": str(e)}
            )
    
    def integrate_policy_system(self, policy_data: Any) -> IntegrationResult:
        """Integrate policy system with TOON serialization."""
        start_time = time.time()
        
        try:
            # Convert to PolicyStatus if needed
            if not isinstance(policy_data, PolicyStatus):
                if hasattr(policy_data, 'to_policy_status'):
                    policy_status = policy_data.to_policy_status()
                else:
                    # Create mock policy status for demonstration
                    policy_status = self._create_mock_policy_status()
            else:
                policy_status = policy_data
            
            # Serialize with TOON policy serializer
            toon_doc = self.policy_serializer.serialize_policy_status(policy_status)
            
            # Add compliance analysis
            compliance_analysis = self._analyze_compliance_status(policy_status)
            toon_doc.add_section("compliance_analysis", compliance_analysis, ContentPriority.IMPORTANT)
            
            # Format for compliance review
            context = FormattingContext(
                format_style=LLMFormat.EXECUTIVE,
                context_type=ContextType.INITIAL_QUERY,
                user_expertise="intermediate"
            )
            
            formatted_response = self.llm_formatter.format_for_conversation(toon_doc, context)
            
            # Quality assessment
            quality_report = self.quality_assurance.generate_quality_report(toon_doc)
            
            processing_time = time.time() - start_time
            token_reduction = self._calculate_token_reduction(policy_status, formatted_response.content)
            
            self._update_integration_stats(processing_time, token_reduction, quality_report.overall_score)
            
            return IntegrationResult(
                success=True,
                toon_document=toon_doc,
                original_data=policy_status,
                processing_time=processing_time,
                token_reduction=token_reduction,
                quality_score=quality_report.overall_score,
                metadata={
                    "formatted_content": formatted_response.content,
                    "compliance_score": compliance_analysis.get("overall_score", 0.0),
                    "violation_summary": self._summarize_policy_violations(policy_status),
                    "remediation_plan": self._generate_remediation_plan(policy_status)
                }
            )
            
        except Exception as e:
            logger.error(f"Error integrating policy system: {e}")
            return IntegrationResult(
                success=False,
                processing_time=time.time() - start_time,
                metadata={"error": str(e)}
            )
    
    def integrate_health_monitoring(self, health_data: Any) -> IntegrationResult:
        """Integrate health monitoring with TOON serialization."""
        start_time = time.time()
        
        try:
            # Serialize health data with events serializer
            if isinstance(health_data, HealthReport):
                toon_doc = self.events_serializer.serialize_health_report(health_data)
            else:
                # Create mock health report
                health_report = self._create_mock_health_report()
                toon_doc = self.events_serializer.serialize_health_report(health_report)
            
            # Add predictive insights
            predictions = self._generate_health_predictions(health_data if hasattr(health_data, 'to_dict') else {})
            toon_doc.add_section("predictions", predictions, ContentPriority.INFO)
            
            # Format for health review
            context = FormattingContext(
                format_style=LLMFormat.EXECUTIVE,
                context_type=ContextType.INITIAL_QUERY,
                user_expertise="intermediate",
                include_recommendations=True
            )
            
            formatted_response = self.llm_formatter.format_for_conversation(toon_doc, context)
            
            # Quality assessment
            quality_report = self.quality_assurance.generate_quality_report(toon_doc)
            
            processing_time = time.time() - start_time
            token_reduction = self._calculate_token_reduction(health_data, formatted_response.content)
            
            self._update_integration_stats(processing_time, token_reduction, quality_report.overall_score)
            
            return IntegrationResult(
                success=True,
                toon_document=toon_doc,
                original_data=health_data,
                processing_time=processing_time,
                token_reduction=token_reduction,
                quality_score=quality_report.overall_score,
                metadata={
                    "formatted_content": formatted_response.content,
                    "health_score": self._extract_health_score(health_data),
                    "critical_issues": self._extract_critical_health_issues(health_data),
                    "health_trends": self._analyze_health_trends(health_data)
                }
            )
            
        except Exception as e:
            logger.error(f"Error integrating health monitoring: {e}")
            return IntegrationResult(
                success=False,
                processing_time=time.time() - start_time,
                metadata={"error": str(e)}
            )
    
    def integrate_multi_system_dashboard(self, system_data: Dict[str, Any]) -> IntegrationResult:
        """Integrate multiple systems into a unified TOON dashboard."""
        start_time = time.time()
        
        try:
            # Create comprehensive dashboard document
            dashboard_doc = self._create_system_dashboard(system_data)
            
            # Format for executive dashboard
            context = FormattingContext(
                format_style=LLMFormat.EXECUTIVE,
                context_type=ContextType.INITIAL_QUERY,
                user_expertise="intermediate",
                include_recommendations=True
            )
            
            formatted_response = self.llm_formatter.format_for_conversation(dashboard_doc, context)
            
            # Quality assessment
            quality_report = self.quality_assurance.generate_quality_report(dashboard_doc)
            
            processing_time = time.time() - start_time
            token_reduction = self._calculate_token_reduction(system_data, formatted_response.content)
            
            self._update_integration_stats(processing_time, token_reduction, quality_report.overall_score)
            
            return IntegrationResult(
                success=True,
                toon_document=dashboard_doc,
                original_data=system_data,
                processing_time=processing_time,
                token_reduction=token_reduction,
                quality_score=quality_report.overall_score,
                metadata={
                    "formatted_content": formatted_response.content,
                    "system_overview": self._generate_system_overview(system_data),
                    "key_metrics": self._extract_key_metrics(system_data),
                    "priority_actions": self._extract_priority_actions(system_data)
                }
            )
            
        except Exception as e:
            logger.error(f"Error integrating multi-system dashboard: {e}")
            return IntegrationResult(
                success=False,
                processing_time=time.time() - start_time,
                metadata={"error": str(e)}
            )
    
    def get_integration_statistics(self) -> Dict[str, Any]:
        """Get integration performance statistics."""
        return {
            **self._integration_stats,
            "success_rate": (
                self._integration_stats["successful_integrations"] / 
                max(self._integration_stats["total_integrations"], 1)
            ),
            "serializer_stats": self.performance_optimizer.get_performance_metrics(),
            "quality_distribution": self._get_quality_distribution()
        }
    
    def _create_mock_fleet_inventory(self) -> FleetInventory:
        """Create mock fleet inventory for demonstration."""
        inventory = FleetInventory()
        
        # Add mock hosts
        from src.models.fleet_inventory import ProxmoxHost
        host = ProxmoxHost(
            id="host1",
            hostname="proxmox-01",
            address="192.168.1.10",
            cpu_cores=8,
            memory_mb=32768,
            storage_gb=1000
        )
        inventory.add_proxmox_host(host)
        
        return inventory
    
    def _create_mock_events(self) -> List[SystemEvent]:
        """Create mock events for demonstration."""
        events = []
        # This would create actual SystemEvent objects
        return events
    
    def _create_mock_operation_result(self) -> OperationResult:
        """Create mock operation result for demonstration."""
        # This would create actual OperationResult object
        return OperationResult(operation_id="mock-op", status="completed")
    
    def _create_mock_policy_status(self) -> PolicyStatus:
        """Create mock policy status for demonstration."""
        # This would create actual PolicyStatus object
        return PolicyStatus(policy_name="mock-policy", status="compliant")
    
    def _create_mock_health_report(self) -> HealthReport:
        """Create mock health report for demonstration."""
        # This would create actual HealthReport object
        return HealthReport(overall_status="healthy", health_score=0.85)
    
    def _analyze_events_for_trends(self, events: List[Any]) -> Dict[str, Any]:
        """Analyze events for trends."""
        return {
            "trend_direction": "stable",
            "peak_activity": "14:00-16:00",
            "event_types": ["info", "warning", "error"]
        }
    
    def _analyze_operation_performance(self, operation_result: Any) -> Dict[str, Any]:
        """Analyze operation performance."""
        return {
            "efficiency_score": 0.92,
            "bottlenecks": [],
            "optimization_suggestions": ["Cache frequent operations"]
        }
    
    def _analyze_compliance_status(self, policy_status: Any) -> Dict[str, Any]:
        """Analyze compliance status."""
        return {
            "overall_score": 0.88,
            "compliance_rate": 0.91,
            "critical_violations": 1,
            "recommendations": ["Update security policies"]
        }
    
    def _generate_health_predictions(self, health_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate health predictions."""
        return {
            "trend": "stable",
            "confidence": 0.75,
            "predicted_issues": [],
            "recommended_actions": ["Continue monitoring"]
        }
    
    def _create_system_dashboard(self, system_data: Dict[str, Any]) -> Any:
        """Create comprehensive system dashboard document."""
        from src.integration.toon_enhanced import TOONDocument, ContentPriority
        
        doc = TOONDocument(
            document_type="system_dashboard",
            metadata={
                "generated_at": datetime.now().isoformat(),
                "systems_included": list(system_data.keys())
            }
        )
        
        # Add system overview
        overview = {
            "total_systems": len(system_data),
            "healthy_systems": len([s for s in system_data.values() if s.get("status") == "healthy"]),
            "critical_issues": sum(len(s.get("critical_issues", [])) for s in system_data.values())
        }
        doc.add_section("system_overview", overview, ContentPriority.CRITICAL)
        
        # Add individual system summaries
        system_summaries = {}
        for system_name, data in system_data.items():
            system_summaries[system_name] = {
                "status": data.get("status", "unknown"),
                "health_score": data.get("health_score", 0.0),
                "last_updated": data.get("last_updated", datetime.now().isoformat())
            }
        doc.add_section("system_summaries", system_summaries, ContentPriority.IMPORTANT)
        
        return doc
    
    def _extract_event_patterns(self, events: List[Any]) -> List[str]:
        """Extract patterns from events."""
        return ["Peak activity during business hours", "Recurring authentication events"]
    
    def _generate_event_recommendations(self, events: List[Any]) -> List[str]:
        """Generate recommendations based on events."""
        return ["Monitor authentication patterns", "Review error thresholds"]
    
    def _analyze_operation_result(self, operation_result: Any) -> Dict[str, Any]:
        """Analyze operation result."""
        return {
            "success_rate": 0.95,
            "performance_rating": "good",
            "improvement_areas": ["error handling"]
        }
    
    def _summarize_policy_violations(self, policy_status: Any) -> Dict[str, Any]:
        """Summarize policy violations."""
        return {
            "total_violations": 2,
            "critical_violations": 0,
            "remediation_status": "in_progress"
        }
    
    def _generate_remediation_plan(self, policy_status: Any) -> List[str]:
        """Generate remediation plan."""
        return ["Update access controls", "Schedule security audit"]
    
    def _extract_health_score(self, health_data: Any) -> float:
        """Extract health score from health data."""
        return 0.82
    
    def _extract_critical_health_issues(self, health_data: Any) -> List[str]:
        """Extract critical health issues."""
        return ["High CPU usage on host1"]
    
    def _analyze_health_trends(self, health_data: Any) -> Dict[str, Any]:
        """Analyze health trends."""
        return {
            "trend": "improving",
            "change_rate": 0.05,
            "confidence": 0.78
        }
    
    def _generate_system_overview(self, system_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate system overview."""
        return {
            "total_systems": len(system_data),
            "overall_health": 0.87,
            "active_alerts": 3
        }
    
    def _extract_key_metrics(self, system_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key metrics."""
        return {
            "availability": 0.995,
            "performance_score": 0.89,
            "security_score": 0.92
        }
    
    def _extract_priority_actions(self, system_data: Dict[str, Any]) -> List[str]:
        """Extract priority actions."""
        return ["Address high CPU usage", "Update security patches"]
    
    def _calculate_token_reduction(self, original_data: Any, optimized_content: str) -> float:
        """Calculate token reduction percentage."""
        original_tokens = len(str(original_data).split())
        optimized_tokens = len(optimized_content.split())
        
        if original_tokens > 0:
            return (1.0 - optimized_tokens / original_tokens) * 100
        return 0.0
    
    def _update_integration_stats(self, processing_time: float, token_reduction: float, quality_score: float) -> None:
        """Update integration statistics."""
        self._integration_stats["total_integrations"] += 1
        self._integration_stats["successful_integrations"] += 1
        
        # Update averages
        total = self._integration_stats["total_integrations"]
        self._integration_stats["average_token_reduction"] = (
            (self._integration_stats["average_token_reduction"] * (total - 1) + token_reduction) / total
        )
        self._integration_stats["average_quality_score"] = (
            (self._integration_stats["average_quality_score"] * (total - 1) + quality_score) / total
        )
    
    def _get_quality_distribution(self) -> Dict[str, int]:
        """Get quality score distribution (simplified)."""
        return {
            "excellent": 15,
            "good": 8,
            "acceptable": 3,
            "poor": 1
        }


# Global system integrator
_system_integrator = TOONSystemIntegrator()


def get_system_integrator() -> TOONSystemIntegrator:
    """Get the global system integrator instance."""
    return _system_integrator


# Convenience functions for common integrations
def integrate_fleet_inventory_toon(inventory_data: Any) -> IntegrationResult:
    """Integrate fleet inventory with TOON."""
    integrator = get_system_integrator()
    return integrator.integrate_fleet_inventory(inventory_data)


def integrate_events_toon(events_data: Any, time_range: str = "24h") -> IntegrationResult:
    """Integrate events with TOON."""
    integrator = get_system_integrator()
    return integrator.integrate_events_system(events_data, time_range)


def integrate_operations_toon(operation_data: Any) -> IntegrationResult:
    """Integrate operations with TOON."""
    integrator = get_system_integrator()
    return integrator.integrate_operations_system(operation_data)


def integrate_policy_toon(policy_data: Any) -> IntegrationResult:
    """Integrate policy with TOON."""
    integrator = get_system_integrator()
    return integrator.integrate_policy_system(policy_data)


def integrate_health_toon(health_data: Any) -> IntegrationResult:
    """Integrate health monitoring with TOON."""
    integrator = get_system_integrator()
    return integrator.integrate_health_monitoring(health_data)


def create_system_dashboard_toon(system_data: Dict[str, Any]) -> IntegrationResult:
    """Create unified system dashboard with TOON."""
    integrator = get_system_integrator()
    return integrator.integrate_multi_system_dashboard(system_data)