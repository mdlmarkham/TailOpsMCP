"""
TOON Document Templates for Standardized LLM-Facing Serialization

This module provides standardized TOON document templates for common use cases,
enabling consistent structure, token limits, and optimization strategies across
the TailOpsMCP system.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import logging

from src.integration.toon_enhanced import TOONDocument, ContentPriority, TOONVersion


logger = logging.getLogger(__name__)


class TemplateType(Enum):
    """Types of TOON document templates."""
    FLEET_OVERVIEW = "fleet_overview"
    OPERATION_RESULT = "operation_result"
    EVENTS_SUMMARY = "events_summary"
    HEALTH_REPORT = "health_report"
    POLICY_STATUS = "policy_status"
    SECURITY_ANALYSIS = "security_analysis"
    RESOURCE_UTILIZATION = "resource_utilization"
    ALERT_SUMMARY = "alert_summary"
    COMPLIANCE_REPORT = "compliance_report"
    PERFORMANCE_ANALYSIS = "performance_analysis"


@dataclass
class TOONSectionTemplate:
    """Template for a single document section."""
    
    name: str
    priority: ContentPriority
    max_tokens: int
    required: bool = True
    compression_strategy: Optional[str] = None
    fallback_content: Optional[str] = None
    validation_rules: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "priority": self.priority.value,
            "max_tokens": self.max_tokens,
            "required": self.required,
            "compression_strategy": self.compression_strategy,
            "fallback_content": self.fallback_content,
            "validation_rules": self.validation_rules
        }


@dataclass
class TOONTemplate:
    """Template for TOON documents with standardized structure and constraints."""
    
    template_type: TemplateType
    name: str
    description: str
    sections: List[TOONSectionTemplate]
    global_token_limit: int
    compression_enabled: bool = True
    smart_prioritization: bool = True
    quality_checks: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    
    def get_section(self, name: str) -> Optional[TOONSectionTemplate]:
        """Get a section template by name."""
        for section in self.sections:
            if section.name == name:
                return section
        return None
    
    def get_required_sections(self) -> List[TOONSectionTemplate]:
        """Get all required sections."""
        return [section for section in self.sections if section.required]
    
    def get_optional_sections(self) -> List[TOONSectionTemplate]:
        """Get all optional sections."""
        return [section for section in self.sections if not section.required]
    
    def calculate_max_content_size(self, available_sections: List[str]) -> int:
        """Calculate maximum content size based on available sections."""
        required_sections = self.get_required_sections()
        optional_sections = [s for s in self.get_optional_sections() if s.name in available_sections]
        
        total_max_tokens = sum(section.max_tokens for section in required_sections + optional_sections)
        return min(total_max_tokens, self.global_token_limit)
    
    def validate_content(self, content: Dict[str, Any]) -> List[str]:
        """Validate content against template requirements."""
        errors = []
        
        # Check required sections
        for section in self.get_required_sections():
            if section.name not in content:
                errors.append(f"Missing required section: {section.name}")
        
        # Check token limits
        for section_name, section_content in content.items():
            section_template = self.get_section(section_name)
            if section_template:
                estimated_tokens = self._estimate_tokens(section_content)
                if estimated_tokens > section_template.max_tokens:
                    errors.append(
                        f"Section '{section_name}' exceeds token limit: "
                        f"{estimated_tokens} > {section_template.max_tokens}"
                    )
        
        return errors
    
    def _estimate_tokens(self, content: Any) -> int:
        """Estimate token count for content."""
        if isinstance(content, str):
            return len(content.split()) + len([c for c in content if c in '.,;:!?'])
        elif isinstance(content, (dict, list)):
            json_str = json.dumps(content, separators=(",", ":"), ensure_ascii=False)
            return self._estimate_tokens(json_str)
        else:
            return self._estimate_tokens(str(content))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert template to dictionary representation."""
        return {
            "template_type": self.template_type.value,
            "name": self.name,
            "description": self.description,
            "sections": [section.to_dict() for section in self.sections],
            "global_token_limit": self.global_token_limit,
            "compression_enabled": self.compression_enabled,
            "smart_prioritization": self.smart_prioritization,
            "quality_checks": self.quality_checks,
            "tags": self.tags
        }


class TOONTemplates:
    """Registry and management of TOON document templates."""
    
    _templates: Dict[TemplateType, TOONTemplate] = {}
    _initialized = False
    
    @classmethod
    def initialize_templates(cls) -> None:
        """Initialize all standard templates."""
        if cls._initialized:
            return
        
        # Fleet Overview Template
        fleet_overview = TOONTemplate(
            template_type=TemplateType.FLEET_OVERVIEW,
            name="Fleet Overview Summary",
            description="Comprehensive fleet status overview for LLM consumption",
            sections=[
                TOONSectionTemplate(
                    name="fleet_summary",
                    priority=ContentPriority.CRITICAL,
                    max_tokens=200,
                    compression_strategy="summary"
                ),
                TOONSectionTemplate(
                    name="health_status",
                    priority=ContentPriority.CRITICAL,
                    max_tokens=300,
                    compression_strategy="compact"
                ),
                TOONSectionTemplate(
                    name="active_issues",
                    priority=ContentPriority.CRITICAL,
                    max_tokens=400,
                    compression_strategy="priority_filter"
                ),
                TOONSectionTemplate(
                    name="recent_operations",
                    priority=ContentPriority.IMPORTANT,
                    max_tokens=500,
                    compression_strategy="recent_first"
                ),
                TOONSectionTemplate(
                    name="resource_utilization",
                    priority=ContentPriority.INFO,
                    max_tokens=300,
                    compression_strategy="aggregate"
                ),
                TOONSectionTemplate(
                    name="recommendations",
                    priority=ContentPriority.IMPORTANT,
                    max_tokens=200,
                    compression_strategy="actionable_only"
                ),
                TOONSectionTemplate(
                    name="metadata",
                    priority=ContentPriority.DEBUG,
                    max_tokens=100,
                    required=False
                )
            ],
            global_token_limit=3000,
            tags=["fleet", "overview", "status"],
            quality_checks=[
                "check_required_sections",
                "validate_token_limits",
                "ensure_health_score_present",
                "verify_recommendations_format"
            ]
        )
        
        # Operation Result Template
        operation_result = TOONTemplate(
            template_type=TemplateType.OPERATION_RESULT,
            name="Operation Result Summary",
            description="Structured operation result for LLM analysis",
            sections=[
                TOONSectionTemplate(
                    name="operation_summary",
                    priority=ContentPriority.CRITICAL,
                    max_tokens=100,
                    compression_strategy="essential_only"
                ),
                TOONSectionTemplate(
                    name="execution_details",
                    priority=ContentPriority.IMPORTANT,
                    max_tokens=200,
                    compression_strategy="key_metrics"
                ),
                TOONSectionTemplate(
                    name="results",
                    priority=ContentPriority.IMPORTANT,
                    max_tokens=300,
                    compression_strategy="structured_data"
                ),
                TOONSectionTemplate(
                    name="errors",
                    priority=ContentPriority.CRITICAL,
                    max_tokens=200,
                    compression_strategy="error_summary"
                ),
                TOONSectionTemplate(
                    name="next_steps",
                    priority=ContentPriority.IMPORTANT,
                    max_tokens=150,
                    compression_strategy="action_items"
                ),
                TOONSectionTemplate(
                    name="performance_metrics",
                    priority=ContentPriority.INFO,
                    max_tokens=100,
                    required=False,
                    compression_strategy="metrics_only"
                )
            ],
            global_token_limit=1000,
            tags=["operation", "result", "execution"],
            quality_checks=[
                "check_status_present",
                "validate_error_format",
                "ensure_actionable_next_steps"
            ]
        )
        
        # Events Summary Template
        events_summary = TOONTemplate(
            template_type=TemplateType.EVENTS_SUMMARY,
            name="Events Summary Analysis",
            description="Comprehensive events analysis with insights and trends",
            sections=[
                TOONSectionTemplate(
                    name="event_statistics",
                    priority=ContentPriority.IMPORTANT,
                    max_tokens=200,
                    compression_strategy="key_metrics"
                ),
                TOONSectionTemplate(
                    name="critical_events",
                    priority=ContentPriority.CRITICAL,
                    max_tokens=400,
                    compression_strategy="recent_first"
                ),
                TOONSectionTemplate(
                    name="event_trends",
                    priority=ContentPriority.IMPORTANT,
                    max_tokens=300,
                    compression_strategy="trend_summary"
                ),
                TOONSectionTemplate(
                    name="top_event_sources",
                    priority=ContentPriority.INFO,
                    max_tokens=200,
                    compression_strategy="top_sources"
                ),
                TOONSectionTemplate(
                    name="actionable_insights",
                    priority=ContentPriority.IMPORTANT,
                    max_tokens=250,
                    compression_strategy="insights_only"
                ),
                TOONSectionTemplate(
                    name="event_patterns",
                    priority=ContentPriority.INFO,
                    max_tokens=150,
                    required=False,
                    compression_strategy="pattern_summary"
                )
            ],
            global_token_limit=1500,
            tags=["events", "monitoring", "analysis"],
            quality_checks=[
                "check_critical_events_present",
                "validate_event_statistics",
                "ensure_insights_actionable"
            ]
        )
        
        # Health Report Template
        health_report = TOONTemplate(
            template_type=TemplateType.HEALTH_REPORT,
            name="System Health Report",
            description="Detailed health assessment with recommendations",
            sections=[
                TOONSectionTemplate(
                    name="overall_health",
                    priority=ContentPriority.CRITICAL,
                    max_tokens=150,
                    compression_strategy="score_focus"
                ),
                TOONSectionTemplate(
                    name="component_health",
                    priority=ContentPriority.IMPORTANT,
                    max_tokens=400,
                    compression_strategy="component_summary"
                ),
                TOONSectionTemplate(
                    name="critical_issues",
                    priority=ContentPriority.CRITICAL,
                    max_tokens=300,
                    compression_strategy="issue_priority"
                ),
                TOONSectionTemplate(
                    name="health_trends",
                    priority=ContentPriority.INFO,
                    max_tokens=200,
                    compression_strategy="trend_analysis"
                ),
                TOONSectionTemplate(
                    name="recommendations",
                    priority=ContentPriority.IMPORTANT,
                    max_tokens=250,
                    compression_strategy="actionable_recommendations"
                )
            ],
            global_token_limit=1300,
            tags=["health", "assessment", "monitoring"],
            quality_checks=[
                "check_health_score_present",
                "validate_component_data",
                "ensure_recommendations_prioritized"
            ]
        )
        
        # Security Analysis Template
        security_analysis = TOONTemplate(
            template_type=TemplateType.SECURITY_ANALYSIS,
            name="Security Analysis Report",
            description="Comprehensive security assessment and threat analysis",
            sections=[
                TOONSectionTemplate(
                    name="security_summary",
                    priority=ContentPriority.CRITICAL,
                    max_tokens=200,
                    compression_strategy="threat_level_focus"
                ),
                TOONSectionTemplate(
                    name="high_priority_events",
                    priority=ContentPriority.CRITICAL,
                    max_tokens=400,
                    compression_strategy="threat_priority"
                ),
                TOONSectionTemplate(
                    name="security_recommendations",
                    priority=ContentPriority.IMPORTANT,
                    max_tokens=300,
                    compression_strategy="security_actions"
                ),
                TOONSectionTemplate(
                    name="threat_indicators",
                    priority=ContentPriority.IMPORTANT,
                    max_tokens=250,
                    compression_strategy="indicator_summary"
                ),
                TOONSectionTemplate(
                    name="compliance_status",
                    priority=ContentPriority.INFO,
                    max_tokens=200,
                    required=False,
                    compression_strategy="compliance_summary"
                )
            ],
            global_token_limit=1350,
            tags=["security", "threats", "analysis"],
            quality_checks=[
                "check_threat_level_assessment",
                "validate_security_events",
                "ensure_recommendations_prioritized"
            ]
        )
        
        # Register templates
        cls._templates[fleet_overview.template_type] = fleet_overview
        cls._templates[operation_result.template_type] = operation_result
        cls._templates[events_summary.template_type] = events_summary
        cls._templates[health_report.template_type] = health_report
        cls._templates[security_analysis.template_type] = security_analysis
        
        cls._initialized = True
    
    @classmethod
    def get_template(cls, template_type: TemplateType) -> Optional[TOONTemplate]:
        """Get template by type."""
        if not cls._initialized:
            cls.initialize_templates()
        return cls._templates.get(template_type)
    
    @classmethod
    def get_all_templates(cls) -> Dict[TemplateType, TOONTemplate]:
        """Get all registered templates."""
        if not cls._initialized:
            cls.initialize_templates()
        return cls._templates.copy()
    
    @classmethod
    def create_custom_template(
        cls,
        template_type: TemplateType,
        name: str,
        description: str,
        sections: List[TOONSectionTemplate],
        global_token_limit: int,
        **kwargs
    ) -> TOONTemplate:
        """Create a custom template."""
        template = TOONTemplate(
            template_type=template_type,
            name=name,
            description=description,
            sections=sections,
            global_token_limit=global_token_limit,
            **kwargs
        )
        cls._templates[template_type] = template
        return template
    
    @classmethod
    def validate_template(cls, template: TOONTemplate) -> List[str]:
        """Validate a template configuration."""
        errors = []
        
        # Check required fields
        if not template.name:
            errors.append("Template name is required")
        
        if not template.sections:
            errors.append("Template must have at least one section")
        
        # Check token limits
        total_max_tokens = sum(section.max_tokens for section in template.sections)
        if total_max_tokens > template.global_token_limit:
            errors.append(
                f"Total section token limits ({total_max_tokens}) exceed global limit ({template.global_token_limit})"
            )
        
        # Check for duplicate section names
        section_names = [section.name for section in template.sections]
        if len(section_names) != len(set(section_names)):
            errors.append("Duplicate section names found")
        
        # Validate section priorities
        valid_priorities = {p.value for p in ContentPriority}
        for section in template.sections:
            if section.priority.value not in valid_priorities:
                errors.append(f"Invalid priority for section '{section.name}': {section.priority.value}")
        
        return errors
    
    @classmethod
    def optimize_content_for_template(
        cls,
        content: Dict[str, Any],
        template: TOONTemplate,
        available_token_budget: Optional[int] = None
    ) -> Dict[str, Any]:
        """Optimize content to fit template constraints."""
        optimized = {}
        remaining_budget = available_token_budget or template.global_token_limit
        
        # Sort sections by priority
        sorted_sections = sorted(
            template.sections,
            key=lambda s: s.priority.value
        )
        
        for section_template in sorted_sections:
            if section_template.name in content:
                section_content = content[section_template.name]
                estimated_tokens = cls._estimate_content_tokens(section_content)
                
                # Check if we can fit this section
                if estimated_tokens <= remaining_budget:
                    optimized[section_template.name] = section_content
                    remaining_budget -= estimated_tokens
                else:
                    # Apply compression strategy
                    compressed_content = cls._apply_compression_strategy(
                        section_content,
                        section_template,
                        remaining_budget
                    )
                    if compressed_content is not None:
                        optimized[section_template.name] = compressed_content
                        remaining_budget = 0  # Budget exhausted
                    break  # No more budget for lower priority content
        
        return optimized
    
    @classmethod
    def _estimate_content_tokens(cls, content: Any) -> int:
        """Estimate tokens in content."""
        if isinstance(content, str):
            return len(content.split()) + len([c for c in content if c in '.,;:!?'])
        elif isinstance(content, (dict, list)):
            json_str = json.dumps(content, separators=(",", ":"), ensure_ascii=False)
            return cls._estimate_content_tokens(json_str)
        else:
            return cls._estimate_content_tokens(str(content))
    
    @classmethod
    def _apply_compression_strategy(
        cls,
        content: Any,
        section_template: TOONSectionTemplate,
        max_tokens: int
    ) -> Optional[Any]:
        """Apply compression strategy to fit token budget."""
        strategy = section_template.compression_strategy
        
        if strategy == "summary":
            return cls._create_summary(content, max_tokens)
        elif strategy == "priority_filter":
            return cls._filter_by_priority(content, max_tokens)
        elif strategy == "recent_first":
            return cls._prioritize_recent(content, max_tokens)
        elif strategy == "aggregate":
            return cls._create_aggregated_view(content, max_tokens)
        elif strategy == "actionable_only":
            return cls._extract_actionable_items(content, max_tokens)
        elif strategy == "error_summary":
            return cls._summarize_errors(content, max_tokens)
        else:
            # Default: truncate content
            return cls._truncate_content(content, max_tokens)
    
    @classmethod
    def _create_summary(cls, content: Any, max_tokens: int) -> Any:
        """Create a summary of content."""
        if isinstance(content, list):
            # Keep first few items with summary
            return content[:max_tokens // 10]  # Rough approximation
        elif isinstance(content, dict):
            # Keep essential key-value pairs
            return {k: v for i, (k, v) in enumerate(content.items()) if i < max_tokens // 20}
        return str(content)[:max_tokens * 5]  # Rough character limit
    
    @classmethod
    def _filter_by_priority(cls, content: Any, max_tokens: int) -> Any:
        """Filter content by priority."""
        # Assume content has priority information
        if isinstance(content, list):
            # Sort by some priority field and keep top items
            return content[:max_tokens // 10]
        return content
    
    @classmethod
    def _prioritize_recent(cls, content: Any, max_tokens: int) -> Any:
        """Prioritize recent items."""
        if isinstance(content, list):
            # Keep recent items
            return content[-max_tokens // 10:]
        return content
    
    @classmethod
    def _create_aggregated_view(cls, content: Any, max_tokens: int) -> Any:
        """Create aggregated view of content."""
        if isinstance(content, dict):
            # Create summary statistics
            return {
                "total_items": len(content),
                "summary": "Aggregated view - see detailed data in source"
            }
        return content
    
    @classmethod
    def _extract_actionable_items(cls, content: Any, max_tokens: int) -> Any:
        """Extract actionable items from content."""
        if isinstance(content, list):
            # Filter for actionable items
            actionable = [item for item in content if isinstance(item, dict) and item.get("actionable", False)]
            return actionable[:max_tokens // 10] if actionable else content[:max_tokens // 10]
        return content
    
    @classmethod
    def _summarize_errors(cls, content: Any, max_tokens: int) -> Any:
        """Summarize error information."""
        if isinstance(content, list):
            # Keep error summaries
            return content[:max_tokens // 10]
        return content
    
    @classmethod
    def _truncate_content(cls, content: Any, max_tokens: int) -> Any:
        """Truncate content to fit token budget."""
        if isinstance(content, str):
            return content[:max_tokens * 5]  # Rough character approximation
        elif isinstance(content, list):
            return content[:max_tokens // 10]
        elif isinstance(content, dict):
            return dict(list(content.items())[:max_tokens // 20])
        return str(content)[:max_tokens * 5]


# Convenience functions for common templates
def get_fleet_overview_template() -> TOONTemplate:
    """Get the fleet overview template."""
    return TOONTemplates.get_template(TemplateType.FLEET_OVERVIEW)


def get_operation_result_template() -> TOONTemplate:
    """Get the operation result template."""
    return TOONTemplates.get_template(TemplateType.OPERATION_RESULT)


def get_events_summary_template() -> TOONTemplate:
    """Get the events summary template."""
    return TOONTemplates.get_template(TemplateType.EVENTS_SUMMARY)


def get_health_report_template() -> TOONTemplate:
    """Get the health report template."""
    return TOONTemplates.get_template(TemplateType.HEALTH_REPORT)


def get_security_analysis_template() -> TOONTemplate:
    """Get the security analysis template."""
    return TOONTemplates.get_template(TemplateType.SECURITY_ANALYSIS)


def create_optimized_document(
    content: Dict[str, Any],
    template_type: TemplateType,
    token_budget: Optional[int] = None
) -> TOONDocument:
    """Create an optimized TOON document using a template."""
    template = TOONTemplates.get_template(template_type)
    if not template:
        raise ValueError(f"Template not found: {template_type}")
    
    # Optimize content for template
    optimized_content = TOONTemplates.optimize_content_for_template(
        content, template, token_budget
    )
    
    # Create document
    doc = TOONDocument(
        document_type=template_type.value,
        metadata={
            "template_name": template.name,
            "template_version": "1.0",
            "optimization_applied": True
        }
    )
    
    # Add sections to document
    for section_name, section_content in optimized_content.items():
        section_template = template.get_section(section_name)
        if section_template:
            doc.add_section(section_name, section_content, section_template.priority)
    
    return doc


def validate_document_against_template(
    document: TOONDocument,
    template: TOONTemplate
) -> List[str]:
    """Validate a TOON document against a template."""
    # Convert document sections to dict
    content = document.sections
    
    # Validate using template
    errors = template.validate_content(content)
    
    # Additional document-specific validation
    if document.token_estimate > template.global_token_limit:
        errors.append(f"Document exceeds global token limit: {document.token_estimate} > {template.global_token_limit}")
    
    # Check required sections are present
    required_sections = template.get_required_sections()
    for section_template in required_sections:
        if section_template.name not in document.sections:
            errors.append(f"Missing required section: {section_template.name}")
    
    return errors