"""
TOON LLM Formatter Module

This module provides advanced formatting capabilities for TOON documents,
optimizing them for LLM consumption through intelligent content organization,
context-aware summaries, and conversational formatting.

CONSOLIDATED: All LLM formatting and template functionality in one place.
- LLM formatting styles and context management
- Template system for different document types
- Executive summaries and actionable insights generation
- Conversational formatting optimization
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Union, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import logging

from .serializer import TOONDocument, ContentPriority, TOONVersion

logger = logging.getLogger(__name__)


# LLM Formatting Classes
class LLMFormat(Enum):
    """LLM formatting styles."""
    CONVERSATIONAL = "conversational"     # Natural language conversation style
    STRUCTURED = "structured"            # Technical documentation style
    EXECUTIVE = "executive"              # Executive summary style
    TECHNICAL = "technical"              # Detailed technical style
    ACTIONABLE = "actionable"            # Action-oriented format


class ContextType(Enum):
    """Types of conversational context."""
    INITIAL_QUERY = "initial_query"
    FOLLOW_UP = "follow_up"
    CLARIFICATION = "clarification"
    COMPARISON = "comparison"
    TREND_ANALYSIS = "trend_analysis"


@dataclass
class FormattingContext:
    """Context for LLM formatting decisions."""
    
    format_style: LLMFormat = LLMFormat.CONVERSATIONAL
    context_type: ContextType = ContextType.INITIAL_QUERY
    user_expertise: str = "intermediate"  # beginner, intermediate, expert
    max_tokens: int = 4000
    include_details: bool = True
    prioritize_critical: bool = True
    time_horizon: str = "current"  # current, short_term, long_term
    business_focus: bool = True
    action_orientation: bool = False


@dataclass
class FormattedResponse:
    """Response from LLM formatting operation."""
    
    content: str
    format_style: LLMFormat
    token_count: int
    sections_included: List[str]
    priority_applied: bool
    context_preserved: bool
    actionable_items: List[str]
    executive_summary: Optional[str] = None
    key_insights: List[str] = None
    
    def __post_init__(self):
        if self.key_insights is None:
            self.key_insights = []


# Template System (Enhanced from toon_templates.py)
class TemplateType(Enum):
    """Types of TOON document templates."""
    FLEET_OVERVIEW = "fleet_overview"
    OPERATION_RESULT = "operation_result"
    EVENTS_SUMMARY = "events_summary"
    POLICY_STATUS = "policy_status"
    HEALTH_REPORT = "health_report"
    SYSTEM_DASHBOARD = "system_dashboard"
    EXECUTIVE_SUMMARY = "executive_summary"


@dataclass
class TOONTemplate:
    """TOON document template with formatting rules."""
    
    name: str
    template_type: TemplateType
    structure: Dict[str, Any]
    formatting_rules: Dict[str, Any]
    priority_mapping: Dict[str, ContentPriority]
    max_tokens_per_section: Dict[str, int]
    include_sections: List[str]
    exclude_sections: List[str]


class TOONTemplates:
    """Template management system for TOON documents."""
    
    def __init__(self):
        self.templates = self._initialize_templates()
    
    def _initialize_templates(self) -> Dict[str, TOONTemplate]:
        """Initialize built-in templates."""
        templates = {}
        
        # Fleet Overview Template
        templates["fleet_overview"] = TOONTemplate(
            name="Fleet Overview",
            template_type=TemplateType.FLEET_OVERVIEW,
            structure={
                "summary": "Critical metrics and health status",
                "targets": "Target status and performance",
                "services": "Service overview and dependencies",
                "issues": "Critical issues and alerts",
                "recommendations": "Action items and next steps"
            },
            formatting_rules={
                "summary": {"style": "executive", "max_length": 200},
                "targets": {"style": "structured", "include_details": True},
                "issues": {"style": "actionable", "prioritize": True}
            },
            priority_mapping={
                "summary": ContentPriority.CRITICAL,
                "targets": ContentPriority.IMPORTANT,
                "services": ContentPriority.INFO,
                "issues": ContentPriority.CRITICAL,
                "recommendations": ContentPriority.IMPORTANT
            },
            max_tokens_per_section={
                "summary": 200,
                "targets": 1000,
                "services": 800,
                "issues": 600,
                "recommendations": 400
            },
            include_sections=["summary", "targets", "issues", "recommendations"],
            exclude_sections=["debug", "verbose"]
        )
        
        # Operation Result Template
        templates["operation_result"] = TOONTemplate(
            name="Operation Result",
            template_type=TemplateType.OPERATION_RESULT,
            structure={
                "result": "Operation outcome and status",
                "details": "Detailed results and data",
                "performance": "Performance metrics and timing",
                "recommendations": "Next steps and follow-up actions"
            },
            formatting_rules={
                "result": {"style": "conversational", "max_length": 150},
                "details": {"style": "technical", "include_metrics": True},
                "performance": {"style": "structured", "include_charts": False}
            },
            priority_mapping={
                "result": ContentPriority.CRITICAL,
                "details": ContentPriority.IMPORTANT,
                "performance": ContentPriority.INFO,
                "recommendations": ContentPriority.IMPORTANT
            },
            max_tokens_per_section={
                "result": 150,
                "details": 800,
                "performance": 300,
                "recommendations": 300
            },
            include_sections=["result", "details", "recommendations"],
            exclude_sections=["debug"]
        )
        
        # Events Summary Template
        templates["events_summary"] = TOONTemplate(
            name="Events Summary",
            template_type=TemplateType.EVENTS_SUMMARY,
            structure={
                "summary": "Event overview and trends",
                "critical": "Critical events requiring attention",
                "patterns": "Event patterns and anomalies",
                "actions": "Recommended actions"
            },
            formatting_rules={
                "summary": {"style": "executive", "time_aware": True},
                "critical": {"style": "actionable", "prioritize": True},
                "patterns": {"style": "analytical", "include_trends": True}
            },
            priority_mapping={
                "summary": ContentPriority.CRITICAL,
                "critical": ContentPriority.CRITICAL,
                "patterns": ContentPriority.IMPORTANT,
                "actions": ContentPriority.IMPORTANT
            },
            max_tokens_per_section={
                "summary": 250,
                "critical": 500,
                "patterns": 600,
                "actions": 400
            },
            include_sections=["summary", "critical", "actions"],
            exclude_sections=["debug", "verbose"]
        )
        
        return templates
    
    def get_template(self, template_type: TemplateType) -> Optional[TOONTemplate]:
        """Get template by type."""
        return self.templates.get(template_type.value)
    
    def apply_template(self, document: TOONDocument, template_type: TemplateType) -> TOONDocument:
        """Apply template to document."""
        template = self.get_template(template_type)
        if not template:
            return document
        
        # Filter sections based on template
        filtered_sections = {}
        filtered_priorities = {}
        
        for section_name, content in document.sections.items():
            if section_name in template.include_sections:
                # Apply token limits
                max_tokens = template.max_tokens_per_section.get(section_name, 1000)
                if isinstance(content, list) and len(content) > max_tokens // 10:
                    # For lists, limit items
                    filtered_sections[section_name] = content[:max_tokens // 10]
                elif isinstance(content, str) and len(content.split()) > max_tokens:
                    # For strings, limit words
                    words = content.split()
                    filtered_sections[section_name] = " ".join(words[:max_tokens])
                else:
                    filtered_sections[section_name] = content
                
                filtered_priorities[section_name] = template.priority_mapping.get(
                    section_name, ContentPriority.INFO
                )
        
        # Create new document with filtered content
        new_doc = TOONDocument(
            version=document.version,
            document_type=document.document_type,
            created_at=document.created_at,
            expires_at=document.expires_at,
            sections=filtered_sections,
            priorities=filtered_priorities,
            metadata=document.metadata.copy()
        )
        
        return new_doc


# LLM Formatter (Enhanced from toon_llm_formatter.py)
class TOONLLMFormatter:
    """Advanced LLM formatter for TOON documents."""
    
    def __init__(self):
        self.templates = TOONTemplates()
        self.format_cache = {}
    
    def format_for_conversation(self, document: TOONDocument, context: FormattingContext) -> FormattedResponse:
        """Format document for conversational LLM interaction."""
        # Select appropriate template
        template = self._select_template(document, context)
        
        # Apply template if available
        if template:
            document = self.templates.apply_template(document, template.template_type)
        
        # Generate formatted content
        content = self._format_content(document, context)
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(document, context)
        
        # Extract actionable insights
        actionable_items = self._extract_actionable_insights(document, context)
        
        # Generate key insights
        key_insights = self._generate_key_insights(document, context)
        
        return FormattedResponse(
            content=content,
            format_style=context.format_style,
            token_count=len(content.split()),
            sections_included=list(document.sections.keys()),
            priority_applied=context.prioritize_critical,
            context_preserved=True,
            actionable_items=actionable_items,
            executive_summary=executive_summary,
            key_insights=key_insights
        )
    
    def _select_template(self, document: TOONDocument, context: FormattingContext) -> Optional[TOONTemplate]:
        """Select appropriate template based on document type and context."""
        template_mapping = {
            "fleet_overview": TemplateType.FLEET_OVERVIEW,
            "operation_result": TemplateType.OPERATION_RESULT,
            "events_summary": TemplateType.EVENTS_SUMMARY,
            "policy_status": TemplateType.POLICY_STATUS,
            "health_report": TemplateType.HEALTH_REPORT,
            "system_dashboard": TemplateType.SYSTEM_DASHBOARD
        }
        
        return self.templates.get_template(template_mapping.get(document.document_type))
    
    def _format_content(self, document: TOONDocument, context: FormattingContext) -> str:
        """Format document content based on context."""
        formatted_parts = []
        
        # Add header
        header = self._format_header(document, context)
        formatted_parts.append(header)
        
        # Format sections by priority
        sections_by_priority = self._group_sections_by_priority(document)
        
        for priority in [ContentPriority.CRITICAL, ContentPriority.IMPORTANT, ContentPriority.INFO]:
            if priority in sections_by_priority:
                for section_name, content in sections_by_priority[priority]:
                    section_text = self._format_section(section_name, content, context)
                    formatted_parts.append(section_text)
        
        return "\n\n".join(formatted_parts)
    
    def _format_header(self, document: TOONDocument, context: FormattingContext) -> str:
        """Format document header."""
        if context.format_style == LLMFormat.EXECUTIVE:
            return f"## {document.document_type.replace('_', ' ').title()} Summary"
        elif context.format_style == LLMFormat.TECHNICAL:
            return f"# {document.document_type.replace('_', ' ').title()}\n\nGenerated: {document.created_at.isoformat()}"
        else:
            return f"## {document.document_type.replace('_', ' ').title()}"
    
    def _format_section(self, section_name: str, content: Any, context: FormattingContext) -> str:
        """Format individual section."""
        section_title = section_name.replace('_', ' ').title()
        
        if context.format_style == LLMFormat.CONVERSATIONAL:
            return f"**{section_title}:**\n{self._format_conversational(content)}"
        elif context.format_style == LLMFormat.EXECUTIVE:
            return f"### {section_title}\n{self._format_executive(content)}"
        elif context.format_style == LLMFormat.ACTIONABLE:
            return f"**{section_title}:**\n{self._format_actionable(content)}"
        else:  # STRUCTURED or TECHNICAL
            return f"#### {section_title}\n{self._format_structured(content)}"
    
    def _format_conversational(self, content: Any) -> str:
        """Format content for conversational style."""
        if isinstance(content, dict):
            if "total" in content and "healthy" in content:
                return f"Overall, you have {content['total']} items total, with {content['healthy']} in good condition."
            elif "status" in content:
                return f"The current status shows: {content['status']}."
            else:
                return str(content)
        elif isinstance(content, list):
            if len(content) == 0:
                return "No items to report."
            elif len(content) == 1:
                return f"There's {len(content)} item: {content[0]}."
            else:
                return f"There are {len(content)} items total."
        else:
            return str(content)
    
    def _format_executive(self, content: Any) -> str:
        """Format content for executive summary style."""
        if isinstance(content, dict):
            # Create executive summary from metrics
            summary_parts = []
            for key, value in content.items():
                if key in ["total", "count", "percentage"]:
                    summary_parts.append(f"{key.replace('_', ' ').title()}: {value}")
            return " ".join(summary_parts) if summary_parts else str(content)
        elif isinstance(content, list):
            return f"Summary of {len(content)} items."
        else:
            return str(content)[:200] + "..." if len(str(content)) > 200 else str(content)
    
    def _format_actionable(self, content: Any) -> str:
        """Format content for actionable style."""
        if isinstance(content, dict):
            action_items = []
            for key, value in content.items():
                if "error" in key.lower() or "issue" in key.lower() or "problem" in key.lower():
                    action_items.append(f"- Address {key}: {value}")
                elif "status" in key.lower() and value != "healthy":
                    action_items.append(f"- Check {key}: currently {value}")
            return "\n".join(action_items) if action_items else str(content)
        elif isinstance(content, list):
            return "\n".join([f"- {item}" for item in content[:5]])  # Limit to 5 items
        else:
            return f"Action required: {content}"
    
    def _format_structured(self, content: Any) -> str:
        """Format content for structured/technical style."""
        if isinstance(content, dict):
            formatted_items = []
            for key, value in content.items():
                formatted_items.append(f"- **{key.replace('_', ' ').title()}:** {value}")
            return "\n".join(formatted_items)
        elif isinstance(content, list):
            return "\n".join([f"- {item}" for item in content])
        else:
            return str(content)
    
    def _group_sections_by_priority(self, document: TOONDocument) -> Dict[ContentPriority, List[Tuple[str, Any]]]:
        """Group sections by priority for ordered formatting."""
        grouped = {priority: [] for priority in ContentPriority}
        
        for section_name, content in document.sections.items():
            priority = document.priorities.get(section_name, ContentPriority.INFO)
            grouped[priority].append((section_name, content))
        
        return grouped
    
    def _generate_executive_summary(self, document: TOONDocument, context: FormattingContext) -> str:
        """Generate executive summary for document."""
        if context.format_style != LLMFormat.EXECUTIVE:
            return None
        
        # Extract key metrics from critical sections
        summary_parts = []
        
        for section_name, content in document.sections.items():
            priority = document.priorities.get(section_name, ContentPriority.INFO)
            if priority == ContentPriority.CRITICAL and isinstance(content, dict):
                for key, value in content.items():
                    if key in ["total", "count", "status", "percentage", "health"]:
                        summary_parts.append(f"{key.replace('_', ' ').title()}: {value}")
        
        return " | ".join(summary_parts) if summary_parts else "Summary unavailable"
    
    def _extract_actionable_insights(self, document: TOONDocument, context: FormattingContext) -> List[str]:
        """Extract actionable insights from document."""
        insights = []
        
        for section_name, content in document.sections.items():
            priority = document.priorities.get(section_name, ContentPriority.INFO)
            
            if priority in [ContentPriority.CRITICAL, ContentPriority.IMPORTANT]:
                if isinstance(content, dict):
                    for key, value in content.items():
                        if "error" in key.lower() or "issue" in key.lower():
                            insights.append(f"Address {key}: {value}")
                        elif "status" in key.lower() and value not in ["healthy", "running", "ok"]:
                            insights.append(f"Investigate {key}: {value}")
                elif isinstance(content, list) and len(content) > 0:
                    insights.append(f"Review {section_name}: {len(content)} items need attention")
        
        return insights[:5]  # Limit to 5 insights
    
    def _generate_key_insights(self, document: TOONDocument, context: FormattingContext) -> List[str]:
        """Generate key insights from document."""
        insights = []
        
        # Look for patterns in the data
        if "summary" in document.sections:
            summary = document.sections["summary"]
            if isinstance(summary, dict):
                for key, value in summary.items():
                    if isinstance(value, (int, float)) and value > 0:
                        insights.append(f"{key.replace('_', ' ').title()}: {value}")
        
        return insights[:3]  # Limit to 3 key insights


# Convenience Functions
def create_optimized_document(data: Dict[str, Any], template_type: TemplateType) -> TOONDocument:
    """Create optimized document using template."""
    from .serializer import TOONDocument, ContentPriority
    
    doc = TOONDocument(
        document_type=template_type.value,
        created_at=datetime.now()
    )
    
    # Add data as main content
    doc.add_section("content", data, ContentPriority.INFO)
    
    return doc


def get_fleet_overview_template() -> TemplateType:
    """Get fleet overview template type."""
    return TemplateType.FLEET_OVERVIEW


def get_operation_result_template() -> TemplateType:
    """Get operation result template type."""
    return TemplateType.OPERATION_RESULT


# Main formatter instance
_formatter = TOONLLMFormatter()

# Convenience function
def get_llm_formatter() -> TOONLLMFormatter:
    """Get the global LLM formatter instance."""
    return _formatter