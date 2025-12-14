"""
TOON LLM Formatter for Optimal Document Consumption

This module provides advanced formatting capabilities for TOON documents,
optimizing them for LLM consumption through intelligent content organization,
context-aware summaries, and conversational formatting.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Union, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import logging

from src.integration.toon_enhanced import TOONDocument, ContentPriority
from src.integration.toon_templates import TOONTemplates, TemplateType, TOONTemplate


logger = logging.getLogger(__name__)


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
    focus_area: Optional[str] = None      # specific area of interest
    previous_context: Optional[Dict[str, Any]] = None
    time_range: str = "24h"
    include_recommendations: bool = True
    include_trends: bool = True
    max_response_length: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "format_style": self.format_style.value,
            "context_type": self.context_type.value,
            "user_expertise": self.user_expertise,
            "focus_area": self.focus_area,
            "previous_context": self.previous_context,
            "time_range": self.time_range,
            "include_recommendations": self.include_recommendations,
            "include_trends": self.include_trends,
            "max_response_length": self.max_response_length
        }


@dataclass
class FormattedResponse:
    """Container for formatted LLM response."""
    
    content: str
    metadata: Dict[str, Any]
    token_count: int
    sections_included: List[str]
    formatting_applied: Dict[str, Any]
    compression_ratio: float


class TOONLLMFormatter:
    """Advanced formatter for TOON documents optimized for LLM consumption."""
    
    def __init__(self):
        self._formatters = {
            LLMFormat.CONVERSATIONAL: self._format_conversational,
            LLMFormat.STRUCTURED: self._format_structured,
            LLMFormat.EXECUTIVE: self._format_executive,
            LLMFormat.TECHNICAL: self._format_technical,
            LLMFormat.ACTIONABLE: self._format_actionable
        }
    
    def format_for_conversation(
        self,
        document: TOONDocument,
        context: FormattingContext
    ) -> FormattedResponse:
        """Format document for conversational LLM interaction."""
        formatter = self._formatters.get(context.format_style, self._format_conversational)
        
        return formatter(document, context)
    
    def generate_executive_summary(self, document: TOONDocument) -> str:
        """Generate executive summary of document."""
        if not document.sections:
            return "No content available for summary."
        
        # Get critical sections first
        critical_sections = [
            (name, content) for name, content in document.sections.items()
            if document.priorities.get(name, ContentPriority.INFO) == ContentPriority.CRITICAL
        ]
        
        summary_parts = []
        summary_parts.append(f"Executive Summary - {document.document_type.replace('_', ' ').title()}")
        summary_parts.append(f"Generated: {document.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        summary_parts.append("")
        
        # Add key metrics
        if "fleet_summary" in document.sections:
            fleet_data = document.sections["fleet_summary"]
            summary_parts.append("Key Metrics:")
            summary_parts.append(f"• Fleet Health: {fleet_data.get('overall_score', 'N/A'):.1%}" if isinstance(fleet_data.get('overall_score'), (int, float)) else f"• Fleet Health: {fleet_data.get('overall_score', 'N/A')}")
            summary_parts.append(f"• Total Targets: {fleet_data.get('total_targets', 'N/A')}")
            summary_parts.append(f"• Critical Issues: {len(fleet_data.get('critical_issues', []))}")
        
        # Add status overview
        summary_parts.append("\nStatus Overview:")
        for section_name, content in critical_sections:
            status_summary = self._extract_status_summary(section_name, content)
            if status_summary:
                summary_parts.append(f"• {status_summary}")
        
        # Add immediate actions needed
        if document.priorities.get("recommendations"):
            recommendations = document.sections.get("recommendations", [])
            if recommendations:
                summary_parts.append("\nImmediate Actions Required:")
                for i, rec in enumerate(recommendations[:3], 1):
                    summary_parts.append(f"{i}. {rec}")
        
        return "\n".join(summary_parts)
    
    def create_actionable_insights(self, document: TOONDocument) -> List[str]:
        """Extract actionable insights from document."""
        insights = []
        
        # Extract from recommendations section
        if "recommendations" in document.sections:
            recommendations = document.sections["recommendations"]
            if isinstance(recommendations, list):
                insights.extend(recommendations)
            elif isinstance(recommendations, str):
                insights.append(recommendations)
        
        # Extract from errors section
        if "errors" in document.sections:
            errors = document.sections["errors"]
            if isinstance(errors, list):
                for error in errors:
                    if isinstance(error, dict):
                        action = error.get("action", error.get("remediation", "Investigate and resolve"))
                        insights.append(f"Resolve: {action}")
        
        # Extract from critical issues
        if "critical_issues" in document.sections:
            issues = document.sections["critical_issues"]
            if isinstance(issues, list):
                for issue in issues:
                    if isinstance(issue, dict):
                        action = issue.get("action", issue.get("solution", "Immediate attention required"))
                        insights.append(f"Critical: {action}")
        
        # Extract from next steps
        if "next_steps" in document.sections:
            next_steps = document.sections["next_steps"]
            if isinstance(next_steps, list):
                insights.extend(next_steps)
        
        return insights[:10]  # Limit to top 10 insights
    
    def format_trend_analysis(self, trends: List[Dict[str, Any]]) -> str:
        """Format trend analysis for LLM consumption."""
        if not trends:
            return "No trend data available."
        
        trend_sections = []
        trend_sections.append("📈 TREND ANALYSIS")
        trend_sections.append("=" * 50)
        
        for trend in trends:
            trend_type = trend.get("type", "unknown")
            direction = trend.get("direction", "stable")
            confidence = trend.get("confidence", 0.5)
            
            # Format trend header
            icon = self._get_trend_icon(direction)
            confidence_level = "High" if confidence > 0.7 else "Medium" if confidence > 0.4 else "Low"
            
            trend_sections.append(f"\n{icon} {trend_type.replace('_', ' ').title()}")
            trend_sections.append(f"   Direction: {direction.title()}")
            trend_sections.append(f"   Confidence: {confidence_level} ({confidence:.1%})")
            
            # Add details if available
            if "details" in trend:
                trend_sections.append(f"   Details: {trend['details']}")
            
            # Add predictions if available
            if "predictions" in trend:
                predictions = trend["predictions"]
                trend_sections.append(f"   Predictions: {predictions}")
        
        return "\n".join(trend_sections)
    
    def build_context_summary(self, conversation_history: List[Dict[str, Any]]) -> str:
        """Build context summary from conversation history."""
        if not conversation_history:
            return "No previous conversation context."
        
        context_parts = []
        context_parts.append("📋 CONVERSATION CONTEXT")
        context_parts.append("=" * 40)
        
        # Extract key topics and decisions
        topics = []
        decisions = []
        
        for interaction in conversation_history[-5:]:  # Last 5 interactions
            user_message = interaction.get("user_message", "")
            assistant_response = interaction.get("assistant_response", "")
            
            # Extract topics (simple keyword extraction)
            topics.extend(self._extract_topics(user_message))
            
            # Extract decisions (look for decision indicators)
            decisions.extend(self._extract_decisions(assistant_response))
        
        if topics:
            context_parts.append(f"\n📝 Recent Topics: {', '.join(set(topics))}")
        
        if decisions:
            context_parts.append(f"\n✅ Recent Decisions: {', '.join(set(decisions))}")
        
        # Add current focus
        current_focus = self._identify_current_focus(conversation_history)
        if current_focus:
            context_parts.append(f"\n🎯 Current Focus: {current_focus}")
        
        return "\n".join(context_parts)
    
    def extract_relevant_context(
        self,
        query: str,
        documents: List[TOONDocument]
    ) -> List[TOONDocument]:
        """Extract relevant documents based on query."""
        query_keywords = self._extract_query_keywords(query)
        relevant_docs = []
        
        for doc in documents:
            relevance_score = self._calculate_relevance_score(query_keywords, doc)
            if relevance_score > 0.3:  # Threshold for relevance
                relevant_docs.append((doc, relevance_score))
        
        # Sort by relevance score
        relevant_docs.sort(key=lambda x: x[1], reverse=True)
        
        return [doc for doc, score in relevant_docs[:3]]  # Return top 3 most relevant
    
    def generate_follow_up_questions(self, document: TOONDocument) -> List[str]:
        """Generate intelligent follow-up questions based on document content."""
        questions = []
        
        # Questions based on document type
        doc_type = document.document_type
        
        if doc_type == "fleet_inventory":
            questions.extend([
                "What are the main resource utilization concerns across the fleet?",
                "Which systems are showing the highest error rates?",
                "What are the top recommendations for improving fleet health?"
            ])
        
        elif doc_type == "events_summary":
            questions.extend([
                "What patterns do you see in the event trends?",
                "Which event sources require immediate attention?",
                "Are there any recurring issues that need long-term solutions?"
            ])
        
        elif doc_type == "health_report":
            questions.extend([
                "What are the most critical health issues requiring immediate action?",
                "How do the current health scores compare to historical baselines?",
                "What preventive measures can reduce future health issues?"
            ])
        
        # Questions based on content analysis
        if "critical_issues" in document.sections and document.sections["critical_issues"]:
            questions.append("Can you provide more details about the critical issues mentioned?")
        
        if "recommendations" in document.sections and document.sections["recommendations"]:
            questions.append("Which recommendations should be prioritized first?")
        
        if "errors" in document.sections and document.sections["errors"]:
            questions.append("What are the root causes of the errors identified?")
        
        return questions[:5]  # Limit to 5 questions
    
    def optimize_for_token_limit(
        self,
        document: TOONDocument,
        max_tokens: int
    ) -> Tuple[str, List[str]]:
        """Optimize document content to fit token limit."""
        current_tokens = document.estimated_token_count()
        
        if current_tokens <= max_tokens:
            return document.to_llm_optimized(), list(document.sections.keys())
        
        # Strategy: Remove lowest priority sections first
        sections_by_priority = sorted(
            document.sections.items(),
            key=lambda x: document.priorities.get(x[0], ContentPriority.INFO).value,
            reverse=True  # Remove low priority first (higher value = lower priority)
        )
        
        selected_sections = []
        remaining_tokens = max_tokens
        
        for section_name, content in sections_by_priority:
            estimated_section_tokens = self._estimate_tokens(content)
            
            if estimated_section_tokens <= remaining_tokens:
                selected_sections.append((section_name, content))
                remaining_tokens -= estimated_section_tokens
            else:
                # Try to compress the section
                compressed_content = self._compress_for_tokens(content, remaining_tokens)
                if compressed_content:
                    selected_sections.append((section_name, compressed_content))
                break
        
        # Build optimized content
        optimized_content = self._build_optimized_content(document, selected_sections)
        included_sections = [name for name, _ in selected_sections]
        
        return optimized_content, included_sections
    
    def _format_conversational(
        self,
        document: TOONDocument,
        context: FormattingContext
    ) -> FormattedResponse:
        """Format in conversational style."""
        content_parts = []
        metadata = {"format_style": "conversational"}
        
        # Add greeting and context
        if context.context_type == ContextType.INITIAL_QUERY:
            content_parts.append(f"Here's what I found regarding your {document.document_type.replace('_', ' ')}:")
        elif context.context_type == ContextType.FOLLOW_UP:
            content_parts.append("Building on our previous discussion:")
        elif context.context_type == ContextType.CLARIFICATION:
            content_parts.append("Let me clarify the details:")
        
        content_parts.append("")
        
        # Format sections in priority order
        sorted_sections = sorted(
            document.sections.items(),
            key=lambda x: document.priorities.get(x[0], ContentPriority.INFO).value
        )
        
        for section_name, section_content in sorted_sections:
            if not self._should_include_section(section_name, context):
                continue
            
            section_header = section_name.replace('_', ' ').title()
            content_parts.append(f"**{section_header}:**")
            content_parts.append(self._format_section_content(section_content, context))
            content_parts.append("")
        
        # Add recommendations if enabled
        if context.include_recommendations and "recommendations" in document.sections:
            content_parts.append("**Here's what I recommend:**")
            recommendations = document.sections["recommendations"]
            if isinstance(recommendations, list):
                for i, rec in enumerate(recommendations[:5], 1):
                    content_parts.append(f"{i}. {rec}")
            else:
                content_parts.append(str(recommendations))
        
        # Add follow-up question
        follow_ups = self.generate_follow_up_questions(document)
        if follow_ups:
            content_parts.append("")
            content_parts.append("**Questions for you:**")
            for question in follow_ups[:3]:
                content_parts.append(f"• {question}")
        
        content = "\n".join(content_parts)
        token_count = self._estimate_tokens(content)
        
        return FormattedResponse(
            content=content,
            metadata=metadata,
            token_count=token_count,
            sections_included=list(document.sections.keys()),
            formatting_applied={"conversational_tone": True, "priority_ordering": True},
            compression_ratio=1.0 - (token_count / max(document.token_estimate, 1))
        )
    
    def _format_structured(
        self,
        document: TOONDocument,
        context: FormattingContext
    ) -> FormattedResponse:
        """Format in structured documentation style."""
        content_parts = []
        metadata = {"format_style": "structured"}
        
        content_parts.append(f"# {document.document_type.replace('_', ' ').title()} Report")
        content_parts.append(f"*Generated: {document.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}*")
        content_parts.append("")
        
        # Table of contents
        content_parts.append("## Contents")
        for section_name in document.sections.keys():
            section_title = section_name.replace('_', ' ').title()
            content_parts.append(f"- [{section_title}](#{section_name.replace('_', ' ')})")
        content_parts.append("")
        
        # Format each section
        for section_name, section_content in document.sections.items():
            section_title = section_name.replace('_', ' ').title()
            content_parts.append(f"## {section_title}")
            content_parts.append("")
            content_parts.append(self._format_section_content(section_content, context))
            content_parts.append("")
        
        content = "\n".join(content_parts)
        token_count = self._estimate_tokens(content)
        
        return FormattedResponse(
            content=content,
            metadata=metadata,
            token_count=token_count,
            sections_included=list(document.sections.keys()),
            formatting_applied={"markdown_structure": True, "toc_included": True},
            compression_ratio=1.0 - (token_count / max(document.token_estimate, 1))
        )
    
    def _format_executive(
        self,
        document: TOONDocument,
        context: FormattingContext
    ) -> FormattedResponse:
        """Format in executive summary style."""
        content_parts = []
        metadata = {"format_style": "executive"}
        
        # Executive summary
        content_parts.append(self.generate_executive_summary(document))
        content_parts.append("")
        
        # Key findings (high priority items only)
        critical_sections = [
            (name, content) for name, content in document.sections.items()
            if document.priorities.get(name, ContentPriority.INFO) == ContentPriority.CRITICAL
        ]
        
        if critical_sections:
            content_parts.append("## KEY FINDINGS")
            for section_name, content in critical_sections:
                findings = self._extract_key_findings(section_name, content)
                for finding in findings:
                    content_parts.append(f"• {finding}")
            content_parts.append("")
        
        # Immediate actions
        insights = self.create_actionable_insights(document)
        if insights:
            content_parts.append("## IMMEDIATE ACTIONS REQUIRED")
            for insight in insights[:5]:
                content_parts.append(f"• {insight}")
        
        content = "\n".join(content_parts)
        token_count = self._estimate_tokens(content)
        
        return FormattedResponse(
            content=content,
            metadata=metadata,
            token_count=token_count,
            sections_included=[name for name, _ in critical_sections],
            formatting_applied={"executive_focus": True, "action_prioritized": True},
            compression_ratio=1.0 - (token_count / max(document.token_estimate, 1))
        )
    
    def _format_technical(
        self,
        document: TOONDocument,
        context: FormattingContext
    ) -> FormattedResponse:
        """Format in detailed technical style."""
        content_parts = []
        metadata = {"format_style": "technical"}
        
        content_parts.append(f"## Technical Analysis: {document.document_type.replace('_', ' ').title()}")
        content_parts.append("")
        
        # Add all sections with technical details
        for section_name, section_content in document.sections.items():
            content_parts.append(f"### {section_name.replace('_', ' ').title()}")
            content_parts.append("")
            
            # Add technical metadata
            priority = document.priorities.get(section_name, ContentPriority.INFO)
            content_parts.append(f"*Priority: {priority.name} | Estimated tokens: {self._estimate_tokens(section_content)}*")
            content_parts.append("")
            
            content_parts.append(self._format_section_content(section_content, context, technical=True))
            content_parts.append("")
        
        # Add document metadata
        content_parts.append("---")
        content_parts.append("### Document Metadata")
        content_parts.append(f"- Document Type: {document.document_type}")
        content_parts.append(f"- Generated: {document.created_at.isoformat()}")
        content_parts.append(f"- Total Sections: {len(document.sections)}")
        content_parts.append(f"- Token Estimate: {document.token_estimate}")
        content_parts.append(f"- Compression Ratio: {document.compression_ratio:.2%}")
        
        content = "\n".join(content_parts)
        token_count = self._estimate_tokens(content)
        
        return FormattedResponse(
            content=content,
            metadata=metadata,
            token_count=token_count,
            sections_included=list(document.sections.keys()),
            formatting_applied={"technical_detail": True, "metadata_included": True},
            compression_ratio=1.0 - (token_count / max(document.token_estimate, 1))
        )
    
    def _format_actionable(
        self,
        document: TOONDocument,
        context: FormattingContext
    ) -> FormattedResponse:
        """Format in action-oriented style."""
        content_parts = []
        metadata = {"format_style": "actionable"}
        
        content_parts.append(f"## Action Items - {document.document_type.replace('_', ' ').title()}")
        content_parts.append("")
        
        # Extract and prioritize actions
        all_actions = []
        
        # From recommendations
        if "recommendations" in document.sections:
            recommendations = document.sections["recommendations"]
            if isinstance(recommendations, list):
                all_actions.extend([("Recommendation", rec) for rec in recommendations])
            else:
                all_actions.append(("Recommendation", str(recommendations)))
        
        # From errors
        if "errors" in document.sections:
            errors = document.sections["errors"]
            if isinstance(errors, list):
                for error in errors:
                    if isinstance(error, dict):
                        action = error.get("action", error.get("fix", "Investigate and resolve"))
                        all_actions.append(("Error", action))
        
        # From critical issues
        if "critical_issues" in document.sections:
            issues = document.sections["critical_issues"]
            if isinstance(issues, list):
                for issue in issues:
                    if isinstance(issue, dict):
                        action = issue.get("action", issue.get("solution", "Immediate attention required"))
                        all_actions.append(("Critical Issue", action))
        
        # Sort by priority and format
        if all_actions:
            content_parts.append("### Priority Actions")
            for i, (action_type, action) in enumerate(all_actions[:10], 1):
                priority_icon = "🔴" if action_type == "Critical Issue" else "🟡" if action_type == "Error" else "🔵"
                content_parts.append(f"{priority_icon} **{i}.** {action}")
            
            content_parts.append("")
        
        # Add status summary
        content_parts.append("### Status Overview")
        for section_name, content in document.sections.items():
            if document.priorities.get(section_name) == ContentPriority.CRITICAL:
                status = self._extract_status_summary(section_name, content)
                if status:
                    content_parts.append(f"- {status}")
        
        content = "\n".join(content_parts)
        token_count = self._estimate_tokens(content)
        
        return FormattedResponse(
            content=content,
            metadata=metadata,
            token_count=token_count,
            sections_included=list(document.sections.keys()),
            formatting_applied={"action_oriented": True, "priority_icons": True},
            compression_ratio=1.0 - (token_count / max(document.token_estimate, 1))
        )
    
    def _should_include_section(self, section_name: str, context: FormattingContext) -> bool:
        """Determine if section should be included based on context."""
        priority = context.previous_context.get("priorities", {})
        focus_area = context.focus_area
        
        # Always include critical sections
        if "critical" in section_name.lower() or "error" in section_name.lower():
            return True
        
        # Filter by focus area if specified
        if focus_area and focus_area.lower() in section_name.lower():
            return True
        
        # Include based on user expertise
        if context.user_expertise == "beginner":
            return priority.get(section_name, 3) <= 2  # Only high priority
        elif context.user_expertise == "expert":
            return True  # Include all sections
        
        # Default: include important and above
        return priority.get(section_name, 3) <= 3
    
    def _format_section_content(
        self,
        content: Any,
        context: FormattingContext,
        technical: bool = False
    ) -> str:
        """Format section content for display."""
        if isinstance(content, dict):
            if technical:
                return self._format_dict_technical(content)
            else:
                return self._format_dict_simple(content)
        elif isinstance(content, list):
            if technical:
                return self._format_list_technical(content)
            else:
                return self._format_list_simple(content)
        else:
            return str(content)
    
    def _format_dict_simple(self, data: Dict[str, Any]) -> str:
        """Format dictionary in simple style."""
        lines = []
        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"{key}:")
                for sub_key, sub_value in value.items():
                    lines.append(f"  {sub_key}: {sub_value}")
            elif isinstance(value, list) and len(value) <= 5:
                lines.append(f"{key}: {', '.join(map(str, value))}")
            else:
                lines.append(f"{key}: {value}")
        return "\n".join(lines)
    
    def _format_dict_technical(self, data: Dict[str, Any]) -> str:
        """Format dictionary in technical style."""
        lines = ["```json", json.dumps(data, indent=2, ensure_ascii=False), "```"]
        return "\n".join(lines)
    
    def _format_list_simple(self, data: List[Any]) -> str:
        """Format list in simple style."""
        if not data:
            return "*No items*"
        
        if len(data) <= 10:
            lines = []
            for item in data:
                if isinstance(item, dict):
                    summary = item.get("name", item.get("id", str(item)[:50]))
                    lines.append(f"- {summary}")
                else:
                    lines.append(f"- {item}")
            return "\n".join(lines)
        else:
            return f"*List with {len(data)} items - showing first 10:*\n" + self._format_list_simple(data[:10])
    
    def _format_list_technical(self, data: List[Any]) -> str:
        """Format list in technical style."""
        if not data:
            return "*Empty list*"
        
        lines = [f"*List with {len(data)} items:*", "```json", json.dumps(data[:20], indent=2, ensure_ascii=False)]
        if len(data) > 20:
            lines.append(f"... and {len(data) - 20} more items")
        lines.append("```")
        return "\n".join(lines)
    
    def _extract_status_summary(self, section_name: str, content: Any) -> Optional[str]:
        """Extract status summary from section content."""
        if isinstance(content, dict):
            if "status" in content:
                return f"{section_name.replace('_', ' ').title()}: {content['status']}"
            elif "health_score" in content:
                score = content["health_score"]
                if isinstance(score, (int, float)):
                    return f"{section_name.replace('_', ' ').title()}: {score:.1%} health"
        elif isinstance(content, str):
            return f"{section_name.replace('_', ' ').title()}: {content[:100]}"
        return None
    
    def _extract_key_findings(self, section_name: str, content: Any) -> List[str]:
        """Extract key findings from content."""
        findings = []
        
        if isinstance(content, dict):
            # Extract important metrics
            for key, value in content.items():
                if key in ["score", "count", "total", "critical", "errors"]:
                    findings.append(f"{key.replace('_', ' ').title()}: {value}")
        
        elif isinstance(content, list) and content:
            # Extract summary of list
            if len(content) > 0:
                findings.append(f"{section_name.replace('_', ' ').title()}: {len(content)} items identified")
        
        return findings
    
    def _get_trend_icon(self, direction: str) -> str:
        """Get icon for trend direction."""
        icons = {
            "increasing": "📈",
            "decreasing": "📉",
            "stable": "➡️",
            "improving": "🚀",
            "declining": "⚠️"
        }
        return icons.get(direction, "📊")
    
    def _extract_topics(self, text: str) -> List[str]:
        """Extract topics from text."""
        # Simple keyword extraction
        keywords = ["fleet", "inventory", "health", "performance", "error", "security", "policy", "resource"]
        topics = []
        
        text_lower = text.lower()
        for keyword in keywords:
            if keyword in text_lower:
                topics.append(keyword)
        
        return topics
    
    def _extract_decisions(self, text: str) -> List[str]:
        """Extract decisions from text."""
        # Look for decision indicators
        decisions = []
        if "decided" in text.lower() or "chosen" in text.lower():
            decisions.append("decision_made")
        if "implemented" in text.lower() or "deployed" in text.lower():
            decisions.append("action_taken")
        return decisions
    
    def _identify_current_focus(self, conversation_history: List[Dict[str, Any]]) -> Optional[str]:
        """Identify current focus area from conversation."""
        if not conversation_history:
            return None
        
        recent_messages = [interaction.get("user_message", "") for interaction in conversation_history[-3:]]
        combined_text = " ".join(recent_messages).lower()
        
        focus_areas = {
            "health": ["health", "status", "monitoring"],
            "security": ["security", "threat", "vulnerability"],
            "performance": ["performance", "latency", "throughput"],
            "inventory": ["inventory", "fleet", "resources"],
            "compliance": ["compliance", "policy", "audit"]
        }
        
        for focus_area, keywords in focus_areas.items():
            if any(keyword in combined_text for keyword in keywords):
                return focus_area
        
        return None
    
    def _calculate_relevance_score(self, query_keywords: List[str], document: TOONDocument) -> float:
        """Calculate relevance score between query and document."""
        if not query_keywords or not document.sections:
            return 0.0
        
        # Score based on keyword matches in section names and content
        score = 0.0
        total_possible = len(query_keywords) * len(document.sections)
        
        for keyword in query_keywords:
            for section_name in document.sections.keys():
                if keyword.lower() in section_name.lower():
                    score += 1.0
                elif keyword.lower() in str(document.sections[section_name]).lower():
                    score += 0.5
        
        return score / max(total_possible, 1)
    
    def _extract_query_keywords(self, query: str) -> List[str]:
        """Extract keywords from query."""
        # Simple keyword extraction
        stop_words = {"the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with", "by"}
        words = re.findall(r'\b\w+\b', query.lower())
        return [word for word in words if word not in stop_words and len(word) > 2]
    
    def _estimate_tokens(self, content: str) -> int:
        """Estimate token count for content."""
        return len(content.split()) + len([c for c in content if c in '.,;:!?'])
    
    def _compress_for_tokens(self, content: Any, max_tokens: int) -> Any:
        """Compress content to fit token limit."""
        if isinstance(content, list):
            return content[:max_tokens // 10]  # Rough approximation
        elif isinstance(content, dict):
            return dict(list(content.items())[:max_tokens // 20])
        elif isinstance(content, str):
            return content[:max_tokens * 5]  # Rough character approximation
        return content
    
    def _build_optimized_content(self, document: TOONDocument, selected_sections: List[Tuple[str, Any]]) -> str:
        """Build optimized content from selected sections."""
        content_parts = []
        content_parts.append(f"Optimized Report: {document.document_type.replace('_', ' ').title()}")
        content_parts.append(f"Generated: {document.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        content_parts.append("")
        
        for section_name, content in selected_sections:
            content_parts.append(f"**{section_name.replace('_', ' ').title()}:**")
            content_parts.append(str(content))
            content_parts.append("")
        
        return "\n".join(content_parts)


# Global formatter instance
_llm_formatter = TOONLLMFormatter()


def get_llm_formatter() -> TOONLLMFormatter:
    """Get the global LLM formatter instance."""
    return _llm_formatter