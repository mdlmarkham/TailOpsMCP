"""
TOON Quality Assurance System

This module provides comprehensive quality assurance for TOON documents,
ensuring optimal structure, token limits, content completeness, and LLM consumption readiness.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Union, Tuple, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import logging
from collections import defaultdict, Counter

from src.integration.toon_enhanced import TOONDocument, ContentPriority
from src.integration.toon_templates import TOONTemplates, TemplateType, TOONTemplate
from src.integration.toon_llm_formatter import TOONLLMFormatter, FormattingContext, LLMFormat


logger = logging.getLogger(__name__)


class QualityLevel(Enum):
    """Quality levels for TOON documents."""
    EXCELLENT = "excellent"      # All checks pass, optimal for LLM
    GOOD = "good"               # Minor issues, acceptable for LLM
    ACCEPTABLE = "acceptable"   # Some issues, may need attention
    POOR = "poor"               # Significant issues, needs improvement
    FAILED = "failed"           # Critical issues, not suitable for LLM


class ValidationResult(Enum):
    """Results of validation checks."""
    PASS = "pass"
    WARNING = "warning"
    FAIL = "fail"
    ERROR = "error"


@dataclass
class QualityIssue:
    """Represents a quality issue in a TOON document."""
    
    category: str
    severity: str  # "critical", "high", "medium", "low"
    message: str
    suggestion: str
    affected_sections: List[str]
    token_impact: int = 0
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


@dataclass
class QualityReport:
    """Comprehensive quality report for TOON documents."""
    
    document_id: str
    quality_level: QualityLevel
    overall_score: float
    total_issues: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    
    issues: List[QualityIssue]
    recommendations: List[str]
    optimization_suggestions: List[str]
    
    # Metrics
    token_count: int
    token_efficiency: float
    structure_score: float
    content_completeness: float
    llm_readiness: float
    
    validation_details: Dict[str, Any]
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "document_id": self.document_id,
            "quality_level": self.quality_level.value,
            "overall_score": self.overall_score,
            "total_issues": self.total_issues,
            "issue_breakdown": {
                "critical": self.critical_issues,
                "high": self.high_issues,
                "medium": self.medium_issues,
                "low": self.low_issues
            },
            "issues": [
                {
                    "category": issue.category,
                    "severity": issue.severity,
                    "message": issue.message,
                    "suggestion": issue.suggestion,
                    "affected_sections": issue.affected_sections,
                    "token_impact": issue.token_impact
                }
                for issue in self.issues
            ],
            "recommendations": self.recommendations,
            "optimization_suggestions": self.optimization_suggestions,
            "metrics": {
                "token_count": self.token_count,
                "token_efficiency": self.token_efficiency,
                "structure_score": self.structure_score,
                "content_completeness": self.content_completeness,
                "llm_readiness": self.llm_readiness
            },
            "validation_details": self.validation_details,
            "timestamp": self.timestamp.isoformat()
        }


class TOONQualityAssurance:
    """Comprehensive quality assurance system for TOON documents."""
    
    def __init__(self):
        self._validator_registry = {
            "structure": self._validate_structure,
            "content": self._validate_content,
            "tokens": self._validate_token_limits,
            "completeness": self._validate_completeness,
            "llm_optimization": self._validate_llm_optimization,
            "performance": self._validate_performance
        }
        
        # Quality thresholds
        self._thresholds = {
            "excellent_score": 0.95,
            "good_score": 0.85,
            "acceptable_score": 0.70,
            "max_tokens": 4000,
            "min_sections": 1,
            "max_sections": 20,
            "min_content_length": 10,
            "max_content_length": 50000
        }
        
        # Quality rules
        self._quality_rules = {
            "required_sections": ["fleet_summary", "health_status", "recommendations"],
            "critical_priorities": ["critical_issues", "errors", "health_summary"],
            "optimization_keywords": ["recommendation", "action", "priority", "status"]
        }
    
    def validate_document_structure(self, document: TOONDocument) -> List[QualityIssue]:
        """Validate document structure and formatting."""
        issues = []
        
        # Check document type
        if not document.document_type:
            issues.append(QualityIssue(
                category="structure",
                severity="high",
                message="Document type is missing",
                suggestion="Set document_type to indicate the document purpose",
                affected_sections=[]
            ))
        
        # Check sections
        if not document.sections:
            issues.append(QualityIssue(
                category="structure",
                severity="critical",
                message="Document has no content sections",
                suggestion="Add meaningful content sections to provide value",
                affected_sections=[]
            ))
        
        # Check section priorities
        sections_without_priority = []
        for section_name in document.sections.keys():
            if section_name not in document.priorities:
                sections_without_priority.append(section_name)
        
        if sections_without_priority:
            issues.append(QualityIssue(
                category="structure",
                severity="medium",
                message=f"Sections missing priority assignment: {', '.join(sections_without_priority)}",
                suggestion="Assign appropriate priorities (CRITICAL, IMPORTANT, INFO, DEBUG) to all sections",
                affected_sections=sections_without_priority
            ))
        
        # Check metadata
        if not document.metadata:
            issues.append(QualityIssue(
                category="structure",
                severity="low",
                message="Document metadata is empty",
                suggestion="Add relevant metadata like generation time, source, and context",
                affected_sections=["metadata"]
            ))
        
        # Check for section name conventions
        invalid_section_names = []
        for section_name in document.sections.keys():
            if not re.match(r'^[a-z_][a-z0-9_]*$', section_name):
                invalid_section_names.append(section_name)
        
        if invalid_section_names:
            issues.append(QualityIssue(
                category="structure",
                severity="medium",
                message=f"Invalid section name conventions: {', '.join(invalid_section_names)}",
                suggestion="Use lowercase snake_case for section names",
                affected_sections=invalid_section_names
            ))
        
        return issues
    
    def check_token_limits(self, document: TOONDocument) -> List[QualityIssue]:
        """Check if document complies with token limits."""
        issues = []
        token_count = document.estimated_token_count()
        
        # Check global token limit
        if token_count > self._thresholds["max_tokens"]:
            excess_tokens = token_count - self._thresholds["max_tokens"]
            issues.append(QualityIssue(
                category="tokens",
                severity="high",
                message=f"Document exceeds token limit: {token_count} > {self._thresholds['max_tokens']}",
                suggestion=f"Reduce content by approximately {excess_tokens} tokens to meet LLM constraints",
                affected_sections=list(document.sections.keys()),
                token_impact=excess_tokens
            ))
        
        # Check for excessively long sections
        for section_name, content in document.sections.items():
            section_tokens = self._estimate_tokens(content)
            if section_tokens > self._thresholds["max_tokens"] * 0.5:  # 50% of global limit
                issues.append(QualityIssue(
                    category="tokens",
                    severity="medium",
                    message=f"Section '{section_name}' is very large: {section_tokens} tokens",
                    suggestion="Consider splitting large sections or applying compression",
                    affected_sections=[section_name],
                    token_impact=section_tokens - (self._thresholds["max_tokens"] * 0.5)
                ))
        
        # Check token efficiency
        token_efficiency = self._calculate_token_efficiency(document)
        if token_efficiency < 0.6:  # Less than 60% efficiency
            issues.append(QualityIssue(
                category="tokens",
                severity="medium",
                message=f"Low token efficiency: {token_efficiency:.1%}",
                suggestion="Improve token efficiency by using more concise language and structured data",
                affected_sections=list(document.sections.keys()),
                token_impact=int((0.6 - token_efficiency) * token_count)
            ))
        
        return issues
    
    def ensure_content_completeness(self, document: TOONDocument) -> List[QualityIssue]:
        """Ensure all required content is present."""
        issues = []
        
        # Check for required sections
        required_sections = self._quality_rules["required_sections"]
        missing_sections = [section for section in required_sections if section not in document.sections]
        
        if missing_sections:
            issues.append(QualityIssue(
                category="completeness",
                severity="medium",
                message=f"Missing recommended sections: {', '.join(missing_sections)}",
                suggestion="Add missing sections to provide comprehensive information",
                affected_sections=missing_sections
            ))
        
        # Check for critical content
        critical_priorities = self._quality_rules["critical_priorities"]
        missing_critical = []
        for priority_section in critical_priorities:
            # Check if any section has critical priority
            has_critical = any(
                document.priorities.get(section) == ContentPriority.CRITICAL
                for section in document.sections.keys()
            )
            if not has_critical and priority_section not in document.sections:
                missing_critical.append(priority_section)
        
        if missing_critical:
            issues.append(QualityIssue(
                category="completeness",
                severity="high",
                message=f"Missing critical content areas: {', '.join(missing_critical)}",
                suggestion="Include critical content sections for comprehensive analysis",
                affected_sections=missing_critical
            ))
        
        # Check content depth
        shallow_sections = []
        for section_name, content in document.sections.items():
            if isinstance(content, dict) and len(content) < 3:
                shallow_sections.append(section_name)
            elif isinstance(content, list) and len(content) < 2:
                shallow_sections.append(section_name)
            elif isinstance(content, str) and len(content) < 20:
                shallow_sections.append(section_name)
        
        if shallow_sections:
            issues.append(QualityIssue(
                category="completeness",
                severity="low",
                message=f"Shallow content in sections: {', '.join(shallow_sections)}",
                suggestion="Consider adding more detailed information to these sections",
                affected_sections=shallow_sections
            ))
        
        return issues
    
    def optimize_for_llm_consumption(self, document: TOONDocument) -> List[QualityIssue]:
        """Optimize document for LLM consumption."""
        issues = []
        
        # Check formatting optimization
        llm_formatter = TOONLLMFormatter()
        try:
            test_context = FormattingContext(format_style=LLMFormat.CONVERSATIONAL)
            formatted_response = llm_formatter.format_for_conversation(document, test_context)
            
            if formatted_response.token_count > self._thresholds["max_tokens"]:
                issues.append(QualityIssue(
                    category="llm_optimization",
                    severity="high",
                    message=f"Formatted output exceeds token limit: {formatted_response.token_count}",
                    suggestion="Apply content compression or section prioritization",
                    affected_sections=list(document.sections.keys())
                ))
            
        except Exception as e:
            issues.append(QualityIssue(
                category="llm_optimization",
                severity="high",
                message=f"LLM formatting failed: {str(e)}",
                suggestion="Fix document structure to enable proper LLM formatting",
                affected_sections=list(document.sections.keys())
            ))
        
        # Check for actionable content
        actionable_sections = ["recommendations", "next_steps", "actions", "action_items"]
        has_actionable = any(section in document.sections for section in actionable_sections)
        
        if not has_actionable:
            issues.append(QualityIssue(
                category="llm_optimization",
                severity="medium",
                message="No actionable content sections found",
                suggestion="Add recommendations, next steps, or action items for better LLM utility",
                affected_sections=["recommendations"]
            ))
        
        # Check for context preservation
        context_indicators = ["timestamp", "generated_at", "time_range", "context"]
        has_context = any(
            any(indicator in str(content).lower() for content in document.sections.values())
            for indicator in context_indicators
        )
        
        if not has_context:
            issues.append(QualityIssue(
                category="llm_optimization",
                severity="low",
                message="Missing temporal or contextual information",
                suggestion="Add timestamps, time ranges, or context information",
                affected_sections=["metadata"]
            ))
        
        # Check for data structure quality
        structure_quality = self._assess_data_structure_quality(document)
        if structure_quality < 0.7:
            issues.append(QualityIssue(
                category="llm_optimization",
                severity="medium",
                message=f"Poor data structure quality: {structure_quality:.1%}",
                suggestion="Improve data structure by using consistent formats and clear hierarchies",
                affected_sections=list(document.sections.keys())
            ))
        
        return issues
    
    def validate_performance_characteristics(self, document: TOONDocument) -> List[QualityIssue]:
        """Validate performance characteristics of the document."""
        issues = []
        
        # Check serialization performance
        try:
            start_time = datetime.now()
            compact_format = document.to_compact_format()
            serialization_time = (datetime.now() - start_time).total_seconds()
            
            if serialization_time > 1.0:  # More than 1 second
                issues.append(QualityIssue(
                    category="performance",
                    severity="medium",
                    message=f"Slow serialization: {serialization_time:.2f}s",
                    suggestion="Optimize document structure for faster serialization",
                    affected_sections=list(document.sections.keys())
                ))
            
        except Exception as e:
            issues.append(QualityIssue(
                category="performance",
                severity="high",
                message=f"Serialization failed: {str(e)}",
                suggestion="Fix document structure to enable proper serialization",
                affected_sections=list(document.sections.keys())
            ))
        
        # Check memory efficiency
        memory_estimate = self._estimate_memory_usage(document)
        max_memory_mb = 50  # 50MB limit for document
        
        if memory_estimate > max_memory_mb * 1024 * 1024:
            issues.append(QualityIssue(
                category="performance",
                severity="medium",
                message=f"High memory usage: {memory_estimate / 1024 / 1024:.1f}MB",
                suggestion="Compress content or reduce section sizes",
                affected_sections=list(document.sections.keys())
            ))
        
        # Check compression potential
        compression_ratio = self._assess_compression_potential(document)
        if compression_ratio < 0.3:  # Less than 30% compressible
            issues.append(QualityIssue(
                category="performance",
                severity="low",
                message=f"Low compression potential: {compression_ratio:.1%}",
                suggestion="Content may benefit from compression strategies",
                affected_sections=list(document.sections.keys())
            ))
        
        return issues
    
    def generate_quality_report(self, document: TOONDocument, template: Optional[TOONTemplate] = None) -> QualityReport:
        """Generate comprehensive quality report."""
        document_id = f"{document.document_type}_{document.created_at.strftime('%Y%m%d_%H%M%S')}"
        
        # Run all validations
        all_issues = []
        
        for validator_name, validator_func in self._validator_registry.items():
            try:
                issues = validator_func(document)
                all_issues.extend(issues)
            except Exception as e:
                logger.error(f"Validation error in {validator_name}: {e}")
                all_issues.append(QualityIssue(
                    category="validation",
                    severity="critical",
                    message=f"Validation failed for {validator_name}: {str(e)}",
                    suggestion="Fix validation system or document structure",
                    affected_sections=[]
                ))
        
        # Categorize issues
        issue_counts = {
            "critical": len([i for i in all_issues if i.severity == "critical"]),
            "high": len([i for i in all_issues if i.severity == "high"]),
            "medium": len([i for i in all_issues if i.severity == "medium"]),
            "low": len([i for i in all_issues if i.severity == "low"])
        }
        
        # Calculate scores
        overall_score = self._calculate_overall_score(document, all_issues)
        token_efficiency = self._calculate_token_efficiency(document)
        structure_score = self._assess_structure_score(document)
        content_completeness = self._assess_content_completeness(document)
        llm_readiness = self._assess_llm_readiness(document, all_issues)
        
        # Determine quality level
        quality_level = self._determine_quality_level(overall_score, issue_counts)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(all_issues)
        optimization_suggestions = self._generate_optimization_suggestions(document)
        
        # Validation details
        validation_details = {
            "validators_run": list(self._validator_registry.keys()),
            "document_size": len(str(document.sections)),
            "section_count": len(document.sections),
            "priority_distribution": self._get_priority_distribution(document),
            "template_compliance": self._check_template_compliance(document, template) if template else None
        }
        
        return QualityReport(
            document_id=document_id,
            quality_level=quality_level,
            overall_score=overall_score,
            total_issues=len(all_issues),
            critical_issues=issue_counts["critical"],
            high_issues=issue_counts["high"],
            medium_issues=issue_counts["medium"],
            low_issues=issue_counts["low"],
            issues=all_issues,
            recommendations=recommendations,
            optimization_suggestions=optimization_suggestions,
            token_count=document.estimated_token_count(),
            token_efficiency=token_efficiency,
            structure_score=structure_score,
            content_completeness=content_completeness,
            llm_readiness=llm_readiness,
            validation_details=validation_details
        )
    
    def apply_quality_fixes(self, document: TOONDocument, report: QualityReport) -> TOONDocument:
        """Apply automatic quality fixes to document."""
        fixed_document = TOONDocument(
            document_type=document.document_type,
            metadata=document.metadata.copy(),
            created_at=document.created_at
        )
        
        # Copy sections with fixes applied
        for section_name, content in document.sections.items():
            priority = document.priorities.get(section_name)
            
            # Apply content fixes
            fixed_content = self._apply_content_fixes(content, report)
            fixed_document.add_section(section_name, fixed_content, priority)
        
        # Add missing recommended sections
        missing_recommended = [issue.affected_sections[0] for issue in report.issues 
                             if issue.category == "completeness" and issue.affected_sections]
        for section in missing_recommended:
            if section not in fixed_document.sections:
                fixed_document.add_section(section, "Added by quality assurance", ContentPriority.INFO)
        
        # Optimize for LLM consumption
        if report.llm_readiness < 0.8:
            fixed_document = self._apply_llm_optimizations(fixed_document)
        
        return fixed_document
    
    def _validate_structure(self, document: TOONDocument) -> List[QualityIssue]:
        """Validate document structure."""
        return self.validate_document_structure(document)
    
    def _validate_content(self, document: TOONDocument) -> List[QualityIssue]:
        """Validate content quality."""
        issues = []
        
        # Check for empty sections
        empty_sections = []
        for section_name, content in document.sections.items():
            if content is None or (isinstance(content, (str, list, dict)) and not content):
                empty_sections.append(section_name)
        
        if empty_sections:
            issues.append(QualityIssue(
                category="content",
                severity="medium",
                message=f"Empty content sections: {', '.join(empty_sections)}",
                suggestion="Remove empty sections or add meaningful content",
                affected_sections=empty_sections
            ))
        
        # Check for content duplication
        content_counts = Counter(str(content) for content in document.sections.values())
        duplicated_content = [content for content, count in content_counts.items() if count > 1]
        
        if duplicated_content:
            issues.append(QualityIssue(
                category="content",
                severity="low",
                message="Duplicate content detected",
                suggestion="Review sections for redundant information",
                affected_sections=list(document.sections.keys())
            ))
        
        return issues
    
    def _validate_token_limits(self, document: TOONDocument) -> List[QualityIssue]:
        """Validate token limits."""
        return self.check_token_limits(document)
    
    def _validate_completeness(self, document: TOONDocument) -> List[QualityIssue]:
        """Validate content completeness."""
        return self.ensure_content_completeness(document)
    
    def _validate_llm_optimization(self, document: TOONDocument) -> List[QualityIssue]:
        """Validate LLM optimization."""
        return self.optimize_for_llm_consumption(document)
    
    def _validate_performance(self, document: TOONDocument) -> List[QualityIssue]:
        """Validate performance characteristics."""
        return self.validate_performance_characteristics(document)
    
    def _estimate_tokens(self, content: Any) -> int:
        """Estimate token count for content."""
        if isinstance(content, str):
            return len(content.split()) + len([c for c in content if c in '.,;:!?'])
        elif isinstance(content, (dict, list)):
            json_str = json.dumps(content, separators=(",", ":"), ensure_ascii=False)
            return self._estimate_tokens(json_str)
        else:
            return self._estimate_tokens(str(content))
    
    def _calculate_token_efficiency(self, document: TOONDocument) -> float:
        """Calculate token efficiency ratio."""
        if not document.sections:
            return 0.0
        
        total_tokens = sum(self._estimate_tokens(content) for content in document.sections.values())
        total_chars = sum(len(str(content)) for content in document.sections.values())
        
        if total_chars == 0:
            return 0.0
        
        # Efficiency = tokens per character (higher is better for structured data)
        return (total_tokens / total_chars) * 10  # Scale factor
    
    def _assess_data_structure_quality(self, document: TOONDocument) -> float:
        """Assess quality of data structures in document."""
        quality_scores = []
        
        for section_name, content in document.sections.items():
            if isinstance(content, dict):
                # Check for consistent structure
                keys = list(content.keys())
                if keys:
                    # Score based on key naming conventions
                    valid_keys = sum(1 for key in keys if re.match(r'^[a-z_][a-z0-9_]*$', key))
                    quality_scores.append(valid_keys / len(keys))
            
            elif isinstance(content, list):
                # Check for consistent list items
                if content:
                    if all(isinstance(item, dict) for item in content):
                        # Lists of dictionaries are good for LLM consumption
                        quality_scores.append(0.9)
                    else:
                        quality_scores.append(0.6)
        
        return sum(quality_scores) / max(len(quality_scores), 1)
    
    def _estimate_memory_usage(self, document: TOONDocument) -> int:
        """Estimate memory usage of document."""
        size = 0
        
        # Document metadata
        size += len(json.dumps(document.metadata, default=str))
        
        # Sections content
        for section_name, content in document.sections.items():
            size += len(section_name)
            size += len(json.dumps(content, default=str))
        
        return size
    
    def _assess_compression_potential(self, document: TOONDocument) -> float:
        """Assess compression potential of document."""
        if not document.sections:
            return 0.0
        
        original_size = sum(len(str(content)) for content in document.sections.values())
        structured_size = sum(len(json.dumps(content, separators=(",", ":"), ensure_ascii=False)) 
                            for content in document.sections.values())
        
        if original_size == 0:
            return 0.0
        
        # Compression potential = (original - structured) / original
        return (original_size - structured_size) / original_size
    
    def _calculate_overall_score(self, document: TOONDocument, issues: List[QualityIssue]) -> float:
        """Calculate overall quality score."""
        base_score = 1.0
        
        # Deduct points for issues
        for issue in issues:
            if issue.severity == "critical":
                base_score -= 0.3
            elif issue.severity == "high":
                base_score -= 0.2
            elif issue.severity == "medium":
                base_score -= 0.1
            elif issue.severity == "low":
                base_score -= 0.05
        
        # Bonus for good characteristics
        token_efficiency = self._calculate_token_efficiency(document)
        if token_efficiency > 0.8:
            base_score += 0.1
        
        structure_quality = self._assess_data_structure_quality(document)
        if structure_quality > 0.8:
            base_score += 0.1
        
        return max(0.0, min(1.0, base_score))
    
    def _assess_structure_score(self, document: TOONDocument) -> float:
        """Assess document structure quality."""
        score = 0.0
        
        # Has document type
        if document.document_type:
            score += 0.2
        
        # Has metadata
        if document.metadata:
            score += 0.2
        
        # Has appropriate number of sections
        if 1 <= len(document.sections) <= 15:
            score += 0.3
        
        # Has priority assignments
        if len(document.priorities) == len(document.sections):
            score += 0.3
        
        return score
    
    def _assess_content_completeness(self, document: TOONDocument) -> float:
        """Assess content completeness."""
        score = 0.0
        
        # Check for recommended sections
        required_sections = self._quality_rules["required_sections"]
        present_required = sum(1 for section in required_sections if section in document.sections)
        score += (present_required / len(required_sections)) * 0.6
        
        # Check content depth
        deep_sections = 0
        for content in document.sections.values():
            if isinstance(content, dict) and len(content) >= 3:
                deep_sections += 1
            elif isinstance(content, list) and len(content) >= 2:
                deep_sections += 1
            elif isinstance(content, str) and len(content) >= 50:
                deep_sections += 1
        
        if document.sections:
            score += (deep_sections / len(document.sections)) * 0.4
        
        return score
    
    def _assess_llm_readiness(self, document: TOONDocument, issues: List[QualityIssue]) -> float:
        """Assess readiness for LLM consumption."""
        score = 1.0
        
        # Deduct for LLM-specific issues
        llm_issues = [issue for issue in issues if issue.category in ["tokens", "llm_optimization"]]
        for issue in llm_issues:
            if issue.severity == "critical":
                score -= 0.3
            elif issue.severity == "high":
                score -= 0.2
            elif issue.severity == "medium":
                score -= 0.1
        
        # Bonus for actionable content
        actionable_sections = ["recommendations", "next_steps", "actions"]
        if any(section in document.sections for section in actionable_sections):
            score += 0.1
        
        return max(0.0, min(1.0, score))
    
    def _determine_quality_level(self, score: float, issue_counts: Dict[str, int]) -> QualityLevel:
        """Determine quality level based on score and issue counts."""
        if issue_counts["critical"] > 0:
            return QualityLevel.FAILED
        elif score >= self._thresholds["excellent_score"]:
            return QualityLevel.EXCELLENT
        elif score >= self._thresholds["good_score"]:
            return QualityLevel.GOOD
        elif score >= self._thresholds["acceptable_score"]:
            return QualityLevel.ACCEPTABLE
        else:
            return QualityLevel.POOR
    
    def _generate_recommendations(self, issues: List[QualityIssue]) -> List[str]:
        """Generate recommendations from issues."""
        recommendations = []
        
        # Group issues by category
        categories = defaultdict(list)
        for issue in issues:
            categories[issue.category].append(issue)
        
        # Generate category-specific recommendations
        if "tokens" in categories:
            recommendations.append("Consider content compression or section prioritization to meet token limits")
        
        if "completeness" in categories:
            recommendations.append("Add missing content sections for comprehensive information")
        
        if "structure" in categories:
            recommendations.append("Improve document structure and formatting")
        
        if "llm_optimization" in categories:
            recommendations.append("Optimize content for LLM consumption and readability")
        
        if "performance" in categories:
            recommendations.append("Optimize document performance characteristics")
        
        return recommendations[:5]  # Limit to top 5 recommendations
    
    def _generate_optimization_suggestions(self, document: TOONDocument) -> List[str]:
        """Generate optimization suggestions."""
        suggestions = []
        
        # Token optimization
        if document.estimated_token_count() > 3000:
            suggestions.append("Consider using more concise language and structured data formats")
        
        # Structure optimization
        if len(document.sections) > 10:
            suggestions.append("Consider grouping related sections or using sub-sections")
        
        # Content optimization
        suggestions.append("Use consistent terminology and formatting across sections")
        suggestions.append("Include actionable recommendations and next steps")
        suggestions.append("Add temporal context with timestamps and time ranges")
        
        return suggestions[:5]  # Limit to top 5 suggestions
    
    def _get_priority_distribution(self, document: TOONDocument) -> Dict[str, int]:
        """Get distribution of section priorities."""
        distribution = defaultdict(int)
        for section_name in document.sections.keys():
            priority = document.priorities.get(section_name, ContentPriority.INFO)
            distribution[priority.name] += 1
        return dict(distribution)
    
    def _check_template_compliance(self, document: TOONDocument, template: TOONTemplate) -> Dict[str, Any]:
        """Check compliance with template requirements."""
        if not template:
            return {"compliant": True, "issues": []}
        
        compliance_issues = []
        
        # Check required sections
        required_sections = template.get_required_sections()
        for section_template in required_sections:
            if section_template.name not in document.sections:
                compliance_issues.append(f"Missing required section: {section_template.name}")
        
        # Check token limits
        for section_name, content in document.sections.items():
            section_template = template.get_section(section_name)
            if section_template:
                token_count = self._estimate_tokens(content)
                if token_count > section_template.max_tokens:
                    compliance_issues.append(
                        f"Section '{section_name}' exceeds token limit: {token_count} > {section_template.max_tokens}"
                    )
        
        return {
            "compliant": len(compliance_issues) == 0,
            "issues": compliance_issues
        }
    
    def _apply_content_fixes(self, content: Any, report: QualityReport) -> Any:
        """Apply automatic content fixes."""
        if isinstance(content, list) and len(content) > 100:
            # Trim overly long lists
            return content[:50] + content[-25:]
        elif isinstance(content, dict) and len(content) > 50:
            # Trim overly large dictionaries
            return dict(list(content.items())[:25])
        elif isinstance(content, str) and len(content) > 5000:
            # Trim overly long strings
            return content[:2500] + "..." + content[-1000:]
        
        return content
    
    def _apply_llm_optimizations(self, document: TOONDocument) -> TOONDocument:
        """Apply LLM-specific optimizations."""
        optimized = TOONDocument(
            document_type=document.document_type,
            metadata=document.metadata.copy()
        )
        
        # Re-prioritize sections for LLM consumption
        llm_priority_order = [
            "executive_summary", "critical_issues", "health_status", "recommendations",
            "summary", "status", "results", "details", "metrics", "analysis"
        ]
        
        # Add sections in priority order
        for priority_name in llm_priority_order:
            if priority_name in document.sections:
                optimized.add_section(
                    priority_name, 
                    document.sections[priority_name], 
                    document.priorities.get(priority_name, ContentPriority.IMPORTANT)
                )
        
        # Add remaining sections
        for section_name, content in document.sections.items():
            if section_name not in llm_priority_order:
                optimized.add_section(
                    section_name, 
                    content, 
                    document.priorities.get(section_name, ContentPriority.INFO)
                )
        
        return optimized


# Global quality assurance instance
_quality_assurance = TOONQualityAssurance()


def get_quality_assurance() -> TOONQualityAssurance:
    """Get the global quality assurance instance."""
    return _quality_assurance


# Convenience functions
def validate_toon_document(document: TOONDocument, template: Optional[TOONTemplate] = None) -> QualityReport:
    """Validate a TOON document and generate quality report."""
    qa = get_quality_assurance()
    return qa.generate_quality_report(document, template)


def optimize_toon_document(document: TOONDocument, template: Optional[TOONTemplate] = None) -> Tuple[TOONDocument, QualityReport]:
    """Optimize a TOON document and return quality report."""
    qa = get_quality_assurance()
    report = qa.generate_quality_report(document, template)
    optimized_doc = qa.apply_quality_fixes(document, report)
    return optimized_doc, report


def check_document_quality(document: TOONDocument, min_quality_level: QualityLevel = QualityLevel.GOOD) -> bool:
    """Check if document meets minimum quality requirements."""
    qa = get_quality_assurance()
    report = qa.generate_quality_report(document)
    
    quality_hierarchy = {
        QualityLevel.FAILED: 0,
        QualityLevel.POOR: 1,
        QualityLevel.ACCEPTABLE: 2,
        QualityLevel.GOOD: 3,
        QualityLevel.EXCELLENT: 4
    }
    
    document_level = quality_hierarchy[report.quality_level]
    required_level = quality_hierarchy[min_quality_level]
    
    return document_level >= required_level