"""
Validation Data Models for Security Validation Framework.

Provides structured data models for validation results, security posture,
and validation contexts throughout the security pipeline.

Orchestrates existing security components:
- src.security.scanner (vulnerability & secrets scanning)
- src.services.policy_gate (policy enforcement)
- src.auth.middleware (authentication & authorization)
- src.utils.audit (audit logging)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class ValidationPhase(Enum):
    """Security validation phases."""

    PRE_EXECUTION = "pre_execution"
    RUNTIME = "runtime"
    POST_EXECUTION = "post_execution"


class SecurityPosture(str, Enum):
    """Security posture levels."""

    SECURE = "secure"  # All validations passed
    WARNING = "warning"  # Minor issues, operation allowed
    RISKY = "risky"  # Significant issues, manual review needed
    BLOCKED = "blocked"  # Critical issues, operation blocked
    UNKNOWN = "unknown"  # Unable to determine posture


class ValidationCategory(Enum):
    """Categories of validation checks."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    POLICY = "policy"
    VULNERABILITY = "vulnerability"
    SECRETS = "secrets"
    INPUT_VALIDATION = "input_validation"
    COMPLIANCE = "compliance"
    RATE_LIMITING = "rate_limiting"
    INFRASTRUCTURE = "infrastructure"
    NETWORK = "network"


class ValidationStatus(Enum):
    """Validation result status."""

    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class ValidationFinding:
    """Individual validation finding."""

    category: ValidationCategory
    status: ValidationStatus
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    recommendation: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    cvss_score: Optional[float] = None
    cve_references: Optional[List[str]] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ValidationResult:
    """Result of a validation check."""

    validator_name: str
    category: ValidationCategory
    status: ValidationStatus
    security_posture: SecurityPosture
    findings: List[ValidationFinding] = field(default_factory=list)
    execution_time_ms: float = 0.0
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def add_finding(self, finding: ValidationFinding) -> None:
        """Add a finding to this validation result."""
        self.findings.append(finding)

    def get_critical_findings(self) -> List[ValidationFinding]:
        """Get all critical findings."""
        return [f for f in self.findings if f.severity == "critical"]

    def get_failed_findings(self) -> List[ValidationFinding]:
        """Get all failed findings."""
        return [f for f in self.findings if f.status == ValidationStatus.FAILED]


@dataclass
class ValidationContext:
    """Context information for validation."""

    tool_name: str
    operation: str
    target_id: str
    user_agent: str
    user_scopes: List[str]
    parameters: Dict[str, Any]
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary."""
        return {
            "tool_name": self.tool_name,
            "operation": self.operation,
            "target_id": self.target_id,
            "user_agent": self.user_agent,
            "user_scopes": self.user_scopes,
            "parameters": self._sanitize_parameters(),
            "session_id": self.session_id,
            "ip_address": self.ip_address,
            "timestamp": self.timestamp.isoformat(),
        }

    def _sanitize_parameters(self) -> Dict[str, Any]:
        """Sanitize parameters for logging."""
        sanitized = {}
        for key, value in self.parameters.items():
            if any(
                secret in key.lower()
                for secret in ["token", "password", "secret", "key"]
            ):
                sanitized[key] = "<REDACTED>"
            else:
                sanitized[key] = value
        return sanitized


@dataclass
class SecurityValidationSummary:
    """Complete security validation summary."""

    overall_posture: SecurityPosture
    validation_results: List[ValidationResult]
    total_findings: int
    critical_findings: int
    high_findings: int
    execution_time_ms: float
    recommendation: str
    allowed_to_proceed: bool
    error_details: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Convert summary to dictionary."""
        return {
            "overall_posture": self.overall_posture.value,
            "validation_results": [
                self._result_to_dict(r) for r in self.validation_results
            ],
            "total_findings": self.total_findings,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "execution_time_ms": self.execution_time_ms,
            "recommendation": self.recommendation,
            "allowed_to_proceed": self.allowed_to_proceed,
            "error_details": self.error_details,
            "timestamp": self.timestamp.isoformat(),
        }

    def _result_to_dict(self, result: ValidationResult) -> Dict[str, Any]:
        """Convert validation result to dictionary."""
        return {
            "validator_name": result.validator_name,
            "category": result.category.value,
            "status": result.status.value,
            "security_posture": result.security_posture.value,
            "findings": [self._finding_to_dict(f) for f in result.findings],
            "execution_time_ms": result.execution_time_ms,
            "error_message": result.error_message,
            "metadata": result.metadata,
            "timestamp": result.timestamp.isoformat(),
        }

    def _finding_to_dict(self, finding: ValidationFinding) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "category": finding.category.value,
            "status": finding.status.value,
            "severity": finding.severity,
            "title": finding.title,
            "description": finding.description,
            "recommendation": finding.recommendation,
            "evidence": finding.evidence,
            "cvss_score": finding.cvss_score,
            "cve_references": finding.cve_references,
            "timestamp": finding.timestamp.isoformat(),
        }

    def to_json(self) -> str:
        """Convert summary to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)


# Export all models
__all__ = [
    "ValidationPhase",
    "SecurityPosture",
    "ValidationCategory",
    "ValidationStatus",
    "ValidationFinding",
    "ValidationResult",
    "ValidationContext",
    "SecurityValidationSummary",
]
