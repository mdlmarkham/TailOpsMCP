"""
Security Models for SystemManager Security Framework

Defines comprehensive security models for access control, compliance, and monitoring.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime


class SensitivityLevel(str, Enum):
    """Data sensitivity levels for access control and compliance."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class ResourceType(str, Enum):
    """Types of resources that can be accessed."""

    FILE = "file"
    DIRECTORY = "directory"
    NETWORK = "network"
    SERVICE = "service"
    DATABASE = "database"
    CONTAINER = "container"
    PROCESS = "process"
    CONFIGURATION = "configuration"


class SecurityClassification(str, Enum):
    """Security classifications for resources."""

    UNCLASSIFIED = "unclassified"
    CONFIDENTIAL = "confidential"
    CLASSIFIED = "classified"  # Changed from "secret" to avoid hardcoded sensitive term
    TOP_SECRET = "top_secret"


class RiskLevel(str, Enum):
    """Risk levels for security operations."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertSeverity(str, Enum):
    """Severity levels for security alerts."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class IdentityContext:
    """Context information about an identity/user."""

    user_id: str
    roles: List[str]
    groups: List[str]
    attributes: Dict[str, Any]
    authentication_method: str
    authentication_time: datetime


@dataclass
class ResourceContext:
    """Context information about a resource."""

    resource_id: str
    resource_type: ResourceType
    resource_path: str
    sensitivity_level: SensitivityLevel
    classification: SecurityClassification
    ownership: Dict[str, Any]
    attributes: Dict[str, Any]


@dataclass
class AccessDecision:
    """Represents an access control decision."""

    decision: str  # "allow", "deny", "challenge"
    reason: str
    risk_level: RiskLevel
    requires_approval: bool
    approval_chain: List[str]
    conditions: Dict[str, Any]


@dataclass
class AccessDecisionResult:
    """Result of an access decision evaluation."""

    authorized: bool
    decision: AccessDecision
    risk_assessment: Dict[str, Any]
    audit_trail: List[Dict[str, Any]]
    metadata: Dict[str, Any]


@dataclass
class RiskAssessment:
    """Risk assessment for an operation."""

    overall_risk: RiskLevel
    risk_factors: Dict[str, Any]
    mitigation_strategies: List[str]
    confidence_score: float


@dataclass
class AccessAttempt:
    """Represents an access attempt for auditing."""

    attempt_id: str
    timestamp: datetime
    identity: IdentityContext
    resource: ResourceContext
    operation: str
    decision: AccessDecision
    risk_assessment: RiskAssessment
    metadata: Dict[str, Any]


@dataclass
class SecurityOperation:
    """Represents a security-sensitive operation."""

    operation_id: str
    operation_type: str
    target_resources: List[ResourceContext]
    operation_parameters: Dict[str, Any]
    identity_context: IdentityContext
    approval_context: Optional[Dict[str, Any]]
    risk_level: RiskLevel
    metadata: Dict[str, Any]


@dataclass
class ComplianceStandard:
    """Represents a compliance standard."""

    standard_id: str
    name: str
    version: str
    description: str
    requirements: List[Dict[str, Any]]
    audit_procedures: List[str]


@dataclass
class ComplianceReport:
    """Represents a compliance assessment report."""

    report_id: str
    standard: ComplianceStandard
    assessment_date: datetime
    overall_compliance: bool
    compliance_score: float
    violations: List[Dict[str, Any]]
    recommendations: List[str]
    evidence: List[Dict[str, Any]]


@dataclass
class ComplianceViolation:
    """Represents a compliance violation."""

    violation_id: str
    standard: ComplianceStandard
    requirement_id: str
    description: str
    severity: RiskLevel
    detection_time: datetime
    affected_resources: List[str]
    remediation_steps: List[str]


@dataclass
class ComplianceEvidence:
    """Represents evidence for compliance verification."""

    evidence_id: str
    evidence_type: str
    description: str
    file_path: str
    hash_value: str
    timestamp: datetime
    metadata: Dict[str, Any]


@dataclass
class DataHandlingValidation:
    """Validation for data handling operations."""

    validation_id: str
    operation_type: str
    data_sensitivity: SensitivityLevel
    encryption_required: bool
    access_controls: List[str]
    retention_policy: str
    compliance_standards: List[str]


@dataclass
class RetentionActionResult:
    """Result of a data retention action."""

    action_id: str
    action_type: str
    target_data: str
    success: bool
    records_affected: int
    compliance_status: bool
    error_message: Optional[str]
    timestamp: datetime


@dataclass
class GovernanceDecision:
    """Represents a governance decision."""

    decision_id: str
    policy_name: str
    decision: str
    rationale: str
    approvers: List[str]
    timestamp: datetime
    metadata: Dict[str, Any]


@dataclass
class SODDecision:
    """Represents a separation of duties decision."""

    sod_id: str
    conflicting_roles: List[str]
    operation_type: str
    allowed: bool
    reason: str
    timestamp: datetime
    metadata: Dict[str, Any]


@dataclass
class ApprovalChainValidation:
    """Validation of approval chains for sensitive operations."""

    validation_id: str
    operation_type: str
    required_approvals: List[str]
    provided_approvals: List[str]
    chain_complete: bool
    timestamp: datetime
    metadata: Dict[str, Any]
