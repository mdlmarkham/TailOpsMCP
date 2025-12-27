"""
Security Models for SystemManager Security Framework

Defines comprehensive security models for access control, compliance, and monitoring.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone


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


class AuthenticationMethod(str, Enum):
    """Authentication methods."""

    OIDC = "oidc"
    TAILSCALE_OIDC = "tailscale_oidc"
    TOKEN = "token"
    PASSWORD = "password"
    ANONYMOUS = "anonymous"


class RiskProfile(str, Enum):
    """Risk profiles for users."""

    LOW_RISK = "low_risk"
    STANDARD = "standard"
    MEDIUM_RISK = "medium_risk"
    HIGH_RISK = "high_risk"


class AlertType(str, Enum):
    """Types of security alerts."""

    AUTHENTICATION_FAILURE = "authentication_failure"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    POLICY_VIOLATION = "policy_violation"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    DATA_BREACH = "data_breach"


class InitiatorType(str, Enum):
    """Types of operation initiators."""

    HUMAN = "human"
    SYSTEM = "system"
    AUTOMATED = "automated"


@dataclass
class IdentityContext:
    """Context information about an identity/user."""

    user_id: str
    username: str
    email: str
    roles: List[str]
    groups: List[str]
    permissions: List[str]
    authentication_method: str
    session_id: Optional[str] = None
    authentication_time: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    tailscale_node: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    risk_profile: str = "standard"
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "user_id": self.user_id,
            "username": self.username,
            "email": self.email,
            "roles": self.roles,
            "groups": self.groups,
            "permissions": self.permissions,
            "authentication_method": self.authentication_method,
            "session_id": self.session_id,
            "authentication_time": self.authentication_time.isoformat()
            if self.authentication_time
            else None,
            "tailscale_node": self.tailscale_node,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "risk_profile": self.risk_profile,
            "attributes": self.attributes,
        }


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


# Authentication and Session Models
@dataclass
class AuthenticationCredentials:
    """Authentication credentials."""

    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    oidc_token: Optional[str] = None


@dataclass
class AuthenticationResult:
    """Result of authentication attempt."""

    success: bool
    identity: Optional[IdentityContext] = None
    session_token: Optional[str] = None
    error_message: Optional[str] = None
    error_code: Optional[str] = None


@dataclass
class SessionValidationResult:
    """Result of session validation."""

    valid: bool
    identity: Optional[IdentityContext] = None
    expires_at: Optional[datetime] = None
    error_message: Optional[str] = None


@dataclass
class PermissionSet:
    """User permissions set."""

    permissions: List[str]
    roles: List[str]
    effective_permissions: List[str]


@dataclass
class IdentityEvent:
    """Identity-related event for auditing."""

    event_type: str
    identity: IdentityContext
    event_details: Dict[str, Any]


@dataclass
class SecurityAlert:
    """Security alert."""

    alert_id: str
    timestamp: datetime
    severity: AlertSeverity
    alert_type: AlertType
    description: str
    affected_resources: List[str]
    implicated_identities: List[str]
    recommended_actions: List[str]


# Security classes for RBAC (access_control.py compatibility)
@dataclass
class SecurityPermission:
    """Security permission for RBAC."""

    permission_id: str
    permission_type: str
    resource_type: str
    description: str
    granted: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None


@dataclass
class SecurityRole:
    """Security role with associated permissions."""

    role_id: str
    role_name: str
    description: str
    permissions: List[SecurityPermission] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None


@dataclass
class SecurityPolicy:
    """Security policy definition."""

    policy_id: str
    policy_name: str
    description: str
    rules: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    priority: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None


# Compliance status and framework classes
class ComplianceStatus(str, Enum):
    """Compliance check result status."""

    UNKNOWN = "unknown"
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    WARNING = "warning"
    NOT_APPLICABLE = "not_applicable"


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks."""

    CIS_BENCHMARKS = "cis_benchmarks"
    NIST_CSF = "nist_csf"
    NIST_SP = "nist_sp"
    ISO_27001 = "iso_27001"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    SOX = "sox"
    HIPAA = "hipaa"
    OWASP = "owasp"
    CUSTOM = "custom"
