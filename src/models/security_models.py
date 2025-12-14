"""
Enhanced security data models for comprehensive security and identity controls.

This module defines the core data structures for:
- Security audit logging and trace
- Identity and access management
- Security monitoring and threat detection
- Compliance and governance
"""

from __future__ import annotations

import datetime
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field
from pydantic import BaseModel, Field


class InitiatorType(str, Enum):
    """Type of operation initiator."""
    HUMAN = "human"
    LLM = "llm"
    SYSTEM = "system"
    AUTOMATION = "automation"


class RiskLevel(str, Enum):
    """Risk level for operations."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuthenticationMethod(str, Enum):
    """Authentication method used."""
    TAILSCALE_OIDC = "tailscale_oidc"
    TOKEN = "token"
    API_KEY = "api_key"
    CERTIFICATE = "certificate"
    ANONYMOUS = "anonymous"


class AlertSeverity(str, Enum):
    """Security alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(str, Enum):
    """Types of security alerts."""
    FAILED_AUTHENTICATION = "failed_authentication"
    BRUTE_FORCE = "brute_force"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_EXFILTRATION = "data_exfiltration"
    POLICY_VIOLATION = "policy_violation"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    COMPLIANCE_VIOLATION = "compliance_violation"


class ComplianceStandard(str, Enum):
    """Compliance standards."""
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    HIPAA = "hipaa"


class ResourceType(str, Enum):
    """Resource types for access control."""
    SYSTEM = "system"
    TARGET = "target"
    CONFIGURATION = "configuration"
    DATA = "data"
    LOGS = "logs"
    AUDIT = "audit"
    POLICY = "policy"
    WORKFLOW = "workflow"


class SensitivityLevel(str, Enum):
    """Data sensitivity levels."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class SecurityClassification(str, Enum):
    """Security classification levels."""
    UNCLASSIFIED = "unclassified"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    TOP_SECRET = "top_secret"


class AccessDecision(str, Enum):
    """Access control decisions."""
    ALLOW = "allow"
    DENY = "deny"
    CONDITIONAL = "conditional"
    REVIEW_REQUIRED = "review_required"


@dataclass
class ResourceContext:
    """Resource context for access control."""
    resource_type: ResourceType
    resource_id: str
    resource_path: str
    sensitivity_level: SensitivityLevel
    ownership: Dict[str, Any] = field(default_factory=dict)
    security_classification: SecurityClassification = SecurityClassification.UNCLASSIFIED
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "resource_type": self.resource_type.value,
            "resource_id": self.resource_id,
            "resource_path": self.resource_path,
            "sensitivity_level": self.sensitivity_level.value,
            "ownership": self.ownership,
            "security_classification": self.security_classification.value
        }


@dataclass
class IdentityContext:
    """Complete identity context for operations."""
    user_id: str
    username: str
    email: Optional[str] = None
    groups: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    authentication_method: AuthenticationMethod = AuthenticationMethod.ANONYMOUS
    session_id: Optional[str] = None
    tailscale_node: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    risk_profile: str = "standard"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "user_id": self.user_id,
            "username": self.username,
            "email": self.email,
            "groups": self.groups,
            "roles": self.roles,
            "permissions": self.permissions,
            "authentication_method": self.authentication_method.value,
            "session_id": self.session_id,
            "tailscale_node": self.tailscale_node,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "risk_profile": self.risk_profile
        }


@dataclass
class ApprovalContext:
    """Context for operation approvals."""
    approval_id: str
    approver_id: str
    approval_timestamp: datetime.datetime
    approval_method: str
    conditions: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "approval_id": self.approval_id,
            "approver_id": self.approver_id,
            "approval_timestamp": self.approval_timestamp.isoformat(),
            "approval_method": self.approval_method,
            "conditions": self.conditions
        }


@dataclass
class SecurityOperation:
    """Complete operation audit record."""
    operation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    initiator_type: InitiatorType = InitiatorType.HUMAN
    initiator_identity: Optional[IdentityContext] = None
    operation_type: str = ""
    target_resources: List[ResourceContext] = field(default_factory=list)
    operation_parameters: Dict[str, Any] = field(default_factory=dict)
    risk_level: RiskLevel = RiskLevel.LOW
    approval_context: Optional[ApprovalContext] = None
    correlation_id: Optional[str] = None
    session_id: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    outcome: Optional[OperationOutcome] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "operation_id": self.operation_id,
            "timestamp": self.timestamp.isoformat(),
            "initiator_type": self.initiator_type.value,
            "initiator_identity": self.initiator_identity.to_dict() if self.initiator_identity else None,
            "operation_type": self.operation_type,
            "target_resources": [r.to_dict() for r in self.target_resources],
            "operation_parameters": self.operation_parameters,
            "risk_level": self.risk_level.value,
            "approval_context": self.approval_context.to_dict() if self.approval_context else None,
            "correlation_id": self.correlation_id,
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "outcome": self.outcome.to_dict() if self.outcome else None
        }


@dataclass
class OperationOutcome:
    """Outcome of a security operation."""
    outcome: str  # success, failure, denied, etc.
    outcome_details: Dict[str, Any] = field(default_factory=dict)
    duration_ms: Optional[int] = None
    error_message: Optional[str] = None
    error_code: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "outcome": self.outcome,
            "outcome_details": self.outcome_details,
            "duration_ms": self.duration_ms,
            "error_message": self.error_message,
            "error_code": self.error_code
        }


@dataclass
class IdentityEvent:
    """Identity-related event for audit logging."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    event_type: str = ""  # login, logout, session_expired, etc.
    identity: IdentityContext
    event_details: Dict[str, Any] = field(default_factory=dict)
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "identity": self.identity.to_dict(),
            "event_details": self.event_details,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent
        }


@dataclass
class PolicyDecision:
    """Policy decision for audit logging."""
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    policy_name: str = ""
    decision: str  # allow, deny, conditional
    reason: str = ""
    policy_context: Dict[str, Any] = field(default_factory=dict)
    enforcement_details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "decision_id": self.decision_id,
            "timestamp": self.timestamp.isoformat(),
            "policy_name": self.policy_name,
            "decision": self.decision,
            "reason": self.reason,
            "policy_context": self.policy_context,
            "enforcement_details": self.enforcement_details
        }


@dataclass
class SecurityViolation:
    """Security violation event."""
    violation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    violation_type: str = ""  # unauthorized_access, policy_breach, etc.
    severity: AlertSeverity = AlertSeverity.MEDIUM
    description: str = ""
    affected_resources: List[str] = field(default_factory=list)
    implicated_identities: List[str] = field(default_factory=list)
    violation_details: Dict[str, Any] = field(default_factory=dict)
    automated_response: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "violation_id": self.violation_id,
            "timestamp": self.timestamp.isoformat(),
            "violation_type": self.violation_type,
            "severity": self.severity.value,
            "description": self.description,
            "affected_resources": self.affected_resources,
            "implicated_identities": self.implicated_identities,
            "violation_details": self.violation_details,
            "automated_response": self.automated_response
        }


@dataclass
class AccessAttempt:
    """Access attempt for audit logging."""
    attempt_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    identity: IdentityContext
    resource: ResourceContext
    action: str
    decision: AccessDecision = AccessDecision.DENY
    decision_reason: str = ""
    risk_score: Optional[float] = None
    enforcement_details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "attempt_id": self.attempt_id,
            "timestamp": self.timestamp.isoformat(),
            "identity": self.identity.to_dict(),
            "resource": self.resource.to_dict(),
            "action": self.action,
            "decision": self.decision.value,
            "decision_reason": self.decision_reason,
            "risk_score": self.risk_score,
            "enforcement_details": self.enforcement_details
        }


@dataclass
class SecurityAlert:
    """Security alert with severity and response."""
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    severity: AlertSeverity = AlertSeverity.MEDIUM
    alert_type: AlertType = AlertType.ANOMALOUS_BEHAVIOR
    description: str = ""
    affected_resources: List[str] = field(default_factory=list)
    implicated_identities: List[str] = field(default_factory=list)
    status: str = "open"  # open, investigating, resolved, closed
    assigned_to: Optional[str] = None
    resolved_at: Optional[datetime.datetime] = None
    resolution_details: Optional[str] = None
    recommended_actions: List[str] = field(default_factory=list)
    automated_response: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.value,
            "alert_type": self.alert_type.value,
            "description": self.description,
            "affected_resources": self.affected_resources,
            "implicated_identities": self.implicated_identities,
            "status": self.status,
            "assigned_to": self.assigned_to,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolution_details": self.resolution_details,
            "recommended_actions": self.recommended_actions,
            "automated_response": self.automated_response
        }


# Pydantic models for API responses
class AuthenticationCredentials(BaseModel):
    """Authentication credentials model."""
    username: str
    password: Optional[str] = None
    token: Optional[str] = None
    certificate: Optional[str] = None
    oidc_token: Optional[str] = None


class AuthenticationResult(BaseModel):
    """Authentication result model."""
    success: bool
    identity: Optional[IdentityContext] = None
    session_token: Optional[str] = None
    error_message: Optional[str] = None
    error_code: Optional[str] = None


class SessionValidationResult(BaseModel):
    """Session validation result model."""
    valid: bool
    identity: Optional[IdentityContext] = None
    expires_at: Optional[datetime.datetime] = None
    error_message: Optional[str] = None


class PermissionSet(BaseModel):
    """Permission set model."""
    permissions: List[str]
    roles: List[str]
    effective_permissions: List[str]


class AccessDecisionResult(BaseModel):
    """Access control decision result."""
    decision: AccessDecision
    reason: str
    conditions: List[str] = []
    requires_approval: bool = False
    risk_score: Optional[float] = None


class RiskAssessment(BaseModel):
    """Risk assessment result."""
    overall_risk: RiskLevel
    risk_factors: Dict[str, Any]
    mitigation_suggestions: List[str]
    requires_approval: bool = False


class ComplianceViolation(BaseModel):
    """Compliance violation model."""
    standard: ComplianceStandard
    violation_type: str
    description: str
    severity: AlertSeverity
    remediation_required: bool = True


class ComplianceReport(BaseModel):
    """Comprehensive compliance report."""
    standard: ComplianceStandard
    assessment_date: datetime.datetime
    compliance_score: float
    violations: List[ComplianceViolation]
    recommendations: List[str]
    evidence_artifacts: List[str]
    next_assessment: datetime.datetime


# Threat Detection Models
@dataclass
class FailedAttempt:
    """Failed authentication attempt."""
    attempt_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    username: Optional[str] = None
    source_ip: Optional[str] = None
    failure_reason: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "attempt_id": self.attempt_id,
            "timestamp": self.timestamp.isoformat(),
            "username": self.username,
            "source_ip": self.source_ip,
            "failure_reason": self.failure_reason
        }


@dataclass
class AccessPattern:
    """Access pattern for monitoring."""
    pattern_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    identity: Optional[IdentityContext] = None
    resource_id: str = ""
    action: str = ""
    source_ip: Optional[str] = None
    success: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "pattern_id": self.pattern_id,
            "timestamp": self.timestamp.isoformat(),
            "identity": self.identity.to_dict() if self.identity else None,
            "resource_id": self.resource_id,
            "action": self.action,
            "source_ip": self.source_ip,
            "success": self.success
        }


@dataclass
class BruteForceAttack:
    """Brute force attack detection."""
    attack_type: str
    source_ip: Optional[str] = None
    source_ips: Optional[List[str]] = None
    target_usernames: Optional[List[str]] = None
    target_username: Optional[str] = None
    attempt_count: int = 0
    time_window_seconds: int = 0
    severity: AlertSeverity = AlertSeverity.MEDIUM
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "attack_type": self.attack_type,
            "source_ip": self.source_ip,
            "source_ips": self.source_ips,
            "target_usernames": self.target_usernames,
            "target_username": self.target_username,
            "attempt_count": self.attempt_count,
            "time_window_seconds": self.time_window_seconds,
            "severity": self.severity.value
        }


@dataclass
class PrivilegeAbuse:
    """Privilege abuse detection."""
    abuse_type: str
    implicated_users: List[str] = field(default_factory=list)
    operation_count: int = 0
    target_privileges: List[str] = field(default_factory=list)
    severity: AlertSeverity = AlertSeverity.MEDIUM
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "abuse_type": self.abuse_type,
            "implicated_users": self.implicated_users,
            "operation_count": self.operation_count,
            "target_privileges": self.target_privileges,
            "severity": self.severity.value
        }


@dataclass
class DataDumping:
    """Data dumping detection."""
    dumping_type: str
    implicated_users: List[str] = field(default_factory=list)
    affected_resources: List[str] = field(default_factory=list)
    total_data_size: int = 0
    operation_count: int = 0
    severity: AlertSeverity = AlertSeverity.MEDIUM
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "dumping_type": self.dumping_type,
            "implicated_users": self.implicated_users,
            "affected_resources": self.affected_resources,
            "total_data_size": self.total_data_size,
            "operation_count": self.operation_count,
            "severity": self.severity.value
        }


@dataclass
class LateralMovement:
    """Lateral movement detection."""
    movement_type: str
    implicated_user: str = ""
    target_resources: List[str] = field(default_factory=list)
    source_ips: List[str] = field(default_factory=list)
    access_count: int = 0
    time_span_minutes: float = 0.0
    severity: AlertSeverity = AlertSeverity.MEDIUM
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "movement_type": self.movement_type,
            "implicated_user": self.implicated_user,
            "target_resources": self.target_resources,
            "source_ips": self.source_ips,
            "access_count": self.access_count,
            "time_span_minutes": self.time_span_minutes,
            "severity": self.severity.value
        }


@dataclass
class Anomaly:
    """Anomaly detection result."""
    anomaly_type: str
    implicated_identity: str = ""
    description: str = ""
    severity: AlertSeverity = AlertSeverity.MEDIUM
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "anomaly_type": self.anomaly_type,
            "implicated_identity": self.implicated_identity,
            "description": self.description,
            "severity": self.severity.value,
            "details": self.details
        }