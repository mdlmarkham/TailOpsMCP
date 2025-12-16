"""
Workflow Approval and Governance System for TailOpsMCP.

Provides comprehensive approval workflows, governance policies,
and compliance validation for workflow execution.
"""

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from enum import Enum

from src.models.workflow_models import (
    WorkflowBlueprint,
    WorkflowExecution,
    WorkflowStep,
    ApprovalStatus,
    ApprovalRecord,
    ExecutionStatus,
)
from src.models.policy_models import PolicyContext, PolicyDecision
from src.models.event_models import (
    SystemEvent,
    EventType,
    EventSeverity,
    EventSource,
    EventCategory,
)
from src.utils.audit import AuditLogger


logger = logging.getLogger(__name__)


class ApprovalType(Enum):
    """Types of approvals."""

    MANUAL = "manual"
    AUTOMATIC = "automatic"
    CONDITIONAL = "conditional"
    ESCALATION = "escalation"


class GovernancePolicy(Enum):
    """Governance policy types."""

    SECURITY_VALIDATION = "security_validation"
    RESOURCE_LIMIT = "resource_limit"
    TIME_WINDOW = "time_window"
    USER_PERMISSION = "user_permission"
    CHANGE_APPROVAL = "change_approval"
    COMPLIANCE_CHECK = "compliance_check"


class ComplianceStandard(Enum):
    """Compliance standards."""

    SOX = "sox"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    ISO27001 = "iso27001"
    NIST = "nist"
    CUSTOM = "custom"


@dataclass
class ApprovalRequest:
    """Approval request details."""

    approval_id: str
    step_id: str
    step_name: str
    workflow_name: str
    execution_id: str
    requester: str
    approvers: List[str]
    approval_type: ApprovalType
    description: str
    parameters: Dict[str, Any]
    created_at: datetime
    expires_at: Optional[datetime]
    escalation_rules: Optional[Dict[str, Any]] = None
    comments: List[str] = None

    def __post_init__(self):
        if self.comments is None:
            self.comments = []


@dataclass
class ComplianceResult:
    """Result of compliance validation."""

    compliant: bool
    standard: ComplianceStandard
    violations: List[str] = None
    warnings: List[str] = None
    recommendations: List[str] = None

    def __post_init__(self):
        if self.violations is None:
            self.violations = []
        if self.warnings is None:
            self.warnings = []
        if self.recommendations is None:
            self.recommendations = []


@dataclass
class GovernanceRule:
    """Governance rule definition."""

    rule_id: str
    name: str
    description: str
    policy_type: GovernancePolicy
    enabled: bool = True
    conditions: Dict[str, Any] = None
    actions: List[str] = None
    severity: str = "medium"

    def __post_init__(self):
        if self.conditions is None:
            self.conditions = {}
        if self.actions is None:
            self.actions = []


class ApprovalSystem:
    """Manage workflow approvals."""

    def __init__(self, event_collector=None, audit_logger=None):
        """Initialize approval system."""
        self.event_collector = event_collector
        self.audit_logger = audit_logger or AuditLogger()
        self._approval_requests: Dict[str, ApprovalRequest] = {}
        self._approval_history: List[ApprovalRecord] = []

    async def request_approval(
        self, execution: WorkflowExecution, step: WorkflowStep
    ) -> ApprovalRequest:
        """Request approval for workflow step."""
        approval_id = str(uuid.uuid4())

        # Check if approval is already pending
        existing_approval = self._find_pending_approval(
            execution.execution_id, step.step_id
        )
        if existing_approval:
            return existing_approval

        # Create approval request
        approval_request = ApprovalRequest(
            approval_id=approval_id,
            step_id=step.step_id,
            step_name=step.name,
            workflow_name=execution.blueprint_name,
            execution_id=execution.execution_id,
            requester=execution.created_by,
            approvers=step.approvers,
            approval_type=ApprovalType.MANUAL,
            description=f"Approval required for step: {step.name}",
            parameters=step.parameters,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )

        # Store approval request
        self._approval_requests[approval_id] = approval_request

        # Emit event
        await self._emit_approval_event(
            "approval_requested",
            {
                "approval_id": approval_id,
                "execution_id": execution.execution_id,
                "step_id": step.step_id,
                "approvers": step.approvers,
            },
        )

        # Audit log
        await self.audit_logger.log_event(
            action="APPROVAL_REQUESTED",
            resource=f"workflow:{execution.blueprint_name}",
            details={
                "approval_id": approval_id,
                "step_id": step.step_id,
                "execution_id": execution.execution_id,
                "requestor": execution.created_by,
            },
        )

        return approval_request

    async def approve_step(
        self, approval_id: str, approver: str, comment: str = ""
    ) -> bool:
        """Approve workflow step."""
        if approval_id not in self._approval_requests:
            return False

        approval_request = self._approval_requests[approval_id]

        # Check if approver is authorized
        if approver not in approval_request.approvers:
            logger.warning(f"Unauthorized approval attempt by {approver}")
            await self._emit_approval_event(
                "unauthorized_approval_attempt",
                {
                    "approval_id": approval_id,
                    "approver": approver,
                    "authorized_approvers": approval_request.approvers,
                },
            )
            return False

        # Create approval record
        approval_record = ApprovalRecord(
            approval_id=approval_id,
            step_id=approval_request.step_id,
            approver=approver,
            status=ApprovalStatus.APPROVED,
            comment=comment,
            responded_at=datetime.now(timezone.utc),
        )

        # Update execution
        execution = await self._get_execution(approval_request.execution_id)
        if execution:
            execution.approvals.append(approval_record)

        # Remove from pending requests
        del self._approval_requests[approval_id]

        # Emit event
        await self._emit_approval_event(
            "step_approved",
            {
                "approval_id": approval_id,
                "execution_id": approval_request.execution_id,
                "step_id": approval_request.step_id,
                "approver": approver,
                "comment": comment,
            },
        )

        # Audit log
        await self.audit_logger.log_event(
            action="STEP_APPROVED",
            resource=f"workflow:{approval_request.workflow_name}",
            details={
                "approval_id": approval_id,
                "step_id": approval_request.step_id,
                "execution_id": approval_request.execution_id,
                "approver": approver,
                "comment": comment,
            },
        )

        return True

    async def reject_step(self, approval_id: str, approver: str, reason: str) -> bool:
        """Reject workflow step."""
        if approval_id not in self._approval_requests:
            return False

        approval_request = self._approval_requests[approval_id]

        # Check if approver is authorized
        if approver not in approval_request.approvers:
            logger.warning(f"Unauthorized rejection attempt by {approver}")
            await self._emit_approval_event(
                "unauthorized_rejection_attempt",
                {
                    "approval_id": approval_id,
                    "approver": approver,
                    "authorized_approvers": approval_request.approvers,
                },
            )
            return False

        # Create rejection record
        approval_record = ApprovalRecord(
            approval_id=approval_id,
            step_id=approval_request.step_id,
            approver=approver,
            status=ApprovalStatus.REJECTED,
            comment=f"Rejected: {reason}",
            responded_at=datetime.now(timezone.utc),
        )

        # Update execution
        execution = await self._get_execution(approval_request.execution_id)
        if execution:
            execution.approvals.append(approval_record)

        # Remove from pending requests
        del self._approval_requests[approval_id]

        # Emit event
        await self._emit_approval_event(
            "step_rejected",
            {
                "approval_id": approval_id,
                "execution_id": approval_request.execution_id,
                "step_id": approval_request.step_id,
                "approver": approver,
                "reason": reason,
            },
        )

        # Audit log
        await self.audit_logger.log_event(
            action="STEP_REJECTED",
            resource=f"workflow:{approval_request.workflow_name}",
            details={
                "approval_id": approval_id,
                "step_id": approval_request.step_id,
                "execution_id": approval_request.execution_id,
                "approver": approver,
                "reason": reason,
            },
        )

        return True

    async def get_pending_approvals(self, approver: str) -> List[Dict[str, Any]]:
        """Get pending approvals for user."""
        pending = []

        for approval_request in self._approval_requests.values():
            if approver in approval_request.approvers:
                pending.append(
                    {
                        "approval_id": approval_request.approval_id,
                        "step_id": approval_request.step_id,
                        "step_name": approval_request.step_name,
                        "workflow_name": approval_request.workflow_name,
                        "execution_id": approval_request.execution_id,
                        "requester": approval_request.requester,
                        "description": approval_request.description,
                        "created_at": approval_request.created_at.isoformat(),
                        "expires_at": approval_request.expires_at.isoformat()
                        if approval_request.expires_at
                        else None,
                        "parameters": approval_request.parameters,
                    }
                )

        return pending

    async def get_approval_history(
        self, execution_id: Optional[str] = None, approver: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get approval history."""
        # This would load from persistent storage
        # For now, return empty list as placeholder
        return []

    async def cancel_approval(self, approval_id: str, reason: str = "") -> bool:
        """Cancel approval request."""
        if approval_id not in self._approval_requests:
            return False

        approval_request = self._approval_requests[approval_id]

        # Create cancellation record
        approval_record = ApprovalRecord(
            approval_id=approval_id,
            step_id=approval_request.step_id,
            approver="system",
            status=ApprovalStatus.EXPIRED,
            comment=f"Cancelled: {reason}",
            responded_at=datetime.now(timezone.utc),
        )

        # Update execution
        execution = await self._get_execution(approval_request.execution_id)
        if execution:
            execution.approvals.append(approval_record)

        # Remove from pending requests
        del self._approval_requests[approval_id]

        # Emit event
        await self._emit_approval_event(
            "approval_cancelled",
            {
                "approval_id": approval_id,
                "execution_id": approval_request.execution_id,
                "reason": reason,
            },
        )

        return True

    def _find_pending_approval(
        self, execution_id: str, step_id: str
    ) -> Optional[ApprovalRequest]:
        """Find pending approval for execution and step."""
        for approval_request in self._approval_requests.values():
            if (
                approval_request.execution_id == execution_id
                and approval_request.step_id == step_id
            ):
                return approval_request
        return None

    async def _get_execution(self, execution_id: str) -> Optional[WorkflowExecution]:
        """Get execution instance."""
        # This would load from storage or workflow engine cache
        # For now, return None as placeholder
        return None

    async def _emit_approval_event(self, event_type: str, details: Dict[str, Any]):
        """Emit approval event."""
        try:
            if not self.event_collector:
                return

            event = SystemEvent(
                event_id=str(uuid.uuid4()),
                event_type=EventType.WORKFLOW,
                severity=EventSeverity.INFO,
                source=EventSource.WORKFLOW_ENGINE,
                category=EventCategory.WORKFLOW,
                timestamp=datetime.now(timezone.utc),
                data={
                    "event_type": event_type,
                    "category": "approval",
                    "details": details,
                },
            )

            await self.event_collector.collect_event(event)
        except Exception as e:
            logger.error(f"Failed to emit approval event: {e}")


class WorkflowGovernance:
    """Workflow governance and compliance."""

    def __init__(self, policy_engine=None, audit_logger=None):
        """Initialize workflow governance."""
        self.policy_engine = policy_engine
        self.audit_logger = audit_logger or AuditLogger()
        self._governance_rules: Dict[str, GovernanceRule] = {}
        self._compliance_standards: Dict[ComplianceStandard, ComplianceResult] = {}
        self._load_default_rules()

    def _load_default_rules(self):
        """Load default governance rules."""
        # Security validation rule
        self._governance_rules["security_validation"] = GovernanceRule(
            rule_id="security_validation",
            name="Security Validation",
            description="Validate security requirements for workflow execution",
            policy_type=GovernancePolicy.SECURITY_VALIDATION,
            conditions={
                "require_security_check": True,
                "validate_user_permissions": True,
                "check_resource_access": True,
            },
            actions=["block_execution", "log_violation"],
            severity="high",
        )

        # Resource limit rule
        self._governance_rules["resource_limit"] = GovernanceRule(
            rule_id="resource_limit",
            name="Resource Limit",
            description="Enforce resource usage limits",
            policy_type=GovernancePolicy.RESOURCE_LIMIT,
            conditions={
                "max_cpu_percent": 80,
                "max_memory_percent": 85,
                "max_disk_usage": "90%",
            },
            actions=["request_approval", "limit_resources"],
            severity="medium",
        )

        # Time window rule
        self._governance_rules["time_window"] = GovernanceRule(
            rule_id="time_window",
            name="Time Window Restriction",
            description="Restrict execution to approved time windows",
            policy_type=GovernancePolicy.TIME_WINDOW,
            conditions={
                "allowed_hours": ["09:00-17:00"],
                "timezone": "UTC",
                "require_weekend_approval": True,
            },
            actions=["request_approval", "delay_execution"],
            severity="medium",
        )

        # Change approval rule
        self._governance_rules["change_approval"] = GovernanceRule(
            rule_id="change_approval",
            name="Change Approval",
            description="Require approval for production changes",
            policy_type=GovernancePolicy.CHANGE_APPROVAL,
            conditions={
                "environments": ["production", "staging"],
                "change_types": ["deployment", "configuration", "upgrade"],
            },
            actions=["require_approval", "log_change"],
            severity="high",
        )

    async def validate_workflow_compliance(
        self, blueprint: WorkflowBlueprint
    ) -> ComplianceResult:
        """Validate workflow against governance policies."""
        violations = []
        warnings = []
        recommendations = []

        # Check against all governance rules
        for rule in self._governance_rules.values():
            if not rule.enabled:
                continue

            rule_result = await self._evaluate_governance_rule(rule, blueprint)
            violations.extend(rule_result.get("violations", []))
            warnings.extend(rule_result.get("warnings", []))
            recommendations.extend(rule_result.get("recommendations", []))

        # Check compliance standards
        compliance_results = []
        for standard in ComplianceStandard:
            result = await self._validate_compliance_standard(standard, blueprint)
            if not result.compliant:
                violations.extend(result.violations)
                warnings.extend(result.warnings)
            compliance_results.append(result)

        return ComplianceResult(
            compliant=len(violations) == 0,
            standard=ComplianceStandard.CUSTOM,  # Would be determined by actual validation
            violations=violations,
            warnings=warnings,
            recommendations=recommendations,
        )

    async def audit_workflow_execution(self, execution_id: str) -> Dict[str, Any]:
        """Generate audit report for workflow execution."""
        # This would generate a comprehensive audit report
        # For now, return placeholder
        return {
            "execution_id": execution_id,
            "audit_timestamp": datetime.now(timezone.utc).isoformat(),
            "compliance_status": "pending",
            "violations": [],
            "approvals": [],
            "governance_checks": [],
            "recommendations": [],
        }

    async def enforce_sla_requirements(
        self, blueprint: WorkflowBlueprint
    ) -> List[Dict[str, Any]]:
        """Enforce SLA requirements for workflow."""
        sla_requirements = []

        # Check estimated duration
        if blueprint.estimated_duration:
            if blueprint.estimated_duration > timedelta(hours=8):
                sla_requirements.append(
                    {
                        "requirement": "long_running_workflow_approval",
                        "description": "Long-running workflows require additional approval",
                        "enforced": True,
                    }
                )

        # Check resource requirements
        resource_requirements = blueprint.resource_requirements
        if resource_requirements.get("cpu_cores", 0) > 16:
            sla_requirements.append(
                {
                    "requirement": "high_resource_approval",
                    "description": "High resource usage requires approval",
                    "enforced": True,
                }
            )

        # Check backup requirements
        if blueprint.category.value in ["provisioning", "upgrade"]:
            sla_requirements.append(
                {
                    "requirement": "backup_before_execution",
                    "description": "Backup required before execution",
                    "enforced": True,
                }
            )

        return sla_requirements

    async def add_governance_rule(self, rule: GovernanceRule) -> bool:
        """Add governance rule."""
        self._governance_rules[rule.rule_id] = rule

        # Emit event
        await self._emit_governance_event(
            "governance_rule_added",
            {
                "rule_id": rule.rule_id,
                "name": rule.name,
                "policy_type": rule.policy_type.value,
            },
        )

        return True

    async def remove_governance_rule(self, rule_id: str) -> bool:
        """Remove governance rule."""
        if rule_id not in self._governance_rules:
            return False

        rule = self._governance_rules[rule_id]
        del self._governance_rules[rule_id]

        # Emit event
        await self._emit_governance_event(
            "governance_rule_removed", {"rule_id": rule_id, "name": rule.name}
        )

        return True

    async def update_governance_rule(self, rule_id: str, **updates) -> bool:
        """Update governance rule."""
        if rule_id not in self._governance_rules:
            return False

        rule = self._governance_rules[rule_id]

        # Apply updates
        for key, value in updates.items():
            if hasattr(rule, key):
                setattr(rule, key, value)

        # Emit event
        await self._emit_governance_event(
            "governance_rule_updated", {"rule_id": rule_id, "updates": updates}
        )

        return True

    async def _evaluate_governance_rule(
        self, rule: GovernanceRule, blueprint: WorkflowBlueprint
    ) -> Dict[str, Any]:
        """Evaluate governance rule against blueprint."""
        violations = []
        warnings = []
        recommendations = []

        try:
            if rule.policy_type == GovernancePolicy.SECURITY_VALIDATION:
                # Check security requirements
                if rule.conditions.get("require_security_check", False):
                    if not blueprint.tags or "security-validated" not in blueprint.tags:
                        violations.append(
                            f"Security validation required for {blueprint.name}"
                        )

            elif rule.policy_type == GovernancePolicy.RESOURCE_LIMIT:
                # Check resource limits
                cpu_cores = blueprint.resource_requirements.get("cpu_cores", 0)
                max_cpu = rule.conditions.get("max_cpu_percent", 80)

                if cpu_cores > max_cpu:
                    violations.append(
                        f"CPU usage exceeds limit: {cpu_cores} > {max_cpu}"
                    )

            elif rule.policy_type == GovernancePolicy.TIME_WINDOW:
                # Check time window restrictions
                if rule.conditions.get("require_weekend_approval", False):
                    if blueprint.category.value in ["production", "deployment"]:
                        recommendations.append(
                            "Weekend execution requires additional approval"
                        )

            elif rule.policy_type == GovernancePolicy.CHANGE_APPROVAL:
                # Check change approval requirements
                if blueprint.category.value in ["deployment", "upgrade"]:
                    if "production" in blueprint.tags:
                        violations.append("Production changes require approval")

        except Exception as e:
            violations.append(f"Rule evaluation error: {str(e)}")

        return {
            "violations": violations,
            "warnings": warnings,
            "recommendations": recommendations,
        }

    async def _validate_compliance_standard(
        self, standard: ComplianceStandard, blueprint: WorkflowBlueprint
    ) -> ComplianceResult:
        """Validate workflow against compliance standard."""
        violations = []
        warnings = []
        recommendations = []

        if standard == ComplianceStandard.SOX:
            # SOX compliance checks
            if blueprint.category.value in ["production", "deployment"]:
                violations.append(
                    "SOX: Production changes require approval and documentation"
                )

        elif standard == ComplianceStandard.GDPR:
            # GDPR compliance checks
            if "personal-data" in blueprint.tags:
                recommendations.append("GDPR: Ensure data processing is documented")

        elif standard == ComplianceStandard.ISO27001:
            # ISO 27001 compliance checks
            if not blueprint.rollback_plan:
                warnings.append(
                    "ISO 27001: Rollback plan recommended for production workflows"
                )

        return ComplianceResult(
            compliant=len(violations) == 0,
            standard=standard,
            violations=violations,
            warnings=warnings,
            recommendations=recommendations,
        )

    async def _emit_governance_event(self, event_type: str, details: Dict[str, Any]):
        """Emit governance event."""
        try:
            event = SystemEvent(
                event_id=str(uuid.uuid4()),
                event_type=EventType.WORKFLOW,
                severity=EventSeverity.INFO,
                source=EventSource.WORKFLOW_ENGINE,
                category=EventCategory.WORKFLOW,
                timestamp=datetime.now(timezone.utc),
                data={
                    "event_type": event_type,
                    "category": "governance",
                    "details": details,
                },
            )

            # This would integrate with the event collector
            logger.info(f"Governance event: {event_type} - {details}")

        except Exception as e:
            logger.error(f"Failed to emit governance event: {e}")


class WorkflowPolicyIntegration:
    """Integrate workflows with policy system."""

    def __init__(
        self,
        policy_engine,
        approval_system: ApprovalSystem,
        governance: WorkflowGovernance,
    ):
        """Initialize workflow policy integration."""
        self.policy_engine = policy_engine
        self.approval_system = approval_system
        self.governance = governance

    async def validate_workflow_policies(
        self, blueprint: WorkflowBlueprint, user: str
    ) -> Dict[str, Any]:
        """Validate workflow against policy rules."""
        try:
            # Create policy context
            context = PolicyContext(
                user=user,
                resource=f"workflow:{blueprint.name}",
                action="execute",
                environment="production"
                if "production" in blueprint.tags
                else "development",
            )

            # Evaluate policies
            evaluation = await self.policy_engine.evaluate_policies(
                [blueprint], context
            )

            return {
                "allowed": evaluation.decision == PolicyDecision.ALLOW,
                "decision": evaluation.decision.value,
                "violations": evaluation.violations,
                "conditions": evaluation.conditions,
            }

        except Exception as e:
            logger.error(f"Policy validation failed: {e}")
            return {
                "allowed": False,
                "decision": "error",
                "violations": [str(e)],
                "conditions": {},
            }

    async def get_workflow_permissions(
        self, user: str, blueprint: WorkflowBlueprint
    ) -> Dict[str, List[str]]:
        """Get workflow permissions for user."""
        try:
            # This would integrate with the policy engine
            # For now, return basic permissions
            return {
                "execute": ["workflow:execute"],
                "approve": ["workflow:approve"],
                "view": ["workflow:view"],
                "admin": ["workflow:admin"]
                if user in ["admin", "operations_manager"]
                else [],
            }

        except Exception as e:
            logger.error(f"Failed to get workflow permissions: {e}")
            return {}

    async def enforce_workflow_policies(self, execution: WorkflowExecution) -> bool:
        """Enforce policies during workflow execution."""
        try:
            # Get blueprint
            blueprint = await self._get_blueprint(execution.blueprint_id)
            if not blueprint:
                return False

            # Validate workflow compliance
            compliance_result = await self.governance.validate_workflow_compliance(
                blueprint
            )

            # Check if execution should be blocked
            if not compliance_result.compliant:
                execution.status = ExecutionStatus.FAILED
                await self._emit_policy_event(
                    "workflow_blocked_by_policy",
                    {
                        "execution_id": execution.execution_id,
                        "violations": compliance_result.violations,
                    },
                )
                return False

            return True

        except Exception as e:
            logger.error(f"Policy enforcement failed: {e}")
            return False

    async def _get_blueprint(self, blueprint_id: str) -> Optional[WorkflowBlueprint]:
        """Get workflow blueprint."""
        # This would load from storage
        # For now, return None as placeholder
        return None

    async def _emit_policy_event(self, event_type: str, details: Dict[str, Any]):
        """Emit policy event."""
        try:
            event = SystemEvent(
                event_id=str(uuid.uuid4()),
                event_type=EventType.WORKFLOW,
                severity=EventSeverity.INFO,
                source=EventSource.WORKFLOW_ENGINE,
                category=EventCategory.WORKFLOW,
                timestamp=datetime.now(timezone.utc),
                data={
                    "event_type": event_type,
                    "category": "policy",
                    "details": details,
                },
            )

            # This would integrate with the event collector
            logger.info(f"Policy event: {event_type} - {details}")

        except Exception as e:
            logger.error(f"Failed to emit policy event: {e}")
