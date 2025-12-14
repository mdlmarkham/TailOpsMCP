"""
Security Workflow Integration for TailOpsMCP.

Integrates the enhanced security controls with the workflow system:
- Security validation for workflow execution
- Security-aware workflow approval enforcement
- Security audit for workflow operations
- Risk-based workflow execution controls
"""

import datetime
import logging
from typing import Any, Dict, List, Optional
from dataclasses import asdict

from src.models.security_models import (
    SecurityOperation, IdentityContext, ResourceContext, RiskLevel,
    RiskAssessment, ApprovalContext
)
from src.services.security_audit_logger import SecurityAuditLogger
from src.services.access_control import AdvancedAccessControl
from src.services.identity_manager import IdentityManager


logger = logging.getLogger(__name__)


class SecurityWorkflowIntegration:
    """Integrate security controls with workflow system."""
    
    def __init__(
        self,
        audit_logger: Optional[SecurityAuditLogger] = None,
        access_control: Optional[AdvancedAccessControl] = None,
        identity_manager: Optional[IdentityManager] = None
    ):
        """Initialize security workflow integration.
        
        Args:
            audit_logger: Security audit logger
            access_control: Advanced access control system
            identity_manager: Identity management system
        """
        self.audit_logger = audit_logger or SecurityAuditLogger()
        self.access_control = access_control or AdvancedAccessControl(
            audit_logger=self.audit_logger,
            identity_manager=identity_manager or IdentityManager()
        )
        self.identity_manager = identity_manager or IdentityManager()
        
        logger.info("Security workflow integration initialized")

    async def validate_workflow_security(self, workflow_blueprint: Dict[str, Any]) -> Dict[str, Any]:
        """Validate workflow security configuration.
        
        Args:
            workflow_blueprint: Workflow blueprint to validate
            
        Returns:
            Security validation result
        """
        try:
            validation_result = {
                "secure": True,
                "risk_level": "low",
                "security_requirements": [],
                "violations": [],
                "recommendations": []
            }
            
            # Extract workflow metadata
            workflow_name = workflow_blueprint.get("name", "unknown")
            workflow_category = workflow_blueprint.get("category", "general")
            steps = workflow_blueprint.get("steps", [])
            
            # Analyze security requirements
            security_requirements = self._analyze_security_requirements(workflow_blueprint)
            validation_result["security_requirements"] = security_requirements
            
            # Check for security violations
            violations = self._check_security_violations(workflow_blueprint)
            validation_result["violations"] = violations
            
            # Assess overall risk
            risk_level = self._assess_workflow_risk(workflow_blueprint, violations)
            validation_result["risk_level"] = risk_level
            
            # Update security status
            if violations or risk_level in ["high", "critical"]:
                validation_result["secure"] = False
            
            # Generate recommendations
            recommendations = self._generate_security_recommendations(violations, risk_level)
            validation_result["recommendations"] = recommendations
            
            # Log validation
            await self._log_workflow_validation(workflow_name, validation_result)
            
            logger.info(f"Workflow security validation completed for '{workflow_name}': {validation_result['secure']}")
            return validation_result
            
        except Exception as e:
            logger.error(f"Workflow security validation failed: {e}")
            return {
                "secure": False,
                "risk_level": "critical",
                "security_requirements": [],
                "violations": [f"Validation error: {str(e)}"],
                "recommendations": ["Manual security review required"]
            }

    async def enforce_workflow_approvals(self, workflow_execution: Dict[str, Any]) -> Dict[str, Any]:
        """Enforce security approvals for workflow execution.
        
        Args:
            workflow_execution: Workflow execution context
            
        Returns:
            Approval enforcement result
        """
        try:
            execution_id = workflow_execution.get("execution_id", "unknown")
            workflow_name = workflow_execution.get("workflow_name", "unknown")
            user_id = workflow_execution.get("user_id", "anonymous")
            
            # Get user identity
            identity = await self._get_user_identity(user_id)
            
            # Create workflow operation context
            workflow_operation = self._create_workflow_operation(workflow_execution, identity)
            
            # Assess risk for workflow execution
            risk_assessment = await self._assess_workflow_execution_risk(workflow_operation)
            
            # Determine approval requirements
            approval_requirements = self._determine_approval_requirements(risk_assessment, workflow_execution)
            
            # Check existing approvals
            existing_approvals = workflow_execution.get("approvals", [])
            missing_approvals = self._check_approval_requirements(
                approval_requirements, existing_approvals, identity
            )
            
            # Create enforcement result
            enforcement_result = {
                "execution_id": execution_id,
                "requires_approval": len(missing_approvals) > 0,
                "missing_approvals": missing_approvals,
                "risk_level": risk_assessment.overall_risk.value,
                "approval_requirements": approval_requirements,
                "can_proceed": len(missing_approvals) == 0,
                "enforcement_timestamp": datetime.datetime.utcnow().isoformat()
            }
            
            # Log approval enforcement
            await self._log_approval_enforcement(execution_id, enforcement_result)
            
            # If approval required, create approval context
            if enforcement_result["requires_approval"]:
                approval_context = ApprovalContext(
                    approval_id=f"approval_{execution_id}",
                    approver_id="pending",
                    approval_timestamp=datetime.datetime.utcnow(),
                    approval_method="workflow_security",
                    conditions=missing_approvals
                )
                enforcement_result["approval_context"] = approval_context.to_dict()
            
            logger.info(f"Workflow approval enforcement completed for execution {execution_id}")
            return enforcement_result
            
        except Exception as e:
            logger.error(f"Workflow approval enforcement failed: {e}")
            return {
                "execution_id": workflow_execution.get("execution_id", "unknown"),
                "requires_approval": True,
                "missing_approvals": ["Security enforcement error"],
                "risk_level": "critical",
                "can_proceed": False,
                "error": str(e)
            }

    async def audit_workflow_security(self, workflow_execution: Dict[str, Any]) -> Dict[str, Any]:
        """Audit workflow security operations.
        
        Args:
            workflow_execution: Workflow execution to audit
            
        Returns:
            Security audit result
        """
        try:
            execution_id = workflow_execution.get("execution_id", "unknown")
            user_id = workflow_execution.get("user_id", "anonymous")
            
            # Create security operation for audit
            identity = await self._get_user_identity(user_id)
            workflow_operation = self._create_workflow_operation(workflow_execution, identity)
            
            # Log workflow operation initiation
            operation_id = await self.audit_logger.log_operation_initiated(workflow_operation)
            
            # Create operation outcome (success for audit)
            from src.models.security_models import OperationOutcome
            outcome = OperationOutcome(
                outcome="success",
                outcome_details={"audit_type": "workflow_security_audit"}
            )
            
            # Log operation outcome
            await self.audit_logger.log_operation_outcome(operation_id, outcome)
            
            # Generate audit summary
            audit_summary = {
                "execution_id": execution_id,
                "operation_id": operation_id,
                "user_id": user_id,
                "workflow_name": workflow_execution.get("workflow_name"),
                "audit_timestamp": datetime.datetime.utcnow().isoformat(),
                "security_context": {
                    "identity": identity.to_dict() if identity else None,
                    "risk_assessment": await self._assess_workflow_execution_risk(workflow_operation).dict() if hasattr(await self._assess_workflow_execution_risk(workflow_operation), 'dict') else asdict(await self._assess_workflow_execution_risk(workflow_operation)),
                    "compliance_status": "audited"
                }
            }
            
            logger.info(f"Workflow security audit completed for execution {execution_id}")
            return audit_summary
            
        except Exception as e:
            logger.error(f"Workflow security audit failed: {e}")
            return {
                "execution_id": workflow_execution.get("execution_id", "unknown"),
                "error": str(e),
                "audit_timestamp": datetime.datetime.utcnow().isoformat()
            }

    def _analyze_security_requirements(self, workflow_blueprint: Dict[str, Any]) -> List[str]:
        """Analyze security requirements for workflow."""
        requirements = []
        
        # Check workflow category
        category = workflow_blueprint.get("category", "").lower()
        if "admin" in category:
            requirements.append("Administrative privileges required")
            requirements.append("Enhanced audit logging")
        elif "security" in category:
            requirements.append("Security team approval required")
            requirements.append("Compliance validation")
        elif "production" in category:
            requirements.append("Production change approval")
            requirements.append("Rollback plan required")
        
        # Check for sensitive operations
        steps = workflow_blueprint.get("steps", [])
        sensitive_operations = ["delete", "shutdown", "restart", "modify_config"]
        
        for step in steps:
            step_type = step.get("type", "").lower()
            if any(op in step_type for op in sensitive_operations):
                requirements.append("High-risk operation detected")
                break
        
        # Check for data operations
        for step in steps:
            step_type = step.get("type", "").lower()
            if "data" in step_type or "export" in step_type:
                requirements.append("Data protection compliance required")
                break
        
        return requirements

    def _check_security_violations(self, workflow_blueprint: Dict[str, Any]) -> List[str]:
        """Check for security violations in workflow."""
        violations = []
        
        # Check for missing security elements
        if not workflow_blueprint.get("rollback_plan"):
            violations.append("No rollback plan defined for production workflow")
        
        # Check for dangerous operations without safeguards
        steps = workflow_blueprint.get("steps", [])
        for step in steps:
            step_type = step.get("type", "").lower()
            if "delete" in step_type and not step.get("requires_approval"):
                violations.append("Delete operation without approval requirement")
            if "shutdown" in step_type and not step.get("confirmation_required"):
                violations.append("Shutdown operation without confirmation")
        
        # Check for missing audit requirements
        if workflow_blueprint.get("category") == "production":
            if not any(step.get("audit_log") for step in steps):
                violations.append("Production workflow missing audit logging")
        
        return violations

    def _assess_workflow_risk(self, workflow_blueprint: Dict[str, Any], violations: List[str]) -> str:
        """Assess overall workflow risk level."""
        risk_score = 0
        
        # Base risk by category
        category = workflow_blueprint.get("category", "").lower()
        if "admin" in category:
            risk_score += 3
        elif "security" in category:
            risk_score += 2
        elif "production" in category:
            risk_score += 2
        
        # Risk by violations
        risk_score += len(violations)
        
        # Risk by step count and complexity
        steps = workflow_blueprint.get("steps", [])
        risk_score += len(steps) // 10  # Each 10 steps adds 1 risk point
        
        # Determine risk level
        if risk_score >= 5:
            return "critical"
        elif risk_score >= 3:
            return "high"
        elif risk_score >= 1:
            return "medium"
        else:
            return "low"

    def _generate_security_recommendations(self, violations: List[str], risk_level: str) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        # Add violation-specific recommendations
        for violation in violations:
            if "rollback" in violation.lower():
                recommendations.append("Implement comprehensive rollback procedures")
            if "approval" in violation.lower():
                recommendations.append("Add approval requirements for high-risk operations")
            if "audit" in violation.lower():
                recommendations.append("Enable audit logging for all operations")
        
        # Add risk-level recommendations
        if risk_level == "critical":
            recommendations.extend([
                "Require executive approval",
                "Implement mandatory security review",
                "Enable real-time monitoring"
            ])
        elif risk_level == "high":
            recommendations.extend([
                "Require management approval",
                "Implement enhanced monitoring",
                "Schedule during maintenance windows"
            ])
        elif risk_level == "medium":
            recommendations.extend([
                "Require team lead approval",
                "Implement standard monitoring"
            ])
        
        return recommendations

    async def _get_user_identity(self, user_id: str) -> Optional[IdentityContext]:
        """Get user identity context."""
        try:
            # This would integrate with identity manager
            return IdentityContext(
                user_id=user_id,
                username=user_id,
                authentication_method="system"
            )
        except Exception as e:
            logger.error(f"Failed to get user identity: {e}")
            return None

    def _create_workflow_operation(self, workflow_execution: Dict[str, Any], identity: Optional[IdentityContext]) -> SecurityOperation:
        """Create security operation from workflow execution."""
        from src.models.security_models import ResourceType, SensitivityLevel, SecurityClassification
        
        return SecurityOperation(
            operation_type=f"workflow_{workflow_execution.get('workflow_name', 'unknown')}",
            initiator_identity=identity,
            target_resources=[
                ResourceContext(
                    resource_type=ResourceType.WORKFLOW,
                    resource_id=workflow_execution.get("workflow_name", "unknown"),
                    resource_path=f"workflow:{workflow_execution.get('workflow_name', 'unknown')}",
                    sensitivity_level=SensitivityLevel.INTERNAL,
                    security_classification=SecurityClassification.INTERNAL
                )
            ],
            operation_parameters=workflow_execution,
            correlation_id=workflow_execution.get("execution_id")
        )

    async def _assess_workflow_execution_risk(self, workflow_operation: SecurityOperation) -> RiskAssessment:
        """Assess risk for workflow execution."""
        try:
            if workflow_operation.initiator_identity:
                return await self.access_control.evaluate_risk(
                    identity=workflow_operation.initiator_identity,
                    operation=workflow_operation
                )
            else:
                return RiskAssessment(
                    overall_risk=RiskLevel.HIGH,
                    risk_factors={"unknown_identity": 1.0},
                    mitigation_suggestions=["Require authentication"],
                    requires_approval=True
                )
        except Exception as e:
            logger.error(f"Workflow execution risk assessment failed: {e}")
            return RiskAssessment(
                overall_risk=RiskLevel.HIGH,
                risk_factors={"assessment_error": str(e)},
                mitigation_suggestions=["Manual review required"],
                requires_approval=True
            )

    def _determine_approval_requirements(self, risk_assessment: RiskAssessment, workflow_execution: Dict[str, Any]) -> List[str]:
        """Determine approval requirements based on risk and workflow."""
        requirements = []
        
        # Risk-based requirements
        if risk_assessment.overall_risk == RiskLevel.CRITICAL:
            requirements.extend(["executive_approval", "security_team_approval"])
        elif risk_assessment.overall_risk == RiskLevel.HIGH:
            requirements.extend(["management_approval", "security_team_approval"])
        elif risk_assessment.overall_risk == RiskLevel.MEDIUM:
            requirements.append("team_lead_approval")
        
        # Workflow-based requirements
        workflow_category = workflow_execution.get("workflow_category", "").lower()
        if "production" in workflow_category:
            requirements.append("production_change_approval")
        if "security" in workflow_category:
            requirements.append("security_team_approval")
        if "admin" in workflow_category:
            requirements.append("admin_approval")
        
        # Step-based requirements
        steps = workflow_execution.get("steps", [])
        for step in steps:
            if step.get("requires_approval"):
                requirements.append(f"step_approval_{step.get('name', 'unknown')}")
        
        return list(set(requirements))  # Remove duplicates

    def _check_approval_requirements(self, requirements: List[str], existing_approvals: List[Dict[str, Any]], identity: Optional[IdentityContext]) -> List[str]:
        """Check which approval requirements are missing."""
        missing = []
        
        # Convert existing approvals to set for faster lookup
        existing_approval_types = {approval.get("type") for approval in existing_approvals}
        
        for requirement in requirements:
            if requirement not in existing_approval_types:
                missing.append(requirement)
        
        return missing

    async def _log_workflow_validation(self, workflow_name: str, validation_result: Dict[str, Any]) -> None:
        """Log workflow security validation."""
        try:
            # Create security operation for validation
            validation_operation = SecurityOperation(
                operation_type="workflow_security_validation",
                initiator_identity=IdentityContext(
                    user_id="system",
                    username="system",
                    authentication_method="system"
                ),
                operation_parameters={
                    "workflow_name": workflow_name,
                    "validation_result": validation_result
                }
            )
            
            # Log operation
            operation_id = await self.audit_logger.log_operation_initiated(validation_operation)
            
            # Log outcome
            from src.models.security_models import OperationOutcome
            outcome = OperationOutcome(
                outcome="success" if validation_result["secure"] else "violation",
                outcome_details=validation_result
            )
            
            await self.audit_logger.log_operation_outcome(operation_id, outcome)
            
        except Exception as e:
            logger.error(f"Failed to log workflow validation: {e}")

    async def _log_approval_enforcement(self, execution_id: str, enforcement_result: Dict[str, Any]) -> None:
        """Log workflow approval enforcement."""
        try:
            # Create security operation for enforcement
            enforcement_operation = SecurityOperation(
                operation_type="workflow_approval_enforcement",
                initiator_identity=IdentityContext(
                    user_id="system",
                    username="system",
                    authentication_method="system"
                ),
                operation_parameters={
                    "execution_id": execution_id,
                    "enforcement_result": enforcement_result
                }
            )
            
            # Log operation
            operation_id = await self.audit_logger.log_operation_initiated(enforcement_operation)
            
            # Log outcome
            from src.models.security_models import OperationOutcome
            outcome = OperationOutcome(
                outcome="success",
                outcome_details=enforcement_result
            )
            
            await self.audit_logger.log_operation_outcome(operation_id, outcome)
            
        except Exception as e:
            logger.error(f"Failed to log approval enforcement: {e}")