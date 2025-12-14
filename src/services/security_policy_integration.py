"""
Security Policy Integration for TailOpsMCP.

Integrates the enhanced security controls with the existing policy system:
- Policy enforcement with security context
- Enhanced policy decisions with security risk assessment
- Security-aware policy validation
- Integration with Policy-as-Code system
"""

import datetime
import logging
from typing import Any, Dict, List, Optional, Set
from dataclasses import asdict

from src.models.security_models import (
    SecurityOperation, PolicyDecision, IdentityContext, ResourceContext,
    RiskLevel, RiskAssessment, AccessDecision
)
from src.services.security_audit_logger import SecurityAuditLogger
from src.services.access_control import AdvancedAccessControl
from src.services.identity_manager import IdentityManager
from src.services.compliance_framework import ComplianceFramework


logger = logging.getLogger(__name__)


class SecurityPolicyIntegration:
    """Integrate security controls with policy system."""
    
    def __init__(
        self,
        audit_logger: Optional[SecurityAuditLogger] = None,
        access_control: Optional[AdvancedAccessControl] = None,
        identity_manager: Optional[IdentityManager] = None,
        compliance_framework: Optional[ComplianceFramework] = None
    ):
        """Initialize security policy integration.
        
        Args:
            audit_logger: Security audit logger
            access_control: Advanced access control system
            identity_manager: Identity management system
            compliance_framework: Compliance framework
        """
        self.audit_logger = audit_logger or SecurityAuditLogger()
        self.access_control = access_control or AdvancedAccessControl(
            audit_logger=self.audit_logger,
            identity_manager=identity_manager or IdentityManager()
        )
        self.identity_manager = identity_manager or IdentityManager()
        self.compliance_framework = compliance_framework or ComplianceFramework(
            audit_logger=self.audit_logger
        )
        
        logger.info("Security policy integration initialized")

    async def enhance_policy_decisions(self, policy_context: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance policy decisions with security context.
        
        Args:
            policy_context: Existing policy context
            
        Returns:
            Enhanced policy context with security information
        """
        try:
            # Extract security-relevant information
            user_id = policy_context.get("user_id", "anonymous")
            resource = policy_context.get("resource", {})
            action = policy_context.get("action", "")
            
            # Get identity context
            identity = await self._get_identity_context(user_id)
            
            # Create resource context
            resource_context = await self._create_resource_context(resource)
            
            # Perform risk assessment
            risk_assessment = await self._assess_security_risk(
                identity, resource_context, action, policy_context
            )
            
            # Apply security controls
            security_controls = await self._apply_security_controls(
                identity, resource_context, action, policy_context
            )
            
            # Check compliance requirements
            compliance_check = await self._check_compliance_requirements(
                identity, resource_context, action, policy_context
            )
            
            # Enhance policy context
            enhanced_context = policy_context.copy()
            enhanced_context.update({
                "security_context": {
                    "identity": identity.to_dict() if identity else None,
                    "risk_assessment": risk_assessment.dict() if hasattr(risk_assessment, 'dict') else asdict(risk_assessment),
                    "security_controls": security_controls,
                    "compliance_check": compliance_check,
                    "enhanced_at": datetime.datetime.utcnow().isoformat()
                },
                "security_enhanced": True
            })
            
            logger.debug(f"Enhanced policy decision for user {user_id}, action {action}")
            return enhanced_context
            
        except Exception as e:
            logger.error(f"Failed to enhance policy decisions: {e}")
            return policy_context

    async def log_policy_enforcement(self, enforcement: Dict[str, Any]) -> None:
        """Log policy enforcement decisions.
        
        Args:
            enforcement: Policy enforcement information
        """
        try:
            # Create policy decision for audit logging
            policy_decision = PolicyDecision(
                policy_name=enforcement.get("policy_name", "unknown"),
                decision=enforcement.get("decision", "unknown"),
                reason=enforcement.get("reason", ""),
                policy_context=enforcement.get("context", {}),
                enforcement_details=enforcement.get("enforcement_details", {})
            )
            
            # Log to security audit system
            await self.audit_logger.log_policy_decision(policy_decision)
            
            logger.debug(f"Logged policy enforcement: {enforcement.get('policy_name', 'unknown')}")
            
        except Exception as e:
            logger.error(f"Failed to log policy enforcement: {e}")

    async def validate_policy_compliance(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """Validate policy against security requirements.
        
        Args:
            policy: Policy to validate
            
        Returns:
            Validation result with security assessment
        """
        try:
            validation_result = {
                "compliant": True,
                "violations": [],
                "recommendations": [],
                "security_score": 100.0
            }
            
            # Check for security-related policy elements
            security_elements = [
                "access_control", "authentication", "authorization",
                "audit_logging", "data_protection", "compliance"
            ]
            
            policy_content = str(policy).lower()
            
            # Validate security requirements
            for element in security_elements:
                if element not in policy_content:
                    validation_result["violations"].append(
                        f"Missing security element: {element}"
                    )
                    validation_result["security_score"] -= 10
            
            # Check for dangerous patterns
            dangerous_patterns = [
                ("allow.*\\*", "Wildcard permissions detected"),
                ("bypass.*auth", "Authentication bypass detected"),
                ("disable.*audit", "Audit logging disable detected"),
                ("ignore.*compliance", "Compliance ignore detected")
            ]
            
            import re
            for pattern, description in dangerous_patterns:
                if re.search(pattern, policy_content):
                    validation_result["violations"].append(description)
                    validation_result["security_score"] -= 20
            
            # Update compliance status
            if validation_result["violations"]:
                validation_result["compliant"] = False
                validation_result["security_score"] = max(0, validation_result["security_score"])
            
            # Generate recommendations
            if not validation_result["compliant"]:
                validation_result["recommendations"].extend([
                    "Review and fix security violations",
                    "Implement proper access controls",
                    "Enable audit logging for all operations",
                    "Ensure compliance requirements are met"
                ])
            
            logger.info(f"Policy validation completed: {validation_result['security_score']:.1f}% secure")
            return validation_result
            
        except Exception as e:
            logger.error(f"Policy compliance validation failed: {e}")
            return {
                "compliant": False,
                "violations": [f"Validation failed: {str(e)}"],
                "recommendations": ["Manual review required"],
                "security_score": 0.0
            }

    async def _get_identity_context(self, user_id: str) -> Optional[IdentityContext]:
        """Get identity context for user."""
        try:
            # This would integrate with the identity manager
            # For now, return a basic identity context
            return IdentityContext(
                user_id=user_id,
                username=user_id,
                authentication_method="system"
            )
        except Exception as e:
            logger.error(f"Failed to get identity context: {e}")
            return None

    async def _create_resource_context(self, resource: Dict[str, Any]) -> ResourceContext:
        """Create resource context from policy resource."""
        try:
            from src.models.security_models import ResourceType, SensitivityLevel, SecurityClassification
            
            return ResourceContext(
                resource_type=ResourceType.SYSTEM,
                resource_id=resource.get("id", "unknown"),
                resource_path=resource.get("path", ""),
                sensitivity_level=SensitivityLevel.INTERNAL,
                security_classification=SecurityClassification.INTERNAL
            )
        except Exception as e:
            logger.error(f"Failed to create resource context: {e}")
            from src.models.security_models import ResourceType, SensitivityLevel, SecurityClassification
            return ResourceContext(
                resource_type=ResourceType.SYSTEM,
                resource_id="unknown",
                resource_path="",
                sensitivity_level=SensitivityLevel.INTERNAL,
                security_classification=SecurityClassification.INTERNAL
            )

    async def _assess_security_risk(
        self,
        identity: Optional[IdentityContext],
        resource: ResourceContext,
        action: str,
        context: Dict[str, Any]
    ) -> RiskAssessment:
        """Assess security risk for policy decision."""
        try:
            if identity:
                return await self.access_control.evaluate_risk(
                    identity=identity,
                    operation=SecurityOperation(
                        operation_type=action,
                        target_resources=[resource],
                        initiator_identity=identity
                    )
                )
            else:
                # Default high risk for unknown identity
                return RiskAssessment(
                    overall_risk=RiskLevel.HIGH,
                    risk_factors={"unknown_identity": 1.0},
                    mitigation_suggestions=["Require authentication"],
                    requires_approval=True
                )
        except Exception as e:
            logger.error(f"Security risk assessment failed: {e}")
            return RiskAssessment(
                overall_risk=RiskLevel.HIGH,
                risk_factors={"assessment_error": str(e)},
                mitigation_suggestions=["Manual review required"],
                requires_approval=True
            )

    async def _apply_security_controls(
        self,
        identity: Optional[IdentityContext],
        resource: ResourceContext,
        action: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Apply security controls to policy decision."""
        try:
            controls = {
                "access_control": True,
                "audit_logging": True,
                "compliance_check": True,
                "risk_assessment": True
            }
            
            if identity:
                # Check if MFA is required
                mfa_required = await self.access_control.enforce_mfa_requirement(
                    identity, SecurityOperation(
                        operation_type=action,
                        target_resources=[resource],
                        initiator_identity=identity
                    )
                )
                controls["mfa_required"] = mfa_required
                
                # Check separation of duties
                controls["separation_of_duties"] = True
                
                # Check approval requirements
                controls["approval_required"] = (
                    identity.risk_profile == "high" or 
                    resource.sensitivity_level.value in ["confidential", "restricted"]
                )
            
            return controls
            
        except Exception as e:
            logger.error(f"Security control application failed: {e}")
            return {"error": str(e)}

    async def _check_compliance_requirements(
        self,
        identity: Optional[IdentityContext],
        resource: ResourceContext,
        action: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check compliance requirements for policy decision."""
        try:
            compliance_check = {
                "compliant": True,
                "standards_checked": [],
                "violations": [],
                "requirements": []
            }
            
            # Check SOC2 requirements
            if resource.sensitivity_level.value in ["confidential", "restricted"]:
                compliance_check["standards_checked"].append("SOC2")
                compliance_check["requirements"].append("Access logging required")
                compliance_check["requirements"].append("Multi-factor authentication required")
            
            # Check ISO 27001 requirements
            if action in ["admin", "delete", "modify"]:
                compliance_check["standards_checked"].append("ISO27001")
                compliance_check["requirements"].append("Change management approval")
            
            # Check data protection requirements
            if "personal_data" in str(context).lower():
                compliance_check["standards_checked"].append("GDPR")
                compliance_check["requirements"].append("Data protection impact assessment")
                compliance_check["requirements"].append("Consent verification")
            
            return compliance_check
            
        except Exception as e:
            logger.error(f"Compliance check failed: {e}")
            return {
                "compliant": False,
                "standards_checked": [],
                "violations": [f"Compliance check failed: {str(e)}"],
                "requirements": []
            }


class SecurityPolicyEnforcement:
    """Enhanced policy enforcement with security controls."""
    
    def __init__(self, security_integration: SecurityPolicyIntegration):
        """Initialize security policy enforcement.
        
        Args:
            security_integration: Security policy integration instance
        """
        self.security_integration = security_integration
        self.audit_logger = security_integration.audit_logger
        
    async def enforce_security_policy(
        self,
        policy_context: Dict[str, Any],
        original_decision: str
    ) -> Dict[str, Any]:
        """Enforce security policy on top of existing policy decision.
        
        Args:
            policy_context: Policy context
            original_decision: Original policy decision
            
        Returns:
            Enhanced decision with security controls
        """
        try:
            # Enhance policy context with security information
            enhanced_context = await self.security_integration.enhance_policy_decisions(policy_context)
            
            # Get security assessment
            security_context = enhanced_context.get("security_context", {})
            risk_assessment = security_context.get("risk_assessment", {})
            
            # Apply security controls
            decision = original_decision
            security_reasons = []
            
            # High-risk operations require additional approval
            if risk_assessment.get("overall_risk") in ["high", "critical"]:
                if decision == "allow":
                    decision = "conditional"
                    security_reasons.append("High-risk operation requires additional approval")
            
            # Check MFA requirements
            security_controls = security_context.get("security_controls", {})
            if security_controls.get("mfa_required") and decision == "allow":
                decision = "conditional"
                security_reasons.append("Multi-factor authentication required")
            
            # Check compliance requirements
            compliance_check = security_context.get("compliance_check", {})
            if not compliance_check.get("compliant", True):
                decision = "deny"
                security_reasons.extend(compliance_check.get("violations", []))
            
            # Log the enhanced decision
            enforcement = {
                "policy_name": enhanced_context.get("policy_name", "unknown"),
                "decision": decision,
                "reason": "; ".join(security_reasons) if security_reasons else "Security controls passed",
                "context": enhanced_context,
                "enforcement_details": {
                    "original_decision": original_decision,
                    "security_enhancement": True,
                    "risk_level": risk_assessment.get("overall_risk"),
                    "security_controls_applied": list(security_controls.keys())
                }
            }
            
            await self.security_integration.log_policy_enforcement(enforcement)
            
            # Return enhanced decision
            return {
                "decision": decision,
                "reason": enforcement["reason"],
                "security_context": security_context,
                "original_decision": original_decision,
                "enhanced": True
            }
            
        except Exception as e:
            logger.error(f"Security policy enforcement failed: {e}")
            # Default to deny on error for security
            return {
                "decision": "deny",
                "reason": f"Security enforcement error: {str(e)}",
                "security_context": {},
                "original_decision": original_decision,
                "enhanced": True
            }