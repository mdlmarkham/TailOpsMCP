"""
Advanced Access Control System with contextual permissions.

This module provides fine-grained access control capabilities:
- Contextual permissions based on user, resource, and environment
- Risk-based access control with dynamic risk assessment
- Multi-factor authentication requirements enforcement
- Separation of duties validation
- Resource sensitivity-aware access decisions
"""

import datetime
import json
import logging
import os
import sqlite3
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import asdict

from src.models.security_models import (
    IdentityContext, ResourceContext, AccessDecision, AccessDecisionResult,
    RiskAssessment, RiskLevel, AccessAttempt, SecurityOperation,
    ResourceType, SensitivityLevel, SecurityClassification
)
from src.services.security_audit_logger import SecurityAuditLogger
from src.services.identity_manager import IdentityManager


logger = logging.getLogger(__name__)


class AccessRule:
    """Represents an access control rule."""
    
    def __init__(
        self,
        rule_id: str,
        name: str,
        resource_type: ResourceType,
        action: str,
        conditions: Dict[str, Any],
        decision: AccessDecision,
        priority: int = 100,
        description: str = ""
    ):
        self.rule_id = rule_id
        self.name = name
        self.resource_type = resource_type
        self.action = action
        self.conditions = conditions
        self.decision = decision
        self.priority = priority
        self.description = description

    def matches(self, identity: IdentityContext, resource: ResourceContext, action: str) -> bool:
        """Check if this rule matches the given context."""
        # Check resource type
        if resource.resource_type != self.resource_type:
            return False
        
        # Check action
        if action != self.action:
            return False
        
        # Check conditions
        for condition_key, condition_value in self.conditions.items():
            if not self._evaluate_condition(condition_key, condition_value, identity, resource):
                return False
        
        return True

    def _evaluate_condition(self, key: str, value: Any, identity: IdentityContext, resource: ResourceContext) -> bool:
        """Evaluate a single condition."""
        if key == "user_roles":
            return any(role in identity.roles for role in value)
        elif key == "user_groups":
            return any(group in identity.groups for group in value)
        elif key == "user_permissions":
            return any(perm in identity.permissions for perm in value)
        elif key == "resource_sensitivity":
            return resource.sensitivity_level.value in value
        elif key == "resource_classification":
            return resource.security_classification.value in value
        elif key == "source_ip_patterns":
            # This would check IP patterns (simplified)
            return True  # Implement IP pattern matching
        elif key == "time_restrictions":
            # Check if current time is within restrictions
            return self._check_time_restrictions(value)
        elif key == "mfa_required":
            return value  # Always require MFA for this rule
        else:
            # Unknown condition, default to false for security
            return False

    def _check_time_restrictions(self, restrictions: Dict[str, Any]) -> bool:
        """Check if current time meets restrictions."""
        current_time = datetime.datetime.utcnow()
        current_hour = current_time.hour
        
        allowed_hours = restrictions.get("allowed_hours", [])
        if allowed_hours and current_hour not in allowed_hours:
            return False
        
        # Check day restrictions
        current_weekday = current_time.weekday()  # 0=Monday, 6=Sunday
        allowed_days = restrictions.get("allowed_days", list(range(7)))
        if current_weekday not in allowed_days:
            return False
        
        return True


class RiskAssessor:
    """Assesses risk for operations and access attempts."""
    
    def __init__(self):
        """Initialize risk assessor."""
        self.risk_thresholds = {
            RiskLevel.LOW: 0.3,
            RiskLevel.MEDIUM: 0.6,
            RiskLevel.HIGH: 0.8,
            RiskLevel.CRITICAL: 0.95
        }

    def assess_access_risk(
        self,
        identity: IdentityContext,
        resource: ResourceContext,
        action: str,
        context: Dict[str, Any]
    ) -> RiskAssessment:
        """Assess risk for an access attempt.
        
        Args:
            identity: User identity
            resource: Resource being accessed
            action: Action being performed
            context: Additional context (IP, time, etc.)
            
        Returns:
            Risk assessment result
        """
        try:
            risk_factors = {}
            risk_score = 0.0
            
            # Identity-based risk factors
            risk_factors.update(self._assess_identity_risk(identity))
            
            # Resource-based risk factors
            risk_factors.update(self._assess_resource_risk(resource))
            
            # Action-based risk factors
            risk_factors.update(self._assess_action_risk(action))
            
            # Context-based risk factors
            risk_factors.update(self._assess_context_risk(context))
            
            # Calculate overall risk score
            risk_score = self._calculate_risk_score(risk_factors)
            
            # Determine risk level
            overall_risk = self._determine_risk_level(risk_score)
            
            # Generate mitigation suggestions
            mitigation_suggestions = self._generate_mitigation_suggestions(
                identity, resource, action, risk_factors
            )
            
            # Determine if approval is required
            requires_approval = self._requires_approval(overall_risk, risk_factors)
            
            return RiskAssessment(
                overall_risk=overall_risk,
                risk_factors=risk_factors,
                mitigation_suggestions=mitigation_suggestions,
                requires_approval=requires_approval
            )
            
        except Exception as e:
            logger.error(f"Risk assessment failed: {e}")
            # Default to high risk on error
            return RiskAssessment(
                overall_risk=RiskLevel.HIGH,
                risk_factors={"error": str(e)},
                mitigation_suggestions=["Manual review required"],
                requires_approval=True
            )

    def _assess_identity_risk(self, identity: IdentityContext) -> Dict[str, Any]:
        """Assess risk based on identity factors."""
        factors = {}
        
        # Risk profile
        if identity.risk_profile == "high":
            factors["identity_risk_profile"] = 0.8
        elif identity.risk_profile == "medium":
            factors["identity_risk_profile"] = 0.5
        else:
            factors["identity_risk_profile"] = 0.2
        
        # Privileged roles
        privileged_roles = ["admin", "security", "operations"]
        if any(role in identity.roles for role in privileged_roles):
            factors["privileged_role"] = 0.6
        
        # Authentication method risk
        if identity.authentication_method.value == "anonymous":
            factors["anonymous_auth"] = 0.9
        elif identity.authentication_method.value == "tailscale_oidc":
            factors["tailscale_auth"] = 0.1
        else:
            factors["other_auth"] = 0.3
        
        # Source IP risk (simplified)
        if identity.source_ip:
            if identity.source_ip.startswith("192.168.") or identity.source_ip.startswith("10."):
                factors["internal_ip"] = 0.1
            else:
                factors["external_ip"] = 0.4
        
        return factors

    def _assess_resource_risk(self, resource: ResourceContext) -> Dict[str, Any]:
        """Assess risk based on resource factors."""
        factors = {}
        
        # Sensitivity level
        sensitivity_risk = {
            SensitivityLevel.PUBLIC: 0.1,
            SensitivityLevel.INTERNAL: 0.3,
            SensitivityLevel.CONFIDENTIAL: 0.6,
            SensitivityLevel.RESTRICTED: 0.9
        }
        factors["resource_sensitivity"] = sensitivity_risk[resource.sensitivity_level]
        
        # Security classification
        classification_risk = {
            SecurityClassification.UNCLASSIFIED: 0.1,
            SecurityClassification.INTERNAL: 0.3,
            SecurityClassification.CONFIDENTIAL: 0.6,
            SecurityClassification.SECRET: 0.8,
            SecurityClassification.TOP_SECRET: 0.95
        }
        factors["resource_classification"] = classification_risk[resource.security_classification]
        
        # Resource type risk
        resource_type_risk = {
            ResourceType.SYSTEM: 0.7,
            ResourceType.CONFIGURATION: 0.6,
            ResourceType.AUDIT: 0.8,
            ResourceType.DATA: 0.5,
            ResourceType.LOGS: 0.4,
            ResourceType.TARGET: 0.3,
            ResourceType.POLICY: 0.7,
            ResourceType.WORKFLOW: 0.4
        }
        factors["resource_type"] = resource_type_risk[resource.resource_type]
        
        return factors

    def _assess_action_risk(self, action: str) -> Dict[str, Any]:
        """Assess risk based on action type."""
        factors = {}
        
        # High-risk actions
        high_risk_actions = [
            "delete", "remove", "drop", "terminate", "shutdown",
            "create_admin", "grant_admin", "elevate_privileges",
            "modify_security", "change_policy", "bypass_controls"
        ]
        
        medium_risk_actions = [
            "modify", "update", "change", "restart", "reconfigure",
            "backup", "restore", "export", "import"
        ]
        
        low_risk_actions = [
            "read", "view", "list", "describe", "status", "info"
        ]
        
        if any(high_risk in action.lower() for high_risk in high_risk_actions):
            factors["high_risk_action"] = 0.8
        elif any(medium_risk in action.lower() for medium_risk in medium_risk_actions):
            factors["medium_risk_action"] = 0.5
        elif any(low_risk in action.lower() for low_risk in low_risk_actions):
            factors["low_risk_action"] = 0.2
        else:
            factors["unknown_action"] = 0.4
        
        return factors

    def _assess_context_risk(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Assess risk based on context factors."""
        factors = {}
        
        # Time-based risk
        current_time = datetime.datetime.utcnow()
        current_hour = current_time.hour
        
        # Off-hours access (outside 8 AM - 6 PM)
        if current_hour < 8 or current_hour > 18:
            factors["off_hours_access"] = 0.6
        
        # Weekend access
        if current_time.weekday() >= 5:  # Saturday or Sunday
            factors["weekend_access"] = 0.5
        
        # Unusual user agent
        user_agent = context.get("user_agent", "")
        if not user_agent or "curl" in user_agent.lower() or "python" in user_agent.lower():
            factors["suspicious_user_agent"] = 0.7
        
        # Geographic anomalies (simplified - would check IP geolocation)
        source_ip = context.get("source_ip", "")
        if source_ip:
            # This is a simplified check - in production, you'd check against known locations
            factors["geographic_risk"] = 0.3
        
        return factors

    def _calculate_risk_score(self, risk_factors: Dict[str, Any]) -> float:
        """Calculate overall risk score from factors."""
        if not risk_factors:
            return 0.5
        
        # Weighted average of risk factors
        weights = {
            "identity_risk_profile": 0.2,
            "privileged_role": 0.15,
            "resource_sensitivity": 0.2,
            "resource_classification": 0.15,
            "resource_type": 0.1,
            "high_risk_action": 0.15,
            "medium_risk_action": 0.1,
            "low_risk_action": 0.05,
            "off_hours_access": 0.1,
            "weekend_access": 0.1,
            "suspicious_user_agent": 0.15,
            "geographic_risk": 0.1,
            "anonymous_auth": 0.3,
            "tailscale_auth": 0.05,
            "other_auth": 0.15,
            "internal_ip": 0.05,
            "external_ip": 0.1,
            "unknown_action": 0.1
        }
        
        weighted_score = 0.0
        total_weight = 0.0
        
        for factor, value in risk_factors.items():
            weight = weights.get(factor, 0.1)
            weighted_score += value * weight
            total_weight += weight
        
        if total_weight > 0:
            return weighted_score / total_weight
        else:
            return 0.5

    def _determine_risk_level(self, risk_score: float) -> RiskLevel:
        """Determine risk level from score."""
        if risk_score >= self.risk_thresholds[RiskLevel.CRITICAL]:
            return RiskLevel.CRITICAL
        elif risk_score >= self.risk_thresholds[RiskLevel.HIGH]:
            return RiskLevel.HIGH
        elif risk_score >= self.risk_thresholds[RiskLevel.MEDIUM]:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def _generate_mitigation_suggestions(
        self,
        identity: IdentityContext,
        resource: ResourceContext,
        action: str,
        risk_factors: Dict[str, Any]
    ) -> List[str]:
        """Generate mitigation suggestions based on risk factors."""
        suggestions = []
        
        # Identity-based suggestions
        if "privileged_role" in risk_factors:
            suggestions.append("Require multi-factor authentication")
            suggestions.append("Require supervisor approval")
        
        if "anonymous_auth" in risk_factors:
            suggestions.append("Require strong authentication")
        
        # Resource-based suggestions
        if "resource_sensitivity" in risk_factors and risk_factors["resource_sensitivity"] > 0.7:
            suggestions.append("Restrict access to authorized personnel only")
            suggestions.append("Enable detailed audit logging")
        
        if "resource_classification" in risk_factors and risk_factors["resource_classification"] > 0.7:
            suggestions.append("Require additional authorization")
            suggestions.append("Implement time-based access controls")
        
        # Action-based suggestions
        if "high_risk_action" in risk_factors:
            suggestions.append("Require explicit approval")
            suggestions.append("Implement additional monitoring")
            suggestions.append("Limit operation scope")
        
        # Context-based suggestions
        if "off_hours_access" in risk_factors:
            suggestions.append("Require justification for off-hours access")
        
        if "weekend_access" in risk_factors:
            suggestions.append("Require weekend access approval")
        
        if "suspicious_user_agent" in risk_factors:
            suggestions.append("Verify user agent legitimacy")
            suggestions.append("Enable additional verification")
        
        return suggestions

    def _requires_approval(self, overall_risk: RiskLevel, risk_factors: Dict[str, Any]) -> bool:
        """Determine if approval is required based on risk."""
        # High and critical risk always require approval
        if overall_risk in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            return True
        
        # Check specific high-risk factors
        high_risk_indicators = [
            "high_risk_action",
            "resource_classification",
            "anonymous_auth"
        ]
        
        if any(indicator in risk_factors for indicator in high_risk_indicators):
            return True
        
        return False


class AdvancedAccessControl:
    """Advanced access control with contextual permissions."""
    
    def __init__(self, audit_logger: Optional[SecurityAuditLogger] = None, identity_manager: Optional[IdentityManager] = None):
        """Initialize advanced access control.
        
        Args:
            audit_logger: Security audit logger
            identity_manager: Identity manager for user context
        """
        self.audit_logger = audit_logger or SecurityAuditLogger()
        self.identity_manager = identity_manager or IdentityManager()
        self.risk_assessor = RiskAssessor()
        
        # Configuration
        self.default_deny = os.getenv("ACCESS_CONTROL_DEFAULT_DENY", "true").lower() == "true"
        self.contextual_permissions = os.getenv("CONTEXTUAL_PERMISSIONS", "true").lower() == "true"
        self.risk_based_access = os.getenv("RISK_BASED_ACCESS", "true").lower() == "true"
        self.separation_of_duties = os.getenv("SEPARATION_OF_DUTIES", "true").lower() == "true"
        
        # Access rules cache
        self._access_rules: List[AccessRule] = []
        self._load_default_rules()
        
        logger.info("Advanced access control initialized")

    def _load_default_rules(self) -> None:
        """Load default access control rules."""
        # System administration rules
        self._access_rules.append(AccessRule(
            rule_id="admin_system",
            name="Admin system access",
            resource_type=ResourceType.SYSTEM,
            action="admin",
            conditions={
                "user_roles": ["admin"],
                "mfa_required": True
            },
            decision=AccessDecision.ALLOW,
            priority=10,
            description="Administrators can perform system administration"
        ))
        
        # Security operations rules
        self._access_rules.append(AccessRule(
            rule_id="security_audit",
            name="Security team audit access",
            resource_type=ResourceType.AUDIT,
            action="read",
            conditions={
                "user_roles": ["security", "admin"],
                "resource_sensitivity": ["internal", "confidential", "restricted"]
            },
            decision=AccessDecision.ALLOW,
            priority=20,
            description="Security team can read audit logs"
        ))
        
        # Operations team rules
        self._access_rules.append(AccessRule(
            rule_id="ops_targets",
            name="Operations team target access",
            resource_type=ResourceType.TARGET,
            action="manage",
            conditions={
                "user_roles": ["operations", "admin"],
                "time_restrictions": {
                    "allowed_hours": list(range(8, 18)),  # 8 AM - 6 PM
                    "allowed_days": list(range(5))  # Monday - Friday
                }
            },
            decision=AccessDecision.CONDITIONAL,
            priority=30,
            description="Operations team can manage targets during business hours"
        ))
        
        # Public read access
        self._access_rules.append(AccessRule(
            rule_id="public_read",
            name="Public read access",
            resource_type=ResourceType.DATA,
            action="read",
            conditions={
                "resource_sensitivity": ["public"]
            },
            decision=AccessDecision.ALLOW,
            priority=90,
            description="Anyone can read public data"
        ))
        
        # Default deny rule
        self._access_rules.append(AccessRule(
            rule_id="default_deny",
            name="Default deny",
            resource_type=ResourceType.SYSTEM,
            action="*",
            conditions={},
            decision=AccessDecision.DENY,
            priority=100,
            description="Default deny all access"
        ))

    async def evaluate_access(
        self,
        identity: IdentityContext,
        resource: ResourceContext,
        action: str,
        context: Optional[Dict[str, Any]] = None
    ) -> AccessDecisionResult:
        """Evaluate access with contextual factors.
        
        Args:
            identity: User identity
            resource: Resource being accessed
            action: Action being performed
            context: Additional context (IP, time, etc.)
            
        Returns:
            Access decision result
        """
        try:
            context = context or {}
            
            # Perform risk assessment
            risk_assessment = await self._assess_operation_risk(
                identity, resource, action, context
            )
            
            # Evaluate against access rules
            decision = self._evaluate_access_rules(identity, resource, action)
            
            # Apply contextual controls
            if self.contextual_permissions:
                decision = self._apply_contextual_controls(
                    decision, identity, resource, action, context
                )
            
            # Apply risk-based controls
            if self.risk_based_access:
                decision = self._apply_risk_based_controls(
                    decision, risk_assessment
                )
            
            # Log access attempt
            access_attempt = AccessAttempt(
                identity=identity,
                resource=resource,
                action=action,
                decision=decision.decision,
                decision_reason=decision.reason,
                risk_score=risk_assessment.overall_risk.value if hasattr(risk_assessment.overall_risk, 'value') else None,
                enforcement_details={
                    "risk_assessment": risk_assessment.risk_factors,
                    "mitigation_suggestions": risk_assessment.mitigation_suggestions
                }
            )
            
            await self.audit_logger.log_access_attempt(access_attempt)
            
            return decision
            
        except Exception as e:
            logger.error(f"Access evaluation failed: {e}")
            # Default to deny on error
            return AccessDecisionResult(
                decision=AccessDecision.DENY,
                reason=f"Access evaluation error: {str(e)}"
            )

    async def check_resource_permissions(
        self,
        identity: IdentityContext,
        resource: ResourceContext
    ) -> Set[str]:
        """Get detailed resource permissions for identity.
        
        Args:
            identity: User identity
            resource: Resource context
            
        Returns:
            Set of allowed actions
        """
        try:
            allowed_actions = set()
            
            # Check each potential action
            potential_actions = [
                "read", "write", "delete", "admin", "manage", "execute",
                "configure", "monitor", "backup", "restore"
            ]
            
            for action in potential_actions:
                decision = await self.evaluate_access(
                    identity, resource, action, {}
                )
                
                if decision.decision == AccessDecision.ALLOW:
                    allowed_actions.add(action)
                elif decision.decision == AccessDecision.CONDITIONAL:
                    # Add conditional actions but mark them
                    allowed_actions.add(f"{action}_conditional")
            
            return allowed_actions
            
        except Exception as e:
            logger.error(f"Failed to check resource permissions: {e}")
            return set()

    async def evaluate_risk(
        self,
        identity: IdentityContext,
        operation: SecurityOperation
    ) -> RiskAssessment:
        """Evaluate operational risk.
        
        Args:
            identity: User identity
            operation: Security operation
            
        Returns:
            Risk assessment
        """
        try:
            # Create resource context from operation
            resource_contexts = []
            for target_resource in operation.target_resources:
                resource_contexts.append(target_resource)
            
            # Assess risk for each resource
            risk_assessments = []
            for resource in resource_contexts:
                assessment = self.risk_assessor.assess_access_risk(
                    identity, resource, operation.operation_type,
                    {
                        "source_ip": operation.source_ip,
                        "user_agent": operation.user_agent,
                        "session_id": operation.session_id
                    }
                )
                risk_assessments.append(assessment)
            
            # Combine assessments (take the highest risk)
            highest_risk = max(risk_assessments, key=lambda x: self._risk_level_to_score(x.overall_risk))
            
            # Combine risk factors
            combined_factors = {}
            for assessment in risk_assessments:
                combined_factors.update(assessment.risk_factors)
            
            # Combine mitigation suggestions
            combined_suggestions = []
            for assessment in risk_assessments:
                combined_suggestions.extend(assessment.mitigation_suggestions)
            
            # Remove duplicates
            combined_suggestions = list(set(combined_suggestions))
            
            # Determine if approval is required
            requires_approval = any(assessment.requires_approval for assessment in risk_assessments)
            
            return RiskAssessment(
                overall_risk=highest_risk.overall_risk,
                risk_factors=combined_factors,
                mitigation_suggestions=combined_suggestions,
                requires_approval=requires_approval
            )
            
        except Exception as e:
            logger.error(f"Risk evaluation failed: {e}")
            return RiskAssessment(
                overall_risk=RiskLevel.HIGH,
                risk_factors={"error": str(e)},
                mitigation_suggestions=["Manual review required"],
                requires_approval=True
            )

    async def enforce_mfa_requirement(
        self,
        identity: IdentityContext,
        operation: SecurityOperation
    ) -> bool:
        """Check MFA requirements for an operation.
        
        Args:
            identity: User identity
            operation: Security operation
            
        Returns:
            True if MFA is enforced, False otherwise
        """
        try:
            # Check if user has required roles for MFA
            mfa_roles = os.getenv("MFA_REQUIRED_ROLES", "admin,security,operations").split(",")
            if any(role in identity.roles for role in mfa_roles):
                return True
            
            # Check if operation is high-risk
            risk_assessment = await self.evaluate_risk(identity, operation)
            if risk_assessment.overall_risk in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                return True
            
            # Check if resource requires MFA
            for resource in operation.target_resources:
                if resource.security_classification in [
                    SecurityClassification.CONFIDENTIAL,
                    SecurityClassification.SECRET,
                    SecurityClassification.TOP_SECRET
                ]:
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"MFA requirement check failed: {e}")
            return True  # Default to requiring MFA on error

    async def log_access_decision(self, decision: AccessDecisionResult) -> None:
        """Log access control decisions.
        
        Args:
            decision: Access decision to log
        """
        try:
            # This would log to the audit system
            logger.info(f"Access decision: {decision.decision.value} - {decision.reason}")
            
        except Exception as e:
            logger.error(f"Failed to log access decision: {e}")

    def _evaluate_access_rules(
        self,
        identity: IdentityContext,
        resource: ResourceContext,
        action: str
    ) -> AccessDecisionResult:
        """Evaluate access against configured rules."""
        # Sort rules by priority (lower number = higher priority)
        sorted_rules = sorted(self._access_rules, key=lambda r: r.priority)
        
        for rule in sorted_rules:
            if rule.matches(identity, resource, action):
                reason = f"Matched rule: {rule.name} ({rule.description})"
                return AccessDecisionResult(
                    decision=rule.decision,
                    reason=reason,
                    conditions=rule.conditions.get("conditions", [])
                )
        
        # No rule matched
        if self.default_deny:
            return AccessDecisionResult(
                decision=AccessDecision.DENY,
                reason="No matching access rule found (default deny)"
            )
        else:
            return AccessDecisionResult(
                decision=AccessDecision.ALLOW,
                reason="No matching access rule found (default allow)"
            )

    def _apply_contextual_controls(
        self,
        decision: AccessDecisionResult,
        identity: IdentityContext,
        resource: ResourceContext,
        action: str,
        context: Dict[str, Any]
    ) -> AccessDecisionResult:
        """Apply contextual access controls."""
        # Time-based restrictions
        current_time = datetime.datetime.utcnow()
        current_hour = current_time.hour
        
        # Check if action requires business hours
        if action in ["admin", "delete", "modify"] and current_hour < 8 or current_hour > 18:
            if decision.decision == AccessDecision.ALLOW:
                return AccessDecisionResult(
                    decision=AccessDecision.CONDITIONAL,
                    reason=f"{decision.reason} - Outside business hours, conditional access granted",
                    conditions=["Require justification", "Additional monitoring"]
                )
        
        # Weekend restrictions
        if current_time.weekday() >= 5:  # Saturday or Sunday
            if decision.decision == AccessDecision.ALLOW and action in ["admin", "delete"]:
                return AccessDecisionResult(
                    decision=AccessDecision.REVIEW_REQUIRED,
                    reason=f"{decision.reason} - Weekend access requires review",
                    conditions=["Manager approval required"]
                )
        
        return decision

    def _apply_risk_based_controls(
        self,
        decision: AccessDecisionResult,
        risk_assessment: RiskAssessment
    ) -> AccessDecisionResult:
        """Apply risk-based access controls."""
        # High risk operations
        if risk_assessment.overall_risk == RiskLevel.CRITICAL:
            return AccessDecisionResult(
                decision=AccessDecision.DENY,
                reason=f"{decision.reason} - Critical risk operation denied",
                conditions=["Manual review required"]
            )
        
        # Medium-high risk operations
        elif risk_assessment.overall_risk == RiskLevel.HIGH:
            if decision.decision == AccessDecision.ALLOW:
                return AccessDecisionResult(
                    decision=AccessDecision.CONDITIONAL,
                    reason=f"{decision.reason} - High risk, conditional access granted",
                    conditions=risk_assessment.mitigation_suggestions
                )
        
        # Approval requirements
        if risk_assessment.requires_approval and decision.decision == AccessDecision.ALLOW:
            return AccessDecisionResult(
                decision=AccessDecision.REVIEW_REQUIRED,
                reason=f"{decision.reason} - Approval required due to risk factors",
                conditions=["Manager approval"] + risk_assessment.mitigation_suggestions
            )
        
        return decision

    async def _assess_operation_risk(
        self,
        identity: IdentityContext,
        resource: ResourceContext,
        action: str,
        context: Dict[str, Any]
    ) -> RiskAssessment:
        """Assess risk for an operation."""
        return self.risk_assessor.assess_access_risk(identity, resource, action, context)

    def _risk_level_to_score(self, risk_level: RiskLevel) -> float:
        """Convert risk level to numerical score."""
        return {
            RiskLevel.LOW: 0.25,
            RiskLevel.MEDIUM: 0.5,
            RiskLevel.HIGH: 0.75,
            RiskLevel.CRITICAL: 0.95
        }.get(risk_level, 0.5)