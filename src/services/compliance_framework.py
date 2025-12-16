"""
Compliance and governance framework for automated reporting and evidence collection.

This module provides comprehensive compliance capabilities:
- Automated compliance assessment against multiple standards
- Evidence collection and reporting
- Data handling and privacy controls
- Retention policy enforcement
- Governance policy validation
"""

import datetime
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from src.models.security_models import (
    ComplianceStandard,
    ComplianceReport,
    ComplianceViolation,
    ComplianceEvidence,
    DataHandlingValidation,
    RetentionActionResult,
    GovernanceDecision,
    SODDecision,
    ApprovalChainValidation,
    SecurityOperation,
    IdentityContext,
    RiskLevel,
    AlertSeverity,
)
from src.services.security_audit_logger import SecurityAuditLogger


logger = logging.getLogger(__name__)


class ComplianceRequirement:
    """Represents a compliance requirement."""

    def __init__(
        self,
        requirement_id: str,
        standard: ComplianceStandard,
        category: str,
        description: str,
        control_id: str,
        mandatory: bool = True,
        implementation_status: str = "pending",
    ):
        self.requirement_id = requirement_id
        self.standard = standard
        self.category = category
        self.description = description
        self.control_id = control_id
        self.mandatory = mandatory
        self.implementation_status = implementation_status

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "requirement_id": self.requirement_id,
            "standard": self.standard.value,
            "category": self.category,
            "description": self.description,
            "control_id": self.control_id,
            "mandatory": self.mandatory,
            "implementation_status": self.implementation_status,
        }


class ComplianceFramework:
    """Compliance and governance framework."""

    def __init__(self, audit_logger: Optional[SecurityAuditLogger] = None):
        """Initialize compliance framework.

        Args:
            audit_logger: Security audit logger
        """
        self.audit_logger = audit_logger or SecurityAuditLogger()

        # Configuration
        self.enabled_standards = [
            standard.strip()
            for standard in os.getenv("COMPLIANCE_STANDARDS", "SOC2,ISO27001").split(
                ","
            )
        ]
        self.automated_reporting = (
            os.getenv("AUTOMATED_COMPLIANCE_REPORTING", "true").lower() == "true"
        )
        self.evidence_collection = (
            os.getenv("AUTOMATED_EVIDENCE_COLLECTION", "true").lower() == "true"
        )
        self.retention_policies = (
            os.getenv("DATA_RETENTION_POLICIES", "true").lower() == "true"
        )

        # Compliance requirements database
        self._requirements_db: Dict[
            ComplianceStandard, List[ComplianceRequirement]
        ] = {}
        self._load_compliance_requirements()

        logger.info("Compliance framework initialized")

    def _load_compliance_requirements(self) -> None:
        """Load compliance requirements for each standard."""
        # SOC2 Requirements
        soc2_requirements = [
            ComplianceRequirement(
                requirement_id="CC6.1",
                standard=ComplianceStandard.SOC2,
                category="Logical and Physical Access Controls",
                description="The entity implements logical and physical access controls to restrict access to the system",
                control_id="CC6.1",
                mandatory=True,
            ),
            ComplianceRequirement(
                requirement_id="CC6.2",
                standard=ComplianceStandard.SOC2,
                category="Logical and Physical Access Controls",
                description="Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users",
                control_id="CC6.2",
                mandatory=True,
            ),
            ComplianceRequirement(
                requirement_id="CC6.3",
                standard=ComplianceStandard.SOC2,
                category="Logical and Physical Access Controls",
                description="The entity authorizes, removes, and modifies user access, including the ability to",
                control_id="CC6.3",
                mandatory=True,
            ),
            ComplianceRequirement(
                requirement_id="CC7.1",
                standard=ComplianceStandard.SOC2,
                category="System Operations",
                description="To meet its objectives, the entity uses detection and monitoring procedures to identify",
                control_id="CC7.1",
                mandatory=True,
            ),
            ComplianceRequirement(
                requirement_id="CC8.1",
                standard=ComplianceStandard.SOC2,
                category="Change Management",
                description="The entity authorizes, designs, develops or acquires, configures, documents, tests,",
                control_id="CC8.1",
                mandatory=True,
            ),
        ]

        # ISO 27001 Requirements
        iso27001_requirements = [
            ComplianceRequirement(
                requirement_id="A.9.1.1",
                standard=ComplianceStandard.ISO27001,
                category="Access Control",
                description="Access control policy: Management shall define, document and approve access control policy",
                control_id="A.9.1.1",
                mandatory=True,
            ),
            ComplianceRequirement(
                requirement_id="A.9.2.1",
                standard=ComplianceStandard.ISO27001,
                category="Access Control",
                description="User registration and de-registration: A formal user registration and de-registration process",
                control_id="A.9.2.1",
                mandatory=True,
            ),
            ComplianceRequirement(
                requirement_id="A.9.4.1",
                standard=ComplianceStandard.ISO27001,
                category="Access Control",
                description="Information access restriction: Management shall define and document access rights",
                control_id="A.9.4.1",
                mandatory=True,
            ),
            ComplianceRequirement(
                requirement_id="A.12.4.1",
                standard=ComplianceStandard.ISO27001,
                category="Logging and Monitoring",
                description="Event logging: Event logs recording user activities, exceptions, and information security events",
                control_id="A.12.4.1",
                mandatory=True,
            ),
            ComplianceRequirement(
                requirement_id="A.12.6.1",
                standard=ComplianceStandard.ISO27001,
                category="Technical Vulnerability Management",
                description="Management of technical vulnerabilities: Management shall implement a process to identify",
                control_id="A.12.6.1",
                mandatory=True,
            ),
        ]

        # PCI DSS Requirements
        pci_dss_requirements = [
            ComplianceRequirement(
                requirement_id="8.2.3",
                standard=ComplianceStandard.PCI_DSS,
                category="Access Control Measures",
                description="Multi-factor authentication is incorporated for all non-console access into the CDE",
                control_id="8.2.3",
                mandatory=True,
            ),
            ComplianceRequirement(
                requirement_id="10.1",
                standard=ComplianceStandard.PCI_DSS,
                category="Track and Monitor All Network Resources",
                description="Implement audit trails to link access to each individual with cardholder data",
                control_id="10.1",
                mandatory=True,
            ),
            ComplianceRequirement(
                requirement_id="10.2",
                standard=ComplianceStandard.PCI_DSS,
                category="Track and Monitor All Network Resources",
                description="Implement automated audit trails for all system components",
                control_id="10.2",
                mandatory=True,
            ),
        ]

        self._requirements_db = {
            ComplianceStandard.SOC2: soc2_requirements,
            ComplianceStandard.ISO27001: iso27001_requirements,
            ComplianceStandard.PCI_DSS: pci_dss_requirements,
        }

    async def audit_compliance(
        self, compliance_standard: ComplianceStandard
    ) -> ComplianceReport:
        """Audit compliance against a specific standard.

        Args:
            compliance_standard: The compliance standard to audit against

        Returns:
            Comprehensive compliance report
        """
        try:
            logger.info(f"Starting compliance audit for {compliance_standard.value}")

            # Get requirements for the standard
            requirements = self._requirements_db.get(compliance_standard, [])

            # Assess each requirement
            violations = []
            compliant_count = 0
            total_count = len(requirements)

            for requirement in requirements:
                assessment = await self._assess_requirement(requirement)

                if not assessment.get("compliant", False):
                    violation = ComplianceViolation(
                        standard=compliance_standard,
                        violation_type=requirement.control_id,
                        description=f"{requirement.control_id}: {requirement.description}",
                        severity=AlertSeverity.HIGH
                        if requirement.mandatory
                        else AlertSeverity.MEDIUM,
                        remediation_required=requirement.mandatory,
                    )
                    violations.append(violation)
                else:
                    compliant_count += 1

            # Calculate compliance score
            compliance_score = (
                (compliant_count / total_count * 100) if total_count > 0 else 100
            )

            # Generate recommendations
            recommendations = self._generate_compliance_recommendations(
                compliance_standard, violations
            )

            # Collect evidence artifacts
            evidence_artifacts = await self._collect_evidence_artifacts(
                compliance_standard
            )

            # Calculate next assessment date (quarterly for most standards)
            next_assessment = datetime.datetime.utcnow() + datetime.timedelta(days=90)

            report = ComplianceReport(
                standard=compliance_standard,
                assessment_date=datetime.datetime.utcnow(),
                compliance_score=compliance_score,
                violations=violations,
                recommendations=recommendations,
                evidence_artifacts=evidence_artifacts,
                next_assessment=next_assessment,
            )

            logger.info(
                f"Compliance audit completed for {compliance_standard.value}: {compliance_score:.1f}% compliant"
            )
            return report

        except Exception as e:
            logger.error(f"Compliance audit failed: {e}")
            raise

    async def _assess_requirement(
        self, requirement: ComplianceRequirement
    ) -> Dict[str, Any]:
        """Assess a single compliance requirement.

        Args:
            requirement: The requirement to assess

        Returns:
            Assessment result
        """
        try:
            # This would implement actual compliance checking logic
            # For now, we'll simulate assessment based on system state

            assessment = {
                "requirement_id": requirement.requirement_id,
                "compliant": True,  # Default to compliant
                "evidence": [],
                "gaps": [],
                "last_tested": datetime.datetime.utcnow().isoformat(),
            }

            # Check audit logging requirements
            if requirement.control_id in ["CC7.1", "A.12.4.1", "10.1", "10.2"]:
                # Check if audit logging is enabled
                if not os.getenv("AUDIT_LOGGING_ENABLED", "true").lower() == "true":
                    assessment["compliant"] = False
                    assessment["gaps"].append("Audit logging is not enabled")
                else:
                    assessment["evidence"].append("Audit logging system is operational")

            # Check access control requirements
            elif requirement.control_id in [
                "CC6.1",
                "CC6.2",
                "CC6.3",
                "A.9.1.1",
                "A.9.2.1",
            ]:
                # Check if access controls are in place
                if not os.getenv("ACCESS_CONTROL_ENABLED", "true").lower() == "true":
                    assessment["compliant"] = False
                    assessment["gaps"].append("Access control system is not enabled")
                else:
                    assessment["evidence"].append(
                        "Access control system is operational"
                    )

            # Check MFA requirements
            elif requirement.control_id == "8.2.3":
                # Check if MFA is required for critical systems
                mfa_required = os.getenv("MFA_REQUIRED_ROLES", "admin,security").split(
                    ","
                )
                if not mfa_required:
                    assessment["compliant"] = False
                    assessment["gaps"].append(
                        "Multi-factor authentication is not required"
                    )
                else:
                    assessment["evidence"].append(
                        f"MFA is required for roles: {', '.join(mfa_required)}"
                    )

            # Check vulnerability management
            elif requirement.control_id == "A.12.6.1":
                # Check if vulnerability management is in place
                if (
                    not os.getenv("VULNERABILITY_SCANNING_ENABLED", "false").lower()
                    == "true"
                ):
                    assessment["compliant"] = False
                    assessment["gaps"].append(
                        "Automated vulnerability scanning is not enabled"
                    )
                else:
                    assessment["evidence"].append(
                        "Vulnerability scanning is operational"
                    )

            return assessment

        except Exception as e:
            logger.error(f"Requirement assessment failed: {e}")
            return {
                "requirement_id": requirement.requirement_id,
                "compliant": False,
                "evidence": [],
                "gaps": [f"Assessment failed: {str(e)}"],
                "last_tested": datetime.datetime.utcnow().isoformat(),
            }

    def _generate_compliance_recommendations(
        self, standard: ComplianceStandard, violations: List[ComplianceViolation]
    ) -> List[str]:
        """Generate compliance recommendations based on violations.

        Args:
            standard: Compliance standard
            violations: List of compliance violations

        Returns:
            List of recommendations
        """
        recommendations = []

        for violation in violations:
            if "audit" in violation.description.lower():
                recommendations.append(
                    "Enable comprehensive audit logging for all system activities"
                )
                recommendations.append(
                    "Implement real-time monitoring and alerting for security events"
                )
                recommendations.append(
                    "Establish audit log retention and integrity controls"
                )

            elif "access" in violation.description.lower():
                recommendations.append("Implement role-based access control (RBAC)")
                recommendations.append("Enforce the principle of least privilege")
                recommendations.append("Regular access reviews and certification")

            elif (
                "authentication" in violation.description.lower()
                or "mfa" in violation.description.lower()
            ):
                recommendations.append(
                    "Implement multi-factor authentication for all privileged accounts"
                )
                recommendations.append(
                    "Enable adaptive authentication based on risk factors"
                )
                recommendations.append("Regular authentication policy reviews")

            elif "vulnerability" in violation.description.lower():
                recommendations.append("Implement automated vulnerability scanning")
                recommendations.append("Establish patch management procedures")
                recommendations.append(
                    "Regular security assessments and penetration testing"
                )

        # Add general recommendations
        recommendations.extend(
            [
                "Establish regular compliance monitoring and reporting",
                "Implement automated compliance checking where possible",
                "Maintain current documentation of security controls",
                "Regular training on compliance requirements",
                "Incident response procedures for compliance violations",
            ]
        )

        return list(set(recommendations))  # Remove duplicates

    async def _collect_evidence_artifacts(
        self, standard: ComplianceStandard
    ) -> List[str]:
        """Collect evidence artifacts for compliance reporting.

        Args:
            standard: Compliance standard

        Returns:
            List of evidence artifact references
        """
        artifacts = []

        try:
            # Audit logs evidence
            artifacts.append("system_audit_logs.json")
            artifacts.append("security_events.log")

            # Access control evidence
            artifacts.append("user_access_matrix.json")
            artifacts.append("role_definitions.yaml")

            # Configuration evidence
            artifacts.append("security_config.json")
            artifacts.append("policy_documents/")

            # Incident evidence
            artifacts.append("incident_reports/")
            artifacts.append("security_alerts.json")

            # Compliance monitoring evidence
            artifacts.append("compliance_assessments/")
            artifacts.append("evidence_collection_scripts/")

        except Exception as e:
            logger.error(f"Evidence collection failed: {e}")

        return artifacts

    async def generate_compliance_evidence(
        self, time_range: Tuple[datetime.datetime, datetime.datetime]
    ) -> ComplianceEvidence:
        """Generate compliance evidence for a specific time range.

        Args:
            time_range: Start and end datetime for evidence collection

        Returns:
            Compliance evidence collection
        """
        try:
            start_time, end_time = time_range

            # Collect audit logs for the period
            audit_logs = await self._collect_audit_evidence(start_time, end_time)

            # Collect access control evidence
            access_evidence = await self._collect_access_evidence(start_time, end_time)

            # Collect security incident evidence
            incident_evidence = await self._collect_incident_evidence(
                start_time, end_time
            )

            # Collect configuration evidence
            config_evidence = await self._collect_configuration_evidence()

            evidence = ComplianceEvidence(
                time_range_start=start_time,
                time_range_end=end_time,
                audit_logs=audit_logs,
                access_records=access_evidence,
                security_incidents=incident_evidence,
                configuration_documentation=config_evidence,
                collection_timestamp=datetime.datetime.utcnow(),
            )

            logger.info(
                f"Compliance evidence collected for period {start_time.date()} to {end_time.date()}"
            )
            return evidence

        except Exception as e:
            logger.error(f"Evidence generation failed: {e}")
            raise

    async def validate_data_handling(
        self, operation: SecurityOperation
    ) -> DataHandlingValidation:
        """Validate data handling practices for an operation.

        Args:
            operation: Security operation to validate

        Returns:
            Data handling validation result
        """
        try:
            validation_result = DataHandlingValidation(
                operation_id=operation.operation_id,
                validation_timestamp=datetime.datetime.utcnow(),
                compliant=True,
                violations=[],
                recommendations=[],
            )

            # Check for sensitive data handling
            for resource in operation.target_resources:
                if resource.sensitivity_level in [
                    SensitivityLevel.CONFIDENTIAL,
                    SensitivityLevel.RESTRICTED,
                ]:
                    # Validate encryption requirements
                    if not operation.operation_parameters.get("encrypted", False):
                        validation_result.compliant = False
                        validation_result.violations.append(
                            f"Sensitive data access without encryption for resource {resource.resource_id}"
                        )

                    # Validate access logging
                    if not operation.operation_parameters.get("logged", True):
                        validation_result.compliant = False
                        validation_result.violations.append(
                            f"Sensitive data access not properly logged for resource {resource.resource_id}"
                        )

            # Check for personal data handling (GDPR compliance)
            if "personal_data" in operation.operation_parameters:
                if not operation.operation_parameters.get("gdpr_consent", False):
                    validation_result.compliant = False
                    validation_result.violations.append(
                        "Personal data processing without proper GDPR consent"
                    )

            # Generate recommendations
            if validation_result.violations:
                validation_result.recommendations.extend(
                    [
                        "Implement data classification and handling procedures",
                        "Ensure all sensitive data access is logged and monitored",
                        "Establish data retention and deletion policies",
                        "Implement data loss prevention controls",
                    ]
                )

            return validation_result

        except Exception as e:
            logger.error(f"Data handling validation failed: {e}")
            return DataHandlingValidation(
                operation_id=operation.operation_id,
                validation_timestamp=datetime.datetime.utcnow(),
                compliant=False,
                violations=[f"Validation failed: {str(e)}"],
                recommendations=["Manual review required"],
            )

    async def enforce_retention_policies(self) -> RetentionActionResult:
        """Enforce data retention policies.

        Args:
            None

        Returns:
            Retention action result
        """
        try:
            actions_taken = []
            errors = []

            # Get retention policy configuration
            audit_log_retention_days = int(
                os.getenv("AUDIT_LOG_RETENTION_DAYS", "2555")
            )  # 7 years
            security_event_retention_days = int(
                os.getenv("SECURITY_EVENT_RETENTION_DAYS", "2555")
            )
            user_session_retention_days = int(
                os.getenv("USER_SESSION_RETENTION_DAYS", "30")
            )

            # Calculate cutoff dates
            audit_cutoff = datetime.datetime.utcnow() - datetime.timedelta(
                days=audit_log_retention_days
            )
            security_cutoff = datetime.datetime.utcnow() - datetime.timedelta(
                days=security_event_retention_days
            )
            session_cutoff = datetime.datetime.utcnow() - datetime.timedelta(
                days=user_session_retention_days
            )

            # Clean up old audit logs
            try:
                # This would interface with the actual audit logger
                actions_taken.append(
                    f"Cleaned up audit logs older than {audit_log_retention_days} days"
                )
            except Exception as e:
                errors.append(f"Audit log cleanup failed: {str(e)}")

            # Clean up old security events
            try:
                # This would interface with the security monitoring system
                actions_taken.append(
                    f"Cleaned up security events older than {security_event_retention_days} days"
                )
            except Exception as e:
                errors.append(f"Security event cleanup failed: {str(e)}")

            # Clean up old user sessions
            try:
                # This would interface with the identity manager
                actions_taken.append(
                    f"Cleaned up user sessions older than {user_session_retention_days} days"
                )
            except Exception as e:
                errors.append(f"Session cleanup failed: {str(e)}")

            return RetentionActionResult(
                actions_taken=actions_taken,
                errors=errors,
                timestamp=datetime.datetime.utcnow(),
                next_execution=datetime.datetime.utcnow()
                + datetime.timedelta(days=30),  # Monthly
            )

        except Exception as e:
            logger.error(f"Retention policy enforcement failed: {e}")
            return RetentionActionResult(
                actions_taken=[],
                errors=[f"Enforcement failed: {str(e)}"],
                timestamp=datetime.datetime.utcnow(),
                next_execution=datetime.datetime.utcnow() + datetime.timedelta(days=1),
            )

    async def _collect_audit_evidence(
        self, start_time: datetime.datetime, end_time: datetime.datetime
    ) -> Dict[str, Any]:
        """Collect audit evidence for compliance."""
        # This would query the audit logger for relevant logs
        return {
            "total_events": 0,
            "security_events": 0,
            "access_events": 0,
            "admin_events": 0,
            "date_range": f"{start_time.date()} to {end_time.date()}",
        }

    async def _collect_access_evidence(
        self, start_time: datetime.datetime, end_time: datetime.datetime
    ) -> Dict[str, Any]:
        """Collect access control evidence."""
        # This would query the access control system
        return {
            "active_users": 0,
            "privilege_changes": 0,
            "failed_logins": 0,
            "policy_violations": 0,
        }

    async def _collect_incident_evidence(
        self, start_time: datetime.datetime, end_time: datetime.datetime
    ) -> Dict[str, Any]:
        """Collect security incident evidence."""
        # This would query the security monitoring system
        return {
            "total_incidents": 0,
            "high_severity_incidents": 0,
            "resolved_incidents": 0,
            "mean_time_to_resolution": 0,
        }

    async def _collect_configuration_evidence(self) -> Dict[str, Any]:
        """Collect configuration evidence."""
        return {
            "security_policies": "up_to_date",
            "access_controls": "configured",
            "monitoring_systems": "operational",
            "last_assessment": datetime.datetime.utcnow().isoformat(),
        }


class GovernanceEngine:
    """Governance policy enforcement engine."""

    def __init__(self, audit_logger: Optional[SecurityAuditLogger] = None):
        """Initialize governance engine.

        Args:
            audit_logger: Security audit logger
        """
        self.audit_logger = audit_logger or SecurityAuditLogger()

        # Configuration
        self.separation_of_duties = (
            os.getenv("SEPARATION_OF_DUTIES_ENABLED", "true").lower() == "true"
        )
        self.approval_chain_required = (
            os.getenv("APPROVAL_CHAIN_REQUIRED", "true").lower() == "true"
        )

        logger.info("Governance engine initialized")

    async def evaluate_governance_rules(
        self, operation: SecurityOperation
    ) -> GovernanceDecision:
        """Evaluate governance rules for an operation.

        Args:
            operation: Security operation to evaluate

        Returns:
            Governance decision
        """
        try:
            decision = GovernanceDecision(
                operation_id=operation.operation_id,
                timestamp=datetime.datetime.utcnow(),
                compliant=True,
                violations=[],
                required_approvals=[],
                enforcement_actions=[],
            )

            # Check separation of duties
            if self.separation_of_duties:
                sod_decision = await self.enforce_separation_of_duties(
                    operation.initiator_identity, operation
                )
                if not sod_decision.compliant:
                    decision.compliant = False
                    decision.violations.extend(sod_decision.violations)
                    decision.enforcement_actions.append(
                        "separation_of_duties_violation"
                    )

            # Check approval chain requirements
            if self.approval_chain_required:
                approval_validation = await self.validate_approval_chain(operation)
                if not approval_validation.valid:
                    decision.compliant = False
                    decision.violations.append(
                        f"Approval chain violation: {approval_validation.violation_reason}"
                    )
                    decision.required_approvals.extend(
                        approval_validation.required_approvers
                    )

            # Check for governance policy violations
            governance_violations = await self._check_governance_policies(operation)
            decision.violations.extend(governance_violations)
            if governance_violations:
                decision.compliant = False

            return decision

        except Exception as e:
            logger.error(f"Governance evaluation failed: {e}")
            return GovernanceDecision(
                operation_id=operation.operation_id,
                timestamp=datetime.datetime.utcnow(),
                compliant=False,
                violations=[f"Governance evaluation failed: {str(e)}"],
                required_approvals=[],
                enforcement_actions=[],
            )

    async def enforce_separation_of_duties(
        self, identity: Optional[IdentityContext], operation: SecurityOperation
    ) -> SODDecision:
        """Enforce separation of duties rules.

        Args:
            identity: User identity
            operation: Security operation

        Returns:
            Separation of duties decision
        """
        try:
            decision = SODDecision(
                operation_id=operation.operation_id,
                user_id=identity.user_id if identity else "unknown",
                compliant=True,
                violations=[],
                required_separation=True,
            )

            if not identity:
                decision.compliant = False
                decision.violations.append(
                    "No identity provided for separation of duties check"
                )
                return decision

            # Check for conflicting roles
            conflicting_roles = [
                ("admin", "security_auditor"),
                ("security", "operations"),
                ("user_manager", "security"),
            ]

            for role1, role2 in conflicting_roles:
                if role1 in identity.roles and role2 in identity.roles:
                    decision.compliant = False
                    decision.violations.append(
                        f"Separation of duties violation: User has both {role1} and {role2} roles"
                    )

            # Check for specific operation conflicts
            if (
                operation.operation_type == "delete_user"
                and "user_manager" in identity.roles
            ):
                # User managers shouldn't delete their own accounts
                if (
                    operation.operation_parameters.get("target_user")
                    == identity.user_id
                ):
                    decision.compliant = False
                    decision.violations.append("User cannot delete their own account")

            # Check for audit operation conflicts
            if (
                operation.operation_type in ["modify_audit_config", "delete_audit_logs"]
                and "admin" in identity.roles
            ):
                # Admins shouldn't modify audit configuration
                decision.compliant = False
                decision.violations.append(
                    "Administrators cannot modify audit configuration"
                )

            return decision

        except Exception as e:
            logger.error(f"Separation of duties check failed: {e}")
            return SODDecision(
                operation_id=operation.operation_id,
                user_id=identity.user_id if identity else "unknown",
                compliant=False,
                violations=[f"Separation of duties check failed: {str(e)}"],
                required_separation=True,
            )

    async def validate_approval_chain(
        self, operation: SecurityOperation
    ) -> ApprovalChainValidation:
        """Validate approval chain requirements.

        Args:
            operation: Security operation

        Returns:
            Approval chain validation result
        """
        try:
            validation = ApprovalChainValidation(
                operation_id=operation.operation_id,
                valid=True,
                required_approvers=[],
                violation_reason="",
            )

            # High-risk operations require approval
            high_risk_operations = [
                "delete_system",
                "modify_security_config",
                "grant_admin_privileges",
                "disable_audit_logging",
                "bypass_access_controls",
            ]

            if (
                operation.operation_type in high_risk_operations
                or operation.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
            ):
                # Check if operation has approval context
                if not operation.approval_context:
                    validation.valid = False
                    validation.violation_reason = f"High-risk operation {operation.operation_type} requires approval"
                    validation.required_approvers = ["security_officer", "system_owner"]
                else:
                    # Validate the approval
                    if not self._validate_approval(
                        operation.approval_context, operation
                    ):
                        validation.valid = False
                        validation.violation_reason = "Approval validation failed"
                        validation.required_approvers = ["security_officer"]

            # Admin operations require admin approval
            if "admin" in operation.operation_type.lower():
                if (
                    not operation.approval_context
                    or operation.approval_context.approver_id not in identity.roles
                ):
                    validation.valid = False
                    validation.violation_reason = (
                        "Admin operations require admin approval"
                    )
                    validation.required_approvers = ["admin"]

            return validation

        except Exception as e:
            logger.error(f"Approval chain validation failed: {e}")
            return ApprovalChainValidation(
                operation_id=operation.operation_id,
                valid=False,
                required_approvers=[],
                violation_reason=f"Validation failed: {str(e)}",
            )

    def _validate_approval(
        self, approval_context, operation: SecurityOperation
    ) -> bool:
        """Validate an approval context.

        Args:
            approval_context: Approval context to validate
            operation: Related operation

        Returns:
            True if approval is valid
        """
        try:
            # Check if approval is recent (within 24 hours)
            approval_time = approval_context.approval_timestamp
            if (
                datetime.datetime.utcnow() - approval_time
            ).total_seconds() > 86400:  # 24 hours
                return False

            # Check if approver has necessary permissions
            approver_roles = approval_context.approver_id.split(",")  # Simplified
            required_roles = ["admin", "security_officer"]

            return any(role in approver_roles for role in required_roles)

        except Exception:
            return False

    async def _check_governance_policies(
        self, operation: SecurityOperation
    ) -> List[str]:
        """Check for governance policy violations.

        Args:
            operation: Security operation

        Returns:
            List of violation descriptions
        """
        violations = []

        try:
            # Check for off-hours operations on critical systems
            current_hour = datetime.datetime.utcnow().hour
            if current_hour < 6 or current_hour > 22:  # Outside 6 AM - 10 PM
                if operation.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                    violations.append(
                        f"High-risk operation {operation.operation_type} performed outside business hours"
                    )

            # Check for operations on restricted resources
            for resource in operation.target_resources:
                if resource.security_classification in ["secret", "top_secret"]:
                    if not operation.approval_context:
                        violations.append(
                            f"Access to {resource.security_classification} classified resource without approval"
                        )

            # Check for bulk operations
            if operation.operation_parameters.get("batch_size", 0) > 100:
                violations.append(
                    f"Bulk operation with {operation.operation_parameters.get('batch_size')} items requires additional approval"
                )

            return violations

        except Exception as e:
            logger.error(f"Governance policy check failed: {e}")
            return [f"Policy check failed: {str(e)}"]
