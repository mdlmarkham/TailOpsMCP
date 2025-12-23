"""
Pre-Execution Security Validator.

Validates security posture before tool execution including:
- Identity and authentication verification
- Authorization and scope validation
- Input sanitization and parameter validation
- Target capability and existence verification
- Policy compliance checking

This validator runs first in the three-phase pipeline and can block execution.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.auth.token_auth import TokenClaims
from src.auth.scopes import Scope, check_authorization
from src.models.target_registry import TargetMetadata
from src.models.validation_models import (
    ValidationCategory,
    ValidationFinding,
    ValidationResult,
    ValidationContext,
    SecurityPosture,
    ValidationStatus,
)
from src.security.scanner import SecurityScanner, ScanType
from src.services.policy_gate import PolicyGate
from src.utils.errors import ErrorCategory, SystemManagerError


logger = logging.getLogger(__name__)


class PreExecutionValidator:
    """Validates security posture before tool execution."""

    def __init__(self, policy_gate: PolicyGate, security_scanner: SecurityScanner):
        """Initialize pre-execution validator.

        Args:
            policy_gate: Policy gate for policy validation
            security_scanner: Security scanner for vulnerability checks
        """
        self.policy_gate = policy_gate
        self.security_scanner = security_scanner

    async def validate(
        self, context: ValidationContext, claims: Optional[TokenClaims] = None
    ) -> ValidationResult:
        """Perform comprehensive pre-execution validation.

        Args:
            context: Validation context with tool operation details
            claims: User authentication claims

        Returns:
            ValidationResult with findings and security posture
        """
        start_time = datetime.now()

        result = ValidationResult(
            validator_name="PreExecutionValidator",
            category=ValidationCategory.AUTHENTICATION,
            status=ValidationStatus.PASSED,
            security_posture=SecurityPosture.SECURE,
        )

        try:
            # Step 1: Identity and Authentication Validation
            if not claims:
                finding = ValidationFinding(
                    category=ValidationCategory.AUTHENTICATION,
                    status=ValidationStatus.FAILED,
                    severity="critical",
                    title="Authentication Required",
                    description="No authentication token provided",
                    recommendation="Provide valid authentication token",
                )
                result.add_finding(finding)
                result.status = ValidationStatus.FAILED
                result.security_posture = SecurityPosture.BLOCKED
                return result

            # Validate token claims
            await self._validate_authentication(claims, result)

            # Step 2: Authorization and Scope Validation
            await self._validate_authorization(context, claims, result)

            # Step 3: Input and Parameter Validation
            await self._validate_inputs(context, result)

            # Step 4: Target Validation (if target_id specified)
            if context.target_id and context.target_id != "local":
                await self._validate_target(context, claims, result)

            # Step 5: Policy Compliance Validation
            await self._validate_policy_compliance(context, claims, result)

            # Step 6: Security Scan for Context
            await self._perform_contextual_security_scan(context, result)

            # Determine final status
            critical_findings = result.get_critical_findings()
            failed_findings = result.get_failed_findings()

            if critical_findings:
                result.status = ValidationStatus.FAILED
                result.security_posture = SecurityPosture.BLOCKED
            elif failed_findings:
                result.status = ValidationStatus.WARNING
                result.security_posture = SecurityPosture.RISKY

        except Exception as e:
            logger.error(f"Pre-execution validation error: {e}")
            result.status = ValidationStatus.ERROR
            result.security_posture = SecurityPosture.UNKNOWN
            result.error_message = str(e)

            finding = ValidationFinding(
                category=ValidationCategory.AUTHENTICATION,
                status=ValidationStatus.ERROR,
                severity="critical",
                title="Validation System Error",
                description=f"Pre-execution validation failed: {e}",
                recommendation="Check system configuration and try again",
            )
            result.add_finding(finding)

        finally:
            result.execution_time_ms = (
                datetime.now() - start_time
            ).total_seconds() * 1000

        return result

    async def _validate_authentication(
        self, claims: TokenClaims, result: ValidationResult
    ) -> None:
        """Validate authentication token and claims."""
        try:
            # Check token expiration
            if claims.exp and claims.exp < datetime.now().timestamp():
                finding = ValidationFinding(
                    category=ValidationCategory.AUTHENTICATION,
                    status=ValidationStatus.FAILED,
                    severity="critical",
                    title="Token Expired",
                    description="Authentication token has expired",
                    recommendation="Obtain new authentication token",
                )
                result.add_finding(finding)
                return

            # Check required claim fields
            if not claims.agent:
                finding = ValidationFinding(
                    category=ValidationCategory.AUTHENTICATION,
                    status=ValidationStatus.FAILED,
                    severity="high",
                    title="Missing Agent Identifier",
                    description="Token missing required agent identifier",
                    recommendation="Token must include agent claim",
                )
                result.add_finding(finding)

            # Check token issuer if present
            if claims.iss:
                expected_issuer = (
                    claims.iss
                )  # In production, validate against trusted issuers
                # Placeholder for issuer validation

            finding = ValidationFinding(
                category=ValidationCategory.AUTHENTICATION,
                status=ValidationStatus.PASSED,
                severity="info",
                title="Authentication Valid",
                description=f"Authentication successful for agent: {claims.agent}",
            )
            result.add_finding(finding)

        except Exception as e:
            finding = ValidationFinding(
                category=ValidationCategory.AUTHENTICATION,
                status=ValidationStatus.ERROR,
                severity="high",
                title="Authentication Validation Error",
                description=f"Failed to validate authentication: {e}",
                recommendation="Check token format and contents",
            )
            result.add_finding(finding)

    async def _validate_authorization(
        self, context: ValidationContext, claims: TokenClaims, result: ValidationResult
    ) -> None:
        """Validate authorization and permissions."""
        try:
            authorized, reason = check_authorization(
                context.tool_name, claims.scopes or []
            )

            if not authorized:
                finding = ValidationFinding(
                    category=ValidationCategory.AUTHORIZATION,
                    status=ValidationStatus.FAILED,
                    severity="critical",
                    title="Authorization Failed",
                    description=f"Insufficient privileges for {context.tool_name}: {reason}",
                    recommendation=f"Required scopes: {self._get_required_scopes(context.tool_name)}",
                    evidence={
                        "user_scopes": claims.scopes or [],
                        "required_scopes": self._get_required_scopes(context.tool_name),
                    },
                )
                result.add_finding(finding)
            else:
                finding = ValidationFinding(
                    category=ValidationCategory.AUTHORIZATION,
                    status=ValidationStatus.PASSED,
                    severity="info",
                    title="Authorization Successful",
                    description=f"Agent authorized to execute {context.tool_name}",
                    evidence={"granted_scopes": claims.scopes or []},
                )
                result.add_finding(finding)

        except Exception as e:
            finding = ValidationFinding(
                category=ValidationCategory.AUTHORIZATION,
                status=ValidationStatus.ERROR,
                severity="high",
                title="Authorization Validation Error",
                description=f"Failed to validate authorization: {e}",
                recommendation="Check permission configuration",
            )
            result.add_finding(finding)

    async def _validate_inputs(
        self, context: ValidationContext, result: ValidationResult
    ) -> None:
        """Validate input parameters and data."""
        try:
            # Validate parameter structure
            if not isinstance(context.parameters, dict):
                finding = ValidationFinding(
                    category=ValidationCategory.INPUT_VALIDATION,
                    status=ValidationStatus.FAILED,
                    severity="high",
                    title="Invalid Parameter Format",
                    description="Parameters must be a dictionary",
                    recommendation="Provide parameters as key-value pairs",
                )
                result.add_finding(finding)
                return

            # Check for suspicious parameter patterns
            suspicious_patterns = [
                ("command_injection", [";", "&", "|", "`", "$(", "${"]),
                ("path_traversal", ["../", "..\\", "/etc/", "/var/"]),
                ("code_injection", ["eval(", "exec(", "subprocess.", "os.system"]),
            ]

            for param_name, param_value in context.parameters.items():
                if isinstance(param_value, str):
                    for pattern_name, patterns in suspicious_patterns:
                        for pattern in patterns:
                            if pattern in param_value.lower():
                                finding = ValidationFinding(
                                    category=ValidationCategory.INPUT_VALIDATION,
                                    status=ValidationStatus.WARNING,
                                    severity="high",
                                    title=f"Potential {pattern_name.replace('_', ' ').title()}",
                                    description=f"Suspicious pattern detected in parameter '{param_name}'",
                                    recommendation="Review parameter value for malicious content",
                                    evidence={
                                        "parameter": param_name,
                                        "pattern": pattern,
                                    },
                                )
                                result.add_finding(finding)

            finding = ValidationFinding(
                category=ValidationCategory.INPUT_VALIDATION,
                status=ValidationStatus.PASSED,
                severity="info",
                title="Input Validation Passed",
                description=f"Validated {len(context.parameters)} parameters",
            )
            result.add_finding(finding)

        except Exception as e:
            finding = ValidationFinding(
                category=ValidationCategory.INPUT_VALIDATION,
                status=ValidationStatus.ERROR,
                severity="medium",
                title="Input Validation Error",
                description=f"Failed to validate inputs: {e}",
                recommendation="Check parameter format and content",
            )
            result.add_finding(finding)

    async def _validate_target(
        self, context: ValidationContext, claims: TokenClaims, result: ValidationResult
    ) -> None:
        """Validate target existence and capabilities."""
        try:
            target = self.policy_gate.validate_target_existence(context.target_id)

            finding = ValidationFinding(
                category=ValidationCategory.AUTHORIZATION,
                status=ValidationStatus.PASSED,
                severity="info",
                title="Target Validated",
                description=f"Target {context.target_id} exists and accessible",
                evidence={"target_id": context.target_id, "target_type": target.type},
            )
            result.add_finding(finding)

        except SystemManagerError as e:
            finding = ValidationFinding(
                category=ValidationCategory.AUTHORIZATION,
                status=ValidationStatus.FAILED,
                severity="critical",
                title="Target Not Found",
                description=f"Target {context.target_id} not found or inaccessible: {e}",
                recommendation="Verify target exists and check connectivity",
                evidence={"target_id": context.target_id},
            )
            result.add_finding(finding)

        except Exception as e:
            finding = ValidationFinding(
                category=ValidationCategory.AUTHORIZATION,
                status=ValidationStatus.ERROR,
                severity="high",
                title="Target Validation Error",
                description=f"Failed to validate target: {e}",
                recommendation="Check target configuration and network connectivity",
            )
            result.add_finding(finding)

    async def _validate_policy_compliance(
        self, context: ValidationContext, claims: TokenClaims, result: ValidationResult
    ) -> None:
        """Validate operation against security policies."""
        try:
            authorized, validation_errors = self.policy_gate.enforce_policy(
                tool_name=context.tool_name,
                target_id=context.target_id,
                operation=context.operation,
                parameters=context.parameters,
                claims=claims,
                dry_run=True,  # Pre-execution is always a dry run initially
            )

            if authorized and not validation_errors:
                finding = ValidationFinding(
                    category=ValidationCategory.POLICY,
                    status=ValidationStatus.PASSED,
                    severity="info",
                    title="Policy Compliance Passed",
                    description="Operation complies with all security policies",
                )
                result.add_finding(finding)
            else:
                for error in validation_errors:
                    finding = ValidationFinding(
                        category=ValidationCategory.POLICY,
                        status=ValidationStatus.WARNING
                        if authorized
                        else ValidationStatus.FAILED,
                        severity="medium" if authorized else "high",
                        title="Policy Validation Issue",
                        description=f"Policy validation: {error}",
                        recommendation="Review operation parameters and user permissions",
                    )
                    result.add_finding(finding)

        except Exception as e:
            finding = ValidationFinding(
                category=ValidationCategory.POLICY,
                status=ValidationStatus.ERROR,
                severity="medium",
                title="Policy Validation Error",
                description=f"Failed to validate policy compliance: {e}",
                recommendation="Check policy configuration",
            )
            result.add_finding(finding)

    async def _perform_contextual_security_scan(
        self, context: ValidationContext, result: ValidationResult
    ) -> None:
        """Perform lightweight security scans relevant to the operation context."""
        try:
            # For now, perform a quick secrets scan on parameters
            scanner_config = self.security_scanner.config
            scanner_config.scan_types = {ScanType.SECRETS}

            # Quick parameter validation (would scan files in production)
            secrets_found = 0
            for param_name, param_value in context.parameters.items():
                if isinstance(param_value, str):
                    # Check for secret patterns in parameters
                    if any(
                        pattern in param_value.lower()
                        for pattern in [
                            "password",
                            "secret",
                            "token",
                            "key",
                            "credential",
                        ]
                    ):
                        # Don't flag obvious placeholders or test values
                        if not any(
                            placeholder in param_value.lower()
                            for placeholder in [
                                "test",
                                "example",
                                "sample",
                                "placeholder",
                                "xxx",
                            ]
                        ):
                            secrets_found += 1

            if secrets_found > 0:
                finding = ValidationFinding(
                    category=ValidationCategory.SECRETS,
                    status=ValidationStatus.WARNING,
                    severity="high",
                    title="Potential Secrets in Parameters",
                    description=f"Detected {secrets_found} parameters that may contain sensitive information",
                    recommendation="Remove sensitive data from parameters and use secure channels",
                )
                result.add_finding(finding)
            else:
                finding = ValidationFinding(
                    category=ValidationCategory.SECRETS,
                    status=ValidationStatus.PASSED,
                    severity="info",
                    title="Parameter Scan Passed",
                    description="No obvious secrets detected in parameters",
                )
                result.add_finding(finding)

        except Exception as e:
            finding = ValidationFinding(
                category=ValidationCategory.SECRETS,
                status=ValidationStatus.ERROR,
                severity="low",
                title="Parameter Scan Error",
                description=f"Failed to scan parameters for secrets: {e}",
                recommendation="Parameter scanning unavailable",
            )
            result.add_finding(finding)

    def _get_required_scopes(self, tool_name: str) -> List[str]:
        """Get required scopes for a tool."""
        # This would be enhanced with proper scope mapping
        scope_mappings = {
            "docker_manager": [Scope.CONTAINER_WRITE.value],
            "system_tools": [Scope.SYSTEM_READ.value],
            "network_tools": [Scope.NETWORK_READ.value],
        }

        for tool_pattern, scopes in scope_mappings.items():
            if tool_pattern in tool_name:
                return scopes

        return []  # Default to no specific scopes


# Export validator class
__all__ = ["PreExecutionValidator"]
