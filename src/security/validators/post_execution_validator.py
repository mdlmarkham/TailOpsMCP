"""
Post-Execution Security Validator.

Validates security posture after tool execution including:
- Output validation and sanitization
- Audit log integrity verification
- Post-operation security scanning
- Compliance verification
- Incident detection and response

This validator runs after tool execution and can trigger security alerts.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.models.validation_models import (
    ValidationCategory,
    ValidationFinding,
    ValidationResult,
    ValidationContext,
    SecurityPosture,
    ValidationStatus,
)


logger = logging.getLogger(__name__)


class PostExecutionValidator:
    """Validates security posture after tool execution."""

    def __init__(self):
        """Initialize post-execution validator."""
        self.suspicious_patterns = [
            "password",
            "secret",
            "token",
            "key",
            "credential",
            "/etc/passwd",
            "/etc/shadow",
            "private_key",
            "BEGIN RSA PRIVATE KEY",
            "BEGIN DSA PRIVATE KEY",
        ]

    async def validate(
        self,
        context: ValidationContext,
        execution_result: Dict[str, Any],
        execution_time_seconds: float,
        runtime_session_id: Optional[str] = None,
    ) -> ValidationResult:
        """Perform comprehensive post-execution validation.

        Args:
            context: Validation context with tool operation details
            execution_result: Result data from tool execution
            execution_time_seconds: Total execution time in seconds
            runtime_session_id: Runtime validation session ID

        Returns:
            ValidationResult with post-execution findings
        """
        start_time = datetime.now()

        result = ValidationResult(
            validator_name="PostExecutionValidator",
            category=ValidationCategory.COMPLIANCE,
            status=ValidationStatus.PASSED,
            security_posture=SecurityPosture.SECURE,
        )

        try:
            # Step 1: Validate output data for sensitive information
            await self._validate_output_data(context, execution_result, result)

            # Step 2: Verify audit trail integrity
            await self._verify_audit_integrity(context, execution_result, result)

            # Step 3: Check execution duration anomalies
            await self._validate_execution_duration(
                context, execution_time_seconds, result
            )

            # Step 4: Scan for security incidents
            await self._detect_security_incidents(context, execution_result, result)

            # Step 5: Verify compliance and policy adherence
            await self._verify_compliance(context, execution_result, result)

            # Step 6: Generate operation summary and recommendations
            await self._generate_operation_summary(context, execution_result, result)

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
            logger.error(f"Post-execution validation error: {e}")
            result.status = ValidationStatus.ERROR
            result.security_posture = SecurityPosture.UNKNOWN
            result.error_message = str(e)

            finding = ValidationFinding(
                category=ValidationCategory.COMPLIANCE,
                status=ValidationStatus.ERROR,
                severity="critical",
                title="Post-Execution Validation Error",
                description=f"Post-execution validation failed: {e}",
                recommendation="Check validation system configuration",
            )
            result.add_finding(finding)

        finally:
            result.execution_time_ms = (
                datetime.now() - start_time
            ).total_seconds() * 1000

        return result

    async def _validate_output_data(
        self,
        context: ValidationContext,
        execution_result: Dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Validate output data for sensitive information leaks."""
        try:
            # Recursively scan result data for sensitive patterns
            sensitive_content = self._scan_for_sensitive_content(execution_result)

            if sensitive_content:
                for content in sensitive_content:
                    finding = ValidationFinding(
                        category=ValidationCategory.SECRETS,
                        status=ValidationStatus.WARNING,
                        severity="high",
                        title="Potential Sensitive Content in Output",
                        description=f"Potential sensitive information detected in operation output",
                        recommendation="Review output for data leaks and implement output sanitization",
                        evidence={
                            "content_type": content["type"],
                            "pattern": content["pattern"],
                            "location": content.get("location", "output_data"),
                        },
                    )
                    result.add_finding(finding)
            else:
                finding = ValidationFinding(
                    category=ValidationCategory.SECRETS,
                    status=ValidationStatus.PASSED,
                    severity="info",
                    title="Output Sanitization Passed",
                    description="No sensitive content detected in operation output",
                )
                result.add_finding(finding)

        except Exception as e:
            finding = ValidationFinding(
                category=ValidationCategory.SECRETS,
                status=ValidationStatus.ERROR,
                severity="medium",
                title="Output Validation Error",
                description=f"Failed to validate output data: {e}",
                recommendation="Check output validation implementation",
            )
            result.add_finding(finding)

    async def _verify_audit_integrity(
        self,
        context: ValidationContext,
        execution_result: Dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Verify audit trail integrity and completeness."""
        try:
            # Check if execution result includes proper audit metadata
            execution_status = execution_result.get("success", False)
            error_message = execution_result.get("error")

            # Validate audit trail structure
            audit_findings = []

            if not execution_result.get("audit_trail_created", True):
                audit_findings.append("Audit trail not properly created")

            if error_message and len(error_message) > 1000:
                audit_findings.append(
                    "Excessively long error message may indicate information disclosure"
                )

            # Check for proper error handling
            if not execution_status and not error_message:
                audit_findings.append("Failed operation without error description")

            if audit_findings:
                for finding in audit_findings:
                    validation_finding = ValidationFinding(
                        category=ValidationCategory.COMPLIANCE,
                        status=ValidationStatus.WARNING,
                        severity="medium",
                        title="Audit Trail Issue",
                        description=finding,
                        recommendation="Review audit logging implementation",
                    )
                    result.add_finding(validation_finding)
            else:
                finding = ValidationFinding(
                    category=ValidationCategory.COMPLIANCE,
                    status=ValidationStatus.PASSED,
                    severity="info",
                    title="Audit Trail Valid",
                    description="Operation audit trail is properly formed",
                )
                result.add_finding(finding)

        except Exception as e:
            finding = ValidationFinding(
                category=ValidationCategory.COMPLIANCE,
                status=ValidationStatus.ERROR,
                severity="medium",
                title="Audit Verification Error",
                description=f"Failed to verify audit integrity: {e}",
                recommendation="Check audit system configuration",
            )
            result.add_finding(finding)

    async def _validate_execution_duration(
        self,
        context: ValidationContext,
        execution_time_seconds: float,
        result: ValidationResult,
    ) -> None:
        """Validate execution duration for anomalies."""
        try:
            # Expected execution time ranges by tool type
            expected_durations = {
                "docker": (5, 120),  # Docker operations: 5-120 seconds
                "system": (1, 30),  # System queries: 1-30 seconds
                "network": (5, 60),  # Network operations: 5-60 seconds
                "file": (1, 10),  # File operations: 1-10 seconds
            }

            # Get expected range based on tool name
            expected_min, expected_max = 1.0, 300.0  # Default range
            for tool_type, (min_time, max_time) in expected_durations.items():
                if tool_type in context.tool_name.lower():
                    expected_min, expected_max = min_time, max_time
                    break

            # Flag unusual execution times
            if execution_time_seconds > expected_max * 2:
                finding = ValidationFinding(
                    category=ValidationCategory.INFRASTRUCTURE,
                    status=ValidationStatus.WARNING,
                    severity="medium",
                    title="Unusual Execution Duration",
                    description=f"Operation took {execution_time_seconds:.1f}s (expected < {expected_max:.1f}s)",
                    recommendation="Investigate potential performance issues or unusual behavior",
                    evidence={
                        "execution_time_seconds": execution_time_seconds,
                        "expected_max_seconds": expected_max,
                        "tool_name": context.tool_name,
                    },
                )
                result.add_finding(finding)
            elif execution_time_seconds < expected_min / 2:
                finding = ValidationFinding(
                    category=ValidationCategory.INFRASTRUCTURE,
                    status=ValidationStatus.WARNING,
                    severity="low",
                    title="Very Fast Execution",
                    description=f"Operation completed unusually quickly: {execution_time_seconds:.1f}s",
                    recommendation="Verify operation completed successfully",
                    evidence={
                        "execution_time_seconds": execution_time_seconds,
                        "expected_min_seconds": expected_min,
                    },
                )
                result.add_finding(finding)
            else:
                finding = ValidationFinding(
                    category=ValidationCategory.INFRASTRUCTURE,
                    status=ValidationStatus.PASSED,
                    severity="info",
                    title="Execution Duration Normal",
                    description=f"Operation completed in expected time: {execution_time_seconds:.1f}s",
                )
                result.add_finding(finding)

        except Exception as e:
            finding = ValidationFinding(
                category=ValidationCategory.INFRASTRUCTURE,
                status=ValidationStatus.ERROR,
                severity="medium",
                title="Execution Duration Validation Error",
                description=f"Failed to validate execution duration: {e}",
                recommendation="Check execution time tracking",
            )
            result.add_finding(finding)

    async def _detect_security_incidents(
        self,
        context: ValidationContext,
        execution_result: Dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Detect potential security incidents from execution results."""
        try:
            incidents = []

            # Check for failed operations that might indicate security issues
            if not execution_result.get("success", False):
                error_message = execution_result.get("error", "").lower()

                # Check for security-related errors
                security_error_patterns = [
                    "permission denied",
                    "access denied",
                    "unauthorized",
                    "forbidden",
                    "authentication failed",
                    "security violation",
                ]

                for pattern in security_error_patterns:
                    if pattern in error_message:
                        incidents.append(
                            {
                                "type": "security_error",
                                "pattern": pattern,
                                "message": execution_result.get("error"),
                            }
                        )
                        break

            # Check for potential data exposure
            result_data_str = str(execution_result.get("data", {}))
            for pattern in self.suspicious_patterns:
                if pattern.lower() in result_data_str.lower():
                    incidents.append(
                        {
                            "type": "data_exposure",
                            "pattern": pattern,
                            "context": "operation_result",
                        }
                    )

            # Check for unusual response sizes
            if "data" in execution_result:
                data_str = str(execution_result["data"])
                if len(data_str) > 1048576:  # 1MB threshold
                    incidents.append(
                        {
                            "type": "large_response",
                            "size": len(data_str),
                            "threshold": 1048576,
                        }
                    )

            if incidents:
                for incident in incidents:
                    severity = (
                        "high"
                        if incident["type"] in ["data_exposure", "security_error"]
                        else "medium"
                    )
                    finding = ValidationFinding(
                        category=ValidationCategory.NETWORK,
                        status=ValidationStatus.WARNING,
                        severity=severity,
                        title=f"Security Incident: {incident['type'].replace('_', ' ').title()}",
                        description=f"Potential security incident detected: {incident.get('type')}",
                        recommendation="Review operation for security implications",
                        evidence=incident,
                    )
                    result.add_finding(finding)
            else:
                finding = ValidationFinding(
                    category=ValidationCategory.NETWORK,
                    status=ValidationStatus.PASSED,
                    severity="info",
                    title="No Security Incidents Detected",
                    description="Operation completed without obvious security incidents",
                )
                result.add_finding(finding)

        except Exception as e:
            finding = ValidationFinding(
                category=ValidationCategory.NETWORK,
                status=ValidationStatus.ERROR,
                severity="medium",
                title="Security Incident Detection Error",
                description=f"Failed to detect security incidents: {e}",
                recommendation="Check incident detection implementation",
            )
            result.add_finding(finding)

    async def _verify_compliance(
        self,
        context: ValidationContext,
        execution_result: Dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Verify operation compliance with security policies."""
        try:
            compliance_issues = []

            # Check for proper error handling and logging
            if execution_result.get("success", False):
                if not execution_result.get("audit_logged", True):
                    compliance_issues.append(
                        "Successful operation not properly audited"
                    )
            else:
                if not execution_result.get("error_logged", True):
                    compliance_issues.append(
                        "Failed operation not properly audit logged"
                    )

            # Check for sensitive data in operation parameters
            for param_name, param_value in context.parameters.items():
                if isinstance(param_value, str) and len(param_value) > 10000:
                    compliance_issues.append(f"Large parameter detected: {param_name}")

            if compliance_issues:
                for issue in compliance_issues:
                    finding = ValidationFinding(
                        category=ValidationCategory.COMPLIANCE,
                        status=ValidationStatus.WARNING,
                        severity="low",
                        title="Compliance Issue",
                        description=issue,
                        recommendation="Review operation for compliance with security policies",
                    )
                    result.add_finding(finding)
            else:
                finding = ValidationFinding(
                    category=ValidationCategory.COMPLIANCE,
                    status=ValidationStatus.PASSED,
                    severity="info",
                    title="Compliance Check Passed",
                    description="Operation appears compliant with security policies",
                )
                result.add_finding(finding)

        except Exception as e:
            finding = ValidationFinding(
                category=ValidationCategory.COMPLIANCE,
                status=ValidationStatus.ERROR,
                severity="medium",
                title="Compliance Verification Error",
                description=f"Failed to verify compliance: {e}",
                recommendation="Check compliance checking implementation",
            )
            result.add_finding(finding)

    async def _generate_operation_summary(
        self,
        context: ValidationContext,
        execution_result: Dict[str, Any],
        result: ValidationResult,
    ) -> None:
        """Generate operation summary and security recommendations."""
        try:
            success = execution_result.get("success", False)
            has_warnings = any(
                f.status == ValidationStatus.WARNING for f in result.findings
            )
            has_failures = any(
                f.status == ValidationStatus.FAILED for f in result.findings
            )

            if success and not has_warnings and not has_failures:
                message = "Operation completed successfully with no security concerns"
                severity = "info"
            elif success and has_warnings:
                message = "Operation completed successfully with security warnings"
                severity = "medium"
            elif not success and not has_failures:
                message = "Operation failed for non-security reasons"
                severity = "low"
            else:
                message = "Operation failed with security issues detected"
                severity = "high"

            finding = ValidationFinding(
                category=ValidationCategory.COMPLIANCE,
                status=ValidationStatus.PASSED if success else ValidationStatus.FAILED,
                severity=severity,
                title="Operation Security Summary",
                description=message,
                recommendation="Review detailed findings for specific security recommendations",
                evidence={
                    "tool_name": context.tool_name,
                    "operation": context.operation,
                    "success": success,
                    "total_findings": len(result.findings),
                    "warning_count": len(
                        [
                            f
                            for f in result.findings
                            if f.status == ValidationStatus.WARNING
                        ]
                    ),
                    "failure_count": len(
                        [
                            f
                            for f in result.findings
                            if f.status == ValidationStatus.FAILED
                        ]
                    ),
                },
            )
            result.add_finding(finding)

        except Exception as e:
            finding = ValidationFinding(
                category=ValidationCategory.COMPLIANCE,
                status=ValidationStatus.ERROR,
                severity="medium",
                title="Summary Generation Error",
                description=f"Failed to generate operation summary: {e}",
                recommendation="Check summary generation implementation",
            )
            result.add_finding(finding)

    def _scan_for_sensitive_content(
        self, data: Any, path: str = "result"
    ) -> List[Dict[str, Any]]:
        """Recursively scan data structure for sensitive content."""
        sensitive_content = []

        if isinstance(data, str):
            data_lower = data.lower()
            for pattern in self.suspicious_patterns:
                if pattern.lower() in data_lower:
                    # Avoid false positives on common technical terms
                    context_words = ["test", "example", "sample", "placeholder", "demo"]
                    is_false_positive = any(
                        word in data_lower for word in context_words
                    )

                    if not is_false_positive:
                        sensitive_content.append(
                            {
                                "type": "text_content",
                                "pattern": pattern,
                                "location": path,
                                "preview": data[:100] + "..."
                                if len(data) > 100
                                else data,
                            }
                        )

        elif isinstance(data, dict):
            for key, value in data.items():
                if any(pattern in key.lower() for pattern in self.suspicious_patterns):
                    sensitive_content.append(
                        {
                            "type": "sensitive_key",
                            "pattern": key,
                            "location": f"{path}.{key}",
                        }
                    )
                sensitive_content.extend(
                    self._scan_for_sensitive_content(value, f"{path}.{key}")
                )

        elif isinstance(data, (list, tuple)):
            for i, item in enumerate(data):
                sensitive_content.extend(
                    self._scan_for_sensitive_content(item, f"{path}[{i}]")
                )

        return sensitive_content


# Export validator class
__all__ = ["PostExecutionValidator"]
