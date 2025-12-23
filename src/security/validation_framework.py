"""
Security Validation Framework - Main Orchestrator.

Comprehensive three-phase security validation system that orchestrates:
- Pre-execution validation (identity, auth, policy, input validation)
- Runtime validation (resource monitoring, behavior analysis)
- Post-execution validation (output sanitization, audit, compliance)

This framework integrates existing security components:
- src.security.scanner (vulnerability & secrets scanning)
- src.services.policy_gate (policy enforcement)
- src.auth.middleware (authentication & authorization)
- src.utils.audit (audit logging)

Usage:
    framework = SecurityValidationFramework()
    result = await framework.validate_full_operation(context, claims)
    if result.allowed_to_proceed:
        # Execute tool with runtime monitoring
        session_id = await framework.start_runtime_validation(context)
        # ... execute tool ...
        return await framework.complete_validation(session_id, tool_result)
"""

from __future__ import annotations

import logging
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.auth.token_auth import TokenClaims
from src.security.scanner import SecurityScanner
from src.services.policy_gate import PolicyGate
from src.models.validation_models import (
    ValidationCategory,
    ValidationFinding,
    ValidationResult,
    ValidationContext,
    SecurityPosture,
    ValidationStatus,
    SecurityValidationSummary,
)
from src.security.validators.pre_execution_validator import PreExecutionValidator
from src.security.validators.runtime_validator import RuntimeValidator
from src.security.validators.post_execution_validator import PostExecutionValidator
from src.utils.errors import ErrorCategory, SystemManagerError
from src.utils.audit import AuditLogger


logger = logging.getLogger(__name__)


class SecurityValidationFramework:
    """Comprehensive security validation framework orchestrator."""

    def __init__(
        self,
        policy_gate: Optional[PolicyGate] = None,
        security_scanner: Optional[SecurityScanner] = None,
        audit_logger: Optional[AuditLogger] = None,
        max_execution_time_seconds: int = 300,
    ):
        """Initialize Security Validation Framework.

        Args:
            policy_gate: Policy gate for policy validation
            security_scanner: Security scanner for vulnerability checks
            audit_logger: Audit logger for validation events
            max_execution_time_seconds: Maximum allowed execution time
        """
        # Initialize dependencies
        self.policy_gate = policy_gate or PolicyGate()
        self.security_scanner = security_scanner or SecurityScanner()
        self.audit_logger = audit_logger or AuditLogger()

        # Initialize validators
        self.pre_execution_validator = PreExecutionValidator(
            policy_gate=self.policy_gate,
            security_scanner=self.security_scanner,
        )
        self.runtime_validator = RuntimeValidator(
            max_execution_time_seconds=max_execution_time_seconds,
        )
        self.post_execution_validator = PostExecutionValidator()

        # Configuration
        self.max_execution_time_seconds = max_execution_time_seconds
        self.enable_runtime_validation = True
        self.enable_post_execution_validation = True

        logger.info("Security Validation Framework initialized")

    async def validate_pre_execution_only(
        self, context: ValidationContext, claims: Optional[TokenClaims] = None
    ) -> SecurityValidationSummary:
        """Perform pre-execution validation only.

        Args:
            context: Validation context with tool operation details
            claims: User authentication claims

        Returns:
            SecurityValidationSummary with pre-execution results
        """
        start_time = datetime.now()
        validation_results = []

        try:
            # Perform pre-execution validation
            pre_result = await self.pre_execution_validator.validate(context, claims)
            validation_results.append(pre_result)

            # Generate summary
            summary = self._generate_summary_from_results(
                validation_results,
                (datetime.now() - start_time).total_seconds() * 1000,
            )

            # Log validation completion
            self._log_validation_event("pre_execution", context, summary)

            return summary

        except Exception as e:
            logger.error(f"Pre-execution validation failed: {e}")
            error_summary = SecurityValidationSummary(
                overall_posture=SecurityPosture.BLOCKED,
                validation_results=[],
                total_findings=0,
                critical_findings=0,
                high_findings=0,
                execution_time_ms=(datetime.now() - start_time).total_seconds() * 1000,
                recommendation="Validation system error - operation blocked",
                allowed_to_proceed=False,
                error_details=str(e),
            )
            return error_summary

    async def validate_full_operation(
        self,
        context: ValidationContext,
        claims: Optional[TokenClaims] = None,
        execute_tool_func: Optional[callable] = None,
    ) -> SecurityValidationSummary:
        """Perform complete three-phase validation with execution.

        Args:
            context: Validation context with tool operation details
            claims: User authentication claims
            execute_tool_func: Optional function to execute the tool

        Returns:
            SecurityValidationSummary with complete validation results
        """
        start_time = datetime.now()
        validation_results = []
        runtime_session_id = None
        tool_result = None

        try:
            # Phase 1: Pre-execution validation
            logger.info(f"Starting pre-execution validation for {context.tool_name}")
            pre_result = await self.pre_execution_validator.validate(context, claims)
            validation_results.append(pre_result)

            # Determine if operation can proceed
            critical_findings = pre_result.get_critical_findings()
            if critical_findings:
                logger.warning(
                    f"Pre-execution validation failed with {len(critical_findings)} critical issues"
                )
                summary = self._generate_summary_from_results(
                    validation_results,
                    (datetime.now() - start_time).total_seconds() * 1000,
                )
                self._log_validation_event("pre_execution_blocked", context, summary)
                return summary

            # Phase 2: Runtime validation (if execution function provided)
            if execute_tool_func:
                logger.info(
                    f"Starting execution with runtime monitoring for {context.tool_name}"
                )
                runtime_session_id = (
                    await self.runtime_validator.start_runtime_validation(context)
                )

                try:
                    # Execute the tool function
                    tool_start = datetime.now()
                    tool_result = await execute_tool_func()
                    execution_time = (datetime.now() - tool_start).total_seconds()

                    # Validate during execution (simulate - in real implementation,
                    # this would be called periodically during execution)
                    runtime_result = (
                        await self.runtime_validator.validate_during_execution(
                            runtime_session_id,
                            {"execution_state": "running", "progress": 1.0},
                        )
                    )
                    validation_results.append(runtime_result)

                except Exception as e:
                    # Log execution error
                    runtime_result = (
                        await self.runtime_validator.validate_during_execution(
                            runtime_session_id, {"error": str(e)}
                        )
                    )
                    validation_results.append(runtime_result)

                    # End runtime validation
                    await self.runtime_validator.end_validation(runtime_session_id)

                    # Generate error summary
                    summary = self._generate_summary_from_results(
                        validation_results,
                        (datetime.now() - start_time).total_seconds() * 1000,
                    )
                    summary.error_details = f"Tool execution failed: {e}"
                    self._log_validation_event("execution_failed", context, summary)
                    return summary

            # Phase 3: Post-execution validation
            if self.enable_post_execution_validation and tool_result:
                logger.info(
                    f"Starting post-execution validation for {context.tool_name}"
                )

                # End runtime validation session
                if runtime_session_id:
                    runtime_end_result = await self.runtime_validator.end_validation(
                        runtime_session_id
                    )
                    # Use runtime results instead of duplicated runtime validation
                    validation_results = [
                        r
                        for r in validation_results
                        if r.validator_name != "RuntimeValidator"
                        or r.status == ValidationStatus.ERROR
                    ]
                    validation_results.append(runtime_end_result)

                # Perform post-execution validation
                post_result = await self.post_execution_validator.validate(
                    context, tool_result, execution_time, runtime_session_id
                )
                validation_results.append(post_result)

            # Generate final summary
            summary = self._generate_summary_from_results(
                validation_results,
                (datetime.now() - start_time).total_seconds() * 1000,
            )

            # Log successful validation
            self._log_validation_event("full_validation_complete", context, summary)

            return summary

        except Exception as e:
            logger.error(f"Full validation process failed: {e}")

            # Clean up runtime session if it exists
            if runtime_session_id:
                try:
                    await self.runtime_validator.end_validation(runtime_session_id)
                except Exception as cleanup_error:
                    logger.error(f"Failed to cleanup runtime session: {cleanup_error}")

            error_summary = SecurityValidationSummary(
                overall_posture=SecurityPosture.UNKNOWN,
                validation_results=validation_results,
                total_findings=len([f for r in validation_results for f in r.findings]),
                critical_findings=0,
                high_findings=0,
                execution_time_ms=(datetime.now() - start_time).total_seconds() * 1000,
                recommendation="Validation system error - operation blocked",
                allowed_to_proceed=False,
                error_details=str(e),
            )
            return error_summary

    async def start_runtime_validation(self, context: ValidationContext) -> str:
        """Start runtime validation session.

        Args:
            context: Validation context

        Returns:
            Runtime validation session ID
        """
        return await self.runtime_validator.start_runtime_validation(context)

    async def validate_during_execution(
        self, session_id: str, execution_state: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """Validate during execution.

        Args:
            session_id: Runtime validation session ID
            execution_state: Current execution state

        Returns:
            ValidationResult with runtime findings
        """
        return await self.runtime_validator.validate_during_execution(
            session_id, execution_state
        )

    async def complete_validation(
        self,
        runtime_session_id: str,
        context: ValidationContext,
        tool_result: Dict[str, Any],
        execution_time_seconds: float,
    ) -> SecurityValidationSummary:
        """Complete validation process after tool execution.

        Args:
            runtime_session_id: Runtime validation session ID
            context: Validation context
            tool_result: Tool execution result
            execution_time_seconds: Execution time in seconds

        Returns:
            Complete SecurityValidationSummary
        """
        start_time = datetime.now()
        validation_results = []

        try:
            # End runtime validation
            runtime_result = await self.runtime_validator.end_validation(
                runtime_session_id
            )
            validation_results.append(runtime_result)

            # Perform post-execution validation
            if self.enable_post_execution_validation:
                post_result = await self.post_execution_validator.validate(
                    context, tool_result, execution_time_seconds, runtime_session_id
                )
                validation_results.append(post_result)

            # Generate summary
            summary = self._generate_summary_from_results(
                validation_results,
                (datetime.now() - start_time).total_seconds() * 1000,
            )

            self._log_validation_event("validation_complete", context, summary)

            return summary

        except Exception as e:
            logger.error(f"Complete validation process failed: {e}")
            error_summary = SecurityValidationSummary(
                overall_posture=SecurityPosture.UNKNOWN,
                validation_results=validation_results,
                total_findings=len([f for r in validation_results for f in r.findings]),
                critical_findings=0,
                high_findings=0,
                execution_time_ms=(datetime.now() - start_time).total_seconds() * 1000,
                recommendation="Validation completion error",
                allowed_to_proceed=False,
                error_details=str(e),
            )
            return error_summary

    def _generate_summary_from_results(
        self, validation_results: List[ValidationResult], execution_time_ms: float
    ) -> SecurityValidationSummary:
        """Generate security validation summary from results."""
        # Collect all findings
        all_findings = [
            finding for result in validation_results for finding in result.findings
        ]

        # Count findings by severity
        critical_findings = len([f for f in all_findings if f.severity == "critical"])
        high_findings = len([f for f in all_findings if f.severity == "high"])

        # Determine overall security posture
        has_critical = critical_findings > 0
        has_failures = any(
            r.status == ValidationStatus.FAILED for r in validation_results
        )
        has_errors = any(r.status == ValidationStatus.ERROR for r in validation_results)

        if has_critical or has_failures:
            overall_posture = SecurityPosture.BLOCKED
            allowed_to_proceed = False
            recommendation = "Operation blocked due to critical security issues"
        elif has_errors:
            overall_posture = SecurityPosture.UNKNOWN
            allowed_to_proceed = False
            recommendation = "Operation blocked due to validation system errors"
        elif high_findings > 0:
            overall_posture = SecurityPosture.RISKY
            allowed_to_proceed = True
            recommendation = "Operation allowed but high security risks detected"
        else:
            overall_posture = SecurityPosture.SECURE
            allowed_to_proceed = True
            recommendation = "Operation secure to proceed"

        return SecurityValidationSummary(
            overall_posture=overall_posture,
            validation_results=validation_results,
            total_findings=len(all_findings),
            critical_findings=critical_findings,
            high_findings=high_findings,
            execution_time_ms=execution_time_ms,
            recommendation=recommendation,
            allowed_to_proceed=allowed_to_proceed,
        )

    def _log_validation_event(
        self,
        event_type: str,
        context: ValidationContext,
        summary: SecurityValidationSummary,
    ) -> None:
        """Log validation event for audit trail."""
        try:
            audit_data = {
                "event_type": f"security_validation_{event_type}",
                "tool_name": context.tool_name,
                "operation": context.operation,
                "target_id": context.target_id,
                "user_agent": context.user_agent,
                "user_scopes": context.user_scopes,
                "session_id": context.session_id,
                "overall_posture": summary.overall_posture.value,
                "total_findings": summary.total_findings,
                "critical_findings": summary.critical_findings,
                "high_findings": summary.high_findings,
                "execution_time_ms": summary.execution_time_ms,
                "allowed_to_proceed": summary.allowed_to_proceed,
                "recommendation": summary.recommendation,
            }

            if summary.error_details:
                audit_data["error_details"] = summary.error_details

            self.audit_logger.log(
                tool="security_validation_framework",
                args=audit_data,
                result={
                    "success": summary.allowed_to_proceed,
                    "posture": summary.overall_posture.value,
                    "findings_count": summary.total_findings,
                },
            )

        except Exception as e:
            logger.error(f"Failed to log validation event: {e}")


# Export framework class
__all__ = ["SecurityValidationFramework"]
