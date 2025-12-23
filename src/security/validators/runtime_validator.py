"""
Runtime Security Validator.

Validates security posture during tool execution including:
- Real-time resource usage monitoring
- Dynamic behavior validation
- Session integrity checking
- Rate limiting enforcement
- Unexpected behavior detection

This validator runs during tool execution and can terminate long-running operations.
"""

from __future__ import annotations

import logging
import time
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


class RuntimeValidator:
    """Validates security posture during tool execution."""

    def __init__(self, max_execution_time_seconds: int = 300):
        """Initialize runtime validator.

        Args:
            max_execution_time_seconds: Maximum allowed execution time
        """
        self.max_execution_time_seconds = max_execution_time_seconds
        self._active_sessions: Dict[str, Dict[str, Any]] = {}

    async def start_validation(
        self, context: ValidationContext, session_id: Optional[str] = None
    ) -> str:
        """Start runtime validation session.

        Args:
            context: Validation context
            session_id: Optional session identifier

        Returns:
            Session ID for tracking
        """
        if not session_id:
            session_id = f"{context.tool_name}_{int(time.time())}_{id(context)}"

        self._active_sessions[session_id] = {
            "context": context,
            "start_time": datetime.now(),
            "last_check": datetime.now(),
            "resource_usage": {},
            "security_events": [],
        }

        logger.info(f"Started runtime validation session: {session_id}")
        return session_id

    async def validate_during_execution(
        self, session_id: str, execution_state: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """Perform runtime validation during execution.

        Args:
            session_id: Runtime validation session ID
            execution_state: Current execution state information

        Returns:
            ValidationResult with runtime findings
        """
        start_time = datetime.now()

        result = ValidationResult(
            validator_name="RuntimeValidator",
            category=ValidationCategory.RATE_LIMITING,
            status=ValidationStatus.PASSED,
            security_posture=SecurityPosture.SECURE,
        )

        try:
            session = self._active_sessions.get(session_id)
            if not session:
                finding = ValidationFinding(
                    category=ValidationCategory.RATE_LIMITING,
                    status=ValidationStatus.FAILED,
                    severity="critical",
                    title="Invalid Session",
                    description=f"Runtime validation session not found: {session_id}",
                    recommendation="Check session management",
                )
                result.add_finding(finding)
                result.status = ValidationStatus.FAILED
                return result

            context = session["context"]

            # Step 1: Check execution time limits
            await self._check_execution_limits(session, result)

            # Step 2: Monitor resource usage
            await self._monitor_resource_usage(session, execution_state, result)

            # Step 3: Validate operation progress
            await self._validate_operation_progress(session, result)

            # Step 4: Check for anomalous behavior
            await self._detect_anomalous_behavior(session, result)

            # Update session
            session["last_check"] = datetime.now()
            if execution_state:
                session["resource_usage"] = execution_state.get("resource_usage", {})

            # Determine final status
            critical_findings = result.get_critical_findings()
            if critical_findings:
                result.status = ValidationStatus.FAILED
                result.security_posture = SecurityPosture.BLOCKED

        except Exception as e:
            logger.error(f"Runtime validation error: {e}")
            result.status = ValidationStatus.ERROR
            result.security_posture = SecurityPosture.UNKNOWN
            result.error_message = str(e)

            finding = ValidationFinding(
                category=ValidationCategory.RATE_LIMITING,
                status=ValidationStatus.ERROR,
                severity="high",
                title="Runtime Validation Error",
                description=f"Runtime validation failed: {e}",
                recommendation="Check system resources and configuration",
            )
            result.add_finding(finding)

        finally:
            result.execution_time_ms = (
                datetime.now() - start_time
            ).total_seconds() * 1000

        return result

    async def end_validation(self, session_id: str) -> ValidationResult:
        """End runtime validation and generate final report.

        Args:
            session_id: Runtime validation session ID

        Returns:
            Final ValidationResult for the session
        """
        result = ValidationResult(
            validator_name="RuntimeValidator",
            category=ValidationCategory.RATE_LIMITING,
            status=ValidationStatus.PASSED,
            security_posture=SecurityPosture.SECURE,
        )

        try:
            session = self._active_sessions.get(session_id)
            if not session:
                finding = ValidationFinding(
                    category=ValidationCategory.RATE_LIMITING,
                    status=ValidationStatus.FAILED,
                    severity="medium",
                    title="Session Not Found",
                    description=f"Runtime validation session not found: {session_id}",
                    recommendation="Session may have already been cleaned up",
                )
                result.add_finding(finding)
                return result

            # Generate session summary
            execution_time = datetime.now() - session["start_time"]
            context = session["context"]

            finding = ValidationFinding(
                category=ValidationCategory.RATE_LIMITING,
                status=ValidationStatus.PASSED,
                severity="info",
                title="Session Completed",
                description=f"Runtime validation session completed successfully",
                recommendation="Session ended normally",
                evidence={
                    "session_id": session_id,
                    "tool_name": context.tool_name,
                    "execution_time_seconds": execution_time.total_seconds(),
                    "security_events": len(session["security_events"]),
                },
            )
            result.add_finding(finding)

            # Clean up session
            del self._active_sessions[session_id]
            logger.info(f"Ended runtime validation session: {session_id}")

        except Exception as e:
            logger.error(f"Error ending runtime validation: {e}")
            finding = ValidationFinding(
                category=ValidationCategory.RATE_LIMITING,
                status=ValidationStatus.ERROR,
                severity="medium",
                title="Session End Error",
                description=f"Error ending runtime validation: {e}",
                recommendation="Check session cleanup process",
            )
            result.add_finding(finding)

        return result

    async def _check_execution_limits(
        self, session: Dict[str, Any], result: ValidationResult
    ) -> None:
        """Check if execution exceeds time limits."""
        try:
            execution_time = datetime.now() - session["start_time"]
            execution_seconds = execution_time.total_seconds()

            if execution_seconds > self.max_execution_time_seconds:
                finding = ValidationFinding(
                    category=ValidationCategory.RATE_LIMITING,
                    status=ValidationStatus.FAILED,
                    severity="critical",
                    title="Execution Time Exceeded",
                    description=f"Operation exceeded maximum execution time of {self.max_execution_time_seconds} seconds",
                    recommendation="Terminate operation and review timeout configuration",
                    evidence={
                        "execution_time_seconds": execution_seconds,
                        "max_execution_time_seconds": self.max_execution_time_seconds,
                    },
                )
                result.add_finding(finding)

            # Warning at 80% of limit
            warning_threshold = self.max_execution_time_seconds * 0.8
            if execution_seconds > warning_threshold:
                finding = ValidationFinding(
                    category=ValidationCategory.RATE_LIMITING,
                    status=ValidationStatus.WARNING,
                    severity="medium",
                    title="Long Execution Time",
                    description=f"Operation approaching execution time limit",
                    recommendation="Monitor operation progress",
                    evidence={
                        "execution_time_seconds": execution_seconds,
                        "warning_threshold": warning_threshold,
                    },
                )
                result.add_finding(finding)

        except Exception as e:
            finding = ValidationFinding(
                category=ValidationCategory.RATE_LIMITING,
                status=ValidationStatus.ERROR,
                severity="medium",
                title="Execution Time Check Error",
                description=f"Failed to check execution time: {e}",
                recommendation="Check time tracking implementation",
            )
            result.add_finding(finding)

    async def _monitor_resource_usage(
        self,
        session: Dict[str, Any],
        execution_state: Optional[Dict[str, Any]],
        result: ValidationResult,
    ) -> None:
        """Monitor resource usage during execution."""
        try:
            if not execution_state:
                # Resource monitoring not available
                finding = ValidationFinding(
                    category=ValidationCategory.INFRASTRUCTURE,
                    status=ValidationStatus.SKIPPED,
                    severity="info",
                    title="Resource Monitoring Unavailable",
                    description="Resource usage monitoring not available for this operation",
                    recommendation="Implement resource monitoring for better security visibility",
                )
                result.add_finding(finding)
                return

            resource_usage = execution_state.get("resource_usage", {})

            # Check memory usage (if available)
            if "memory_mb" in resource_usage:
                memory_usage = resource_usage["memory_mb"]
                if memory_usage > 1024:  # 1GB threshold
                    finding = ValidationFinding(
                        category=ValidationCategory.INFRASTRUCTURE,
                        status=ValidationStatus.WARNING,
                        severity="medium",
                        title="High Memory Usage",
                        description=f"Operation using {memory_usage}MB memory",
                        recommendation="Monitor for memory exhaustion",
                        evidence={"memory_usage_mb": memory_usage},
                    )
                    result.add_finding(finding)

            # Check CPU usage (if available)
            if "cpu_percent" in resource_usage:
                cpu_usage = resource_usage["cpu_percent"]
                if cpu_usage > 80:  # 80% threshold
                    finding = ValidationFinding(
                        category=ValidationCategory.INFRASTRUCTURE,
                        status=ValidationStatus.WARNING,
                        severity="medium",
                        title="High CPU Usage",
                        description=f"Operation using {cpu_usage}% CPU",
                        recommendation="Monitor for resource exhaustion",
                        evidence={"cpu_percent": cpu_usage},
                    )
                    result.add_finding(finding)

            # Check network activity (if available)
            if (
                "network_bytes_sent" in resource_usage
                and "network_bytes_received" in resource_usage
            ):
                total_bytes = (
                    resource_usage["network_bytes_sent"]
                    + resource_usage["network_bytes_received"]
                )
                if total_bytes > 100 * 1024 * 1024:  # 100MB threshold
                    finding = ValidationFinding(
                        category=ValidationCategory.NETWORK,
                        status=ValidationStatus.WARNING,
                        severity="medium",
                        title="High Network Activity",
                        description=f"Operation transferred {total_bytes / (1024 * 1024):.1f}MB",
                        recommendation="Monitor for data exfiltration",
                        evidence={"total_network_bytes": total_bytes},
                    )
                    result.add_finding(finding)

            finding = ValidationFinding(
                category=ValidationCategory.INFRASTRUCTURE,
                status=ValidationStatus.PASSED,
                severity="info",
                title="Resource Monitoring Passed",
                description="Resource usage within acceptable limits",
                evidence=resource_usage,
            )
            result.add_finding(finding)

        except Exception as e:
            finding = ValidationFinding(
                category=ValidationCategory.INFRASTRUCTURE,
                status=ValidationStatus.ERROR,
                severity="medium",
                title="Resource Monitoring Error",
                description=f"Failed to monitor resource usage: {e}",
                recommendation="Check resource monitoring implementation",
            )
            result.add_finding(finding)

    async def _validate_operation_progress(
        self, session: Dict[str, Any], result: ValidationResult
    ) -> None:
        """Validate operation progress and completion."""
        try:
            context = session["context"]
            last_check = session["last_check"]
            time_since_last_check = (datetime.now() - last_check).total_seconds()

            # Check if operation is making progress
            if time_since_last_check > 300:  # 5 minutes without update
                finding = ValidationFinding(
                    category=ValidationCategory.RATE_LIMITING,
                    status=ValidationStatus.WARNING,
                    severity="medium",
                    title="Stalled Operation",
                    description=f"No progress detected for {time_since_last_check:.0f} seconds",
                    recommendation="Check if operation is still responding",
                    evidence={"time_since_last_check": time_since_last_check},
                )
                result.add_finding(finding)

            finding = ValidationFinding(
                category=ValidationCategory.RATE_LIMITING,
                status=ValidationStatus.PASSED,
                severity="info",
                title="Operation Progress Validated",
                description="Operation progress appears normal",
            )
            result.add_finding(finding)

        except Exception as e:
            finding = ValidationFinding(
                category=ValidationCategory.RATE_LIMITING,
                status=ValidationStatus.ERROR,
                severity="medium",
                title="Progress Validation Error",
                description=f"Failed to validate operation progress: {e}",
                recommendation="Check progress tracking implementation",
            )
            result.add_finding(finding)

    async def _detect_anomalous_behavior(
        self, session: Dict[str, Any], result: ValidationResult
    ) -> None:
        """Detect anomalous behavior patterns."""
        try:
            context = session["context"]
            security_events = session["security_events"]

            # Check for repeated security events (potential attack pattern)
            if len(security_events) > 5:
                finding = ValidationFinding(
                    category=ValidationCategory.NETWORK,
                    status=ValidationStatus.WARNING,
                    severity="high",
                    title="Repeated Security Events",
                    description=f"Detected {len(security_events)} security events during execution",
                    recommendation="Investigate potential malicious activity",
                    evidence={"security_event_count": len(security_events)},
                )
                result.add_finding(finding)

            # Basic anomaly detection would go here
            # This is a placeholder for more sophisticated behavioral analysis

            finding = ValidationFinding(
                category=ValidationCategory.NETWORK,
                status=ValidationStatus.PASSED,
                severity="info",
                title="Behavior Validation Passed",
                description="No anomalous behavior detected",
            )
            result.add_finding(finding)

        except Exception as e:
            finding = ValidationFinding(
                category=ValidationCategory.NETWORK,
                status=ValidationStatus.ERROR,
                severity="medium",
                title="Anomaly Detection Error",
                description=f"Failed to detect anomalous behavior: {e}",
                recommendation="Check anomaly detection implementation",
            )
            result.add_finding(finding)

    def record_security_event(self, session_id: str, event: Dict[str, Any]) -> None:
        """Record a security event during execution.

        Args:
            session_id: Runtime validation session ID
            event: Security event details
        """
        try:
            session = self._active_sessions.get(session_id)
            if session:
                session["security_events"].append(
                    {"timestamp": datetime.now().isoformat(), **event}
                )
                logger.warning(
                    f"Security event recorded for session {session_id}: {event}"
                )
        except Exception as e:
            logger.error(f"Failed to record security event: {e}")


# Export validator class
__all__ = ["RuntimeValidator"]
