"""
Testing utilities and assertion helpers for comprehensive test infrastructure.
"""

import time
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta

from src.services.executor import ExecutionResult, ExecutionStatus
from src.models.target_registry import TargetMetadata
from src.auth.token_auth import TokenClaims


class ExecutionAssertions:
    """Assertion helpers for execution results."""

    @staticmethod
    def assert_execution_success(
        result: ExecutionResult,
        expected_output: Optional[str] = None,
        expected_exit_code: int = 0,
    ):
        """Assert that execution was successful.

        Args:
            result: Execution result to check
            expected_output: Expected output (optional)
            expected_exit_code: Expected exit code
        """
        assert result.success is True, f"Execution failed: {result.error}"
        assert result.status == ExecutionStatus.SUCCESS
        assert result.exit_code == expected_exit_code

        if expected_output is not None:
            assert result.output == expected_output

    @staticmethod
    def assert_execution_failure(
        result: ExecutionResult,
        expected_error: Optional[str] = None,
        expected_status: ExecutionStatus = ExecutionStatus.FAILURE,
    ):
        """Assert that execution failed.

        Args:
            result: Execution result to check
            expected_error: Expected error message (optional)
            expected_status: Expected failure status
        """
        assert result.success is False
        assert result.status == expected_status

        if expected_error is not None:
            assert expected_error in result.error

    @staticmethod
    def assert_execution_duration(
        result: ExecutionResult, max_duration: float, min_duration: float = 0.0
    ):
        """Assert that execution duration is within expected range.

        Args:
            result: Execution result to check
            max_duration: Maximum allowed duration
            min_duration: Minimum expected duration
        """
        assert (
            min_duration <= result.duration <= max_duration
        ), f"Duration {result.duration}s not in range [{min_duration}, {max_duration}]"


class TargetAssertions:
    """Assertion helpers for target metadata."""

    @staticmethod
    def assert_target_has_capabilities(
        target: TargetMetadata, required_capabilities: List[str]
    ):
        """Assert that target has required capabilities.

        Args:
            target: Target metadata to check
            required_capabilities: List of required capabilities
        """
        for capability in required_capabilities:
            assert (
                capability in target.capabilities
            ), f"Target {target.id} missing capability: {capability}"

    @staticmethod
    def assert_target_constraints(
        target: TargetMetadata, constraint_name: str, expected_value: Any
    ):
        """Assert that target constraint has expected value.

        Args:
            target: Target metadata to check
            constraint_name: Name of constraint to check
            expected_value: Expected constraint value
        """
        constraints_dict = (
            target.constraints.dict() if hasattr(target.constraints, "dict") else {}
        )

        if constraint_name in constraints_dict:
            assert (
                constraints_dict[constraint_name] == expected_value
            ), f"Constraint {constraint_name} mismatch: {constraints_dict[constraint_name]} != {expected_value}"
        else:
            # If constraint doesn't exist, it should be None or empty
            assert (
                expected_value is None or expected_value == []
            ), f"Constraint {constraint_name} not found but expected {expected_value}"

    @staticmethod
    def assert_target_metadata(
        target: TargetMetadata, expected_metadata: Dict[str, Any]
    ):
        """Assert that target metadata matches expected values.

        Args:
            target: Target metadata to check
            expected_metadata: Expected metadata key-value pairs
        """
        for key, expected_value in expected_metadata.items():
            assert key in target.metadata, f"Metadata key {key} not found"
            assert (
                target.metadata[key] == expected_value
            ), f"Metadata {key} mismatch: {target.metadata[key]} != {expected_value}"


class AuthorizationAssertions:
    """Assertion helpers for authorization results."""

    @staticmethod
    def assert_authorized(
        auth_result: Dict[str, Any], expected_requires_approval: bool = False
    ):
        """Assert that operation was authorized.

        Args:
            auth_result: Authorization result
            expected_requires_approval: Whether approval should be required
        """
        assert auth_result["authorized"] is True
        assert auth_result["requires_approval"] == expected_requires_approval

    @staticmethod
    def assert_denied(
        auth_result: Dict[str, Any], expected_reason: Optional[str] = None
    ):
        """Assert that operation was denied.

        Args:
            auth_result: Authorization result
            expected_reason: Expected denial reason (optional)
        """
        assert auth_result["authorized"] is False
        assert auth_result["requires_approval"] is False

        if expected_reason is not None:
            assert expected_reason in auth_result["reason"]

    @staticmethod
    def assert_dry_run_result(
        auth_result: Dict[str, Any], expected_simulated: bool = True
    ):
        """Assert dry run result properties.

        Args:
            auth_result: Authorization result
            expected_simulated: Whether simulation should be indicated
        """
        dry_run_result = auth_result.get("dry_run_result")

        if dry_run_result is not None:
            assert dry_run_result["simulated"] == expected_simulated
            assert "message" in dry_run_result


class TestDataGenerators:
    """Generators for test data and scenarios."""

    @staticmethod
    def generate_execution_result(
        success: bool = True,
        status: ExecutionStatus = ExecutionStatus.SUCCESS,
        output: str = "Test output",
        error: str = "",
        exit_code: int = 0,
        duration: float = 0.1,
    ) -> ExecutionResult:
        """Generate a mock execution result.

        Args:
            success: Whether execution was successful
            status: Execution status
            output: Output text
            error: Error text
            exit_code: Exit code
            duration: Execution duration

        Returns:
            Configured ExecutionResult
        """
        return ExecutionResult(
            status=status,
            success=success,
            exit_code=exit_code,
            output=output,
            error=error,
            duration=duration,
        )

    @staticmethod
    def generate_token_claims(
        agent: str = "test-user",
        scopes: List[str] = None,
        host_tags: List[str] = None,
        expiry: Optional[datetime] = None,
    ) -> TokenClaims:
        """Generate token claims for testing.

        Args:
            agent: Agent identifier
            scopes: List of scopes
            host_tags: List of host tags
            expiry: Token expiry time

        Returns:
            Configured TokenClaims
        """
        if scopes is None:
            scopes = ["container:read", "system:read"]

        if host_tags is None:
            host_tags = []

        if expiry is None:
            expiry = datetime.utcnow() + timedelta(hours=1)

        return TokenClaims(
            agent=agent, scopes=scopes, host_tags=host_tags, expiry=expiry
        )

    @staticmethod
    def generate_command_variations(
        base_command: str, parameters: Dict[str, List[Any]]
    ) -> List[Dict[str, Any]]:
        """Generate command variations for parameter testing.

        Args:
            base_command: Base command template
            parameters: Parameter variations

        Returns:
            List of command variations
        """
        variations = []

        # Generate all combinations of parameter values
        from itertools import product

        param_names = list(parameters.keys())
        param_values = list(parameters.values())

        for value_combination in product(*param_values):
            command_params = dict(zip(param_names, value_combination))
            variations.append({"command": base_command, "parameters": command_params})

        return variations

    @staticmethod
    def generate_stress_test_scenarios(
        operation_count: int, concurrent_operations: int, base_delay: float = 0.01
    ) -> List[Dict[str, Any]]:
        """Generate stress test scenarios.

        Args:
            operation_count: Total number of operations
            concurrent_operations: Number of concurrent operations
            base_delay: Base delay between operations

        Returns:
            List of stress test scenarios
        """
        scenarios = []

        for i in range(operation_count):
            scenario = {
                "operation_id": f"stress-test-{i}",
                "concurrent_group": i % concurrent_operations,
                "delay": base_delay * (i // concurrent_operations),
                "expected_duration": base_delay
                * (operation_count // concurrent_operations),
            }
            scenarios.append(scenario)

        return scenarios


class PerformanceMetrics:
    """Performance measurement and assertion utilities.

    This class provides utilities for measuring and asserting performance
    characteristics of the system under test.
    """

    def __init__(self):
        """Initialize performance metrics collector."""
        self.metrics: Dict[str, List[float]] = {}
        self.start_times: Dict[str, float] = {}

    def start_timer(self, metric_name: str):
        """Start timing for a metric.

        Args:
            metric_name: Name of the metric to time
        """
        self.start_times[metric_name] = time.time()

    def stop_timer(self, metric_name: str) -> float:
        """Stop timing and record metric.

        Args:
            metric_name: Name of the metric to stop

        Returns:
            Elapsed time in seconds
        """
        if metric_name not in self.start_times:
            raise ValueError(f"Timer not started for metric: {metric_name}")

        elapsed = time.time() - self.start_times[metric_name]

        if metric_name not in self.metrics:
            self.metrics[metric_name] = []

        self.metrics[metric_name].append(elapsed)
        del self.start_times[metric_name]

        return elapsed

    def get_metric_stats(self, metric_name: str) -> Dict[str, float]:
        """Get statistics for a metric.

        Args:
            metric_name: Name of the metric

        Returns:
            Dictionary with min, max, avg, and count
        """
        if metric_name not in self.metrics:
            return {}

        values = self.metrics[metric_name]

        return {
            "min": min(values),
            "max": max(values),
            "avg": sum(values) / len(values),
            "count": len(values),
        }

    def assert_performance_threshold(
        self, metric_name: str, max_threshold: float, min_threshold: float = 0.0
    ):
        """Assert that performance metric meets thresholds.

        Args:
            metric_name: Name of the metric
            max_threshold: Maximum allowed value
            min_threshold: Minimum expected value
        """
        stats = self.get_metric_stats(metric_name)

        if not stats:
            raise ValueError(f"No data for metric: {metric_name}")

        assert min_threshold <= stats["avg"] <= max_threshold, (
            f"Performance metric {metric_name} out of range: {stats['avg']} "
            f"not in [{min_threshold}, {max_threshold}]"
        )

    def assert_concurrent_performance(
        self,
        metric_name: str,
        concurrent_count: int,
        max_increase_percent: float = 50.0,
    ):
        """Assert that concurrent operations don't degrade performance excessively.

        Args:
            metric_name: Name of the metric
            concurrent_count: Number of concurrent operations
            max_increase_percent: Maximum allowed performance degradation
        """
        stats = self.get_metric_stats(metric_name)

        if not stats or stats["count"] < concurrent_count:
            return  # Not enough data for meaningful comparison

        # Calculate expected single-threaded performance
        # This is a simplified model - real analysis would be more complex
        single_thread_estimate = stats["avg"] / concurrent_count

        # Allow some degradation due to concurrency overhead
        max_allowed = single_thread_estimate * (1 + max_increase_percent / 100)

        assert (
            stats["avg"] <= max_allowed
        ), f"Concurrent performance degradation too high: {stats['avg']} > {max_allowed}"


# Utility functions for common test patterns
def retry_assertion(assertion_func, max_attempts: int = 3, delay: float = 0.1):
    """Retry an assertion until it passes or max attempts reached.

    Args:
        assertion_func: Function that performs assertion
        max_attempts: Maximum number of retry attempts
        delay: Delay between attempts in seconds
    """
    for attempt in range(max_attempts):
        try:
            assertion_func()
            return  # Assertion passed
        except AssertionError:
            if attempt == max_attempts - 1:
                raise  # Final attempt failed
            time.sleep(delay)


def assert_json_contains(response: Dict[str, Any], expected: Dict[str, Any]):
    """Assert that JSON response contains expected fields and values.

    Args:
        response: Response dictionary
        expected: Expected fields and values
    """
    for key, expected_value in expected.items():
        assert key in response, f"Response missing key: {key}"
        assert (
            response[key] == expected_value
        ), f"Value mismatch for {key}: {response[key]} != {expected_value}"


def assert_error_response(
    response: Dict[str, Any], expected_error: str, expected_success: bool = False
):
    """Assert that response indicates an error.

    Args:
        response: Response dictionary
        expected_error: Expected error message
        expected_success: Expected success value
    """
    assert response.get("success") == expected_success
    assert expected_error in response.get("error", "")


# Export commonly used utilities
assert_execution_success = ExecutionAssertions.assert_execution_success
assert_execution_failure = ExecutionAssertions.assert_execution_failure
assert_target_has_capabilities = TargetAssertions.assert_target_has_capabilities
assert_authorized = AuthorizationAssertions.assert_authorized
assert_denied = AuthorizationAssertions.assert_denied
generate_execution_result = TestDataGenerators.generate_execution_result
generate_token_claims = TestDataGenerators.generate_token_claims
