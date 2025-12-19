"""
Example usage and integration guide for the new observability system.
"""

import time
from typing import Dict, Any

from src.models.execution import ExecutionStatus
from src.utils import (
    AuditLogger,
    get_logger,
    metrics_collector,
    health_checker,
    generate_correlation_id,
    ObservabilityIntegration,
    ToolIntegration,
)


class ObservabilityExample:
    """Example class demonstrating observability features."""

    def __init__(self):
        self.logger = get_logger("observability_example")
        self.audit_logger = AuditLogger()

    def example_structured_logging(self) -> None:
        """Example of structured logging with correlation IDs."""

        correlation_id = generate_correlation_id()
        self.logger.set_correlation_id(correlation_id)

        self.logger.debug("Starting structured logging example", operation="example")
        self.logger.info("Processing data batch", batch_size=100, target="database")
        self.logger.warning("High latency detected", latency_ms=1500, threshold_ms=1000)
        self.logger.error(
            "Database connection failed", error_code="DB_CONN_001", retry_count=3
        )

    def example_audit_logging(self) -> None:
        """Example of comprehensive audit logging."""

        correlation_id = generate_correlation_id()

        # Log operation start
        self.audit_logger.log_operation(
            operation="data_processing",
            correlation_id=correlation_id,
            target="database_server",
            capability="batch_processing",
            executor_type="python",
            parameters={"batch_size": 100, "chunk_size": 10},
            status=ExecutionStatus.SUCCESS,
            success=True,
            duration=2.5,
            subject="system_user",
            scopes=["read", "write"],
            risk_level="medium",
        )

    def example_metrics_collection(self) -> None:
        """Example of metrics collection."""

        # Start timing an operation
        metrics_collector.start_timer("data_processing")

        # Simulate processing
        time.sleep(0.1)

        # Stop timing and record duration
        metrics_collector.stop_timer("data_processing")

        # Record additional metrics
        metrics_collector.increment_counter("processed_records", 100)
        metrics_collector.record_gauge("memory_usage_mb", 256.5)
        metrics_collector.increment_counter("successful_operations")

        # Get all metrics
        metrics = metrics_collector.get_metrics()
        self.logger.info("Metrics collected", metrics=metrics)

    def example_health_checks(self) -> None:
        """Example of health checking."""

        # Run all health checks
        health_checker.run_all_checks()

        # Get status report
        status_report = health_checker.get_status_report()

        self.logger.info(
            "Health check results",
            overall_status=status_report["overall_status"],
            summary=status_report["summary"],
        )

    def example_legacy_integration(self) -> Dict[str, Any]:
        """Example of integrating with legacy execution results."""

        # Simulate a legacy execution result
        legacy_result = {
            "success": True,
            "output": "Operation completed successfully",
            "error": None,
            "duration": 1.5,
            "exit_code": 0,
        }

        # Enhance with observability features
        enhanced_result = ObservabilityIntegration.enhance_execution_result(
            original_result=legacy_result,
            correlation_id=generate_correlation_id(),
            target_id="target_server",
            capability="file_operation",
            executor_type="local",
            dry_run=False,
        )

        # Log the enhanced result
        self.audit_logger.log_execution_result(enhanced_result)

        return enhanced_result.dict()

    def example_tool_integration(self):
        """Example of tool integration with observability."""

        # Define a simple tool function
        def example_tool(
            param1: str, param2: int, target: str = "local", dry_run: bool = False
        ):
            """Example tool function."""
            # Simulate some work
            time.sleep(0.05)
            return {
                "success": True,
                "result": f"Processed {param1} with value {param2}",
                "target": target,
            }

        # Wrap the tool with observability
        wrapped_tool = ToolIntegration.wrap_tool_execution(
            example_tool, tool_name="example_tool", capability="data_processing"
        )

        # Execute the wrapped tool
        result = wrapped_tool("test_data", 42, target="remote_server", dry_run=False)

        return result


def demonstrate_observability() -> None:
    """Demonstrate all observability features."""

    example = ObservabilityExample()

    print("=== Structured Logging Example ===")
    example.example_structured_logging()

    print("\n=== Audit Logging Example ===")
    example.example_audit_logging()

    print("\n=== Metrics Collection Example ===")
    example.example_metrics_collection()

    print("\n=== Health Checks Example ===")
    example.example_health_checks()

    print("\n=== Legacy Integration Example ===")
    legacy_result = example.example_legacy_integration()
    print(f"Enhanced result: {legacy_result}")

    print("\n=== Tool Integration Example ===")
    tool_result = example.example_tool_integration()
    print(f"Tool result: {tool_result}")

    print("\n=== Observability demonstration complete ===")


if __name__ == "__main__":
    demonstrate_observability()
