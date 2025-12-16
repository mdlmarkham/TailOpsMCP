"""
Integration test framework for end-to-end testing of the control plane gateway.
"""

import asyncio
from typing import Any, Dict, List, Optional, Callable
from unittest.mock import Mock

from src.services.execution_service import ExecutionService
from src.utils.audit import AuditLogger

from tests.fixtures.target_registry_fixtures import TargetRegistryFixtures
from tests.mock_policy_gate import MockPolicyGate
from tests.test_utils import AuthorizationAssertions


class IntegrationTestFramework:
    """Framework for integration testing the control plane gateway."""

    def __init__(self):
        """Initialize integration test framework."""
        self.test_scenarios: Dict[str, Dict[str, Any]] = {}
        self.test_results: Dict[str, Dict[str, Any]] = {}
        self.performance_metrics: Dict[str, List[float]] = {}

    def register_test_scenario(
        self,
        scenario_id: str,
        description: str,
        setup_func: Callable,
        test_func: Callable,
        teardown_func: Optional[Callable] = None,
    ):
        """Register a test scenario.

        Args:
            scenario_id: Unique identifier for the scenario
            description: Description of the scenario
            setup_func: Function to set up test environment
            test_func: Function to execute the test
            teardown_func: Function to clean up after test
        """
        self.test_scenarios[scenario_id] = {
            "description": description,
            "setup": setup_func,
            "test": test_func,
            "teardown": teardown_func,
        }

    async def run_test_scenario(self, scenario_id: str) -> Dict[str, Any]:
        """Run a specific test scenario.

        Args:
            scenario_id: Identifier of the scenario to run

        Returns:
            Test results
        """
        if scenario_id not in self.test_scenarios:
            raise ValueError(f"Unknown test scenario: {scenario_id}")

        scenario = self.test_scenarios[scenario_id]

        # Setup
        test_context = {}
        if scenario["setup"]:
            test_context = await self._execute_function(scenario["setup"])

        # Test
        start_time = asyncio.get_event_loop().time()
        test_result = await self._execute_function(scenario["test"], test_context)
        end_time = asyncio.get_event_loop().time()

        # Record performance
        duration = end_time - start_time
        if "performance" not in self.performance_metrics:
            self.performance_metrics["performance"] = []
        self.performance_metrics["performance"].append(duration)

        # Teardown
        if scenario["teardown"]:
            await self._execute_function(scenario["teardown"], test_context)

        # Store results
        self.test_results[scenario_id] = {
            "success": test_result.get("success", True),
            "duration": duration,
            "details": test_result,
        }

        return self.test_results[scenario_id]

    async def run_all_scenarios(self) -> Dict[str, Dict[str, Any]]:
        """Run all registered test scenarios.

        Returns:
            Dictionary of all test results
        """
        for scenario_id in self.test_scenarios:
            await self.run_test_scenario(scenario_id)

        return self.test_results

    async def _execute_function(
        self, func: Callable, context: Dict[str, Any] = None
    ) -> Any:
        """Execute a function with proper error handling.

        Args:
            func: Function to execute
            context: Context to pass to function

        Returns:
            Function result
        """
        if context is None:
            context = {}

        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(**context)
            else:
                result = func(**context)
            return result
        except Exception as e:
            return {"success": False, "error": str(e)}


class EndToEndTestBuilder:
    """Builder for creating end-to-end test scenarios."""

    @staticmethod
    def create_basic_operation_test(
        tool_name: str, target_id: str = "local-host", parameters: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Create a basic operation test scenario.

        Args:
            tool_name: Name of the tool to test
            target_id: Target identifier
            parameters: Tool parameters

        Returns:
            Test scenario configuration
        """
        if parameters is None:
            parameters = {}

        async def setup():
            """Setup for basic operation test."""
            # Create mock components
            target_registry = TargetRegistryFixtures.create_mock_target_registry()
            policy_gate = MockPolicyGate(default_allow=True)
            audit_logger = Mock(spec=AuditLogger)

            # Create execution service
            execution_service = ExecutionService(
                target_registry, policy_gate, audit_logger
            )

            return {
                "execution_service": execution_service,
                "target_registry": target_registry,
                "policy_gate": policy_gate,
                "audit_logger": audit_logger,
                "tool_name": tool_name,
                "target_id": target_id,
                "parameters": parameters,
            }

        async def test(context):
            """Execute the test."""
            execution_service = context["execution_service"]
            tool_name = context["tool_name"]
            target_id = context["target_id"]
            parameters = context["parameters"]

            # Generate test claims
            from tests.test_utils import TestDataGenerators

            claims = TestDataGenerators.generate_token_claims()

            # Execute operation
            result = await execution_service.execute_operation(
                tool_name, target_id, parameters, claims
            )

            # Verify result
            assert result["success"] is True
            assert "execution_result" in result

            return {"success": True, "execution_result": result["execution_result"]}

        return {"setup": setup, "test": test, "teardown": None}

    @staticmethod
    def create_authorization_test(
        tool_name: str, target_id: str = "local-host", should_authorize: bool = True
    ) -> Dict[str, Any]:
        """Create an authorization test scenario.

        Args:
            tool_name: Name of the tool to test
            target_id: Target identifier
            should_authorize: Whether operation should be authorized

        Returns:
            Test scenario configuration
        """

        async def setup():
            """Setup for authorization test."""
            target_registry = TargetRegistryFixtures.create_mock_target_registry()

            # Configure policy gate based on test requirements
            policy_gate = MockPolicyGate(default_allow=should_authorize)
            if not should_authorize:
                policy_gate.deny_operation(tool_name, target_id)

            audit_logger = Mock(spec=AuditLogger)
            execution_service = ExecutionService(
                target_registry, policy_gate, audit_logger
            )

            return {
                "execution_service": execution_service,
                "policy_gate": policy_gate,
                "tool_name": tool_name,
                "target_id": target_id,
                "should_authorize": should_authorize,
            }

        async def test(context):
            """Execute the authorization test."""
            execution_service = context["execution_service"]
            tool_name = context["tool_name"]
            target_id = context["target_id"]
            should_authorize = context["should_authorize"]

            from tests.test_utils import TestDataGenerators

            claims = TestDataGenerators.generate_token_claims()

            result = await execution_service.execute_operation(
                tool_name, target_id, {}, claims
            )

            # Verify authorization result
            if should_authorize:
                assert result["success"] is True
                AuthorizationAssertions.assert_authorized(
                    result.get("authorization_result", {})
                )
            else:
                assert result["success"] is False
                AuthorizationAssertions.assert_denied(
                    result.get("authorization_result", {})
                )

            return {"success": True, "authorized": should_authorize}

        return {"setup": setup, "test": test, "teardown": None}

    @staticmethod
    def create_performance_test(
        tool_name: str,
        target_id: str = "local-host",
        operation_count: int = 10,
        concurrent_operations: int = 3,
    ) -> Dict[str, Any]:
        """Create a performance test scenario.

        Args:
            tool_name: Name of the tool to test
            target_id: Target identifier
            operation_count: Number of operations to perform
            concurrent_operations: Number of concurrent operations

        Returns:
            Test scenario configuration
        """

        async def setup():
            """Setup for performance test."""
            target_registry = TargetRegistryFixtures.create_mock_target_registry()
            policy_gate = MockPolicyGate(default_allow=True)
            audit_logger = Mock(spec=AuditLogger)
            execution_service = ExecutionService(
                target_registry, policy_gate, audit_logger
            )

            return {
                "execution_service": execution_service,
                "tool_name": tool_name,
                "target_id": target_id,
                "operation_count": operation_count,
                "concurrent_operations": concurrent_operations,
            }

        async def test(context):
            """Execute performance test."""
            execution_service = context["execution_service"]
            tool_name = context["tool_name"]
            target_id = context["target_id"]
            operation_count = context["operation_count"]
            concurrent_operations = context["concurrent_operations"]

            from tests.test_utils import TestDataGenerators

            claims = TestDataGenerators.generate_token_claims()

            # Execute operations concurrently
            tasks = []
            start_time = asyncio.get_event_loop().time()

            for i in range(operation_count):
                task = execution_service.execute_operation(
                    tool_name, target_id, {"iteration": i}, claims
                )
                tasks.append(task)

                # Limit concurrency
                if len(tasks) >= concurrent_operations:
                    await asyncio.gather(*tasks)
                    tasks = []

            # Wait for remaining tasks
            if tasks:
                await asyncio.gather(*tasks)

            end_time = asyncio.get_event_loop().time()
            total_duration = end_time - start_time

            return {
                "success": True,
                "operation_count": operation_count,
                "concurrent_operations": concurrent_operations,
                "total_duration": total_duration,
                "operations_per_second": operation_count / total_duration,
            }

        return {"setup": setup, "test": test, "teardown": None}


# Predefined integration test scenarios
class IntegrationTestScenarios:
    """Predefined integration test scenarios for common use cases."""

    @staticmethod
    def get_container_status() -> Dict[str, Any]:
        """Test getting container status."""
        return EndToEndTestBuilder.create_basic_operation_test(
            "get_container_status", parameters={"container_id": "test-container"}
        )

    @staticmethod
    def start_container_authorized() -> Dict[str, Any]:
        """Test starting a container with authorization."""
        return EndToEndTestBuilder.create_authorization_test(
            "start_container", should_authorize=True
        )

    @staticmethod
    def start_container_denied() -> Dict[str, Any]:
        """Test starting a container without authorization."""
        return EndToEndTestBuilder.create_authorization_test(
            "start_container", should_authorize=False
        )

    @staticmethod
    def list_containers_performance() -> Dict[str, Any]:
        """Test performance of listing containers."""
        return EndToEndTestBuilder.create_performance_test(
            "list_containers", operation_count=50, concurrent_operations=5
        )

    @staticmethod
    def system_status_check() -> Dict[str, Any]:
        """Test system status check operation."""
        return EndToEndTestBuilder.create_basic_operation_test("get_system_status")


def run_integration_test_suite() -> Dict[str, Any]:
    """Run the complete integration test suite.

    Returns:
        Test suite results
    """
    framework = IntegrationTestFramework()

    # Register all test scenarios
    scenarios = IntegrationTestScenarios

    framework.register_test_scenario(
        "get_container_status",
        "Test getting container status",
        scenarios.get_container_status()["setup"],
        scenarios.get_container_status()["test"],
    )

    framework.register_test_scenario(
        "start_container_authorized",
        "Test starting container with authorization",
        scenarios.start_container_authorized()["setup"],
        scenarios.start_container_authorized()["test"],
    )

    framework.register_test_scenario(
        "start_container_denied",
        "Test starting container without authorization",
        scenarios.start_container_denied()["setup"],
        scenarios.start_container_denied()["test"],
    )

    framework.register_test_scenario(
        "list_containers_performance",
        "Test performance of listing containers",
        scenarios.list_containers_performance()["setup"],
        scenarios.list_containers_performance()["test"],
    )

    framework.register_test_scenario(
        "system_status_check",
        "Test system status check operation",
        scenarios.system_status_check()["setup"],
        scenarios.system_status_check()["test"],
    )

    # Run all scenarios
    results = asyncio.run(framework.run_all_scenarios())

    return {
        "scenarios_run": len(results),
        "successful_scenarios": sum(1 for r in results.values() if r["success"]),
        "failed_scenarios": sum(1 for r in results.values() if not r["success"]),
        "detailed_results": results,
    }
