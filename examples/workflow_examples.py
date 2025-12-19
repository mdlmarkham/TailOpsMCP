"""
Workflow Examples and Test Scenarios for TailOpsMCP.

Provides comprehensive examples of how to use the workflow system
and test scenarios for validation.
"""

import asyncio
import logging
from datetime import datetime, timedelta

from src.models.workflow_models import (
    WorkflowBlueprint,
    WorkflowCategory,
    ApprovalRequirement,
    RollbackAction,
    RollbackPlan,
    WorkflowStep,
    StepType,
)
from src.services.workflow_blueprints import (
    EnvironmentProvisioningWorkflow,
    BackupOrchestrationWorkflow,
    SafeUpgradeWorkflow,
    DisasterRecoveryWorkflow,
)


logger = logging.getLogger(__name__)


class WorkflowExamples:
    """Examples of workflow usage."""

    @staticmethod
    async def example_provision_environment():
        """Example: Provision a production environment."""
        print("=== Environment Provisioning Example ===")

        # Create workflow blueprint
        workflow = EnvironmentProvisioningWorkflow(
            environment_name="production-api-v2",
            container_count=5,
            service_type="api",
            node_type="high-memory",
        )

        # Set execution parameters
        parameters = {
            "environment_name": "production-api-v2",
            "container_count": 5,
            "service_type": "api",
            "node_type": "high-memory",
            "backup_enabled": True,
            "monitoring_enabled": True,
        }

        print(f"Created workflow: {workflow.name}")
        print(f"Parameters: {parameters}")
        print(f"Estimated duration: {workflow.estimated_duration}")
        print(
            f"Required approvals: {[step.step_id for step in workflow.steps if step.requires_approval]}"
        )

        return {
            "workflow": workflow,
            "parameters": parameters,
            "required_approvals": ["allocate_resources", "create_initial_backup"],
        }

    @staticmethod
    async def example_fleet_backup():
        """Example: Execute fleet backup."""
        print("=== Fleet Backup Example ===")

        # Create backup workflow
        workflow = BackupOrchestrationWorkflow(
            backup_retention_days=30, backup_compression=True
        )

        parameters = {
            "backup_retention_days": 30,
            "backup_compression": True,
            "backup_destination": "s3",
            "include_logs": False,
            "backup_schedule": "daily",
        }

        print(f"Created workflow: {workflow.name}")
        print(f"Parameters: {parameters}")
        print(f"Resource requirements: {workflow.resource_requirements}")

        return {"workflow": workflow, "parameters": parameters}

    @staticmethod
    async def example_safe_upgrade():
        """Example: Safe container upgrade."""
        print("=== Safe Upgrade Example ===")

        # Create upgrade workflow
        workflow = SafeUpgradeWorkflow(
            upgrade_type="rolling", maintenance_window="off-hours"
        )

        parameters = {
            "upgrade_type": "rolling",
            "maintenance_window": "off-hours",
            "max_downtime_minutes": 30,
            "rollback_on_failure": True,
            "test_environment": "staging",
        }

        print(f"Created workflow: {workflow.name}")
        print(f"Upgrade strategy: {parameters['upgrade_type']}")
        print(f"Rollback enabled: {parameters['rollback_on_failure']}")

        return {"workflow": workflow, "parameters": parameters}

    @staticmethod
    async def example_disaster_recovery():
        """Example: Disaster recovery."""
        print("=== Disaster Recovery Example ===")

        # Create recovery workflow
        workflow = DisasterRecoveryWorkflow(
            recovery_type="full", validation_level="comprehensive"
        )

        parameters = {
            "recovery_type": "full",
            "backup_timestamp": "2025-12-14T02:00:00Z",
            "validation_level": "comprehensive",
            "target_environment": "production-recovery",
            "preserve_current_state": True,
        }

        print(f"Created workflow: {workflow.name}")
        print(f"Recovery type: {parameters['recovery_type']}")
        print(f"Backup timestamp: {parameters['backup_timestamp']}")
        print(f"Target environment: {parameters['target_environment']}")

        return {"workflow": workflow, "parameters": parameters}


class WorkflowTestScenarios:
    """Test scenarios for workflow system validation."""

    @staticmethod
    async def test_basic_workflow_execution():
        """Test basic workflow execution."""
        print("\n=== Test: Basic Workflow Execution ===")

        try:
            # Create simple test workflow
            from src.models.workflow_models import WorkflowStep, StepType, Parameter

            parameters = {
                "test_param": Parameter(
                    name="test_param",
                    type="string",
                    required=True,
                    description="Test parameter",
                )
            }

            steps = [
                WorkflowStep(
                    step_id="test_step",
                    name="Test Step",
                    description="A simple test step",
                    step_type=StepType.VALIDATION,
                    timeout=timedelta(minutes=5),
                )
            ]

            workflow = WorkflowBlueprint(
                name="Test Workflow",
                description="Simple test workflow",
                version="1.0.0",
                category=WorkflowCategory.TESTING,
                parameters=parameters,
                steps=steps,
            )

            # Validate workflow
            validation_result = workflow.validate()
            if validation_result:
                print(f"❌ Workflow validation failed: {validation_result}")
                return False

            print("✅ Basic workflow creation and validation passed")
            return True

        except Exception as e:
            print(f"❌ Basic workflow test failed: {e}")
            return False

    @staticmethod
    async def test_workflow_with_approvals():
        """Test workflow with approval requirements."""
        print("\n=== Test: Workflow with Approvals ===")

        try:
            # Create workflow with approval requirements
            steps = [
                WorkflowStep(
                    step_id="step1",
                    name="Step 1",
                    description="Step requiring approval",
                    step_type=StepType.VALIDATION,
                    requires_approval=True,
                    approvers=["test_approver"],
                ),
                WorkflowStep(
                    step_id="step2",
                    name="Step 2",
                    description="Step after approval",
                    step_type=StepType.VALIDATION,
                    dependencies=["step1"],
                ),
            ]

            approvals = [
                ApprovalRequirement(
                    step_id="step1",
                    required_approvers=["test_approver"],
                    description="Test approval",
                )
            ]

            workflow = WorkflowBlueprint(
                name="Approval Test Workflow",
                description="Test workflow with approvals",
                version="1.0.0",
                category=WorkflowCategory.TESTING,
                steps=steps,
                approvals=approvals,
            )

            # Check approval requirements
            approval_steps = [step for step in workflow.steps if step.requires_approval]
            if not approval_steps:
                print("❌ No approval steps found")
                return False

            print(
                f"✅ Workflow with approvals created: {len(approval_steps)} approval steps"
            )
            return True

        except Exception as e:
            print(f"❌ Approval workflow test failed: {e}")
            return False

    @staticmethod
    async def test_workflow_rollback():
        """Test workflow rollback functionality."""
        print("\n=== Test: Workflow Rollback ===")

        try:
            # Create workflow with rollback plan
            rollback_actions = [
                RollbackAction(
                    action_id="cleanup",
                    name="Cleanup Test Resources",
                    step_type=StepType.CONTAINER_OPERATIONS,
                    parameters={"action": "cleanup"},
                )
            ]

            rollback_plan = RollbackPlan(
                enabled=True, actions=rollback_actions, conditions=["test_failure"]
            )

            workflow = WorkflowBlueprint(
                name="Rollback Test Workflow",
                description="Test workflow with rollback",
                version="1.0.0",
                category=WorkflowCategory.TESTING,
                steps=[
                    WorkflowStep(
                        step_id="test_step",
                        name="Test Step",
                        description="Test step for rollback",
                        step_type=StepType.VALIDATION,
                    )
                ],
                rollback_plan=rollback_plan,
            )

            if not workflow.rollback_plan or not workflow.rollback_plan.enabled:
                print("❌ Rollback plan not properly configured")
                return False

            print(
                f"✅ Workflow with rollback created: {len(rollback_plan.actions)} rollback actions"
            )
            return True

        except Exception as e:
            print(f"❌ Rollback workflow test failed: {e}")
            return False

    @staticmethod
    async def test_workflow_scheduling():
        """Test workflow scheduling functionality."""
        print("\n=== Test: Workflow Scheduling ===")

        try:
            # Test cron expression validation
            from src.services.workflow_scheduler import ScheduleManager

            schedule_manager = ScheduleManager(None)  # Mock scheduler

            # Test valid cron expressions
            valid_expressions = [
                "0 2 * * *",  # Daily at 2 AM
                "0 0 * * 0",  # Weekly on Sunday at midnight
                "0 0 1 * *",  # Monthly on 1st at midnight
                "*/15 * * * *",  # Every 15 minutes
            ]

            for expression in valid_expressions:
                result = await schedule_manager.validate_cron_expression(expression)
                if not result["valid"]:
                    print(f"❌ Invalid cron expression: {expression}")
                    return False

            print("✅ Workflow scheduling validation passed")
            return True

        except Exception as e:
            print(f"❌ Workflow scheduling test failed: {e}")
            return False

    @staticmethod
    async def test_workflow_integration():
        """Test workflow system integration."""
        print("\n=== Test: Workflow Integration ===")

        try:
            # Test workflow blueprint serialization
            workflow = EnvironmentProvisioningWorkflow(
                environment_name="test-env", service_type="web"
            )

            # Test to_dict conversion
            workflow_dict = workflow.to_dict()
            if not isinstance(workflow_dict, dict):
                print("❌ Workflow serialization failed")
                return False

            # Test required fields
            required_fields = ["name", "description", "category", "steps", "parameters"]
            for field in required_fields:
                if field not in workflow_dict:
                    print(f"❌ Missing required field: {field}")
                    return False

            print("✅ Workflow integration test passed")
            return True

        except Exception as e:
            print(f"❌ Workflow integration test failed: {e}")
            return False


class WorkflowPerformanceTests:
    """Performance tests for workflow system."""

    @staticmethod
    async def test_workflow_validation_performance():
        """Test workflow validation performance."""
        print("\n=== Performance Test: Workflow Validation ===")

        try:
            # Create multiple workflows for testing
            workflows = []
            for i in range(10):
                workflow = EnvironmentProvisioningWorkflow(
                    environment_name=f"test-env-{i}", service_type="web"
                )
                workflows.append(workflow)

            # Time the validation
            start_time = datetime.now()

            for workflow in workflows:
                validation_result = workflow.validate()
                if validation_result:
                    print(
                        f"❌ Validation failed for workflow {workflow.name}: {validation_result}"
                    )
                    return False

            end_time = datetime.now()
            validation_time = (end_time - start_time).total_seconds()

            print(
                f"✅ Validated {len(workflows)} workflows in {validation_time:.2f} seconds"
            )

            if validation_time > 5.0:  # Should complete within 5 seconds
                print(
                    f"⚠️  Validation took longer than expected: {validation_time:.2f}s"
                )

            return True

        except Exception as e:
            print(f"❌ Performance test failed: {e}")
            return False

    @staticmethod
    async def test_workflow_serialization_performance():
        """Test workflow serialization performance."""
        print("\n=== Performance Test: Workflow Serialization ===")

        try:
            # Create complex workflow
            workflow = EnvironmentProvisioningWorkflow(
                environment_name="complex-test-env",
                container_count=10,
                service_type="api",
            )

            # Time serialization
            start_time = datetime.now()

            for _ in range(100):
                workflow_dict = workflow.to_dict()
                if not isinstance(workflow_dict, dict):
                    return False

            end_time = datetime.now()
            serialization_time = (end_time - start_time).total_seconds()

            print(
                f"✅ Serialized workflow 100 times in {serialization_time:.2f} seconds"
            )

            if serialization_time > 2.0:  # Should complete within 2 seconds
                print(
                    f"⚠️  Serialization took longer than expected: {serialization_time:.2f}s"
                )

            return True

        except Exception as e:
            print(f"❌ Serialization performance test failed: {e}")
            return False


class WorkflowScenarioRunner:
    """Run comprehensive workflow scenarios."""

    def __init__(self):
        """Initialize scenario runner."""
        self.test_results = []

    async def run_all_tests(self):
        """Run all workflow tests."""
        print("🚀 Starting TailOpsMCP Workflow System Tests\n")

        # Basic functionality tests
        tests = [
            self.test_basic_workflow_execution(),
            self.test_workflow_with_approvals(),
            self.test_workflow_rollback(),
            self.test_workflow_scheduling(),
            self.test_workflow_integration(),
        ]

        # Performance tests
        performance_tests = [
            self.test_workflow_validation_performance(),
            self.test_workflow_serialization_performance(),
        ]

        # Run tests
        for test in tests:
            result = await test
            self.test_results.append(result)

        for test in performance_tests:
            result = await test
            self.test_results.append(result)

        # Print summary
        self.print_test_summary()

    async def run_example_scenarios(self):
        """Run example workflow scenarios."""
        print("🎯 Running TailOpsMCP Workflow Examples\n")

        examples = [
            WorkflowExamples.example_provision_environment(),
            WorkflowExamples.example_fleet_backup(),
            WorkflowExamples.example_safe_upgrade(),
            WorkflowExamples.example_disaster_recovery(),
        ]

        for example in examples:
            result = await example
            print(f"✅ Example completed: {result['workflow'].name}\n")

    def print_test_summary(self):
        """Print test execution summary."""
        print("\n" + "=" * 60)
        print("📊 WORKFLOW SYSTEM TEST SUMMARY")
        print("=" * 60)

        passed = sum(1 for result in self.test_results if result)
        total = len(self.test_results)

        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {total - passed}")
        print(f"Success Rate: {(passed / total) * 100:.1f}%")

        if passed == total:
            print("\n🎉 All tests passed! Workflow system is ready for use.")
        else:
            print(
                f"\n⚠️  {total - passed} tests failed. Please review the issues above."
            )

        print("=" * 60)


async def main():
    """Main test runner."""
    runner = WorkflowScenarioRunner()

    # Run example scenarios first
    await runner.run_example_scenarios()

    # Run tests
    await runner.run_all_tests()


if __name__ == "__main__":
    asyncio.run(main())
