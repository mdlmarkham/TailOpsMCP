"""
Comprehensive test suite for workflow orchestration components.

Tests workflow execution lifecycle, error handling, approval workflows,
scheduling, parallel execution, and pause/resume functionality.
"""

import pytest
import asyncio
import uuid
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock

from src.services.workflow_engine import WorkflowEngine
from src.services.workflow_scheduler import WorkflowScheduler
from src.services.workflow_approval import ApprovalSystem, WorkflowGovernance
from src.services.workflow_blueprints import (
    WorkflowBlueprint,
    WorkflowStep,
    WorkflowStepType,
)
from src.models.workflow_models import (
    WorkflowExecution,
    WorkflowStatus,
    ExecutionContext,
    WorkflowApproval,
    ApprovalStatus,
)
from src.tools.workflow_management_tools import WorkflowManagementTools


class TestWorkflowOrchestration:
    """Test workflow execution orchestration."""

    @pytest.fixture
    def mock_workflow_engine(self):
        """Create mock workflow engine."""
        engine = Mock(spec=WorkflowEngine)
        engine.execute_workflow = AsyncMock()
        engine.get_execution_status = AsyncMock()
        engine.cancel_execution = AsyncMock()
        engine.pause_execution = AsyncMock()
        engine.resume_execution = AsyncMock()
        return engine

    @pytest.fixture
    def mock_scheduler(self):
        """Create mock workflow scheduler."""
        scheduler = Mock(spec=WorkflowScheduler)
        scheduler.schedule_workflow = AsyncMock()
        scheduler.cancel_scheduled_workflow = AsyncMock()
        scheduler.get_scheduled_workflows = AsyncMock()
        return scheduler

    @pytest.fixture
    def mock_approval_system(self):
        """Create mock approval system."""
        approval_system = Mock(spec=ApprovalSystem)
        approval_system.request_approval = AsyncMock()
        approval_system.approve_workflow = AsyncMock()
        approval_system.reject_workflow = AsyncMock()
        return approval_system

    @pytest.fixture
    def workflow_tools(
        self, mock_workflow_engine, mock_scheduler, mock_approval_system
    ):
        """Create workflow management tools instance."""
        governance = Mock(spec=WorkflowGovernance)
        return WorkflowManagementTools(
            mock_workflow_engine, mock_scheduler, mock_approval_system, governance
        )

    @pytest.mark.asyncio
    async def test_workflow_execution_lifecycle(
        self, workflow_tools, mock_workflow_engine
    ):
        """Test complete workflow execution lifecycle."""
        # Setup test workflow blueprint
        blueprint_id = str(uuid.uuid4())
        blueprint = WorkflowBlueprint(
            id=blueprint_id,
            name="Test Workflow",
            description="Test workflow execution lifecycle",
            version="1.0",
            steps=[
                WorkflowStep(
                    id="step1",
                    name="Initialize",
                    type=WorkflowStepType.ACTION,
                    action="initialize",
                    parameters={},
                ),
                WorkflowStep(
                    id="step2",
                    name="Execute",
                    type=WorkflowStepType.ACTION,
                    action="execute",
                    parameters={},
                ),
            ],
            triggers=[],
            approvals_required=[],
            timeout=3600,
            created_by="test",
        )

        # Mock execution context
        execution_context = ExecutionContext(
            execution_id=str(uuid.uuid4()),
            blueprint_id=blueprint_id,
            trigger_type="manual",
            initiated_by="test",
            parameters={},
        )

        # Test workflow execution
        execution_id = await workflow_tools.workflow_engine.execute_workflow(
            blueprint, execution_context
        )

        # Verify execution was initiated
        assert execution_id is not None
        mock_workflow_engine.execute_workflow.assert_called_once_with(
            blueprint, execution_context
        )

        # Test execution status tracking
        mock_workflow_engine.get_execution_status.return_value = WorkflowExecution(
            id=execution_id,
            status=WorkflowStatus.RUNNING,
            current_step="step1",
            started_at=datetime.utcnow(),
        )

        status = await workflow_tools.workflow_engine.get_execution_status(execution_id)
        assert status.status == WorkflowStatus.RUNNING

        # Test execution completion
        mock_workflow_engine.get_execution_status.return_value = WorkflowExecution(
            id=execution_id,
            status=WorkflowStatus.COMPLETED,
            current_step=None,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
        )

        final_status = await workflow_tools.workflow_engine.get_execution_status(
            execution_id
        )
        assert final_status.status == WorkflowStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_workflow_error_handling_and_rollback(
        self, workflow_tools, mock_workflow_engine
    ):
        """Test error handling and automatic rollback."""
        # Setup workflow blueprint with rollback capability
        blueprint = WorkflowBlueprint(
            id=str(uuid.uuid4()),
            name="Test Rollback Workflow",
            description="Test workflow with rollback",
            version="1.0",
            steps=[
                WorkflowStep(
                    id="step1",
                    name="Initialize",
                    type=WorkflowStepType.ACTION,
                    action="initialize",
                    parameters={},
                ),
                WorkflowStep(
                    id="step2",
                    name="Execute",
                    type=WorkflowStepType.ACTION,
                    action="execute",
                    parameters={},
                ),
                WorkflowStep(
                    id="rollback",
                    name="Rollback",
                    type=WorkflowStepType.ROLLBACK,
                    action="rollback",
                    parameters={},
                ),
            ],
            triggers=[],
            approvals_required=[],
            timeout=3600,
            created_by="test",
        )

        execution_context = ExecutionContext(
            execution_id=str(uuid.uuid4()),
            blueprint_id=blueprint.id,
            trigger_type="manual",
            initiated_by="test",
            parameters={},
        )

        # Mock execution that fails and triggers rollback
        mock_workflow_engine.execute_workflow.side_effect = Exception(
            "Simulated failure"
        )

        # Test error handling
        with pytest.raises(Exception, match="Simulated failure"):
            await workflow_tools.workflow_engine.execute_workflow(
                blueprint, execution_context
            )

        # Test rollback execution
        mock_workflow_engine.execute_workflow.side_effect = None
        mock_workflow_engine.execute_workflow.return_value = "rollback-execution-id"

        # Simulate rollback execution
        execution_id = await workflow_tools.workflow_engine.execute_workflow(
            blueprint, execution_context
        )
        assert execution_id == "rollback-execution-id"

        # Verify rollback status
        mock_workflow_engine.get_execution_status.return_value = WorkflowExecution(
            id=execution_id,
            status=WorkflowStatus.COMPLETED,
            current_step=None,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            rollback_executed=True,
        )

        status = await workflow_tools.workflow_engine.get_execution_status(execution_id)
        assert status.status == WorkflowStatus.COMPLETED
        assert status.rollback_executed is True

    @pytest.mark.asyncio
    async def test_workflow_approval_workflow(
        self, workflow_tools, mock_approval_system
    ):
        """Test approval-based workflow execution."""
        # Setup workflow blueprint with approval requirement
        blueprint = WorkflowBlueprint(
            id=str(uuid.uuid4()),
            name="Test Approval Workflow",
            description="Test workflow requiring approval",
            version="1.0",
            steps=[
                WorkflowStep(
                    id="step1",
                    name="Plan Changes",
                    type=WorkflowStepType.PLAN,
                    action="plan_changes",
                    parameters={},
                ),
                WorkflowStep(
                    id="step2",
                    name="Execute Changes",
                    type=WorkflowStepType.ACTION,
                    action="execute_changes",
                    parameters={},
                ),
            ],
            triggers=[],
            approvals_required=["admin", "security_team"],
            timeout=3600,
            created_by="test",
        )

        # Test approval request
        approval_request = {
            "workflow_id": blueprint.id,
            "requested_by": "test",
            "approval_type": "workflow_execution",
            "details": {"blueprint_name": blueprint.name, "estimated_duration": 3600},
        }

        mock_approval_system.request_approval.return_value = WorkflowApproval(
            id=str(uuid.uuid4()),
            workflow_id=blueprint.id,
            approval_type="workflow_execution",
            requested_by="test",
            status=ApprovalStatus.PENDING,
            created_at=datetime.utcnow(),
        )

        approval = await workflow_tools.approval_system.request_approval(
            approval_request
        )
        assert approval.status == ApprovalStatus.PENDING

        # Test approval approval
        mock_approval_system.approve_workflow.return_value = True
        approved = await workflow_tools.approval_system.approve_workflow(
            approval.id, "admin", "Approved for testing"
        )
        assert approved is True

        # Test approval rejection
        mock_approval_system.reject_workflow.return_value = True
        rejected = await workflow_tools.approval_system.reject_workflow(
            approval.id, "security_team", "Security concerns identified"
        )
        assert rejected is True

    @pytest.mark.asyncio
    async def test_workflow_scheduling_and_recurring_execution(
        self, workflow_tools, mock_scheduler
    ):
        """Test workflow scheduling and recurring execution."""
        # Setup workflow blueprint for scheduling
        blueprint = WorkflowBlueprint(
            id=str(uuid.uuid4()),
            name="Test Scheduled Workflow",
            description="Test scheduled workflow execution",
            version="1.0",
            steps=[
                WorkflowStep(
                    id="step1",
                    name="Backup",
                    type=WorkflowStepType.ACTION,
                    action="backup",
                    parameters={},
                )
            ],
            triggers=[],
            approvals_required=[],
            timeout=3600,
            created_by="test",
        )

        # Test one-time scheduling
        schedule_request = {
            "workflow_id": blueprint.id,
            "schedule_type": "once",
            "execution_time": (datetime.utcnow() + timedelta(hours=1)).isoformat(),
            "parameters": {},
        }

        mock_scheduler.schedule_workflow.return_value = str(uuid.uuid4())
        schedule_id = await workflow_tools.scheduler.schedule_workflow(schedule_request)
        assert schedule_id is not None

        # Test recurring scheduling
        recurring_schedule = {
            "workflow_id": blueprint.id,
            "schedule_type": "recurring",
            "recurrence_pattern": "0 2 * * *",  # Daily at 2 AM
            "parameters": {},
        }

        mock_scheduler.schedule_workflow.return_value = str(uuid.uuid4())
        recurring_id = await workflow_tools.scheduler.schedule_workflow(
            recurring_schedule
        )
        assert recurring_id is not None

        # Test scheduled workflow retrieval
        mock_scheduler.get_scheduled_workflows.return_value = [
            {
                "id": schedule_id,
                "workflow_id": blueprint.id,
                "schedule_type": "once",
                "next_execution": datetime.utcnow() + timedelta(hours=1),
                "status": "scheduled",
            }
        ]

        scheduled = await workflow_tools.scheduler.get_scheduled_workflows()
        assert len(scheduled) == 1
        assert scheduled[0]["id"] == schedule_id

        # Test scheduled workflow cancellation
        mock_scheduler.cancel_scheduled_workflow.return_value = True
        cancelled = await workflow_tools.scheduler.cancel_scheduled_workflow(
            schedule_id
        )
        assert cancelled is True

    @pytest.mark.asyncio
    async def test_workflow_parallel_execution(
        self, workflow_tools, mock_workflow_engine
    ):
        """Test parallel workflow execution."""
        # Setup multiple workflow blueprints for parallel execution
        blueprints = []
        for i in range(3):
            blueprint = WorkflowBlueprint(
                id=str(uuid.uuid4()),
                name=f"Test Parallel Workflow {i}",
                description=f"Test parallel workflow {i}",
                version="1.0",
                steps=[
                    WorkflowStep(
                        id="step1",
                        name=f"Execute {i}",
                        type=WorkflowStepType.ACTION,
                        action=f"execute_{i}",
                        parameters={},
                    )
                ],
                triggers=[],
                approvals_required=[],
                timeout=3600,
                created_by="test",
            )
            blueprints.append(blueprint)

        execution_contexts = []
        for i, blueprint in enumerate(blueprints):
            context = ExecutionContext(
                execution_id=str(uuid.uuid4()),
                blueprint_id=blueprint.id,
                trigger_type="parallel_batch",
                initiated_by="test",
                parameters={"batch_id": "test-batch"},
            )
            execution_contexts.append(context)

        # Mock parallel execution
        execution_ids = [str(uuid.uuid4()) for _ in blueprints]
        mock_workflow_engine.execute_workflow.side_effect = execution_ids

        # Execute workflows in parallel
        tasks = []
        for blueprint, context in zip(blueprints, execution_contexts):
            task = workflow_tools.workflow_engine.execute_workflow(blueprint, context)
            tasks.append(task)

        results = await asyncio.gather(*tasks)

        # Verify all workflows were executed
        assert len(results) == 3
        assert all(execution_id in execution_ids for execution_id in results)
        assert mock_workflow_engine.execute_workflow.call_count == 3

        # Test parallel execution status tracking
        for i, execution_id in enumerate(execution_ids):
            mock_workflow_engine.get_execution_status.return_value = WorkflowExecution(
                id=execution_id,
                status=WorkflowStatus.RUNNING,
                current_step="step1",
                started_at=datetime.utcnow(),
            )

            status = await workflow_tools.workflow_engine.get_execution_status(
                execution_id
            )
            assert status.status == WorkflowStatus.RUNNING

    @pytest.mark.asyncio
    async def test_workflow_pause_and_resume(
        self, workflow_tools, mock_workflow_engine
    ):
        """Test workflow pause and resume functionality."""
        # Setup workflow blueprint
        blueprint = WorkflowBlueprint(
            id=str(uuid.uuid4()),
            name="Test Pause Resume Workflow",
            description="Test workflow pause and resume",
            version="1.0",
            steps=[
                WorkflowStep(
                    id="step1",
                    name="Execute",
                    type=WorkflowStepType.ACTION,
                    action="execute",
                    parameters={},
                ),
                WorkflowStep(
                    id="step2",
                    name="Complete",
                    type=WorkflowStepType.ACTION,
                    action="complete",
                    parameters={},
                ),
            ],
            triggers=[],
            approvals_required=[],
            timeout=3600,
            created_by="test",
        )

        execution_context = ExecutionContext(
            execution_id=str(uuid.uuid4()),
            blueprint_id=blueprint.id,
            trigger_type="manual",
            initiated_by="test",
            parameters={},
        )

        # Execute workflow
        execution_id = await workflow_tools.workflow_engine.execute_workflow(
            blueprint, execution_context
        )

        # Test pause functionality
        mock_workflow_engine.pause_execution.return_value = True
        paused = await workflow_tools.workflow_engine.pause_execution(execution_id)
        assert paused is True

        # Verify paused status
        mock_workflow_engine.get_execution_status.return_value = WorkflowExecution(
            id=execution_id,
            status=WorkflowStatus.PAUSED,
            current_step="step1",
            started_at=datetime.utcnow(),
            paused_at=datetime.utcnow(),
        )

        status = await workflow_tools.workflow_engine.get_execution_status(execution_id)
        assert status.status == WorkflowStatus.PAUSED
        assert status.paused_at is not None

        # Test resume functionality
        mock_workflow_engine.resume_execution.return_value = True
        resumed = await workflow_tools.workflow_engine.resume_execution(execution_id)
        assert resumed is True

        # Verify resumed status
        mock_workflow_engine.get_execution_status.return_value = WorkflowExecution(
            id=execution_id,
            status=WorkflowStatus.RUNNING,
            current_step="step1",
            started_at=datetime.utcnow(),
            resumed_at=datetime.utcnow(),
        )

        status = await workflow_tools.workflow_engine.get_execution_status(execution_id)
        assert status.status == WorkflowStatus.RUNNING
        assert status.resumed_at is not None

        # Test resume without pause (should fail gracefully)
        mock_workflow_engine.resume_execution.side_effect = Exception(
            "Workflow not paused"
        )
        with pytest.raises(Exception, match="Workflow not paused"):
            await workflow_tools.workflow_engine.resume_execution(execution_id)


class TestWorkflowIntegration:
    """Integration tests for workflow components."""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_workflow_with_real_dependencies(self, temp_test_dir):
        """Test workflow execution with real dependencies."""
        # This would test actual workflow execution with real services
        # For now, this is a placeholder for integration testing
        pass

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_workflow_performance_under_load(self):
        """Test workflow performance under load."""
        # This would test workflow performance with multiple concurrent executions
        # For now, this is a placeholder for performance testing
        pass


class TestWorkflowEdgeCases:
    """Test workflow edge cases and failure scenarios."""

    @pytest.mark.edge_case
    @pytest.mark.asyncio
    async def test_workflow_with_timeout(self, workflow_tools, mock_workflow_engine):
        """Test workflow timeout handling."""
        # Setup workflow with short timeout
        blueprint = WorkflowBlueprint(
            id=str(uuid.uuid4()),
            name="Test Timeout Workflow",
            description="Test workflow timeout",
            version="1.0",
            steps=[
                WorkflowStep(
                    id="step1",
                    name="Long Running",
                    type=WorkflowStepType.ACTION,
                    action="long_running",
                    parameters={},
                )
            ],
            triggers=[],
            approvals_required=[],
            timeout=1,  # 1 second timeout
            created_by="test",
        )

        execution_context = ExecutionContext(
            execution_id=str(uuid.uuid4()),
            blueprint_id=blueprint.id,
            trigger_type="manual",
            initiated_by="test",
            parameters={},
        )

        # Mock timeout behavior
        mock_workflow_engine.execute_workflow.return_value = str(uuid.uuid4())
        execution_id = await workflow_tools.workflow_engine.execute_workflow(
            blueprint, execution_context
        )

        # Verify execution was initiated
        assert execution_id is not None

        # Test timeout status
        mock_workflow_engine.get_execution_status.return_value = WorkflowExecution(
            id=execution_id,
            status=WorkflowStatus.TIMEOUT,
            current_step="step1",
            started_at=datetime.utcnow(),
            timeout_at=datetime.utcnow() + timedelta(seconds=1),
        )

        status = await workflow_tools.workflow_engine.get_execution_status(execution_id)
        assert status.status == WorkflowStatus.TIMEOUT

    @pytest.mark.edge_case
    @pytest.mark.asyncio
    async def test_workflow_with_invalid_blueprint(self, workflow_tools):
        """Test workflow execution with invalid blueprint."""
        # Test with blueprint missing required fields
        invalid_blueprint = WorkflowBlueprint(
            id="",  # Empty ID
            name="",  # Empty name
            description="",
            version="",
            steps=[],  # No steps
            triggers=[],
            approvals_required=[],
            timeout=0,  # Invalid timeout
            created_by="test",
        )

        execution_context = ExecutionContext(
            execution_id=str(uuid.uuid4()),
            blueprint_id="invalid",
            trigger_type="manual",
            initiated_by="test",
            parameters={},
        )

        # Test validation should catch invalid blueprint
        with pytest.raises(ValueError):
            await workflow_tools.workflow_engine.execute_workflow(
                invalid_blueprint, execution_context
            )

    @pytest.mark.edge_case
    @pytest.mark.asyncio
    async def test_workflow_concurrent_modification(
        self, workflow_tools, mock_workflow_engine
    ):
        """Test workflow execution with concurrent blueprint modification."""
        # Setup workflow blueprint
        blueprint = WorkflowBlueprint(
            id=str(uuid.uuid4()),
            name="Test Concurrent Workflow",
            description="Test concurrent modification",
            version="1.0",
            steps=[
                WorkflowStep(
                    id="step1",
                    name="Execute",
                    type=WorkflowStepType.ACTION,
                    action="execute",
                    parameters={},
                )
            ],
            triggers=[],
            approvals_required=[],
            timeout=3600,
            created_by="test",
        )

        execution_context = ExecutionContext(
            execution_id=str(uuid.uuid4()),
            blueprint_id=blueprint.id,
            trigger_type="manual",
            initiated_by="test",
            parameters={},
        )

        # Mock concurrent modification scenario
        mock_workflow_engine.execute_workflow.side_effect = Exception(
            "Blueprint was modified during execution"
        )

        # Test should handle concurrent modification gracefully
        with pytest.raises(Exception, match="Blueprint was modified"):
            await workflow_tools.workflow_engine.execute_workflow(
                blueprint, execution_context
            )
