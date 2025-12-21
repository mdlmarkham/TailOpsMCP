"""
Workflow Execution Engine for TailOpsMCP.

Provides robust workflow execution with rollback capabilities, integration
with existing systems, and comprehensive error handling.
"""

import asyncio
import logging
import traceback
import uuid
from types import SimpleNamespace
from datetime import datetime
from datetime import timezone, timezone, timezone, timezone
from typing import Any, Dict, List, Optional, cast

from src.models.event_models import (
    EventCategory,
    EventSeverity,
    EventSource,
    EventType,
    SystemEvent,
)
from src.models.workflow_models import (
    ApprovalRecord,
    ApprovalStatus,
    ExecutionStatus,
    Parameter,
    RollbackAction,
    StepResult,
    StepType,
    ValidationResult,
    WorkflowBlueprint,
    WorkflowExecution,
    WorkflowMetrics,
    WorkflowStep,
)
from src.services.capability_executor import CapabilityExecutor
from src.services.event_collector import EventCollector
from src.services.policy_engine import PolicyEngine
from src.utils.audit import AuditLogger
from src.utils.errors import ErrorCategory, SystemManagerError

logger = logging.getLogger(__name__)


class WorkflowExecutionError(SystemManagerError):
    """Workflow execution error."""

    def __init__(
        self,
        message: str,
        step_id: Optional[str] = None,
        execution_id: Optional[str] = None,
    ):
        super().__init__(message, ErrorCategory.EXECUTION)
        self.step_id = step_id
        self.execution_id = execution_id


class WorkflowValidationError(WorkflowExecutionError):
    """Workflow validation error."""

    pass


class WorkflowStepError(WorkflowExecutionError):
    """Workflow step execution error."""

    def __init__(
        self,
        message: str,
        step_id: str,
        execution_id: str,
        original_error: Optional[Exception] = None,
    ):
        super().__init__(message, step_id, execution_id)
        self.original_error = original_error


class WorkflowEngine:
    """Execute workflows with proper orchestration."""

    def __init__(
        self,
        capability_executor: CapabilityExecutor,
        event_collector: EventCollector,
        policy_engine: PolicyEngine,
    ):
        """Initialize workflow engine."""
        self.capability_executor = capability_executor
        self.event_collector = event_collector
        self.policy_engine = policy_engine
        self.audit_logger = AuditLogger()
        self._execution_tasks: Dict[str, asyncio.Task] = {}
        self._blueprint_cache: Dict[str, WorkflowBlueprint] = {}

    async def execute_workflow(
        self,
        blueprint: WorkflowBlueprint,
        parameters: Dict[str, Any],
        created_by: str = "",
        approvals: Optional[Dict[str, str]] = None,
    ) -> WorkflowExecution:
        """Execute a workflow blueprint."""
        execution_id = str(uuid.uuid4())

        try:
            # Validate workflow
            validation_result = await self.validate_workflow_prerequisites(
                blueprint, parameters
            )
            if not validation_result.valid:
                raise WorkflowValidationError(
                    f"Workflow validation failed: {'; '.join(validation_result.errors)}"
                )

            # Check policy permissions
            policy_validation = await self._validate_workflow_policies(
                blueprint, created_by
            )
            if not policy_validation:
                raise WorkflowExecutionError(
                    f"Policy validation failed for user {created_by}"
                )

            # Create execution instance
            execution = WorkflowExecution(
                execution_id=execution_id,
                blueprint_id=blueprint.name,
                blueprint_name=blueprint.name,
                parameters=parameters,
                status=ExecutionStatus.PENDING,
                created_by=created_by,
                context={"created_by": created_by},
            )

            # Handle approvals
            if approvals:
                await self._apply_approvals(execution, approvals)

            # Start execution
            execution.status = ExecutionStatus.RUNNING
            execution.start_time = datetime.now(timezone.utc)

            # Emit event
            await self._emit_workflow_event(
                execution,
                "workflow_started",
                {"blueprint_name": blueprint.name, "created_by": created_by},
            )

            # Start execution task
            task = asyncio.create_task(
                self._execute_workflow_async(execution, blueprint)
            )
            self._execution_tasks[execution_id] = task

            return execution

        except Exception as e:
            logger.error(f"Failed to start workflow execution {execution_id}: {e}")
            await self._emit_workflow_event(
                execution if "execution" in locals() else None,
                "workflow_start_failed",
                {"error": str(e), "blueprint_name": blueprint.name},
            )
            raise

    async def validate_workflow_prerequisites(
        self, blueprint: WorkflowBlueprint, parameters: Dict[str, Any]
    ) -> ValidationResult:
        """Validate workflow prerequisites."""
        errors: List[str] = []
        warnings: List[str] = []

        # Validate blueprint structure
        blueprint_errors = blueprint.validate()
        errors.extend(blueprint_errors)

        # Validate parameters
        for param_name, param_def in blueprint.parameters.items():
            if param_name not in parameters:
                if param_def.required:
                    errors.append(f"Required parameter '{param_name}' is missing")
                elif param_def.default is not None:
                    parameters[param_name] = param_def.default

            # Validate parameter value
            if param_name in parameters:
                value = parameters[param_name]
                param_errors = self._validate_parameter(param_def, value)
                errors.extend(param_errors)

        # Check prerequisites
        for prereq in blueprint.prerequisites:
            try:
                if prereq.required:
                    prereq.check_function()
            except Exception as e:
                errors.append(f"Prerequisite '{prereq.name}' failed: {str(e)}")

        return ValidationResult(
            valid=len(errors) == 0, errors=errors, warnings=warnings
        )

    async def execute_workflow_step(
        self, execution: WorkflowExecution, step: WorkflowStep
    ) -> StepResult:
        """Execute individual workflow step."""
        step_id = step.step_id
        start_time = datetime.now(timezone.utc)

        try:
            # Update execution status
            execution.current_step = step_id

            # Emit step started event
            await self._emit_workflow_event(
                execution, "step_started", {"step_id": step_id, "step_name": step.name}
            )

            # Validate preconditions
            await self._validate_step_preconditions(execution, step)

            # Check if approval is required
            if step.requires_approval:
                approval_status = await self._check_step_approval(execution, step)
                if approval_status != ApprovalStatus.APPROVED:
                    execution.status = ExecutionStatus.WAITING_APPROVAL
                    await self._emit_workflow_event(
                        execution,
                        "step_waiting_approval",
                        {"step_id": step_id, "step_name": step.name},
                    )
                    raise WorkflowExecutionError(f"Step {step_id} requires approval")

            # Execute step with retries
            result = await self._execute_step_with_retry(execution, step)

            # Update execution
            execution.step_results[step_id] = result

            if not result.success:
                execution.status = ExecutionStatus.FAILED
                await self._emit_workflow_event(
                    execution,
                    "step_failed",
                    {
                        "step_id": step_id,
                        "step_name": step.name,
                        "error": result.message,
                    },
                )
                raise WorkflowStepError(
                    f"Step {step_id} failed: {result.message}",
                    step_id,
                    execution.execution_id,
                )

            # Mark step as completed
            result.completed_at = datetime.now(timezone.utc)
            result.execution_time = result.completed_at - start_time

            await self._emit_workflow_event(
                execution,
                "step_completed",
                {
                    "step_id": step_id,
                    "step_name": step.name,
                    "execution_time": result.execution_time.total_seconds(),
                },
            )

            return result

        except Exception as e:
            # Handle step execution error
            execution.status = ExecutionStatus.FAILED

            result = StepResult(
                step_id=step_id,
                success=False,
                message=str(e),
                started_at=start_time,
                completed_at=datetime.now(timezone.utc),
                execution_time=datetime.now(timezone.utc) - start_time,
            )

            execution.step_results[step_id] = result

            await self._emit_workflow_event(
                execution,
                "step_error",
                {"step_id": step_id, "step_name": step.name, "error": str(e)},
            )

            logger.error(f"Step {step_id} execution failed: {e}")
            logger.error(traceback.format_exc())

            return result

    async def handle_workflow_failure(
        self, execution: WorkflowExecution, step: WorkflowStep, error: Exception
    ) -> bool:
        """Handle workflow failure with rollback if needed."""
        try:
            # Check if rollback should be executed
            if not execution.blueprint_id or not execution.context.get(
                "rollback_enabled", True
            ):
                return False

            # Load blueprint to check rollback plan
            blueprint = await self._get_blueprint(execution.blueprint_id)
            if (
                not blueprint
                or not blueprint.rollback_plan
                or not blueprint.rollback_plan.enabled
            ):
                return False

            # Start rollback
            execution.status = ExecutionStatus.ROLLING_BACK
            execution.rollback_executed = True

            await self._emit_workflow_event(
                execution,
                "rollback_started",
                {"failed_step": step.step_id, "error": str(error)},
            )

            # Execute rollback actions in reverse order
            for rollback_action in reversed(blueprint.rollback_plan.actions):
                try:
                    await self._execute_rollback_action(execution, rollback_action)
                except Exception as rollback_error:
                    logger.error(
                        f"Rollback action {rollback_action.action_id} failed: {rollback_error}"
                    )

            execution.status = ExecutionStatus.ROLLED_BACK
            execution.end_time = datetime.now(timezone.utc)

            await self._emit_workflow_event(
                execution, "rollback_completed", {"failed_step": step.step_id}
            )

            return True

        except Exception as e:
            logger.error(f"Rollback handling failed: {e}")
            return False

    async def pause_workflow(self, execution_id: str) -> bool:
        """Pause workflow for manual intervention."""
        if execution_id not in self._execution_tasks:
            return False

        task = self._execution_tasks[execution_id]
        if task.done():
            return False

        # Find execution instance
        execution = await self._get_execution(execution_id)
        if execution:
            execution.status = ExecutionStatus.PAUSED
            await self._emit_workflow_event(execution, "workflow_paused", {})

        return True

    async def resume_workflow(self, execution_id: str) -> bool:
        """Resume paused workflow."""
        if execution_id not in self._execution_tasks:
            return False

        task = self._execution_tasks[execution_id]
        if task.done():
            return False

        # Find execution instance
        execution = await self._get_execution(execution_id)
        if execution and execution.status == ExecutionStatus.PAUSED:
            execution.status = ExecutionStatus.RUNNING
            await self._emit_workflow_event(execution, "workflow_resumed", {})
            return True

        return False

    async def cancel_workflow(self, execution_id: str, reason: str = "") -> bool:
        """Cancel workflow execution."""
        if execution_id in self._execution_tasks:
            task = self._execution_tasks[execution_id]
            task.cancel()
            del self._execution_tasks[execution_id]

        # Find execution instance
        execution = await self._get_execution(execution_id)
        if execution:
            execution.status = ExecutionStatus.CANCELLED
            execution.end_time = datetime.now(timezone.utc)
            await self._emit_workflow_event(
                execution, "workflow_cancelled", {"reason": reason}
            )

        return True

    async def get_workflow_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get status of workflow execution."""
        execution = await self._get_execution(execution_id)
        return execution.to_dict() if execution else None

    async def get_workflow_metrics(
        self, execution_id: str
    ) -> Optional[WorkflowMetrics]:
        """Get workflow execution metrics."""
        execution = await self._get_execution(execution_id)
        if not execution:
            return None

        return WorkflowMetrics(
            execution_id=execution_id,
            blueprint_name=execution.blueprint_name,
            start_time=execution.start_time,
            end_time=execution.end_time,
            status=execution.status,
            total_steps=len(
                execution.blueprint_id
            ),  # This would need to be loaded from blueprint
            completed_steps=len(execution.get_completed_steps()),
            failed_steps=len(execution.get_failed_steps()),
            total_execution_time=execution.get_total_execution_time()
            if execution.end_time
            else None,
            approval_count=len(execution.approvals),
            rollback_count=1 if execution.rollback_executed else 0,
        )

    async def _execute_workflow_async(
        self, execution: WorkflowExecution, blueprint: WorkflowBlueprint
    ) -> None:
        """Internal workflow execution coroutine."""
        try:
            # Execute steps in dependency order
            completed_steps: set[str] = set()

            while len(completed_steps) < len(blueprint.steps):
                # Find next executable steps
                executable_steps = []
                for step in blueprint.steps:
                    if step.step_id not in completed_steps:
                        # Check if dependencies are satisfied
                        if all(dep in completed_steps for dep in step.dependencies):
                            executable_steps.append(step)

                if not executable_steps:
                    # No executable steps found - check for failed steps
                    failed_steps = set(execution.get_failed_steps())
                    if failed_steps:
                        # Workflow failed
                        execution.status = ExecutionStatus.FAILED
                        execution.end_time = datetime.now(timezone.utc)
                        await self._emit_workflow_event(
                            execution,
                            "workflow_failed",
                            {"failed_steps": list(failed_steps)},
                        )
                        break
                    else:
                        # Deadlock - no steps can execute
                        raise WorkflowExecutionError(
                            "Workflow deadlock detected - no executable steps found"
                        )

                # Execute executable steps
                for step in executable_steps:
                    try:
                        result = await self.execute_workflow_step(execution, step)
                        if result.success:
                            completed_steps.add(step.step_id)
                        else:
                            # Step failed - handle rollback
                            await self.handle_workflow_failure(
                                execution, step, Exception(result.message)
                            )
                            return
                    except WorkflowExecutionError:
                        # Re-raise workflow execution errors
                        raise
                    except Exception as e:
                        # Handle unexpected errors
                        await self.handle_workflow_failure(execution, step, e)
                        return

            # All steps completed successfully
            execution.status = ExecutionStatus.COMPLETED
            execution.end_time = datetime.now(timezone.utc)
            await self._emit_workflow_event(execution, "workflow_completed", {})

        except Exception as e:
            logger.error(f"Workflow execution failed: {e}")
            execution.status = ExecutionStatus.FAILED
            execution.end_time = datetime.now(timezone.utc)
            await self._emit_workflow_event(
                execution, "workflow_error", {"error": str(e)}
            )
        finally:
            # Clean up execution task
            if execution.execution_id in self._execution_tasks:
                del self._execution_tasks[execution.execution_id]

    async def _execute_step_with_retry(
        self, execution: WorkflowExecution, step: WorkflowStep
    ) -> StepResult:
        """Execute step with retry policy."""
        retry_policy = step.retry_policy
        max_attempts = retry_policy.max_attempts
        attempt = 0

        while attempt < max_attempts:
            try:
                result = await self._execute_step_implementation(execution, step)
                result.retry_count = attempt
                return result
            except Exception as e:
                attempt += 1
                if attempt >= max_attempts:
                    # Max retries reached
                    return StepResult(
                        step_id=step.step_id,
                        success=False,
                        message=f"Step failed after {max_attempts} attempts: {str(e)}",
                        retry_count=attempt,
                    )

                # Wait before retry
                delay = min(
                    retry_policy.initial_delay.total_seconds()
                    * (retry_policy.backoff_factor ** (attempt - 1)),
                    retry_policy.max_delay.total_seconds(),
                )

                await asyncio.sleep(delay)

        # Should not reach here
        return StepResult(
            step_id=step.step_id, success=False, message="Max retry attempts reached"
        )

    async def _execute_step_implementation(
        self, execution: WorkflowExecution, step: WorkflowStep
    ) -> StepResult:
        """Execute the actual step implementation."""
        start_time = datetime.now(timezone.utc)

        try:
            # Map step types to execution functions
            step_handlers: Dict[StepType, Any] = {
                StepType.VALIDATION: self._handle_validation_step,
                StepType.RESOURCE_ALLOCATION: self._handle_resource_allocation_step,
                StepType.CONTAINER_OPERATIONS: self._handle_container_operations_step,
                StepType.SERVICE_DEPLOYMENT: self._handle_service_deployment_step,
                StepType.NETWORK_CONFIGURATION: self._handle_network_configuration_step,
                StepType.HEALTH_VALIDATION: self._handle_health_validation_step,
                StepType.BACKUP: self._handle_backup_step,
                StepType.RESTORE: self._handle_restore_step,
                StepType.SNAPSHOT: self._handle_snapshot_step,
                StepType.UPGRADE: self._handle_upgrade_step,
                StepType.TESTING: self._handle_testing_step,
                StepType.CONFIGURATION: self._handle_configuration_step,
                StepType.DISCOVERY: self._handle_discovery_step,
                StepType.TRANSFER: self._handle_transfer_step,
                StepType.MAINTENANCE: self._handle_maintenance_step,
            }

            handler = step_handlers.get(step.step_type)
            if not handler:
                raise WorkflowExecutionError(
                    f"No handler found for step type: {step.step_type}"
                )

            result = await handler(execution, step)
            result.step_id = step.step_id
            result.started_at = start_time
            result.completed_at = datetime.now(timezone.utc)
            result.execution_time = result.completed_at - start_time

            return result

        except Exception as e:
            return StepResult(
                step_id=step.step_id,
                success=False,
                message=str(e),
                started_at=start_time,
                completed_at=datetime.now(timezone.utc),
                execution_time=datetime.now(timezone.utc) - start_time,
            )

    async def _handle_validation_step(
        self, execution: WorkflowExecution, step: WorkflowStep
    ) -> StepResult:
        """Handle validation step execution."""
        try:
            # Use capability executor for validation
            # capability_executor provides execute_operation(Operation) interface
            # Build a minimal CapabilityOperation-like object if needed
            try:
                validation_result = await self.capability_executor.validate_operation(
                    operation_type="validate_workflow_step",
                    parameters={
                        "step_id": step.step_id,
                        "step_type": step.step_type.value,
                        "parameters": step.parameters,
                        "execution_context": execution.context,
                    },
                )
            except AttributeError:
                # Fallback to execute_operation signature
                from types import SimpleNamespace

                op = SimpleNamespace()
                op.capability = None
                op.parameters = {
                    "step_id": step.step_id,
                    "step_type": step.step_type.value,
                    "parameters": step.parameters,
                    "execution_context": execution.context,
                }
                validation_result = await self.capability_executor.execute_operation(
                    cast(Any, op)
                )

            if validation_result.success:
                return StepResult(
                    step_id=step.step_id,
                    success=True,
                    message="Validation completed successfully",
                    data=validation_result.data,
                )
            else:
                return StepResult(
                    step_id=step.step_id,
                    success=False,
                    message=f"Validation failed: {validation_result.message}",
                )
        except Exception as e:
            return StepResult(
                step_id=step.step_id,
                success=False,
                message=f"Validation error: {str(e)}",
            )

    async def _handle_resource_allocation_step(
        self, execution: WorkflowExecution, step: WorkflowStep
    ) -> StepResult:
        """Handle resource allocation step execution."""
        try:
            # Validate resource allocation parameters
            required_params = ["resource_type", "quantity"]
            for param in required_params:
                if param not in step.parameters:
                    return StepResult(
                        step_id=step.step_id,
                        success=False,
                        message=f"Missing required parameter: {param}",
                    )

            # Use capability executor for resource allocation
            from types import SimpleNamespace

            op = SimpleNamespace()
            op.capability = "allocate_resources"
            op.parameters = {
                **step.parameters,
                "execution_id": execution.execution_id,
                "workflow_name": execution.blueprint_name,
            }
            allocation_result = await self.capability_executor.execute_operation(
                cast(Any, op)
            )

            return StepResult(
                step_id=step.step_id,
                success=allocation_result.success,
                message=allocation_result.message,
                data=allocation_result.data,
            )
        except Exception as e:
            return StepResult(
                step_id=step.step_id,
                success=False,
                message=f"Resource allocation error: {str(e)}",
            )

    async def _handle_container_operations_step(
        self, execution: WorkflowExecution, step: WorkflowStep
    ) -> StepResult:
        """Handle container operations step execution."""
        try:
            # Use capability executor for container operations
            op = SimpleNamespace()
            op.capability = "container_operations"
            op.parameters = {
                **step.parameters,
                "execution_id": execution.execution_id,
                "workflow_name": execution.blueprint_name,
            }
            operation_result = await self.capability_executor.execute_operation(
                cast(Any, op)
            )

            return StepResult(
                step_id=step.step_id,
                success=operation_result.success,
                message=operation_result.message,
                data=operation_result.data,
            )
        except Exception as e:
            return StepResult(
                step_id=step.step_id,
                success=False,
                message=f"Container operations error: {str(e)}",
            )

    async def _handle_service_deployment_step(
        self, execution: WorkflowExecution, step: WorkflowStep
    ) -> StepResult:
        """Handle service deployment step execution."""
        try:
            # Use capability executor for service deployment
            op = SimpleNamespace()
            op.capability = "service_deployment"
            op.parameters = {
                **step.parameters,
                "execution_id": execution.execution_id,
                "workflow_name": execution.blueprint_name,
            }
            deployment_result = await self.capability_executor.execute_operation(
                cast(Any, op)
            )

            return StepResult(
                step_id=step.step_id,
                success=deployment_result.success,
                message=deployment_result.message,
                data=deployment_result.data,
            )
        except Exception as e:
            return StepResult(
                step_id=step.step_id,
                success=False,
                message=f"Service deployment error: {str(e)}",
            )

    async def _handle_network_configuration_step(
        self, execution: WorkflowExecution, step: WorkflowStep
    ) -> StepResult:
        """Handle network configuration step execution."""
        try:
            # Use capability executor for network configuration
            from types import SimpleNamespace

            op = SimpleNamespace()
            op.capability = "network_configuration"
            op.parameters = {
                **step.parameters,
                "execution_id": execution.execution_id,
                "workflow_name": execution.blueprint_name,
            }
            network_result = await self.capability_executor.execute_operation(
                cast(Any, op)
            )

            return StepResult(
                step_id=step.step_id,
                success=network_result.success,
                message=network_result.message,
                data=network_result.data,
            )
        except Exception as e:
            return StepResult(
                step_id=step.step_id,
                success=False,
                message=f"Network configuration error: {str(e)}",
            )

    async def _handle_health_validation_step(
        self, execution: WorkflowExecution, step: WorkflowStep
    ) -> StepResult:
        """Handle health validation step execution."""
        try:
            # Use capability executor for health validation
            from types import SimpleNamespace

            op = SimpleNamespace()
            op.capability = "health_validation"
            op.parameters = {
                **step.parameters,
                "execution_id": execution.execution_id,
                "workflow_name": execution.blueprint_name,
            }
            health_result = await self.capability_executor.execute_operation(
                cast(Any, op)
            )

            return StepResult(
                step_id=step.step_id,
                success=health_result.success,
                message=health_result.message,
                data=health_result.data,
            )
        except Exception as e:
            return StepResult(
                step_id=step.step_id,
                success=False,
                message=f"Health validation error: {str(e)}",
            )

    async def _handle_backup_step(
        self, execution: WorkflowExecution, step: WorkflowStep
    ) -> StepResult:
        """Handle backup step execution."""
        try:
            # Use capability executor for backup operations
            from types import SimpleNamespace

            op = SimpleNamespace()
            op.capability = "backup_operations"
            op.parameters = {
                **step.parameters,
                "execution_id": execution.execution_id,
                "workflow_name": execution.blueprint_name,
            }
            backup_result = await self.capability_executor.execute_operation(
                cast(Any, op)
            )

            return StepResult(
                step_id=step.step_id,
                success=backup_result.success,
                message=backup_result.message,
                data=backup_result.data,
            )
        except Exception as e:
            return StepResult(
                step_id=step.step_id, success=False, message=f"Backup error: {str(e)}"
            )

    async def _handle_restore_step(
        self, execution: WorkflowExecution, step: WorkflowStep
    ) -> StepResult:
        """Handle restore step execution."""
        try:
            # Use capability executor for restore operations
            from types import SimpleNamespace

            op = SimpleNamespace()
            op.capability = "restore_operations"
            op.parameters = {
                **step.parameters,
                "execution_id": execution.execution_id,
                "workflow_name": execution.blueprint_name,
            }
            restore_result = await self.capability_executor.execute_operation(
                cast(Any, op)
            )

            return StepResult(
                step_id=step.step_id,
                success=restore_result.success,
                message=restore_result.message,
                data=restore_result.data,
            )
        except Exception as e:
            return StepResult(
                step_id=step.step_id, success=False, message=f"Restore error: {str(e)}"
            )

    async def _handle_snapshot_step(
        self, execution: WorkflowExecution, step: WorkflowStep
    ) -> StepResult:
        """Handle snapshot step execution."""
        try:
            # Use capability executor for snapshot operations
            from types import SimpleNamespace

            op = SimpleNamespace()
            op.capability = "snapshot_operations"
            op.parameters = {
                **step.parameters,
                "execution_id": execution.execution_id,
                "workflow_name": execution.blueprint_name,
            }
            snapshot_result = await self.capability_executor.execute_operation(
                cast(Any, op)
            )

            return StepResult(
                step_id=step.step_id,
                success=snapshot_result.success,
                message=snapshot_result.message,
                data=snapshot_result.data,
            )
        except Exception as e:
            return StepResult(
                step_id=step.step_id, success=False, message=f"Snapshot error: {str(e)}"
            )

    async def _handle_upgrade_step(
        self, execution: WorkflowExecution, step: WorkflowStep
    ) -> StepResult:
        """Handle upgrade step execution."""
        try:
            # Use capability executor for upgrade operations
            from types import SimpleNamespace

            op = SimpleNamespace()
            op.capability = "upgrade_operations"
            op.parameters = {
                **step.parameters,
                "execution_id": execution.execution_id,
                "workflow_name": execution.blueprint_name,
            }
            upgrade_result = await self.capability_executor.execute_operation(
                cast(Any, op)
            )

            return StepResult(
                step_id=step.step_id,
                success=upgrade_result.success,
                message=upgrade_result.message,
                data=upgrade_result.data,
            )
        except Exception as e:
            return StepResult(
                step_id=step.step_id, success=False, message=f"Upgrade error: {str(e)}"
            )

    async def _handle_testing_step(
        self, execution: WorkflowExecution, step: WorkflowStep
    ) -> StepResult:
        """Handle testing step execution."""
        try:
            # Use capability executor for testing operations
            from types import SimpleNamespace

            op = SimpleNamespace()
            op.capability = "testing_operations"
            op.parameters = {
                **step.parameters,
                "execution_id": execution.execution_id,
                "workflow_name": execution.blueprint_name,
            }
            test_result = await self.capability_executor.execute_operation(
                cast(Any, op)
            )

            return StepResult(
                step_id=step.step_id,
                success=test_result.success,
                message=test_result.message,
                data=test_result.data,
            )
        except Exception as e:
            return StepResult(
                step_id=step.step_id, success=False, message=f"Testing error: {str(e)}"
            )

    async def _handle_configuration_step(
        self, execution: WorkflowExecution, step: WorkflowStep
    ) -> StepResult:
        """Handle configuration step execution."""
        try:
            # Use capability executor for configuration operations
            from types import SimpleNamespace

            op = SimpleNamespace()
            op.capability = "configuration_operations"
            op.parameters = {
                **step.parameters,
                "execution_id": execution.execution_id,
                "workflow_name": execution.blueprint_name,
            }
            config_result = await self.capability_executor.execute_operation(
                cast(Any, op)
            )

            return StepResult(
                step_id=step.step_id,
                success=config_result.success,
                message=config_result.message,
                data=config_result.data,
            )
        except Exception as e:
            return StepResult(
                step_id=step.step_id,
                success=False,
                message=f"Configuration error: {str(e)}",
            )

    async def _handle_discovery_step(
        self, execution: WorkflowExecution, step: WorkflowStep
    ) -> StepResult:
        """Handle discovery step execution."""
        try:
            # Use capability executor for discovery operations
            from types import SimpleNamespace

            op = SimpleNamespace()
            op.capability = "discovery_operations"
            op.parameters = {
                **step.parameters,
                "execution_id": execution.execution_id,
                "workflow_name": execution.blueprint_name,
            }
            discovery_result = await self.capability_executor.execute_operation(
                cast(Any, op)
            )

            return StepResult(
                step_id=step.step_id,
                success=discovery_result.success,
                message=discovery_result.message,
                data=discovery_result.data,
            )
        except Exception as e:
            return StepResult(
                step_id=step.step_id,
                success=False,
                message=f"Discovery error: {str(e)}",
            )

    async def _handle_transfer_step(
        self, execution: WorkflowExecution, step: WorkflowStep
    ) -> StepResult:
        """Handle transfer step execution."""
        try:
            # Use capability executor for transfer operations
            from types import SimpleNamespace

            op = SimpleNamespace()
            op.capability = "transfer_operations"
            op.parameters = {
                **step.parameters,
                "execution_id": execution.execution_id,
                "workflow_name": execution.blueprint_name,
            }
            transfer_result = await self.capability_executor.execute_operation(
                cast(Any, op)
            )

            return StepResult(
                step_id=step.step_id,
                success=transfer_result.success,
                message=transfer_result.message,
                data=transfer_result.data,
            )
        except Exception as e:
            return StepResult(
                step_id=step.step_id, success=False, message=f"Transfer error: {str(e)}"
            )

    async def _handle_maintenance_step(
        self, execution: WorkflowExecution, step: WorkflowStep
    ) -> StepResult:
        """Handle maintenance step execution."""
        try:
            from types import SimpleNamespace

            op = SimpleNamespace()
            op.capability = "maintenance_operations"
            op.parameters = {
                **step.parameters,
                "execution_id": execution.execution_id,
                "workflow_name": execution.blueprint_name,
            }
            maintenance_result = await self.capability_executor.execute_operation(
                cast(Any, op)
            )

            return StepResult(
                step_id=step.step_id,
                success=maintenance_result.success,
                message=maintenance_result.message,
                data=maintenance_result.data,
            )
        except Exception as e:
            return StepResult(
                step_id=step.step_id,
                success=False,
                message=f"Maintenance error: {str(e)}",
            )

    async def _execute_rollback_action(
        self, execution: WorkflowExecution, rollback_action: RollbackAction
    ):
        """Execute rollback action."""
        try:
            from types import SimpleNamespace

            op = SimpleNamespace()
            op.capability = "rollback_operations"
            op.parameters = {
                **rollback_action.parameters,
                "execution_id": execution.execution_id,
                "workflow_name": execution.blueprint_name,
                "action_id": rollback_action.action_id,
            }
            rollback_result = await self.capability_executor.execute_operation(
                cast(Any, op)
            )

            if not rollback_result.success:
                logger.warning(
                    f"Rollback action {rollback_action.action_id} reported failure: {rollback_result.message}"
                )

        except Exception as e:
            logger.error(f"Rollback action {rollback_action.action_id} failed: {e}")
            raise

    def _validate_parameter(self, param_def: Parameter, value: Any) -> List[str]:
        """Validate parameter against definition."""
        errors = []

        # Type validation
        if param_def.type == "string" and not isinstance(value, str):
            errors.append("Parameter must be a string")
        elif param_def.type == "integer" and not isinstance(value, int):
            errors.append("Parameter must be an integer")
        elif param_def.type == "boolean" and not isinstance(value, bool):
            errors.append("Parameter must be a boolean")
        elif param_def.type == "list" and not isinstance(value, list):
            errors.append("Parameter must be a list")
        elif param_def.type == "dict" and not isinstance(value, dict):
            errors.append("Parameter must be a dictionary")

        # Choices validation
        if param_def.choices and value not in param_def.choices:
            errors.append(f"Value must be one of: {param_def.choices}")

        # Custom validation
        if param_def.validation:
            pattern = param_def.validation.get("pattern")
            if pattern and isinstance(value, str):
                import re

                if not re.match(pattern, value):
                    errors.append(f"Value does not match required pattern: {pattern}")

        return errors

    async def _validate_step_preconditions(
        self, execution: WorkflowExecution, step: WorkflowStep
    ):
        """Validate step preconditions."""
        for precondition in step.preconditions:
            # Check if precondition is satisfied
            if precondition not in execution.get_completed_steps():
                raise WorkflowExecutionError(
                    f"Precondition '{precondition}' not satisfied"
                )

    async def _check_step_approval(
        self, execution: WorkflowExecution, step: WorkflowStep
    ) -> ApprovalStatus:
        """Check if step has required approval."""
        # Find approval record for this step
        for approval in execution.approvals:
            if (
                approval.step_id == step.step_id
                and approval.status == ApprovalStatus.APPROVED
            ):
                return ApprovalStatus.APPROVED

        return ApprovalStatus.PENDING

    async def _apply_approvals(
        self, execution: WorkflowExecution, approvals: Dict[str, str]
    ):
        """Apply pre-approved steps."""
        for step_id, approver in approvals.items():
            approval = ApprovalRecord(
                approval_id=str(uuid.uuid4()),
                step_id=step_id,
                approver=approver,
                status=ApprovalStatus.APPROVED,
                comment="Pre-approved via workflow execution",
            )
            execution.approvals.append(approval)

    async def _validate_workflow_policies(
        self, blueprint: WorkflowBlueprint, user: str
    ) -> bool:
        """Validate workflow against policies."""
        try:
            # This would integrate with the policy engine
            # For now, return True as a placeholder
            return True
        except Exception as e:
            logger.error(f"Policy validation failed: {e}")
            return False

    async def _emit_workflow_event(
        self,
        execution: Optional[WorkflowExecution],
        event_type: str,
        details: Dict[str, Any],
    ):
        """Emit workflow event."""
        try:
            if not execution:
                return

            event = SystemEvent(
                event_id=str(uuid.uuid4()),
                event_type=EventType.WORKFLOW,
                severity=EventSeverity.INFO,
                source=EventSource.WORKFLOW_ENGINE,
                category=EventCategory.WORKFLOW,
                timestamp=datetime.now(timezone.utc),
                data={
                    "execution_id": execution.execution_id,
                    "blueprint_name": execution.blueprint_name,
                    "event_type": event_type,
                    "details": details,
                },
            )

            await self.event_collector.collect_event(event)
        except Exception as e:
            logger.error(f"Failed to emit workflow event: {e}")

    async def _get_blueprint(self, blueprint_id: str) -> Optional[WorkflowBlueprint]:
        """Get workflow blueprint from cache or database."""
        if blueprint_id in self._blueprint_cache:
            return self._blueprint_cache[blueprint_id]

        # This would load from database
        # For now, return None as placeholder
        return None

    async def _get_execution(self, execution_id: str) -> Optional[WorkflowExecution]:
        """Get execution from cache or database."""
        # This would load from database
        # For now, return None as placeholder
        return None
