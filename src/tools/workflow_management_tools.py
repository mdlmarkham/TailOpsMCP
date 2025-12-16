"""
Workflow Management Tools for TailOpsMCP.

Provides comprehensive MCP tools for managing workflow blueprints,
executing workflows, monitoring execution, and handling approvals.
"""

import logging
from typing import Dict, Optional, Any

from fastmcp import FastMCP
from src.auth.middleware import secure_tool
from src.services.workflow_engine import WorkflowEngine
from src.services.workflow_scheduler import WorkflowScheduler, ScheduleManager
from src.services.workflow_approval import ApprovalSystem, WorkflowGovernance
from src.services.workflow_blueprints import (
    EnvironmentProvisioningWorkflow,
    BackupOrchestrationWorkflow,
    SafeUpgradeWorkflow,
    DisasterRecoveryWorkflow,
    SecurityComplianceWorkflow,
    MonitoringSetupWorkflow,
)
from src.models.workflow_models import WorkflowBlueprint
from src.server.utils import format_error


logger = logging.getLogger(__name__)


class WorkflowManagementTools:
    """MCP tools for workflow management."""

    def __init__(
        self,
        workflow_engine: WorkflowEngine,
        scheduler: WorkflowScheduler,
        approval_system: ApprovalSystem,
        governance: WorkflowGovernance,
    ):
        """Initialize workflow management tools."""
        self.workflow_engine = workflow_engine
        self.scheduler = scheduler
        self.approval_system = approval_system
        self.governance = governance
        self.schedule_manager = ScheduleManager(scheduler)
        self._available_blueprints = self._load_default_blueprints()

    def _load_default_blueprints(self) -> Dict[str, WorkflowBlueprint]:
        """Load default workflow blueprints."""
        blueprints = {}

        # Add standard blueprints
        blueprints["environment_provisioning"] = EnvironmentProvisioningWorkflow(
            environment_name="default", service_type="web"
        )
        blueprints["fleet_backup_orchestration"] = BackupOrchestrationWorkflow()
        blueprints["safe_container_upgrade"] = SafeUpgradeWorkflow()
        blueprints["disaster_recovery"] = DisasterRecoveryWorkflow()
        blueprints["security_compliance"] = SecurityComplianceWorkflow()
        blueprints["monitoring_setup"] = MonitoringSetupWorkflow()

        return blueprints

    def list_available_workflows(self) -> Dict[str, Any]:
        """List all available workflow blueprints."""
        try:
            workflows = []

            for blueprint_name, blueprint in self._available_blueprints.items():
                workflows.append(
                    {
                        "name": blueprint.name,
                        "blueprint_id": blueprint_name,
                        "description": blueprint.description,
                        "category": blueprint.category.value,
                        "version": blueprint.version,
                        "estimated_duration_minutes": blueprint.estimated_duration.total_seconds()
                        / 60
                        if blueprint.estimated_duration
                        else None,
                        "tags": list(blueprint.tags),
                        "owner": blueprint.owner,
                        "parameters": {
                            param_name: {
                                "type": param.type,
                                "required": param.required,
                                "default": param.default,
                                "description": param.description,
                                "choices": param.choices,
                            }
                            for param_name, param in blueprint.parameters.items()
                        },
                        "requires_approval": any(
                            step.requires_approval for step in blueprint.steps
                        ),
                        "has_rollback": blueprint.rollback_plan is not None
                        and blueprint.rollback_plan.enabled,
                    }
                )

            return {
                "success": True,
                "workflows": workflows,
                "total_count": len(workflows),
                "categories": list(set(w["category"] for w in workflows)),
            }

        except Exception as e:
            logger.error(f"Failed to list workflows: {e}")
            return {"success": False, "error": str(e)}

    def get_workflow_details(self, workflow_name: str) -> Dict[str, Any]:
        """Get detailed information about a workflow."""
        try:
            # Find blueprint by name
            blueprint = None
            blueprint_id = None

            for bp_id, bp in self._available_blueprints.items():
                if bp.name.lower() == workflow_name.lower() or bp_id == workflow_name:
                    blueprint = bp
                    blueprint_id = bp_id
                    break

            if not blueprint:
                return {
                    "success": False,
                    "error": f"Workflow '{workflow_name}' not found",
                }

            # Get workflow details
            details = {
                "name": blueprint.name,
                "blueprint_id": blueprint_id,
                "description": blueprint.description,
                "version": blueprint.version,
                "category": blueprint.category.value,
                "owner": blueprint.owner,
                "documentation": blueprint.documentation,
                "created_at": blueprint.created_at.isoformat(),
                "updated_at": blueprint.updated_at.isoformat(),
                "estimated_duration_minutes": blueprint.estimated_duration.total_seconds()
                / 60
                if blueprint.estimated_duration
                else None,
                "resource_requirements": blueprint.resource_requirements,
                "tags": list(blueprint.tags),
                "parameters": {},
                "steps": [],
                "approvals": [],
                "rollback_plan": None,
            }

            # Add parameters
            for param_name, param in blueprint.parameters.items():
                details["parameters"][param_name] = {
                    "type": param.type,
                    "required": param.required,
                    "default": param.default,
                    "description": param.description,
                    "validation": param.validation,
                    "choices": param.choices,
                    "sensitive": param.sensitive,
                }

            # Add steps
            for step in blueprint.steps:
                details["steps"].append(
                    {
                        "step_id": step.step_id,
                        "name": step.name,
                        "description": step.description,
                        "type": step.step_type.value,
                        "timeout_minutes": step.timeout.total_seconds() / 60,
                        "dependencies": step.dependencies,
                        "requires_approval": step.requires_approval,
                        "approvers": step.approvers,
                        "retry_policy": {
                            "max_attempts": step.retry_policy.max_attempts,
                            "initial_delay_seconds": step.retry_policy.initial_delay.total_seconds(),
                            "backoff_factor": step.retry_policy.backoff_factor,
                        },
                    }
                )

            # Add approvals
            for approval in blueprint.approvals:
                details["approvals"].append(
                    {
                        "step_id": approval.step_id,
                        "required_approvers": approval.required_approvers,
                        "description": approval.description,
                        "timeout_hours": approval.timeout.total_seconds() / 3600
                        if approval.timeout
                        else None,
                    }
                )

            # Add rollback plan
            if blueprint.rollback_plan:
                rollback_actions = []
                for action in blueprint.rollback_plan.actions:
                    rollback_actions.append(
                        {
                            "action_id": action.action_id,
                            "name": action.name,
                            "type": action.step_type.value,
                            "timeout_minutes": action.timeout.total_seconds() / 60,
                        }
                    )

                details["rollback_plan"] = {
                    "enabled": blueprint.rollback_plan.enabled,
                    "actions": rollback_actions,
                    "conditions": blueprint.rollback_plan.conditions,
                }

            return {"success": True, "workflow": details}

        except Exception as e:
            logger.error(f"Failed to get workflow details: {e}")
            return {"success": False, "error": str(e)}

    def execute_workflow(
        self,
        workflow_name: str,
        parameters: Dict[str, Any],
        created_by: str = "",
        approvals: Dict[str, str] = None,
    ) -> Dict[str, Any]:
        """Execute a workflow with parameters."""
        try:
            # Find blueprint
            blueprint = None
            for bp_id, bp in self._available_blueprints.items():
                if bp.name.lower() == workflow_name.lower() or bp_id == workflow_name:
                    blueprint = bp
                    break

            if not blueprint:
                return {
                    "success": False,
                    "error": f"Workflow '{workflow_name}' not found",
                }

            # Validate parameters
            validation_result = self.workflow_engine.validate_workflow_prerequisites(
                blueprint, parameters
            )
            if not validation_result.valid:
                return {
                    "success": False,
                    "error": "Parameter validation failed",
                    "validation_errors": validation_result.errors,
                }

            # Execute workflow
            execution = self.workflow_engine.execute_workflow(
                blueprint=blueprint,
                parameters=parameters,
                created_by=created_by,
                approvals=approvals,
            )

            return {
                "success": True,
                "execution_id": execution.execution_id,
                "status": execution.status.value,
                "message": f"Workflow '{workflow_name}' started successfully",
            }

        except Exception as e:
            logger.error(f"Failed to execute workflow: {e}")
            return {"success": False, "error": str(e)}

    def get_workflow_status(self, execution_id: str) -> Dict[str, Any]:
        """Get status of workflow execution."""
        try:
            status = self.workflow_engine.get_workflow_status(execution_id)

            if not status:
                return {
                    "success": False,
                    "error": f"Execution '{execution_id}' not found",
                }

            return {"success": True, "execution": status}

        except Exception as e:
            logger.error(f"Failed to get workflow status: {e}")
            return {"success": False, "error": str(e)}

    def pause_workflow(self, execution_id: str) -> Dict[str, Any]:
        """Pause running workflow."""
        try:
            success = self.workflow_engine.pause_workflow(execution_id)

            if not success:
                return {
                    "success": False,
                    "error": f"Failed to pause workflow '{execution_id}' - execution may not exist or already completed",
                }

            return {
                "success": True,
                "message": f"Workflow '{execution_id}' paused successfully",
            }

        except Exception as e:
            logger.error(f"Failed to pause workflow: {e}")
            return {"success": False, "error": str(e)}

    def resume_workflow(self, execution_id: str) -> Dict[str, Any]:
        """Resume paused workflow."""
        try:
            success = self.workflow_engine.resume_workflow(execution_id)

            if not success:
                return {
                    "success": False,
                    "error": f"Failed to resume workflow '{execution_id}' - execution may not exist or not paused",
                }

            return {
                "success": True,
                "message": f"Workflow '{execution_id}' resumed successfully",
            }

        except Exception as e:
            logger.error(f"Failed to resume workflow: {e}")
            return {"success": False, "error": str(e)}

    def cancel_workflow(self, execution_id: str, reason: str = "") -> Dict[str, Any]:
        """Cancel workflow execution."""
        try:
            success = self.workflow_engine.cancel_workflow(execution_id, reason)

            if not success:
                return {
                    "success": False,
                    "error": f"Failed to cancel workflow '{execution_id}' - execution may not exist",
                }

            return {
                "success": True,
                "message": f"Workflow '{execution_id}' cancelled successfully",
            }

        except Exception as e:
            logger.error(f"Failed to cancel workflow: {e}")
            return {"success": False, "error": str(e)}

    def list_workflow_executions(
        self, workflow_name: Optional[str] = None, limit: int = 50
    ) -> Dict[str, Any]:
        """List workflow executions."""
        try:
            # This would query from persistent storage
            # For now, return placeholder data
            executions = []

            return {
                "success": True,
                "executions": executions,
                "total_count": len(executions),
                "limit": limit,
            }

        except Exception as e:
            logger.error(f"Failed to list workflow executions: {e}")
            return {"success": False, "error": str(e)}

    def get_workflow_history(self, execution_id: str) -> Dict[str, Any]:
        """Get detailed execution history."""
        try:
            # This would load detailed history from persistent storage
            # For now, return basic status
            status = self.workflow_engine.get_workflow_status(execution_id)

            if not status:
                return {
                    "success": False,
                    "error": f"Execution '{execution_id}' not found",
                }

            # Generate history from current status
            history = {
                "execution_id": execution_id,
                "status": status["status"],
                "events": [
                    {
                        "timestamp": status["start_time"],
                        "event_type": "workflow_started",
                        "description": "Workflow execution started",
                    }
                ],
            }

            if status.get("end_time"):
                history["events"].append(
                    {
                        "timestamp": status["end_time"],
                        "event_type": "workflow_completed",
                        "description": f"Workflow execution {status['status']}",
                    }
                )

            return {"success": True, "history": history}

        except Exception as e:
            logger.error(f"Failed to get workflow history: {e}")
            return {"success": False, "error": str(e)}

    def schedule_workflow(
        self, workflow_name: str, schedule: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Schedule recurring workflow."""
        try:
            # Find blueprint
            blueprint = None
            for bp_id, bp in self._available_blueprints.items():
                if bp.name.lower() == workflow_name.lower() or bp_id == workflow_name:
                    blueprint = bp
                    break

            if not blueprint:
                return {
                    "success": False,
                    "error": f"Workflow '{workflow_name}' not found",
                }

            # Validate cron expression
            cron_expression = schedule.get("cron_expression")
            if not cron_expression:
                return {"success": False, "error": "cron_expression is required"}

            validation = self.schedule_manager.validate_cron_expression(cron_expression)
            if not validation["valid"]:
                return {
                    "success": False,
                    "error": f"Invalid cron expression: {validation['error']}",
                }

            # Schedule workflow
            schedule_id = self.scheduler.schedule_recurring_workflow(
                blueprint=blueprint,
                schedule_expression=cron_expression,
                timezone_str=schedule.get("timezone", "UTC"),
                parameters=schedule.get("parameters", {}),
                created_by=schedule.get("created_by", ""),
            )

            return {
                "success": True,
                "schedule_id": schedule_id,
                "message": f"Workflow '{workflow_name}' scheduled successfully",
                "next_runs": validation["next_runs"][:5],  # Show next 5 runs
            }

        except Exception as e:
            logger.error(f"Failed to schedule workflow: {e}")
            return {"success": False, "error": str(e)}

    def cancel_scheduled_workflow(self, schedule_id: str) -> Dict[str, Any]:
        """Cancel scheduled workflow."""
        try:
            success = self.scheduler.cancel_scheduled_workflow(schedule_id)

            if not success:
                return {
                    "success": False,
                    "error": f"Scheduled workflow '{schedule_id}' not found",
                }

            return {
                "success": True,
                "message": f"Scheduled workflow '{schedule_id}' cancelled successfully",
            }

        except Exception as e:
            logger.error(f"Failed to cancel scheduled workflow: {e}")
            return {"success": False, "error": str(e)}

    def list_scheduled_workflows(
        self, workflow_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """List scheduled workflows."""
        try:
            scheduled_workflows = self.scheduler.get_scheduled_workflows(workflow_name)

            return {
                "success": True,
                "scheduled_workflows": scheduled_workflows,
                "total_count": len(scheduled_workflows),
            }

        except Exception as e:
            logger.error(f"Failed to list scheduled workflows: {e}")
            return {"success": False, "error": str(e)}

    def get_upcoming_executions(self, hours_ahead: int = 24) -> Dict[str, Any]:
        """Get upcoming workflow executions."""
        try:
            upcoming = self.scheduler.get_upcoming_executions(hours_ahead)

            return {
                "success": True,
                "upcoming_executions": upcoming,
                "hours_ahead": hours_ahead,
                "total_count": len(upcoming),
            }

        except Exception as e:
            logger.error(f"Failed to get upcoming executions: {e}")
            return {"success": False, "error": str(e)}

    def request_workflow_approval(
        self, execution_id: str, step_id: str, approver: str, comment: str = None
    ) -> Dict[str, Any]:
        """Request approval for workflow step."""
        try:
            # Get execution
            execution = self.workflow_engine.get_workflow_status(execution_id)
            if not execution:
                return {
                    "success": False,
                    "error": f"Execution '{execution_id}' not found",
                }

            # Find step in blueprint
            blueprint = None
            for bp in self._available_blueprints.values():
                if bp.name == execution["blueprint_name"]:
                    blueprint = bp
                    break

            if not blueprint:
                return {
                    "success": False,
                    "error": f"Blueprint '{execution['blueprint_name']}' not found",
                }

            step = None
            for s in blueprint.steps:
                if s.step_id == step_id:
                    step = s
                    break

            if not step:
                return {
                    "success": False,
                    "error": f"Step '{step_id}' not found in workflow",
                }

            # Create execution instance for approval system
            from src.models.workflow_models import WorkflowExecution

            execution_instance = WorkflowExecution(
                execution_id=execution_id,
                blueprint_id=blueprint.name,
                blueprint_name=blueprint.name,
                parameters=execution["parameters"],
                status=execution["status"],
                created_by=execution.get("created_by", ""),
            )

            # Request approval
            approval_request = self.approval_system.request_approval(
                execution_instance, step
            )

            return {
                "success": True,
                "approval_id": approval_request.approval_id,
                "message": f"Approval requested for step '{step_id}'",
                "approvers": approval_request.approvers,
                "expires_at": approval_request.expires_at.isoformat()
                if approval_request.expires_at
                else None,
            }

        except Exception as e:
            logger.error(f"Failed to request approval: {e}")
            return {"success": False, "error": str(e)}

    def approve_workflow_step(
        self, approval_id: str, approver: str, comment: str = None
    ) -> Dict[str, Any]:
        """Approve workflow step."""
        try:
            success = self.approval_system.approve_step(approval_id, approver, comment)

            if not success:
                return {
                    "success": False,
                    "error": "Failed to approve step - approval may not exist or approver not authorized",
                }

            return {
                "success": True,
                "message": f"Step approved successfully by {approver}",
            }

        except Exception as e:
            logger.error(f"Failed to approve step: {e}")
            return {"success": False, "error": str(e)}

    def reject_workflow_step(
        self, approval_id: str, approver: str, reason: str
    ) -> Dict[str, Any]:
        """Reject workflow step."""
        try:
            success = self.approval_system.reject_step(approval_id, approver, reason)

            if not success:
                return {
                    "success": False,
                    "error": "Failed to reject step - approval may not exist or approver not authorized",
                }

            return {
                "success": True,
                "message": f"Step rejected by {approver}: {reason}",
            }

        except Exception as e:
            logger.error(f"Failed to reject step: {e}")
            return {"success": False, "error": str(e)}

    def get_pending_approvals(self, approver: str) -> Dict[str, Any]:
        """Get pending approvals for user."""
        try:
            pending_approvals = self.approval_system.get_pending_approvals(approver)

            return {
                "success": True,
                "pending_approvals": pending_approvals,
                "total_count": len(pending_approvals),
            }

        except Exception as e:
            logger.error(f"Failed to get pending approvals: {e}")
            return {"success": False, "error": str(e)}

    def validate_workflow_compliance(self, workflow_name: str) -> Dict[str, Any]:
        """Validate workflow against governance policies."""
        try:
            # Find blueprint
            blueprint = None
            for bp_id, bp in self._available_blueprints.items():
                if bp.name.lower() == workflow_name.lower() or bp_id == workflow_name:
                    blueprint = bp
                    break

            if not blueprint:
                return {
                    "success": False,
                    "error": f"Workflow '{workflow_name}' not found",
                }

            # Validate compliance
            compliance_result = self.governance.validate_workflow_compliance(blueprint)

            return {
                "success": True,
                "compliant": compliance_result.compliant,
                "violations": compliance_result.violations,
                "warnings": compliance_result.warnings,
                "recommendations": compliance_result.recommendations,
            }

        except Exception as e:
            logger.error(f"Failed to validate compliance: {e}")
            return {"success": False, "error": str(e)}

    def get_workflow_metrics(self, execution_id: str) -> Dict[str, Any]:
        """Get workflow execution metrics."""
        try:
            metrics = self.workflow_engine.get_workflow_metrics(execution_id)

            if not metrics:
                return {
                    "success": False,
                    "error": f"Execution '{execution_id}' not found",
                }

            return {
                "success": True,
                "metrics": {
                    "execution_id": metrics.execution_id,
                    "blueprint_name": metrics.blueprint_name,
                    "status": metrics.status.value,
                    "total_steps": metrics.total_steps,
                    "completed_steps": metrics.completed_steps,
                    "failed_steps": metrics.failed_steps,
                    "total_execution_time_minutes": metrics.total_execution_time.total_seconds()
                    / 60
                    if metrics.total_execution_time
                    else None,
                    "approval_count": metrics.approval_count,
                    "rollback_count": metrics.rollback_count,
                    "start_time": metrics.start_time.isoformat(),
                    "end_time": metrics.end_time.isoformat()
                    if metrics.end_time
                    else None,
                },
            }

        except Exception as e:
            logger.error(f"Failed to get workflow metrics: {e}")
            return {"success": False, "error": str(e)}


def register_tools(mcp: FastMCP, workflow_tools: WorkflowManagementTools):
    """Register workflow management tools with MCP instance."""

    @mcp.tool()
    @secure_tool("list_workflows")
    async def list_workflows() -> dict:
        """List all available workflow blueprints.

        Returns:
            Dictionary containing all available workflows with basic information
        """
        try:
            return workflow_tools.list_available_workflows()
        except Exception as e:
            logger.error(f"List workflows failed: {e}")
            return format_error(e)

    @mcp.tool()
    @secure_tool("get_workflow_details")
    async def get_workflow_details(workflow_name: str) -> dict:
        """Get detailed information about a specific workflow.

        Args:
            workflow_name: Name or ID of the workflow to get details for

        Returns:
            Dictionary containing detailed workflow information
        """
        try:
            return workflow_tools.get_workflow_details(workflow_name)
        except Exception as e:
            logger.error(f"Get workflow details failed: {e}")
            return format_error(e)

    @mcp.tool()
    @secure_tool("execute_workflow")
    async def execute_workflow(
        workflow_name: str,
        parameters: dict,
        created_by: str = "",
        approvals: dict = None,
    ) -> dict:
        """Execute a workflow with specified parameters.

        Args:
            workflow_name: Name or ID of the workflow to execute
            parameters: Dictionary of parameters for the workflow
            created_by: User who initiated the workflow (optional)
            approvals: Pre-approved steps (optional)

        Returns:
            Dictionary containing execution ID and status
        """
        try:
            return workflow_tools.execute_workflow(
                workflow_name, parameters, created_by, approvals
            )
        except Exception as e:
            logger.error(f"Execute workflow failed: {e}")
            return format_error(e)

    @mcp.tool()
    @secure_tool("get_workflow_status")
    async def get_workflow_status(execution_id: str) -> dict:
        """Get the current status of a workflow execution.

        Args:
            execution_id: ID of the workflow execution

        Returns:
            Dictionary containing execution status and details
        """
        try:
            return workflow_tools.get_workflow_status(execution_id)
        except Exception as e:
            logger.error(f"Get workflow status failed: {e}")
            return format_error(e)

    @mcp.tool()
    @secure_tool("pause_workflow")
    async def pause_workflow(execution_id: str) -> dict:
        """Pause a running workflow execution.

        Args:
            execution_id: ID of the workflow execution to pause

        Returns:
            Dictionary indicating success or failure
        """
        try:
            return workflow_tools.pause_workflow(execution_id)
        except Exception as e:
            logger.error(f"Pause workflow failed: {e}")
            return format_error(e)

    @mcp.tool()
    @secure_tool("resume_workflow")
    async def resume_workflow(execution_id: str) -> dict:
        """Resume a paused workflow execution.

        Args:
            execution_id: ID of the workflow execution to resume

        Returns:
            Dictionary indicating success or failure
        """
        try:
            return workflow_tools.resume_workflow(execution_id)
        except Exception as e:
            logger.error(f"Resume workflow failed: {e}")
            return format_error(e)

    @mcp.tool()
    @secure_tool("cancel_workflow")
    async def cancel_workflow(execution_id: str, reason: str = "") -> dict:
        """Cancel a workflow execution.

        Args:
            execution_id: ID of the workflow execution to cancel
            reason: Reason for cancellation (optional)

        Returns:
            Dictionary indicating success or failure
        """
        try:
            return workflow_tools.cancel_workflow(execution_id, reason)
        except Exception as e:
            logger.error(f"Cancel workflow failed: {e}")
            return format_error(e)

    @mcp.tool()
    @secure_tool("list_workflow_executions")
    async def list_workflow_executions(
        workflow_name: str = None, limit: int = 50
    ) -> dict:
        """List workflow executions with optional filtering.

        Args:
            workflow_name: Filter by workflow name (optional)
            limit: Maximum number of executions to return

        Returns:
            Dictionary containing list of executions
        """
        try:
            return workflow_tools.list_workflow_executions(workflow_name, limit)
        except Exception as e:
            logger.error(f"List workflow executions failed: {e}")
            return format_error(e)

    @mcp.tool()
    @secure_tool("get_workflow_history")
    async def get_workflow_history(execution_id: str) -> dict:
        """Get detailed execution history for a workflow.

        Args:
            execution_id: ID of the workflow execution

        Returns:
            Dictionary containing execution history
        """
        try:
            return workflow_tools.get_workflow_history(execution_id)
        except Exception as e:
            logger.error(f"Get workflow history failed: {e}")
            return format_error(e)

    @mcp.tool()
    @secure_tool("schedule_workflow")
    async def schedule_workflow(workflow_name: str, schedule: dict) -> dict:
        """Schedule a workflow for recurring execution.

        Args:
            workflow_name: Name or ID of the workflow to schedule
            schedule: Dictionary containing cron expression and options

        Returns:
            Dictionary containing schedule ID and details
        """
        try:
            return workflow_tools.schedule_workflow(workflow_name, schedule)
        except Exception as e:
            logger.error(f"Schedule workflow failed: {e}")
            return format_error(e)

    @mcp.tool()
    @secure_tool("cancel_scheduled_workflow")
    async def cancel_scheduled_workflow(schedule_id: str) -> dict:
        """Cancel a scheduled workflow.

        Args:
            schedule_id: ID of the scheduled workflow to cancel

        Returns:
            Dictionary indicating success or failure
        """
        try:
            return workflow_tools.cancel_scheduled_workflow(schedule_id)
        except Exception as e:
            logger.error(f"Cancel scheduled workflow failed: {e}")
            return format_error(e)

    @mcp.tool()
    @secure_tool("list_scheduled_workflows")
    async def list_scheduled_workflows(workflow_name: str = None) -> dict:
        """List all scheduled workflows.

        Args:
            workflow_name: Filter by workflow name (optional)

        Returns:
            Dictionary containing list of scheduled workflows
        """
        try:
            return workflow_tools.list_scheduled_workflows(workflow_name)
        except Exception as e:
            logger.error(f"List scheduled workflows failed: {e}")
            return format_error(e)

    @mcp.tool()
    @secure_tool("get_upcoming_executions")
    async def get_upcoming_executions(hours_ahead: int = 24) -> dict:
        """Get upcoming workflow executions.

        Args:
            hours_ahead: Number of hours to look ahead

        Returns:
            Dictionary containing upcoming executions
        """
        try:
            return workflow_tools.get_upcoming_executions(hours_ahead)
        except Exception as e:
            logger.error(f"Get upcoming executions failed: {e}")
            return format_error(e)

    @mcp.tool()
    @secure_tool("request_workflow_approval")
    async def request_workflow_approval(
        execution_id: str, step_id: str, approver: str, comment: str = None
    ) -> dict:
        """Request approval for a workflow step.

        Args:
            execution_id: ID of the workflow execution
            step_id: ID of the step requiring approval
            approver: User who can approve the step
            comment: Optional comment for the approval request

        Returns:
            Dictionary containing approval request details
        """
        try:
            return workflow_tools.request_workflow_approval(
                execution_id, step_id, approver, comment
            )
        except Exception as e:
            logger.error(f"Request workflow approval failed: {e}")
            return format_error(e)

    @mcp.tool()
    @secure_tool("approve_workflow_step")
    async def approve_workflow_step(
        approval_id: str, approver: str, comment: str = None
    ) -> dict:
        """Approve a workflow step.

        Args:
            approval_id: ID of the approval request
            approver: User approving the step
            comment: Optional comment for the approval

        Returns:
            Dictionary indicating success or failure
        """
        try:
            return workflow_tools.approve_workflow_step(approval_id, approver, comment)
        except Exception as e:
            logger.error(f"Approve workflow step failed: {e}")
            return format_error(e)

    @mcp.tool()
    @secure_tool("reject_workflow_step")
    async def reject_workflow_step(
        approval_id: str, approver: str, reason: str
    ) -> dict:
        """Reject a workflow step.

        Args:
            approval_id: ID of the approval request
            approver: User rejecting the step
            reason: Required reason for rejection

        Returns:
            Dictionary indicating success or failure
        """
        try:
            return workflow_tools.reject_workflow_step(approval_id, approver, reason)
        except Exception as e:
            logger.error(f"Reject workflow step failed: {e}")
            return format_error(e)

    @mcp.tool()
    @secure_tool("get_pending_approvals")
    async def get_pending_approvals(approver: str) -> dict:
        """Get pending approvals for a user.

        Args:
            approver: User to get approvals for

        Returns:
            Dictionary containing pending approvals
        """
        try:
            return workflow_tools.get_pending_approvals(approver)
        except Exception as e:
            logger.error(f"Get pending approvals failed: {e}")
            return format_error(e)

    @mcp.tool()
    @secure_tool("validate_workflow_compliance")
    async def validate_workflow_compliance(workflow_name: str) -> dict:
        """Validate workflow against governance policies.

        Args:
            workflow_name: Name or ID of the workflow to validate

        Returns:
            Dictionary containing compliance validation results
        """
        try:
            return workflow_tools.validate_workflow_compliance(workflow_name)
        except Exception as e:
            logger.error(f"Validate workflow compliance failed: {e}")
            return format_error(e)

    @mcp.tool()
    @secure_tool("get_workflow_metrics")
    async def get_workflow_metrics(execution_id: str) -> dict:
        """Get metrics for a workflow execution.

        Args:
            execution_id: ID of the workflow execution

        Returns:
            Dictionary containing execution metrics
        """
        try:
            return workflow_tools.get_workflow_metrics(execution_id)
        except Exception as e:
            logger.error(f"Get workflow metrics failed: {e}")
            return format_error(e)
