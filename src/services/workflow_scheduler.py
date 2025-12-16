"""
Workflow Scheduler for TailOpsMCP.

Provides scheduling capabilities for recurring workflow execution
with support for cron expressions and various schedule types.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
from croniter import croniter
import pytz

from src.models.workflow_models import WorkflowBlueprint, ScheduledWorkflow
from src.services.workflow_engine import WorkflowEngine
from src.models.event_models import (
    SystemEvent,
    EventType,
    EventSeverity,
    EventSource,
    EventCategory,
)


logger = logging.getLogger(__name__)


class WorkflowSchedulerError(Exception):
    """Workflow scheduler error."""

    pass


class WorkflowScheduler:
    """Schedule recurring workflows."""

    def __init__(self, workflow_engine: WorkflowEngine):
        """Initialize workflow scheduler."""
        self.workflow_engine = workflow_engine
        self._scheduled_workflows: Dict[str, ScheduledWorkflow] = {}
        self._schedule_tasks: Dict[str, asyncio.Task] = {}
        self._running = False
        self._scheduler_task: Optional[asyncio.Task] = None
        self._check_interval = 60  # Check every minute

    async def start_scheduler(self):
        """Start the workflow scheduler."""
        if self._running:
            return

        self._running = True
        self._scheduler_task = asyncio.create_task(self._scheduler_loop())
        logger.info("Workflow scheduler started")

    async def stop_scheduler(self):
        """Stop the workflow scheduler."""
        self._running = False

        # Cancel scheduler task
        if self._scheduler_task:
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass

        # Cancel all schedule tasks
        for task in self._schedule_tasks.values():
            task.cancel()

        self._schedule_tasks.clear()
        logger.info("Workflow scheduler stopped")

    async def schedule_recurring_workflow(
        self,
        blueprint: WorkflowBlueprint,
        schedule_expression: str,
        timezone_str: str = "UTC",
        parameters: Dict[str, Any] = None,
        created_by: str = "",
    ) -> str:
        """Schedule workflow for recurring execution."""
        schedule_id = str(uuid.uuid4())

        try:
            # Validate cron expression
            cron = croniter(schedule_expression)
            next_run = cron.get_next(datetime)

            # Convert to timezone
            timezone_obj = pytz.timezone(timezone_str)
            next_run = timezone_obj.localize(next_run)

            scheduled_workflow = ScheduledWorkflow(
                schedule_id=schedule_id,
                blueprint_id=blueprint.name,
                blueprint_name=blueprint.name,
                schedule_expression=schedule_expression,
                timezone=timezone_str,
                enabled=True,
                next_run=next_run,
                parameters=parameters or {},
                created_by=created_by,
            )

            # Store scheduled workflow
            self._scheduled_workflows[schedule_id] = scheduled_workflow

            # Start schedule task
            task = asyncio.create_task(
                self._schedule_workflow_execution(scheduled_workflow)
            )
            self._schedule_tasks[schedule_id] = task

            # Emit event
            await self._emit_scheduler_event(
                "workflow_scheduled",
                {
                    "schedule_id": schedule_id,
                    "blueprint_name": blueprint.name,
                    "schedule_expression": schedule_expression,
                    "next_run": next_run.isoformat(),
                },
            )

            logger.info(
                f"Scheduled workflow {blueprint.name} with schedule ID {schedule_id}"
            )
            return schedule_id

        except Exception as e:
            logger.error(f"Failed to schedule workflow: {e}")
            raise WorkflowSchedulerError(f"Failed to schedule workflow: {e}")

    async def cancel_scheduled_workflow(self, schedule_id: str) -> bool:
        """Cancel scheduled workflow."""
        if schedule_id not in self._scheduled_workflows:
            return False

        # Cancel schedule task
        if schedule_id in self._schedule_tasks:
            task = self._schedule_tasks[schedule_id]
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            del self._schedule_tasks[schedule_id]

        # Remove from scheduled workflows
        scheduled_workflow = self._scheduled_workflows[schedule_id]
        del self._scheduled_workflows[schedule_id]

        # Emit event
        await self._emit_scheduler_event(
            "workflow_unscheduled",
            {
                "schedule_id": schedule_id,
                "blueprint_name": scheduled_workflow.blueprint_name,
            },
        )

        logger.info(f"Cancelled scheduled workflow {schedule_id}")
        return True

    async def update_scheduled_workflow(
        self,
        schedule_id: str,
        schedule_expression: Optional[str] = None,
        timezone_str: Optional[str] = None,
        enabled: Optional[bool] = None,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Update scheduled workflow configuration."""
        if schedule_id not in self._scheduled_workflows:
            return False

        scheduled_workflow = self._scheduled_workflows[schedule_id]

        try:
            updated = False

            if schedule_expression is not None:
                # Validate new cron expression
                cron = croniter(schedule_expression)
                next_run = cron.get_next(datetime)

                timezone_obj = pytz.timezone(
                    timezone_str or scheduled_workflow.timezone
                )
                next_run = timezone_obj.localize(next_run)

                scheduled_workflow.schedule_expression = schedule_expression
                scheduled_workflow.next_run = next_run
                updated = True

            if timezone_str is not None:
                scheduled_workflow.timezone = timezone_str
                updated = True

            if enabled is not None:
                scheduled_workflow.enabled = enabled
                updated = True

            if parameters is not None:
                scheduled_workflow.parameters.update(parameters)
                updated = True

            if updated:
                # Emit event
                await self._emit_scheduler_event(
                    "workflow_schedule_updated",
                    {
                        "schedule_id": schedule_id,
                        "blueprint_name": scheduled_workflow.blueprint_name,
                        "changes": {
                            "schedule_expression": schedule_expression,
                            "timezone": timezone_str,
                            "enabled": enabled,
                            "parameters": parameters,
                        },
                    },
                )

                logger.info(f"Updated scheduled workflow {schedule_id}")

            return True

        except Exception as e:
            logger.error(f"Failed to update scheduled workflow {schedule_id}: {e}")
            return False

    async def get_scheduled_workflows(
        self, blueprint_name: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get all scheduled workflows."""
        workflows = []

        for scheduled_workflow in self._scheduled_workflows.values():
            if (
                blueprint_name is None
                or scheduled_workflow.blueprint_name == blueprint_name
            ):
                workflows.append(scheduled_workflow.to_dict())

        return workflows

    async def get_scheduled_workflow(
        self, schedule_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get specific scheduled workflow."""
        scheduled_workflow = self._scheduled_workflows.get(schedule_id)
        return scheduled_workflow.to_dict() if scheduled_workflow else None

    async def pause_scheduled_workflow(self, schedule_id: str) -> bool:
        """Pause scheduled workflow."""
        return await self.update_scheduled_workflow(schedule_id, enabled=False)

    async def resume_scheduled_workflow(self, schedule_id: str) -> bool:
        """Resume scheduled workflow."""
        return await self.update_scheduled_workflow(schedule_id, enabled=True)

    async def get_upcoming_executions(
        self, hours_ahead: int = 24
    ) -> List[Dict[str, Any]]:
        """Get upcoming workflow executions."""
        upcoming = []
        now = datetime.now(timezone.utc)
        cutoff = now + timedelta(hours=hours_ahead)

        for scheduled_workflow in self._scheduled_workflows.values():
            if scheduled_workflow.enabled and scheduled_workflow.next_run:
                # Convert next_run to UTC for comparison
                next_run_utc = scheduled_workflow.next_run
                if scheduled_workflow.next_run.tzinfo:
                    next_run_utc = scheduled_workflow.next_run.astimezone(timezone.utc)

                if now <= next_run_utc <= cutoff:
                    upcoming.append(
                        {
                            "schedule_id": scheduled_workflow.schedule_id,
                            "blueprint_name": scheduled_workflow.blueprint_name,
                            "next_run": next_run_utc.isoformat(),
                            "timezone": scheduled_workflow.timezone,
                            "parameters": scheduled_workflow.parameters,
                        }
                    )

        # Sort by next_run time
        upcoming.sort(key=lambda x: x["next_run"])
        return upcoming

    async def _scheduler_loop(self):
        """Main scheduler loop."""
        while self._running:
            try:
                await self._check_and_trigger_schedules()
                await asyncio.sleep(self._check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Scheduler loop error: {e}")
                await asyncio.sleep(self._check_interval)

    async def _check_and_trigger_schedules(self):
        """Check schedules and trigger executions if needed."""
        now = datetime.now(timezone.utc)

        for schedule_id, scheduled_workflow in list(self._scheduled_workflows.items()):
            if not scheduled_workflow.enabled:
                continue

            if not scheduled_workflow.next_run:
                continue

            # Convert next_run to UTC for comparison
            next_run_utc = scheduled_workflow.next_run
            if scheduled_workflow.next_run.tzinfo:
                next_run_utc = scheduled_workflow.next_run.astimezone(timezone.utc)

            # Check if it's time to trigger
            if now >= next_run_utc:
                try:
                    await self._trigger_scheduled_execution(scheduled_workflow)
                except Exception as e:
                    logger.error(
                        f"Failed to trigger scheduled execution {schedule_id}: {e}"
                    )

    async def _trigger_scheduled_execution(self, scheduled_workflow: ScheduledWorkflow):
        """Trigger scheduled workflow execution."""
        try:
            # Get blueprint (this would load from storage)
            # For now, we'll use the workflow engine's blueprint cache
            blueprint = await self._get_blueprint(scheduled_workflow.blueprint_id)
            if not blueprint:
                logger.error(
                    f"Blueprint not found for scheduled workflow: {scheduled_workflow.blueprint_id}"
                )
                return

            # Execute workflow
            execution = await self.workflow_engine.execute_workflow(
                blueprint=blueprint,
                parameters=scheduled_workflow.parameters,
                created_by=scheduled_workflow.created_by,
            )

            # Update scheduled workflow
            scheduled_workflow.last_run = datetime.now(timezone.utc)

            # Calculate next run
            cron = croniter(scheduled_workflow.schedule_expression)
            timezone_obj = pytz.timezone(scheduled_workflow.timezone)
            next_run_naive = cron.get_next(datetime)
            scheduled_workflow.next_run = timezone_obj.localize(next_run_naive)

            # Emit event
            await self._emit_scheduler_event(
                "scheduled_execution_triggered",
                {
                    "schedule_id": scheduled_workflow.schedule_id,
                    "blueprint_name": scheduled_workflow.blueprint_name,
                    "execution_id": execution.execution_id,
                    "next_run": scheduled_workflow.next_run.isoformat(),
                },
            )

            logger.info(
                f"Triggered scheduled execution for {scheduled_workflow.blueprint_name}"
            )

        except Exception as e:
            logger.error(f"Failed to trigger scheduled execution: {e}")
            await self._emit_scheduler_event(
                "scheduled_execution_failed",
                {
                    "schedule_id": scheduled_workflow.schedule_id,
                    "blueprint_name": scheduled_workflow.blueprint_name,
                    "error": str(e),
                },
            )

    async def _schedule_workflow_execution(self, scheduled_workflow: ScheduledWorkflow):
        """Schedule individual workflow execution."""
        try:
            # Calculate time until next run
            now = datetime.now(timezone.utc)
            if scheduled_workflow.next_run:
                next_run_utc = scheduled_workflow.next_run
                if scheduled_workflow.next_run.tzinfo:
                    next_run_utc = scheduled_workflow.next_run.astimezone(timezone.utc)

                delay = (next_run_utc - now).total_seconds()
                if delay > 0:
                    await asyncio.sleep(delay)

            # Trigger execution
            await self._trigger_scheduled_execution(scheduled_workflow)

        except asyncio.CancelledError:
            # Task was cancelled
            pass
        except Exception as e:
            logger.error(f"Scheduled execution task failed: {e}")

    async def _get_blueprint(self, blueprint_id: str) -> Optional[WorkflowBlueprint]:
        """Get workflow blueprint."""
        # This would load from storage or workflow engine cache
        # For now, return None as placeholder
        return None

    async def _emit_scheduler_event(self, event_type: str, details: Dict[str, Any]):
        """Emit scheduler event."""
        try:
            # Create system event
            event = SystemEvent(
                event_id=str(uuid.uuid4()),
                event_type=EventType.WORKFLOW,
                severity=EventSeverity.INFO,
                source=EventSource.WORKFLOW_ENGINE,
                category=EventCategory.WORKFLOW,
                timestamp=datetime.now(timezone.utc),
                data={"event_type": event_type, "details": details},
            )

            # This would integrate with the event collector
            # For now, just log the event
            logger.info(f"Scheduler event: {event_type} - {details}")

        except Exception as e:
            logger.error(f"Failed to emit scheduler event: {e}")


class ScheduleManager:
    """Manage workflow schedules and configurations."""

    def __init__(self, scheduler: WorkflowScheduler):
        """Initialize schedule manager."""
        self.scheduler = scheduler

    async def create_daily_schedule(
        self,
        blueprint_name: str,
        hour: int = 2,
        minute: int = 0,
        timezone_str: str = "UTC",
    ) -> str:
        """Create daily schedule."""
        cron_expression = f"{minute} {hour} * * *"
        return await self._create_schedule(
            blueprint_name, cron_expression, timezone_str
        )

    async def create_weekly_schedule(
        self,
        blueprint_name: str,
        day_of_week: int,
        hour: int = 2,
        minute: int = 0,
        timezone_str: str = "UTC",
    ) -> str:
        """Create weekly schedule."""
        cron_expression = f"{minute} {hour} * * {day_of_week}"
        return await self._create_schedule(
            blueprint_name, cron_expression, timezone_str
        )

    async def create_monthly_schedule(
        self,
        blueprint_name: str,
        day_of_month: int,
        hour: int = 2,
        minute: int = 0,
        timezone_str: str = "UTC",
    ) -> str:
        """Create monthly schedule."""
        cron_expression = f"{minute} {hour} {day_of_month} * *"
        return await self._create_schedule(
            blueprint_name, cron_expression, timezone_str
        )

    async def create_hourly_schedule(
        self, blueprint_name: str, minute: int = 0, timezone_str: str = "UTC"
    ) -> str:
        """Create hourly schedule."""
        cron_expression = f"{minute} * * * *"
        return await self._create_schedule(
            blueprint_name, cron_expression, timezone_str
        )

    async def _create_schedule(
        self, blueprint_name: str, cron_expression: str, timezone_str: str = "UTC"
    ) -> str:
        """Create schedule with given cron expression."""
        try:
            # Get blueprint (this would load from storage)
            # For now, return None as placeholder
            blueprint = None

            if not blueprint:
                raise WorkflowSchedulerError(f"Blueprint not found: {blueprint_name}")

            schedule_id = await self.scheduler.schedule_recurring_workflow(
                blueprint=blueprint,
                schedule_expression=cron_expression,
                timezone_str=timezone_str,
            )

            return schedule_id

        except Exception as e:
            logger.error(f"Failed to create schedule: {e}")
            raise

    async def validate_cron_expression(self, cron_expression: str) -> Dict[str, Any]:
        """Validate cron expression."""
        try:
            cron = croniter(cron_expression)
            next_runs = []

            # Get next 10 execution times
            now = datetime.now()
            for i in range(10):
                next_run = cron.get_next(datetime)
                next_runs.append(next_run.strftime("%Y-%m-%d %H:%M:%S"))

            return {
                "valid": True,
                "next_runs": next_runs,
                "cron_expression": cron_expression,
            }

        except Exception as e:
            return {"valid": False, "error": str(e), "cron_expression": cron_expression}
