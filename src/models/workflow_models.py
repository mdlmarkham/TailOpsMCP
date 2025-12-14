"""
Workflow and orchestration data models for TailOpsMCP.

This module defines comprehensive workflow blueprints, execution instances,
and related data structures for orchestrating common operational tasks.
"""

import asyncio
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from typing import Dict, List, Optional, Any, Union, Callable, Set
from dataclasses import dataclass, field, asdict
import json


class WorkflowCategory(Enum):
    """Workflow categories for organization."""
    PROVISIONING = "provisioning"
    BACKUP = "backup"
    UPGRADE = "upgrade"
    RECOVERY = "recovery"
    MAINTENANCE = "maintenance"
    MONITORING = "monitoring"
    SECURITY = "security"
    DEPLOYMENT = "deployment"
    SCALING = "scaling"
    COMPLIANCE = "compliance"


class StepType(Enum):
    """Types of workflow steps."""
    VALIDATION = "validation"
    RESOURCE_ALLOCATION = "resource_allocation"
    CONTAINER_OPERATIONS = "container_operations"
    SERVICE_DEPLOYMENT = "service_deployment"
    NETWORK_CONFIGURATION = "network_configuration"
    HEALTH_VALIDATION = "health_validation"
    BACKUP = "backup"
    RESTORE = "restore"
    SNAPSHOT = "snapshot"
    UPGRADE = "upgrade"
    TESTING = "testing"
    CONFIGURATION = "configuration"
    DISCOVERY = "discovery"
    TRANSFER = "transfer"
    MAINTENANCE = "maintenance"


class ExecutionStatus(Enum):
    """Workflow execution statuses."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    WAITING_APPROVAL = "waiting_approval"


class ApprovalStatus(Enum):
    """Approval request statuses."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class Parameter:
    """Parameter definition for workflow steps."""
    name: str
    type: str
    required: bool = False
    default: Any = None
    description: str = ""
    validation: Optional[Dict[str, Any]] = None
    choices: Optional[List[Any]] = None
    sensitive: bool = False


@dataclass
class Prerequisite:
    """Prerequisite for workflow execution."""
    name: str
    description: str
    check_function: Callable
    required: bool = True
    timeout: Optional[timedelta] = None


@dataclass
class RetryPolicy:
    """Retry policy for workflow steps."""
    max_attempts: int = 3
    initial_delay: timedelta = timedelta(seconds=10)
    backoff_factor: float = 2.0
    max_delay: timedelta = timedelta(minutes=5)
    retry_on_exceptions: List[str] = field(default_factory=list)


@dataclass
class RollbackAction:
    """Rollback action for workflow steps."""
    action_id: str
    name: str
    step_type: StepType
    parameters: Dict[str, Any] = field(default_factory=dict)
    timeout: timedelta = field(default_factory=lambda: timedelta(minutes=30))
    retry_policy: Optional[RetryPolicy] = None


@dataclass
class RollbackPlan:
    """Rollback plan for workflows."""
    enabled: bool = False
    actions: List[RollbackAction] = field(default_factory=list)
    conditions: List[str] = field(default_factory=list)


@dataclass
class ApprovalRequirement:
    """Approval requirement for workflow steps."""
    step_id: str
    required_approvers: List[str]
    description: str = ""
    timeout: Optional[timedelta] = None
    escalation_rules: Optional[Dict[str, Any]] = None


@dataclass
class WorkflowStep:
    """Individual step in a workflow."""
    step_id: str
    name: str
    description: str
    step_type: StepType
    parameters: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    timeout: timedelta = field(default_factory=lambda: timedelta(minutes=30))
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    rollback_action: Optional[RollbackAction] = None
    requires_approval: bool = False
    approvers: List[str] = field(default_factory=list)
    validation_function: Optional[Callable] = None
    preconditions: List[str] = field(default_factory=list)

    def validate(self) -> List[str]:
        """Validate workflow step configuration."""
        errors = []
        
        if not self.step_id or not self.step_id.strip():
            errors.append("Step ID is required")
        
        if not self.name or not self.name.strip():
            errors.append("Step name is required")
        
        if not self.description or not self.description.strip():
            errors.append("Step description is required")
        
        if self.requires_approval and not self.approvers:
            errors.append("Approval-required steps must specify approvers")
        
        if self.rollback_action and not self.rollback_action.action_id:
            errors.append("Rollback action must have an action_id")
        
        return errors


@dataclass
class WorkflowBlueprint:
    """Blueprint for workflow definition."""
    name: str
    description: str
    version: str
    category: WorkflowCategory
    prerequisites: List[Prerequisite] = field(default_factory=list)
    parameters: Dict[str, Parameter] = field(default_factory=dict)
    steps: List[WorkflowStep] = field(default_factory=list)
    approvals: List[ApprovalRequirement] = field(default_factory=list)
    rollback_plan: Optional[RollbackPlan] = None
    estimated_duration: Optional[timedelta] = None
    resource_requirements: Dict[str, Any] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)
    owner: str = ""
    documentation: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def validate(self) -> List[str]:
        """Validate workflow blueprint configuration."""
        errors = []
        
        if not self.name or not self.name.strip():
            errors.append("Workflow name is required")
        
        if not self.description or not self.description.strip():
            errors.append("Workflow description is required")
        
        if not self.version or not self.version.strip():
            errors.append("Workflow version is required")
        
        if not self.steps:
            errors.append("Workflow must have at least one step")
        else:
            # Validate all steps
            step_ids = set()
            for step in self.steps:
                step_errors = step.validate()
                errors.extend([f"Step {step.step_id}: {error}" for error in step_errors])
                
                if step.step_id in step_ids:
                    errors.append(f"Duplicate step ID: {step.step_id}")
                step_ids.add(step.step_id)
        
        # Validate step dependencies
        step_ids = {step.step_id for step in self.steps}
        for step in self.steps:
            for dependency in step.dependencies:
                if dependency not in step_ids:
                    errors.append(f"Step {step.step_id} depends on unknown step: {dependency}")
        
        # Validate approval requirements
        approval_steps = {approval.step_id for approval in self.approvals}
        for approval_step in approval_steps:
            if approval_step not in step_ids:
                errors.append(f"Approval requirement for unknown step: {approval_step}")
        
        return errors
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert blueprint to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "category": self.category.value,
            "prerequisites": [
                {
                    "name": p.name,
                    "description": p.description,
                    "required": p.required
                } for p in self.prerequisites
            ],
            "parameters": {k: asdict(v) for k, v in self.parameters.items()},
            "steps": [asdict(step) for step in self.steps],
            "approvals": [asdict(approval) for approval in self.approvals],
            "rollback_plan": asdict(self.rollback_plan) if self.rollback_plan else None,
            "estimated_duration": self.estimated_duration.total_seconds() if self.estimated_duration else None,
            "resource_requirements": self.resource_requirements,
            "tags": list(self.tags),
            "owner": self.owner,
            "documentation": self.documentation,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WorkflowBlueprint':
        """Create blueprint from dictionary."""
        # Parse enums
        category = WorkflowCategory(data["category"])
        
        # Parse prerequisites
        prerequisites = []
        for prereq_data in data.get("prerequisites", []):
            prerequisite = Prerequisite(
                name=prereq_data["name"],
                description=prereq_data["description"],
                check_function=lambda: True,  # Placeholder
                required=prereq_data.get("required", True)
            )
            prerequisites.append(prerequisite)
        
        # Parse parameters
        parameters = {}
        for param_name, param_data in data.get("parameters", {}).items():
            parameters[param_name] = Parameter(**param_data)
        
        # Parse steps
        steps = []
        for step_data in data.get("steps", []):
            step_type = StepType(step_data["step_type"])
            
            # Parse retry policy
            retry_policy_data = step_data.get("retry_policy", {})
            retry_policy = RetryPolicy(**retry_policy_data)
            
            # Parse rollback action
            rollback_action = None
            if step_data.get("rollback_action"):
                rollback_data = step_data["rollback_action"]
                rollback_action = RollbackAction(
                    action_id=rollback_data["action_id"],
                    name=rollback_data["name"],
                    step_type=StepType(rollback_data["step_type"]),
                    parameters=rollback_data.get("parameters", {})
                )
            
            step = WorkflowStep(
                step_id=step_data["step_id"],
                name=step_data["name"],
                description=step_data["description"],
                step_type=step_type,
                parameters=step_data.get("parameters", {}),
                dependencies=step_data.get("dependencies", []),
                timeout=timedelta(seconds=step_data.get("timeout", 1800)),
                retry_policy=retry_policy,
                rollback_action=rollback_action,
                requires_approval=step_data.get("requires_approval", False),
                approvers=step_data.get("approvers", [])
            )
            steps.append(step)
        
        # Parse approvals
        approvals = []
        for approval_data in data.get("approvals", []):
            approval = ApprovalRequirement(
                step_id=approval_data["step_id"],
                required_approvers=approval_data["required_approvers"],
                description=approval_data.get("description", "")
            )
            approvals.append(approval)
        
        # Parse rollback plan
        rollback_plan = None
        if data.get("rollback_plan"):
            rollback_data = data["rollback_plan"]
            rollback_actions = []
            for action_data in rollback_data.get("actions", []):
                action = RollbackAction(
                    action_id=action_data["action_id"],
                    name=action_data["name"],
                    step_type=StepType(action_data["step_type"]),
                    parameters=action_data.get("parameters", {})
                )
                rollback_actions.append(action)
            
            rollback_plan = RollbackPlan(
                enabled=rollback_data.get("enabled", False),
                actions=rollback_actions
            )
        
        return cls(
            name=data["name"],
            description=data["description"],
            version=data["version"],
            category=category,
            prerequisites=prerequisites,
            parameters=parameters,
            steps=steps,
            approvals=approvals,
            rollback_plan=rollback_plan,
            estimated_duration=timedelta(seconds=data.get("estimated_duration", 0)) if data.get("estimated_duration") else None,
            resource_requirements=data.get("resource_requirements", {}),
            tags=set(data.get("tags", [])),
            owner=data.get("owner", ""),
            documentation=data.get("documentation", "")
        )


@dataclass
class StepResult:
    """Result of workflow step execution."""
    step_id: str
    success: bool
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    execution_time: Optional[timedelta] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    retry_count: int = 0
    logs: List[str] = field(default_factory=list)


@dataclass
class ApprovalRecord:
    """Record of workflow approval."""
    approval_id: str
    step_id: str
    approver: str
    status: ApprovalStatus
    comment: str = ""
    requested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    responded_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None


@dataclass
class WorkflowExecution:
    """Workflow execution instance."""
    execution_id: str
    blueprint_id: str
    blueprint_name: str
    parameters: Dict[str, Any]
    status: ExecutionStatus = ExecutionStatus.PENDING
    current_step: Optional[str] = None
    step_results: Dict[str, StepResult] = field(default_factory=dict)
    approvals: List[ApprovalRecord] = field(default_factory=list)
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    created_by: str = ""
    context: Dict[str, Any] = field(default_factory=dict)
    rollback_executed: bool = False
    
    def get_completed_steps(self) -> List[str]:
        """Get list of completed step IDs."""
        return [step_id for step_id, result in self.step_results.items() if result.success]
    
    def get_failed_steps(self) -> List[str]:
        """Get list of failed step IDs."""
        return [step_id for step_id, result in self.step_results.items() if not result.success]
    
    def get_pending_approvals(self) -> List[ApprovalRecord]:
        """Get list of pending approvals."""
        return [approval for approval in self.approvals if approval.status == ApprovalStatus.PENDING]
    
    def get_total_execution_time(self) -> timedelta:
        """Get total execution time."""
        if not self.end_time:
            return datetime.now(timezone.utc) - self.start_time
        return self.end_time - self.start_time
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert execution to dictionary."""
        return {
            "execution_id": self.execution_id,
            "blueprint_id": self.blueprint_id,
            "blueprint_name": self.blueprint_name,
            "parameters": self.parameters,
            "status": self.status.value,
            "current_step": self.current_step,
            "step_results": {k: asdict(v) for k, v in self.step_results.items()},
            "approvals": [asdict(approval) for approval in self.approvals],
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "created_by": self.created_by,
            "context": self.context,
            "rollback_executed": self.rollback_executed,
            "completed_steps": self.get_completed_steps(),
            "failed_steps": self.get_failed_steps(),
            "total_execution_time": self.get_total_execution_time().total_seconds()
        }


@dataclass
class ScheduledWorkflow:
    """Scheduled workflow instance."""
    schedule_id: str
    blueprint_id: str
    blueprint_name: str
    schedule_expression: str
    timezone: str = "UTC"
    enabled: bool = True
    next_run: Optional[datetime] = None
    last_run: Optional[datetime] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert scheduled workflow to dictionary."""
        return {
            "schedule_id": self.schedule_id,
            "blueprint_id": self.blueprint_id,
            "blueprint_name": self.blueprint_name,
            "schedule_expression": self.schedule_expression,
            "timezone": self.timezone,
            "enabled": self.enabled,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "parameters": self.parameters,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by
        }


@dataclass
class ValidationResult:
    """Result of workflow validation."""
    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)


@dataclass
class WorkflowMetrics:
    """Metrics for workflow execution."""
    execution_id: str
    blueprint_name: str
    start_time: datetime
    end_time: Optional[datetime]
    status: ExecutionStatus
    total_steps: int
    completed_steps: int
    failed_steps: int
    total_execution_time: Optional[timedelta]
    approval_count: int
    rollback_count: int


class WorkflowBlueprintFactory:
    """Factory for creating common workflow blueprints."""
    
    @staticmethod
    def create_environment_provisioning_workflow() -> WorkflowBlueprint:
        """Create environment provisioning workflow blueprint."""
        steps = [
            WorkflowStep(
                step_id="validate_prerequisites",
                name="Validate Prerequisites",
                description="Validate system prerequisites and requirements",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=5)
            ),
            WorkflowStep(
                step_id="allocate_resources",
                name="Allocate Resources",
                description="Allocate necessary resources for the environment",
                step_type=StepType.RESOURCE_ALLOCATION,
                timeout=timedelta(minutes=10),
                requires_approval=True,
                approvers=["operations_manager"]
            ),
            WorkflowStep(
                step_id="create_containers",
                name="Create Containers",
                description="Create and configure containers",
                step_type=StepType.CONTAINER_OPERATIONS,
                timeout=timedelta(minutes=30),
                dependencies=["allocate_resources"]
            ),
            WorkflowStep(
                step_id="deploy_services",
                name="Deploy Services",
                description="Deploy services to containers",
                step_type=StepType.SERVICE_DEPLOYMENT,
                timeout=timedelta(minutes=20),
                dependencies=["create_containers"]
            ),
            WorkflowStep(
                step_id="configure_networking",
                name="Configure Networking",
                description="Configure network settings and connectivity",
                step_type=StepType.NETWORK_CONFIGURATION,
                timeout=timedelta(minutes=15),
                dependencies=["create_containers"]
            ),
            WorkflowStep(
                step_id="run_health_checks",
                name="Run Health Checks",
                description="Perform health validation of the environment",
                step_type=StepType.HEALTH_VALIDATION,
                timeout=timedelta(minutes=10),
                dependencies=["deploy_services", "configure_networking"]
            ),
            WorkflowStep(
                step_id="create_backup",
                name="Create Initial Backup",
                description="Create initial backup of the environment",
                step_type=StepType.BACKUP,
                timeout=timedelta(minutes=30),
                dependencies=["run_health_checks"]
            )
        ]
        
        rollback_actions = [
            RollbackAction(
                action_id="delete_containers",
                name="Delete Created Containers",
                step_type=StepType.CONTAINER_OPERATIONS,
                parameters={"action": "delete"}
            ),
            RollbackAction(
                action_id="release_resources",
                name="Release Allocated Resources",
                step_type=StepType.RESOURCE_ALLOCATION,
                parameters={"action": "release"}
            )
        ]
        
        rollback_plan = RollbackPlan(enabled=True, actions=rollback_actions)
        
        return WorkflowBlueprint(
            name="Environment Provisioning",
            description="Provision a complete environment with containers, services, and networking",
            version="1.0.0",
            category=WorkflowCategory.PROVISIONING,
            steps=steps,
            rollback_plan=rollback_plan,
            estimated_duration=timedelta(hours=2),
            tags={"provisioning", "environment", "infrastructure"}
        )
    
    @staticmethod
    def create_backup_orchestration_workflow() -> WorkflowBlueprint:
        """Create backup orchestration workflow blueprint."""
        steps = [
            WorkflowStep(
                step_id="discover_targets",
                name="Discover Backup Targets",
                description="Discover containers and services that need backup",
                step_type=StepType.DISCOVERY,
                timeout=timedelta(minutes=10)
            ),
            WorkflowStep(
                step_id="validate_backup_space",
                name="Validate Backup Storage",
                description="Validate available backup storage space",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=5),
                dependencies=["discover_targets"]
            ),
            WorkflowStep(
                step_id="create_snapshots",
                name="Create Container Snapshots",
                description="Create snapshots of all containers",
                step_type=StepType.SNAPSHOT,
                timeout=timedelta(minutes=60),
                dependencies=["validate_backup_space"]
            ),
            WorkflowStep(
                step_id="upload_backups",
                name="Upload Backups to Storage",
                description="Upload backups to external storage",
                step_type=StepType.TRANSFER,
                timeout=timedelta(minutes=120),
                dependencies=["create_snapshots"]
            ),
            WorkflowStep(
                step_id="verify_backups",
                name="Verify Backup Integrity",
                description="Verify integrity of created backups",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=30),
                dependencies=["upload_backups"]
            ),
            WorkflowStep(
                step_id="cleanup_old_backups",
                name="Cleanup Old Backups",
                description="Clean up expired or old backups",
                step_type=StepType.MAINTENANCE,
                timeout=timedelta(minutes=15),
                dependencies=["verify_backups"]
            )
        ]
        
        return WorkflowBlueprint(
            name="Fleet Backup Orchestration",
            description="Orchestrate backup of all containers across the fleet",
            version="1.0.0",
            category=WorkflowCategory.BACKUP,
            steps=steps,
            estimated_duration=timedelta(hours=4),
            tags={"backup", "maintenance", "fleet"}
        )
    
    @staticmethod
    def create_safe_upgrade_workflow() -> WorkflowBlueprint:
        """Create safe upgrade workflow blueprint."""
        steps = [
            WorkflowStep(
                step_id="pre_upgrade_checks",
                name="Pre-upgrade Health Check",
                description="Perform health check before upgrade",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=15)
            ),
            WorkflowStep(
                step_id="create_snapshots",
                name="Create Pre-upgrade Snapshots",
                description="Create snapshots before upgrade",
                step_type=StepType.SNAPSHOT,
                timeout=timedelta(minutes=30),
                dependencies=["pre_upgrade_checks"]
            ),
            WorkflowStep(
                step_id="upgrade_containers",
                name="Upgrade Containers",
                description="Upgrade containers to new versions",
                step_type=StepType.UPGRADE,
                timeout=timedelta(minutes=60),
                dependencies=["create_snapshots"]
            ),
            WorkflowStep(
                step_id="post_upgrade_verification",
                name="Post-upgrade Verification",
                description="Verify successful upgrade",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=20),
                dependencies=["upgrade_containers"]
            ),
            WorkflowStep(
                step_id="run_integration_tests",
                name="Run Integration Tests",
                description="Run integration tests to verify functionality",
                step_type=StepType.TESTING,
                timeout=timedelta(minutes=45),
                dependencies=["post_upgrade_verification"]
            ),
            WorkflowStep(
                step_id="update_monitoring",
                name="Update Monitoring Configuration",
                description="Update monitoring for new versions",
                step_type=StepType.CONFIGURATION,
                timeout=timedelta(minutes=15),
                dependencies=["run_integration_tests"]
            )
        ]
        
        rollback_actions = [
            RollbackAction(
                action_id="restore_snapshots",
                name="Restore from Snapshots",
                step_type=StepType.RESTORE,
                parameters={"restore_point": "pre_upgrade"}
            )
        ]
        
        rollback_plan = RollbackPlan(enabled=True, actions=rollback_actions)
        
        return WorkflowBlueprint(
            name="Safe Container Upgrade",
            description="Safely upgrade containers with rollback capability",
            version="1.0.0",
            category=WorkflowCategory.UPGRADE,
            steps=steps,
            rollback_plan=rollback_plan,
            estimated_duration=timedelta(hours=3),
            tags={"upgrade", "safety", "rollback"}
        )
    
    @staticmethod
    def create_disaster_recovery_workflow() -> WorkflowBlueprint:
        """Create disaster recovery workflow blueprint."""
        steps = [
            WorkflowStep(
                step_id="validate_backup",
                name="Validate Backup Availability",
                description="Validate backup availability and integrity",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=10)
            ),
            WorkflowStep(
                step_id="stop_affected_containers",
                name="Stop Affected Containers",
                description="Stop containers that need restoration",
                step_type=StepType.CONTAINER_OPERATIONS,
                timeout=timedelta(minutes=15),
                dependencies=["validate_backup"]
            ),
            WorkflowStep(
                step_id="restore_from_backup",
                name="Restore from Backup",
                description="Restore containers from backup",
                step_type=StepType.RESTORE,
                timeout=timedelta(minutes=90),
                dependencies=["stop_affected_containers"]
            ),
            WorkflowStep(
                step_id="verify_restoration",
                name="Verify Restoration",
                description="Verify successful restoration",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=20),
                dependencies=["restore_from_backup"]
            ),
            WorkflowStep(
                step_id="update_dns",
                name="Update DNS if needed",
                description="Update DNS records if required",
                step_type=StepType.NETWORK_CONFIGURATION,
                timeout=timedelta(minutes=10),
                dependencies=["verify_restoration"]
            ),
            WorkflowStep(
                step_id="run_health_checks",
                name="Final Health Validation",
                description="Perform final health validation",
                step_type=StepType.HEALTH_VALIDATION,
                timeout=timedelta(minutes=15),
                dependencies=["update_dns"]
            )
        ]
        
        return WorkflowBlueprint(
            name="Disaster Recovery",
            description="Restore containers from backup with validation",
            version="1.0.0",
            category=WorkflowCategory.RECOVERY,
            steps=steps,
            estimated_duration=timedelta(hours=3),
            tags={"recovery", "disaster", "restoration"}
        )