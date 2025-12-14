"""
Workflow Integration Services for TailOpsMCP.

Integrates the workflow system with existing policy, inventory,
and event systems for comprehensive orchestration.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import asyncio

from src.models.workflow_models import WorkflowBlueprint, WorkflowExecution, WorkflowStep
from src.models.policy_models import PolicyContext, PolicyDecision
from src.models.event_models import SystemEvent, EventType, EventSeverity, EventSource, EventCategory
from src.services.policy_engine import PolicyEngine
from src.tools.inventory_tools import EnhancedInventoryTools
from src.services.event_collector import EventCollector
from src.services.capability_executor import CapabilityExecutor


logger = logging.getLogger(__name__)


class WorkflowPolicyIntegration:
    """Integrate workflows with policy system."""
    
    def __init__(self, policy_engine: PolicyEngine):
        """Initialize workflow policy integration."""
        self.policy_engine = policy_engine
    
    async def validate_workflow_policies(self, blueprint: WorkflowBlueprint, 
                                       user: str) -> Dict[str, Any]:
        """Validate workflow against policy rules."""
        try:
            # Create policy context for workflow execution
            context = PolicyContext(
                user=user,
                resource=f"workflow:{blueprint.name}",
                action="execute",
                environment="production" if "production" in blueprint.tags else "development",
                metadata={
                    "blueprint_category": blueprint.category.value,
                    "estimated_duration": blueprint.estimated_duration.total_seconds() if blueprint.estimated_duration else 0,
                    "resource_requirements": blueprint.resource_requirements,
                    "requires_approval": any(step.requires_approval for step in blueprint.steps),
                    "has_rollback": blueprint.rollback_plan is not None and blueprint.rollback_plan.enabled
                }
            )
            
            # Evaluate policies
            evaluation = await self.policy_engine.evaluate_policies([blueprint], context)
            
            return {
                "allowed": evaluation.decision == PolicyDecision.ALLOW,
                "decision": evaluation.decision.value,
                "violations": evaluation.violations,
                "conditions": evaluation.conditions,
                "warnings": evaluation.warnings,
                "recommendations": evaluation.recommendations
            }
            
        except Exception as e:
            logger.error(f"Policy validation failed: {e}")
            return {
                "allowed": False,
                "decision": "error",
                "violations": [f"Policy validation error: {str(e)}"],
                "conditions": {},
                "warnings": [],
                "recommendations": []
            }
    
    async def get_workflow_permissions(self, user: str, 
                                     blueprint: WorkflowBlueprint) -> Dict[str, List[str]]:
        """Get workflow permissions for user."""
        try:
            # Check if user has workflow execution permissions
            permissions = {
                "execute": [],
                "approve": [],
                "view": [],
                "admin": []
            }
            
            # Basic permissions
            permissions["view"].append("workflow:view")
            
            # Execute permission
            policy_result = await self.validate_workflow_policies(blueprint, user)
            if policy_result["allowed"]:
                permissions["execute"].append("workflow:execute")
            
            # Approval permissions for specified approvers
            for step in blueprint.steps:
                if step.requires_approval and user in step.approvers:
                    permissions["approve"].append(f"workflow:approve:{step.step_id}")
            
            # Admin permissions (placeholder - would be based on role management)
            if user in ["admin", "operations_manager", "security_admin"]:
                permissions["admin"].append("workflow:admin")
                permissions["approve"].extend(["workflow:approve:all"])
            
            return permissions
            
        except Exception as e:
            logger.error(f"Failed to get workflow permissions: {e}")
            return {
                "execute": [],
                "approve": [],
                "view": ["workflow:view"],
                "admin": []
            }
    
    async def enforce_workflow_policies(self, execution: WorkflowExecution) -> bool:
        """Enforce policies during workflow execution."""
        try:
            # Get blueprint for policy enforcement
            # This would load from storage or cache
            blueprint = await self._get_blueprint(execution.blueprint_id)
            if not blueprint:
                logger.error(f"Blueprint not found for execution: {execution.execution_id}")
                return False
            
            # Validate policies
            policy_result = await self.validate_workflow_policies(blueprint, execution.created_by)
            
            if not policy_result["allowed"]:
                logger.warning(f"Policy violation blocked workflow: {policy_result['violations']}")
                return False
            
            # Continue enforcement during execution
            return True
            
        except Exception as e:
            logger.error(f"Policy enforcement failed: {e}")
            return False
    
    async def _get_blueprint(self, blueprint_id: str) -> Optional[WorkflowBlueprint]:
        """Get workflow blueprint."""
        # This would load from persistent storage or cache
        # For now, return None as placeholder
        return None


class WorkflowInventoryIntegration:
    """Integrate workflows with fleet inventory."""
    
    def __init__(self, inventory_tools: EnhancedInventoryTools):
        """Initialize workflow inventory integration."""
        self.inventory_tools = inventory_tools
    
    async def get_workflow_targets(self, blueprint: WorkflowBlueprint, 
                                 parameters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get targets for workflow execution."""
        try:
            targets = []
            
            # Get fleet status to determine available targets
            fleet_status = await self.inventory_tools.get_fleet_status()
            
            if not fleet_status or 'targets' not in fleet_status:
                return targets
            
            # Filter targets based on workflow requirements
            for target_name, target_data in fleet_status['targets'].items():
                if self._is_target_compatible(target_data, blueprint, parameters):
                    targets.append({
                        "name": target_name,
                        "type": target_data.get('type', 'unknown'),
                        "status": target_data.get('status', 'unknown'),
                        "health_score": target_data.get('health_score', 0),
                        "capabilities": target_data.get('capabilities', []),
                        "metadata": target_data.get('metadata', {})
                    })
            
            return targets
            
        except Exception as e:
            logger.error(f"Failed to get workflow targets: {e}")
            return []
    
    async def validate_target_compatibility(self, targets: List[Dict[str, Any]], 
                                          blueprint: WorkflowBlueprint) -> Dict[str, Any]:
        """Validate target compatibility with workflow."""
        try:
            validation_result = {
                "compatible": True,
                "errors": [],
                "warnings": [],
                "recommendations": []
            }
            
            # Check if any targets are available
            if not targets:
                validation_result["compatible"] = False
                validation_result["errors"].append("No compatible targets found for workflow execution")
                return validation_result
            
            # Validate resource requirements
            resource_reqs = blueprint.resource_requirements
            for target in targets:
                # Check CPU requirements
                target_cpu = target.get('metadata', {}).get('cpu_cores', 0)
                required_cpu = resource_reqs.get('cpu_cores', 0)
                if target_cpu < required_cpu:
                    validation_result["warnings"].append(
                        f"Target {target['name']} may not have sufficient CPU cores ({target_cpu} < {required_cpu})"
                    )
                
                # Check memory requirements
                target_memory = target.get('metadata', {}).get('memory_gb', 0)
                required_memory = resource_reqs.get('memory_gb', 0)
                if target_memory < required_memory:
                    validation_result["warnings"].append(
                        f"Target {target['name']} may not have sufficient memory ({target_memory}GB < {required_memory}GB)"
                    )
            
            # Check health status
            unhealthy_targets = [t for t in targets if t.get('health_score', 100) < 70]
            if unhealthy_targets:
                validation_result["warnings"].append(
                    f"{len(unhealthy_targets)} targets have low health scores"
                )
            
            # Validate workflow category compatibility
            if blueprint.category.value == "provisioning":
                provisioning_targets = [t for t in targets if 'provisionable' in t.get('capabilities', [])]
                if not provisioning_targets:
                    validation_result["compatible"] = False
                    validation_result["errors"].append("No targets with provisioning capabilities found")
            
            return validation_result
            
        except Exception as e:
            logger.error(f"Failed to validate target compatibility: {e}")
            return {
                "compatible": False,
                "errors": [f"Validation error: {str(e)}"],
                "warnings": [],
                "recommendations": []
            }
    
    async def get_target_workload_info(self, target_name: str) -> Optional[Dict[str, Any]]:
        """Get workload information for a target."""
        try:
            # Get target details from inventory
            target_info = await self.inventory_tools.get_target_info(target_name)
            
            if not target_info:
                return None
            
            # Extract workload information
            workload_info = {
                "target_name": target_name,
                "containers": target_info.get('containers', []),
                "services": target_info.get('services', []),
                "resource_usage": target_info.get('resource_usage', {}),
                "performance_metrics": target_info.get('performance_metrics', {}),
                "last_backup": target_info.get('last_backup'),
                "compliance_status": target_info.get('compliance_status', 'unknown')
            }
            
            return workload_info
            
        except Exception as e:
            logger.error(f"Failed to get target workload info: {e}")
            return None
    
    async def reserve_targets_for_workflow(self, execution_id: str, 
                                         targets: List[str]) -> bool:
        """Reserve targets for workflow execution."""
        try:
            # Mark targets as reserved for the workflow
            for target_name in targets:
                await self.inventory_tools.update_target_metadata(
                    target_name, 
                    {
                        "reserved_for_workflow": execution_id,
                        "reservation_timestamp": datetime.now(timezone.utc).isoformat()
                    }
                )
            
            logger.info(f"Reserved {len(targets)} targets for workflow {execution_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to reserve targets: {e}")
            return False
    
    async def release_target_reservations(self, execution_id: str) -> bool:
        """Release target reservations after workflow completion."""
        try:
            # Get all targets reserved for this workflow
            fleet_status = await self.inventory_tools.get_fleet_status()
            
            if not fleet_status or 'targets' not in fleet_status:
                return False
            
            reserved_targets = []
            for target_name, target_data in fleet_status['targets'].items():
                reserved_for = target_data.get('metadata', {}).get('reserved_for_workflow')
                if reserved_for == execution_id:
                    reserved_targets.append(target_name)
            
            # Release reservations
            for target_name in reserved_targets:
                await self.inventory_tools.update_target_metadata(
                    target_name,
                    {
                        "reserved_for_workflow": None,
                        "reservation_timestamp": None
                    }
                )
            
            logger.info(f"Released {len(reserved_targets)} target reservations for workflow {execution_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to release target reservations: {e}")
            return False
    
    def _is_target_compatible(self, target_data: Dict[str, Any], 
                            blueprint: WorkflowBlueprint, 
                            parameters: Dict[str, Any]) -> bool:
        """Check if target is compatible with workflow."""
        try:
            # Check target status
            if target_data.get('status') not in ['active', 'healthy']:
                return False
            
            # Check health score
            health_score = target_data.get('health_score', 0)
            if health_score < 50:  # Minimum health threshold
                return False
            
            # Check capabilities based on workflow category
            capabilities = target_data.get('capabilities', [])
            
            if blueprint.category.value == "provisioning":
                return 'provisionable' in capabilities
            elif blueprint.category.value == "backup":
                return 'backup-capable' in capabilities
            elif blueprint.category.value == "upgrade":
                return 'upgradable' in capabilities
            elif blueprint.category.value == "recovery":
                return 'recoverable' in capabilities
            elif blueprint.category.value == "monitoring":
                return 'monitorable' in capabilities
            
            # Default: any target is compatible
            return True
            
        except Exception as e:
            logger.error(f"Failed to check target compatibility: {e}")
            return False


class WorkflowEventIntegration:
    """Integrate workflows with event system."""
    
    def __init__(self, event_collector: EventCollector):
        """Initialize workflow event integration."""
        self.event_collector = event_collector
    
    async def emit_workflow_event(self, execution: WorkflowExecution, 
                                event_type: str, details: Dict[str, Any]) -> None:
        """Emit workflow events."""
        try:
            # Create system event
            event = SystemEvent(
                event_id=details.get('event_id', f"workflow-{execution.execution_id}-{event_type}"),
                event_type=EventType.WORKFLOW,
                severity=self._determine_event_severity(event_type, details),
                source=EventSource.WORKFLOW_ENGINE,
                category=EventCategory.WORKFLOW,
                timestamp=datetime.now(timezone.utc),
                data={
                    "execution_id": execution.execution_id,
                    "blueprint_name": execution.blueprint_name,
                    "event_type": event_type,
                    "details": details,
                    "workflow_status": execution.status.value,
                    "current_step": execution.current_step,
                    "parameters": execution.parameters
                }
            )
            
            # Collect the event
            await self.event_collector.collect_event(event)
            
            # Also emit to workflow-specific event stream
            await self._emit_workflow_specific_event(execution, event_type, details)
            
        except Exception as e:
            logger.error(f"Failed to emit workflow event: {e}")
    
    async def track_workflow_metrics(self, execution: WorkflowExecution) -> Dict[str, Any]:
        """Track workflow execution metrics."""
        try:
            metrics = {
                "execution_id": execution.execution_id,
                "blueprint_name": execution.blueprint_name,
                "status": execution.status.value,
                "start_time": execution.start_time.isoformat(),
                "end_time": execution.end_time.isoformat() if execution.end_time else None,
                "total_execution_time_seconds": execution.get_total_execution_time().total_seconds(),
                "current_step": execution.current_step,
                "completed_steps": execution.get_completed_steps(),
                "failed_steps": execution.get_failed_steps(),
                "step_count": len(execution.step_results),
                "approval_count": len(execution.approvals),
                "rollback_executed": execution.rollback_executed,
                "created_by": execution.created_by,
                "context": execution.context
            }
            
            # Emit metrics event
            await self.emit_workflow_event(
                execution,
                "workflow_metrics",
                {
                    "metrics": metrics,
                    "event_category": "metrics"
                }
            )
            
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to track workflow metrics: {e}")
            return {}
    
    async def emit_workflow_alert(self, execution: WorkflowExecution, 
                                alert_type: str, message: str, 
                                severity: str = "warning") -> None:
        """Emit workflow alerts."""
        try:
            # Map severity to event severity
            event_severity = {
                "critical": EventSeverity.CRITICAL,
                "warning": EventSeverity.WARNING,
                "info": EventSeverity.INFO
            }.get(severity.lower(), EventSeverity.WARNING)
            
            # Create alert event
            alert_event = SystemEvent(
                event_id=f"alert-{execution.execution_id}-{alert_type}",
                event_type=EventType.WORKFLOW,
                severity=event_severity,
                source=EventSource.WORKFLOW_ENGINE,
                category=EventCategory.ALERT,
                timestamp=datetime.now(timezone.utc),
                data={
                    "execution_id": execution.execution_id,
                    "blueprint_name": execution.blueprint_name,
                    "alert_type": alert_type,
                    "message": message,
                    "severity": severity,
                    "workflow_status": execution.status.value,
                    "current_step": execution.current_step,
                    "parameters": execution.parameters
                }
            )
            
            # Collect the alert event
            await self.event_collector.collect_event(alert_event)
            
        except Exception as e:
            logger.error(f"Failed to emit workflow alert: {e}")
    
    async def get_workflow_events(self, execution_id: str, 
                                event_types: List[str] = None,
                                start_time: Optional[datetime] = None,
                                end_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Get workflow events for analysis."""
        try:
            # This would query the event collector for workflow events
            # For now, return empty list as placeholder
            return []
            
        except Exception as e:
            logger.error(f"Failed to get workflow events: {e}")
            return []
    
    async def _determine_event_severity(self, event_type: str, details: Dict[str, Any]) -> EventSeverity:
        """Determine event severity based on event type and details."""
        # Map event types to severities
        severity_mapping = {
            "workflow_started": EventSeverity.INFO,
            "workflow_completed": EventSeverity.INFO,
            "workflow_failed": EventSeverity.CRITICAL,
            "workflow_cancelled": EventSeverity.WARNING,
            "workflow_paused": EventSeverity.INFO,
            "workflow_resumed": EventSeverity.INFO,
            "step_started": EventSeverity.INFO,
            "step_completed": EventSeverity.INFO,
            "step_failed": EventSeverity.WARNING,
            "step_retry": EventSeverity.WARNING,
            "approval_requested": EventSeverity.INFO,
            "approval_granted": EventSeverity.INFO,
            "approval_denied": EventSeverity.WARNING,
            "rollback_started": EventSeverity.WARNING,
            "rollback_completed": EventSeverity.WARNING,
            "policy_violation": EventSeverity.CRITICAL,
            "resource_exhausted": EventSeverity.CRITICAL,
            "timeout_occurred": EventSeverity.WARNING
        }
        
        return severity_mapping.get(event_type, EventSeverity.INFO)
    
    async def _emit_workflow_specific_event(self, execution: WorkflowExecution, 
                                          event_type: str, details: Dict[str, Any]):
        """Emit workflow-specific events to dedicated stream."""
        try:
            # This would integrate with workflow-specific event processing
            # For now, just log the event
            logger.info(f"Workflow event: {execution.execution_id} - {event_type} - {details}")
            
        except Exception as e:
            logger.error(f"Failed to emit workflow-specific event: {e}")


class WorkflowCapabilityIntegration:
    """Integrate workflows with capability executor."""
    
    def __init__(self, capability_executor: CapabilityExecutor):
        """Initialize workflow capability integration."""
        self.capability_executor = capability_executor
    
    async def execute_workflow_step_capability(self, step: WorkflowStep, 
                                             execution_context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute workflow step using capability executor."""
        try:
            # Map workflow step types to capability operations
            operation_mapping = {
                "validation": "validate_workflow_step",
                "resource_allocation": "allocate_resources",
                "container_operations": "container_management",
                "service_deployment": "service_deployment",
                "network_configuration": "network_management",
                "health_validation": "health_check",
                "backup": "backup_operations",
                "restore": "restore_operations",
                "snapshot": "snapshot_operations",
                "upgrade": "upgrade_operations",
                "testing": "testing_operations",
                "configuration": "configuration_management",
                "discovery": "discovery_operations",
                "transfer": "data_transfer",
                "maintenance": "maintenance_operations"
            }
            
            operation_type = operation_mapping.get(step.step_type.value)
            if not operation_type:
                return {
                    "success": False,
                    "message": f"No capability operation mapped for step type: {step.step_type.value}"
                }
            
            # Execute the capability operation
            result = await self.capability_executor.execute_operation(
                operation_type=operation_type,
                parameters={
                    **step.parameters,
                    **execution_context,
                    "step_id": step.step_id,
                    "workflow_step_type": step.step_type.value
                }
            )
            
            return {
                "success": result.success,
                "message": result.message,
                "data": result.data,
                "operation_type": operation_type
            }
            
        except Exception as e:
            logger.error(f"Failed to execute workflow step capability: {e}")
            return {
                "success": False,
                "message": f"Capability execution error: {str(e)}"
            }
    
    async def validate_step_capability(self, step: WorkflowStep, 
                                     execution_context: Dict[str, Any]) -> Dict[str, Any]:
        """Validate step capability before execution."""
        try:
            # Check if capability is available
            operation_mapping = {
                "validation": "validate_workflow_step",
                "resource_allocation": "allocate_resources",
                "container_operations": "container_management",
                "service_deployment": "service_deployment",
                "network_configuration": "network_management",
                "health_validation": "health_check",
                "backup": "backup_operations",
                "restore": "restore_operations",
                "snapshot": "snapshot_operations",
                "upgrade": "upgrade_operations",
                "testing": "testing_operations",
                "configuration": "configuration_management",
                "discovery": "discovery_operations",
                "transfer": "data_transfer",
                "maintenance": "maintenance_operations"
            }
            
            operation_type = operation_mapping.get(step.step_type.value)
            if not operation_type:
                return {
                    "valid": False,
                    "error": f"No capability operation available for step type: {step.step_type.value}"
                }
            
            # Validate parameters for the capability
            validation_result = await self.capability_executor.validate_operation(
                operation_type=operation_type,
                parameters={
                    **step.parameters,
                    **execution_context
                }
            )
            
            return {
                "valid": validation_result.success,
                "error": validation_result.message if not validation_result.success else None,
                "warnings": validation_result.data.get("warnings", []) if validation_result.data else []
            }
            
        except Exception as e:
            logger.error(f"Failed to validate step capability: {e}")
            return {
                "valid": False,
                "error": f"Validation error: {str(e)}"
            }


class WorkflowOrchestrator:
    """Main orchestrator for workflow integrations."""
    
    def __init__(self, policy_integration: WorkflowPolicyIntegration,
                 inventory_integration: WorkflowInventoryIntegration,
                 event_integration: WorkflowEventIntegration,
                 capability_integration: WorkflowCapabilityIntegration):
        """Initialize workflow orchestrator."""
        self.policy_integration = policy_integration
        self.inventory_integration = inventory_integration
        self.event_integration = event_integration
        self.capability_integration = capability_integration
    
    async def prepare_workflow_execution(self, blueprint: WorkflowBlueprint,
                                       parameters: Dict[str, Any],
                                       user: str) -> Dict[str, Any]:
        """Prepare workflow execution with all integrations."""
        try:
            preparation_result = {
                "ready": True,
                "errors": [],
                "warnings": [],
                "recommendations": [],
                "targets": [],
                "permissions": {}
            }
            
            # 1. Policy validation
            policy_result = await self.policy_integration.validate_workflow_policies(blueprint, user)
            if not policy_result["allowed"]:
                preparation_result["ready"] = False
                preparation_result["errors"].extend(policy_result["violations"])
            
            preparation_result["warnings"].extend(policy_result["warnings"])
            preparation_result["recommendations"].extend(policy_result["recommendations"])
            
            # 2. Get workflow targets
            targets = await self.inventory_integration.get_workflow_targets(blueprint, parameters)
            preparation_result["targets"] = targets
            
            # 3. Validate target compatibility
            compatibility_result = await self.inventory_integration.validate_target_compatibility(targets, blueprint)
            if not compatibility_result["compatible"]:
                preparation_result["ready"] = False
                preparation_result["errors"].extend(compatibility_result["errors"])
            
            preparation_result["warnings"].extend(compatibility_result["warnings"])
            preparation_result["recommendations"].extend(compatibility_result["recommendations"])
            
            # 4. Get user permissions
            permissions = await self.policy_integration.get_workflow_permissions(user, blueprint)
            preparation_result["permissions"] = permissions
            
            return preparation_result
            
        except Exception as e:
            logger.error(f"Failed to prepare workflow execution: {e}")
            return {
                "ready": False,
                "errors": [f"Preparation error: {str(e)}"],
                "warnings": [],
                "recommendations": [],
                "targets": [],
                "permissions": {}
            }
    
    async def execute_workflow_step_with_integration(self, execution: WorkflowExecution,
                                                   step: WorkflowStep) -> Dict[str, Any]:
        """Execute workflow step with full integration."""
        try:
            execution_context = {
                "execution_id": execution.execution_id,
                "blueprint_name": execution.blueprint_name,
                "created_by": execution.created_by,
                "current_step": step.step_id,
                "parameters": execution.parameters,
                "context": execution.context
            }
            
            # 1. Validate step capability
            validation_result = await self.capability_integration.validate_step_capability(
                step, execution_context
            )
            
            if not validation_result["valid"]:
                return {
                    "success": False,
                    "message": validation_result["error"],
                    "validation_errors": [validation_result["error"]]
                }
            
            # 2. Emit step started event
            await self.event_integration.emit_workflow_event(
                execution,
                "step_started",
                {
                    "step_id": step.step_id,
                    "step_name": step.name,
                    "validation_warnings": validation_result.get("warnings", [])
                }
            )
            
            # 3. Execute step with capability executor
            result = await self.capability_integration.execute_workflow_step_capability(
                step, execution_context
            )
            
            # 4. Emit step completion event
            event_type = "step_completed" if result["success"] else "step_failed"
            await self.event_integration.emit_workflow_event(
                execution,
                event_type,
                {
                    "step_id": step.step_id,
                    "step_name": step.name,
                    "success": result["success"],
                    "message": result["message"],
                    "operation_type": result.get("operation_type")
                }
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to execute workflow step with integration: {e}")
            return {
                "success": False,
                "message": f"Integration execution error: {str(e)}"
            }
    
    async def cleanup_workflow_execution(self, execution: WorkflowExecution) -> bool:
        """Cleanup after workflow execution."""
        try:
            # Release any reserved targets
            await self.inventory_integration.release_target_reservations(execution.execution_id)
            
            # Emit workflow completion events
            await self.event_integration.track_workflow_metrics(execution)
            
            # Emit final completion event
            await self.event_integration.emit_workflow_event(
                execution,
                "workflow_cleanup_completed",
                {
                    "execution_time": execution.get_total_execution_time().total_seconds(),
                    "completed_steps": execution.get_completed_steps(),
                    "failed_steps": execution.get_failed_steps()
                }
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to cleanup workflow execution: {e}")
            return False