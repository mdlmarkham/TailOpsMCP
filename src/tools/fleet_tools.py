"""Fleet management tools for Gateway mode with policy-gated operations."""

import logging
import uuid
from typing import Literal, Union, Optional, List, Dict, Any
from datetime import datetime
from fastmcp import FastMCP

from src.auth.middleware import secure_tool
from src.server.utils import format_response, format_error
from src.services.policy_gate import OperationTier, ValidationMode
from src.services.executor_factory import ExecutorFactory
from src.services.discovery_manager import DiscoveryManager
from src.services.fleet_inventory_persistence import FleetInventoryPersistence
from src.models.fleet_inventory import Node, Event, EventSeverity
from src.utils.audit import AuditLogger
from src.utils.gateway_mode import is_gateway_mode

logger = logging.getLogger(__name__)
audit = AuditLogger()


def register_tools(mcp: FastMCP):
    """Register fleet management tools with MCP instance for Gateway mode."""

    @mcp.tool()
    @secure_tool("fleet_discover")
    async def fleet_discover(
        targets: Optional[List[str]] = None,
        force_refresh: bool = False,
        format: Literal["json", "toon"] = "toon",
    ) -> Union[dict, str]:
        """Run fleet discovery and return summary.

        Args:
            targets: Optional list of specific targets to discover (all if None)
            force_refresh: Force fresh discovery even if cached data exists
            format: Response format - 'toon' (compact, default) or 'json' (verbose)
        """
        try:
            # Check if in gateway mode
            if not is_gateway_mode():
                return format_error(
                    "fleet_discover", "Operation only available in gateway mode"
                )

            # Use Policy Gate for authorization
            from src.server.dependencies import deps

            policy_gate = deps.policy_gate
            await policy_gate.authorize(
                operation="fleet_discover", target="gateway", tier=OperationTier.OBSERVE
            )

            # Initialize discovery manager
            discovery_manager = DiscoveryManager()

            # Run discovery
            discovery_result = await discovery_manager.pipeline.run_discovery(
                targets=targets, force_refresh=force_refresh
            )

            # Format response
            if format == "toon":
                summary = {
                    "discovered_nodes": len(discovery_result.nodes),
                    "discovered_services": len(discovery_result.services),
                    "discovered_containers": len(discovery_result.containers),
                    "timestamp": datetime.now().isoformat(),
                    "status": "success",
                }
                return format_response("fleet_discover", summary)
            else:
                return format_response("fleet_discover", discovery_result.to_dict())

        except Exception as e:
            logger.error(f"Fleet discovery failed: {e}")
            audit.log_operation(
                operation="fleet_discover",
                target="gateway",
                success=False,
                error=str(e),
            )
            return format_error("fleet_discover", str(e))

    @mcp.tool()
    @secure_tool("fleet_inventory_get")
    async def fleet_inventory_get(
        format: Literal["json", "toon"] = "toon",
    ) -> Union[dict, str]:
        """Return latest fleet inventory snapshot.

        Args:
            format: Response format - 'toon' (compact, default) or 'json' (verbose)
        """
        try:
            # Check if in gateway mode
            if not is_gateway_mode():
                return format_error(
                    "fleet_inventory_get", "Operation only available in gateway mode"
                )

            # Use Policy Gate for authorization
            from src.server.dependencies import deps

            policy_gate = deps.policy_gate
            await policy_gate.authorize(
                operation="fleet_inventory_get",
                target="gateway",
                tier=OperationTier.OBSERVE,
            )

            # Get latest inventory
            persistence = FleetInventoryPersistence()
            inventory = persistence.load_latest()

            if not inventory:
                return format_error(
                    "fleet_inventory_get", "No inventory data available"
                )

            # Format response
            if format == "toon":
                summary = {
                    "total_nodes": len(inventory.nodes),
                    "total_services": len(inventory.services),
                    "total_containers": len(inventory.containers),
                    "last_updated": inventory.last_updated.isoformat()
                    if inventory.last_updated
                    else None,
                    "status": "success",
                }
                return format_response("fleet_inventory_get", summary)
            else:
                return format_response("fleet_inventory_get", inventory.to_dict())

        except Exception as e:
            logger.error(f"Fleet inventory retrieval failed: {e}")
            audit.log_operation(
                operation="fleet_inventory_get",
                target="gateway",
                success=False,
                error=str(e),
            )
            return format_error("fleet_inventory_get", str(e))

    @mcp.tool()
    @secure_tool("fleet_node_health")
    async def fleet_node_health(node_id: str) -> dict:
        """Get health summary and last events for a specific node.

        Args:
            node_id: ID of the node to check
        """
        try:
            # Check if in gateway mode
            if not is_gateway_mode():
                return format_error(
                    "fleet_node_health", "Operation only available in gateway mode"
                )

            # Use Policy Gate for authorization
            from src.server.dependencies import deps

            policy_gate = deps.policy_gate
            await policy_gate.authorize(
                operation="fleet_node_health",
                target=node_id,
                tier=OperationTier.OBSERVE,
            )

            # Get latest inventory
            persistence = FleetInventoryPersistence()
            inventory = persistence.load_latest()

            if not inventory:
                return format_error("fleet_node_health", "No inventory data available")

            # Find the node
            node = inventory.get_node(node_id)
            if not node:
                return format_error("fleet_node_health", f"Node {node_id} not found")

            # Get recent events for this node
            recent_events = inventory.get_events_for_node(node_id, limit=10)

            # Calculate health status
            health_status = _calculate_node_health(node, recent_events)

            result = {
                "node_id": node_id,
                "health_status": health_status,
                "last_seen": node.last_seen.isoformat() if node.last_seen else None,
                "recent_events": [event.to_dict() for event in recent_events],
                "status": "success",
            }

            return format_response("fleet_node_health", result)

        except Exception as e:
            logger.error(f"Node health check failed for {node_id}: {e}")
            audit.log_operation(
                operation="fleet_node_health",
                target=node_id,
                success=False,
                error=str(e),
            )
            return format_error("fleet_node_health", str(e))

    @mcp.tool()
    @secure_tool("fleet_operation_plan")
    async def fleet_operation_plan(
        op_name: str, targets: List[str], parameters: Dict[str, Any]
    ) -> dict:
        """Create an operation plan for fleet-wide operations.

        Args:
            op_name: Operation name (update_packages, restart_service, etc.)
            targets: List of target node IDs
            parameters: Operation-specific parameters
        """
        try:
            # Check if in gateway mode
            if not is_gateway_mode():
                return format_error(
                    "fleet_operation_plan", "Operation only available in gateway mode"
                )

            # Validate operation name
            valid_operations = [
                "update_packages",
                "restart_service",
                "docker_compose_pull_up",
                "snapshot_or_backup",
                "restore",
            ]
            if op_name not in valid_operations:
                return format_error(
                    "fleet_operation_plan",
                    f"Invalid operation: {op_name}. Valid operations: {valid_operations}",
                )

            # Use Policy Gate for authorization (planning phase)
            from src.server.dependencies import deps

            policy_gate = deps.policy_gate
            for target in targets:
                await policy_gate.authorize(
                    operation=f"plan_{op_name}",
                    target=target,
                    tier=OperationTier.CONTROL,
                    parameters=parameters,
                )

            # Create operation plan
            plan_id = str(uuid.uuid4())
            plan = {
                "plan_id": plan_id,
                "operation": op_name,
                "targets": targets,
                "parameters": parameters,
                "created_at": datetime.now().isoformat(),
                "status": "planned",
                "estimated_impact": _estimate_operation_impact(
                    op_name, targets, parameters
                ),
            }

            # Store plan for later execution
            _store_operation_plan(plan_id, plan)

            return format_response("fleet_operation_plan", plan)

        except Exception as e:
            logger.error(f"Operation planning failed for {op_name}: {e}")
            audit.log_operation(
                operation="fleet_operation_plan",
                target="gateway",
                success=False,
                error=str(e),
            )
            return format_error("fleet_operation_plan", str(e))

    @mcp.tool()
    @secure_tool("fleet_operation_execute")
    async def fleet_operation_execute(plan_id: str) -> dict:
        """Execute a previously created operation plan.

        Args:
            plan_id: ID of the operation plan to execute
        """
        try:
            # Check if in gateway mode
            if not is_gateway_mode():
                return format_error(
                    "fleet_operation_execute",
                    "Operation only available in gateway mode",
                )

            # Retrieve operation plan
            plan = _retrieve_operation_plan(plan_id)
            if not plan:
                return format_error(
                    "fleet_operation_execute", f"Plan {plan_id} not found"
                )

            # Use Policy Gate for authorization (execution phase)
            from src.server.dependencies import deps

            policy_gate = deps.policy_gate
            for target in plan["targets"]:
                await policy_gate.authorize(
                    operation=plan["operation"],
                    target=target,
                    tier=OperationTier.CONTROL,
                    parameters=plan["parameters"],
                    mode=ValidationMode.STRICT,
                )

            # Execute operation
            results = await _execute_operation_plan(plan)

            # Update plan status
            plan["status"] = "executed"
            plan["executed_at"] = datetime.now().isoformat()
            plan["results"] = results

            _store_operation_plan(plan_id, plan)

            return format_response(
                "fleet_operation_execute",
                {"plan_id": plan_id, "status": "executed", "results": results},
            )

        except Exception as e:
            logger.error(f"Operation execution failed for plan {plan_id}: {e}")
            audit.log_operation(
                operation="fleet_operation_execute",
                target="gateway",
                success=False,
                error=str(e),
            )
            return format_error("fleet_operation_execute", str(e))


def _calculate_node_health(node: Node, recent_events: List[Event]) -> str:
    """Calculate health status based on node state and recent events."""
    if not node.last_seen:
        return "unknown"

    # Check if node is unreachable
    time_since_last_seen = (datetime.now() - node.last_seen).total_seconds()
    if time_since_last_seen > 300:  # 5 minutes
        return "unreachable"

    # Check for recent error events
    error_events = [
        e
        for e in recent_events
        if e.severity in [EventSeverity.ERROR, EventSeverity.CRITICAL]
    ]
    if error_events:
        return "degraded"

    # Check for recent warning events
    warning_events = [e for e in recent_events if e.severity == EventSeverity.WARNING]
    if warning_events:
        return "warning"

    return "healthy"


def _estimate_operation_impact(
    op_name: str, targets: List[str], parameters: Dict[str, Any]
) -> Dict[str, Any]:
    """Estimate the impact of an operation."""
    impact = {
        "targets_affected": len(targets),
        "estimated_duration": "5-15 minutes",
        "risk_level": "medium",
        "requires_approval": False,
    }

    if op_name == "update_packages":
        impact.update(
            {
                "estimated_duration": "10-30 minutes",
                "risk_level": "low",
                "description": "Package updates with potential service restarts",
            }
        )
    elif op_name == "restart_service":
        impact.update(
            {
                "estimated_duration": "1-5 minutes",
                "risk_level": "medium",
                "description": "Service restart with brief downtime",
            }
        )
    elif op_name == "docker_compose_pull_up":
        impact.update(
            {
                "estimated_duration": "5-15 minutes",
                "risk_level": "medium",
                "description": "Container updates with rolling restart",
            }
        )
    elif op_name == "snapshot_or_backup":
        impact.update(
            {
                "estimated_duration": "10-60 minutes",
                "risk_level": "low",
                "description": "Backup operation with minimal impact",
            }
        )
    elif op_name == "restore":
        impact.update(
            {
                "estimated_duration": "15-60 minutes",
                "risk_level": "high",
                "requires_approval": True,
                "description": "Restore operation with potential data loss",
            }
        )

    return impact


def _store_operation_plan(plan_id: str, plan: Dict[str, Any]):
    """Store operation plan for later retrieval."""
    # In a real implementation, this would persist to database or file
    # For now, we'll use a simple in-memory store
    if not hasattr(_store_operation_plan, "plans"):
        _store_operation_plan.plans = {}

    _store_operation_plan.plans[plan_id] = plan


def _retrieve_operation_plan(plan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve operation plan by ID."""
    if hasattr(_store_operation_plan, "plans"):
        return _store_operation_plan.plans.get(plan_id)
    return None


async def _execute_operation_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
    """Execute an operation plan across multiple targets."""
    results = {}
    op_name = plan["operation"]

    for target in plan["targets"]:
        try:
            # Get executor for target
            executor = ExecutorFactory.get_executor(target)

            # Execute operation based on type
            if op_name == "update_packages":
                result = await _execute_update_packages(executor, plan["parameters"])
            elif op_name == "restart_service":
                result = await _execute_restart_service(executor, plan["parameters"])
            elif op_name == "docker_compose_pull_up":
                result = await _execute_docker_compose_pull_up(
                    executor, plan["parameters"]
                )
            elif op_name == "snapshot_or_backup":
                result = await _execute_snapshot_or_backup(executor, plan["parameters"])
            elif op_name == "restore":
                result = await _execute_restore(executor, plan["parameters"])
            else:
                result = {"success": False, "error": f"Unknown operation: {op_name}"}

            results[target] = result

        except Exception as e:
            results[target] = {"success": False, "error": str(e)}

    return results


async def _execute_update_packages(
    executor, parameters: Dict[str, Any]
) -> Dict[str, Any]:
    """Execute package update operation."""
    # Safe package update with apt
    result = await executor.execute(
        command="update_packages",
        parameters={
            "update_only": parameters.get("update_only", True),
            "upgrade": parameters.get("upgrade", False),
            "packages": parameters.get("packages", []),
        },
        timeout=1800,  # 30 minutes timeout
    )
    return (
        result.to_dict()
        if hasattr(result, "to_dict")
        else {"success": result.success, "output": result.output}
    )


async def _execute_restart_service(
    executor, parameters: Dict[str, Any]
) -> Dict[str, Any]:
    """Execute service restart operation."""
    service = parameters.get("service")
    if not service:
        return {"success": False, "error": "Service name required"}

    result = await executor.execute(
        command="restart_service",
        parameters={"service": service},
        timeout=300,  # 5 minutes timeout
    )
    return (
        result.to_dict()
        if hasattr(result, "to_dict")
        else {"success": result.success, "output": result.output}
    )


async def _execute_docker_compose_pull_up(
    executor, parameters: Dict[str, Any]
) -> Dict[str, Any]:
    """Execute docker-compose pull and up operation."""
    stack = parameters.get("stack")
    if not stack:
        return {"success": False, "error": "Stack name required"}

    result = await executor.execute(
        command="docker_compose_pull_up",
        parameters={"stack": stack, "detach": parameters.get("detach", True)},
        timeout=900,  # 15 minutes timeout
    )
    return (
        result.to_dict()
        if hasattr(result, "to_dict")
        else {"success": result.success, "output": result.output}
    )


async def _execute_snapshot_or_backup(
    executor, parameters: Dict[str, Any]
) -> Dict[str, Any]:
    """Execute snapshot or backup operation."""
    # This would integrate with Proxmox or other backup systems
    result = await executor.execute(
        command="snapshot_or_backup",
        parameters={
            "type": parameters.get("type", "snapshot"),
            "target": parameters.get("target", "all"),
        },
        timeout=3600,  # 60 minutes timeout
    )
    return (
        result.to_dict()
        if hasattr(result, "to_dict")
        else {"success": result.success, "output": result.output}
    )


async def _execute_restore(executor, parameters: Dict[str, Any]) -> Dict[str, Any]:
    """Execute restore operation (admin-only)."""
    # This is a high-risk operation that requires additional validation
    result = await executor.execute(
        command="restore",
        parameters={
            "backup_id": parameters.get("backup_id"),
            "target": parameters.get("target"),
        },
        timeout=3600,  # 60 minutes timeout
    )
    return (
        result.to_dict()
        if hasattr(result, "to_dict")
        else {"success": result.success, "output": result.output}
    )


logger.info("Registered 5 fleet management tools for Gateway mode")
