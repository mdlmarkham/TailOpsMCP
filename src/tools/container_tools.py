"""Docker container management tools for TailOpsMCP with capability-driven operations."""

import logging
from typing import Literal, Union
from datetime import datetime
from datetime import timezone, timezone
from fastmcp import FastMCP
from src.auth.middleware import secure_tool
from src.server.utils import format_response, format_error
from src.services.policy_gate import OperationTier, ValidationMode
from src.services.executor_factory import ExecutorFactory
from src.utils.audit import AuditLogger

logger = logging.getLogger(__name__)
audit = AuditLogger()


def register_tools(mcp: FastMCP):
    """Register Docker container management tools with MCP instance using capability-driven operations."""

    @mcp.tool()
    @secure_tool("get_container_list")
    async def get_container_list(
        target: str = "local", format: Literal["json", "toon"] = "toon"
    ) -> Union[dict, str]:
        """List all Docker containers with status and image information.

        Args:
            target: Target system to query (default: "local")
            format: Response format - 'toon' (compact, default) or 'json' (verbose)
        """
        try:
            # Use Policy Gate for authorization

            # Get executor for target
            executor = ExecutorFactory.get_executor(target)

            # Execute container list query
            result = await executor.execute(
                command="list_containers", parameters={}, timeout=30
            )

            if result.success:
                return format_response(result.output, format)
            else:
                return format_error(result.error, "get_container_list")

        except Exception as e:
            audit.log_operation(
                operation="get_container_list",
                target=target,
                success=False,
                error=str(e),
            )
            return format_error(e, "get_container_list")

    @mcp.tool()
    @secure_tool("start_container")
    async def start_container(
        container: str, target: str = "local", dry_run: bool = False
    ) -> dict:
        """Start a Docker container.

        Args:
            target: Target system (default: "local")
            container: Container name or ID
            dry_run: If True, simulate without executing
        """
        try:
            # Use Policy Gate for authorization
            from src.server.dependencies import deps

            policy_gate = deps.policy_gate
            validation_mode = (
                ValidationMode.DRY_RUN if dry_run else ValidationMode.STRICT
            )

            await policy_gate.authorize(
                operation="start_container",
                target=target,
                tier=OperationTier.CONTROL,
                parameters={"container": container},
                mode=validation_mode,
            )

            if dry_run:
                return {
                    "success": True,
                    "dry_run": True,
                    "operation": "start_container",
                    "container": container,
                    "target": target,
                    "message": "Operation would be executed in non-dry-run mode",
                }

            # Get executor for target
            executor = ExecutorFactory.get_executor(target)

            # Execute container start
            result = await executor.execute(
                command="start_container",
                parameters={"container": container},
                timeout=60,
            )

            audit.log_operation(
                operation="start_container",
                target=target,
                success=result.success,
                parameters={"container": container},
            )

            if result.success:
                return {
                    "success": True,
                    "operation": "start_container",
                    "container": container,
                    "target": target,
                    "output": result.output,
                }
            else:
                return {
                    "success": False,
                    "operation": "start_container",
                    "container": container,
                    "target": target,
                    "error": result.error,
                }

        except Exception as e:
            audit.log_operation(
                operation="start_container", target=target, success=False, error=str(e)
            )
            return format_error(e, "start_container")

    @mcp.tool()
    @secure_tool("stop_container")
    async def stop_container(
        container: str, target: str = "local", dry_run: bool = False
    ) -> dict:
        """Stop a Docker container.

        Args:
            target: Target system (default: "local")
            container: Container name or ID
            dry_run: If True, simulate without executing
        """
        try:
            # Use Policy Gate for authorization
            from src.server.dependencies import deps

            policy_gate = deps.policy_gate
            validation_mode = (
                ValidationMode.DRY_RUN if dry_run else ValidationMode.STRICT
            )

            await policy_gate.authorize(
                operation="stop_container",
                target=target,
                tier=OperationTier.CONTROL,
                parameters={"container": container},
                mode=validation_mode,
            )

            if dry_run:
                return {
                    "success": True,
                    "dry_run": True,
                    "operation": "stop_container",
                    "container": container,
                    "target": target,
                    "message": "Operation would be executed in non-dry-run mode",
                }

            # Get executor for target
            executor = ExecutorFactory.get_executor(target)

            # Execute container stop
            result = await executor.execute(
                command="stop_container",
                parameters={"container": container},
                timeout=60,
            )

            audit.log_operation(
                operation="stop_container",
                target=target,
                success=result.success,
                parameters={"container": container},
            )

            if result.success:
                return {
                    "success": True,
                    "operation": "stop_container",
                    "container": container,
                    "target": target,
                    "output": result.output,
                }
            else:
                return {
                    "success": False,
                    "operation": "stop_container",
                    "container": container,
                    "target": target,
                    "error": result.error,
                }

        except Exception as e:
            audit.log_operation(
                operation="stop_container", target=target, success=False, error=str(e)
            )
            return format_error(e, "stop_container")

    @mcp.tool()
    @secure_tool("inspect_container")
    async def inspect_container(
        container: str, target: str = "local", format: Literal["json", "toon"] = "toon"
    ) -> Union[dict, str]:
        """Inspect a Docker container for detailed information.

        Args:
            target: Target system (default: "local")
            container: Container name or ID
            format: Response format - 'toon' (compact, default) or 'json' (verbose)
        """
        try:
            # Use Policy Gate for authorization
            from src.server.dependencies import deps

            policy_gate = deps.policy_gate
            await policy_gate.authorize(
                operation="inspect_container",
                target=target,
                tier=OperationTier.OBSERVE,
                parameters={"container": container},
            )

            # Get executor for target
            executor = ExecutorFactory.get_executor(target)

            # Execute container inspection
            result = await executor.execute(
                command="inspect_container",
                parameters={"container": container},
                timeout=30,
            )

            if result.success:
                return format_response(result.output, format)
            else:
                return format_error(result.error, "inspect_container")

        except Exception as e:
            audit.log_operation(
                operation="inspect_container",
                target=target,
                success=False,
                error=str(e),
            )
            return format_error(e, "inspect_container")

    @mcp.tool()
    @secure_tool("get_container_logs")
    async def get_container_logs(
        container: str, target: str = "local", lines: int = 100
    ) -> dict:
        """Get logs from a Docker container.

        Args:
            target: Target system (default: "local")
            container: Container name or ID
            lines: Number of log lines to retrieve
        """
        try:
            # Use Policy Gate for authorization
            from src.server.dependencies import deps

            policy_gate = deps.policy_gate
            await policy_gate.authorize(
                operation="get_container_logs",
                target=target,
                tier=OperationTier.OBSERVE,
                parameters={"container": container, "lines": lines},
            )

            # Get executor for target
            executor = ExecutorFactory.get_executor(target)

            # Execute container logs query
            result = await executor.execute(
                command="container_logs",
                parameters={"container": container, "lines": lines},
                timeout=30,
            )

            if result.success:
                return {
                    "success": True,
                    "container": container,
                    "target": target,
                    "lines": lines,
                    "logs": result.output,
                    "timestamp": datetime.now().isoformat(),
                }
            else:
                return {
                    "success": False,
                    "container": container,
                    "target": target,
                    "error": result.error,
                    "timestamp": datetime.now().isoformat(),
                }

        except Exception as e:
            audit.log_operation(
                operation="get_container_logs",
                target=target,
                success=False,
                error=str(e),
            )
            return format_error(e, "get_container_logs")

    # Backward compatibility wrapper for existing manage_container tool
    @mcp.tool()
    @secure_tool("manage_container")
    async def manage_container(
        action: Literal["start", "stop", "restart", "logs"],
        name_or_id: str,
        lines: int = 100,
        target: str = "local",
        dry_run: bool = False,
    ) -> dict:
        """Manage Docker container lifecycle: start, stop, restart, or get logs (backward compatibility).

        Args:
            action: Operation to perform (start|stop|restart|logs)
            name_or_id: Container name or ID
            lines: Number of log lines to retrieve (only for 'logs' action)
            target: Target system (default: "local")
            dry_run: If True, simulate without executing
        """
        try:
            if action == "start":
                return await start_container(
                    target=target, container=name_or_id, dry_run=dry_run
                )
            elif action == "stop":
                return await stop_container(
                    target=target, container=name_or_id, dry_run=dry_run
                )
            elif action == "restart":
                # For restart, we'll stop then start
                if dry_run:
                    return {
                        "success": True,
                        "dry_run": True,
                        "operation": "restart_container",
                        "container": name_or_id,
                        "target": target,
                        "message": "Operation would be executed in non-dry-run mode",
                    }

                stop_result = await stop_container(
                    target=target, container=name_or_id, dry_run=False
                )
                if not stop_result.get("success", False):
                    return stop_result

                start_result = await start_container(
                    target=target, container=name_or_id, dry_run=False
                )
                return {
                    "success": start_result.get("success", False),
                    "operation": "restart_container",
                    "container": name_or_id,
                    "target": target,
                    "stop_result": stop_result,
                    "start_result": start_result,
                }
            elif action == "logs":
                return await get_container_logs(
                    target=target, container=name_or_id, lines=lines
                )
            else:
                return {"success": False, "error": f"Invalid action: {action}"}

        except Exception as e:
            audit.log_operation(
                operation="manage_container", target=target, success=False, error=str(e)
            )
            return format_error(e, "manage_container")

    logger.info(
        "Registered 6 container management tools with capability-driven operations"
    )
