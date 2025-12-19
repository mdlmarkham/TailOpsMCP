"""Stack management tools for TailOpsMCP with capability-driven operations."""

from __future__ import annotations

import os
from typing import Literal, Union
from fastmcp import FastMCP

from src.auth.middleware import secure_tool
from src.server.utils import format_response, format_error
from src.services.policy_gate import OperationTier, ValidationMode
from src.services.executor_factory import ExecutorFactory
from src.utils.audit import AuditLogger

logger = logging.getLogger(__name__)
audit = AuditLogger()

# Stack deployment history storage
STACKS_DIR = os.getenv("TAILOPS_STACKS_DIR", "/opt/stacks")
HISTORY_DIR = os.getenv("TAILOPS_HISTORY_DIR", "/var/lib/systemmanager/stack_history")


def register_tools(mcp: FastMCP):
    """Register stack management tools with MCP instance using capability-driven operations."""

    @mcp.tool()
    @secure_tool("deploy_stack")
    async def deploy_stack(
        stack: str, target: str = "local", dry_run: bool = False, force: bool = False
    ) -> dict:
        """Deploy a Docker stack.

        Args:
            target: Target system (default: "local")
            stack: Stack name to deploy
            dry_run: If True, simulate without executing
            force: If True, force deployment even if already running
        """
        try:
            # Use Policy Gate for authorization
            from src.server.dependencies import deps

            policy_gate = deps.policy_gate
            validation_mode = (
                ValidationMode.DRY_RUN if dry_run else ValidationMode.STRICT
            )

            await policy_gate.authorize(
                operation="deploy_stack",
                target=target,
                tier=OperationTier.CONTROL,
                parameters={"stack": stack, "force": force},
                mode=validation_mode,
            )

            if dry_run:
                return {
                    "success": True,
                    "dry_run": True,
                    "operation": "deploy_stack",
                    "stack": stack,
                    "target": target,
                    "message": "Operation would be executed in non-dry-run mode",
                }

            # Get executor for target
            executor = ExecutorFactory.get_executor(target)

            # Execute stack deployment
            result = await executor.execute(
                command="deploy_stack",
                parameters={"stack": stack, "force": force},
                timeout=300,
            )

            audit.log_operation(
                operation="deploy_stack",
                target=target,
                success=result.success,
                parameters={"stack": stack, "force": force},
            )

            if result.success:
                return {
                    "success": True,
                    "operation": "deploy_stack",
                    "stack": stack,
                    "target": target,
                    "output": result.output,
                }
            else:
                return {
                    "success": False,
                    "operation": "deploy_stack",
                    "stack": stack,
                    "target": target,
                    "error": result.error,
                }

        except Exception as e:
            audit.log_operation(
                operation="deploy_stack", target=target, success=False, error=str(e)
            )
            return format_error(e, "deploy_stack")

    @mcp.tool()
    @secure_tool("pull_stack")
    async def pull_stack(
        stack: str, target: str = "local", dry_run: bool = False
    ) -> dict:
        """Pull latest images for a Docker stack.

        Args:
            target: Target system (default: "local")
            stack: Stack name to pull images for
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
                operation="pull_stack",
                target=target,
                tier=OperationTier.CONTROL,
                parameters={"stack": stack},
                mode=validation_mode,
            )

            if dry_run:
                return {
                    "success": True,
                    "dry_run": True,
                    "operation": "pull_stack",
                    "stack": stack,
                    "target": target,
                    "message": "Operation would be executed in non-dry-run mode",
                }

            # Get executor for target
            executor = ExecutorFactory.get_executor(target)

            # Execute stack pull
            result = await executor.execute(
                command="pull_stack", parameters={"stack": stack}, timeout=600
            )

            audit.log_operation(
                operation="pull_stack",
                target=target,
                success=result.success,
                parameters={"stack": stack},
            )

            if result.success:
                return {
                    "success": True,
                    "operation": "pull_stack",
                    "stack": stack,
                    "target": target,
                    "output": result.output,
                }
            else:
                return {
                    "success": False,
                    "operation": "pull_stack",
                    "stack": stack,
                    "target": target,
                    "error": result.error,
                }

        except Exception as e:
            audit.log_operation(
                operation="pull_stack", target=target, success=False, error=str(e)
            )
            return format_error(e, "pull_stack")

    @mcp.tool()
    @secure_tool("restart_stack")
    async def restart_stack(
        stack: str, target: str = "local", dry_run: bool = False
    ) -> dict:
        """Restart a Docker stack.

        Args:
            target: Target system (default: "local")
            stack: Stack name to restart
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
                operation="restart_stack",
                target=target,
                tier=OperationTier.CONTROL,
                parameters={"stack": stack},
                mode=validation_mode,
            )

            if dry_run:
                return {
                    "success": True,
                    "dry_run": True,
                    "operation": "restart_stack",
                    "stack": stack,
                    "target": target,
                    "message": "Operation would be executed in non-dry-run mode",
                }

            # Get executor for target
            executor = ExecutorFactory.get_executor(target)

            # Execute stack restart
            result = await executor.execute(
                command="restart_stack", parameters={"stack": stack}, timeout=180
            )

            audit.log_operation(
                operation="restart_stack",
                target=target,
                success=result.success,
                parameters={"stack": stack},
            )

            if result.success:
                return {
                    "success": True,
                    "operation": "restart_stack",
                    "stack": stack,
                    "target": target,
                    "output": result.output,
                }
            else:
                return {
                    "success": False,
                    "operation": "restart_stack",
                    "stack": stack,
                    "target": target,
                    "error": result.error,
                }

        except Exception as e:
            audit.log_operation(
                operation="restart_stack", target=target, success=False, error=str(e)
            )
            return format_error(e, "restart_stack")

    @mcp.tool()
    @secure_tool("get_stack_status")
    async def get_stack_status(
        stack: str, target: str = "local", format: Literal["json", "toon"] = "toon"
    ) -> Union[dict, str]:
        """Get status of a Docker stack.

        Args:
            target: Target system (default: "local")
            stack: Stack name to get status for
            format: Response format - 'toon' (compact, default) or 'json' (verbose)
        """
        try:
            # Use Policy Gate for authorization
            from src.server.dependencies import deps

            policy_gate = deps.policy_gate
            await policy_gate.authorize(
                operation="get_stack_status",
                target=target,
                tier=OperationTier.OBSERVE,
                parameters={"stack": stack},
            )

            # Get executor for target
            executor = ExecutorFactory.get_executor(target)

            # Execute stack status query
            result = await executor.execute(
                command="stack_status", parameters={"stack": stack}, timeout=60
            )

            if result.success:
                return format_response(result.output, format)
            else:
                return format_error(result.error, "get_stack_status")

        except Exception as e:
            audit.log_operation(
                operation="get_stack_status", target=target, success=False, error=str(e)
            )
            return format_error(e, "get_stack_status")

    @mcp.tool()
    @secure_tool("list_stacks")
    async def list_stacks(
        target: str = "local", format: Literal["json", "toon"] = "toon"
    ) -> Union[dict, str]:
        """List all Docker stacks on the target system.

        Args:
            target: Target system (default: "local")
            format: Response format - 'toon' (compact, default) or 'json' (verbose)
        """
        try:
            # Use Policy Gate for authorization
            from src.server.dependencies import deps

            policy_gate = deps.policy_gate
            await policy_gate.authorize(
                operation="list_stacks", target=target, tier=OperationTier.OBSERVE
            )

            # Get executor for target
            executor = ExecutorFactory.get_executor(target)

            # Execute stack list query
            result = await executor.execute(
                command="list_stacks", parameters={}, timeout=30
            )

            if result.success:
                return format_response(result.output, format)
            else:
                return format_error(result.error, "list_stacks")

        except Exception as e:
            audit.log_operation(
                operation="list_stacks", target=target, success=False, error=str(e)
            )
            return format_error(e, "list_stacks")

    # Backward compatibility wrapper for existing stack operations
    @mcp.tool()
    @secure_tool("stack_operations")
    async def stack_operations(
        action: Literal["deploy", "pull", "restart", "status", "list"],
        stack_name: str = "",
        target: str = "local",
        dry_run: bool = False,
        force: bool = False,
        format: Literal["json", "toon"] = "toon",
    ) -> Union[dict, str]:
        """Perform stack operations (backward compatibility).

        Args:
            action: Operation to perform (deploy|pull|restart|status|list)
            stack_name: Stack name (required for deploy, pull, restart, status)
            target: Target system (default: "local")
            dry_run: If True, simulate without executing
            force: If True, force deployment even if already running
            format: Response format - 'toon' (compact, default) or 'json' (verbose)
        """
        try:
            if action == "deploy":
                if not stack_name:
                    return {
                        "success": False,
                        "error": "Stack name required for deploy operation",
                    }
                return await deploy_stack(target, stack_name, dry_run, force)
            elif action == "pull":
                if not stack_name:
                    return {
                        "success": False,
                        "error": "Stack name required for pull operation",
                    }
                return await pull_stack(target, stack_name, dry_run)
            elif action == "restart":
                if not stack_name:
                    return {
                        "success": False,
                        "error": "Stack name required for restart operation",
                    }
                return await restart_stack(target, stack_name, dry_run)
            elif action == "status":
                if not stack_name:
                    return {
                        "success": False,
                        "error": "Stack name required for status operation",
                    }
                return await get_stack_status(target, stack_name, format)
            elif action == "list":
                return await list_stacks(target, format)
            else:
                return {"success": False, "error": f"Invalid action: {action}"}

        except Exception as e:
            audit.log_operation(
                operation="stack_operations", target=target, success=False, error=str(e)
            )
            return format_error(e, "stack_operations")

    logger.info("Registered 6 stack management tools with capability-driven operations")
