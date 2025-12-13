"""System monitoring tools for TailOpsMCP with capability-driven operations."""
import logging
from typing import Literal, Union, Optional
from datetime import datetime
from fastmcp import FastMCP
from src.auth.middleware import secure_tool
from src.server.utils import cached, format_response, format_error
from src.services.policy_gate import PolicyGate, OperationTier, ValidationMode
from src.services.executor_factory import ExecutorFactory
from src.services.target_registry import TargetRegistry
from src.utils.audit import AuditLogger

logger = logging.getLogger(__name__)
audit = AuditLogger()


def register_tools(mcp: FastMCP):
    """Register system monitoring tools with MCP instance using capability-driven operations."""

    @mcp.tool()
    @secure_tool("get_system_status")
    @cached(ttl_seconds=5)
    async def get_system_status(
        target: str = "local",
        format: Literal["json", "toon"] = "toon"
    ) -> Union[dict, str]:
        """Get comprehensive system status with CPU, memory, disk, and uptime.

        Args:
            target: Target system to query (default: "local")
            format: Response format - 'toon' (compact, default) or 'json' (verbose)
        """
        try:
            # Use Policy Gate for authorization
            policy_gate = PolicyGate()
            await policy_gate.authorize(
                operation="get_system_status",
                target=target,
                tier=OperationTier.OBSERVE
            )

            # Get executor for target
            executor = ExecutorFactory.get_executor(target)
            
            # Execute system status query
            result = await executor.execute(
                command="system_status",
                parameters={},
                timeout=30
            )

            if result.success:
                return format_response(result.output, format)
            else:
                return format_error(result.error, "get_system_status")
                
        except Exception as e:
            audit.log_operation(
                operation="get_system_status",
                target=target,
                success=False,
                error=str(e)
            )
            return format_error(e, "get_system_status")

    @mcp.tool()
    @secure_tool("get_top_processes")
    async def get_top_processes(
        target: str = "local",
        limit: int = 10,
        sort_by: str = "cpu",
        format: Literal["json", "toon"] = "toon"
    ) -> Union[dict, str]:
        """Get top processes by CPU or memory usage.

        Args:
            target: Target system to query (default: "local")
            limit: Number of processes to return
            sort_by: Sort by 'cpu' or 'memory'
            format: Response format - 'toon' (compact, default) or 'json' (verbose)
        """
        try:
            # Use Policy Gate for authorization
            policy_gate = PolicyGate()
            await policy_gate.authorize(
                operation="get_top_processes",
                target=target,
                tier=OperationTier.OBSERVE
            )

            # Get executor for target
            executor = ExecutorFactory.get_executor(target)
            
            # Execute process query
            result = await executor.execute(
                command="top_processes",
                parameters={"limit": limit, "sort_by": sort_by},
                timeout=30
            )

            if result.success:
                return format_response(result.output, format)
            else:
                return format_error(result.error, "get_top_processes")
                
        except Exception as e:
            audit.log_operation(
                operation="get_top_processes",
                target=target,
                success=False,
                error=str(e)
            )
            return format_error(e, "get_top_processes")

    @mcp.tool()
    @secure_tool("restart_service")
    async def restart_service(
        target: str = "local",
        service: str,
        dry_run: bool = False
    ) -> dict:
        """Restart a system service.

        Args:
            target: Target system (default: "local")
            service: Service name to restart
            dry_run: If True, simulate without executing
        """
        try:
            # Use Policy Gate for authorization
            policy_gate = PolicyGate()
            validation_mode = ValidationMode.DRY_RUN if dry_run else ValidationMode.STRICT
            
            await policy_gate.authorize(
                operation="restart_service",
                target=target,
                tier=OperationTier.CONTROL,
                parameters={"service": service},
                mode=validation_mode
            )

            if dry_run:
                return {
                    "success": True,
                    "dry_run": True,
                    "operation": "restart_service",
                    "service": service,
                    "target": target,
                    "message": "Operation would be executed in non-dry-run mode"
                }

            # Get executor for target
            executor = ExecutorFactory.get_executor(target)
            
            # Execute service restart
            result = await executor.execute(
                command="restart_service",
                parameters={"service": service},
                timeout=60
            )

            audit.log_operation(
                operation="restart_service",
                target=target,
                success=result.success,
                parameters={"service": service}
            )

            if result.success:
                return {
                    "success": True,
                    "operation": "restart_service",
                    "service": service,
                    "target": target,
                    "output": result.output
                }
            else:
                return {
                    "success": False,
                    "operation": "restart_service",
                    "service": service,
                    "target": target,
                    "error": result.error
                }
                
        except Exception as e:
            audit.log_operation(
                operation="restart_service",
                target=target,
                success=False,
                error=str(e)
            )
            return format_error(e, "restart_service")

    @mcp.tool()
    @secure_tool("get_network_io_counters")
    async def get_network_io_counters(
        target: str = "local"
    ) -> dict:
        """Get network I/O statistics (bytes, packets, errors) - summary only.

        Args:
            target: Target system to query (default: "local")
        """
        try:
            # Use Policy Gate for authorization
            policy_gate = PolicyGate()
            await policy_gate.authorize(
                operation="get_network_io_counters",
                target=target,
                tier=OperationTier.OBSERVE
            )

            # Get executor for target
            executor = ExecutorFactory.get_executor(target)
            
            # Execute network I/O query
            result = await executor.execute(
                command="network_io_counters",
                parameters={},
                timeout=30
            )

            if result.success:
                return result.output
            else:
                return format_error(result.error, "get_network_io_counters")
                
        except Exception as e:
            audit.log_operation(
                operation="get_network_io_counters",
                target=target,
                success=False,
                error=str(e)
            )
            return format_error(e, "get_network_io_counters")

    @mcp.tool()
    @secure_tool("health_check")
    async def health_check(
        target: str = "local"
    ) -> dict:
        """Health check endpoint.

        Args:
            target: Target system to check (default: "local")
        """
        try:
            # Use Policy Gate for authorization
            policy_gate = PolicyGate()
            await policy_gate.authorize(
                operation="health_check",
                target=target,
                tier=OperationTier.OBSERVE
            )

            # Get executor for target
            executor = ExecutorFactory.get_executor(target)
            
            # Execute health check
            result = await executor.execute(
                command="health_check",
                parameters={},
                timeout=10
            )

            if result.success:
                return {
                    "status": "healthy",
                    "target": target,
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return {
                    "status": "unhealthy",
                    "target": target,
                    "error": result.error,
                    "timestamp": datetime.now().isoformat()
                }
                
        except Exception as e:
            audit.log_operation(
                operation="health_check",
                target=target,
                success=False,
                error=str(e)
            )
            return {
                "status": "error",
                "target": target,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

    logger.info("Registered 5 system monitoring tools with capability-driven operations")