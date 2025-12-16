"""Network diagnostic tools for TailOpsMCP with capability-driven operations."""
from __future__ import annotations

import json
import logging
import os
import socket
from typing import Dict, List, Literal, Union, Optional
from datetime import datetime
from fastmcp import FastMCP
from src.auth.middleware import secure_tool
from src.server.utils import format_response, format_error
from src.services.policy_gate import PolicyGate, OperationTier, ValidationMode
from src.services.executor_factory import ExecutorFactory
from src.utils.audit import AuditLogger

logger = logging.getLogger(__name__)
audit = AuditLogger()


def register_tools(mcp: FastMCP):
    """Register network diagnostic tools with MCP instance using capability-driven operations."""

    @mcp.tool()
    @secure_tool("test_connectivity")
    async def test_connectivity(
        host: str,
        port: int,
        target: str = "local",
        timeout: int = 5
    ) -> dict:
        """Test connectivity to a specific host and port.

        Args:
            target: Target system to test from (default: "local")
            host: Hostname or IP address to test
            port: Port number to test
            timeout: Connection timeout in seconds
        """
        try:
            # Use Policy Gate for authorization
            from src.server.dependencies import deps
            policy_gate = deps.policy_gate
            await policy_gate.authorize(
                operation="test_connectivity",
                target=target,
                tier=OperationTier.OBSERVE,
                parameters={"host": host, "port": port, "timeout": timeout}
            )

            # Get executor for target
            executor = ExecutorFactory.get_executor(target)

            # Execute connectivity test
            result = await executor.execute(
                command="test_connectivity",
                parameters={"host": host, "port": port, "timeout": timeout},
                timeout=timeout + 5
            )

            if result.success:
                return {
                    "success": True,
                    "target": target,
                    "host": host,
                    "port": port,
                    "connectivity": result.output.get("connectivity", "unknown"),
                    "response_time": result.output.get("response_time", None),
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return {
                    "success": False,
                    "target": target,
                    "host": host,
                    "port": port,
                    "error": result.error,
                    "timestamp": datetime.now().isoformat()
                }

        except Exception as e:
            audit.log_operation(
                operation="test_connectivity",
                target=target,
                success=False,
                error=str(e)
            )
            return format_error(e, "test_connectivity")

    @mcp.tool()
    @secure_tool("scan_ports")
    async def scan_ports(
        target: str = "local",
        range: str = "1-1000",
        timeout: int = 1
    ) -> dict:
        """Scan a range of ports on a target system.

        Args:
            target: Target system to scan (default: "local")
            range: Port range to scan (e.g., "1-1000", "80,443,8080")
            timeout: Connection timeout in seconds per port
        """
        try:
            # Use Policy Gate for authorization
            from src.server.dependencies import deps
            policy_gate = deps.policy_gate
            await policy_gate.authorize(
                operation="scan_ports",
                target=target,
                tier=OperationTier.OBSERVE,
                parameters={"range": range, "timeout": timeout}
            )

            # Get executor for target
            executor = ExecutorFactory.get_executor(target)

            # Execute port scan
            result = await executor.execute(
                command="scan_ports",
                parameters={"range": range, "timeout": timeout},
                timeout=300  # 5 minutes max for large scans
            )

            if result.success:
                return {
                    "success": True,
                    "target": target,
                    "range": range,
                    "open_ports": result.output.get("open_ports", []),
                    "total_scanned": result.output.get("total_scanned", 0),
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return {
                    "success": False,
                    "target": target,
                    "range": range,
                    "error": result.error,
                    "timestamp": datetime.now().isoformat()
                }

        except Exception as e:
            audit.log_operation(
                operation="scan_ports",
                target=target,
                success=False,
                error=str(e)
            )
            return format_error(e, "scan_ports")

    @mcp.tool()
    @secure_tool("get_network_status")
    async def get_network_status(
        target: str = "local",
        format: Literal["json", "toon"] = "toon"
    ) -> Union[dict, str]:
        """Get network interface status with addresses and statistics.

        Args:
            target: Target system to query (default: "local")
            format: Response format - 'toon' (compact, default) or 'json' (verbose)
        """
        try:
            # Use Policy Gate for authorization
            from src.server.dependencies import deps
            policy_gate = deps.policy_gate
            await policy_gate.authorize(
                operation="get_network_status",
                target=target,
                tier=OperationTier.OBSERVE
            )

            # Get executor for target
            executor = ExecutorFactory.get_executor(target)

            # Execute network status query
            result = await executor.execute(
                command="network_status",
                parameters={},
                timeout=30
            )

            if result.success:
                return format_response(result.output, format)
            else:
                return format_error(result.error, "get_network_status")

        except Exception as e:
            audit.log_operation(
                operation="get_network_status",
                target=target,
                success=False,
                error=str(e)
            )
            return format_error(e, "get_network_status")

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
            from src.server.dependencies import deps
            policy_gate = deps.policy_gate
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

    # Backward compatibility wrapper for existing network operations
    @mcp.tool()
    @secure_tool("network_operations")
    async def network_operations(
        action: Literal["status", "io_counters", "connectivity", "port_scan"],
        target: str = "local",
        host: Optional[str] = None,
        port: Optional[int] = None,
        range: Optional[str] = None,
        timeout: int = 5,
        format: Literal["json", "toon"] = "toon"
    ) -> Union[dict, str]:
        """Perform network operations (backward compatibility).

        Args:
            action: Operation to perform (status|io_counters|connectivity|port_scan)
            target: Target system (default: "local")
            host: Hostname or IP address (required for connectivity)
            port: Port number (required for connectivity)
            range: Port range (required for port_scan)
            timeout: Connection timeout in seconds
            format: Response format - 'toon' (compact, default) or 'json' (verbose)
        """
        try:
            if action == "status":
                return await get_network_status(target, format)
            elif action == "io_counters":
                return await get_network_io_counters(target)
            elif action == "connectivity":
                if not host or not port:
                    return {"success": False, "error": "Host and port required for connectivity test"}
                return await test_connectivity(target, host, port, timeout)
            elif action == "port_scan":
                if not range:
                    return {"success": False, "error": "Port range required for port scan"}
                return await scan_ports(target, range, timeout)
            else:
                return {"success": False, "error": f"Invalid action: {action}"}

        except Exception as e:
            audit.log_operation(
                operation="network_operations",
                target=target,
                success=False,
                error=str(e)
            )
            return format_error(e, "network_operations")

    logger.info("Registered 5 network diagnostic tools with capability-driven operations")
