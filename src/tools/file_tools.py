"""File operations tools for TailOpsMCP with capability-driven operations."""
import logging
from typing import Literal, Union
from datetime import datetime
from fastmcp import FastMCP
from src.auth.middleware import secure_tool
from src.server.utils import format_error
from src.services.policy_gate import PolicyGate, OperationTier, ValidationMode
from src.services.executor_factory import ExecutorFactory
from src.utils.audit import AuditLogger

logger = logging.getLogger(__name__)
audit = AuditLogger()


def register_tools(mcp: FastMCP):
    """Register file operation tools with MCP instance using capability-driven operations."""

    @mcp.tool()
    @secure_tool("read_file")
    async def read_file(
        target: str = "local",
        path: str,
        lines: int = 100,
        offset: int = 0
    ) -> dict:
        """Read a file from the target system.

        Args:
            target: Target system (default: "local")
            path: File path to read
            lines: Number of lines to read
            offset: Line offset to start reading from
        """
        try:
            # Use Policy Gate for authorization
            from src.server.dependencies import deps
            policy_gate = deps.policy_gate
            await policy_gate.authorize(
                operation="read_file",
                target=target,
                tier=OperationTier.OBSERVE,
                parameters={"path": path, "lines": lines, "offset": offset}
            )

            # Get executor for target
            executor = ExecutorFactory.get_executor(target)
            
            # Execute file read
            result = await executor.execute(
                command="read_file",
                parameters={"path": path, "lines": lines, "offset": offset},
                timeout=30
            )

            if result.success:
                return {
                    "success": True,
                    "target": target,
                    "path": path,
                    "content": result.output.get("content", ""),
                    "total_lines": result.output.get("total_lines", 0),
                    "offset": offset,
                    "lines_returned": result.output.get("lines_returned", 0),
                    "has_more": result.output.get("has_more", False),
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return {
                    "success": False,
                    "target": target,
                    "path": path,
                    "error": result.error,
                    "timestamp": datetime.now().isoformat()
                }
                
        except Exception as e:
            audit.log_operation(
                operation="read_file",
                target=target,
                success=False,
                error=str(e)
            )
            return format_error(e, "read_file")

    @mcp.tool()
    @secure_tool("list_directory")
    async def list_directory(
        target: str = "local",
        path: str = "/"
    ) -> dict:
        """List directory contents on the target system.

        Args:
            target: Target system (default: "local")
            path: Directory path to list
        """
        try:
            # Use Policy Gate for authorization
            from src.server.dependencies import deps
            policy_gate = deps.policy_gate
            await policy_gate.authorize(
                operation="list_directory",
                target=target,
                tier=OperationTier.OBSERVE,
                parameters={"path": path}
            )

            # Get executor for target
            executor = ExecutorFactory.get_executor(target)
            
            # Execute directory listing
            result = await executor.execute(
                command="list_directory",
                parameters={"path": path},
                timeout=30
            )

            if result.success:
                return {
                    "success": True,
                    "target": target,
                    "path": path,
                    "files": result.output.get("files", []),
                    "directories": result.output.get("directories", []),
                    "total_count": result.output.get("total_count", 0),
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return {
                    "success": False,
                    "target": target,
                    "path": path,
                    "error": result.error,
                    "timestamp": datetime.now().isoformat()
                }
                
        except Exception as e:
            audit.log_operation(
                operation="list_directory",
                target=target,
                success=False,
                error=str(e)
            )
            return format_error(e, "list_directory")

    @mcp.tool()
    @secure_tool("get_file_info")
    async def get_file_info(
        target: str = "local",
        path: str
    ) -> dict:
        """Get file information (size, permissions, timestamps).

        Args:
            target: Target system (default: "local")
            path: File path to get info for
        """
        try:
            # Use Policy Gate for authorization
            from src.server.dependencies import deps
            policy_gate = deps.policy_gate
            await policy_gate.authorize(
                operation="get_file_info",
                target=target,
                tier=OperationTier.OBSERVE,
                parameters={"path": path}
            )

            # Get executor for target
            executor = ExecutorFactory.get_executor(target)
            
            # Execute file info query
            result = await executor.execute(
                command="get_file_info",
                parameters={"path": path},
                timeout=30
            )

            if result.success:
                return {
                    "success": True,
                    "target": target,
                    "path": path,
                    "info": result.output,
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return {
                    "success": False,
                    "target": target,
                    "path": path,
                    "error": result.error,
                    "timestamp": datetime.now().isoformat()
                }
                
        except Exception as e:
            audit.log_operation(
                operation="get_file_info",
                target=target,
                success=False,
                error=str(e)
            )
            return format_error(e, "get_file_info")

    @mcp.tool()
    @secure_tool("search_files")
    async def search_files(
        target: str = "local",
        path: str,
        pattern: str = "*",
        max_results: int = 100
    ) -> dict:
        """Search for files matching a pattern.

        Args:
            target: Target system (default: "local")
            path: Directory path to search in
            pattern: Search pattern (supports wildcards)
            max_results: Maximum number of results to return
        """
        try:
            # Use Policy Gate for authorization
            from src.server.dependencies import deps
            policy_gate = deps.policy_gate
            await policy_gate.authorize(
                operation="search_files",
                target=target,
                tier=OperationTier.OBSERVE,
                parameters={"path": path, "pattern": pattern, "max_results": max_results}
            )

            # Get executor for target
            executor = ExecutorFactory.get_executor(target)
            
            # Execute file search
            result = await executor.execute(
                command="search_files",
                parameters={"path": path, "pattern": pattern, "max_results": max_results},
                timeout=60
            )

            if result.success:
                return {
                    "success": True,
                    "target": target,
                    "path": path,
                    "pattern": pattern,
                    "results": result.output.get("results", []),
                    "total_found": result.output.get("total_found", 0),
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return {
                    "success": False,
                    "target": target,
                    "path": path,
                    "pattern": pattern,
                    "error": result.error,
                    "timestamp": datetime.now().isoformat()
                }
                
        except Exception as e:
            audit.log_operation(
                operation="search_files",
                target=target,
                success=False,
                error=str(e)
            )
            return format_error(e, "search_files")

    # Backward compatibility wrapper for existing file operations
    @mcp.tool()
    @secure_tool("file_operations")
    async def file_operations(
        action: Literal["list", "info", "read", "tail", "search"],
        path: str,
        target: str = "local",
        lines: int = 100,
        offset: int = 0,
        pattern: str = "*"
    ) -> dict:
        """Perform file system operations (backward compatibility).

        Args:
            action: Operation to perform (list|info|read|tail|search)
            path: File or directory path
            target: Target system (default: "local")
            lines: Number of lines for read/tail operations
            offset: Line offset for read operation
            pattern: Search pattern for search operation (supports wildcards)
        """
        try:
            if action == "list":
                return await list_directory(target, path)
            elif action == "info":
                return await get_file_info(target, path)
            elif action == "read":
                return await read_file(target, path, lines, offset)
            elif action == "tail":
                # For tail, we need to calculate the offset based on total lines
                # This is a simplified implementation
                return await read_file(target, path, lines, -lines)
            elif action == "search":
                return await search_files(target, path, pattern)
            else:
                return {"success": False, "error": f"Invalid action: {action}"}
                
        except Exception as e:
            audit.log_operation(
                operation="file_operations",
                target=target,
                success=False,
                error=str(e)
            )
            return format_error(e, "file_operations")

    logger.info("Registered 5 file operation tools with capability-driven operations")