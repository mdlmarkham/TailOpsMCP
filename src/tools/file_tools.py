"""File operations tools for TailOpsMCP."""
import logging
from typing import Literal
from datetime import datetime
from fastmcp import FastMCP
from src.auth.middleware import secure_tool
from src.server.utils import format_error

logger = logging.getLogger(__name__)

def register_tools(mcp: FastMCP):
    """Register file operation tools with MCP instance."""

    @mcp.tool()
    @secure_tool("file_operations")
    async def file_operations(
        action: Literal["list", "info", "read", "tail", "search"],
        path: str,
        lines: int = 100,
        offset: int = 0,
        pattern: str = "*"
    ) -> dict:
        """Perform file system operations: list directory, get file info, read, tail, or search.

        Args:
            action: Operation to perform (list|info|read|tail|search)
            path: File or directory path
            lines: Number of lines for read/tail operations
            offset: Line offset for read operation
            pattern: Search pattern for search operation (supports wildcards)
        """
        import os
        import fnmatch
        from src.utils import filesec

        try:
            # SECURITY: Validate and sanitize path
            clean_path = filesec.sanitize_path(path)
            path_allowed, reason = filesec.is_path_allowed(clean_path)
            if not path_allowed:
                return {
                    "success": False,
                    "error": f"Access denied: {reason}",
                    "allowed_paths": filesec.DEFAULT_ALLOWED_PATHS
                }

            if action == "list":
                result = {"path": path, "files": [], "directories": []}
                for item in os.listdir(clean_path):
                    full_path = os.path.join(clean_path, item)
                    if os.path.isdir(full_path):
                        result["directories"].append(item)
                    else:
                        result["files"].append(item)
                return result

            elif action == "info":
                stat_info = os.stat(clean_path)
                is_dir = os.path.isdir(clean_path)
                return {
                    "path": path,
                    "exists": True,
                    "type": "directory" if is_dir else "file",
                    "size": stat_info.st_size,
                    "modified": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                    "created": datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                    "permissions": oct(stat_info.st_mode)[-3:],
                    "owner_uid": stat_info.st_uid,
                    "group_gid": stat_info.st_gid
                }

            elif action == "read":
                # SECURITY: Check file size before reading
                size_ok, msg = filesec.check_file_size(clean_path)
                if not size_ok:
                    return {"success": False, "error": msg}

                with open(clean_path, 'r', encoding='utf-8', errors='replace') as f:
                    all_lines = f.readlines()
                    selected_lines = all_lines[offset:offset + lines]
                    return {
                        "path": path,
                        "total_lines": len(all_lines),
                        "offset": offset,
                        "lines_returned": len(selected_lines),
                        "content": ''.join(selected_lines),
                        "has_more": offset + lines < len(all_lines)
                    }

            elif action == "tail":
                # SECURITY: Check file size before reading
                size_ok, msg = filesec.check_file_size(clean_path)
                if not size_ok:
                    return {"success": False, "error": msg}

                with open(clean_path, 'r', encoding='utf-8', errors='replace') as f:
                    all_lines = f.readlines()
                    tail_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines
                    return {
                        "path": path,
                        "total_lines": len(all_lines),
                        "lines_returned": len(tail_lines),
                        "content": ''.join(tail_lines)
                    }

            elif action == "search":
                result = {"pattern": pattern, "directory": path, "files": []}
                for root, dirs, files in os.walk(clean_path):
                    for filename in files:
                        if fnmatch.fnmatch(filename, pattern):
                            result["files"].append(os.path.join(root, filename))
                            if len(result["files"]) >= 100:
                                result["truncated"] = True
                                return result
                return result

            else:
                return {"success": False, "error": f"Invalid action: {action}"}

        except FileNotFoundError:
            return {"path": path, "exists": False, "error": "File or directory not found"}
        except Exception as e:
            return format_error(e, "file_operations")

    logger.info("Registered 1 file operations tool")
