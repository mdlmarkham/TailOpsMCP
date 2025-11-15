"""
MCP Server for SystemManager - Official MCP SDK Implementation
"""

import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging
import json
from fastmcp import FastMCP
from fastmcp.server import ServerStream
import mcp.types as types

from src.models.system import SystemStatus, MemoryUsage, DiskUsage
from src.models.containers import ContainerInfo, ContainerStats
from src.models.files import FileInfo, DirectoryListing
from src.models.network import NetworkStatus, InterfaceStats
from src.utils.errors import SystemManagerError, ErrorCategory
from src.auth.token_auth import require_scopes
from src.utils.retry import retry_with_backoff
from src.tools import stack_tools as stack_tools_module

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastMCP server instance
mcp = FastMCP("SystemManager")

@mcp.tool()
async def get_system_status(format: str = "json") -> dict:
    """Get comprehensive system status including CPU, memory, disk, and network."""
    import psutil
    
    # Get CPU usage (non-blocking)
    cpu_percent = psutil.cpu_percent(interval=None)
    
    # Get memory usage
    memory = psutil.virtual_memory()
    memory_usage = {
        "total": memory.total,
        "available": memory.available,
        "used": memory.used,
        "percent": memory.percent
    }
    
    # Get disk usage
    disk = psutil.disk_usage('/')
    disk_usage = {
        "total": disk.total,
        "used": disk.used,
        "free": disk.free,
        "percent": disk.percent
    }
    
    # Get system uptime
    boot_time = psutil.boot_time()
    uptime = int(datetime.now().timestamp() - boot_time)
    
    result = {
        "cpu_percent": cpu_percent,
        "memory_usage": memory_usage,
        "disk_usage": disk_usage,
        "uptime": uptime,
        "timestamp": datetime.now().isoformat()
    }
    
    return result

@mcp.tool()
async def get_container_list(all_containers: bool = False) -> dict:
    """List all Docker containers with their status."""
    try:
        import docker
        client = docker.from_env()
        containers = client.containers.list(all=all_containers)
        
        result = []
        for container in containers:
            result.append({
                "id": container.id[:12],
                "name": container.name,
                "status": container.status,
                "image": container.image.tags[0] if container.image.tags else "unknown"
            })
        
        return {"containers": result, "count": len(result)}
    except Exception as e:
        logger.error(f"Docker error: {e}")
        return {"error": str(e), "containers": []}

@mcp.tool()
async def list_directory(path: str, recursive: bool = False) -> dict:
    """List contents of a directory."""
    import os
    
    try:
        result = {"path": path, "files": [], "directories": []}
        
        for item in os.listdir(path):
            full_path = os.path.join(path, item)
            if os.path.isdir(full_path):
                result["directories"].append(item)
            else:
                result["files"].append(item)
        
        return result
    except Exception as e:
        logger.error(f"Directory list error: {e}")
        return {"error": str(e), "path": path, "files": [], "directories": []}

@mcp.tool()
async def get_network_status(interface: str = None) -> dict:
    """Get network interface status and statistics."""
    import psutil
    
    try:
        result = {"interfaces": []}
        
        interfaces = psutil.net_if_stats()
        for name, stats in interfaces.items():
            if interface and name != interface:
                continue
            
            result["interfaces"].append({
                "name": name,
                "isup": stats.isup,
                "speed": stats.speed,
                "mtu": stats.mtu,
                "bytes_sent": stats.bytes_sent,
                "bytes_recv": stats.bytes_recv,
                "packets_sent": stats.packets_sent,
                "packets_recv": stats.packets_recv
            })
        
        result["timestamp"] = datetime.now().isoformat()
        return result
    except Exception as e:
        logger.error(f"Network status error: {e}")
        return {"error": str(e), "interfaces": []}

@mcp.tool()
async def search_files(pattern: str, directory: str = ".", max_results: int = 100) -> dict:
    """Search for files by name pattern."""
    import os
    import fnmatch
    
    try:
        result = {"pattern": pattern, "directory": directory, "files": []}
        
        count = 0
        for root, dirs, files in os.walk(directory):
            for filename in files:
                if fnmatch.fnmatch(filename, pattern):
                    result["files"].append(os.path.join(root, filename))
                    count += 1
                    if count >= max_results:
                        return result
        
        return result
    except Exception as e:
        logger.error(f"Search error: {e}")
        return {"error": str(e), "pattern": pattern, "files": []}

async def main():
    """Main entry point - run the FastMCP server with HTTP transport."""
    import uvicorn
    
    logger.info("Starting SystemManager MCP server on http://0.0.0.0:8080")
    
    # Run with uvicorn HTTP server
    config = uvicorn.Config(
        mcp.app,
        host="0.0.0.0",
        port=8080,
        log_level="info"
    )
    server = uvicorn.Server(config)
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())


# Backwards compatibility: expose a module-level `mcp` (tests and older code expect this)
# This creates a server instance and exposes its `server` object as `mcp`.
_server_instance = SystemManagerMCPServer()
class _MCPCompat:
    """Compatibility wrapper exposing older FastMCP-style decorators onto the
    new `mcp.server.Server` instance used by this project.
    """

    def __init__(self, server):
        self._server = server

    def tool(self):
        return self._server.call_tool()

    def list_tools(self):
        return self._server.list_tools()

    def call_tool(self):
        return self._server.call_tool()

    @property
    def name(self) -> str:
        # Prefer underlying server name if available
        return getattr(self._server, "name", "SystemManager")

    @property
    def tools(self):
        # Return stored tools if available, wrapped with a callable `.function` for compatibility
        raw_tools = getattr(self._server, "_tools", [])

        class _ToolWrapper:
            def __init__(self, tool):
                self.name = tool.name
                self.description = tool.description
                self.inputSchema = getattr(tool, "inputSchema", None)

                async def _callable(**kwargs):
                    # Map to the implementation on the module-level server instance
                    impl_name = f"_{self.name}"
                    impl = getattr(_server_instance, impl_name, None)
                    if impl is None:
                        return {"success": False, "error": f"Tool implementation for {self.name} not available"}

                    try:
                        # Prepare audit and sandbox helpers
                        from src.utils.audit import AuditLogger
                        from src.utils import sandbox

                        audit = AuditLogger()

                        # Extract token-subject if present
                        subject = None
                        if "_token_claims" in kwargs:
                            try:
                                subject = getattr(kwargs["_token_claims"], "agent", None)
                            except Exception:
                                subject = None

                        # Validate path-like kwargs against allowed paths
                        path_keys = [k for k in kwargs.keys() if any(x in k.lower() for x in ("path", "file", "dir", "directory"))]
                        try:
                            for pk in path_keys:
                                val = kwargs.get(pk)
                                if isinstance(val, str) and val:
                                    if not sandbox.is_path_allowed(val):
                                        return {"success": False, "error": f"Access to path not allowed: {val}"}
                        except PermissionError as e:
                            return {"success": False, "error": str(e)}

                        # Non-root enforcement
                        enforce_nonroot = os.getenv("SYSTEMMANAGER_ENFORCE_NON_ROOT", "false").lower() in ("1","true","yes")
                        if enforce_nonroot and sandbox.is_running_as_root():
                            return {"success": False, "error": "Execution as root is disallowed by server policy"}

                        # Pop format param so underlying impl doesn't receive unexpected kwargs
                        fmt = kwargs.pop("format", kwargs.pop("_format", None))

                        # Default monitoring tools to TOON for token efficiency when client
                        # did not explicitly request a format.
                        monitoring_defaults = {"get_system_status", "get_container_list", "list_directory", "get_network_status", "search_files"}
                        if fmt is None and self.name in monitoring_defaults:
                            fmt = "toon"

                        if asyncio.iscoroutinefunction(impl):
                            impl_result = await impl(**kwargs)
                        else:
                            impl_result = impl(**kwargs)
                        # Normalize Pydantic models to dicts or compact TOON if requested
                        # restore fmt var for conversion logic
                        # (if fmt was popped above, it's already captured; else keep None)
                        # fmt variable is already set above
                        # Prefer model-based TOON if available
                        try:
                            from src.utils.toon import model_to_toon
                        except Exception:
                            model_to_toon = None

                        # Helper to convert model/list/dict to suitable return
                        def _convert_result(res):
                            # If client requested TOON and we have a converter, try it
                            if fmt == "toon" and model_to_toon is not None:
                                try:
                                    return model_to_toon(res)
                                except Exception:
                                    # fallback to compact JSON (for dict/list results)
                                    try:
                                        # If it's already a dict/list, dump compact JSON
                                        if isinstance(res, (dict, list)):
                                            return json.dumps(res, separators=(",",":"), ensure_ascii=False)
                                    except Exception:
                                        pass

                            # If Pydantic v2 style
                            if hasattr(res, "model_dump"):
                                return res.model_dump()
                            # Pydantic v1 style
                            if hasattr(res, "dict"):
                                return res.dict()
                            # Already a primitive/dict/list
                            # If TOON requested, compact it
                            if fmt == "toon":
                                try:
                                    return json.dumps(res, separators=(",",":"), ensure_ascii=False)
                                except Exception:
                                    return res

                            return res

                        data = _convert_result(impl_result)

                        # Enforce output caps: bytes and optional line limits
                        max_bytes = int(os.getenv("SYSTEMMANAGER_MAX_OUTPUT_BYTES", "65536"))
                        max_lines = os.getenv("SYSTEMMANAGER_MAX_OUTPUT_LINES")
                        max_lines = int(max_lines) if max_lines and max_lines.isdigit() else None

                        truncated = False
                        # If data is not a string, serialize compactly for truncation check
                        if not isinstance(data, str):
                            try:
                                compact = json.dumps(data, separators=(",",":"), ensure_ascii=False)
                            except Exception:
                                compact = str(data)
                        else:
                            compact = data

                        # Truncate by bytes
                        compact_bytes = compact.encode("utf-8")
                        if len(compact_bytes) > max_bytes:
                            # Truncate safely on utf-8 boundary
                            truncated = True
                            compact = compact_bytes[:max_bytes].decode("utf-8", errors="ignore")

                        # If max_lines set, truncate to that many lines
                        if max_lines is not None:
                            lines = compact.splitlines(True)
                            if len(lines) > max_lines:
                                truncated = True
                                compact = "".join(lines[:max_lines])

                        # Build final result; if original expected structured data and format!=toon, attempt to return parsed JSON
                        final_data = compact
                        if fmt != "toon":
                            # Try to rehydrate JSON back to object if we serialized above and it fits
                            try:
                                parsed = json.loads(compact)
                                final_data = parsed
                            except Exception:
                                final_data = compact

                        result = {"success": True, "data": final_data}

                        # Audit the call
                        try:
                            audit.log(self.name, kwargs, result, subject=subject, truncated=truncated)
                        except Exception:
                            # swallow audit errors
                            pass

                        return result
                    except Exception as e:
                        # Audit error
                        try:
                            audit.log(self.name, kwargs, {"success": False, "error": str(e)}, subject=subject, truncated=False)
                        except Exception:
                            pass
                        return {"success": False, "error": str(e)}

                self.function = _callable

        return [ _ToolWrapper(t) for t in raw_tools ]

    def custom_route(self, *args, **kwargs):
        # forward if available
        fn = getattr(self._server, "custom_route", None)
        if fn:
            return fn(*args, **kwargs)
        raise AttributeError("custom_route not available on underlying server")


mcp = _MCPCompat(_server_instance.server)


@require_scopes(["monitor"] )
@mcp.tool()
async def get_container_list(all_containers: bool = False) -> Dict:
    """List Docker containers."""
    if not docker_client:
        return {"success": False, "error": "Docker client not available"}
    
    try:
        containers = docker_client.containers.list(all=all_containers)
        container_list = []
        
        for container in containers:
            container_info = {
                "id": container.id[:12],
                "name": container.name,
                "status": container.status,
                "image": container.image.tags[0] if container.image.tags else "",
                "created": container.attrs["Created"],
                "ports": container.attrs["HostConfig"].get("PortBindings", {}),
            }
            container_list.append(container_info)
        
        return {"success": True, "data": container_list}
        
    except Exception as e:
        logger.error(f"Error listing containers: {e}")
        return {"success": False, "error": str(e)}

@require_scopes(["monitor"] )
@mcp.tool()
async def list_directory(path: str = "/", recursive: bool = False) -> Dict:
    """List contents of a directory."""
    try:
        if not os.path.exists(path):
            return {"success": False, "error": f"Path does not exist: {path}"}
        
        if not os.path.isdir(path):
            return {"success": False, "error": f"Path is not a directory: {path}"}
        
        entries = []
        
        for entry in os.listdir(path):
            entry_path = os.path.join(path, entry)
            try:
                stat = os.stat(entry_path)
                entry_info = {
                    "name": entry,
                    "path": entry_path,
                    "type": "directory" if os.path.isdir(entry_path) else "file",
                    "size": stat.st_size if os.path.isfile(entry_path) else 0,
                    "permissions": oct(stat.st_mode)[-3:],
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "accessed": datetime.fromtimestamp(stat.st_atime).isoformat()
                }
                entries.append(entry_info)
            except PermissionError:
                # Skip entries we don't have permission to access
                continue
        
        return {"success": True, "data": entries}
        
    except Exception as e:
        logger.error(f"Error listing directory {path}: {e}")
        return {"success": False, "error": str(e)}


    @require_scopes(["monitor"])
    @mcp.tool()
    async def get_stack_network_info(host: str, stack_name: str) -> Dict:
        """MCP-exposed wrapper for stack network inspection.

        Delegates to `src.tools.stack_tools.get_stack_network_info` and returns
        a standardized MCP tool response.
        """
        try:
            res = await stack_tools_module.get_stack_network_info(host, stack_name)
            return {"success": True, "data": res}
        except Exception as e:
            logger.error(f"Error in get_stack_network_info: {e}")
            return {"success": False, "error": str(e)}

@require_scopes(["monitor"] )
@mcp.tool()
async def get_network_status(interface: Optional[str] = None) -> Dict:
    """Get network interface status."""
    try:
        interfaces = {}
        
        for iface, addrs in psutil.net_if_addrs().items():
            if interface and iface != interface:
                continue
                
            interface_info = {
                "name": iface,
                "addresses": []
            }
            
            for addr in addrs:
                interface_info["addresses"].append({
                    "family": str(addr.family),
                    "address": addr.address,
                    "netmask": addr.netmask,
                    "broadcast": addr.broadcast
                })
            
            interfaces[iface] = interface_info
        
        # Add I/O statistics
        io_stats = psutil.net_io_counters(pernic=True)
        for iface in interfaces:
            if iface in io_stats:
                interfaces[iface]["io_stats"] = dict(io_stats[iface]._asdict())
        
        return {"success": True, "data": list(interfaces.values())}
        
    except Exception as e:
        logger.error(f"Error getting network status: {e}")
        return {"success": False, "error": str(e)}


try:
    # Register a lightweight Tool descriptor for compatibility listing
    _server_instance.server._tools.append(
        types.Tool(
            name="get_stack_network_info",
            description="Inspect stack network exposure and port bindings",
            inputSchema={
                "type": "object",
                "properties": {"host": {"type": "string"}, "stack_name": {"type": "string"}, "format": {"type": "string", "enum": ["json","toon"]}},
                "required": ["host","stack_name"],
            },
        )
    )
except Exception:
    pass

# For compatibility wrapper: expose an implementation method on the server instance
try:
    setattr(_server_instance, "_get_stack_network_info", get_stack_network_info)
except Exception:
    pass

@require_scopes(["monitor"] )
@mcp.tool()
async def search_files(pattern: str, path: str = "/", max_results: int = 100) -> Dict:
    """Search for files by name pattern."""
    import fnmatch
    import os
    
    try:
        if not os.path.exists(path):
            return {"success": False, "error": f"Path does not exist: {path}"}
        
        results = []
        
        for root, dirs, files in os.walk(path):
            # Skip directories we can't access
            try:
                dirs[:] = [d for d in dirs if os.access(os.path.join(root, d), os.R_OK)]
            except PermissionError:
                continue
            
            for file in files:
                if fnmatch.fnmatch(file, pattern):
                    file_path = os.path.join(root, file)
                    try:
                        stat = os.stat(file_path)
                        results.append({
                            "path": file_path,
                            "name": file,
                            "size": stat.st_size,
                            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                        })
                        
                        if len(results) >= max_results:
                            break
                    except (PermissionError, OSError):
                        continue
            
            if len(results) >= max_results:
                break
        
        return {"success": True, "data": results}
        
    except Exception as e:
        logger.error(f"Error searching files: {e}")
        return {"success": False, "error": str(e)}


# The module-level entrypoint uses `asyncio.run(main())` above.
# Remove duplicate synchronous `mcp.run(...)` invocation which passes
# an unexpected keyword to `Server.run()` in some SDK versions.