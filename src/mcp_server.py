"""
MCP Server for SystemManager - Official MCP SDK Implementation
"""

import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging
from mcp.server import Server
from mcp.server.models import InitializationOptions
import mcp.types as types

from src.models.system import SystemStatus, MemoryUsage, DiskUsage
from src.models.containers import ContainerInfo, ContainerStats
from src.models.files import FileInfo, DirectoryListing
from src.models.network import NetworkStatus, InterfaceStats
from src.utils.errors import SystemManagerError, ErrorCategory
from src.auth.token_auth import require_scopes
from src.utils.retry import retry_with_backoff

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SystemManagerMCPServer:
    """Main MCP server for SystemManager."""
    
    def __init__(self):
        self.server = Server("SystemManager")
        self._setup_tools()
    
    def _setup_tools(self):
        """Register all MCP tools."""
        
        tools_list = [
            types.Tool(
                name="get_system_status",
                description="Get comprehensive system status including CPU, memory, disk, and network",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                },
            ),
            types.Tool(
                name="get_container_list",
                description="List all Docker containers with their status",
                inputSchema={"type": "object", "properties": {}, "required": []},
            ),
            types.Tool(
                name="list_directory",
                description="List contents of a directory",
                inputSchema={
                    "type": "object",
                    "properties": {"path": {"type": "string", "description": "Directory path to list"}},
                    "required": ["path"],
                },
            ),
            types.Tool(
                name="get_network_status",
                description="Get network interface status and statistics",
                inputSchema={"type": "object", "properties": {}, "required": []},
            ),
            types.Tool(
                name="search_files",
                description="Search for files by name pattern",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "File name pattern to search for"},
                        "directory": {"type": "string", "description": "Directory to search in (default: current directory)"},
                    },
                    "required": ["pattern"],
                },
            ),
        ]

        # Store tools on the server instance for backward compatibility/access
        self.server._tools = tools_list

        @self.server.list_tools()
        async def handle_list_tools() -> List[types.Tool]:
            """List available tools."""
            return tools_list
        
        @self.server.call_tool()
        async def handle_call_tool(
            name: str,
            arguments: Dict[str, Any]
        ) -> List[types.TextContent]:
            """Handle tool execution requests."""
            
            try:
                if name == "get_system_status":
                    result = await self._get_system_status()
                elif name == "get_container_list":
                    result = await self._get_container_list()
                elif name == "list_directory":
                    result = await self._list_directory(arguments["path"])
                elif name == "get_network_status":
                    result = await self._get_network_status()
                elif name == "search_files":
                    directory = arguments.get("directory", ".")
                    result = await self._search_files(arguments["pattern"], directory)
                else:
                    raise SystemManagerError(
                        f"Unknown tool: {name}",
                        ErrorCategory.VALIDATION
                    )
                
                return [types.TextContent(type="text", text=str(result))]
                
            except SystemManagerError as e:
                logger.error(f"Tool error: {e}")
                raise
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                raise SystemManagerError(
                    f"Internal server error: {str(e)}",
                    ErrorCategory.SYSTEM
                )
    
    @retry_with_backoff(max_retries=3)
    async def _get_system_status(self) -> SystemStatus:
        """Get comprehensive system status."""
        import psutil
        
        # Get CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Get memory usage
        memory = psutil.virtual_memory()
        memory_usage = MemoryUsage(
            total=memory.total,
            available=memory.available,
            used=memory.used,
            percent=memory.percent
        )
        
        # Get disk usage
        disk = psutil.disk_usage('/')
        disk_usage = DiskUsage(
            total=disk.total,
            used=disk.used,
            free=disk.free,
            percent=disk.percent
        )
        
        # Get system uptime
        boot_time = psutil.boot_time()
        uptime = int(datetime.now().timestamp() - boot_time)
        
        return SystemStatus(
            cpu_percent=cpu_percent,
            memory_usage=memory_usage,
            disk_usage=disk_usage,
            uptime=uptime,
            timestamp=datetime.now()
        )
    
    async def _get_container_list(self) -> List[ContainerInfo]:
        """Get list of Docker containers."""
        # Placeholder implementation - will be implemented in Phase 3
        return []
    
    async def _list_directory(self, path: str) -> DirectoryListing:
        """List directory contents."""
        # Placeholder implementation - will be implemented in Phase 3
        return DirectoryListing(path=path, files=[], directories=[])
    
    async def _get_network_status(self) -> NetworkStatus:
        """Get network interface status."""
        # Placeholder implementation - will be implemented in Phase 3
        return NetworkStatus(interfaces=[], timestamp=datetime.now())
    
    async def _search_files(self, pattern: str, directory: str) -> List[FileInfo]:
        """Search for files by pattern."""
        # Placeholder implementation - will be implemented in Phase 3
        return []
    
    async def run(self, transport: str = "stdio"):
        """Run the MCP server."""
        async with self.server.run(transport=transport) as session:
            await session.wait_for_disconnect()

async def main():
    """Main entry point."""
    server = SystemManagerMCPServer()
    await server.run()

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
                        if asyncio.iscoroutinefunction(impl):
                            impl_result = await impl(**kwargs)
                        else:
                            impl_result = impl(**kwargs)
                        # Normalize Pydantic models to dicts or compact TOON if requested
                        fmt = kwargs.get("format") or kwargs.get("_format")
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
                                    # fallback to compact JSON
                                    pass

                            # If Pydantic v2 style
                            if hasattr(res, "model_dump"):
                                return res.model_dump()
                            # Pydantic v1 style
                            if hasattr(res, "dict"):
                                return res.dict()
                            # Already a primitive/dict/list
                            return res

                        data = _convert_result(impl_result)

                        # If TOON produced a compact string, put it under `data` so callers remain compatible
                        return {"success": True, "data": data}
                    except Exception as e:
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


if __name__ == "__main__":
    # Run the MCP server
    mcp.run(transport="stdio")