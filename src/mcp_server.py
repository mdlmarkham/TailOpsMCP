"""
MCP Server for SystemManager
"""

from fastmcp import FastMCP
import psutil
import docker
import os
from typing import Dict, List, Optional
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize MCP server
mcp = FastMCP("SystemManager")

# Docker client (will be initialized later)
docker_client = None

try:
    docker_client = docker.from_env()
    logger.info("Docker client initialized successfully")
except Exception as e:
    logger.warning(f"Failed to initialize Docker client: {e}")


@mcp.tool()
async def get_system_status(detailed: bool = False) -> Dict:
    """Get current system health metrics."""
    try:
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Memory usage
        memory = psutil.virtual_memory()
        
        # Disk usage
        disk_usage = {}
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_usage[partition.mountpoint] = {
                    "total": usage.total,
                    "used": usage.used,
                    "free": usage.free,
                    "percent": usage.percent
                }
            except PermissionError:
                continue
        
        # Load average
        load_avg = os.getloadavg()
        
        # Network I/O
        net_io = psutil.net_io_counters()
        
        status = {
            "cpu_percent": cpu_percent,
            "memory": {
                "total": memory.total,
                "available": memory.available,
                "used": memory.used,
                "percent": memory.percent
            },
            "disk_usage": disk_usage,
            "load_average": {
                "1min": load_avg[0],
                "5min": load_avg[1],
                "15min": load_avg[2]
            },
            "network": {
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv
            },
            "uptime": int((datetime.now() - datetime.fromtimestamp(psutil.boot_time())).total_seconds()),
            "timestamp": datetime.now().isoformat()
        }
        
        if detailed:
            # Add detailed information
            status.update({
                "cpu_times": dict(psutil.cpu_times()._asdict()),
                "memory_details": dict(psutil.virtual_memory()._asdict()),
                "swap": dict(psutil.swap_memory()._asdict()),
                "network_interfaces": {
                    iface: dict(psutil.net_io_counters(pernic=True).get(iface, {})._asdict())
                    for iface in psutil.net_io_counters(pernic=True)
                }
            })
        
        return {"success": True, "data": status}
        
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        return {"success": False, "error": str(e)}


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