"""
SystemManager MCP Server - FastMCP with HTTP Transport
"""

import logging
from datetime import datetime
from fastmcp import FastMCP

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

mcp = FastMCP("SystemManager")

@mcp.tool()
async def get_system_status() -> dict:
    """Get comprehensive system status."""
    import psutil
    import os
    
    cpu_percent = psutil.cpu_percent(interval=None)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    boot_time = psutil.boot_time()
    uptime = int(datetime.now().timestamp() - boot_time)
    
    load_avg = {}
    if hasattr(os, 'getloadavg'):
        load_avg = {
            "1m": os.getloadavg()[0],
            "5m": os.getloadavg()[1],
            "15m": os.getloadavg()[2]
        }
    else:
        load_avg = {"note": "Not available on this platform"}
    
    return {
        "cpu_percent": cpu_percent,
        "load_average": load_avg,
        "memory_usage": {
            "total": memory.total,
            "available": memory.available,
            "used": memory.used,
            "percent": memory.percent
        },
        "disk_usage": {
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
            "percent": disk.percent
        },
        "uptime": uptime,
        "timestamp": datetime.now().isoformat()
    }

@mcp.tool()
async def get_container_list() -> dict:
    """List all Docker containers."""
    try:
        import docker
        client = docker.from_env()
        containers = client.containers.list(all=True)
        
        result = []
        for container in containers:
            image_name = container.image.tags[0] if container.image.tags else "unknown"
            result.append({
                "id": container.id[:12],
                "name": container.name,
                "status": container.status,
                "image": image_name
            })
        
        return {"containers": result, "count": len(result)}
    except Exception as e:
        return {"error": str(e), "containers": [], "count": 0}

@mcp.tool()
async def list_directory(path: str = "/tmp") -> dict:
    """List directory contents."""
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
        return {"error": str(e), "path": path, "files": [], "directories": []}

@mcp.tool()
async def get_network_status() -> dict:
    """Get network interface status."""
    import psutil
    
    try:
        result = {"interfaces": []}
        interfaces = psutil.net_if_stats()
        for name, stats in interfaces.items():
            result["interfaces"].append({
                "name": name,
                "isup": stats.isup,
                "speed": stats.speed,
                "mtu": stats.mtu
            })
        result["timestamp"] = datetime.now().isoformat()
        return result
    except Exception as e:
        return {"error": str(e), "interfaces": []}

@mcp.tool()
async def search_files(pattern: str, directory: str = "/tmp") -> dict:
    """Search for files by pattern."""
    import os
    import fnmatch
    
    try:
        result = {"pattern": pattern, "directory": directory, "files": []}
        for root, dirs, files in os.walk(directory):
            for filename in files:
                if fnmatch.fnmatch(filename, pattern):
                    result["files"].append(os.path.join(root, filename))
                    if len(result["files"]) >= 100:
                        return result
        return result
    except Exception as e:
        return {"error": str(e), "pattern": pattern, "files": []}

@mcp.tool()
async def health_check() -> dict:
    """Health check."""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

if __name__ == "__main__":
    logger.info("Starting SystemManager MCP Server on http://0.0.0.0:8080")
    mcp.run(transport="sse", host="0.0.0.0", port=8080)
