"""
SystemManager MCP Server - FastMCP with HTTP Transport
"""

import asyncio
import logging
from datetime import datetime
from fastmcp import FastMCP
import uvicorn

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastMCP server instance
mcp = FastMCP("SystemManager")

@mcp.tool()
async def get_system_status() -> dict:
    """Get comprehensive system status including CPU, memory, disk, and network."""
    import psutil
    import os
    
    try:
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
        
        # Get load average (with platform guard)
        load_avg = {}
        if hasattr(os, 'getloadavg'):
            load_avg = {
                "1m": os.getloadavg()[0],
                "5m": os.getloadavg()[1],
                "15m": os.getloadavg()[2]
            }
        else:
            load_avg = {"note": "Not available on this platform"}
        
        result = {
            "cpu_percent": cpu_percent,
            "load_average": load_avg,
            "memory_usage": memory_usage,
            "disk_usage": disk_usage,
            "uptime": uptime,
            "timestamp": datetime.now().isoformat()
        }
        
        logger.info(f"System status: CPU {cpu_percent}%, Memory {memory_usage['percent']}%")
        return result
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        return {"error": str(e)}

@mcp.tool()
async def get_container_list() -> dict:
    """List all Docker containers with their status."""
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
        
        logger.info(f"Found {len(result)} containers")
        return {"containers": result, "count": len(result)}
    except Exception as e:
        logger.error(f"Docker error: {e}")
        return {"error": str(e), "containers": [], "count": 0}

@mcp.tool()
async def list_directory(path: str = "/tmp") -> dict:
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
        
        logger.info(f"Listed directory {path}: {len(result['files'])} files, {len(result['directories'])} dirs")
        return result
    except Exception as e:
        logger.error(f"Directory list error: {e}")
        return {"error": str(e), "path": path, "files": [], "directories": []}

@mcp.tool()
async def get_network_status() -> dict:
    """Get network interface status and statistics."""
    import psutil
    
    try:
        result = {"interfaces": []}
        
        interfaces = psutil.net_if_stats()
        for name, stats in interfaces.items():
            result["interfaces"].append({
                "name": name,
                "isup": stats.isup,
                "speed": stats.speed,
                "mtu": stats.mtu,
                "bytes_sent": stats.bytes_sent,
                "bytes_recv": stats.bytes_recv,
                "packets_sent": stats.packets_sent,
                "packets_recv": stats.packets_recv,
                "errors_in": stats.errin,
                "errors_out": stats.errout,
                "drops_in": stats.dropin,
                "drops_out": stats.dropout
            })
        
        result["timestamp"] = datetime.now().isoformat()
        logger.info(f"Network status: {len(result['interfaces'])} interfaces")
        return result
    except Exception as e:
        logger.error(f"Network status error: {e}")
        return {"error": str(e), "interfaces": []}

@mcp.tool()
async def search_files(pattern: str, directory: str = "/tmp") -> dict:
    """Search for files by name pattern."""
    import os
    import fnmatch
    
    try:
        result = {"pattern": pattern, "directory": directory, "files": []}
        max_results = 100
        count = 0
        
        for root, dirs, files in os.walk(directory):
            for filename in files:
                if fnmatch.fnmatch(filename, pattern):
                    result["files"].append(os.path.join(root, filename))
                    count += 1
                    if count >= max_results:
                        result["truncated"] = True
                        return result
        
        logger.info(f"Found {count} files matching {pattern}")
        return result
    except Exception as e:
        logger.error(f"Search error: {e}")
        return {"error": str(e), "pattern": pattern, "files": []}

@mcp.tool()
async def health_check() -> dict:
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }

async def main():
    """Main entry point - run the FastMCP server with HTTP transport."""
    logger.info("=" * 60)
    logger.info("Starting SystemManager MCP Server")
    logger.info("=" * 60)
    logger.info("Listening on http://0.0.0.0:8080")
    logger.info("Available tools:")
    logger.info("  - get_system_status")
    logger.info("  - get_container_list")
    logger.info("  - list_directory")
    logger.info("  - get_network_status")
    logger.info("  - search_files")
    logger.info("  - health_check")
    logger.info("=" * 60)
    
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
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down...")
