"""System monitoring tools for TailOpsMCP."""
import logging
from typing import Literal, Union
from datetime import datetime
from fastmcp import FastMCP
from src.auth.middleware import secure_tool
from src.server.utils import cached, format_response, format_error

logger = logging.getLogger(__name__)

def register_tools(mcp: FastMCP):
    """Register system monitoring tools with MCP instance."""

    @mcp.tool()
    @secure_tool("get_system_status")
    @cached(ttl_seconds=5)
    async def get_system_status(format: Literal["json", "toon"] = "toon") -> Union[dict, str]:
        """Get comprehensive system status with CPU, memory, disk, and uptime.

        Args:
            format: Response format - 'toon' (compact, default) or 'json' (verbose)
        """
        import psutil
        import os

        try:
            # Non-blocking CPU measurement (returns cached value from previous call)
            cpu_percent = psutil.cpu_percent(interval=None)
            memory = psutil.virtual_memory()
            boot_time = psutil.boot_time()
            uptime = int(datetime.now().timestamp() - boot_time)

            # Get all disk partitions
            disk_info = []
            for partition in psutil.disk_partitions(all=False):
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_info.append({
                        "mountpoint": partition.mountpoint,
                        "device": partition.device,
                        "fstype": partition.fstype,
                        "total": usage.total,
                        "used": usage.used,
                        "free": usage.free,
                        "percent": usage.percent
                    })
                except (PermissionError, OSError):
                    continue

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
                "memory_usage": {
                    "total": memory.total,
                    "available": memory.available,
                    "used": memory.used,
                    "percent": memory.percent
                },
                "disk_usage": disk_info,
                "uptime": uptime,
                "timestamp": datetime.now().isoformat()
            }
            return format_response(result, format)
        except Exception as e:
            return format_error(e, "get_system_status")

    @mcp.tool()
    @secure_tool("get_top_processes")
    async def get_top_processes(
        limit: int = 10,
        sort_by: str = "cpu",
        format: Literal["json", "toon"] = "toon"
    ) -> Union[dict, str]:
        """Get top processes by CPU or memory usage.

        Args:
            limit: Number of processes to return
            sort_by: Sort by 'cpu' or 'memory'
            format: Response format - 'toon' (compact, default) or 'json' (verbose)
        """
        import psutil

        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'username']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Sort by requested metric
            if sort_by == "memory":
                processes.sort(key=lambda p: p.get('memory_percent', 0), reverse=True)
            else:  # default to cpu
                processes.sort(key=lambda p: p.get('cpu_percent', 0), reverse=True)

            result = {
                "processes": processes[:limit],
                "sort_by": sort_by,
                "total_processes": len(processes),
                "timestamp": datetime.now().isoformat()
            }
            return format_response(result, format)
        except Exception as e:
            return format_error(e, "get_top_processes")

    @mcp.tool()
    @secure_tool("get_network_io_counters")
    async def get_network_io_counters() -> dict:
        """Get network I/O statistics (bytes, packets, errors) - summary only."""
        import psutil

        try:
            io = psutil.net_io_counters()
            return {
                "bytes_sent_mb": round(io.bytes_sent / 1024 / 1024, 2),
                "bytes_recv_mb": round(io.bytes_recv / 1024 / 1024, 2),
                "packets_sent": io.packets_sent,
                "packets_recv": io.packets_recv,
                "errors_in": io.errin,
                "errors_out": io.errout,
                "drops_in": io.dropin,
                "drops_out": io.dropout
            }
        except Exception as e:
            return format_error(e, "get_network_io_counters")

    @mcp.tool()
    @secure_tool("health_check")
    async def health_check() -> dict:
        """Health check endpoint."""
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat()
        }

    logger.info("Registered 4 system monitoring tools")
