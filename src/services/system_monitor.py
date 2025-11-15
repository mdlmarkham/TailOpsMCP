"""
System monitoring service for SystemManager MCP Server
"""

import psutil
import os
from datetime import datetime
from typing import Dict, Optional


class SystemMonitor:
    """Service for monitoring system health and performance."""
    
    async def get_status(self, detailed: bool = False) -> Dict:
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
            
            # Load average (Linux only)
            load_avg = (0.0, 0.0, 0.0)
            if hasattr(os, 'getloadavg'):
                try:
                    load_avg = os.getloadavg()
                except OSError:
                    pass
            
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
                    "cpu_times": self._dict_from_namedtuple(psutil.cpu_times()),
                    "memory_details": self._dict_from_namedtuple(psutil.virtual_memory()),
                    "swap": self._dict_from_namedtuple(psutil.swap_memory()),
                    "network_interfaces": {
                        iface: self._dict_from_namedtuple(stats)
                        for iface, stats in psutil.net_io_counters(pernic=True).items()
                    }
                })
            
            return {"success": True, "data": status}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _dict_from_namedtuple(self, nt) -> Dict:
        """Convert namedtuple to dictionary."""
        return {field: getattr(nt, field) for field in nt._fields}
    
    async def get_process_list(self, limit: int = 50) -> Dict:
        """Get list of running processes."""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append(proc.info)
                    if len(processes) >= limit:
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Sort by CPU usage
            processes.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
            
            return {"success": True, "data": processes}
            
        except Exception as e:
            return {"success": False, "error": str(e)}