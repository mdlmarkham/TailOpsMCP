"""
Network status service for SystemManager MCP Server
"""

import psutil
import socket
from typing import Dict, List, Optional


class NetworkStatus:
    """Service for monitoring network interfaces and connectivity."""
    
    async def get_status(self, interface: Optional[str] = None) -> Dict:
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
                    interfaces[iface]["io_stats"] = self._dict_from_namedtuple(io_stats[iface])
            
            return {"success": True, "data": list(interfaces.values())}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def test_connectivity(self, host: str, port: int = 80, timeout: float = 5.0) -> Dict:
        """Test connectivity to a remote host."""
        try:
            start_time = psutil.cpu_times().user
            
            # Try to resolve hostname first
            try:
                ip = socket.gethostbyname(host)
            except socket.gaierror:
                return {"success": False, "error": f"Could not resolve host: {host}"}
            
            # Test TCP connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            try:
                sock.connect((ip, port))
                end_time = psutil.cpu_times().user
                latency = (end_time - start_time) * 1000  # Convert to milliseconds
                
                result = {
                    "host": host,
                    "ip": ip,
                    "port": port,
                    "reachable": True,
                    "latency_ms": round(latency, 2)
                }
                
                return {"success": True, "data": result}
                
            except socket.timeout:
                return {"success": False, "error": f"Connection timeout to {host}:{port}"}
            except ConnectionRefusedError:
                return {"success": False, "error": f"Connection refused by {host}:{port}"}
            except Exception as e:
                return {"success": False, "error": str(e)}
            finally:
                sock.close()
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def get_connections(self) -> Dict:
        """Get active network connections."""
        try:
            connections = psutil.net_connections()
            connection_list = []
            
            for conn in connections:
                if conn.status == "LISTEN":
                    continue  # Skip listening sockets
                
                conn_info = {
                    "family": str(conn.family),
                    "type": str(conn.type),
                    "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                    "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                    "status": conn.status,
                    "pid": conn.pid
                }
                connection_list.append(conn_info)
            
            return {"success": True, "data": connection_list}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _dict_from_namedtuple(self, nt) -> Dict:
        """Convert namedtuple to dictionary."""
        return {field: getattr(nt, field) for field in nt._fields}