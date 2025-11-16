"""
SystemManager MCP Server - FastMCP with HTTP Transport
"""

import logging
import functools
import time
from datetime import datetime
from typing import Optional, Literal, Union
from fastmcp import FastMCP
from src.utils.toon import model_to_toon
from src.services.package_manager import PackageManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

mcp = FastMCP("SystemManager")

# Initialize services
package_manager = PackageManager()

# Cache decorator for system stats
_cache = {}
def cached(ttl_seconds: int = 5):
    """Cache function results for ttl_seconds"""
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            cache_key = f"{func.__name__}:{args}:{kwargs}"
            now = time.time()
            
            if cache_key in _cache:
                result, timestamp = _cache[cache_key]
                if now - timestamp < ttl_seconds:
                    return result
            
            result = await func(*args, **kwargs)
            _cache[cache_key] = (result, now)
            return result
        return wrapper
    return decorator

def format_error(e: Exception, tool_name: str) -> dict:
    """Format error with context"""
    return {
        "error": str(e),
        "error_type": type(e).__name__,
        "tool": tool_name
    }

def format_response(data: dict, format: str = "json") -> Union[dict, str]:
    """Format response as JSON (default) or TOON.
    
    Args:
        data: Response dictionary
        format: 'json' for standard JSON, 'toon' for compact TOON format
    
    Returns:
        dict for json format, str for toon format
    """
    if format == "toon":
        return model_to_toon(data)
    return data

@mcp.tool()
@cached(ttl_seconds=5)
async def get_system_status(format: Literal["json", "toon"] = "json") -> Union[dict, str]:
    """Get comprehensive system status with CPU, memory, disk, and uptime.
    
    Args:
        format: Response format - 'json' (default) or 'toon' (compact, token-efficient)
    """
    import psutil
    import os
    
    try:
        # Non-blocking CPU measurement
        cpu_percent = psutil.cpu_percent(interval=0.1)
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
async def get_container_list(format: Literal["json", "toon"] = "json") -> Union[dict, str]:
    """List all Docker containers with status and image information.
    
    Args:
        format: Response format - 'json' (default) or 'toon' (compact, token-efficient)
    """
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
                "image": image_name,
                "created": container.attrs['Created'],
                "ports": container.ports
            })
        
        return format_response({"containers": result, "count": len(result)}, format)
    except Exception as e:
        return format_error(e, "get_container_list")

@mcp.tool()
async def start_container(name_or_id: str) -> dict:
    """Start a Docker container by name or ID."""
    try:
        import docker
        client = docker.from_env()
        container = client.containers.get(name_or_id)
        container.start()
        return {
            "success": True,
            "container": name_or_id,
            "status": "started",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return format_error(e, "start_container")

@mcp.tool()
async def stop_container(name_or_id: str) -> dict:
    """Stop a Docker container by name or ID."""
    try:
        import docker
        client = docker.from_env()
        container = client.containers.get(name_or_id)
        container.stop()
        return {
            "success": True,
            "container": name_or_id,
            "status": "stopped",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return format_error(e, "stop_container")

@mcp.tool()
async def restart_container(name_or_id: str) -> dict:
    """Restart a Docker container by name or ID."""
    try:
        import docker
        client = docker.from_env()
        container = client.containers.get(name_or_id)
        container.restart()
        return {
            "success": True,
            "container": name_or_id,
            "status": "restarted",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return format_error(e, "restart_container")

@mcp.tool()
async def get_container_logs(name_or_id: str, lines: int = 100) -> dict:
    """Get recent logs from a Docker container."""
    try:
        import docker
        client = docker.from_env()
        container = client.containers.get(name_or_id)
        logs = container.logs(tail=lines, timestamps=True).decode('utf-8')
        return {
            "container": name_or_id,
            "lines": lines,
            "logs": logs,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return format_error(e, "get_container_logs")

@mcp.tool()
async def list_directory(path: str = "/tmp") -> dict:
    """List directory contents with file and directory names."""
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
        return format_error(e, "list_directory")

@mcp.tool()
async def get_file_info(path: str) -> dict:
    """Get detailed information about a file or directory."""
    import os
    
    try:
        stat_info = os.stat(path)
        is_dir = os.path.isdir(path)
        
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
    except FileNotFoundError:
        return {"path": path, "exists": False}
    except Exception as e:
        return format_error(e, "get_file_info")

@mcp.tool()
async def read_file(path: str, lines: int = 50, offset: int = 0) -> dict:
    """Read file contents with line limit and offset."""
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
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
    except Exception as e:
        return format_error(e, "read_file")

@mcp.tool()
async def tail_file(path: str, lines: int = 100) -> dict:
    """Get the last N lines from a file (useful for logs)."""
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            all_lines = f.readlines()
            tail_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines
            
            return {
                "path": path,
                "total_lines": len(all_lines),
                "lines_returned": len(tail_lines),
                "content": ''.join(tail_lines)
            }
    except Exception as e:
        return format_error(e, "tail_file")

@mcp.tool()
async def get_network_status(format: Literal["json", "toon"] = "json") -> Union[dict, str]:
    """Get network interface status with addresses and statistics.
    
    Args:
        format: Response format - 'json' (default) or 'toon' (compact, token-efficient)
    """
    import psutil
    
    try:
        result = {"interfaces": []}
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        
        for name, stat in stats.items():
            interface_info = {
                "name": name,
                "isup": stat.isup,
                "speed": stat.speed,
                "mtu": stat.mtu
            }
            
            # Add IP addresses if available
            if name in addrs:
                interface_info["addresses"] = []
                for addr in addrs[name]:
                    interface_info["addresses"].append({
                        "family": str(addr.family),
                        "address": addr.address,
                        "netmask": addr.netmask if addr.netmask else None
                    })
            
            result["interfaces"].append(interface_info)
        
        result["timestamp"] = datetime.now().isoformat()
        return format_response(result, format)
    except Exception as e:
        return format_error(e, "get_network_status")

@mcp.tool()
async def search_files(pattern: str, directory: str = "/tmp") -> dict:
    """Search for files by pattern (supports wildcards like *.log)."""
    import os
    import fnmatch
    
    try:
        result = {"pattern": pattern, "directory": directory, "files": []}
        for root, dirs, files in os.walk(directory):
            for filename in files:
                if fnmatch.fnmatch(filename, pattern):
                    result["files"].append(os.path.join(root, filename))
                    if len(result["files"]) >= 100:
                        result["truncated"] = True
                        return result
        return result
    except Exception as e:
        return format_error(e, "search_files")

@mcp.tool()
async def get_top_processes(limit: int = 10, sort_by: str = "cpu", format: Literal["json", "toon"] = "json") -> Union[dict, str]:
    """Get top processes by CPU or memory usage.
    
    Args:
        limit: Number of processes to return
        sort_by: Sort by 'cpu' or 'memory'
        format: Response format - 'json' (default) or 'toon' (compact, token-efficient)
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
async def get_system_overview() -> dict:
    """Get comprehensive system overview (system stats, containers, network) in one call."""
    import psutil
    import os
    
    try:
        # Inline system status
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        boot_time = psutil.boot_time()
        uptime = int(datetime.now().timestamp() - boot_time)
        
        disk_info = []
        for partition in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_info.append({
                    "mountpoint": partition.mountpoint,
                    "total": usage.total,
                    "used": usage.used,
                    "free": usage.free,
                    "percent": usage.percent
                })
            except (PermissionError, OSError):
                continue
        
        load_avg = {}
        if hasattr(os, 'getloadavg'):
            load_avg = {"1m": os.getloadavg()[0], "5m": os.getloadavg()[1], "15m": os.getloadavg()[2]}
        
        system = {
            "cpu_percent": cpu_percent,
            "load_average": load_avg,
            "memory_usage": {"total": memory.total, "available": memory.available, "used": memory.used, "percent": memory.percent},
            "disk_usage": disk_info,
            "uptime": uptime
        }
        
        # Inline container list
        containers_result = {"containers": [], "count": 0}
        try:
            import docker
            client = docker.from_env()
            containers = client.containers.list(all=True)
            for container in containers:
                image_name = container.image.tags[0] if container.image.tags else "unknown"
                containers_result["containers"].append({
                    "id": container.id[:12],
                    "name": container.name,
                    "status": container.status,
                    "image": image_name
                })
            containers_result["count"] = len(containers_result["containers"])
        except:
            pass
        
        # Inline network status
        network = {"interfaces": []}
        try:
            stats = psutil.net_if_stats()
            for name, stat in stats.items():
                network["interfaces"].append({"name": name, "isup": stat.isup, "speed": stat.speed})
        except:
            pass
        
        # Inline top processes
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            processes.sort(key=lambda p: p.get('cpu_percent', 0), reverse=True)
            processes = processes[:5]
        except:
            pass
        
        return {
            "system": system,
            "containers": containers_result,
            "network": network,
            "top_processes": processes,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return format_error(e, "get_system_overview")

@mcp.tool()
async def health_check() -> dict:
    """Health check."""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

# ============================================================================
# NETWORK DIAGNOSTICS - Token-efficient output
# ============================================================================

@mcp.tool()
async def ping_host(host: str, count: int = 4, format: Literal["json", "toon"] = "json") -> Union[dict, str]:
    """Ping a host and return latency statistics (min/avg/max/loss).
    
    Args:
        host: Hostname or IP address to ping
        count: Number of ping packets to send
        format: Response format - 'json' (default) or 'toon' (compact, token-efficient)
    """
    import subprocess
    import re
    
    try:
        # Linux/Unix ping command
        result = subprocess.run(
            ['ping', '-c', str(count), host],
            capture_output=True,
            text=True,
            timeout=count + 5
        )
        
        # Parse compact stats from output
        stats = {"host": host, "count": count, "reachable": False}
        
        if result.returncode == 0:
            stats["reachable"] = True
            # Extract packet loss
            loss_match = re.search(r'(\d+)% packet loss', result.stdout)
            if loss_match:
                stats["loss_percent"] = int(loss_match.group(1))
            
            # Extract rtt stats (min/avg/max/mdev)
            rtt_match = re.search(r'min/avg/max/\w+ = ([\d.]+)/([\d.]+)/([\d.]+)', result.stdout)
            if rtt_match:
                stats["latency_ms"] = {
                    "min": float(rtt_match.group(1)),
                    "avg": float(rtt_match.group(2)),
                    "max": float(rtt_match.group(3))
                }
        
        return format_response(stats, format)

@mcp.tool()
async def test_tcp_port(host: str, port: int, timeout: int = 5) -> dict:
    """Test TCP port connectivity (returns open/closed status and latency)."""
    import socket
    import time as tm
    
    try:
        start = tm.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        result = sock.connect_ex((host, port))
        latency = (tm.time() - start) * 1000  # Convert to ms
        sock.close()
        
        return {
            "host": host,
            "port": port,
            "open": result == 0,
            "latency_ms": round(latency, 2) if result == 0 else None
        }
    except Exception as e:
        return format_error(e, "test_tcp_port")

@mcp.tool()
async def dns_lookup(domain: str, record_type: str = "A") -> dict:
    """DNS lookup (supports A, AAAA, MX, TXT, CNAME). Returns compact results."""
    import socket
    
    try:
        results = {"domain": domain, "type": record_type, "records": []}
        
        if record_type == "A":
            # IPv4 addresses
            results["records"] = socket.gethostbyname_ex(domain)[2]
        elif record_type == "AAAA":
            # IPv6 addresses
            info = socket.getaddrinfo(domain, None, socket.AF_INET6)
            results["records"] = list(set([addr[4][0] for addr in info]))
        else:
            # For MX, TXT, CNAME - require dnspython (optional)
            try:
                import dns.resolver
                answers = dns.resolver.resolve(domain, record_type)
                results["records"] = [str(rdata) for rdata in answers]
            except ImportError:
                results["error"] = f"{record_type} records require 'dnspython' package"
        
        results["count"] = len(results["records"])
        return results
    except Exception as e:
        return format_error(e, "dns_lookup")

@mcp.tool()
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
async def get_active_connections(limit: int = 20, format: Literal["json", "toon"] = "json") -> Union[dict, str]:
    """Get active network connections (limited to 'limit' for token efficiency).
    
    Args:
        limit: Maximum number of connections to return
        format: Response format - 'json' (default) or 'toon' (compact, token-efficient)
    """
    import psutil
    
    try:
        conns = psutil.net_connections(kind='inet')
        
        # Group by status for summary
        summary = {}
        detailed = []
        
        for conn in conns[:limit]:
            status = conn.status
            summary[status] = summary.get(status, 0) + 1
            
            if len(detailed) < limit:
                detailed.append({
                    "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    "status": status,
                    "pid": conn.pid
                })
        
        result = {
            "total": len(conns),
            "summary": summary,
            "connections": detailed,
            "truncated": len(conns) > limit
        }
        return format_response(result, format)
    except Exception as e:
        return format_error(e, "get_active_connections")

@mcp.tool()
async def check_open_ports(ports: list[int] = [22, 80, 443, 3306, 5432, 6379, 8080]) -> dict:
    """Check which ports are listening on localhost (returns only open ports)."""
    import socket
    
    try:
        open_ports = []
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            
            if result == 0:
                open_ports.append(port)
        
        return {
            "scanned": len(ports),
            "open": open_ports,
            "count": len(open_ports)
        }
    except Exception as e:
        return format_error(e, "check_open_ports")

@mcp.tool()
async def http_request_test(url: str, method: str = "GET", timeout: int = 10) -> dict:
    """Test HTTP/HTTPS request (returns timing breakdown and status)."""
    import time as tm
    
    try:
        import requests
        
        start = tm.time()
        response = requests.request(method, url, timeout=timeout, allow_redirects=True)
        total_time = (tm.time() - start) * 1000
        
        return {
            "url": url,
            "method": method,
            "status_code": response.status_code,
            "ok": response.ok,
            "total_time_ms": round(total_time, 2),
            "size_bytes": len(response.content),
            "redirects": len(response.history)
        }
    except Exception as e:
        return format_error(e, "http_request_test")

@mcp.tool()
async def check_ssl_certificate(host: str, port: int = 443) -> dict:
    """Check SSL/TLS certificate (returns validity, expiration, issuer - compact)."""
    import socket
    import ssl
    from datetime import datetime
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                
                # Parse expiration
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (not_after - datetime.now()).days
                
                return {
                    "host": host,
                    "valid": True,
                    "subject": dict(x[0] for x in cert['subject']),
                    "issuer": dict(x[0] for x in cert['issuer'])['organizationName'],
                    "expires": cert['notAfter'],
                    "days_until_expiry": days_until_expiry,
                    "expired": days_until_expiry < 0,
                    "expiring_soon": 0 < days_until_expiry < 30
                }
    except Exception as e:
        return format_error(e, "check_ssl_certificate")

@mcp.tool()
async def get_docker_networks() -> dict:
    """List Docker networks (compact summary)."""
    try:
        import docker
        client = docker.from_env()
        networks = client.networks.list()
        
        return {
            "networks": [
                {
                    "name": net.name,
                    "id": net.id[:12],
                    "driver": net.attrs['Driver'],
                    "scope": net.attrs['Scope'],
                    "containers": len(net.attrs.get('Containers', {}))
                }
                for net in networks
            ],
            "count": len(networks)
        }
    except Exception as e:
        return format_error(e, "get_docker_networks")

@mcp.tool()
async def traceroute(host: str, max_hops: int = 15) -> dict:
    """Perform traceroute (returns hop summary, not full details)."""
    import subprocess
    import re
    
    try:
        result = subprocess.run(
            ['traceroute', '-m', str(max_hops), '-w', '2', host],
            capture_output=True,
            text=True,
            timeout=max_hops * 3
        )
        
        hops = []
        for line in result.stdout.split('\n')[1:]:  # Skip header
            if not line.strip():
                continue
            
            # Extract hop number and IP/hostname (simplified parsing)
            match = re.match(r'\s*(\d+)\s+(\S+)', line)
            if match:
                hop_num = int(match.group(1))
                hop_addr = match.group(2)
                if hop_addr != '*':
                    hops.append({"hop": hop_num, "address": hop_addr})
        
        return {
            "host": host,
            "hops": hops,
            "hop_count": len(hops),
            "reached": hops[-1]["address"] == host if hops else False
        }
    except Exception as e:
        return format_error(e, "traceroute")

# System Package Management Tools

@mcp.tool()
async def check_system_updates() -> dict:
    """Check for available system package updates without installing.
    
    Returns list of packages that can be upgraded with version information.
    Supports apt (Debian/Ubuntu) and yum (RHEL/CentOS) based systems.
    """
    try:
        result = await package_manager.check_updates()
        return result
    except Exception as e:
        return format_error(e, "check_system_updates")

@mcp.tool()
async def update_system_packages(auto_approve: bool = False) -> dict:
    """Update all system packages (apt-get upgrade or yum update).
    
    Args:
        auto_approve: If True, automatically approve updates without prompting.
                     Use with caution in production environments.
    
    Note: Requires sudo privileges. May take several minutes.
    """
    try:
        result = await package_manager.update_system(auto_approve)
        return result
    except Exception as e:
        return format_error(e, "update_system_packages")

@mcp.tool()
async def install_package(package_name: str, auto_approve: bool = False) -> dict:
    """Install a specific system package.
    
    Args:
        package_name: Name of the package to install
        auto_approve: If True, automatically approve installation without prompting
    
    Note: Requires sudo privileges.
    """
    try:
        result = await package_manager.install_package(package_name, auto_approve)
        return result
    except Exception as e:
        return format_error(e, "install_package")

# Docker Image Management Tools

@mcp.tool()
async def pull_docker_image(image_name: str, tag: str = "latest") -> dict:
    """Pull a Docker image from registry.
    
    Args:
        image_name: Name of the image (e.g., 'nginx', 'mysql', 'ubuntu')
        tag: Image tag (default: 'latest')
    
    Returns image ID, tags, and size information.
    """
    try:
        import docker
        client = docker.from_env()
        from src.services.docker_manager import DockerManager
        dm = DockerManager()
        dm.client = client
        result = await dm.pull_image(image_name, tag)
        return result
    except Exception as e:
        return format_error(e, "pull_docker_image")

@mcp.tool()
async def update_docker_container(name_or_id: str, pull_latest: bool = True) -> dict:
    """Update a Docker container by pulling latest image and recreating it.
    
    This stops the container, pulls the latest image (if requested), 
    removes the old container, and creates a new one with the same configuration.
    
    Args:
        name_or_id: Container name or ID to update
        pull_latest: Whether to pull latest image first (default: True)
    
    Warning: Container will be stopped and recreated. Ensure data is in volumes.
    """
    try:
        import docker
        client = docker.from_env()
        from src.services.docker_manager import DockerManager
        dm = DockerManager()
        dm.client = client
        result = await dm.update_container(name_or_id, pull_latest)
        return result
    except Exception as e:
        return format_error(e, "update_docker_container")

@mcp.tool()
async def list_docker_images() -> dict:
    """List all Docker images on the system.
    
    Returns image IDs, tags, sizes, and creation dates.
    """
    try:
        import docker
        client = docker.from_env()
        from src.services.docker_manager import DockerManager
        dm = DockerManager()
        dm.client = client
        result = await dm.list_images()
        return result
    except Exception as e:
        return format_error(e, "list_docker_images")

if __name__ == "__main__":
    logger.info("Starting SystemManager MCP Server on http://0.0.0.0:8080")
    mcp.run(transport="sse", host="0.0.0.0", port=8080)

