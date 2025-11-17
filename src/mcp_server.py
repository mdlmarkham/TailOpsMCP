"""
TailOpsMCP - FastMCP with HTTP Transport

Supports two authentication modes:
1. TSIDP OIDC - Uses Tailscale Identity Provider for zero-trust SSO
2. HMAC Token - Legacy token-based authentication

Set SYSTEMMANAGER_AUTH_MODE environment variable:
- "oidc" - Use TSIDP as OIDC provider (recommended)
- "token" - Use HMAC token authentication (default)
"""

import logging
import functools
import time
import os
from datetime import datetime
from typing import Optional, Literal, Union, Any, Dict
from fastmcp import FastMCP, Context
from src.utils.toon import model_to_toon
from src.services.package_manager import PackageManager
from src.auth.middleware import secure_tool
from src.tools import stack_tools
from src.services.log_analyzer import LogAnalyzer

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
# Enable FastMCP auth debugging
logging.getLogger("fastmcp.server.auth").setLevel(logging.DEBUG)

# Determine authentication mode
AUTH_MODE = os.getenv("SYSTEMMANAGER_AUTH_MODE", "token").lower()

# Create FastMCP instance
if AUTH_MODE == "oidc":
    # TSIDP OIDC Authentication using Token Introspection
    tsidp_url = os.getenv("TSIDP_URL", "https://tsidp.tailf9480.ts.net")
    base_url = os.getenv("SYSTEMMANAGER_BASE_URL", "http://localhost:8080")
    client_id = os.getenv("TSIDP_CLIENT_ID")
    client_secret = os.getenv("TSIDP_CLIENT_SECRET")
    
    if not client_id or not client_secret:
        raise ValueError("TSIDP_CLIENT_ID and TSIDP_CLIENT_SECRET required for OIDC mode")
    
    logger.info(f"Configuring OIDC authentication with TSIDP: {tsidp_url}")
    
    from fastmcp.server.auth import RemoteAuthProvider
    from pydantic import AnyHttpUrl
    from src.auth.tsidp_introspection import TSIDPIntrospectionVerifier
    
    # TSIDP token verification using RFC 7662 introspection
    # TSIDP issues opaque access tokens, not JWTs
    token_verifier = TSIDPIntrospectionVerifier(
        introspection_endpoint=f"{tsidp_url}/introspect",
        client_id=client_id,
        client_secret=client_secret,
        audience=base_url + "/mcp",  # Expected resource identifier
    )
    
    auth = RemoteAuthProvider(
        token_verifier=token_verifier,
        authorization_servers=[AnyHttpUrl(tsidp_url)],
        base_url=base_url,
    )
    mcp = FastMCP("TailOpsMCP", auth=auth)
    logger.info("OIDC authentication enabled - users will authenticate via Tailscale")
    logger.info(f"Token introspection endpoint: {tsidp_url}/introspect")
else:
    # Token-based authentication (default)
    mcp = FastMCP("TailOpsMCP")
    logger.info("Token-based authentication enabled")

# Initialize log analyzer
log_analyzer = LogAnalyzer()

# Initialize services
package_manager = PackageManager()

# Initialize inventory
from src.inventory import Inventory, SystemIdentity, ApplicationMetadata
from src.services.app_scanner import ApplicationScanner
inventory = Inventory()
app_scanner = ApplicationScanner()

# Try to load or detect system identity at startup
system_identity = inventory.get_system_identity()
if not system_identity:
    # Auto-detect on first run
    import socket
    import platform
    hostname = socket.gethostname()
    
    # Try to detect if running in Proxmox LXC
    container_id = None
    container_type = None
    try:
        # Check for Proxmox container ID in /proc/self/cgroup
        with open('/proc/self/cgroup', 'r') as f:
            content = f.read()
            if 'lxc' in content:
                container_type = 'lxc'
                # Try to extract VMID/CTID
                import re
                match = re.search(r'/lxc/(\d+)/', content)
                if match:
                    container_id = match.group(1)
    except (FileNotFoundError, PermissionError):
        # Running on bare metal or can't detect
        container_type = 'bare-metal' if platform.system() != 'Windows' else None
    
    system_identity = SystemIdentity(
        hostname=hostname,
        container_id=container_id,
        container_type=container_type
    )
    inventory.set_system_identity(system_identity)
    logger.info(f"Auto-detected system identity: {system_identity.get_display_name()}")
else:
    logger.info(f"Loaded system identity: {system_identity.get_display_name()}")

# Update MCP server name if configured
if system_identity and system_identity.get_display_name() != "TailOpsMCP":
    # Note: FastMCP name is set during instantiation, so this is for logging
    logger.info(f"MCP Server ID: {system_identity.get_display_name()}")

# Docker client singleton (P1 optimization)
_docker_client = None

def get_docker_client():
    """Get or create Docker client singleton."""
    global _docker_client
    if _docker_client is None:
        import docker
        _docker_client = docker.from_env()
    return _docker_client

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
@secure_tool("get_container_list")
async def get_container_list(format: Literal["json", "toon"] = "toon") -> Union[dict, str]:
    """List all Docker containers with status and image information.
    
    Args:
        format: Response format - 'toon' (compact, default) or 'json' (verbose)
    """
    try:
        client = get_docker_client()
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
@secure_tool("manage_container")
async def manage_container(action: Literal["start", "stop", "restart", "logs"], name_or_id: str, lines: int = 100) -> dict:
    """Manage Docker container lifecycle: start, stop, restart, or get logs.
    
    Args:
        action: Operation to perform (start|stop|restart|logs)
        name_or_id: Container name or ID
        lines: Number of log lines to retrieve (only for 'logs' action)
    """
    try:
        client = get_docker_client()
        container = client.containers.get(name_or_id)
        
        if action == "start":
            container.start()
            return {
                "success": True,
                "container": name_or_id,
                "action": "started",
                "timestamp": datetime.now().isoformat()
            }
        elif action == "stop":
            container.stop()
            return {
                "success": True,
                "container": name_or_id,
                "action": "stopped",
                "timestamp": datetime.now().isoformat()
            }
        elif action == "restart":
            container.restart()
            return {
                "success": True,
                "container": name_or_id,
                "action": "restarted",
                "timestamp": datetime.now().isoformat()
            }
        elif action == "logs":
            logs = container.logs(tail=lines, timestamps=True).decode('utf-8')
            return {
                "success": True,
                "container": name_or_id,
                "action": "logs",
                "lines": lines,
                "logs": logs,
                "timestamp": datetime.now().isoformat()
            }
        else:
            return {"success": False, "error": f"Invalid action: {action}"}
    except Exception as e:
        return format_error(e, "manage_container")

@mcp.tool()
@secure_tool("analyze_container_logs")
async def analyze_container_logs(
    name_or_id: str,
    lines: int = 200,
    context: Optional[str] = None,
    use_ai: bool = True,
    ctx: Context = None
) -> dict:
    """Analyze Docker container logs OR system log files using AI to extract insights and identify issues.
    
    This tool uses AI sampling to intelligently analyze logs, providing:
    - Summary of log contents
    - Identified errors and warnings with severity
    - Root cause analysis
    - Performance issue detection
    - Actionable recommendations
    
    Args:
        name_or_id: Container name/ID OR path to system log file
                   - For Docker: container name like "nginx" or ID like "abc123"
                   - For system logs: full path like "/var/log/syslog" or "/var/log/auth.log"
                   - Common system logs: syslog, auth.log, kern.log, dmesg, apache2/error.log
        lines: Number of recent log lines to analyze (default: 200)
        context: Optional context about what to look for (e.g., "why did it crash?", "find security issues")
        use_ai: Use AI analysis if available, otherwise fallback to pattern matching
    
    Returns:
        Comprehensive analysis including summary, errors, root cause, and recommendations
        
    Examples:
        - Docker: name_or_id="nginx"
        - System: name_or_id="/var/log/syslog"
        - Auth:   name_or_id="/var/log/auth.log"
    """
    try:
        # Check if it's a file path (system log)
        if name_or_id.startswith('/'):
            # System log file analysis
            log_path = name_or_id
            
            # Read the log file (tail last N lines)
            import subprocess
            result = subprocess.run(
                ['tail', '-n', str(lines), log_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"Failed to read log file: {result.stderr}"
                }
            
            logs = result.stdout
            log_name = log_path.split('/')[-1]
            
            # Perform intelligent analysis
            analysis = await log_analyzer.analyze_container_logs(
                container_name=f"System Log: {log_name}",
                logs=logs,
                analysis_context=context,
                use_ai=use_ai,
                mcp_context=ctx
            )
            
            return analysis
        
        else:
            # Docker container log analysis (original behavior)
            client = get_docker_client()
            container = client.containers.get(name_or_id)
            logs = container.logs(tail=lines, timestamps=True).decode('utf-8')
            
            # Perform intelligent analysis - pass Context for AI sampling
            analysis = await log_analyzer.analyze_container_logs(
                container_name=container.name,
                logs=logs,
                analysis_context=context,
                use_ai=use_ai,
                mcp_context=ctx
            )
            
            return analysis
        
    except Exception as e:
        logger.error(f"Log analysis failed: {e}")
        return format_error(e, "analyze_container_logs")

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


@mcp.tool()
@secure_tool("get_stack_network_info")
async def get_stack_network_info(
    host: str,
    stack_name: str,
    format: Literal["json", "toon"] = "json",
) -> Union[dict, str]:
    """Return Docker stack network metadata via the stack_tools helper."""

    try:
        info = await stack_tools.get_stack_network_info(host, stack_name)
        return format_response(info, format)
    except Exception as e:
        logger.exception("get_stack_network_info failed for host=%s stack=%s", host, stack_name)
        return format_error(e, "get_stack_network_info")

@mcp.tool()
@secure_tool("get_network_status")
async def get_network_status(format: Literal["json", "toon"] = "toon") -> Union[dict, str]:
    """Get network interface status with addresses and statistics.
    
    Args:
        format: Response format - 'toon' (compact, default) or 'json' (verbose)
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
@secure_tool("get_top_processes")
async def get_top_processes(limit: int = 10, sort_by: str = "cpu", format: Literal["json", "toon"] = "toon") -> Union[dict, str]:
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
@secure_tool("health_check")
async def health_check() -> dict:
    """Health check."""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

# ============================================================================
# NETWORK DIAGNOSTICS - Token-efficient output

# ============================================================================
# NETWORK DIAGNOSTICS - Token-efficient output
# ============================================================================

@mcp.tool()
@secure_tool("ping_host")
async def ping_host(host: str, count: int = 4, format: Literal["json", "toon"] = "toon") -> Union[dict, str]:
    """Ping a host and return latency statistics (min/avg/max/loss).
    
    Args:
        host: Hostname or IP address to ping
        count: Number of ping packets to send
        format: Response format - 'toon' (compact, default) or 'json' (verbose)
    """
    import subprocess
    import re
    from src.utils import netsec
    
    try:
        # SECURITY: Validate host to prevent SSRF
        host_allowed, reason = netsec.is_host_allowed(host)
        if not host_allowed:
            return format_response({
                "success": False,
                "error": f"Access denied: {reason}",
                "host": host
            }, format)
        
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
    except Exception as e:
        return format_error(e, "ping_host")

@mcp.tool()
@secure_tool("test_port_connectivity")
async def test_port_connectivity(host: str, port: int = None, ports: list[int] = None, timeout: int = 5) -> dict:
    """Test TCP port connectivity - single port or multiple ports.
    
    Args:
        host: Hostname or IP address (use '127.0.0.1' or 'localhost' for local)
        port: Single port to test
        ports: List of ports to test (alternative to single port)
        timeout: Connection timeout in seconds
    
    Examples:
        - Single port: test_port_connectivity(host="example.com", port=443)
        - Multiple ports: test_port_connectivity(host="localhost", ports=[22, 80, 443])
    """
    import socket
    import time as tm
    from src.utils import netsec
    
    try:
        # SECURITY: Validate host and ports
        host_allowed, host_reason = netsec.is_host_allowed(host)
        if not host_allowed:
            return {
                "success": False,
                "error": f"Access denied: {host_reason}",
            }
        
        # Determine which ports to test
        test_ports = []
        if port:
            port_allowed, reason = netsec.is_port_allowed(port)
            if not port_allowed:
                return {"success": False, "error": f"Port {port} is not allowed: {reason}"}
            test_ports = [port]
        elif ports:
            filtered_ports = []
            for p in ports:
                allowed, _reason = netsec.is_port_allowed(p)
                if allowed:
                    filtered_ports.append(p)
            test_ports = filtered_ports
            if not test_ports:
                return {"success": False, "error": "No allowed ports in request"}
        else:
            # Default common ports for localhost (filtered through allowlist)
            default_ports = [22, 80, 443, 3306, 5432, 6379, 8080]
            test_ports = [p for p in default_ports if netsec.is_port_allowed(p)[0]]
            if not test_ports:
                return {"success": False, "error": "No default ports are permitted by the allowlist"}
        
        results = []
        open_count = 0
        
        for p in test_ports:
            start = tm.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            result_code = sock.connect_ex((host, p))
            latency = (tm.time() - start) * 1000  # Convert to ms
            sock.close()
            
            is_open = result_code == 0
            if is_open:
                open_count += 1
                
            results.append({
                "port": p,
                "open": is_open,
                "latency_ms": round(latency, 2) if is_open else None
            })
        
        return {
            "host": host,
            "scanned": len(test_ports),
            "open_count": open_count,
            "ports": results
        }
    except Exception as e:
        return format_error(e, "test_port_connectivity")

@mcp.tool()
@secure_tool("dns_lookup")
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
@secure_tool("get_active_connections")
async def get_active_connections(limit: int = 20, format: Literal["json", "toon"] = "toon") -> Union[dict, str]:
    """Get active network connections (limited to 'limit' for token efficiency).
    
    Args:
        limit: Maximum number of connections to return
        format: Response format - 'toon' (compact, default) or 'json' (verbose)
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
@secure_tool("http_request_test")
async def http_request_test(url: str, method: str = "GET", timeout: int = 10) -> dict:
    """Test HTTP/HTTPS request (returns timing breakdown and status)."""
    import time as tm
    from src.utils import netsec
    
    try:
        # SECURITY: Validate URL to prevent SSRF
        url_allowed, reason = netsec.is_url_allowed(url)
        if not url_allowed:
            return {
                "success": False,
                "error": f"Access denied: {reason}",
                "url": url,
            }
        
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
@secure_tool("check_ssl_certificate")
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
@secure_tool("get_docker_networks")
async def get_docker_networks(format: Literal["json", "toon"] = "toon") -> Union[dict, str]:
    """List Docker networks (compact summary).
    
    Args:
        format: Response format - 'toon' (compact, default) or 'json' (verbose)
    """
    try:
        client = get_docker_client()
        networks = client.networks.list()
        
        result = {
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
        return format_response(result, format)
    except Exception as e:
        return format_error(e, "get_docker_networks")

@mcp.tool()
@secure_tool("traceroute")
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
@secure_tool("check_system_updates")
async def manage_packages(
    action: Literal["check", "update", "install"],
    package_name: str = None,
    auto_approve: bool = False
) -> dict:
    """Manage system packages: check updates, update all, or install specific package.
    
    Args:
        action: Operation to perform (check|update|install)
        package_name: Package name (required for 'install' action)
        auto_approve: Auto-approve without prompting (for update/install)
    
    Note: update/install require sudo privileges and may take several minutes.
    Supports apt (Debian/Ubuntu) and yum (RHEL/CentOS) based systems.
    """
    try:
        if action == "check":
            result = await package_manager.check_updates()
        elif action == "update":
            result = await package_manager.update_system(auto_approve)
        elif action == "install":
            if not package_name:
                return {"error": "package_name required for install action"}
            result = await package_manager.install_package(package_name, auto_approve)
        else:
            return {"error": f"Invalid action: {action}"}
        return result
    except Exception as e:
        return format_error(e, "manage_packages")

# Docker Image Management Tools

@mcp.tool()
@secure_tool("pull_docker_image")
async def pull_docker_image(image_name: str, tag: str = "latest") -> dict:
    """Pull a Docker image from registry.
    
    Args:
        image_name: Name of the image (e.g., 'nginx', 'mysql', 'ubuntu')
        tag: Image tag (default: 'latest')
    
    Returns image ID, tags, and size information.
    """
    try:
        client = get_docker_client()
        from src.services.docker_manager import DockerManager
        dm = DockerManager()
        dm.client = client
        result = await dm.pull_image(image_name, tag)
        return result
    except Exception as e:
        return format_error(e, "pull_docker_image")

@mcp.tool()
@secure_tool("update_docker_container")
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
        client = get_docker_client()
        from src.services.docker_manager import DockerManager
        dm = DockerManager()
        dm.client = client
        result = await dm.update_container(name_or_id, pull_latest)
        return result
    except Exception as e:
        return format_error(e, "update_docker_container")

@mcp.tool()
@secure_tool("list_docker_images")
async def list_docker_images(format: Literal["json", "toon"] = "toon") -> Union[dict, str]:
    """List all Docker images on the system.
    
    Args:
        format: Response format - 'toon' (compact, default) or 'json' (verbose)
    
    Returns image IDs, tags, sizes, and creation dates.
    """
    try:
        client = get_docker_client()
        from src.services.docker_manager import DockerManager
        dm = DockerManager()
        dm.client = client
        result = await dm.list_images()
        return format_response(result, format)
    except Exception as e:
        return format_error(e, "list_docker_images")

# ============================================================================
# INVENTORY MANAGEMENT - Track system identity and installed applications
# ============================================================================

@mcp.tool()
@secure_tool("scan_installed_applications")
async def scan_installed_applications(save_to_inventory: bool = True) -> dict:
    """Scan the system for installed applications (Jellyfin, Pi-hole, Ollama, PostgreSQL, etc.).
    
    This auto-detects common home lab applications running directly on the LXC container,
    not just Docker containers. Useful for initial system discovery.
    
    Args:
        save_to_inventory: If True, automatically save detected apps to inventory
    
    Returns:
        Dictionary with detected applications and their metadata
    """
    try:
        detected = app_scanner.scan()
        
        result = {
            "scanned_at": datetime.now().isoformat(),
            "system": system_identity.get_display_name() if system_identity else "unknown",
            "detected_count": len(detected),
            "applications": []
        }
        
        for app in detected:
            app_data = {
                "name": app.name,
                "type": app.type,
                "version": app.version,
                "port": app.port,
                "service_name": app.service_name,
                "config_path": app.config_path,
                "data_path": app.data_path,
                "confidence": app.confidence
            }
            result["applications"].append(app_data)
            
            # Save to inventory if requested
            if save_to_inventory:
                app_meta = ApplicationMetadata(
                    name=app.name,
                    type=app.type,
                    version=app.version,
                    port=app.port,
                    service_name=app.service_name,
                    config_path=app.config_path,
                    data_path=app.data_path,
                    auto_detected=True
                )
                inventory.add_application(app.name, app_meta)
        
        if save_to_inventory and detected:
            result["saved_to_inventory"] = True
            logger.info(f"Saved {len(detected)} detected applications to inventory")
        
        return result
    except Exception as e:
        return format_error(e, "scan_installed_applications")

@mcp.tool()
@secure_tool("get_inventory")
async def get_inventory() -> dict:
    """Get the complete system inventory including identity, applications, and stacks.
    
    Returns:
        Complete inventory with system identity, applications, and Docker stacks
    """
    try:
        system = inventory.get_system_identity()
        apps = inventory.list_applications()
        stacks = inventory.list_stacks()
        
        return {
            "system": {
                "hostname": system.hostname if system else "unknown",
                "container_id": system.container_id if system else None,
                "container_type": system.container_type if system else None,
                "display_name": system.get_display_name() if system else "unknown",
                "mcp_server_name": system.mcp_server_name if system else None
            } if system else None,
            "applications": apps,
            "stacks": stacks,
            "inventory_path": inventory.path,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return format_error(e, "get_inventory")

@mcp.tool()
@secure_tool("add_application_to_inventory")
async def manage_inventory(
    action: Literal["add", "remove"],
    name: str,
    app_type: str = None,
    version: Optional[str] = None,
    port: Optional[int] = None,
    service_name: Optional[str] = None,
    config_path: Optional[str] = None,
    data_path: Optional[str] = None,
    notes: Optional[str] = None
) -> dict:
    """Add or remove applications from the inventory.
    
    Args:
        action: Operation to perform (add|remove)
        name: Application name (e.g., "jellyfin", "pihole")
        app_type: Type/category (required for add: "media-server", "dns", "database")
        version: Application version (optional, for add)
        port: Primary port number (optional, for add)
        service_name: systemd service name (optional, for add)
        config_path: Configuration directory (optional, for add)
        data_path: Data directory (optional, for add)
        notes: Custom notes (optional, for add)
    """
    try:
        if action == "add":
            if not app_type:
                return {"error": "app_type required for add action"}
            
            app_meta = ApplicationMetadata(
                name=name,
                type=app_type,
                version=version,
                port=port,
                service_name=service_name,
                config_path=config_path,
                data_path=data_path,
                auto_detected=False,
                notes=notes
            )
            
            inventory.add_application(name, app_meta)
            
            return {
                "success": True,
                "action": "added",
                "application": name,
                "details": {
                    "name": name,
                    "type": app_type,
                    "version": version,
                    "port": port,
                    "service_name": service_name,
                    "config_path": config_path,
                    "data_path": data_path,
                    "notes": notes
                },
                "timestamp": datetime.now().isoformat()
            }
        
        elif action == "remove":
            app = inventory.get_application(name)
            if not app:
                return {
                    "success": False,
                    "error": f"Application '{name}' not found in inventory"
                }
            
            inventory.remove_application(name)
            
            return {
                "success": True,
                "action": "removed",
                "application": name,
                "timestamp": datetime.now().isoformat()
            }
        
        else:
            return {"error": f"Invalid action: {action}"}
            
    except Exception as e:
        return format_error(e, "manage_inventory")

@mcp.tool()
@secure_tool("set_system_identity")
async def set_system_identity(
    hostname: Optional[str] = None,
    container_id: Optional[str] = None,
    container_type: Optional[str] = None,
    mcp_server_name: Optional[str] = None
) -> dict:
    """Set or update the system identity for this MCP server instance.
    
    This is useful when managing multiple systems with a single LLM, as each
    system can have a unique identifier (hostname + container ID).
    
    Args:
        hostname: System hostname (auto-detected if not provided)
        container_id: Proxmox VMID/CTID (e.g., "103")
        container_type: "lxc", "vm", or "bare-metal"
        mcp_server_name: Custom name for this MCP server instance
    
    Returns:
        Updated system identity
    """
    try:
        import socket
        
        # Use current identity as base if it exists
        current = inventory.get_system_identity()
        
        new_identity = SystemIdentity(
            hostname=hostname or (current.hostname if current else socket.gethostname()),
            container_id=container_id or (current.container_id if current else None),
            container_type=container_type or (current.container_type if current else None),
            mcp_server_name=mcp_server_name or (current.mcp_server_name if current else None)
        )
        
        inventory.set_system_identity(new_identity)
        
        # Update global reference
        global system_identity
        system_identity = new_identity
        
        logger.info(f"Updated system identity: {new_identity.get_display_name()}")
        
        return {
            "success": True,
            "action": "updated",
            "system_identity": {
                "hostname": new_identity.hostname,
                "container_id": new_identity.container_id,
                "container_type": new_identity.container_type,
                "display_name": new_identity.get_display_name(),
                "mcp_server_name": new_identity.mcp_server_name
            },
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return format_error(e, "set_system_identity")

# ============================================================================
# PROMPTS - Pre-configured workflows for common home lab tasks
# ============================================================================

@mcp.prompt(
    description="Comprehensive security audit of the system including logs, Docker containers, and network configuration",
    tags={"security", "audit", "homelab"}
)
def security_audit() -> str:
    """Generate a comprehensive security audit prompt for the home lab."""
    return """Please perform a comprehensive security audit of this home lab system:

1. **System Logs Analysis**
   - Analyze /var/log/syslog for the last 500 lines
   - Look for failed authentication attempts
   - Check for suspicious network connections
   - Identify any security warnings or errors

2. **Docker Security**
   - List all running containers
   - Check for containers running as root
   - Analyze container logs for security issues
   - Review exposed ports and network configuration

3. **Network Security**
   - Show active network connections
   - Check for unusual listening ports
   - Review firewall configuration (if available)
   - Test connectivity to critical services

4. **System Health**
   - Check system resource usage
   - Review disk space and permissions
   - Look for any performance anomalies

Please provide:
- Summary of findings
- Severity ratings (Critical/High/Medium/Low)
- Specific remediation recommendations
- Commands to fix identified issues
"""

@mcp.prompt(
    description="Quick health check of all critical home lab services",
    tags={"monitoring", "health", "homelab"}
)
def health_check() -> str:
    """Generate a health check prompt for monitoring critical services."""
    return """Please perform a quick health check of this home lab:

1. **System Status**
   - CPU, memory, and disk usage
   - System uptime and load average
   - Any resource warnings

2. **Docker Containers**
   - List all containers with their status
   - Identify any stopped or restarting containers
   - Check resource usage of top containers

3. **Network Connectivity**
   - Ping test to 1.1.1.1 (internet connectivity)
   - Check Tailscale connection status (if available)
   - Review active network connections

4. **Recent Errors**
   - Check system logs for errors in last 100 lines
   - Review Docker container logs for failures

Provide:
- Overall health score (Healthy/Degraded/Critical)
- List of issues found
- Quick fix commands for any problems
"""

@mcp.prompt(
    description="Troubleshoot a specific Docker container that's having issues",
    tags={"docker", "troubleshooting", "homelab"}
)
def troubleshoot_container(container_name: str) -> str:
    """Generate a troubleshooting workflow for a Docker container."""
    return f"""Please help troubleshoot the Docker container '{container_name}':

1. **Container Status**
   - Get current status and details of {container_name}
   - Check restart count and uptime
   - Review resource limits and usage

2. **Log Analysis**
   - Analyze the last 200 lines of container logs
   - Use AI-powered log analysis to identify root cause
   - Look for error patterns and failure modes

3. **Configuration Review**
   - Check environment variables
   - Review port mappings and network configuration
   - Verify volume mounts and permissions

4. **Dependencies**
   - Test connectivity to required services (databases, APIs, etc.)
   - Check DNS resolution
   - Verify network accessibility

Provide:
- Root cause analysis
- Step-by-step fix instructions
- Prevention recommendations
- Example docker-compose.yml if configuration changes needed
"""

@mcp.prompt(
    description="Performance analysis to identify resource bottlenecks",
    tags={"performance", "monitoring", "homelab"}
)
def performance_analysis() -> str:
    """Generate a performance analysis prompt."""
    return """Please analyze the performance of this home lab system:

1. **Resource Usage**
   - Get top 10 processes by CPU usage
   - Get top 10 processes by memory usage
   - Check disk I/O statistics
   - Review network I/O counters

2. **Docker Performance**
   - List containers with resource usage
   - Identify containers using excessive resources
   - Check for resource limits and constraints

3. **System Bottlenecks**
   - Analyze current CPU, memory, and disk usage trends
   - Identify potential bottlenecks
   - Check for swap usage

4. **Optimization Opportunities**
   - Suggest resource limit adjustments
   - Recommend containers to restart or optimize
   - Identify services that could be moved to other hosts

Provide:
- Performance summary with metrics
- Bottleneck identification
- Optimization recommendations with specific commands
- Resource allocation suggestions
"""

@mcp.prompt(
    description="Review and optimize network configuration for security and performance",
    tags={"network", "security", "homelab"}
)
def network_audit() -> str:
    """Generate a network audit prompt."""
    return """Please perform a network audit of this home lab:

1. **Network Interfaces**
   - List all network interfaces and their status
   - Check IP addresses and routing configuration
   - Review MTU settings

2. **Active Connections**
   - Show active network connections (limit to 20 most important)
   - Identify any unusual connections
   - Check for connections to unexpected external IPs

3. **Port Security**
   - Test common ports for accessibility
   - Identify all listening services
   - Check for unnecessary open ports

4. **Docker Networking**
   - List Docker networks
   - Review bridge configurations
   - Check container network isolation

5. **DNS and Connectivity**
   - Test DNS resolution
   - Check connectivity to key services
   - Verify Tailscale configuration (if available)

Provide:
- Network topology summary
- Security issues found
- Performance optimizations
- Recommended firewall rules
"""

@mcp.prompt(
    description="Plan and prepare for Docker Compose stack deployment from a GitHub repository",
    tags={"docker", "deployment", "homelab"}
)
def plan_stack_deployment(repo_url: str, stack_name: str) -> str:
    """Generate a deployment planning prompt for a Docker Compose stack."""
    return f"""Please help plan the deployment of a Docker Compose stack:

**Repository:** {repo_url}
**Stack Name:** {stack_name}

1. **Pre-Deployment Checks**
   - Verify system resources are adequate
   - Check for port conflicts with existing containers
   - Review required environment variables
   - Verify volume mount paths exist

2. **Security Review**
   - Check the docker-compose.yml for security issues
   - Verify secrets aren't hardcoded
   - Review network exposure and port mappings
   - Check for privilege escalation risks

3. **Deployment Steps**
   - Create necessary directories
   - Set up environment variables
   - Review and adjust resource limits
   - Plan backup strategy for data volumes

4. **Post-Deployment**
   - How to verify the stack is running correctly
   - Health check commands
   - Monitoring recommendations
   - Rollback procedure if needed

Please provide:
- Step-by-step deployment checklist
- Required environment variables template
- Example backup commands
- Troubleshooting guide for common issues
"""

@mcp.prompt(
    description="Investigate and resolve high resource usage on the system",
    tags={"performance", "troubleshooting", "homelab"}
)
def investigate_high_usage() -> str:
    """Generate a resource investigation prompt."""
    return """The system appears to be experiencing high resource usage. Please investigate:

1. **Immediate Assessment**
   - Get current system status (CPU, memory, disk)
   - Identify top resource consumers
   - Check for any runaway processes

2. **Historical Analysis**
   - Review system logs for recent changes
   - Check for recently started containers
   - Look for patterns in resource usage

3. **Docker Investigation**
   - List all containers with resource stats
   - Identify containers without resource limits
   - Check for containers in restart loops
   - Review container logs for errors

4. **Root Cause**
   - Analyze logs with AI to find root cause
   - Identify specific problematic services
   - Check for memory leaks or CPU spikes

5. **Remediation**
   - Immediate steps to free up resources
   - Long-term fixes to prevent recurrence
   - Resource limit recommendations
   - Monitoring improvements

Provide:
- Severity assessment
- Root cause analysis
- Immediate action items
- Long-term prevention strategy
"""

@mcp.prompt(
    description="Backup verification and disaster recovery planning",
    tags={"backup", "disaster-recovery", "homelab"}
)
def backup_planning() -> str:
    """Generate a backup and disaster recovery planning prompt."""
    return """Please help plan and verify backup and disaster recovery strategy:

1. **Current State Assessment**
   - List all Docker containers and their data volumes
   - Identify critical data that needs backup
   - Check available disk space for backups

2. **Backup Strategy**
   - Recommend backup frequency for each service
   - Suggest backup retention policies
   - Identify what can be recreated vs. what must be backed up

3. **Implementation**
   - Provide backup scripts for critical containers
   - Docker volume backup commands
   - Configuration file backup locations

4. **Disaster Recovery**
   - Recovery time objectives (RTO) for each service
   - Step-by-step restore procedures
   - Testing plan to verify backups work

5. **Automation**
   - Systemd timer examples for automated backups
   - Backup verification commands
   - Off-site backup recommendations

Provide:
- Comprehensive backup script
- Restore procedure documentation
- Testing checklist
- Monitoring alerts for backup failures
"""

@mcp.prompt(
    description="Interactive setup to discover and document applications running on this system",
    tags={"inventory", "setup", "homelab"}
)
def setup_inventory() -> str:
    """Guide user through setting up the system inventory."""
    return """Let's set up the inventory for this system to track what's running here.

This helps me provide better context-aware assistance since I'll know what applications
you have installed (Jellyfin, Pi-hole, Ollama, PostgreSQL, etc.) and can tailor my
recommendations accordingly.

**Step 1: System Identity**

First, let's identify this system for multi-system tracking:
- Use `get_inventory` to see current system identity
- If needed, use `set_system_identity` to configure:
  - hostname (auto-detected)
  - container_id (Proxmox VMID/CTID if applicable)
  - container_type ("lxc", "vm", or "bare-metal")
  - mcp_server_name (custom name for this MCP instance)

**Step 2: Auto-Scan Applications**

Run an automatic scan to detect installed applications:
- Use `scan_installed_applications` to auto-detect common apps
- This will scan for: Jellyfin, Pi-hole, Ollama, PostgreSQL, MySQL, Nginx, 
  Home Assistant, Plex, Nextcloud, Prometheus, Grafana, and more
- Detected apps are automatically saved to inventory

**Step 3: Manual Additions**

Add any applications that weren't auto-detected:
- Use `add_application_to_inventory` for each application
- Include useful metadata like:
  - name and type
  - version
  - port numbers
  - systemd service name
  - config and data paths
  - custom notes

**Step 4: Review**

- Use `get_inventory` to see the complete inventory
- This creates a local scratchpad at `inventory.json`
- I'll use this context to provide better assistance

**Benefits:**
✓ Context-aware troubleshooting (I know what apps you're running)
✓ Better security audit recommendations
✓ Targeted performance analysis
✓ Multi-system tracking (if you have multiple LXC containers)
✓ Documentation of your infrastructure

Let's start! What would you like to do first?
"""

if __name__ == "__main__":
    logger.info("Starting TailOpsMCP on http://0.0.0.0:8080")
    logger.info(f"Authentication mode: {AUTH_MODE}")
    
    if AUTH_MODE == "oidc":
        logger.info("OIDC authentication via TSIDP")
        logger.info("Users will authenticate with their Tailscale identity")
        logger.info(f"OIDC Issuer: {os.getenv('TSIDP_URL', 'https://tsidp.tailf9480.ts.net')}")
    else:
        logger.info("Token-based authentication")
    
    logger.info("Intelligent log analysis with AI sampling enabled")
    
    # Use HTTP streaming transport instead of SSE
    mcp.run(transport="http", host="0.0.0.0", port=8080)

