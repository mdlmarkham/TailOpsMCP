"""Network diagnostic tools for TailOpsMCP."""
from __future__ import annotations

import json
import logging
import os
import socket
from typing import Dict, List, Literal, Union
from datetime import datetime
from fastmcp import FastMCP
from src.auth.middleware import secure_tool
from src.server.utils import format_response, format_error

logger = logging.getLogger(__name__)

# Utility functions for network analysis
def local_listening_ports() -> List[Dict[str, str]]:
    """Return a list of (port, pid, proto) for local listening sockets.

    This is a lightweight implementation using `socket` and `/proc` when
    available. On systems without `/proc` this will return an empty list.
    """
    results: List[Dict[str, str]] = []
    # Best-effort: parse /proc/net/tcp and /proc/net/tcp6 for Linux
    proc_net = "/proc/net/tcp"
    if os.path.exists(proc_net):
        try:
            with open(proc_net, "r", encoding="utf-8") as f:
                lines = f.readlines()[1:]
            for l in lines:
                parts = l.split()
                local_address = parts[1]
                state = parts[3]
                if state != "0A":
                    continue
                ip_hex, port_hex = local_address.split(":")
                port = int(port_hex, 16)
                results.append({"port": str(port), "proto": "tcp", "info": "listening"})
        except Exception:
            pass
    return results


def port_exposure_summary() -> Dict[str, object]:
    """Return a small summary useful for alerts and inventory.

    - total_listening: int
    - top_ports: list
    """
    ports = local_listening_ports()
    by_port = {}
    for p in ports:
        by_port[p["port"]] = by_port.get(p["port"], 0) + 1
    top_ports = sorted(by_port.items(), key=lambda x: x[1], reverse=True)[:10]
    return {"total_listening": len(ports), "top_ports": top_ports}


def register_tools(mcp: FastMCP):
    """Register network diagnostic tools with MCP instance."""

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
        import ssl

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

    logger.info("Registered 9 network diagnostic tools")
