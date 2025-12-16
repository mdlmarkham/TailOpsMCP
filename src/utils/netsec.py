"""
Network security controls for SystemManager.

Implements URL/host allowlists to prevent:
- SSRF attacks
- Port scanning internal networks
- DNS reconnaissance
- Unauthorized HTTP requests
"""

import ipaddress
import os
from typing import List, Optional
from urllib.parse import urlparse


# Private/internal IP ranges that should be blocked by default
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),  # Localhost
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("::1/128"),  # IPv6 localhost
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
]

# Metadata service IPs (AWS, GCP, Azure)
METADATA_IPS = [
    "169.254.169.254",  # AWS/Azure
    "169.254.169.253",  # AWS DNS
    "metadata.google.internal",  # GCP
]

# Default allowed hosts for HTTP requests
# "*" = allow all public hosts (private IPs still blocked)
# Empty list = deny all
DEFAULT_ALLOWED_HOSTS: List[str] = ["*"]

# Default allowed ports for connectivity testing
DEFAULT_ALLOWED_PORTS = [22, 80, 443, 8080]


def is_ip_private(ip_str: str) -> bool:
    """Check if IP address is private/internal.

    Args:
        ip_str: IP address string

    Returns:
        True if private/internal
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in network for network in PRIVATE_IP_RANGES)
    except ValueError:
        return False


def is_host_allowed(
    host: str, allowed_hosts: Optional[List[str]] = None
) -> tuple[bool, str]:
    """Check if host is allowed for network operations.

    Args:
        host: Hostname or IP address
        allowed_hosts: List of allowed hosts (None = use defaults, [] = deny all)

    Returns:
        (allowed: bool, reason: str)
    """
    if allowed_hosts is None:
        # Get from environment or use default
        env_hosts = os.getenv("SYSTEMMANAGER_ALLOWED_HOSTS")
        if env_hosts:
            allowed_hosts = [h.strip() for h in env_hosts.split(",")]
        else:
            allowed_hosts = DEFAULT_ALLOWED_HOSTS

    # Block localhost/localhosts variations
    if host.lower() in ["localhost", "localhost.localdomain", "ip6-localhost"]:
        return False, "localhost not allowed (internal access)"

    # Block metadata services
    if host in METADATA_IPS:
        return False, "Access to metadata services denied"

    # Check if it's an IP address
    try:
        ip = ipaddress.ip_address(host)
        if is_ip_private(str(ip)):
            return False, f"Private IP address not allowed: {host}"
    except ValueError:
        # It's a hostname, not an IP
        pass

    # Check allowlist
    if not allowed_hosts:
        return False, "No hosts allowed (empty allowlist)"

    # Check exact match or wildcard
    for allowed in allowed_hosts:
        if allowed == "*":
            # Wildcard - allow any public host
            return True, "Wildcard allowed"
        if host == allowed:
            return True, f"Host in allowlist: {allowed}"
        if allowed.startswith("*.") and host.endswith(allowed[1:]):
            return True, f"Host matches wildcard: {allowed}"

    return False, f"Host not in allowlist: {allowed_hosts}"


def is_url_allowed(
    url: str, allowed_hosts: Optional[List[str]] = None
) -> tuple[bool, str]:
    """Check if URL is allowed for HTTP requests.

    Args:
        url: URL to check
        allowed_hosts: List of allowed hosts

    Returns:
        (allowed: bool, reason: str)
    """
    try:
        parsed = urlparse(url)

        # Require http/https scheme
        if parsed.scheme not in ["http", "https"]:
            return False, f"Scheme not allowed: {parsed.scheme}"

        # Check host
        if not parsed.hostname:
            return False, "No hostname in URL"

        return is_host_allowed(parsed.hostname, allowed_hosts)

    except Exception as e:
        return False, f"URL validation error: {e}"


def is_port_allowed(
    port: int, allowed_ports: Optional[List[int]] = None
) -> tuple[bool, str]:
    """Check if port is allowed for connectivity testing.

    Args:
        port: Port number
        allowed_ports: List of allowed ports

    Returns:
        (allowed: bool, reason: str)
    """
    if allowed_ports is None:
        # Get from environment or use default
        env_ports = os.getenv("SYSTEMMANAGER_ALLOWED_PORTS")
        if env_ports:
            try:
                allowed_ports = [int(p.strip()) for p in env_ports.split(",")]
            except ValueError:
                allowed_ports = DEFAULT_ALLOWED_PORTS
        else:
            allowed_ports = DEFAULT_ALLOWED_PORTS

    if port in allowed_ports:
        return True, f"Port in allowlist: {port}"

    return False, f"Port not in allowlist: {allowed_ports}"
