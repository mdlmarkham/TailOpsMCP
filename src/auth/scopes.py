"""
Scope definitions and authorization for SystemManager MCP tools.

Implements least-privilege access control for tailnet deployments where
Tailscale ACLs provide network-level security but application-level
authorization is still required.
"""

from enum import Enum
from typing import List, Set
from dataclasses import dataclass


class Scope(str, Enum):
    """Authorization scopes for SystemManager tools.
    
    Security Model:
    - Tailscale ACLs control WHO can reach the server (network-level)
    - Application scopes control WHAT they can do (application-level)
    - Both layers are required for defense-in-depth
    """
    
    # Read-only scopes (low risk)
    SYSTEM_READ = "system:read"           # View system status, metrics
    NETWORK_READ = "network:read"         # View network status, connections
    CONTAINER_READ = "container:read"     # List containers, view logs
    FILE_READ = "file:read"              # Read files (within allowed paths)
    
    # Diagnostic scopes (moderate risk)
    NETWORK_DIAG = "network:diag"        # Ping, DNS, port tests
    
    # Write scopes (high risk)
    CONTAINER_WRITE = "container:write"   # Start, stop, restart containers
    FILE_WRITE = "file:write"            # Write files (not implemented)
    
    # Administrative scopes (critical risk - require additional approval)
    CONTAINER_ADMIN = "container:admin"   # Update containers, pull images
    SYSTEM_ADMIN = "system:admin"        # Install packages, system updates
    DOCKER_ADMIN = "docker:admin"        # Full Docker access
    
    # Meta scopes
    ADMIN = "admin"                      # All permissions
    READ_ONLY = "readonly"               # All read permissions


@dataclass
class ToolScopeRequirement:
    """Defines scope requirements for a tool."""
    tool_name: str
    required_scopes: List[str]
    risk_level: str  # "low", "moderate", "high", "critical"
    requires_approval: bool = False
    description: str = ""


# Tool scope mappings
TOOL_SCOPES = {
    # System Monitoring (READ-ONLY, LOW RISK)
    "get_system_status": ToolScopeRequirement(
        tool_name="get_system_status",
        required_scopes=[Scope.SYSTEM_READ],
        risk_level="low",
        description="View CPU, memory, disk, uptime"
    ),
    "get_top_processes": ToolScopeRequirement(
        tool_name="get_top_processes",
        required_scopes=[Scope.SYSTEM_READ],
        risk_level="low",
        description="View running processes"
    ),
    "get_network_status": ToolScopeRequirement(
        tool_name="get_network_status",
        required_scopes=[Scope.NETWORK_READ],
        risk_level="low",
        description="View network interfaces"
    ),
    "get_network_io_counters": ToolScopeRequirement(
        tool_name="get_network_io_counters",
        required_scopes=[Scope.NETWORK_READ],
        risk_level="low",
        description="View network I/O stats"
    ),
    "health_check": ToolScopeRequirement(
        tool_name="health_check",
        required_scopes=[],  # No auth required
        risk_level="low",
        description="Server health check"
    ),
    
    # Container Management (MODERATE-HIGH RISK)
    "get_container_list": ToolScopeRequirement(
        tool_name="get_container_list",
        required_scopes=[Scope.CONTAINER_READ],
        risk_level="low",
        description="List Docker containers"
    ),
    "manage_container": ToolScopeRequirement(
        tool_name="manage_container",
        required_scopes=[Scope.CONTAINER_WRITE],
        risk_level="high",
        description="Start, stop, restart containers"
    ),
    "list_docker_images": ToolScopeRequirement(
        tool_name="list_docker_images",
        required_scopes=[Scope.CONTAINER_READ],
        risk_level="low",
        description="List Docker images"
    ),
    "get_docker_networks": ToolScopeRequirement(
        tool_name="get_docker_networks",
        required_scopes=[Scope.CONTAINER_READ],
        risk_level="low",
        description="List Docker networks"
    ),
    
    # Docker Administration (CRITICAL RISK - requires approval)
    "update_docker_container": ToolScopeRequirement(
        tool_name="update_docker_container",
        required_scopes=[Scope.CONTAINER_ADMIN],
        risk_level="critical",
        requires_approval=True,
        description="Update container with latest image"
    ),
    "pull_docker_image": ToolScopeRequirement(
        tool_name="pull_docker_image",
        required_scopes=[Scope.DOCKER_ADMIN],
        risk_level="critical",
        requires_approval=True,
        description="Pull Docker image from registry"
    ),
    
    # File Operations (HIGH RISK - unrestricted read is dangerous)
    "file_operations": ToolScopeRequirement(
        tool_name="file_operations",
        required_scopes=[Scope.FILE_READ],
        risk_level="high",
        requires_approval=False,  # But should enforce path restrictions
        description="File system operations (read-only)"
    ),
    
    # Network Diagnostics (MODERATE RISK)
    "ping_host": ToolScopeRequirement(
        tool_name="ping_host",
        required_scopes=[Scope.NETWORK_DIAG],
        risk_level="moderate",
        description="Ping remote hosts"
    ),
    "test_port_connectivity": ToolScopeRequirement(
        tool_name="test_port_connectivity",
        required_scopes=[Scope.NETWORK_DIAG],
        risk_level="moderate",
        description="Test TCP port connectivity"
    ),
    "dns_lookup": ToolScopeRequirement(
        tool_name="dns_lookup",
        required_scopes=[Scope.NETWORK_DIAG],
        risk_level="moderate",
        description="DNS resolution"
    ),
    "check_ssl_certificate": ToolScopeRequirement(
        tool_name="check_ssl_certificate",
        required_scopes=[Scope.NETWORK_DIAG],
        risk_level="moderate",
        description="Check SSL certificate"
    ),
    "http_request_test": ToolScopeRequirement(
        tool_name="http_request_test",
        required_scopes=[Scope.NETWORK_DIAG],
        risk_level="high",  # Can be used for SSRF
        requires_approval=True,
        description="HTTP request testing (SSRF risk)"
    ),
    "get_active_connections": ToolScopeRequirement(
        tool_name="get_active_connections",
        required_scopes=[Scope.NETWORK_READ],
        risk_level="moderate",
        description="View active network connections"
    ),
    "traceroute": ToolScopeRequirement(
        tool_name="traceroute",
        required_scopes=[Scope.NETWORK_DIAG],
        risk_level="moderate",
        description="Network route tracing"
    ),
    
    # System Administration (CRITICAL RISK - requires approval)
    "check_system_updates": ToolScopeRequirement(
        tool_name="check_system_updates",
        required_scopes=[Scope.SYSTEM_READ],
        risk_level="low",
        description="Check for available updates"
    ),
    "update_system_packages": ToolScopeRequirement(
        tool_name="update_system_packages",
        required_scopes=[Scope.SYSTEM_ADMIN],
        risk_level="critical",
        requires_approval=True,
        description="Update all system packages (destructive)"
    ),
    "install_package": ToolScopeRequirement(
        tool_name="install_package",
        required_scopes=[Scope.SYSTEM_ADMIN],
        risk_level="critical",
        requires_approval=True,
        description="Install system packages (code execution risk)"
    ),
}


def expand_scopes(scopes: List[str]) -> Set[str]:
    """Expand meta-scopes into specific scopes.
    
    Args:
        scopes: List of scope strings (may include meta-scopes)
        
    Returns:
        Set of all granted scopes including expanded meta-scopes
    """
    expanded = set(scopes)
    
    if Scope.ADMIN in scopes:
        # Admin grants everything
        expanded.update([s.value for s in Scope])
    
    if Scope.READ_ONLY in scopes:
        # Read-only grants all read scopes
        expanded.update([
            Scope.SYSTEM_READ,
            Scope.NETWORK_READ,
            Scope.CONTAINER_READ,
            Scope.FILE_READ,
        ])
    
    return expanded


def check_authorization(tool_name: str, user_scopes: List[str]) -> tuple[bool, str]:
    """Check if user has required scopes for a tool.
    
    Args:
        tool_name: Name of the tool being invoked
        user_scopes: List of scopes granted to the user
        
    Returns:
        (authorized: bool, reason: str)
    """
    if tool_name not in TOOL_SCOPES:
        # Unknown tool - deny by default
        return False, f"Unknown tool: {tool_name}"
    
    requirement = TOOL_SCOPES[tool_name]
    
    # Expand meta-scopes
    granted = expand_scopes(user_scopes)
    
    # Check if all required scopes are present
    for required_scope in requirement.required_scopes:
        if required_scope not in granted:
            return False, f"Missing required scope: {required_scope}"
    
    return True, "Authorized"


def requires_approval(tool_name: str) -> bool:
    """Check if tool requires interactive approval.
    
    Args:
        tool_name: Name of the tool
        
    Returns:
        True if tool requires approval
    """
    if tool_name not in TOOL_SCOPES:
        return True  # Unknown tools require approval
    
    return TOOL_SCOPES[tool_name].requires_approval


def get_tool_risk_level(tool_name: str) -> str:
    """Get risk level for a tool.
    
    Args:
        tool_name: Name of the tool
        
    Returns:
        Risk level: "low", "moderate", "high", "critical"
    """
    if tool_name not in TOOL_SCOPES:
        return "critical"  # Unknown tools are max risk
    
    return TOOL_SCOPES[tool_name].risk_level
