"""MCP prompts for TailOpsMCP - Pre-configured workflows for common home lab tasks."""
import logging
from fastmcp import FastMCP

logger = logging.getLogger(__name__)

def register_prompts(mcp: FastMCP):
    """Register MCP prompts with FastMCP instance."""

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

    logger.info("Registered 9 MCP prompts")
