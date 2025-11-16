# SystemManager MCP Prompts

SystemManager includes pre-configured MCP prompts for common home lab management tasks. These prompts provide ready-to-use workflows that combine multiple tools into comprehensive operations.

## Available Prompts

### 🔒 Security Audit
**Name:** `security_audit`  
**Tags:** security, audit, homelab

Performs a comprehensive security audit including:
- System log analysis for authentication failures and suspicious activity
- Docker container security review
- Network security assessment
- System health and resource usage

**Usage in Claude Desktop:**
```
Use the security_audit prompt to check my home lab for security issues
```

---

### 💚 Health Check
**Name:** `health_check`  
**Tags:** monitoring, health, homelab

Quick health check of all critical services:
- System resource usage (CPU, memory, disk)
- Docker container status
- Network connectivity tests
- Recent error detection

**Usage:**
```
Run the health_check prompt to see if everything is running smoothly
```

---

### 🔧 Troubleshoot Container
**Name:** `troubleshoot_container`  
**Arguments:** `container_name` (required)  
**Tags:** docker, troubleshooting, homelab

Comprehensive Docker container troubleshooting workflow:
- Container status and resource usage
- AI-powered log analysis
- Configuration review
- Dependency and connectivity tests

**Usage:**
```
Use troubleshoot_container for my nginx container
```

---

### ⚡ Performance Analysis
**Name:** `performance_analysis`  
**Tags:** performance, monitoring, homelab

System-wide performance analysis:
- Resource usage by process and container
- Bottleneck identification
- Optimization recommendations
- Resource allocation suggestions

**Usage:**
```
Run performance_analysis to see what's slowing down my system
```

---

### 🌐 Network Audit
**Name:** `network_audit`  
**Tags:** network, security, homelab

Complete network security and configuration review:
- Network interface status
- Active connections audit
- Port security check
- Docker network configuration
- DNS and connectivity tests

**Usage:**
```
Perform a network_audit on my home lab
```

---

### 🚀 Plan Stack Deployment
**Name:** `plan_stack_deployment`  
**Arguments:** `repo_url` (required), `stack_name` (required)  
**Tags:** docker, deployment, homelab

Plan Docker Compose stack deployment from GitHub:
- Pre-deployment system checks
- Security review of compose file
- Resource planning
- Post-deployment verification steps

**Usage:**
```
Use plan_stack_deployment for https://github.com/user/monitoring-stack called "monitoring"
```

---

### 📈 Investigate High Usage
**Name:** `investigate_high_usage`  
**Tags:** performance, troubleshooting, homelab

Investigate and resolve high resource usage:
- Immediate resource assessment
- Historical analysis
- Docker container investigation  
- Root cause identification
- Remediation steps

**Usage:**
```
My system is slow, run investigate_high_usage
```

---

### 💾 Backup Planning
**Name:** `backup_planning`  
**Tags:** backup, disaster-recovery, homelab

Backup and disaster recovery planning:
- Current state assessment
- Backup strategy recommendations
- Implementation scripts
- Disaster recovery procedures
- Automation setup

**Usage:**
```
Help me create a backup plan using the backup_planning prompt
```

---

### 📦 Setup Inventory
**Name:** `setup_inventory`  
**Tags:** inventory, setup, homelab

Interactive workflow to set up the system inventory for application tracking:
- System identity configuration (hostname, container ID, MCP name)
- Auto-scan for installed applications (Jellyfin, Pi-hole, Ollama, PostgreSQL, etc.)
- Manual application additions
- Complete inventory review

This prompt helps SystemManager understand what applications are running on your LXC container
(not just Docker), enabling context-aware assistance for troubleshooting, security, and monitoring.

**Usage:**
```
Let's set up the inventory for this system
```

**Why Use This:**
- **Context-Aware Help**: AI knows what apps you're running
- **Better Troubleshooting**: Targeted recommendations based on your stack
- **Multi-System Support**: Unique identifiers when managing multiple LXC containers
- **Documentation**: Auto-generated infrastructure documentation

**See Also:** [Inventory Documentation](./inventory.md)

---

## How Prompts Work

MCP Prompts are reusable, parameterized templates that guide AI assistants through complex multi-step workflows. When you invoke a prompt in an MCP-compatible client (like Claude Desktop or VS Code with Copilot), the prompt:

1. Returns a structured message to the AI
2. The AI uses available MCP tools to complete the workflow
3. Results are analyzed and presented with actionable recommendations

## Using Prompts in Different Clients

### Claude Desktop

1. Make sure SystemManager is configured in your MCP settings
2. Use natural language to invoke prompts:
   - "Use the security_audit prompt"
   - "Run health_check"
   - "Troubleshoot my nginx container with troubleshoot_container"

### VS Code with GitHub Copilot

1. Install SystemManager MCP server
2. Prompts appear in the Copilot chat interface
3. Select from available prompts or type the prompt name

### API/SDK

```python
from mcp import ClientSession

async with ClientSession(...) as session:
    # List available prompts
    prompts = await session.list_prompts()
    
    # Get a specific prompt
    result = await session.get_prompt(
        "troubleshoot_container",
        arguments={"container_name": "nginx"}
    )
    
    # The result contains the formatted message for the AI
    print(result.messages[0].content.text)
```

## Creating Custom Prompts

You can add your own prompts to SystemManager by editing `src/mcp_server.py`:

```python
@mcp.prompt(
    description="Your custom workflow description",
    tags={"your", "tags"}
)
def my_custom_prompt(param1: str, param2: int = 10) -> str:
    """Generate your custom prompt."""
    return f"""
    Custom workflow instructions for the AI assistant:
    
    1. First step using {param1}
    2. Second step with {param2}
    3. Final recommendations
    """
```

### Best Practices for Custom Prompts

1. **Clear Structure**: Use numbered steps and clear section headers
2. **Specific Instructions**: Tell the AI exactly which tools to use
3. **Expected Output**: Specify what format you want results in
4. **Context**: Include enough context for the AI to understand the task
5. **Actionable**: End with concrete next steps or recommendations

---

## Examples

### Complete Security Audit Workflow

```
User: Use security_audit prompt

AI: I'll perform a comprehensive security audit of your home lab.

[Uses tools: analyze_container_logs, get_system_status, get_active_connections, etc.]

Summary:
✅ System Health: Good
⚠️  Security Issues Found: 3

Critical Issues:
1. Container 'web' running as root without security profile
   Fix: Add security_opt: ["no-new-privileges:true"] to compose file
   
2. Port 22 (SSH) exposed to 0.0.0.0
   Fix: sudo ufw allow from 10.0.0.0/8 to any port 22
   
3. Failed login attempts from 192.168.1.unknown (15 times)
   Fix: Consider fail2ban installation

All issues have been documented with specific remediation steps.
```

### Container Troubleshooting

```
User: My postgres container keeps restarting, use troubleshoot_container

AI: I'll troubleshoot the postgres container for you.

[Analyzes logs, checks configuration, tests dependencies]

Root Cause: Out of memory - container hitting 256MB limit

Fix Steps:
1. Increase memory limit in docker-compose.yml:
   mem_limit: 512m
   
2. Restart container:
   docker-compose up -d postgres
   
3. Monitor memory usage:
   docker stats postgres

The container was experiencing OOM kills due to insufficient memory allocation.
PostgreSQL requires at least 512MB for stable operation with your current
database size.
```

---

## Reference

- **MCP Specification**: https://modelcontextprotocol.io/specification/2025-06-18/server/prompts
- **FastMCP Prompts Documentation**: https://gofastmcp.com/servers/prompts
- **SystemManager GitHub**: https://github.com/mdlmarkham/SystemManager
