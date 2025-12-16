# TailOpsMCP Quick Start Guide (Control Plane Gateway)

## Overview

TailOpsMCP is a secure control plane gateway that centralizes management of distributed infrastructure through AI assistants like Claude, ChatGPT, or any MCP-compatible client. The control plane gateway architecture provides centralized management of multiple target systems through a single interface.

## Prerequisites

- **Tailscale Account**: Required for secure network connectivity
- **Proxmox Host** (recommended): For isolated gateway deployment
- **MCP-Compatible AI Assistant**: Claude Desktop, Cursor, or similar
- **SSH Access**: To target systems you want to manage
- **Target Systems**: One or more systems to manage through the gateway

## Step 1: Deploy Control Plane Gateway

### Option A: Automated Proxmox Deployment (Recommended)

```bash
# On your Proxmox host
bash -c "$(wget -qLO - https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/ct/build.func)"
```

This creates an isolated LXC container with:
- Debian 12 LXC (2GB RAM, 2 CPU cores, 4GB disk)
- Python 3.12 and all dependencies
- Tailscale OAuth authentication
- Systemd service configuration

### Option B: Manual Installation

```bash
# Download and run the installer
curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/install.sh | sudo bash

# Or clone and run manually
git clone https://github.com/mdlmarkham/TailOpsMCP.git
cd TailOpsMCP
sudo bash install.sh
```

## Step 2: Configure Target Registry

Create your `targets.yaml` configuration file:

```yaml
version: "1.0"
gateway:
  id: "gateway-001"
  name: "Quick Start Gateway"
  description: "Quick start configuration for getting started"

targets:
  # Local gateway management
  local:
    id: "local"
    type: "local"
    executor: "local"
    capabilities:
      - "system:read"
      - "container:read"
      - "network:read"

  # SSH target example
  web-server-01:
    id: "web-server-01"
    type: "remote"
    executor: "ssh"
    connection:
      host: "192.168.1.100"
      username: "admin"
      key_path: "${SSH_KEY_WEB_SERVER_01}"
    capabilities:
      - "system:read"
      - "container:read"

  # Docker socket target
  docker-host-01:
    id: "docker-host-01"
    type: "remote"
    executor: "docker"
    connection:
      socket_path: "/var/run/docker.sock"
    capabilities:
      - "container:read"
      - "container:control"
```

## Step 3: Configure Authentication

### Tailscale OAuth (Recommended)

```bash
# In /opt/systemmanager/.env
SYSTEMMANAGER_AUTH_MODE=oauth
SYSTEMMANAGER_REQUIRE_AUTH=true
TSIDP_URL=https://tsidp.yourtailnet.ts.net
```

### Token Authentication (Fallback)

```bash
# In /opt/systemmanager/.env
SYSTEMMANAGER_AUTH_MODE=token
SYSTEMMANAGER_SHARED_SECRET=your-secure-secret
```

## Step 4: Connect AI Assistant

Configure your MCP-compatible AI assistant:

```json
{
  "mcpServers": {
    "tailopsmcp": {
      "command": "python",
      "args": ["-m", "src.mcp_server"],
      "env": {
        "SYSTEMMANAGER_TARGETS_CONFIG": "/opt/systemmanager/targets.yaml"
      }
    }
  }
}
```

## Step 5: Test Your Setup

```bash
# Check gateway service status
sudo systemctl status systemmanager-mcp

# View gateway logs
sudo journalctl -u systemmanager-mcp -f

# Test connectivity
curl http://localhost:8080/.well-known/oauth-protected-resource/mcp
```

## Common Operations

### System Health Check

```bash
# Check all targets
system_health_check()

# Check specific target
system_health_check(target="web-server-01")
```

### Container Management

```bash
# List containers
list_containers(target="docker-host-01")

# Restart container
restart_container(target="docker-host-01", container="nginx")
```

### Log Analysis

```bash
# Analyze container logs
analyze_container_logs(name_or_id="nginx", lines=200)
```

## Troubleshooting

### Gateway Not Starting

```bash
# Check service status
sudo systemctl status systemmanager-mcp

# View detailed logs
sudo journalctl -u systemmanager-mcp -n 50

# Check configuration
python -c "from src.services.target_registry import TargetRegistry; tr = TargetRegistry(); print('Valid targets:', list(tr._targets.keys()))"
```

### Target Connectivity Issues

```bash
# Test SSH connectivity
ssh admin@192.168.1.100

# Test Docker socket
sudo docker ps

# Check Tailscale connectivity
tailscale status
```

## Next Steps

- Read the [Security Guide](./SECURITY.md) for production deployment
- Explore [Use Cases](./gateway-use-cases.md) for advanced scenarios
- Review [Best Practices](./best-practices.md) for optimal configuration
- Check [Troubleshooting Guide](./troubleshooting.md) for common issues

## Support

- **Documentation**: [https://github.com/mdlmarkham/SystemManager](https://github.com/mdlmarkham/SystemManager)
- **Issues**: [GitHub Issues](https://github.com/mdlmarkham/SystemManager/issues)
- **Discussions**: [GitHub Discussions](https://github.com/mdlmarkham/SystemManager/discussions)

---

*Last updated: $(date)*
