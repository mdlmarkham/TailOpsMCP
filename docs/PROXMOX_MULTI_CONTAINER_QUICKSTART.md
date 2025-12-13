# Proxmox Multi-Container Quick Start

> **One-page reference for deploying SystemManager control plane gateways to multiple LXC containers**

## Installation in 3 Steps

### 1. Download Installer (on Proxmox host)

```bash
curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/main/scripts/install/install-proxmox-multi.sh -o install-proxmox-multi.sh
chmod +x install-proxmox-multi.sh
```

### 2. Choose Your Deployment Method

#### Option A: Quick Deploy (existing containers)

```bash
./install-proxmox-multi.sh --containers 101,102,103 --auth token
```

#### Option B: Configuration File (recommended)

```bash
# Download template
wget https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/main/scripts/install/templates/proxmox-multi.conf

# Edit configuration
nano proxmox-multi.conf

# Deploy
./install-proxmox-multi.sh --config proxmox-multi.conf
```

### 3. Access Your Instances

```bash
# Find container IPs
pct list

# Check service status
pct exec 101 -- systemctl status systemmanager-mcp

# Access via IP
http://192.168.1.101:8080
```

---

## Quick Configuration Templates

### Minimal (Development)

```bash
# File: dev.conf
CONTAINERS="301,302,303"
CREATE_CONTAINERS=true
AUTH_MODE="none"
SKIP_DOCKER=true
```

Run: `./install-proxmox-multi.sh --config dev.conf`

### Production (OIDC Auth)

```bash
# File: production.conf
CONTAINERS="101,102,103"
AUTH_MODE="oidc"
TSIDP_URL="https://tsidp.tail12345.ts.net"
TSIDP_CLIENT_ID="your-client-id"
TSIDP_CLIENT_SECRET="your-client-secret"
DEPLOYMENT_STRATEGY="sequential"
RUN_VALIDATION=true
```

Run: `./install-proxmox-multi.sh --config production.conf`

### Multi-Tenant (Token per container)

```bash
# File: multi-tenant.conf
CONTAINERS="111,112,113"
CREATE_CONTAINERS=true
AUTH_MODE="token"

CONTAINER_CONFIG_111_SHARED_SECRET="team-alpha-secret"
CONTAINER_CONFIG_112_SHARED_SECRET="team-beta-secret"
CONTAINER_CONFIG_113_SHARED_SECRET="team-gamma-secret"
```

Run: `./install-proxmox-multi.sh --config multi-tenant.conf`

---

## Common Commands

```bash
# Deploy to existing containers
./install-proxmox-multi.sh --containers 101,102,103 --auth token

# Create new containers and deploy
./install-proxmox-multi.sh --create --containers 201,202,203

# Parallel deployment (faster)
./install-proxmox-multi.sh --config myconfig.conf --parallel

# Sequential deployment (safer)
./install-proxmox-multi.sh --config myconfig.conf --sequential

# Show help
./install-proxmox-multi.sh --help
```

---

## Configuration Options Reference

### Container Selection

```bash
# By ID
CONTAINERS="101,102,103"

# By name
CONTAINER_NAMES="tailops-dev,tailops-prod"

# Create new
CREATE_CONTAINERS=true
CONTAINER_TEMPLATE="debian-12-standard"
CONTAINER_MEMORY=2048
CONTAINER_CORES=2
CONTAINER_DISK_SIZE="8G"
```

### Authentication

```bash
# OIDC (recommended)
AUTH_MODE="oidc"
TSIDP_URL="https://tsidp.tail12345.ts.net"
TSIDP_CLIENT_ID="your-id"
TSIDP_CLIENT_SECRET="your-secret"

# Token (simple)
AUTH_MODE="token"
SYSTEMMANAGER_SHARED_SECRET="your-secret"

# None (dev only)
AUTH_MODE="none"
```

### Deployment Options

```bash
# Strategy
DEPLOYMENT_STRATEGY="sequential"  # or "parallel"
MAX_PARALLEL=3                     # for parallel

# Features
AUTO_FIX_FEATURES=true            # Auto-configure containers
CONTINUE_ON_FAILURE=true          # Keep going on errors
RUN_VALIDATION=true               # Post-install checks
FORCE_REINSTALL=false             # Force reinstall
```

### Per-Container Overrides

```bash
# Different ports
CONTAINER_CONFIG_101_PORT=8080
CONTAINER_CONFIG_102_PORT=8081

# Different auth
CONTAINER_CONFIG_103_AUTH_MODE="none"

# Different secrets
CONTAINER_CONFIG_101_SHARED_SECRET="secret-1"
CONTAINER_CONFIG_102_SHARED_SECRET="secret-2"
```

---

## Troubleshooting

### Container creation failed

```bash
# Download template manually
pveam update
pveam download local debian-12-standard
```

### Features not enabled

```bash
# Auto-fix in config
AUTO_FIX_FEATURES=true

# Or manual fix
pct stop 101
nano /etc/pve/lxc/101.conf
# Add: features: nesting=1,keyctl=1
pct start 101
```

### Installation failed on one container

```bash
# Check logs
pct exec 101 -- journalctl -u systemmanager-mcp -n 100

# Retry single container
./install-proxmox-multi.sh --containers 101 --config myconfig.conf
```

### Service not starting

```bash
# Check status and logs
pct exec 101 -- systemctl status systemmanager-mcp
pct exec 101 -- journalctl -u systemmanager-mcp -xe

# Test manual start
pct exec 101 -- /opt/systemmanager/venv/bin/python -m src.mcp_server
```

---

## Post-Installation

### Check Status

```bash
# All containers
pct list

# Specific container
pct exec 101 -- systemctl status systemmanager-mcp
pct exec 101 -- journalctl -u systemmanager-mcp -f
```

### Manage Services

```bash
# Start/stop/restart
pct exec 101 -- systemctl start systemmanager-mcp
pct exec 101 -- systemctl stop systemmanager-mcp
pct exec 101 -- systemctl restart systemmanager-mcp

# View logs
pct exec 101 -- journalctl -u systemmanager-mcp -f
```

### Access Instances

```bash
# Find IPs
pct list

# Access via browser or API
http://192.168.1.101:8080
http://192.168.1.102:8080
```

### Configure Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "tailops-prod": {
      "url": "http://192.168.1.101:8080",
      "headers": {
        "Authorization": "Bearer your-token-here"
      }
    },
    "tailops-staging": {
      "url": "http://192.168.1.102:8080",
      "headers": {
        "Authorization": "Bearer your-token-here"
      }
    }
  }
}
```

---

## Complete Documentation

For detailed documentation, see:
- [PROXMOX_MULTI_CONTAINER_INSTALL.md](./PROXMOX_MULTI_CONTAINER_INSTALL.md) - Complete guide
- [TSIDP_OIDC_SETUP.md](./TSIDP_OIDC_SETUP.md) - OIDC authentication setup
- [SECURITY.md](./SECURITY.md) - Security best practices

---

**Quick Reference Version 1.0 | Last Updated: 2025-11-18**
