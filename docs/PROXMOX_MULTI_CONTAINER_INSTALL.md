# Proxmox Multi-Container Gateway Deployment Guide

Deploy SystemManager control plane gateways from a Proxmox host to multiple LXC containers simultaneously.

## Overview

The Proxmox multi-container installer allows you to deploy SystemManager control plane gateways to multiple LXC containers from your Proxmox host in a single operation. This is ideal for:

- **Control plane gateway deployment**: Deploy isolated gateways for managing targets
- **Segment-based deployment**: Deploy gateways per network segment for blast radius limitation
- **High availability**: Deploy multiple gateways for redundancy
- **Multi-tenant setups**: Separate gateways for different teams or environments
- **Testing configurations**: Deploy gateways with different target registries and capabilities

## Features

- ✅ Deploy to existing containers or create new ones
- ✅ Parallel or sequential deployment strategies
- ✅ Auto-configure container features (nesting, TUN device)
- ✅ Per-container configuration overrides
- ✅ Multiple authentication modes (OIDC, token, none)
- ✅ Automatic validation and health checks
- ✅ Comprehensive error handling and rollback
- ✅ Deployment status tracking and reporting

## Prerequisites

### On Proxmox Host

1. **Proxmox VE 7.0 or later**
2. **Root access** to the Proxmox host
3. **Network connectivity** from containers to the internet
4. **Available resources**:
   - CPU: 2 cores per container (minimum 1)
   - Memory: 2GB per container (minimum 1GB)
   - Disk: 8GB per container (minimum 5GB)
   - Storage: Space for container images

### Required LXC Features

Each container needs:
- **Nesting enabled** (`features: nesting=1,keyctl=1`) - Required for Docker
- **TUN device** (`lxc.cgroup2.devices.allow: c 10:200 rwm`) - Required for Tailscale
- **AppArmor** set to unconfined (recommended)

> **Note**: The installer can automatically configure these features if `AUTO_FIX_FEATURES=true`

## Quick Start

### Option 1: Using Configuration File (Recommended)

1. **Create configuration file** from template:
   ```bash
   cd /root
   wget https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/main/scripts/install/templates/proxmox-multi.conf
   ```

2. **Edit configuration**:
   ```bash
   nano proxmox-multi.conf
   ```

   Minimal configuration:
   ```bash
   # Target existing containers
   CONTAINERS="101,102,103"

   # Or create new containers
   # CONTAINERS="201,202,203"
   # CREATE_CONTAINERS=true

   # Authentication
   AUTH_MODE="token"
   SYSTEMMANAGER_SHARED_SECRET="your-secret-here"
   ```

3. **Run installation**:
   ```bash
   curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/main/scripts/install/install-proxmox-multi.sh -o install-proxmox-multi.sh
   chmod +x install-proxmox-multi.sh
   ./install-proxmox-multi.sh --config proxmox-multi.conf
   ```

### Option 2: Command Line Quick Deploy

Deploy to existing containers:
```bash
./install-proxmox-multi.sh --containers 101,102,103 --auth token
```

Create and deploy to new containers:
```bash
./install-proxmox-multi.sh --create --containers 201,202,203 --auth none
```

## Detailed Configuration

### Container Selection

**Option 1: Existing containers by ID**
```bash
CONTAINERS="101,102,103"
```

**Option 2: Existing containers by name**
```bash
CONTAINER_NAMES="tailops-dev,tailops-staging,tailops-prod"
```

**Option 3: Create new containers**
```bash
CONTAINERS="201,202,203"
CREATE_CONTAINERS=true
CONTAINER_TEMPLATE="debian-12-standard"
CONTAINER_MEMORY=2048
CONTAINER_CORES=2
CONTAINER_DISK_SIZE="8G"
```

### Authentication Modes

#### OIDC (Recommended for Production)

```bash
AUTH_MODE="oidc"
TSIDP_URL="https://tsidp.tail12345.ts.net"
TSIDP_CLIENT_ID="your-client-id"
TSIDP_CLIENT_SECRET="your-client-secret"
```

See [TSIDP_OIDC_SETUP.md](./TSIDP_OIDC_SETUP.md) for setting up Tailscale OAuth.

#### Token-based (Shared Secret)

```bash
AUTH_MODE="token"
SYSTEMMANAGER_SHARED_SECRET="your-secret-here"
# Or leave empty to auto-generate:
# SYSTEMMANAGER_SHARED_SECRET=""
```

#### No Authentication (Development Only)

```bash
AUTH_MODE="none"
```

⚠️ **WARNING**: Only use `none` for development/testing environments.

### Deployment Strategies

#### Sequential (Default - Safer)

Deploy containers one at a time:
```bash
DEPLOYMENT_STRATEGY="sequential"
```

Advantages:
- Easier to debug issues
- Lower resource usage during deployment
- Clear progress tracking

#### Parallel (Faster)

Deploy multiple containers simultaneously:
```bash
DEPLOYMENT_STRATEGY="parallel"
MAX_PARALLEL=3  # Deploy 3 containers at a time
```

Advantages:
- Faster deployment for many containers
- Efficient use of time

### Per-Container Overrides

Customize settings for specific containers:

```bash
# Different ports
CONTAINER_CONFIG_101_PORT=8080
CONTAINER_CONFIG_102_PORT=8081
CONTAINER_CONFIG_103_PORT=8082

# Different auth modes
CONTAINER_CONFIG_103_AUTH_MODE="none"  # Dev environment

# Container-specific secrets
CONTAINER_CONFIG_101_SHARED_SECRET="secret-for-prod"
CONTAINER_CONFIG_102_SHARED_SECRET="secret-for-staging"
```

## Usage Examples

### Example 1: Development Environment

Create 3 containers for development with no authentication:

```bash
# Config file: dev-environment.conf
CONTAINERS="301,302,303"
CREATE_CONTAINERS=true
CONTAINER_TEMPLATE="debian-12-standard"
CONTAINER_MEMORY=1024
CONTAINER_CORES=1

AUTH_MODE="none"
SKIP_DOCKER=true
DEPLOYMENT_STRATEGY="parallel"
```

```bash
./install-proxmox-multi.sh --config dev-environment.conf
```

### Example 2: Production Deployment

Deploy to existing containers with OIDC authentication:

```bash
# Config file: production.conf
CONTAINERS="101,102,103"
AUTH_MODE="oidc"
TSIDP_URL="https://tsidp.tail12345.ts.net"
TSIDP_CLIENT_ID="k1234567890"
TSIDP_CLIENT_SECRET="tskey-client-abc123..."

DEPLOYMENT_STRATEGY="sequential"
RUN_VALIDATION=true
CONTINUE_ON_FAILURE=false
```

```bash
./install-proxmox-multi.sh --config production.conf
```

### Example 3: Multi-Tenant Setup

Create containers for different teams with different auth tokens:

```bash
# Config file: multi-tenant.conf
CONTAINERS="111,112,113"
CREATE_CONTAINERS=true
AUTH_MODE="token"

CONTAINER_CONFIG_111_SHARED_SECRET="team-alpha-secret"
CONTAINER_CONFIG_112_SHARED_SECRET="team-beta-secret"
CONTAINER_CONFIG_113_SHARED_SECRET="team-gamma-secret"

HOSTNAME_PREFIX="tailops-team"
```

### Example 4: Staged Rollout

Deploy to containers in stages:

```bash
# Stage 1: Deploy to dev
./install-proxmox-multi.sh --containers 301 --auth none

# Stage 2: Deploy to staging
./install-proxmox-multi.sh --containers 302 --auth token

# Stage 3: Deploy to production
./install-proxmox-multi.sh --containers 101,102,103 --config production.conf
```

## Container Templates

### Download Available Templates

List available templates:
```bash
pveam update
pveam available
```

Common templates:
- `debian-12-standard` (recommended)
- `ubuntu-22.04-standard`
- `ubuntu-24.04-standard`
- `rocky-9-default`
- `almalinux-9-default`

Download a template:
```bash
pveam download local debian-12-standard
```

## Deployment Workflow

The installer follows this workflow for each container:

```
1. Validation
   ├─ Check Proxmox host
   ├─ Validate configuration
   └─ Resolve container IDs

2. Container Preparation (for each container)
   ├─ Check if container exists
   ├─ Create container if needed
   ├─ Start container
   ├─ Check/fix container features
   └─ Validate resources

3. Installation (for each container)
   ├─ Copy installation files
   ├─ Generate container-specific config
   ├─ Run installation script
   └─ Configure authentication

4. Validation (for each container)
   ├─ Check service is running
   ├─ Verify port is listening
   └─ Run integration tests

5. Summary
   └─ Display deployment report
```

## Monitoring Deployment

### Real-time Progress

The installer provides real-time progress:
- Container preparation status
- Installation progress per container
- Success/failure indicators
- Final summary report

### Check Container Status

During deployment:
```bash
pct list
pct status 101
```

After deployment:
```bash
pct exec 101 -- systemctl status systemmanager-mcp
pct exec 101 -- journalctl -u systemmanager-mcp -f
```

### Deployment Summary

After completion, you'll see a summary:

```
╔════════════════════════════════════════════════════════════════════╗
║          TailOpsMCP Multi-Container Deployment Summary             ║
╚════════════════════════════════════════════════════════════════════╝

Container    Status      IP Address           Notes
----------   --------    ------------         -----
101          ✓ Success   192.168.1.101        Token: abc123...
102          ✓ Success   192.168.1.102        Token: def456...
103          ✗ Failed    N/A                  Installation script failed
```

## Troubleshooting

### Container Creation Failed

**Problem**: Template not found
```bash
# Download template first
pveam update
pveam download local debian-12-standard

# Then retry installation
```

**Problem**: Insufficient storage
```bash
# Check storage
pvesm status

# Free up space or use different storage
CONTAINER_STORAGE="local-lvm"
```

### Container Features Missing

**Problem**: Nesting or TUN device not enabled

**Solution 1**: Auto-fix (recommended)
```bash
AUTO_FIX_FEATURES=true
```

**Solution 2**: Manual fix
```bash
# Stop container
pct stop 101

# Edit config
nano /etc/pve/lxc/101.conf

# Add:
features: nesting=1,keyctl=1
lxc.cgroup2.devices.allow: c 10:200 rwm
lxc.mount.entry: /dev/net dev/net none bind,create=dir
lxc.apparmor.profile: unconfined

# Restart
pct start 101
```

### Installation Failed on One Container

If `CONTINUE_ON_FAILURE=true`, deployment continues to other containers.

Check logs:
```bash
# Inside container
pct exec 101 -- journalctl -u systemmanager-mcp -n 100

# Installation files (kept for debugging)
pct exec 101 -- ls -la /tmp/tailops-install
```

Retry single container:
```bash
./install-proxmox-multi.sh --containers 101 --config production.conf
```

### Service Not Starting

```bash
# Check service status
pct exec 101 -- systemctl status systemmanager-mcp

# Check logs
pct exec 101 -- journalctl -u systemmanager-mcp -xe

# Check Python environment
pct exec 101 -- /opt/systemmanager/venv/bin/python --version

# Test manual start
pct exec 101 -- /opt/systemmanager/venv/bin/python -m src.mcp_server
```

### Network Issues

```bash
# Check container can reach internet
pct exec 101 -- ping -c 3 github.com

# Check DNS
pct exec 101 -- cat /etc/resolv.conf

# Check IP configuration
pct exec 101 -- ip addr show
```

## Advanced Configuration

### Custom Installation Directory

```bash
SYSTEMMANAGER_INSTALL_DIR="/opt/custom/path"
```

### Different Git Branch

```bash
SYSTEMMANAGER_REPO_BRANCH="develop"
```

### Skip Docker Installation

If you don't need Docker features:
```bash
SKIP_DOCKER=true
```

### Force Reinstall

Reinstall even if already installed:
```bash
FORCE_REINSTALL=true
BACKUP_BEFORE_INSTALL=true
```

### Custom Timeouts

```bash
CONTAINER_START_TIMEOUT=60
INSTALL_TIMEOUT=900
```

### Logging

```bash
LOG_LEVEL="debug"  # debug, info, warning, error
LOG_DIR="/var/log/systemmanager-install"
```

## Post-Installation

### Access Your Instances

Each container will have TailOpsMCP running:
```bash
# Find container IPs
pct list

# Access via IP
http://192.168.1.101:8080
http://192.168.1.102:8080
http://192.168.1.103:8080
```

### Configure Claude Desktop

Add each instance to Claude Desktop MCP configuration:

```json
{
  "mcpServers": {
    "systemmanager-prod": {
      "url": "http://192.168.1.101:8080",
      "headers": {
        "Authorization": "Bearer your-token-here"
      }
    },
    "systemmanager-staging": {
      "url": "http://192.168.1.102:8080",
      "headers": {
        "Authorization": "Bearer your-token-here"
      }
    }
  }
}
```

See [integration.md](./integration.md) for more details.

### Managing Services

```bash
# Start/stop/restart service
pct exec 101 -- systemctl start systemmanager-mcp
pct exec 101 -- systemctl stop systemmanager-mcp
pct exec 101 -- systemctl restart systemmanager-mcp

# View logs
pct exec 101 -- journalctl -u systemmanager-mcp -f

# Check status
pct exec 101 -- systemctl status systemmanager-mcp
```

### Upgrading Installations

To upgrade all containers:
```bash
FORCE_REINSTALL=true
BACKUP_BEFORE_INSTALL=true
./install-proxmox-multi.sh --config your-config.conf
```

## Security Considerations

1. **Use OIDC in production**: Token-based auth is simpler but OIDC is more secure
2. **Store secrets securely**: Don't commit config files with secrets to version control
3. **Network isolation**: Consider using Tailscale VPN for secure access
4. **Regular updates**: Keep containers and TailOpsMCP updated
5. **Monitor logs**: Regularly check service logs for suspicious activity
6. **Unique secrets per container**: Use per-container overrides for different secrets

See [SECURITY.md](./SECURITY.md) for comprehensive security guidance.

## Best Practices

### Container Naming

Use descriptive hostnames:
```bash
HOSTNAME_PREFIX="tailops-prod"
# Results in: tailops-prod-101, tailops-prod-102, etc.
```

### Resource Allocation

- **Production**: 2GB RAM, 2 cores minimum
- **Development**: 1GB RAM, 1 core is acceptable
- **Disk**: 8GB minimum, 16GB recommended for logs

### Backup Strategy

Before major changes:
```bash
BACKUP_BEFORE_INSTALL=true
```

Regular container backups:
```bash
vzdump 101 --mode snapshot --storage backup-storage
```

### Testing Deployment

Test with a single container first:
```bash
./install-proxmox-multi.sh --containers 999 --create --auth none
```

Then scale to production:
```bash
./install-proxmox-multi.sh --config production.conf
```

## Comparison with Other Installation Methods

| Method | Use Case | Pros | Cons |
|--------|----------|------|------|
| **Proxmox Multi** | Deploy to multiple containers | Fast, automated, consistent | Requires Proxmox host access |
| **Standalone** | Single installation | Simple, flexible | Manual for each system |
| **Docker Compose** | Containerized deployment | Portable, isolated | Requires Docker |
| **Manual** | Custom setup | Full control | Time-consuming, error-prone |

## Support and Resources

- **Documentation**: See `/docs` directory for detailed guides
- **Issues**: Report bugs at https://github.com/mdlmarkham/TailOpsMCP/issues
- **Security**: Review [SECURITY.md](./SECURITY.md) for security best practices
- **Authentication**: See [TSIDP_OIDC_SETUP.md](./TSIDP_OIDC_SETUP.md) for OIDC setup

## Complete Configuration Reference

See [scripts/install/templates/proxmox-multi.conf](../scripts/install/templates/proxmox-multi.conf) for a fully documented configuration template with all available options.

---

**Last Updated**: 2025-11-18
**Version**: 1.0.0
