# TailOpsMCP Gateway One-Liner Deployment

This guide explains how to deploy TailOpsMCP gateways using the simple one-liner command on Proxmox VE hosts.

## Overview

The TailOpsMCP Gateway One-Liner is a single command that creates a dedicated LXC container and installs TailOpsMCP inside it. This provides:

- ✅ **Isolated Gateway**: LXC container for security and resource management
- ✅ **Sensible Defaults**: Debian 12, 2GB RAM, 2 CPU cores, 8GB disk
- ✅ **Production Ready**: Pre-configured for Tailscale and Docker integration
- ✅ **Simple Management**: One command creates everything needed
- ✅ **Safe Execution**: Idempotent with proper error handling

## Quick Start

### Basic One-Liner Command

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/ct/tailops-gateway.sh)"
```

This command will:
1. ✅ Create a new LXC container with TailOpsMCP
2. ✅ Configure it with sensible defaults
3. ✅ Install and configure TailOpsMCP
4. ✅ Start the service
5. ✅ Display access instructions

### Customized Deployment

Override default configuration with environment variables:

```bash
# High-performance deployment
DEBIAN_VERSION=12 RAM_SIZE=4096 CPU_CORES=4 DISK_SIZE=16 \
bash -c "$(curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/ct/tailops-gateway.sh)"

# Minimal deployment
DEBIAN_VERSION=12 RAM_SIZE=1024 CPU_CORES=1 DISK_SIZE=4 \
bash -c "$(curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/ct/tailops-gateway.sh)"

# Custom container ID and network
NEXTID=201 BRIDGE=vmbr1 \
bash -c "$(curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/ct/tailops-gateway.sh)"
```

## Configuration Options

### Environment Variables

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `DEBIAN_VERSION` | Debian OS version | `12` | `12` |
| `RAM_SIZE` | Container memory in MB | `2048` | `4096` |
| `CPU_CORES` | Number of CPU cores | `2` | `4` |
| `DISK_SIZE` | Disk size in GB | `8` | `16` |
| `BRIDGE` | Network bridge | `vmbr0` | `vmbr1` |
| `UNPRIVILEGED` | Run unprivileged | `1` | `0` |
| `CONTAINER_TEMPLATE` | LXC template | `debian-12-standard` | `ubuntu-22.04-standard` |
| `PVE_HOST` | Hostname prefix | `$(hostname)` | `pve-prod-01` |
| `NEXTID` | Container ID | `auto-select` | `201` |

### Pre-Deployment Checklist

Before running the one-liner:

- ✅ **Proxmox VE Host**: Ensure you're on a Proxmox VE host
- ✅ **Root Access**: Script must be run as root
- ✅ **Template Available**: Debian 12 standard template must be available
- ✅ **Resources**: Sufficient RAM, CPU, and disk space
- ✅ **Network**: DHCP available on the target bridge
- ✅ **Tailscale**: Plan for Tailscale integration

## What Gets Created

### LXC Container

The script creates a container with these characteristics:

```yaml
Container Configuration:
  ID: Auto-selected (or specified)
  Hostname: tailops-gateway-{hostname}
  OS: Debian 12
  Memory: 2GB (configurable)
  CPU: 2 cores (configurable)
  Disk: 8GB (configurable)
  Network: DHCP on bridge (configurable)
  Features:
    - Nesting enabled (for Docker)
    - Keyctl enabled
    - TUN device access (for Tailscale)
    - AppArmor unconfined
```

### TailOpsMCP Installation

Inside the container, TailOpsMCP is installed with:

```yaml
Installation Details:
  Location: /opt/tailopsmcp
  Service: tailopsmcp-mcp
  Port: 8080
  User: tailopsmcp
  Python: 3.12
  Dependencies: Docker, Git, Python packages
  Configuration: targets.yaml
```

## Security Considerations

### Container Security

- **Unprivileged by Default**: Runs as non-root user inside container
- **AppArmor Profile**: Unconfined for functionality, can be hardened
- **Resource Limits**: CPU and memory constraints
- **Network Isolation**: Container networking

### External Dependencies

- **Community-Scripts**: Pinned to specific commit hash
- **Docker**: Downloaded from official get.docker.com
- **Python Packages**: Installed from official repositories

### Supply Chain Security

The one-liner uses pinned versions for security:

```bash
# External dependency pinned to commit hash
source <(curl -s https://raw.githubusercontent.com/community-scripts/ProxmoxVE/3c8e7a1/misc/build.func)
```

**Security Note**: Always verify the commit hash before deployment.

## Configuration After Deployment

### 1. Configure Targets

Edit the targets configuration inside the container:

```bash
# Enter the container
pct enter $(pct list | grep tailops-gateway | awk '{print $1}')

# Edit configuration
nano /opt/tailopsmcp/targets.yaml
```

### 2. Tailscale Integration

If not already integrated, set up Tailscale:

```bash
# Inside container
tailscale up --auth-key=YOUR_AUTH_KEY
```

### 3. Service Management

```bash
# Check service status
pct exec $(CONTAINER_ID) -- systemctl status tailopsmcp-mcp

# View logs
pct exec $(CONTAINER_ID) -- journalctl -u tailopsmcp-mcp -f

# Restart service
pct exec $(CONTAINER_ID) -- systemctl restart tailopsmcp-mcp
```

## Troubleshooting

### Common Issues

#### Container Creation Failed

**Problem**: Template not found
```bash
# Solution: Download template first
pveam update
pveam download local debian-12-standard
```

**Problem**: Insufficient resources
```bash
# Check available resources
free -m
pvesm status

# Use smaller configuration
RAM_SIZE=1024 CPU_CORES=1 DISK_SIZE=4 bash -c "$(curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/ct/tailops-gateway.sh)"
```

**Problem**: Container ID conflicts
```bash
# Specify different container ID
NEXTID=201 bash -c "$(curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/ct/tailops-gateway.sh)"
```

#### Installation Failed

**Problem**: Network connectivity
```bash
# Test connectivity inside container
pct exec $(CONTAINER_ID) -- ping -c 3 github.com

# Check DNS
pct exec $(CONTAINER_ID) -- cat /etc/resolv.conf
```

**Problem**: Git clone failed
```bash
# Manual installation inside container
pct enter $(CONTAINER_ID)
cd /opt/tailopsmcp
git clone https://github.com/mdlmarkham/TailOpsMCP.git .
bash scripts/install/install-proxmox.sh
```

#### Service Not Starting

**Problem**: Python environment issues
```bash
# Check Python installation
pct exec $(CONTAINER_ID) -- /opt/tailopsmcp/venv/bin/python --version

# Reinstall Python dependencies
pct exec $(CONTAINER_ID) -- bash -c "source /opt/tailopsmcp/venv/bin/activate && pip install -r /opt/tailopsmcp/requirements.txt"
```

**Problem**: Port conflicts
```bash
# Check what's using port 8080
pct exec $(CONTAINER_ID) -- netstat -tulpn | grep 8080

# Change port in configuration
# Edit /opt/tailopsmcp/config/policy.yaml
```

### Debug Mode

For detailed logging:

```bash
# Run with debug output
bash -x "$(curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/ct/tailops-gateway.sh)"
```

### Container Logs

View detailed installation logs:

```bash
# Check container console
pct console $(CONTAINER_ID)

# Check system logs
pct exec $(CONTAINER_ID) -- journalctl -xe

# Check TailOpsMCP specific logs
pct exec $(CONTAINER_ID) -- journalctl -u tailopsmcp-mcp --since "1 hour ago"
```

## Maintenance

### Updates

To update TailOpsMCP inside the container:

```bash
# Enter container
pct enter $(CONTAINER_ID)

# Update TailOpsMCP
cd /opt/tailopsmcp
git pull
source venv/bin/activate
pip install -r requirements.txt

# Restart service
systemctl restart tailopsmcp-mcp
```

### Backup

Backup container configuration and data:

```bash
# Backup container
pct backup $(CONTAINER_ID) /var/lib/vz/dump/tailops-gateway-backup.tar.gz

# Backup configuration
pct exec $(CONTAINER_ID) -- tar -czf /tmp/tailopsmcp-config.tar.gz /opt/tailopsmcp/targets.yaml /opt/tailopsmcp/config/
```

### Migration

To migrate to a new container:

```bash
# Create new container
NEXTID=202 bash -c "$(curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/ct/tailops-gateway.sh)"

# Copy configuration
pct exec $(OLD_CONTAINER_ID) -- tar -czf /tmp/config.tar.gz /opt/tailopsmcp/targets.yaml /opt/tailopsmcp/config/
pct pull $(OLD_CONTAINER_ID) /tmp/config.tar.gz /tmp/config.tar.gz
pct push $(NEW_CONTAINER_ID) /tmp/config.tar.gz /tmp/config.tar.gz
pct exec $(NEW_CONTAINER_ID) -- tar -xzf /tmp/config.tar.gz -C /

# Clean up old container
pct stop $(OLD_CONTAINER_ID)
pct destroy $(OLD_CONTAINER_ID)
```

## Removal

### Complete Removal

To completely remove the TailOpsMCP gateway:

```bash
# Stop and destroy container
pct stop $(CONTAINER_ID)
pct destroy $(CONTAINER_ID)

# Remove any backups
rm -f /var/lib/vz/dump/*tailops-gateway*

# Remove Tailscale node (if desired)
# Use Tailscale admin panel to remove the node
```

### Selective Removal

Keep container but remove TailOpsMCP:

```bash
# Enter container
pct enter $(CONTAINER_ID)

# Stop service
systemctl stop tailopsmcp-mcp
systemctl disable tailopsmcp-mcp

# Remove installation
rm -rf /opt/tailopsmcp
rm -f /etc/systemd/system/tailopsmcp-mcp.service

# Cleanup
systemctl daemon-reload
```

## Advanced Usage

### Multiple Gateways

Deploy multiple gateways with different configurations:

```bash
# Development gateway
DEBIAN_VERSION=12 RAM_SIZE=1024 CPU_CORES=1 NEXTID=201 \
bash -c "$(curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/ct/tailops-gateway.sh)"

# Production gateway
DEBIAN_VERSION=12 RAM_SIZE=4096 CPU_CORES=4 NEXTID=202 \
bash -c "$(curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/ct/tailops-gateway.sh)"
```

### Network Isolation

Deploy on different network segments:

```bash
# Management network
BRIDGE=vmbr1 NEXTID=210 \
bash -c "$(curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/ct/tailops-gateway.sh)"

# Production network
BRIDGE=vmbr2 NEXTID=211 \
bash -c "$(curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/ct/tailops-gateway.sh)"
```

### Custom Templates

Use different OS templates:

```bash
# Ubuntu template
CONTAINER_TEMPLATE=ubuntu-22.04-standard \
bash -c "$(curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/ct/tailops-gateway.sh)"
```

## Performance Tuning

### Resource Optimization

For high-performance deployments:

```bash
# High-performance configuration
RAM_SIZE=8192 CPU_CORES=8 DISK_SIZE=32 CONTAINER_TEMPLATE=debian-12-standard \
bash -c "$(curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/ct/tailops-gateway.sh)"
```

### Resource Monitoring

Monitor container resource usage:

```bash
# Check container resources
pct status $(CONTAINER_ID)
pct exec $(CONTAINER_ID) -- free -h
pct exec $(CONTAINER_ID) -- df -h /

# Monitor in real-time
watch -n 5 'pct exec $(CONTAINER_ID) -- free -h && pct exec $(CONTAINER_ID) -- top -bn1 | head -10'
```

## Integration with Existing Infrastructure

### Existing Tailscale Networks

If you already have Tailscale networks:

```bash
# Deploy to specific Tailscale network
# Configure ACLs to allow gateway access
# Join gateway to existing tailnet
tailscale up --auth-key=EXISTING_AUTH_KEY --advertise-routes=192.168.1.0/24
```

### Integration with CI/CD

Automate deployment in CI/CD pipelines:

```yaml
# GitHub Actions example
- name: Deploy TailOpsMCP Gateway
  run: |
    ssh root@proxmox-host "
      DEBIAN_VERSION=12 RAM_SIZE=2048 CPU_CORES=2 NEXTID=${{ matrix.container_id }} \
      bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/ct/tailops-gateway.sh)\"
    "
```

## Security Hardening

### Container Hardening

Additional security measures:

```bash
# Use privileged mode if needed (less secure)
UNPRIVILEGED=0 bash -c "\$(curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/ct/tailops-gateway.sh)"

# Add additional LXC security features
# Edit container config manually after creation
pct set $(CONTAINER_ID) -lxc.cap.drop=sys_admin
pct set $(CONTAINER_ID) -lxc.cap.drop=net_admin
```

### Network Security

Secure network configuration:

```bash
# Use specific VLAN
BRIDGE=vmbr0.100 VLAN=100 \
bash -c "\$(curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/ct/tailops-gateway.sh)"
```

## Support and Community

- **Documentation**: https://github.com/mdlmarkham/TailOpsMCP
- **Issues**: https://github.com/mdlmarkham/TailOpsMCP/issues
- **Discussions**: https://github.com/mdlmarkham/TailOpsMCP/discussions
- **Security**: Report security issues privately

## License

MIT License - see LICENSE file for details.