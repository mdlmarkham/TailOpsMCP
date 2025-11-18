# TailOpsMCP Installation Configuration Templates

This directory contains configuration templates for different installation scenarios.

## Available Templates

### 1. `install.conf.example`
General template with all available options documented. Use this as a reference or starting point for custom configurations.

**Usage:**
```bash
cp templates/install.conf.example /etc/systemmanager/install.conf
# Edit /etc/systemmanager/install.conf with your values
sudo bash install.sh --config /etc/systemmanager/install.conf
```

### 2. `proxmox-lxc.conf`
Optimized configuration for ProxMox LXC containers with Tailscale OAuth authentication.

**Usage:**
```bash
# 1. Copy and edit the template
cp templates/proxmox-lxc.conf /tmp/my-config.conf
nano /tmp/my-config.conf  # Fill in your OAuth credentials

# 2. Run installation
sudo bash install.sh --config /tmp/my-config.conf
```

**Requirements:**
- ProxMox LXC container with nesting enabled
- Tailscale installed and running
- OAuth application created in Tailscale admin

### 3. `ec2-cloud.conf`
Optimized for cloud environments (AWS EC2, GCP, Azure, DigitalOcean, etc.).

**Usage:**
```bash
# 1. Install Tailscale first
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up

# 2. Copy and edit the template
cp templates/ec2-cloud.conf /tmp/my-config.conf
nano /tmp/my-config.conf  # Fill in your configuration

# 3. Run installation
sudo bash install.sh --config /tmp/my-config.conf
```

**Security Note:**
Always use authentication in cloud environments. Do NOT expose port 8080 to the public internet without Tailscale or proper authentication.

### 4. `development.conf`
Configuration for local development and testing.

**Usage:**
```bash
sudo bash install.sh --config templates/development.conf
```

**⚠️ WARNING:**
This template disables authentication for development convenience. NEVER use in production or on network-accessible systems.

## Quick Start Examples

### Interactive Installation (Recommended for First Time)
```bash
# Auto-detect platform and run interactive installer
sudo bash install.sh
```

### Non-Interactive with Token Auth
```bash
# Generate token
TOKEN=$(openssl rand -hex 32)

# Install with token auth
sudo SYSTEMMANAGER_AUTH_MODE=token \
     SYSTEMMANAGER_SHARED_SECRET="$TOKEN" \
     NON_INTERACTIVE=true \
     bash install.sh

echo "Save this token: $TOKEN"
```

### Non-Interactive with Config File
```bash
# 1. Create config file
cat > /tmp/install.conf << EOF
SYSTEMMANAGER_AUTH_MODE="token"
SYSTEMMANAGER_SHARED_SECRET="$(openssl rand -hex 32)"
NON_INTERACTIVE=true
SKIP_DOCKER=false
EOF

# 2. Run installer
sudo bash install.sh --config /tmp/install.conf
```

### ProxMox LXC Quick Install
```bash
# From ProxMox host - creates new LXC
bash -c "$(wget -qLO - https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/main/ct/build.func)"

# Or inside existing LXC
sudo bash install.sh --platform proxmox
```

### EC2/Cloud Quick Install
```bash
# Install Tailscale first
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up

# Then install TailOpsMCP
curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/main/scripts/install/install.sh | sudo bash
```

## Configuration Options

### Authentication Modes

#### OIDC (Tailscale OAuth) - Recommended
```bash
SYSTEMMANAGER_AUTH_MODE="oidc"
TSIDP_URL="https://tsidp.tail12345.ts.net"
TSIDP_CLIENT_ID="your-client-id"
TSIDP_CLIENT_SECRET="your-client-secret"
SYSTEMMANAGER_BASE_URL="http://server.tail12345.ts.net:8080"
```

#### Token-Based - Simple
```bash
SYSTEMMANAGER_AUTH_MODE="token"
SYSTEMMANAGER_SHARED_SECRET="$(openssl rand -hex 32)"
```

#### None - Development Only
```bash
SYSTEMMANAGER_AUTH_MODE="none"
```

### Installation Options

```bash
# Installation directory
SYSTEMMANAGER_INSTALL_DIR="/opt/systemmanager"

# Data directory
SYSTEMMANAGER_DATA_DIR="/var/lib/systemmanager"

# Service port
SYSTEMMANAGER_PORT=8080

# Skip Docker installation
SKIP_DOCKER=false

# Non-interactive mode
NON_INTERACTIVE=false

# Force reinstall
FORCE_REINSTALL=false

# Repository and branch
SYSTEMMANAGER_REPO_URL="https://github.com/mdlmarkham/TailOpsMCP.git"
SYSTEMMANAGER_REPO_BRANCH="main"

# Logging level
LOG_LEVEL="INFO"
```

## Platform-Specific Notes

### ProxMox LXC

Required container features:
```
features: nesting=1,keyctl=1
lxc.apparmor.profile: unconfined
lxc.cgroup2.devices.allow: c 10:200 rwm  # For Tailscale
```

### AWS EC2

Security group requirements:
- Keep port 8080 CLOSED to public internet
- Use Tailscale for secure access
- Or restrict port 8080 to specific IPs only

### GCP / Azure / DigitalOcean

Similar to EC2:
- Configure firewall to block public access to port 8080
- Use Tailscale for secure remote access

## Upgrade Existing Installation

```bash
# Interactive upgrade
sudo bash install.sh

# Non-interactive upgrade
sudo FORCE_REINSTALL=true bash install.sh --config /path/to/config
```

## Troubleshooting

### Check System Before Installation
```bash
sudo bash install.sh --check
```

### View Installation Logs
```bash
# During installation, log file location is shown
# After installation:
journalctl -u systemmanager-mcp -n 100
```

### Test Installation
```bash
# Check service status
sudo systemctl status systemmanager-mcp

# Test locally
curl http://localhost:8080/.well-known/oauth-protected-resource/mcp

# Test via Tailscale (if configured)
curl http://your-server.tail12345.ts.net:8080/.well-known/oauth-protected-resource/mcp
```

## Support

- Documentation: https://github.com/mdlmarkham/TailOpsMCP
- Issues: https://github.com/mdlmarkham/TailOpsMCP/issues
