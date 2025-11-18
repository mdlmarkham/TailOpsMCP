# TailOpsMCP Installation Scripts

Modular, robust, and platform-aware installation scripts for TailOpsMCP.

## Architecture

The installation system is designed for maximum flexibility, robustness, and maintainability:

```
scripts/install/
├── install.sh                 # Main dispatcher (auto-detects platform)
├── install-standalone.sh      # Universal installer (works anywhere)
├── install-proxmox.sh         # ProxMox LXC optimizations
├── install-ec2.sh             # Cloud environment optimizations
├── lib/                       # Shared library modules
│   ├── common.sh              # Utility functions, logging, error handling
│   ├── platform-detect.sh     # Platform/OS/cloud detection
│   ├── preflight.sh           # Pre-installation validation
│   ├── auth-setup.sh          # Authentication configuration
│   └── validation.sh          # Post-installation testing
└── templates/                 # Configuration templates
    ├── install.conf.example   # General template
    ├── proxmox-lxc.conf       # ProxMox LXC template
    ├── ec2-cloud.conf         # Cloud environment template
    └── development.conf       # Development template
```

## Key Features

### 1. Robust Error Handling
- **Rollback on failure**: Automatically undoes changes if installation fails
- **State tracking**: Knows what was installed and can clean up
- **Detailed logging**: All operations logged for troubleshooting
- **Safe interrupt handling**: Can recover from Ctrl+C

### 2. Platform Detection & Optimization
- **Automatic detection**: LXC, EC2, GCP, Azure, DigitalOcean, bare metal
- **Platform-specific optimizations**:
  - ProxMox LXC: Container feature checks, networking, MOTD
  - EC2/Cloud: Security groups, metadata, cloud-init
  - Bare metal: Standard installation
- **Adaptive configuration**: Adjusts based on environment

### 3. Comprehensive Pre-flight Checks
- **Resource validation**: Memory, disk, CPU
- **Network connectivity**: Internet, DNS, specific hosts
- **Port availability**: Checks for conflicts
- **OS compatibility**: Validates supported distributions
- **Dependency detection**: Checks for required tools
- **Existing installation**: Handles upgrades gracefully

### 4. Flexible Authentication
- **Tailscale OAuth (OIDC)**: Multi-user, recommended
- **Token-based**: Simple shared secret
- **No auth**: Development only
- **Configuration files**: Non-interactive setup

### 5. Idempotent & Safe
- **Detects existing installations**: Offers upgrade path
- **Backup before changes**: Preserves configuration
- **Non-destructive**: Won't overwrite without confirmation
- **Upgrade support**: Seamless version updates

### 6. Post-Installation Validation
- **Service checks**: Running, enabled, healthy
- **Port listening**: Confirms network availability
- **File integrity**: Validates installation
- **Python environment**: Checks dependencies
- **Integration tests**: Basic functionality

## Usage

### Quick Start

#### Automatic Platform Detection
```bash
# Download and run
curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/main/install.sh | sudo bash

# Or from repository
sudo bash install.sh
```

#### Check System First
```bash
sudo bash install.sh --check
```

### Platform-Specific Installation

#### ProxMox LXC Container
```bash
# From ProxMox host (creates new LXC)
bash -c "$(wget -qLO - https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/main/ct/build.func)"

# Inside existing LXC
sudo bash install.sh --platform proxmox
```

#### EC2 / Cloud Instance
```bash
sudo bash install.sh --platform ec2
```

#### Standalone / Bare Metal
```bash
sudo bash install.sh --platform standalone
```

### Non-Interactive Installation

#### With Configuration File
```bash
# Copy and edit template
cp scripts/install/templates/ec2-cloud.conf /tmp/config.conf
nano /tmp/config.conf

# Run installation
sudo bash install.sh --config /tmp/config.conf
```

#### With Environment Variables
```bash
sudo SYSTEMMANAGER_AUTH_MODE=token \
     SYSTEMMANAGER_SHARED_SECRET="$(openssl rand -hex 32)" \
     NON_INTERACTIVE=true \
     bash install.sh
```

### Advanced Options

```bash
# Custom installation directory
sudo bash install.sh --install-dir /opt/custom

# Custom port
sudo bash install.sh --port 9090

# Skip Docker installation
sudo SKIP_DOCKER=true bash install.sh

# Force reinstall
sudo FORCE_REINSTALL=true bash install.sh

# Development branch
sudo SYSTEMMANAGER_REPO_BRANCH=develop bash install.sh
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SYSTEMMANAGER_INSTALL_DIR` | Installation directory | `/opt/systemmanager` |
| `SYSTEMMANAGER_PORT` | Service port | `8080` |
| `SYSTEMMANAGER_DATA_DIR` | Data directory | `/var/lib/systemmanager` |
| `SYSTEMMANAGER_AUTH_MODE` | Auth mode (oidc/token/none) | Interactive prompt |
| `SYSTEMMANAGER_SHARED_SECRET` | Token for token-based auth | Auto-generated |
| `TSIDP_URL` | Tailscale IdP URL | - |
| `TSIDP_CLIENT_ID` | OAuth client ID | - |
| `TSIDP_CLIENT_SECRET` | OAuth client secret | - |
| `NON_INTERACTIVE` | Skip prompts | `false` |
| `SKIP_DOCKER` | Skip Docker installation | `false` |
| `FORCE_REINSTALL` | Force reinstall | `false` |
| `SYSTEMMANAGER_REPO_URL` | Git repository | Official repo |
| `SYSTEMMANAGER_REPO_BRANCH` | Git branch | `main` |

### Configuration Files

Configuration files support all environment variables plus comments:

```bash
# /etc/systemmanager/install.conf
SYSTEMMANAGER_AUTH_MODE="oidc"
TSIDP_URL="https://tsidp.tail12345.ts.net"
TSIDP_CLIENT_ID="your-client-id"
TSIDP_CLIENT_SECRET="your-client-secret"
NON_INTERACTIVE=true
```

Load with:
```bash
sudo bash install.sh --config /etc/systemmanager/install.conf
```

## Library Modules

### common.sh
Core functionality used by all installers:
- Logging functions (msg_info, msg_ok, msg_warn, msg_error)
- State tracking and rollback
- Version management
- User and permission management
- Package management (apt, dnf, yum)
- Python and Docker installation
- Service management
- Git repository operations

### platform-detect.sh
Platform and environment detection:
- Virtualization type (LXC, KVM, VMware, etc.)
- Cloud provider (AWS, GCP, Azure, DigitalOcean, etc.)
- Operating system and version
- System resources
- Network information
- Tailscale detection

### preflight.sh
Pre-installation validation:
- Resource checks (memory, disk, CPU)
- Network connectivity and DNS
- Port availability
- Required commands
- Systemd availability
- Existing installation detection
- Security requirements (SELinux, AppArmor, firewall)
- Platform-specific requirements

### auth-setup.sh
Authentication configuration:
- OIDC/Tailscale OAuth setup
- Token-based authentication
- No authentication (development)
- Tailscale installation helper
- Configuration validation

### validation.sh
Post-installation testing:
- Service status and health
- Port listening checks
- Local connectivity tests
- File system validation
- Permission checks
- Python environment validation
- Authentication validation
- Docker validation
- Integration tests
- Installation summary display

## Upgrading

### From Existing Installation

The installer automatically detects existing installations:

```bash
# Interactive upgrade (will prompt)
sudo bash install.sh

# Non-interactive upgrade
sudo FORCE_REINSTALL=true bash install.sh
```

### What Happens During Upgrade
1. Service is stopped
2. Configuration is backed up
3. Repository is updated (git pull)
4. Python dependencies are updated
5. Configuration is restored
6. Service is restarted
7. Quick validation is run

### Configuration Preservation

Your `.env` file is always preserved during upgrades. Backup copies are created with timestamps:
- `/opt/systemmanager/.env.backup-1234567890`

## Troubleshooting

### Check Installation Logs
```bash
# Installation logs are saved to /tmp/systemmanager-install-*.log
# Service logs:
journalctl -u systemmanager-mcp -n 100
```

### Common Issues

#### Port Already in Use
The installer detects port conflicts and offers to use a different port:
```bash
# Specify custom port
sudo bash install.sh --port 9090
```

#### Python Version Too Old
The installer automatically installs Python 3.11+ on supported distributions. If your distribution doesn't have it available, consider:
- Using a newer OS version
- Installing Python from source
- Using Docker to run the service

#### Docker Not Working in LXC
ProxMox LXC containers need special configuration:
```
features: nesting=1,keyctl=1
lxc.apparmor.profile: unconfined
```

#### Tailscale Not Working in LXC
Enable TUN device in LXC configuration:
```
lxc.cgroup2.devices.allow: c 10:200 rwm
lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file
```

### Rollback on Failure

If installation fails, the installer automatically rolls back:
- Removes systemd service
- Removes service user
- Optionally removes installation directory
- Cleans up state files

### Manual Cleanup

If you need to manually clean up a failed installation:

```bash
# Stop and remove service
sudo systemctl stop systemmanager-mcp
sudo systemctl disable systemmanager-mcp
sudo rm /etc/systemd/system/systemmanager-mcp.service
sudo systemctl daemon-reload

# Remove user
sudo userdel systemmanager

# Remove installation
sudo rm -rf /opt/systemmanager
sudo rm -rf /var/lib/systemmanager

# Remove logs
sudo rm /tmp/systemmanager-install-*.log
```

## Development

### Testing Installation Scripts

```bash
# Test in Docker container
docker run -it --rm --privileged debian:12 bash
# Inside container:
curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/main/install.sh | bash

# Test platform detection
sudo bash install.sh --check

# Test with configuration file
sudo bash install.sh --config templates/development.conf

# Test upgrade path
sudo bash install.sh  # Install first
sudo bash install.sh  # Run again to test upgrade
```

### Modifying Library Functions

All library functions are exported and can be used in any installer:

```bash
source lib/common.sh
source lib/platform-detect.sh

# Use functions
run_platform_detection
install_base_packages
create_service_user
```

### Adding New Platform Support

1. Create new installer: `install-newplatform.sh`
2. Source `install-standalone.sh` for base functionality
3. Add platform-specific optimizations
4. Update `install.sh` dispatcher to detect new platform
5. Update documentation

### Testing Checklist

- [ ] Clean install on each platform (LXC, EC2, bare metal)
- [ ] Upgrade from previous version
- [ ] Non-interactive installation
- [ ] Configuration file installation
- [ ] Rollback on failure
- [ ] Port conflict handling
- [ ] Pre-existing installation detection
- [ ] Each authentication mode
- [ ] Post-installation validation

## Contributing

When modifying installation scripts:

1. **Test thoroughly** on all supported platforms
2. **Maintain idempotency** - script should be safe to run multiple times
3. **Add error handling** - use error traps and rollback
4. **Document changes** - update relevant README sections
5. **Follow conventions** - use existing function patterns
6. **Test rollback** - ensure cleanup works on failure

## Support

- Documentation: https://github.com/mdlmarkham/TailOpsMCP
- Issues: https://github.com/mdlmarkham/TailOpsMCP/issues
- Discussions: https://github.com/mdlmarkham/TailOpsMCP/discussions
