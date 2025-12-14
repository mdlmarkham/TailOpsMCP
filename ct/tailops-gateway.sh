#!/usr/bin/env bash

# TailOpsMCP Gateway One-Liner Installer
# Usage: bash -c "$(curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/ct/tailops-gateway.sh)"
# 
# This script creates a dedicated LXC container and installs TailOpsMCP inside it.
# For detailed documentation, see: docs/DEPLOY_PROXMOX_ONE_LINER.md

set -euo pipefail

# Configuration with sensible defaults
DEBIAN_VERSION="${DEBIAN_VERSION:-12}"
RAM_SIZE="${RAM_SIZE:-2048}"
CPU_CORES="${CPU_CORES:-2}"
DISK_SIZE="${DISK_SIZE:-8}"
BRIDGE="${BRIDGE:-vmbr0}"
UNPRIVILEGED="${UNPRIVILEGED:-1}"
CONTAINER_TEMPLATE="${CONTAINER_TEMPLATE:-debian-12-standard}"
PVE_HOST="${PVE_HOST:-$(hostname)}"
NEXTID="${NEXTID:-}"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Error handler
error_exit() {
    log_error "$1"
    exit 1
}

# Check if running on Proxmox
check_proxmox() {
    if ! command -v pct &>/dev/null; then
        error_exit "This script must be run on a Proxmox VE host. Command 'pct' not found."
    fi
    
    if ! pvesh get cluster info &>/dev/null; then
        error_exit "Not connected to Proxmox cluster. Please ensure you're on a Proxmox VE host."
    fi
}

# Validate environment
validate_environment() {
    log_info "Validating environment..."
    
    # Check if we have root access
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root on the Proxmox host."
    fi
    
    # Check for available container ID
    if [[ -z "$NEXTID" ]]; then
        # Find next available container ID
        local max_id=0
        for id in $(pct list | awk 'NR>1 {print $1}'); do
            if [[ $id -gt $max_id ]]; then
                max_id=$id
            fi
        done
        NEXTID=$((max_id + 100))
        log_info "Auto-selected container ID: $NEXTID"
    fi
    
    # Check if container ID already exists
    if pct status "$NEXTID" &>/dev/null; then
        error_exit "Container ID $NEXTID already exists. Please choose a different NEXTID or remove existing container."
    fi
    
    # Check for template
    if ! pveam available | grep -q "$CONTAINER_TEMPLATE"; then
        log_warning "Template $CONTAINER_TEMPLATE not found. Updating package list..."
        pveam update
        
        if ! pveam available | grep -q "$CONTAINER_TEMPLATE"; then
            error_exit "Template $CONTAINER_TEMPLATE not available. Please download it first: pveam download local $CONTAINER_TEMPLATE"
        fi
    fi
    
    # Check available resources
    local available_ram=$(free -m | awk 'NR==2{print $7}')
    if [[ $available_ram -lt $((RAM_SIZE + 512)) ]]; then
        log_warning "Available RAM (${available_ram}MB) may be insufficient for ${RAM_SIZE}MB container."
    fi
    
    log_success "Environment validation passed"
}

# Create LXC container
create_container() {
    log_info "Creating LXC container $NEXTID..."
    
    # Generate hostname
    local hostname="tailops-gateway-${PVE_HOST}"
    
    # Check available storage
    local storage=$(pvesm status | grep -v 'Name.*Type' | head -n1 | awk '{print $1}')
    if [[ -z "$storage" ]]; then
        storage="local-lvm"
    fi
    
    # Create container
    pct create "$NEXTID" \
        "$storage:vztmpl/$CONTAINER_TEMPLATE" \
        --hostname "$hostname" \
        --cores "$CPU_CORES" \
        --memory "$RAM_SIZE" \
        --rootfs "$storage:$DISK_SIZE" \
        --net0 name=eth0,bridge="$BRIDGE",ip=dhcp \
        --unprivileged "$UNPRIVILEGED" \
        --features nesting=1,keyctl=1 \
        --password="" \
        --ssh-public-keys="" \
        || error_exit "Failed to create container $NEXTID"
    
    # Configure LXC features for Tailscale and Docker
    log_info "Configuring container features..."
    
    # Add TUN device access
    pct set "$NEXTID" -cgroup2.devices.allow "c 10:200 rwm"
    
    # Add AppArmor profile for nesting
    pct set "$NEXTID" -apparmor.profile unconfined
    
    # Mount /dev/net for Tailscale
    pct set "$NEXTID" -mp0 dev/net,mp=/dev/net,options=bind,create=dir
    
    log_success "Container $NEXTID created and configured"
}

# Start container and wait for it to be ready
start_container() {
    log_info "Starting container $NEXTID..."
    
    pct start "$NEXTID" || error_exit "Failed to start container $NEXTID"
    
    # Wait for container to be ready
    log_info "Waiting for container to be ready..."
    local timeout=60
    local count=0
    
    while [[ $count -lt $timeout ]]; do
        if pct status "$NEXTID" | grep -q "running"; then
            log_success "Container is running"
            return 0
        fi
        sleep 2
        count=$((count + 2))
    done
    
    error_exit "Container failed to start within $timeout seconds"
}

# Install TailOpsMCP in container
install_tailopsmcp() {
    log_info "Installing TailOpsMCP in container $NEXTID..."
    
    # Copy installation script to container
    local install_script="/tmp/tailops-install-$$.sh"
    cat > "$install_script" << 'INSTALL_EOF'
#!/usr/bin/env bash
set -euo pipefail

echo "TailOpsMCP Installation Starting..."

# Update package list
apt-get update

# Install required dependencies
DEBIAN_FRONTEND=noninteractive apt-get install -y curl sudo git ca-certificates

# Clone TailOpsMCP repository
INSTALL_DIR="/opt/tailopsmcp"
echo "Cloning TailOpsMCP repository to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

if ! git clone https://github.com/mdlmarkham/TailOpsMCP.git .; then
    echo "ERROR: Failed to clone repository"
    exit 1
fi

echo "Repository cloned successfully"

# Run the Proxmox installer
if [[ -f "scripts/install/install-proxmox.sh" ]]; then
    echo "Running TailOpsMCP Proxmox installer..."
    chmod +x scripts/install/install-proxmox.sh
    bash scripts/install/install-proxmox.sh
else
    echo "ERROR: Proxmox installer not found"
    exit 1
fi

echo "TailOpsMCP installation completed"
INSTALL_EOF

    # Copy script to container and execute
    pct push "$NEXTID" "$install_script" "/tmp/install.sh"
    pct exec "$NEXTID" -- chmod +x /tmp/install.sh
    pct exec "$NEXTID" -- bash /tmp/install.sh
    
    # Cleanup
    rm -f "$install_script"
    
    log_success "TailOpsMCP installed in container $NEXTID"
}

# Get container information
get_container_info() {
    local ip=$(pct exec "$NEXTID" -- hostname -I | awk '{print $1}')
    local hostname=$(pct exec "$NEXTID" -- hostname)
    
    log_success "Container Details:"
    echo "  Container ID: $NEXTID"
    echo "  Hostname: $hostname"
    echo "  IP Address: $ip"
    echo "  Memory: ${RAM_SIZE}MB"
    echo "  CPU Cores: $CPU_CORES"
    echo "  Disk: ${DISK_SIZE}GB"
}

# Show final instructions
show_instructions() {
    local ip=$(pct exec "$NEXTID" -- hostname -I | awk '{print $1}')
    local hostname=$(pct exec "$NEXTID" -- hostname)
    
    echo
    echo "═══════════════════════════════════════════════════════════════"
    echo "          TailOpsMCP Gateway Installation Complete!"
    echo "═══════════════════════════════════════════════════════════════"
    echo
    echo "Container Details:"
    echo "  ID: $NEXTID"
    echo "  Hostname: $hostname"
    echo "  IP: $ip"
    echo
    echo "Next Steps:"
    echo "  1. Join Tailscale network (if not already connected)"
    echo "  2. Configure targets.yaml in the container:"
    echo "     pct exec $NEXTID -- nano /opt/tailopsmcp/targets.yaml"
    echo "  3. Connect your AI assistant to the gateway:"
    echo "     http://$ip:8080"
    echo
    echo "Useful Commands:"
    echo "  Check status: pct exec $NEXTID -- systemctl status tailopsmcp-mcp"
    echo "  View logs: pct exec $NEXTID -- journalctl -u tailopsmcp-mcp -f"
    echo "  Enter container: pct enter $NEXTID"
    echo "  Stop container: pct stop $NEXTID"
    echo "  Remove container: pct destroy $NEXTID"
    echo
    echo "Documentation: https://github.com/mdlmarkham/TailOpsMCP/blob/master/docs/DEPLOY_PROXMOX_ONE_LINER.md"
    echo
    echo "═══════════════════════════════════════════════════════════════"
}

# Cleanup on exit
cleanup() {
    if [[ -n "${install_script:-}" && -f "$install_script" ]]; then
        rm -f "$install_script"
    fi
}

trap cleanup EXIT

# Main execution
main() {
    echo "TailOpsMCP Gateway One-Liner Installer"
    echo "======================================"
    echo
    
    check_proxmox
    validate_environment
    create_container
    start_container
    install_tailopsmcp
    get_container_info
    show_instructions
    
    log_success "TailOpsMCP Gateway deployed successfully!"
}

# Show usage if called with --help
if [[ "${1:-}" == "--help" ]]; then
    cat << EOF
TailOpsMCP Gateway One-Liner Installer

Usage: bash -c "\$(curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/ct/tailops-gateway.sh)"

Environment Variables (optional):
  DEBIAN_VERSION     Debian version (default: 12)
  RAM_SIZE          Memory in MB (default: 2048)
  CPU_CORES         Number of CPU cores (default: 2)
  DISK_SIZE         Disk size in GB (default: 8)
  BRIDGE            Network bridge (default: vmbr0)
  UNPRIVILEGED      Run as unprivileged (default: 1)
  CONTAINER_TEMPLATE LXC template (default: debian-12-standard)
  PVE_HOST          Hostname prefix (default: current hostname)
  NEXTID            Container ID (default: auto-select)

Example:
  DEBIAN_VERSION=12 RAM_SIZE=4096 CPU_CORES=4 bash -c "\$(curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/ct/tailops-gateway.sh)"

For more information, see: docs/DEPLOY_PROXMOX_ONE_LINER.md
EOF
    exit 0
fi

# Check for immediate failure conditions
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi