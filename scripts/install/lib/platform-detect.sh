#!/usr/bin/env bash
# Platform detection for TailOpsMCP installation
# Copyright (c) 2024 TailOpsMCP Contributors
# License: MIT

#######################################
# Detect Virtualization Type
#######################################

function detect_virtualization() {
    VIRT_TYPE="none"

    # Try systemd-detect-virt first (most reliable)
    if command -v systemd-detect-virt &>/dev/null; then
        VIRT_TYPE=$(systemd-detect-virt 2>/dev/null || echo "none")
    # Fallback to other detection methods
    elif [ -f /proc/1/environ ]; then
        if grep -qa container /proc/1/environ; then
            VIRT_TYPE="container"
        fi
    fi

    # Special case detection
    if [ "$VIRT_TYPE" = "none" ] && [ -e /dev/lxd/sock ]; then
        VIRT_TYPE="lxd"
    fi

    export VIRT_TYPE
    msg_info "Virtualization type: $VIRT_TYPE"
}

#######################################
# Detect Cloud Provider
#######################################

function detect_cloud_provider() {
    CLOUD_PROVIDER="none"

    # AWS EC2
    if [ -f /sys/hypervisor/uuid ] && grep -qi ec2 /sys/hypervisor/uuid 2>/dev/null; then
        CLOUD_PROVIDER="aws"
    elif [ -f /sys/class/dmi/id/product_uuid ] && grep -qi ec2 /sys/class/dmi/id/product_uuid 2>/dev/null; then
        CLOUD_PROVIDER="aws"
    elif [ -f /sys/class/dmi/id/bios_vendor ] && grep -qi amazon /sys/class/dmi/id/bios_vendor 2>/dev/null; then
        CLOUD_PROVIDER="aws"
    # Check IMDSv2 endpoint (most reliable for EC2)
    elif curl -s -m 1 http://169.254.169.254/latest/meta-data/instance-id &>/dev/null; then
        CLOUD_PROVIDER="aws"

    # Google Cloud Platform
    elif curl -s -H "Metadata-Flavor: Google" -m 1 http://metadata.google.internal/computeMetadata/v1/instance/id &>/dev/null; then
        CLOUD_PROVIDER="gcp"

    # Microsoft Azure
    elif curl -s -H "Metadata:true" -m 1 "http://169.254.169.254/metadata/instance?api-version=2021-02-01" &>/dev/null; then
        CLOUD_PROVIDER="azure"

    # DigitalOcean
    elif curl -s -m 1 http://169.254.169.254/metadata/v1/id &>/dev/null; then
        CLOUD_PROVIDER="digitalocean"

    # Oracle Cloud
    elif [ -f /sys/class/dmi/id/chassis_asset_tag ] && grep -qi oraclecloud /sys/class/dmi/id/chassis_asset_tag 2>/dev/null; then
        CLOUD_PROVIDER="oracle"

    # Hetzner Cloud
    elif [ -f /sys/class/dmi/id/sys_vendor ] && grep -qi hetzner /sys/class/dmi/id/sys_vendor 2>/dev/null; then
        CLOUD_PROVIDER="hetzner"
    fi

    export CLOUD_PROVIDER
    if [ "$CLOUD_PROVIDER" != "none" ]; then
        msg_info "Cloud provider: $CLOUD_PROVIDER"
    fi
}

#######################################
# Detect Platform Type
#######################################

function detect_platform() {
    # Detect virtualization first
    detect_virtualization

    # Detect cloud provider
    detect_cloud_provider

    # Determine platform type
    if [ "$CLOUD_PROVIDER" != "none" ]; then
        PLATFORM="$CLOUD_PROVIDER"
    elif [ "$VIRT_TYPE" = "lxc" ]; then
        PLATFORM="lxc"
    elif [ "$VIRT_TYPE" = "kvm" ]; then
        PLATFORM="kvm"
    elif [ "$VIRT_TYPE" = "docker" ]; then
        PLATFORM="docker"
    elif [ "$VIRT_TYPE" = "vmware" ]; then
        PLATFORM="vmware"
    elif [ "$VIRT_TYPE" = "xen" ]; then
        PLATFORM="xen"
    elif [ "$VIRT_TYPE" = "none" ]; then
        PLATFORM="baremetal"
    else
        PLATFORM="$VIRT_TYPE"
    fi

    export PLATFORM
    msg_ok "Platform detected: $PLATFORM"
}

#######################################
# Detect Operating System
#######################################

function detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_VERSION="$VERSION_ID"
        OS_NAME="$NAME"
        OS_PRETTY_NAME="$PRETTY_NAME"
    elif [ -f /etc/redhat-release ]; then
        OS_NAME=$(cat /etc/redhat-release)
        OS_ID="rhel"
    elif [ -f /etc/debian_version ]; then
        OS_NAME="Debian"
        OS_ID="debian"
        OS_VERSION=$(cat /etc/debian_version)
    else
        OS_NAME="Unknown"
        OS_ID="unknown"
        OS_VERSION="unknown"
    fi

    export OS_ID OS_VERSION OS_NAME OS_PRETTY_NAME
    msg_info "Operating System: $OS_PRETTY_NAME"
}

#######################################
# Check OS Compatibility
#######################################

function check_os_compatibility() {
    local supported=0

    case "$OS_ID" in
        ubuntu)
            # Ubuntu 20.04 and newer
            if [ "${OS_VERSION%%.*}" -ge 20 ]; then
                supported=1
            fi
            ;;
        debian)
            # Debian 11 and newer
            if [ "${OS_VERSION%%.*}" -ge 11 ]; then
                supported=1
            fi
            ;;
        rhel|centos|rocky|almalinux)
            # RHEL 8 and newer
            if [ "${OS_VERSION%%.*}" -ge 8 ]; then
                supported=1
            fi
            ;;
        fedora)
            # Fedora 35 and newer
            if [ "${OS_VERSION%%.*}" -ge 35 ]; then
                supported=1
            fi
            ;;
        *)
            msg_warn "Unsupported or untested OS: $OS_NAME"
            ;;
    esac

    if [ $supported -eq 0 ]; then
        msg_warn "This OS version may not be fully supported"
        msg_warn "Supported: Ubuntu 20.04+, Debian 11+, RHEL/Rocky/Alma 8+, Fedora 35+"

        if ! confirm_action "Continue with unsupported OS?" "N"; then
            msg_error "Installation cancelled"
            exit 1
        fi
    else
        msg_ok "OS version supported"
    fi
}

#######################################
# Detect System Resources
#######################################

function detect_system_resources() {
    # Memory (in MB)
    TOTAL_MEM=$(free -m | awk '/^Mem:/{print $2}')

    # Disk space (in GB)
    AVAIL_DISK=$(df -BG /opt 2>/dev/null | tail -1 | awk '{print $4}' | sed 's/G//' || echo "0")
    if [ "$AVAIL_DISK" = "0" ]; then
        AVAIL_DISK=$(df -BG / 2>/dev/null | tail -1 | awk '{print $4}' | sed 's/G//' || echo "0")
    fi

    # CPU cores
    CPU_CORES=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo "1")

    export TOTAL_MEM AVAIL_DISK CPU_CORES

    msg_info "System resources:"
    msg_info "  Memory: ${TOTAL_MEM}MB"
    msg_info "  Available disk: ${AVAIL_DISK}GB"
    msg_info "  CPU cores: $CPU_CORES"
}

#######################################
# Platform-Specific Checks
#######################################

function check_lxc_features() {
    if [ "$PLATFORM" = "lxc" ]; then
        msg_info "Checking LXC container features..."

        # Check for Docker support (nesting)
        if [ -f /proc/self/status ]; then
            if grep -q "^CapBnd:.*[^0]" /proc/self/status; then
                msg_ok "Container has sufficient capabilities"
            else
                msg_warn "Container may have limited capabilities"
                msg_warn "For Docker support, enable: features: nesting=1"
            fi
        fi

        # Check if /dev/net/tun exists for Tailscale
        if [ -c /dev/net/tun ]; then
            msg_ok "TUN device available for Tailscale"
        else
            msg_warn "/dev/net/tun not available"
            msg_warn "For Tailscale, add to LXC config: lxc.cgroup2.devices.allow: c 10:200 rwm"
        fi
    fi
}

function check_cloud_specific() {
    case "$CLOUD_PROVIDER" in
        aws)
            msg_info "Detected AWS EC2 instance"
            # Check IMDSv2
            if curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" &>/dev/null; then
                msg_ok "IMDSv2 is enabled"
            else
                msg_warn "IMDSv2 may not be enabled"
            fi
            ;;
        gcp)
            msg_info "Detected Google Cloud Platform instance"
            ;;
        azure)
            msg_info "Detected Microsoft Azure instance"
            ;;
        digitalocean)
            msg_info "Detected DigitalOcean Droplet"
            ;;
    esac
}

#######################################
# Detect ProxMox Host Environment
#######################################

function is_proxmox_host() {
    # Check if this is a ProxMox VE host
    if [ -f /etc/pve/.version ] || command -v pveversion &>/dev/null; then
        return 0
    fi
    return 1
}

function detect_proxmox_container_id() {
    if [ "$PLATFORM" = "lxc" ] && [ -f /proc/1/cgroup ]; then
        # Extract container ID from cgroup
        CONTAINER_ID=$(grep -oP 'lxc/\K\d+' /proc/1/cgroup | head -1)
        if [ -n "$CONTAINER_ID" ]; then
            export CONTAINER_ID
            msg_info "ProxMox LXC container ID: $CONTAINER_ID"
        fi
    fi
}

#######################################
# Get Network Information
#######################################

function detect_network_info() {
    # Get primary IP address
    PRIMARY_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "unknown")

    # Get hostname
    HOSTNAME=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "unknown")

    export PRIMARY_IP HOSTNAME

    msg_info "Network information:"
    msg_info "  Hostname: $HOSTNAME"
    msg_info "  Primary IP: $PRIMARY_IP"
}

#######################################
# Detect Tailscale
#######################################

function detect_tailscale() {
    TAILSCALE_INSTALLED=false
    TAILSCALE_RUNNING=false
    TAILSCALE_HOSTNAME=""

    if command -v tailscale &>/dev/null; then
        TAILSCALE_INSTALLED=true
        msg_ok "Tailscale is installed"

        if tailscale status &>/dev/null 2>&1; then
            TAILSCALE_RUNNING=true
            msg_ok "Tailscale is running"

            # Get Tailscale hostname
            TAILSCALE_HOSTNAME=$(tailscale status --json 2>/dev/null | grep -oP '"DNSName":"\K[^"]+' | head -1 | sed 's/\.$//' || echo "")
            if [ -n "$TAILSCALE_HOSTNAME" ]; then
                msg_info "Tailscale hostname: $TAILSCALE_HOSTNAME"
            fi
        else
            msg_warn "Tailscale is installed but not running"
        fi
    else
        msg_info "Tailscale not installed"
    fi

    export TAILSCALE_INSTALLED TAILSCALE_RUNNING TAILSCALE_HOSTNAME
}

#######################################
# Main Detection Function
#######################################

function run_platform_detection() {
    msg_info "Detecting system platform and configuration..."
    print_separator

    detect_os
    check_os_compatibility
    detect_platform
    detect_system_resources
    detect_network_info
    detect_tailscale

    # Platform-specific checks
    check_lxc_features
    check_cloud_specific

    # ProxMox specific
    if [ "$PLATFORM" = "lxc" ]; then
        detect_proxmox_container_id
    fi

    print_separator
    msg_ok "Platform detection complete"

    # Export summary
    export PLATFORM VIRT_TYPE CLOUD_PROVIDER
    export OS_ID OS_VERSION OS_NAME
    export TOTAL_MEM AVAIL_DISK CPU_CORES
    export PRIMARY_IP HOSTNAME
}

# Export functions
export -f detect_virtualization detect_cloud_provider detect_platform
export -f detect_os check_os_compatibility
export -f detect_system_resources
export -f check_lxc_features check_cloud_specific
export -f is_proxmox_host detect_proxmox_container_id
export -f detect_network_info detect_tailscale
export -f run_platform_detection
