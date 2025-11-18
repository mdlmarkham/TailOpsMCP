#!/usr/bin/env bash
# TailOpsMCP Universal Installer Dispatcher
# Automatically detects platform and runs appropriate installer
# Copyright (c) 2024 TailOpsMCP Contributors
# License: MIT

set -euo pipefail

#######################################
# Configuration
#######################################

VERSION="2.0.0"

# Detect script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

#######################################
# Quick Platform Detection
#######################################

function quick_detect_platform() {
    local platform="standalone"

    # Detect virtualization
    local virt="none"
    if command -v systemd-detect-virt &>/dev/null; then
        virt=$(systemd-detect-virt 2>/dev/null || echo "none")
    fi

    # Check for cloud providers
    if [ -f /sys/hypervisor/uuid ] && grep -qi ec2 /sys/hypervisor/uuid 2>/dev/null; then
        platform="ec2"
    elif curl -sf -m 1 http://169.254.169.254/latest/meta-data/instance-id &>/dev/null; then
        platform="ec2"
    elif curl -sf -H "Metadata-Flavor: Google" -m 1 http://metadata.google.internal/computeMetadata/v1/instance/id &>/dev/null; then
        platform="ec2"  # Use same installer for all clouds
    elif curl -sf -H "Metadata:true" -m 1 "http://169.254.169.254/metadata/instance?api-version=2021-02-01" &>/dev/null; then
        platform="ec2"  # Use same installer for all clouds
    elif [ "$virt" = "lxc" ]; then
        platform="proxmox"
    fi

    echo "$platform"
}

#######################################
# Display Help
#######################################

function show_help() {
    cat << EOF
TailOpsMCP Universal Installer v${VERSION}

Automatically detects your environment and runs the optimized installer.

USAGE:
    sudo bash $0 [OPTIONS]

OPTIONS:
    --help              Show this help message
    --platform TYPE     Force specific platform installer
                        (standalone, proxmox, ec2)
    --version           Show version information
    --check             Check system and show what would be installed

    All other options are passed to the platform-specific installer.
    See platform installer help for details:
      • Standalone: --help
      • ProxMox:    scripts/install/install-proxmox.sh --help
      • EC2/Cloud:  scripts/install/install-ec2.sh --help

EXAMPLES:
    # Automatic detection and installation
    sudo bash $0

    # Force ProxMox installer
    sudo bash $0 --platform proxmox

    # Non-interactive installation with token auth
    sudo SYSTEMMANAGER_AUTH_MODE=token NON_INTERACTIVE=true bash $0

    # Check what would be installed
    sudo bash $0 --check

ENVIRONMENT VARIABLES:
    SYSTEMMANAGER_INSTALL_DIR       Installation directory
    SYSTEMMANAGER_PORT              Service port (default: 8080)
    SYSTEMMANAGER_AUTH_MODE         Auth mode (oidc/token/none)
    SYSTEMMANAGER_SHARED_SECRET     Token for token-based auth
    NON_INTERACTIVE                 Set to 'true' for non-interactive mode
    SKIP_DOCKER                     Set to 'true' to skip Docker
    FORCE_REINSTALL                 Set to 'true' to force reinstall

DOCUMENTATION:
    https://github.com/mdlmarkham/TailOpsMCP

EOF
}

function show_version() {
    echo "TailOpsMCP Universal Installer v${VERSION}"
    echo "Copyright (c) 2024 TailOpsMCP Contributors"
    echo "License: MIT"
}

#######################################
# System Check
#######################################

function check_system() {
    echo "========================================"
    echo " TailOpsMCP Installation Check"
    echo "========================================"
    echo ""

    # Detect platform
    local platform=$(quick_detect_platform)
    echo "Detected Platform: $platform"

    # Check OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "Operating System: $PRETTY_NAME"
    fi

    # Check virtualization
    if command -v systemd-detect-virt &>/dev/null; then
        local virt=$(systemd-detect-virt 2>/dev/null || echo "none")
        echo "Virtualization: $virt"
    fi

    # Check resources
    echo ""
    echo "System Resources:"
    echo "  • Memory: $(free -h | awk '/^Mem:/{print $2}')"
    echo "  • Disk: $(df -h / | awk 'NR==2{print $4}') available"
    echo "  • CPU Cores: $(nproc 2>/dev/null || echo "unknown")"

    # Check network
    echo ""
    echo "Network:"
    echo "  • Hostname: $(hostname -f 2>/dev/null || hostname)"
    echo "  • IP: $(hostname -I 2>/dev/null | awk '{print $1}')"

    # Check Tailscale
    echo ""
    if command -v tailscale &>/dev/null; then
        echo "Tailscale: Installed"
        if tailscale status &>/dev/null 2>&1; then
            echo "  Status: Running"
            local ts_hostname=$(tailscale status --json 2>/dev/null | grep -oP '"DNSName":"\K[^"]+' | head -1 | sed 's/\.$//' || echo "")
            if [ -n "$ts_hostname" ]; then
                echo "  Hostname: $ts_hostname"
            fi
        else
            echo "  Status: Not running"
        fi
    else
        echo "Tailscale: Not installed"
    fi

    # Check Docker
    echo ""
    if command -v docker &>/dev/null; then
        echo "Docker: Installed ($(docker --version 2>&1 | head -1))"
    else
        echo "Docker: Not installed (will be installed)"
    fi

    # Check Python
    echo ""
    for py_cmd in python3.12 python3.11 python3; do
        if command -v "$py_cmd" &>/dev/null; then
            echo "Python: $($py_cmd --version 2>&1)"
            break
        fi
    done

    echo ""
    echo "========================================"
    echo "Installer to use: install-${platform}.sh"
    echo "========================================"
    echo ""
}

#######################################
# Main Dispatcher
#######################################

function main() {
    local force_platform=""
    local check_only=false
    local installer_args=()

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_help
                exit 0
                ;;
            --version|-v)
                show_version
                exit 0
                ;;
            --check)
                check_only=true
                shift
                ;;
            --platform)
                force_platform="$2"
                shift 2
                ;;
            *)
                # Pass through to installer
                installer_args+=("$1")
                shift
                ;;
        esac
    done

    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        echo "ERROR: This script must be run as root"
        echo "Please run: sudo $0"
        exit 1
    fi

    # If check only, show system info and exit
    if [ "$check_only" = "true" ]; then
        check_system
        exit 0
    fi

    # Detect platform
    local platform="$force_platform"
    if [ -z "$platform" ]; then
        platform=$(quick_detect_platform)
        echo "Auto-detected platform: $platform"
    else
        echo "Using forced platform: $platform"
    fi

    # Validate platform
    case "$platform" in
        standalone|proxmox|ec2)
            ;;
        *)
            echo "ERROR: Invalid platform: $platform"
            echo "Valid platforms: standalone, proxmox, ec2"
            exit 1
            ;;
    esac

    # Select installer
    local installer="$SCRIPT_DIR/install-${platform}.sh"

    if [ ! -f "$installer" ]; then
        echo "ERROR: Installer not found: $installer"
        exit 1
    fi

    if [ ! -x "$installer" ]; then
        chmod +x "$installer"
    fi

    # Run installer
    echo "Running installer: $installer"
    echo ""

    exec bash "$installer" "${installer_args[@]}"
}

# Run main function
main "$@"
