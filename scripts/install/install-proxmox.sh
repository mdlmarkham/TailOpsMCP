#!/usr/bin/env bash
# TailOpsMCP ProxMox LXC Installer
# Optimized for ProxMox LXC containers
# Copyright (c) 2024 TailOpsMCP Contributors
# License: MIT

set -euo pipefail

#######################################
# ProxMox LXC Optimizations
#######################################

function apply_proxmox_optimizations() {
    if [ "$PLATFORM" != "lxc" ]; then
        msg_info "Not running in LXC, skipping ProxMox optimizations"
        return 0
    fi

    msg_info "Applying ProxMox LXC optimizations"

    # Check if running in privileged mode
    if [ -w /sys/fs/cgroup ]; then
        msg_ok "Running in privileged LXC mode"
    else
        msg_warn "Running in unprivileged LXC mode"
        msg_info "Some features may have limited functionality"
    fi

    # Optimize for container environment
    if [ -f /etc/systemd/journald.conf ]; then
        # Reduce journal disk usage in containers
        if ! grep -q "^SystemMaxUse=50M" /etc/systemd/journald.conf; then
            cat >> /etc/systemd/journald.conf << EOF

# TailOpsMCP optimizations for LXC
SystemMaxUse=50M
MaxRetentionSec=1week
EOF
            systemctl restart systemd-journald || true
            msg_ok "Optimized journald for container"
        fi
    fi

    msg_ok "ProxMox optimizations applied"
}

function check_proxmox_features() {
    if [ "$PLATFORM" != "lxc" ]; then
        return 0
    fi

    msg_info "Checking ProxMox LXC features"

    # Check for nesting (required for Docker)
    if [ "$SKIP_DOCKER" != "true" ]; then
        if [ ! -d /sys/fs/cgroup/systemd ]; then
            msg_warn "Container nesting not detected"
            msg_warn "Docker may not work properly"
            echo ""
            msg_info "To enable Docker in LXC, add to container config:"
            msg_info "  features: nesting=1,keyctl=1"
            msg_info "  lxc.apparmor.profile: unconfined"
            echo ""

            if [ "$NON_INTERACTIVE" != "true" ]; then
                if ! confirm_action "Continue without Docker support?" "y"; then
                    exit 1
                fi
                SKIP_DOCKER=true
                export SKIP_DOCKER
            fi
        else
            msg_ok "Container nesting enabled"
        fi
    fi

    # Check for TUN device (required for Tailscale)
    if [ ! -c /dev/net/tun ]; then
        msg_warn "/dev/net/tun not available"
        msg_warn "Tailscale may not work properly"
        echo ""
        msg_info "To enable Tailscale in LXC, add to container config:"
        msg_info "  lxc.cgroup2.devices.allow: c 10:200 rwm"
        msg_info "  lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file"
        echo ""

        if [ "$NON_INTERACTIVE" != "true" ]; then
            if ! confirm_action "Continue without Tailscale support?" "y"; then
                exit 1
            fi
        fi
    else
        msg_ok "TUN device available"
    fi
}

function setup_proxmox_networking() {
    if [ "$PLATFORM" != "lxc" ]; then
        return 0
    fi

    msg_info "Configuring networking for LXC"

    # Ensure DNS resolution works
    if [ ! -f /etc/resolv.conf ] || [ ! -s /etc/resolv.conf ]; then
        msg_warn "DNS configuration missing or empty"
        echo "nameserver 1.1.1.1" > /etc/resolv.conf
        echo "nameserver 8.8.8.8" >> /etc/resolv.conf
        msg_ok "DNS configuration fixed"
    fi

    msg_ok "Networking configured"
}

function create_proxmox_motd() {
    if [ "$PLATFORM" != "lxc" ]; then
        return 0
    fi

    msg_info "Creating ProxMox MOTD"

    # Create custom MOTD
    cat > /etc/update-motd.d/99-systemmanager << 'EOF'
#!/bin/bash
echo ""
echo "  ╭────────────────────────────────────────────────╮"
echo "  │     TailOpsMCP - ProxMox LXC Container         │"
echo "  ╰────────────────────────────────────────────────╯"
echo ""
echo "  Service: systemctl status systemmanager-mcp"
echo "  Logs:    journalctl -u systemmanager-mcp -f"
echo ""
EOF

    chmod +x /etc/update-motd.d/99-systemmanager

    msg_ok "MOTD created"
}

function display_proxmox_notes() {
    if [ "$PLATFORM" != "lxc" ]; then
        return 0
    fi

    print_separator
    echo -e "${BLUE}ProxMox LXC Notes:${NC}"
    echo ""

    if [ -n "$CONTAINER_ID" ]; then
        echo "  • Container ID: $CONTAINER_ID"
        echo ""
        echo "  Update container from host:"
        echo "    pct exec $CONTAINER_ID -- bash -c 'cd /opt/systemmanager && git pull'"
        echo ""
    fi

    echo "  Recommended container configuration:"
    echo "    cores: 2"
    echo "    memory: 2048"
    echo "    features: nesting=1,keyctl=1"
    echo "    lxc.apparmor.profile: unconfined"
    echo "    lxc.cgroup2.devices.allow: c 10:200 rwm  # For Tailscale"
    echo ""
    print_separator
}

#######################################
# Main ProxMox Installation
#######################################

# Detect script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the standalone installer
if [ -f "$SCRIPT_DIR/install-standalone.sh" ]; then
    # Just source functions, don't run main
    source "$SCRIPT_DIR/install-standalone.sh" --help >/dev/null 2>&1 || true

    # Load libraries manually
    load_libraries

    # Run ProxMox-specific installation
    print_banner
    init_state
    setup_error_handling

    # Load config if provided
    load_config_file

    # Platform detection
    run_platform_detection

    # ProxMox-specific checks
    check_proxmox_features

    # Run pre-flight checks
    run_preflight_checks || exit 1

    # Check for upgrade mode
    if [ "$UPGRADE_MODE" = "true" ]; then
        perform_upgrade
        display_installation_summary "$SYSTEMMANAGER_PORT"
        display_proxmox_notes
        cleanup_state
        exit 0
    fi

    # Fresh installation
    print_separator
    msg_info "Starting TailOpsMCP installation (ProxMox LXC)"
    print_separator

    # Install dependencies
    install_dependencies

    # Setup installation
    setup_installation_directory
    setup_python_environment
    setup_service_user

    # ProxMox optimizations
    apply_proxmox_optimizations
    setup_proxmox_networking

    # Configure authentication
    configure_authentication || exit 1

    # Setup and start service
    setup_systemd_service
    start_systemmanager_service

    # Create MOTD
    create_proxmox_motd

    # Validate installation
    print_separator
    if run_post_install_validation; then
        # Display success summary
        display_installation_summary "$SYSTEMMANAGER_PORT"
        display_proxmox_notes

        cleanup_state
        exit 0
    else
        msg_error "Installation validation failed"
        msg_info "Check logs: journalctl -u systemmanager-mcp -n 100"
        exit 1
    fi
else
    echo "ERROR: install-standalone.sh not found in $SCRIPT_DIR"
    exit 1
fi
