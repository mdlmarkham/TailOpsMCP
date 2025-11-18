#!/usr/bin/env bash
# Pre-flight checks for TailOpsMCP installation
# Copyright (c) 2024 TailOpsMCP Contributors
# License: MIT

#######################################
# Resource Requirements
#######################################

# Minimum requirements
MIN_MEMORY_MB=1024
MIN_DISK_GB=5
MIN_CPU_CORES=1

# Recommended requirements
REC_MEMORY_MB=2048
REC_DISK_GB=10
REC_CPU_CORES=2

#######################################
# Check System Resources
#######################################

function check_memory() {
    local errors=0

    if [ "$TOTAL_MEM" -lt "$MIN_MEMORY_MB" ]; then
        msg_error "Insufficient memory: ${TOTAL_MEM}MB (minimum: ${MIN_MEMORY_MB}MB)"
        ((errors++))
    elif [ "$TOTAL_MEM" -lt "$REC_MEMORY_MB" ]; then
        msg_warn "Low memory: ${TOTAL_MEM}MB (recommended: ${REC_MEMORY_MB}MB)"
    else
        msg_ok "Memory check passed: ${TOTAL_MEM}MB"
    fi

    return $errors
}

function check_disk_space() {
    local errors=0

    if [ "$AVAIL_DISK" -lt "$MIN_DISK_GB" ]; then
        msg_error "Insufficient disk space: ${AVAIL_DISK}GB (minimum: ${MIN_DISK_GB}GB)"
        ((errors++))
    elif [ "$AVAIL_DISK" -lt "$REC_DISK_GB" ]; then
        msg_warn "Low disk space: ${AVAIL_DISK}GB (recommended: ${REC_DISK_GB}GB)"
    else
        msg_ok "Disk space check passed: ${AVAIL_DISK}GB available"
    fi

    return $errors
}

function check_cpu_cores() {
    if [ "$CPU_CORES" -lt "$MIN_CPU_CORES" ]; then
        msg_warn "Low CPU cores: $CPU_CORES (minimum: $MIN_CPU_CORES)"
    elif [ "$CPU_CORES" -lt "$REC_CPU_CORES" ]; then
        msg_info "CPU cores: $CPU_CORES (recommended: $REC_CPU_CORES)"
    else
        msg_ok "CPU cores check passed: $CPU_CORES"
    fi

    return 0
}

#######################################
# Check Network Connectivity
#######################################

function check_internet_connectivity() {
    local errors=0
    local test_hosts=(
        "github.com"
        "raw.githubusercontent.com"
        "pypi.org"
    )

    msg_info "Checking internet connectivity..."

    for host in "${test_hosts[@]}"; do
        if ping -c 1 -W 2 "$host" &>/dev/null; then
            msg_ok "Can reach $host"
        else
            msg_error "Cannot reach $host"
            ((errors++))
        fi
    done

    if [ $errors -eq ${#test_hosts[@]} ]; then
        msg_error "No internet connectivity detected"
        msg_error "Installation requires internet access"
        return 1
    elif [ $errors -gt 0 ]; then
        msg_warn "Partial connectivity issues detected ($errors/${#test_hosts[@]} hosts unreachable)"
        return 0
    else
        msg_ok "Internet connectivity check passed"
        return 0
    fi
}

function check_dns_resolution() {
    local errors=0

    msg_info "Checking DNS resolution..."

    if command -v nslookup &>/dev/null; then
        if nslookup github.com &>/dev/null; then
            msg_ok "DNS resolution working"
        else
            msg_error "DNS resolution failed"
            ((errors++))
        fi
    elif command -v dig &>/dev/null; then
        if dig github.com +short &>/dev/null; then
            msg_ok "DNS resolution working"
        else
            msg_error "DNS resolution failed"
            ((errors++))
        fi
    else
        msg_warn "Cannot verify DNS (nslookup/dig not found)"
    fi

    return $errors
}

#######################################
# Check Port Availability
#######################################

function check_port_availability() {
    local port="${1:-$SYSTEMMANAGER_PORT}"
    port="${port:-8080}"

    msg_info "Checking if port $port is available..."

    if check_port_available "$port"; then
        msg_ok "Port $port is available"
        return 0
    else
        msg_error "Port $port is already in use"

        # Try to identify what's using the port
        if command -v lsof &>/dev/null; then
            local process_info=$(lsof -ti ":$port" 2>/dev/null)
            if [ -n "$process_info" ]; then
                msg_info "Process using port $port:"
                lsof -i ":$port" | grep -v COMMAND | head -3 | while read line; do
                    msg_info "  $line"
                done
            fi
        fi

        if [ "$NON_INTERACTIVE" = "true" ]; then
            msg_error "Cannot proceed with port $port in use"
            return 1
        fi

        if confirm_action "Use a different port?" "y"; then
            read -p "Enter port number: " SYSTEMMANAGER_PORT
            export SYSTEMMANAGER_PORT
            # Recursive check with new port
            check_port_availability "$SYSTEMMANAGER_PORT"
            return $?
        else
            return 1
        fi
    fi
}

#######################################
# Check Required Commands
#######################################

function check_required_commands() {
    local errors=0
    local required_cmds=(
        "curl"
        "wget"
        "git"
        "systemctl"
    )

    msg_info "Checking required commands..."

    for cmd in "${required_cmds[@]}"; do
        if command -v "$cmd" &>/dev/null; then
            msg_ok "Found: $cmd"
        else
            msg_error "Missing required command: $cmd"
            ((errors++))
        fi
    done

    if [ $errors -gt 0 ]; then
        msg_error "$errors required command(s) missing"
        msg_info "These will be installed during setup"
    fi

    return 0  # Don't fail, we'll install them
}

#######################################
# Check Systemd
#######################################

function check_systemd() {
    msg_info "Checking systemd..."

    if ! command -v systemctl &>/dev/null; then
        msg_error "systemctl not found - systemd is required"
        return 1
    fi

    if ! systemctl --version &>/dev/null; then
        msg_error "systemd is not functioning properly"
        return 1
    fi

    # Check if we can interact with systemd
    if ! systemctl list-units &>/dev/null; then
        msg_error "Cannot interact with systemd"
        return 1
    fi

    msg_ok "systemd is available and working"
    return 0
}

#######################################
# Check Existing Installation
#######################################

function check_existing_installation() {
    if detect_existing_installation; then
        msg_warn "Existing installation found"

        if [ "$FORCE_REINSTALL" = "true" ]; then
            msg_info "FORCE_REINSTALL=true, will upgrade/reinstall"
            return 0
        fi

        if [ "$NON_INTERACTIVE" = "true" ]; then
            msg_error "Existing installation found and NON_INTERACTIVE=true"
            msg_error "Set FORCE_REINSTALL=true to upgrade"
            return 1
        fi

        echo ""
        echo "Options:"
        echo "  1) Upgrade existing installation"
        echo "  2) Reinstall (preserve configuration)"
        echo "  3) Abort"
        echo ""
        read -p "Select [1-3]: " choice

        case $choice in
            1)
                UPGRADE_MODE=true
                export UPGRADE_MODE
                msg_info "Will upgrade existing installation"
                return 0
                ;;
            2)
                REINSTALL_MODE=true
                export REINSTALL_MODE
                msg_info "Will reinstall (configuration preserved)"
                return 0
                ;;
            3|*)
                msg_error "Installation aborted by user"
                return 1
                ;;
        esac
    fi

    return 0
}

#######################################
# Check User Privileges
#######################################

function check_root_privileges() {
    if [ "$EUID" -ne 0 ]; then
        msg_error "This script must be run as root"
        msg_info "Please run: sudo $0"
        return 1
    fi

    msg_ok "Running with root privileges"
    return 0
}

#######################################
# Check for Conflicting Services
#######################################

function check_conflicting_services() {
    local conflicts=0

    msg_info "Checking for conflicting services..."

    # Check if systemmanager-mcp service already exists but is from different installation
    if systemctl list-unit-files | grep -q "systemmanager-mcp.service"; then
        if [ ! -d "$INSTALL_DIR" ]; then
            msg_warn "systemmanager-mcp service exists but installation directory not found"
            msg_warn "May need manual cleanup"
            ((conflicts++))
        fi
    fi

    if [ $conflicts -gt 0 ]; then
        msg_warn "$conflicts potential conflict(s) found"
        if [ "$NON_INTERACTIVE" != "true" ]; then
            if ! confirm_action "Continue anyway?" "y"; then
                return 1
            fi
        fi
    fi

    return 0
}

#######################################
# Security Checks
#######################################

function check_security_requirements() {
    msg_info "Checking security requirements..."

    # Check if SELinux is enforcing (might cause issues)
    if command -v getenforce &>/dev/null; then
        SELINUX_STATUS=$(getenforce 2>/dev/null || echo "Unknown")
        if [ "$SELINUX_STATUS" = "Enforcing" ]; then
            msg_warn "SELinux is enforcing - may require additional configuration"
            msg_info "Consider running: setenforce 0"
        fi
    fi

    # Check if AppArmor is active
    if command -v aa-status &>/dev/null; then
        if aa-status --enabled 2>/dev/null; then
            msg_info "AppArmor is active - service will run in confined mode"
        fi
    fi

    # Check if firewall is active
    if command -v ufw &>/dev/null; then
        if ufw status 2>/dev/null | grep -q "Status: active"; then
            msg_warn "UFW firewall is active"
            msg_info "You may need to allow port ${SYSTEMMANAGER_PORT:-8080}"
            msg_info "Run: ufw allow ${SYSTEMMANAGER_PORT:-8080}/tcp"
        fi
    elif command -v firewall-cmd &>/dev/null; then
        if firewall-cmd --state 2>/dev/null | grep -q "running"; then
            msg_warn "firewalld is active"
            msg_info "You may need to allow port ${SYSTEMMANAGER_PORT:-8080}"
            msg_info "Run: firewall-cmd --permanent --add-port=${SYSTEMMANAGER_PORT:-8080}/tcp && firewall-cmd --reload"
        fi
    fi

    return 0
}

#######################################
# Platform-Specific Checks
#######################################

function check_lxc_requirements() {
    if [ "$PLATFORM" = "lxc" ]; then
        msg_info "Checking LXC-specific requirements..."

        # Check for privileged mode if installing Docker
        if [ "$SKIP_DOCKER" != "true" ]; then
            if [ ! -d /sys/fs/cgroup/systemd ]; then
                msg_warn "Systemd cgroup not detected"
                msg_warn "Docker may not work properly"
                msg_info "Enable nesting in LXC config: features: nesting=1"
            fi
        fi

        # Check TUN device for Tailscale
        if [ ! -c /dev/net/tun ] && [ "$TAILSCALE_INSTALLED" != "true" ]; then
            msg_warn "/dev/net/tun not available"
            msg_info "For Tailscale support, add to LXC config:"
            msg_info "  lxc.cgroup2.devices.allow: c 10:200 rwm"
            msg_info "  lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file"
        fi
    fi
}

function check_cloud_requirements() {
    case "$CLOUD_PROVIDER" in
        aws)
            msg_info "AWS EC2 detected - checking cloud-specific requirements..."
            # Check security groups (can't do from inside, just inform)
            msg_info "Ensure security group allows inbound on port ${SYSTEMMANAGER_PORT:-8080}"
            msg_info "Or use Tailscale for secure access"
            ;;
        gcp|azure|digitalocean)
            msg_info "$CLOUD_PROVIDER detected - ensure firewall rules allow access"
            ;;
    esac
}

#######################################
# Main Preflight Function
#######################################

function run_preflight_checks() {
    local errors=0

    msg_info "Running pre-flight checks..."
    print_separator

    # Critical checks (must pass)
    check_root_privileges || ((errors++))
    check_systemd || ((errors++))

    # Resource checks
    check_memory || ((errors++))
    check_disk_space || ((errors++))
    check_cpu_cores

    # Network checks
    check_internet_connectivity || ((errors++))
    check_dns_resolution

    # Port check
    check_port_availability || ((errors++))

    # Installation checks
    check_existing_installation || ((errors++))
    check_conflicting_services || ((errors++))

    # Security checks
    check_security_requirements

    # Platform-specific checks
    check_lxc_requirements
    check_cloud_requirements

    # Command checks (informational)
    check_required_commands

    print_separator

    if [ $errors -gt 0 ]; then
        msg_error "$errors critical pre-flight check(s) failed"
        msg_error "Cannot proceed with installation"
        return 1
    else
        msg_ok "All pre-flight checks passed"
        return 0
    fi
}

#######################################
# Quick Preflight (for upgrades)
#######################################

function run_quick_preflight() {
    local errors=0

    msg_info "Running quick pre-flight checks..."

    check_root_privileges || ((errors++))
    check_internet_connectivity || ((errors++))
    check_disk_space || ((errors++))

    if [ $errors -gt 0 ]; then
        msg_error "$errors check(s) failed"
        return 1
    else
        msg_ok "Quick pre-flight checks passed"
        return 0
    fi
}

# Export functions
export -f check_memory check_disk_space check_cpu_cores
export -f check_internet_connectivity check_dns_resolution
export -f check_port_availability check_required_commands
export -f check_systemd check_existing_installation
export -f check_root_privileges check_conflicting_services
export -f check_security_requirements
export -f check_lxc_requirements check_cloud_requirements
export -f run_preflight_checks run_quick_preflight
