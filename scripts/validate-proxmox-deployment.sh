#!/usr/bin/env bash

# TailOpsMCP Deployment Validation Script
# Usage: bash scripts/validate-proxmox-deployment.sh [container_id]
# Validates TailOpsMCP gateway deployment and configuration

set -euo pipefail

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

# Default values
CONTAINER_ID="${1:-}"
VERBOSE="${VERBOSE:-false}"

# Validation functions
validate_environment() {
    log_info "Validating deployment environment..."

    # Check if running on Proxmox
    if ! command -v pct &>/dev/null; then
        error_exit "Not running on Proxmox host. Command 'pct' not found."
    fi

    # Check root access
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root on the Proxmox host."
    fi

    log_success "Environment validation passed"
}

find_tailops_container() {
    if [[ -z "$CONTAINER_ID" ]]; then
        log_info "No container ID specified, searching for TailOpsMCP containers..."

        # Find container by hostname pattern
        local containers=$(pct list | awk 'NR>1 {print $1}')
        for ctid in $containers; do
            local hostname=$(pct exec "$ctid" -- hostname 2>/dev/null || echo "")
            if [[ "$hostname" == tailops-gateway-* ]]; then
                CONTAINER_ID="$ctid"
                log_info "Found TailOpsMCP container: $CONTAINER_ID (hostname: $hostname)"
                return 0
            fi
        done

        error_exit "No TailOpsMCP container found. Please specify container ID as argument."
    fi

    # Validate container exists
    if ! pct status "$CONTAINER_ID" &>/dev/null; then
        error_exit "Container $CONTAINER_ID does not exist."
    fi

    log_success "Container validation passed for ID: $CONTAINER_ID"
}

validate_container_config() {
    log_info "Validating container configuration..."

    # Check if container is running
    if ! pct status "$CONTAINER_ID" | grep -q "running"; then
        error_exit "Container $CONTAINER_ID is not running."
    fi

    # Check container features
    local config=$(pct config "$CONTAINER_ID")

    # Check for required features
    if ! echo "$config" | grep -q "features:.*nesting=1"; then
        log_warning "Nesting feature not enabled - Docker may not work properly"
    fi

    if ! echo "$config" | grep -q "cgroup2.devices.allow.*10:200"; then
        log_warning "TUN device access not configured - Tailscale may not work properly"
    fi

    log_success "Container configuration validation completed"
}

validate_tailopsmcp_installation() {
    log_info "Validating TailOpsMCP installation..."

    # Check installation directory
    if ! pct exec "$CONTAINER_ID" -- test -d /opt/tailopsmcp; then
        error_exit "TailOpsMCP not installed at /opt/tailopsmcp"
    fi

    # Check Python environment
    if ! pct exec "$CONTAINER_ID" -- test -f /opt/tailopsmcp/venv/bin/python; then
        error_exit "Python virtual environment not found"
    fi

    # Check requirements file
    if ! pct exec "$CONTAINER_ID" -- test -f /opt/tailopsmcp/requirements.txt; then
        error_exit "requirements.txt not found"
    fi

    log_success "TailOpsMCP installation validation passed"
}

validate_service_status() {
    log_info "Validating service status..."

    # Check service exists
    if ! pct exec "$CONTAINER_ID" -- systemctl list-unit-files | grep -q "tailopsmcp-mcp.service"; then
        error_exit "tailopsmcp-mcp.service not found"
    fi

    # Check service status
    local status=$(pct exec "$CONTAINER_ID" -- systemctl is-active tailopsmcp-mcp 2>/dev/null || echo "inactive")
    if [[ "$status" != "active" ]]; then
        log_warning "Service tailopsmcp-mcp is not active (status: $status)"

        # Show service logs
        log_info "Service logs:"
        pct exec "$CONTAINER_ID" -- journalctl -u tailopsmcp-mcp -n 20 --no-pager || true
    else
        log_success "Service tailopsmcp-mcp is active"
    fi
}

validate_network_connectivity() {
    log_info "Validating network connectivity..."

    # Get container IP
    local ip=$(pct exec "$CONTAINER_ID" -- hostname -I | awk '{print $1}')
    log_info "Container IP: $ip"

    # Check if port 8080 is listening
    if pct exec "$CONTAINER_ID" -- netstat -tulpn | grep -q ":8080"; then
        log_success "Port 8080 is listening"
    else
        log_warning "Port 8080 is not listening"
    fi

    # Test local connectivity
    if pct exec "$CONTAINER_ID" -- curl -sf http://localhost:8080 >/dev/null 2>&1; then
        log_success "Local HTTP connectivity working"
    else
        log_warning "Local HTTP connectivity failed"
    fi
}

validate_configuration() {
    log_info "Validating configuration..."

    # Check targets.yaml
    if pct exec "$CONTAINER_ID" -- test -f /opt/tailopsmcp/targets.yaml; then
        log_success "targets.yaml configuration file found"

        # Validate YAML syntax (basic check)
        if pct exec "$CONTAINER_ID" -- python -c "import yaml; yaml.safe_load(open('/opt/tailopsmcp/targets.yaml'))" 2>/dev/null; then
            log_success "targets.yaml syntax is valid"
        else
            log_warning "targets.yaml has syntax issues"
        fi
    else
        log_warning "targets.yaml configuration file not found"
    fi

    # Check .env file
    if pct exec "$CONTAINER_ID" -- test -f /opt/tailopsmcp/.env; then
        log_success ".env configuration file found"
    else
        log_warning ".env configuration file not found"
    fi
}

validate_resource_usage() {
    log_info "Validating resource usage..."

    # Check memory usage
    local memory=$(pct exec "$CONTAINER_ID" -- free -m | awk 'NR==2{print $3}')
    local memory_total=$(pct exec "$CONTAINER_ID" -- free -m | awk 'NR==2{print $2}')
    local memory_percent=$((memory * 100 / memory_total))

    log_info "Memory usage: ${memory}MB / ${memory_total}MB (${memory_percent}%)"

    if [[ $memory_percent -gt 90 ]]; then
        log_warning "High memory usage detected"
    fi

    # Check disk usage
    local disk_usage=$(pct exec "$CONTAINER_ID" -- df -h / | awk 'NR==2{print $5}' | sed 's/%//')
    log_info "Disk usage: ${disk_usage}%"

    if [[ $disk_usage -gt 90 ]]; then
        log_warning "High disk usage detected"
    fi
}

run_comprehensive_test() {
    log_info "Running comprehensive TailOpsMCP functionality test..."

    # Test MCP server startup (basic check)
    if pct exec "$CONTAINER_ID" -- timeout 10 /opt/tailopsmcp/venv/bin/python -c "
import sys
sys.path.insert(0, '/opt/tailopsmcp')
try:
    from src.mcp_server import main
    print('MCP server module loads successfully')
except Exception as e:
    print(f'MCP server module load failed: {e}')
    sys.exit(1)
" 2>/dev/null; then
        log_success "MCP server module loads successfully"
    else
        log_warning "MCP server module load failed or timed out"
    fi
}

generate_report() {
    echo
    echo "═══════════════════════════════════════════════════════════════"
    echo "              TailOpsMCP Deployment Validation Report"
    echo "═══════════════════════════════════════════════════════════════"
    echo
    echo "Container ID: $CONTAINER_ID"
    echo "Hostname: $(pct exec "$CONTAINER_ID" -- hostname 2>/dev/null || echo 'N/A')"
    echo "IP Address: $(pct exec "$CONTAINER_ID" -- hostname -I | awk '{print $1}' 2>/dev/null || echo 'N/A')"
    echo "Status: $(pct status "$CONTAINER_ID" | awk '{print $2}' 2>/dev/null || echo 'N/A')"
    echo "Service Status: $(pct exec "$CONTAINER_ID" -- systemctl is-active tailopsmcp-mcp 2>/dev/null || echo 'N/A')"
    echo
    echo "Validation completed at: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
}

# Main execution
main() {
    echo "TailOpsMCP Deployment Validation Script"
    echo "========================================"
    echo

    validate_environment
    find_tailops_container
    validate_container_config
    validate_tailopsmcp_installation
    validate_service_status
    validate_network_connectivity
    validate_configuration
    validate_resource_usage
    run_comprehensive_test
    generate_report

    log_success "Validation completed successfully!"
}

# Show usage if called with --help
if [[ "${1:-}" == "--help" ]]; then
    cat << EOF
TailOpsMCP Deployment Validation Script

Usage: bash scripts/validate-proxmox-deployment.sh [container_id]

Arguments:
  container_id    Specific container ID to validate (optional)

Environment Variables:
  VERBOSE         Set to 'true' for verbose output

Examples:
  # Validate first found TailOpsMCP container
  bash scripts/validate-proxmox-deployment.sh

  # Validate specific container
  bash scripts/validate-proxmox-deployment.sh 101

  # Validate with verbose output
  VERBOSE=true bash scripts/validate-proxmox-deployment.sh 101

This script validates:
- Proxmox environment
- Container configuration
- TailOpsMCP installation
- Service status
- Network connectivity
- Configuration files
- Resource usage
- Basic functionality

Exit codes:
  0 - Validation passed
  1 - Validation failed
EOF
    exit 0
fi

# Check for immediate failure conditions
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
