#!/usr/bin/env bash
# Post-installation validation for TailOpsMCP
# Copyright (c) 2024 TailOpsMCP Contributors
# License: MIT

#######################################
# Service Validation
#######################################

function validate_service_status() {
    msg_info "Validating service status..."

    # Check if service exists
    if ! systemctl list-unit-files | grep -q "systemmanager-mcp.service"; then
        msg_error "Service file not found"
        return 1
    fi

    # Check if service is enabled
    if systemctl is-enabled --quiet systemmanager-mcp.service; then
        msg_ok "Service is enabled"
    else
        msg_warn "Service is not enabled for auto-start"
    fi

    # Check if service is running
    if systemctl is-active --quiet systemmanager-mcp.service; then
        msg_ok "Service is running"
    else
        msg_error "Service is not running"
        msg_info "Check logs: journalctl -u systemmanager-mcp -n 50"
        return 1
    fi

    # Check service status details
    local service_state=$(systemctl show systemmanager-mcp.service -p ActiveState --value)
    local service_substate=$(systemctl show systemmanager-mcp.service -p SubState --value)

    msg_info "Service state: $service_state ($service_substate)"

    return 0
}

function validate_service_logs() {
    msg_info "Checking service logs for errors..."

    # Get last 20 lines of logs
    local logs=$(journalctl -u systemmanager-mcp -n 20 --no-pager 2>/dev/null)

    if echo "$logs" | grep -qi "error\|failed\|exception"; then
        msg_warn "Potential errors found in logs:"
        echo "$logs" | grep -i "error\|failed\|exception" | tail -5
        msg_info "Full logs: journalctl -u systemmanager-mcp -n 100"
        return 1
    else
        msg_ok "No obvious errors in recent logs"
    fi

    return 0
}

#######################################
# Network Validation
#######################################

function validate_port_listening() {
    local port="${1:-${SYSTEMMANAGER_PORT:-8080}}"

    msg_info "Checking if service is listening on port $port..."

    # Wait a bit for service to fully start
    sleep 2

    # Check with multiple tools
    local listening=false

    if command -v lsof &>/dev/null; then
        if lsof -Pi ":$port" -sTCP:LISTEN -t >/dev/null 2>&1; then
            listening=true
        fi
    elif command -v ss &>/dev/null; then
        if ss -tlnp 2>/dev/null | grep -q ":$port "; then
            listening=true
        fi
    elif command -v netstat &>/dev/null; then
        if netstat -tlnp 2>/dev/null | grep -q ":$port "; then
            listening=true
        fi
    fi

    if [ "$listening" = "true" ]; then
        msg_ok "Service is listening on port $port"
        return 0
    else
        msg_error "Service is not listening on port $port"
        return 1
    fi
}

function validate_local_connectivity() {
    local port="${1:-${SYSTEMMANAGER_PORT:-8080}}"
    local url="http://localhost:$port"

    msg_info "Testing local connectivity to $url..."

    # Try to connect
    if curl -sf --max-time 5 "$url" >/dev/null 2>&1; then
        msg_ok "Service is responding"
        return 0
    else
        msg_error "Service is not responding at $url"
        return 1
    fi
}

function validate_health_endpoint() {
    local port="${1:-${SYSTEMMANAGER_PORT:-8080}}"
    local health_url="http://localhost:$port/.well-known/oauth-protected-resource/mcp"

    msg_info "Testing health endpoint..."

    local response=$(curl -sf --max-time 5 "$health_url" 2>/dev/null)

    if [ -n "$response" ]; then
        msg_ok "Health endpoint is responding"
        return 0
    else
        msg_warn "Health endpoint not responding (may require authentication)"
        return 0  # Don't fail on this
    fi
}

#######################################
# File System Validation
#######################################

function validate_installation_files() {
    local errors=0

    msg_info "Validating installation files..."

    # Check installation directory
    if [ ! -d "$INSTALL_DIR" ]; then
        msg_error "Installation directory not found: $INSTALL_DIR"
        ((errors++))
    else
        msg_ok "Installation directory exists"
    fi

    # Check critical files
    local critical_files=(
        "$INSTALL_DIR/.env"
        "$INSTALL_DIR/venv/bin/python"
        "$INSTALL_DIR/venv/bin/pip"
        "$INSTALL_DIR/.version"
    )

    for file in "${critical_files[@]}"; do
        if [ -f "$file" ] || [ -L "$file" ]; then
            msg_ok "Found: $file"
        else
            msg_error "Missing: $file"
            ((errors++))
        fi
    done

    # Check data directory
    if [ ! -d "$DEFAULT_DATA_DIR" ]; then
        msg_error "Data directory not found: $DEFAULT_DATA_DIR"
        ((errors++))
    else
        msg_ok "Data directory exists"
    fi

    return $errors
}

function validate_permissions() {
    msg_info "Validating file permissions..."

    # Check .env permissions
    if [ -f "$INSTALL_DIR/.env" ]; then
        local env_perms=$(stat -c %a "$INSTALL_DIR/.env" 2>/dev/null || stat -f %OLp "$INSTALL_DIR/.env" 2>/dev/null)
        if [ "$env_perms" = "600" ]; then
            msg_ok ".env file has correct permissions (600)"
        else
            msg_warn ".env file permissions: $env_perms (should be 600)"
        fi
    fi

    # Check ownership
    if [ -d "$INSTALL_DIR" ]; then
        local owner=$(stat -c %U "$INSTALL_DIR" 2>/dev/null || stat -f %Su "$INSTALL_DIR" 2>/dev/null)
        if [ "$owner" = "systemmanager" ]; then
            msg_ok "Installation directory owned by systemmanager"
        else
            msg_warn "Installation directory owned by: $owner"
        fi
    fi

    return 0
}

#######################################
# Python Environment Validation
#######################################

function validate_python_env() {
    msg_info "Validating Python environment..."

    # Check venv activation
    if [ ! -f "$INSTALL_DIR/venv/bin/activate" ]; then
        msg_error "Virtual environment activation script not found"
        return 1
    fi

    # Check Python version
    local python_version=$("$INSTALL_DIR/venv/bin/python" --version 2>&1 | awk '{print $2}')
    local major=$(echo "$python_version" | cut -d. -f1)
    local minor=$(echo "$python_version" | cut -d. -f2)

    if [ "$major" -ge 3 ] && [ "$minor" -ge 11 ]; then
        msg_ok "Python version: $python_version"
    else
        msg_error "Python version too old: $python_version (need 3.11+)"
        return 1
    fi

    # Check critical Python packages
    msg_info "Checking Python dependencies..."

    local packages=("fastmcp" "uvicorn" "python-dotenv")
    local missing=0

    for pkg in "${packages[@]}"; do
        if "$INSTALL_DIR/venv/bin/python" -c "import ${pkg//-/_}" 2>/dev/null; then
            msg_ok "Package installed: $pkg"
        else
            msg_error "Package missing: $pkg"
            ((missing++))
        fi
    done

    if [ $missing -gt 0 ]; then
        msg_error "$missing Python package(s) missing"
        return 1
    fi

    msg_ok "Python environment validated"
    return 0
}

#######################################
# Authentication Validation
#######################################

function validate_authentication() {
    msg_info "Validating authentication configuration..."

    if [ ! -f "$INSTALL_DIR/.env" ]; then
        msg_error "Configuration file not found"
        return 1
    fi

    source "$INSTALL_DIR/.env"

    case "$SYSTEMMANAGER_AUTH_MODE" in
        oidc)
            msg_info "Auth mode: OIDC/Tailscale"
            if [ -n "$TSIDP_URL" ] && [ -n "$TSIDP_CLIENT_ID" ] && [ -n "$TSIDP_CLIENT_SECRET" ]; then
                msg_ok "OIDC configuration present"
            else
                msg_error "Incomplete OIDC configuration"
                return 1
            fi
            ;;
        token)
            msg_info "Auth mode: Token-based"
            if [ -n "$SYSTEMMANAGER_SHARED_SECRET" ]; then
                msg_ok "Token configuration present"
            else
                msg_error "Token not configured"
                return 1
            fi
            ;;
        none)
            msg_warn "Auth mode: None (development only)"
            ;;
        *)
            msg_error "Invalid auth mode: $SYSTEMMANAGER_AUTH_MODE"
            return 1
            ;;
    esac

    return 0
}

#######################################
# Docker Validation
#######################################

function validate_docker() {
    if [ "$SKIP_DOCKER" = "true" ]; then
        msg_info "Docker validation skipped (SKIP_DOCKER=true)"
        return 0
    fi

    msg_info "Validating Docker installation..."

    if ! command -v docker &>/dev/null; then
        msg_warn "Docker not installed (optional)"
        return 0
    fi

    # Check Docker daemon
    if ! docker info &>/dev/null; then
        msg_error "Docker daemon not running"
        return 1
    fi

    msg_ok "Docker is installed and running"

    # Check if systemmanager user is in docker group
    if id -nG systemmanager 2>/dev/null | grep -qw docker; then
        msg_ok "systemmanager user is in docker group"
    else
        msg_warn "systemmanager user not in docker group"
    fi

    return 0
}

#######################################
# Integration Tests
#######################################

function run_integration_test() {
    local port="${1:-${SYSTEMMANAGER_PORT:-8080}}"

    msg_info "Running integration test..."

    # Simple health check
    local response=$(curl -sf --max-time 10 "http://localhost:$port/" 2>/dev/null)

    if [ $? -eq 0 ]; then
        msg_ok "Integration test passed"
        return 0
    else
        msg_warn "Integration test failed (may require authentication)"
        return 0  # Don't fail validation
    fi
}

#######################################
# Main Validation Function
#######################################

function run_post_install_validation() {
    local errors=0

    msg_info "Running post-installation validation..."
    print_separator

    # File system checks
    validate_installation_files || ((errors++))
    validate_permissions

    # Service checks
    validate_service_status || ((errors++))
    validate_service_logs

    # Network checks
    validate_port_listening || ((errors++))
    validate_local_connectivity || ((errors++))
    validate_health_endpoint

    # Environment checks
    validate_python_env || ((errors++))
    validate_authentication || ((errors++))

    # Optional checks
    validate_docker

    # Integration test
    run_integration_test

    print_separator

    if [ $errors -gt 0 ]; then
        msg_error "$errors validation check(s) failed"
        msg_info "Installation may have issues"
        return 1
    else
        msg_ok "All validation checks passed"
        return 0
    fi
}

#######################################
# Quick Validation (for upgrades)
#######################################

function run_quick_validation() {
    local errors=0

    msg_info "Running quick validation..."

    validate_service_status || ((errors++))
    validate_port_listening || ((errors++))
    validate_local_connectivity || ((errors++))

    if [ $errors -gt 0 ]; then
        msg_error "$errors check(s) failed"
        return 1
    else
        msg_ok "Quick validation passed"
        return 0
    fi
}

#######################################
# Display Installation Summary
#######################################

function display_installation_summary() {
    local port="${1:-${SYSTEMMANAGER_PORT:-8080}}"

    print_separator
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  ✓ Installation Complete!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${BLUE}Installation Summary:${NC}"
    echo "  • Location:   $INSTALL_DIR"
    echo "  • Version:    $(get_installed_version)"
    echo "  • Service:    systemmanager-mcp"
    echo "  • Port:       $port"

    if [ -f "$INSTALL_DIR/.env" ]; then
        source "$INSTALL_DIR/.env"
        echo "  • Auth Mode:  $SYSTEMMANAGER_AUTH_MODE"

        if [ "$SYSTEMMANAGER_AUTH_MODE" = "oidc" ] && [ -n "$SYSTEMMANAGER_BASE_URL" ]; then
            echo "  • Server URL: $SYSTEMMANAGER_BASE_URL"
        fi
    fi

    echo ""
    echo -e "${BLUE}Service Commands:${NC}"
    echo "  • Status:     systemctl status systemmanager-mcp"
    echo "  • Logs:       journalctl -u systemmanager-mcp -f"
    echo "  • Restart:    systemctl restart systemmanager-mcp"
    echo "  • Stop:       systemctl stop systemmanager-mcp"

    echo ""
    echo -e "${BLUE}Testing:${NC}"
    echo "  • Local test: curl http://localhost:$port/.well-known/oauth-protected-resource/mcp"

    if [ "$TAILSCALE_RUNNING" = "true" ] && [ -n "$TAILSCALE_HOSTNAME" ]; then
        echo "  • Tailscale:  curl http://${TAILSCALE_HOSTNAME}:$port/.well-known/oauth-protected-resource/mcp"
    fi

    echo ""
    echo -e "${BLUE}Configuration:${NC}"
    echo "  • Config:     $INSTALL_DIR/.env"
    echo "  • Data:       $DEFAULT_DATA_DIR"
    echo "  • Logs:       journalctl -u systemmanager-mcp"

    if [ "$SYSTEMMANAGER_AUTH_MODE" = "token" ] && [ -n "$SYSTEMMANAGER_SHARED_SECRET" ]; then
        echo ""
        echo -e "${YELLOW}⚠️  Token Authentication:${NC}"
        echo "  • Token: $SYSTEMMANAGER_SHARED_SECRET"
        echo "  • Save this token securely!"
    fi

    if [ "$SYSTEMMANAGER_AUTH_MODE" = "oidc" ]; then
        echo ""
        echo -e "${BLUE}MCP Client Configuration:${NC}"
        echo "  • URL: ${SYSTEMMANAGER_BASE_URL:-http://$HOSTNAME:$port}/mcp"
        echo "  • Use OAuth authentication in your MCP client"
    fi

    echo ""
    echo -e "${BLUE}Documentation:${NC}"
    echo "  • GitHub: https://github.com/mdlmarkham/TailOpsMCP"
    echo "  • Issues: https://github.com/mdlmarkham/TailOpsMCP/issues"

    print_separator
    echo ""
}

# Export functions
export -f validate_service_status validate_service_logs
export -f validate_port_listening validate_local_connectivity validate_health_endpoint
export -f validate_installation_files validate_permissions
export -f validate_python_env validate_authentication validate_docker
export -f run_integration_test
export -f run_post_install_validation run_quick_validation
export -f display_installation_summary
