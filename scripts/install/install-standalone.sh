#!/usr/bin/env bash
# TailOpsMCP Standalone Installer
# Works on any Linux system (LXC, EC2, bare metal, etc.)
# Copyright (c) 2024 TailOpsMCP Contributors
# License: MIT

set -euo pipefail

#######################################
# Configuration
#######################################

# Installation defaults
INSTALL_DIR="${SYSTEMMANAGER_INSTALL_DIR:-/opt/systemmanager}"
SYSTEMMANAGER_PORT="${SYSTEMMANAGER_PORT:-8080}"
DATA_DIR="${SYSTEMMANAGER_DATA_DIR:-/var/lib/systemmanager}"

# Repository settings
REPO_URL="${SYSTEMMANAGER_REPO_URL:-https://github.com/mdlmarkham/TailOpsMCP.git}"
REPO_BRANCH="${SYSTEMMANAGER_REPO_BRANCH:-main}"

# Installation options
NON_INTERACTIVE="${NON_INTERACTIVE:-false}"
SKIP_DOCKER="${SKIP_DOCKER:-false}"
FORCE_REINSTALL="${FORCE_REINSTALL:-false}"
CONFIG_FILE="${CONFIG_FILE:-}"

# Mode flags
UPGRADE_MODE=false
REINSTALL_MODE=false

# Standard output mode
STD="${STD:-}"

#######################################
# Detect Script Directory
#######################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"

#######################################
# Load Library Modules
#######################################

function load_libraries() {
    local libs=(
        "$LIB_DIR/common.sh"
        "$LIB_DIR/platform-detect.sh"
        "$LIB_DIR/preflight.sh"
        "$LIB_DIR/auth-setup.sh"
        "$LIB_DIR/validation.sh"
    )

    for lib in "${libs[@]}"; do
        if [ -f "$lib" ]; then
            source "$lib"
        else
            echo "ERROR: Required library not found: $lib"
            exit 1
        fi
    done
}

# Load all library modules
load_libraries

#######################################
# Load Configuration File (if provided)
#######################################

function load_config_file() {
    if [ -n "$CONFIG_FILE" ] && [ -f "$CONFIG_FILE" ]; then
        msg_info "Loading configuration from: $CONFIG_FILE"
        source "$CONFIG_FILE"
        msg_ok "Configuration loaded"
    fi
}

#######################################
# Core Installation Steps
#######################################

function install_dependencies() {
    msg_info "Installing dependencies"

    install_base_packages
    install_python

    if [ "$SKIP_DOCKER" != "true" ]; then
        install_docker
    fi

    msg_ok "Dependencies installed"
}

function setup_installation_directory() {
    msg_info "Setting up installation directory"

    # Clone or update repository
    clone_repository "$INSTALL_DIR" "$REPO_URL" "$REPO_BRANCH"

    track_step "files_created"
    msg_ok "Installation directory setup complete"
}

function setup_python_environment() {
    msg_info "Setting up Python environment"

    setup_python_venv "$INSTALL_DIR"

    msg_ok "Python environment ready"
}

function setup_service_user() {
    msg_info "Setting up service user and permissions"

    create_service_user
    setup_permissions "$INSTALL_DIR" "$DATA_DIR"

    msg_ok "Service user configured"
}

function setup_systemd_service() {
    msg_info "Setting up systemd service"

    create_systemd_service "$INSTALL_DIR" "$SYSTEMMANAGER_PORT" "$DATA_DIR"

    msg_ok "Systemd service created"
}

function start_systemmanager_service() {
    msg_info "Starting SystemManager service"

    start_service

    msg_ok "Service started"
}

#######################################
# Upgrade Process
#######################################

function perform_upgrade() {
    msg_info "Performing upgrade..."
    print_separator

    # Stop service
    msg_info "Stopping service..."
    systemctl stop systemmanager-mcp.service || true

    # Backup configuration
    backup_existing_config

    # Update repository
    msg_info "Updating repository..."
    cd "$INSTALL_DIR"
    git fetch origin
    git checkout "$REPO_BRANCH"
    git pull origin "$REPO_BRANCH"

    # Get new version
    local new_version=$(git describe --tags --always 2>/dev/null || git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    save_version "$new_version"
    msg_ok "Updated to version: $new_version"

    # Update Python dependencies
    msg_info "Updating Python dependencies..."
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    deactivate

    # Restore configuration (keep existing .env)
    msg_info "Configuration preserved"

    # Start service
    msg_info "Starting service..."
    systemctl start systemmanager-mcp.service

    # Quick validation
    run_quick_validation

    msg_ok "Upgrade complete"
    print_separator
}

#######################################
# Main Installation Flow
#######################################

function main() {
    # Initialize
    print_banner
    init_state
    setup_error_handling

    # Load configuration file if provided
    load_config_file

    # Platform detection
    run_platform_detection

    # Pre-flight checks
    run_preflight_checks || exit 1

    # Check for upgrade mode
    if [ "$UPGRADE_MODE" = "true" ]; then
        perform_upgrade
        display_installation_summary "$SYSTEMMANAGER_PORT"
        cleanup_state
        exit 0
    fi

    # Fresh installation
    print_separator
    msg_info "Starting TailOpsMCP installation"
    print_separator

    # Install dependencies
    install_dependencies

    # Setup installation
    setup_installation_directory
    setup_python_environment
    setup_service_user

    # Configure authentication
    configure_authentication || exit 1

    # Setup and start service
    setup_systemd_service
    start_systemmanager_service

    # Validate installation
    print_separator
    if run_post_install_validation; then
        # Display success summary
        display_installation_summary "$SYSTEMMANAGER_PORT"

        cleanup_state
        exit 0
    else
        msg_error "Installation validation failed"
        msg_info "Check logs: journalctl -u systemmanager-mcp -n 100"
        exit 1
    fi
}

#######################################
# Handle Script Arguments
#######################################

function show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

TailOpsMCP Standalone Installer

OPTIONS:
    --help                  Show this help message
    --non-interactive       Run without prompts (requires env vars)
    --skip-docker          Skip Docker installation
    --force-reinstall      Force reinstall over existing installation
    --config FILE          Load configuration from file
    --install-dir DIR      Installation directory (default: /opt/systemmanager)
    --port PORT            Service port (default: 8080)
    --auth-mode MODE       Authentication mode: oidc, token, none

ENVIRONMENT VARIABLES:
    SYSTEMMANAGER_INSTALL_DIR       Installation directory
    SYSTEMMANAGER_PORT              Service port
    SYSTEMMANAGER_AUTH_MODE         Auth mode (oidc/token/none)
    SYSTEMMANAGER_SHARED_SECRET     Token for token-based auth
    TSIDP_URL                       Tailscale IdP URL for OIDC
    TSIDP_CLIENT_ID                 OIDC client ID
    TSIDP_CLIENT_SECRET             OIDC client secret
    NON_INTERACTIVE                 Set to 'true' for non-interactive mode
    SKIP_DOCKER                     Set to 'true' to skip Docker
    FORCE_REINSTALL                 Set to 'true' to force reinstall

EXAMPLES:
    # Interactive installation
    sudo bash $0

    # Non-interactive with token auth
    sudo SYSTEMMANAGER_AUTH_MODE=token NON_INTERACTIVE=true bash $0

    # Custom installation directory
    sudo bash $0 --install-dir /opt/custom

    # With configuration file
    sudo bash $0 --config /etc/systemmanager/install.conf

EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --help)
            show_usage
            exit 0
            ;;
        --non-interactive)
            NON_INTERACTIVE=true
            shift
            ;;
        --skip-docker)
            SKIP_DOCKER=true
            shift
            ;;
        --force-reinstall)
            FORCE_REINSTALL=true
            shift
            ;;
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --install-dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --port)
            SYSTEMMANAGER_PORT="$2"
            shift 2
            ;;
        --auth-mode)
            SYSTEMMANAGER_AUTH_MODE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Export configuration
export INSTALL_DIR SYSTEMMANAGER_PORT DATA_DIR
export NON_INTERACTIVE SKIP_DOCKER FORCE_REINSTALL
export REPO_URL REPO_BRANCH

# Run main installation
main "$@"
