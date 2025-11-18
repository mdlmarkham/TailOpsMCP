#!/usr/bin/env bash
# Common utility functions for TailOpsMCP installation
# Copyright (c) 2024 TailOpsMCP Contributors
# License: MIT

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;36m'
NC='\033[0m' # No Color

# Installation state tracking
INSTALL_STATE="/tmp/systemmanager-install-state-$$"
INSTALL_LOG="/tmp/systemmanager-install-$$.log"

# Default configuration
DEFAULT_INSTALL_DIR="/opt/systemmanager"
DEFAULT_PORT=8080
DEFAULT_DATA_DIR="/var/lib/systemmanager"

#######################################
# Logging Functions
#######################################

function msg_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$INSTALL_LOG"
}

function msg_ok() {
    echo -e "${GREEN}[✓]${NC} $1" | tee -a "$INSTALL_LOG"
}

function msg_warn() {
    echo -e "${YELLOW}[⚠]${NC} $1" | tee -a "$INSTALL_LOG"
}

function msg_error() {
    echo -e "${RED}[✗]${NC} $1" | tee -a "$INSTALL_LOG"
}

#######################################
# State Tracking Functions
#######################################

function track_step() {
    echo "$1:$(date +%s)" >> "$INSTALL_STATE"
}

function has_step() {
    grep -q "^$1:" "$INSTALL_STATE" 2>/dev/null
}

function init_state() {
    > "$INSTALL_STATE"
    > "$INSTALL_LOG"
    msg_info "Installation started at $(date)"
    msg_info "Log file: $INSTALL_LOG"
}

function cleanup_state() {
    if [ -f "$INSTALL_STATE" ]; then
        rm -f "$INSTALL_STATE"
    fi
}

#######################################
# Error Handling & Rollback
#######################################

function rollback() {
    local exit_code=$?

    msg_error "Installation failed with exit code $exit_code"
    msg_info "Rolling back changes..."

    # Stop and remove service if created
    if has_step "service_created"; then
        msg_info "Removing systemd service..."
        systemctl stop systemmanager-mcp 2>/dev/null || true
        systemctl disable systemmanager-mcp 2>/dev/null || true
        rm -f /etc/systemd/system/systemmanager-mcp.service
        systemctl daemon-reload
    fi

    # Remove user if created
    if has_step "user_created"; then
        msg_info "Removing systemmanager user..."
        userdel systemmanager 2>/dev/null || true
        # Only remove group if it's now empty
        if getent group systemmanager >/dev/null 2>&1; then
            groupdel systemmanager 2>/dev/null || true
        fi
    fi

    # Handle installation directory
    if has_step "files_created"; then
        if [ "$NON_INTERACTIVE" = "true" ]; then
            msg_info "Removing installation directory: $INSTALL_DIR"
            rm -rf "$INSTALL_DIR"
        else
            read -p "Remove installation directory ($INSTALL_DIR)? [y/N]: " remove_choice
            if [[ $remove_choice =~ ^[Yy]$ ]]; then
                rm -rf "$INSTALL_DIR"
                msg_ok "Installation directory removed"
            else
                msg_info "Installation directory preserved at $INSTALL_DIR"
            fi
        fi
    fi

    cleanup_state
    msg_error "Rollback complete. Check log: $INSTALL_LOG"
    exit 1
}

function setup_error_handling() {
    set -eE  # Exit on error, inherit ERR trap
    trap rollback ERR
}

#######################################
# Version Management
#######################################

function save_version() {
    local version="${1:-unknown}"
    echo "$version" > "$INSTALL_DIR/.version"
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$INSTALL_DIR/.install_date"
}

function get_installed_version() {
    if [ -f "$INSTALL_DIR/.version" ]; then
        cat "$INSTALL_DIR/.version"
    else
        echo "unknown"
    fi
}

function detect_existing_installation() {
    if [ -d "$INSTALL_DIR" ]; then
        CURRENT_VERSION=$(get_installed_version)
        msg_warn "Existing installation detected"
        msg_info "  Location: $INSTALL_DIR"
        msg_info "  Version: $CURRENT_VERSION"

        if [ -f "$INSTALL_DIR/.install_date" ]; then
            msg_info "  Installed: $(cat "$INSTALL_DIR/.install_date")"
        fi

        return 0  # Installation exists
    else
        return 1  # No installation
    fi
}

#######################################
# Backup Functions
#######################################

function backup_existing_config() {
    if [ -f "$INSTALL_DIR/.env" ]; then
        local backup_file="$INSTALL_DIR/.env.backup-$(date +%s)"
        msg_info "Backing up existing configuration..."
        cp "$INSTALL_DIR/.env" "$backup_file"
        chmod 600 "$backup_file"
        msg_ok "Configuration backed up to: $backup_file"
        track_step "config_backed_up"
    fi
}

function restore_config_from_backup() {
    local latest_backup=$(ls -t "$INSTALL_DIR"/.env.backup-* 2>/dev/null | head -1)
    if [ -n "$latest_backup" ]; then
        msg_info "Restoring configuration from backup..."
        cp "$latest_backup" "$INSTALL_DIR/.env"
        chmod 600 "$INSTALL_DIR/.env"
        msg_ok "Configuration restored"
    fi
}

#######################################
# User & Permissions
#######################################

function create_service_user() {
    msg_info "Creating dedicated service user"

    if id -u systemmanager >/dev/null 2>&1; then
        msg_ok "systemmanager user already exists"
    else
        useradd --system --no-create-home --shell /usr/sbin/nologin systemmanager
        msg_ok "Created systemmanager user"
        track_step "user_created"
    fi

    # Add to docker group if docker is installed
    if command -v docker &>/dev/null; then
        usermod -aG docker systemmanager 2>/dev/null || true
        msg_ok "Added systemmanager to docker group"
    fi
}

function setup_permissions() {
    local install_dir="${1:-$INSTALL_DIR}"
    local data_dir="${2:-$DEFAULT_DATA_DIR}"

    msg_info "Setting up permissions"

    # Create and set ownership of data directory
    mkdir -p "$data_dir"
    chown -R systemmanager:systemmanager "$data_dir"
    chmod 755 "$data_dir"

    # Set ownership of installation directory
    chown -R systemmanager:systemmanager "$install_dir"

    # Secure sensitive files
    if [ -f "$install_dir/.env" ]; then
        chmod 600 "$install_dir/.env"
        chown systemmanager:systemmanager "$install_dir/.env"
    fi

    msg_ok "Permissions configured"
}

#######################################
# Network & Connectivity
#######################################

function check_port_available() {
    local port="${1:-$DEFAULT_PORT}"

    if command -v lsof >/dev/null 2>&1; then
        if lsof -Pi ":$port" -sTCP:LISTEN -t >/dev/null 2>&1; then
            return 1  # Port in use
        fi
    elif command -v ss >/dev/null 2>&1; then
        if ss -tlnp | grep -q ":$port "; then
            return 1  # Port in use
        fi
    elif command -v netstat >/dev/null 2>&1; then
        if netstat -tlnp 2>/dev/null | grep -q ":$port "; then
            return 1  # Port in use
        fi
    fi

    return 0  # Port available
}

function test_network_connectivity() {
    local test_hosts=("github.com" "raw.githubusercontent.com" "pypi.org")
    local failures=0

    for host in "${test_hosts[@]}"; do
        if ! ping -c 1 -W 2 "$host" &>/dev/null; then
            msg_warn "Cannot reach $host"
            ((failures++))
        fi
    done

    if [ $failures -eq ${#test_hosts[@]} ]; then
        msg_error "No internet connectivity detected"
        return 1
    elif [ $failures -gt 0 ]; then
        msg_warn "Partial connectivity issues detected"
    fi

    return 0
}

#######################################
# Package Management
#######################################

function detect_package_manager() {
    if command -v apt-get &>/dev/null; then
        PKG_MANAGER="apt"
        PKG_UPDATE="apt-get update"
        PKG_INSTALL="apt-get install -y"
        PKG_UPGRADE="apt-get upgrade -y"
    elif command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
        PKG_UPDATE="dnf check-update || true"
        PKG_INSTALL="dnf install -y"
        PKG_UPGRADE="dnf upgrade -y"
    elif command -v yum &>/dev/null; then
        PKG_MANAGER="yum"
        PKG_UPDATE="yum check-update || true"
        PKG_INSTALL="yum install -y"
        PKG_UPGRADE="yum upgrade -y"
    else
        msg_error "No supported package manager found (apt, dnf, yum)"
        return 1
    fi

    export PKG_MANAGER PKG_UPDATE PKG_INSTALL PKG_UPGRADE
    return 0
}

function install_base_packages() {
    msg_info "Installing base dependencies"

    detect_package_manager || return 1

    # Update package lists
    $STD $PKG_UPDATE

    # Common packages across all distros
    local packages=(
        curl
        wget
        git
        ca-certificates
        gnupg
        lsof
    )

    # Add distro-specific packages
    case $PKG_MANAGER in
        apt)
            packages+=(sudo gpg)
            ;;
        dnf|yum)
            packages+=(sudo which)
            ;;
    esac

    $STD $PKG_INSTALL "${packages[@]}"

    msg_ok "Installed base dependencies"
    track_step "base_packages_installed"
}

#######################################
# Python Management
#######################################

function detect_python() {
    # Try to find Python 3.11+
    for py_cmd in python3.12 python3.11 python3; do
        if command -v "$py_cmd" &>/dev/null; then
            PYTHON_CMD="$py_cmd"
            PYTHON_VERSION=$($py_cmd --version 2>&1 | awk '{print $2}')

            # Check if version is >= 3.11
            local major=$(echo "$PYTHON_VERSION" | cut -d. -f1)
            local minor=$(echo "$PYTHON_VERSION" | cut -d. -f2)

            if [ "$major" -ge 3 ] && [ "$minor" -ge 11 ]; then
                msg_ok "Found compatible Python: $PYTHON_CMD ($PYTHON_VERSION)"
                export PYTHON_CMD PYTHON_VERSION
                return 0
            fi
        fi
    done

    msg_error "Python 3.11+ not found"
    return 1
}

function install_python() {
    msg_info "Installing Python"

    detect_package_manager || return 1

    case $PKG_MANAGER in
        apt)
            $STD $PKG_INSTALL \
                python3 \
                python3-pip \
                python3-venv \
                python3-dev \
                build-essential
            ;;
        dnf|yum)
            $STD $PKG_INSTALL \
                python3 \
                python3-pip \
                python3-devel \
                gcc \
                gcc-c++ \
                make
            ;;
    esac

    # Verify installation
    if ! detect_python; then
        msg_error "Python installation failed"
        return 1
    fi

    msg_ok "Installed Python $PYTHON_VERSION"
    track_step "python_installed"
}

#######################################
# Docker Management
#######################################

function install_docker() {
    if command -v docker &>/dev/null; then
        msg_ok "Docker already installed: $(docker --version)"
        return 0
    fi

    if [ "$SKIP_DOCKER" = "true" ]; then
        msg_info "Skipping Docker installation (SKIP_DOCKER=true)"
        return 0
    fi

    msg_info "Installing Docker"

    # Download Docker install script
    local docker_script="/tmp/docker-install-$$.sh"
    curl -fsSL https://get.docker.com -o "$docker_script"

    # Optional: Review in interactive mode
    if [ "$NON_INTERACTIVE" != "true" ]; then
        echo ""
        msg_warn "About to run Docker installation script"
        read -p "Review script before installation? [y/N]: " review_choice
        if [[ $review_choice =~ ^[Yy]$ ]]; then
            ${PAGER:-less} "$docker_script"
            read -p "Proceed with Docker installation? [y/N]: " proceed_choice
            if [[ ! $proceed_choice =~ ^[Yy]$ ]]; then
                rm "$docker_script"
                msg_error "Docker installation cancelled"
                return 1
            fi
        fi
    fi

    # Run Docker install script
    $STD bash "$docker_script"
    rm "$docker_script"

    # Enable and start Docker
    systemctl enable docker 2>/dev/null || true
    systemctl start docker 2>/dev/null || true

    # Wait for Docker to be ready
    local retries=0
    while ! docker info &>/dev/null && [ $retries -lt 10 ]; do
        sleep 1
        ((retries++))
    done

    if docker info &>/dev/null; then
        msg_ok "Installed Docker: $(docker --version)"
        track_step "docker_installed"
        return 0
    else
        msg_error "Docker installation succeeded but service not ready"
        return 1
    fi
}

#######################################
# Service Management
#######################################

function create_systemd_service() {
    local install_dir="${1:-$INSTALL_DIR}"
    local port="${2:-$DEFAULT_PORT}"
    local data_dir="${3:-$DEFAULT_DATA_DIR}"

    msg_info "Creating systemd service"

    cat > /etc/systemd/system/systemmanager-mcp.service << EOF
[Unit]
Description=TailOpsMCP - Secure MCP control surface for Tailscale homelabs
Documentation=https://github.com/mdlmarkham/TailOpsMCP
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
User=systemmanager
Group=systemmanager
WorkingDirectory=$install_dir
Environment="PATH=$install_dir/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Load secrets from protected environment file
EnvironmentFile=$install_dir/.env

ExecStart=$install_dir/venv/bin/python -m src.mcp_server
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$data_dir
NoNewPrivileges=true
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable systemmanager-mcp.service

    msg_ok "Created systemd service"
    track_step "service_created"
}

function start_service() {
    msg_info "Starting SystemManager MCP Server"

    systemctl start systemmanager-mcp.service

    # Wait for service to start
    sleep 3

    if systemctl is-active --quiet systemmanager-mcp.service; then
        msg_ok "SystemManager MCP Server started successfully"
        return 0
    else
        msg_error "Failed to start service"
        msg_error "Check logs: journalctl -u systemmanager-mcp -n 50"
        return 1
    fi
}

#######################################
# Git & Repository Management
#######################################

function clone_repository() {
    local install_dir="${1:-$INSTALL_DIR}"
    local repo_url="${2:-https://github.com/mdlmarkham/TailOpsMCP.git}"
    local branch="${3:-main}"

    msg_info "Cloning TailOpsMCP repository"

    mkdir -p "$install_dir"
    cd "$install_dir"

    # Check if already a git repository
    if [ -d ".git" ]; then
        msg_info "Repository already exists, updating..."
        $STD git fetch origin
        $STD git checkout "$branch"
        $STD git pull origin "$branch"
    else
        $STD git clone "$repo_url" .
        $STD git checkout "$branch"
    fi

    # Get current version/commit
    local version=$(git describe --tags --always 2>/dev/null || git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    save_version "$version"

    msg_ok "Repository cloned/updated: $version"
    track_step "repo_cloned"
}

#######################################
# Python Virtual Environment
#######################################

function setup_python_venv() {
    local install_dir="${1:-$INSTALL_DIR}"

    msg_info "Setting up Python virtual environment"

    cd "$install_dir"

    # Create venv if it doesn't exist
    if [ ! -d "venv" ]; then
        $STD $PYTHON_CMD -m venv venv
        msg_ok "Created virtual environment"
    else
        msg_ok "Virtual environment already exists"
    fi

    # Activate and upgrade pip
    source venv/bin/activate
    $STD pip install --upgrade pip setuptools wheel

    # Install requirements
    if [ -f "requirements.txt" ]; then
        $STD pip install -r requirements.txt
        msg_ok "Installed Python dependencies"
    else
        msg_warn "requirements.txt not found"
    fi

    deactivate
    track_step "venv_setup"
}

#######################################
# Utility Functions
#######################################

function confirm_action() {
    local prompt="$1"
    local default="${2:-N}"

    if [ "$NON_INTERACTIVE" = "true" ]; then
        return 0  # Always proceed in non-interactive mode
    fi

    local response
    read -p "$prompt [$default]: " response
    response=${response:-$default}

    if [[ $response =~ ^[Yy]$ ]]; then
        return 0
    else
        return 1
    fi
}

function print_separator() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

function print_banner() {
    clear
    cat << "EOF"
   _____           __                 __  ___
  / ___/__  ______/ /____  ____ ___  /  |/  /___ _____  ____ _____ ____  _____
  \__ \/ / / / ___/ __/ _ \/ __ `__ \/ /|_/ / __ `/ __ \/ __ `/ __ `/ _ \/ ___/
 ___/ / /_/ (__  ) /_/  __/ / / / / / /  / / /_/ / / / / /_/ / /_/ /  __/ /
/____/\__, /____/\__/\___/_/ /_/ /_/_/  /_/\__,_/_/ /_/\__,_/\__, /\___/_/
     /____/                                                 /____/

TailOpsMCP - Secure MCP control surface for Tailscale homelabs
EOF
    echo ""
}

# Initialize variables if not set
: "${STD:=}"
: "${NON_INTERACTIVE:=false}"
: "${SKIP_DOCKER:=false}"
: "${INSTALL_DIR:=$DEFAULT_INSTALL_DIR}"
: "${SYSTEMMANAGER_PORT:=$DEFAULT_PORT}"

# Export all functions for use in other scripts
export -f msg_info msg_ok msg_warn msg_error
export -f track_step has_step init_state cleanup_state
export -f rollback setup_error_handling
export -f save_version get_installed_version detect_existing_installation
export -f backup_existing_config restore_config_from_backup
export -f create_service_user setup_permissions
export -f check_port_available test_network_connectivity
export -f detect_package_manager install_base_packages
export -f detect_python install_python
export -f install_docker
export -f create_systemd_service start_service
export -f clone_repository setup_python_venv
export -f confirm_action print_separator print_banner
