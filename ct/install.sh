#!/usr/bin/env bash

# Copyright (c) 2024 TailOpsMCP Contributors
# Author: TailOpsMCP Team
# License: MIT
# https://github.com/mdlmarkham/TailOpsMCP

# Source ProxMox helper functions if available
if [ -n "$FUNCTIONS_FILE_PATH" ]; then
    source /dev/stdin <<< "$FUNCTIONS_FILE_PATH"
    color
    verb_ip6
    catch_errors
    setting_up_container
    network_check
    update_os
fi

# Clone repository first to get access to modular installers
INSTALL_DIR="/opt/tailopsmcp"
msg_info "Cloning TailOpsMCP repository..."
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

if ! git clone https://github.com/mdlmarkham/TailOpsMCP.git .; then
    msg_error "Failed to clone repository"
    exit 1
fi
msg_ok "Repository cloned"

# Now run the modular ProxMox installer from the repository
INSTALLER_SCRIPT="$INSTALL_DIR/scripts/install/install-proxmox.sh"

if [ ! -f "$INSTALLER_SCRIPT" ]; then
    msg_error "Installer script not found: $INSTALLER_SCRIPT"
    msg_info "Falling back to legacy installation..."

    # Fallback to legacy inline installation
    msg_info "Installing Dependencies"
    $STD apt-get install -y curl sudo git make gpg ca-certificates
    msg_ok "Installed Dependencies"

    msg_info "Installing Python 3.12"
    $STD apt-get install -y python3 python3-pip python3-venv python3-dev build-essential
    msg_ok "Installed Python 3.12"

    msg_info "Installing Docker"
    $STD bash <(curl -fsSL https://get.docker.com)
    $STD systemctl enable --now docker
    msg_ok "Installed Docker"

    # Continue with legacy installation...
    # (rest of the old script logic)

    msg_error "Please use the new installation method or check repository"
    exit 1
fi

# Make installer executable
chmod +x "$INSTALLER_SCRIPT"

# Execute the new modular installer
msg_info "Running TailOpsMCP modular installation..."
bash "$INSTALLER_SCRIPT" "$@"
INSTALL_RESULT=$?

# Handle ProxMox-specific cleanup if functions are available
if command -v motd_ssh &>/dev/null; then
    motd_ssh
fi

if command -v customize &>/dev/null; then
    customize
fi

# Cleanup packages
if command -v msg_info &>/dev/null && command -v msg_ok &>/dev/null; then
    msg_info "Cleaning up"
    $STD apt-get -y autoremove 2>/dev/null || apt-get -y autoremove
    $STD apt-get -y autoclean 2>/dev/null || apt-get -y autoclean
    msg_ok "Cleaned"
fi

exit $INSTALL_RESULT
