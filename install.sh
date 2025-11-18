#!/usr/bin/env bash

# TailOpsMCP Universal Installer
# Copyright (c) 2024 TailOpsMCP Contributors
# License: MIT
# https://github.com/mdlmarkham/TailOpsMCP

set -euo pipefail

# Detect script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if we're running from the repository
if [ -f "$SCRIPT_DIR/scripts/install/install.sh" ]; then
    # Running from repository - use modular installer
    exec bash "$SCRIPT_DIR/scripts/install/install.sh" "$@"
else
    # Running standalone (downloaded directly) - download and run
    echo "Downloading TailOpsMCP installer..."

    TEMP_DIR="/tmp/tailopsmcp-install-$$"
    mkdir -p "$TEMP_DIR"

    # Download the installer
    INSTALLER_URL="https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/main/scripts/install/install.sh"
    if ! curl -fsSL "$INSTALLER_URL" -o "$TEMP_DIR/install.sh"; then
        echo "ERROR: Failed to download installer"
        rm -rf "$TEMP_DIR"
        exit 1
    fi

    # Download library modules
    LIB_DIR="$TEMP_DIR/lib"
    mkdir -p "$LIB_DIR"

    for lib in common.sh platform-detect.sh preflight.sh auth-setup.sh validation.sh; do
        LIB_URL="https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/main/scripts/install/lib/$lib"
        if ! curl -fsSL "$LIB_URL" -o "$LIB_DIR/$lib"; then
            echo "ERROR: Failed to download library: $lib"
            rm -rf "$TEMP_DIR"
            exit 1
        fi
    done

    # Download platform-specific installers
    for installer in install-standalone.sh install-proxmox.sh install-ec2.sh; do
        INST_URL="https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/main/scripts/install/$installer"
        curl -fsSL "$INST_URL" -o "$TEMP_DIR/$installer" 2>/dev/null || true
    done

    # Make scripts executable
    chmod +x "$TEMP_DIR"/*.sh 2>/dev/null || true

    # Run installer
    cd "$TEMP_DIR"
    bash "$TEMP_DIR/install.sh" "$@"
    RESULT=$?

    # Cleanup
    cd /
    rm -rf "$TEMP_DIR"

    exit $RESULT
fi
