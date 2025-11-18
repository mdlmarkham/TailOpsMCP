#!/usr/bin/env bash
# Authentication setup for TailOpsMCP installation
# Copyright (c) 2024 TailOpsMCP Contributors
# License: MIT

#######################################
# OIDC / Tailscale OAuth Setup
#######################################

function setup_oidc_auth() {
    msg_info "Setting up Tailscale OAuth (TSIDP) authentication"

    # Check if Tailscale is installed
    if ! command -v tailscale &>/dev/null; then
        msg_error "Tailscale not detected"
        echo ""
        msg_info "To install Tailscale:"
        msg_info "  curl -fsSL https://tailscale.com/install.sh | sh"
        echo ""

        if confirm_action "Install Tailscale now?" "y"; then
            install_tailscale || return 1
        else
            msg_error "Tailscale is required for OIDC authentication"
            return 1
        fi
    fi

    # Check if Tailscale is running
    if ! tailscale status &>/dev/null 2>&1; then
        msg_error "Tailscale is not running"
        msg_info "Start Tailscale and authenticate:"
        msg_info "  sudo tailscale up"
        return 1
    fi

    msg_ok "Tailscale is installed and running"

    # Display OAuth setup instructions
    print_separator
    echo -e "${YELLOW}Tailscale OAuth Setup Instructions:${NC}"
    echo ""
    echo "1. Open: https://login.tailscale.com/admin/oauth"
    echo "2. Go to Settings → OAuth → Identity Provider"
    echo "3. Click 'Enable' if not already enabled"
    echo "4. Create a new OAuth application:"
    echo "   • Name: TailOpsMCP"
    echo "   • Redirect URI: https://vscode.dev/redirect"
    echo "   • Scopes: openid, email, profile"
    echo "5. Copy the Client ID and Client Secret"
    print_separator
    echo ""

    # Get OAuth credentials
    if [ -z "$TSIDP_URL" ]; then
        read -p "TSIDP URL (e.g., https://tsidp.tail12345.ts.net): " TSIDP_URL
    fi

    if [ -z "$TSIDP_CLIENT_ID" ]; then
        read -p "Client ID: " TSIDP_CLIENT_ID
    fi

    if [ -z "$TSIDP_CLIENT_SECRET" ]; then
        read -sp "Client Secret (hidden): " TSIDP_CLIENT_SECRET
        echo ""
    fi

    # Validate inputs
    if [ -z "$TSIDP_URL" ] || [ -z "$TSIDP_CLIENT_ID" ] || [ -z "$TSIDP_CLIENT_SECRET" ]; then
        msg_error "Missing required OAuth credentials"
        return 1
    fi

    # Auto-detect Tailscale hostname
    if [ -z "$SYSTEMMANAGER_BASE_URL" ]; then
        if [ "$TAILSCALE_RUNNING" = "true" ] && [ -n "$TAILSCALE_HOSTNAME" ]; then
            SYSTEMMANAGER_BASE_URL="http://${TAILSCALE_HOSTNAME}:${SYSTEMMANAGER_PORT:-8080}"
            msg_ok "Auto-detected server URL: $SYSTEMMANAGER_BASE_URL"
        else
            read -p "Server Base URL (e.g., http://server.tail12345.ts.net:8080): " SYSTEMMANAGER_BASE_URL
        fi
    fi

    # Create .env file
    cat > "$INSTALL_DIR/.env" << EOF
# TailOpsMCP Configuration
# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)

# Authentication Mode
SYSTEMMANAGER_AUTH_MODE=oidc
SYSTEMMANAGER_REQUIRE_AUTH=true

# Tailscale OAuth (TSIDP)
TSIDP_URL=$TSIDP_URL
TSIDP_CLIENT_ID=$TSIDP_CLIENT_ID
TSIDP_CLIENT_SECRET=$TSIDP_CLIENT_SECRET
SYSTEMMANAGER_BASE_URL=$SYSTEMMANAGER_BASE_URL

# Logging
LOG_LEVEL=INFO
EOF

    chmod 600 "$INSTALL_DIR/.env"
    chown systemmanager:systemmanager "$INSTALL_DIR/.env" 2>/dev/null || true

    msg_ok "OIDC authentication configured"
    AUTH_MODE="oidc"
    export AUTH_MODE
}

#######################################
# Token-Based Authentication Setup
#######################################

function setup_token_auth() {
    msg_info "Setting up token-based authentication"

    # Generate or use provided token
    if [ -z "$SYSTEMMANAGER_SHARED_SECRET" ]; then
        msg_info "Generating secure token..."
        SYSTEMMANAGER_SHARED_SECRET=$(openssl rand -hex 32)

        echo ""
        print_separator
        echo -e "${GREEN}IMPORTANT: Save this token securely!${NC}"
        echo ""
        echo -e "  ${BLUE}$SYSTEMMANAGER_SHARED_SECRET${NC}"
        echo ""
        print_separator
        echo ""

        if [ "$NON_INTERACTIVE" != "true" ]; then
            read -p "Press Enter to continue..."
        fi
    else
        msg_info "Using provided token"
    fi

    # Create .env file
    cat > "$INSTALL_DIR/.env" << EOF
# TailOpsMCP Configuration
# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)

# Authentication Mode
SYSTEMMANAGER_AUTH_MODE=token
SYSTEMMANAGER_REQUIRE_AUTH=true

# Shared Secret Token
SYSTEMMANAGER_SHARED_SECRET=$SYSTEMMANAGER_SHARED_SECRET

# Logging
LOG_LEVEL=INFO
EOF

    chmod 600 "$INSTALL_DIR/.env"
    chown systemmanager:systemmanager "$INSTALL_DIR/.env" 2>/dev/null || true

    msg_ok "Token authentication configured"
    AUTH_MODE="token"
    export AUTH_MODE SYSTEMMANAGER_SHARED_SECRET
}

#######################################
# No Authentication (Development Only)
#######################################

function setup_no_auth() {
    msg_warn "⚠️  WARNING: Configuring without authentication!"
    msg_warn "This should ONLY be used in development environments"
    msg_warn "Never expose this server to the internet without authentication"

    if [ "$NON_INTERACTIVE" != "true" ]; then
        echo ""
        if ! confirm_action "Continue without authentication?" "N"; then
            msg_error "Authentication setup cancelled"
            return 1
        fi
    fi

    # Create .env file
    cat > "$INSTALL_DIR/.env" << EOF
# TailOpsMCP Configuration
# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)

# Authentication Mode - DEVELOPMENT ONLY
SYSTEMMANAGER_AUTH_MODE=none
SYSTEMMANAGER_REQUIRE_AUTH=false

# Logging
LOG_LEVEL=DEBUG
EOF

    chmod 600 "$INSTALL_DIR/.env"
    chown systemmanager:systemmanager "$INSTALL_DIR/.env" 2>/dev/null || true

    msg_ok "No authentication configured (DEVELOPMENT MODE)"
    AUTH_MODE="none"
    export AUTH_MODE
}

#######################################
# Tailscale Installation Helper
#######################################

function install_tailscale() {
    msg_info "Installing Tailscale..."

    # Download Tailscale installer
    local ts_script="/tmp/tailscale-install-$$.sh"
    curl -fsSL https://tailscale.com/install.sh -o "$ts_script"

    if [ ! -f "$ts_script" ]; then
        msg_error "Failed to download Tailscale installer"
        return 1
    fi

    # Run installer
    $STD bash "$ts_script"
    rm "$ts_script"

    if command -v tailscale &>/dev/null; then
        msg_ok "Tailscale installed successfully"

        # Prompt to start Tailscale
        msg_info "Starting Tailscale..."
        msg_info "You may be prompted to authenticate"
        echo ""

        if tailscale up; then
            msg_ok "Tailscale is running"
            TAILSCALE_INSTALLED=true
            TAILSCALE_RUNNING=true
            detect_tailscale  # Re-detect to get hostname
            return 0
        else
            msg_error "Failed to start Tailscale"
            return 1
        fi
    else
        msg_error "Tailscale installation failed"
        return 1
    fi
}

#######################################
# Main Authentication Configuration
#######################################

function configure_authentication() {
    msg_info "Configuring Authentication"
    print_separator

    # Check if already configured during upgrade
    if [ "$UPGRADE_MODE" = "true" ] && [ -f "$INSTALL_DIR/.env" ]; then
        msg_ok "Authentication already configured (upgrade mode)"

        # Load existing auth mode
        if grep -q "SYSTEMMANAGER_AUTH_MODE=oidc" "$INSTALL_DIR/.env"; then
            AUTH_MODE="oidc"
        elif grep -q "SYSTEMMANAGER_AUTH_MODE=token" "$INSTALL_DIR/.env"; then
            AUTH_MODE="token"
        else
            AUTH_MODE="none"
        fi

        export AUTH_MODE
        msg_info "Existing auth mode: $AUTH_MODE"

        if [ "$NON_INTERACTIVE" != "true" ]; then
            if ! confirm_action "Keep existing authentication?" "y"; then
                backup_existing_config
            else
                return 0
            fi
        else
            return 0
        fi
    fi

    # Determine authentication mode
    if [ -z "$SYSTEMMANAGER_AUTH_MODE" ]; then
        if [ "$NON_INTERACTIVE" = "true" ]; then
            msg_error "NON_INTERACTIVE=true requires SYSTEMMANAGER_AUTH_MODE to be set"
            msg_info "Set one of: oidc, token, none"
            return 1
        fi

        echo ""
        echo -e "${YELLOW}Choose Authentication Method:${NC}"
        echo "  1) Tailscale OAuth (TSIDP) - Recommended for multi-user"
        echo "  2) Token-based - Simple shared secret"
        echo "  3) No authentication - Development only"
        echo ""
        read -p "Select [1-3]: " auth_choice

        case $auth_choice in
            1) SYSTEMMANAGER_AUTH_MODE="oidc" ;;
            2) SYSTEMMANAGER_AUTH_MODE="token" ;;
            3) SYSTEMMANAGER_AUTH_MODE="none" ;;
            *)
                msg_error "Invalid selection"
                return 1
                ;;
        esac
    fi

    # Setup authentication based on mode
    case "$SYSTEMMANAGER_AUTH_MODE" in
        oidc)
            setup_oidc_auth || return 1
            ;;
        token)
            setup_token_auth || return 1
            ;;
        none)
            setup_no_auth || return 1
            ;;
        *)
            msg_error "Invalid authentication mode: $SYSTEMMANAGER_AUTH_MODE"
            msg_info "Valid modes: oidc, token, none"
            return 1
            ;;
    esac

    print_separator
    msg_ok "Authentication configuration complete"
    track_step "auth_configured"

    return 0
}

#######################################
# Validate Authentication Configuration
#######################################

function validate_auth_config() {
    if [ ! -f "$INSTALL_DIR/.env" ]; then
        msg_error "Authentication configuration file not found"
        return 1
    fi

    source "$INSTALL_DIR/.env"

    case "$SYSTEMMANAGER_AUTH_MODE" in
        oidc)
            if [ -z "$TSIDP_URL" ] || [ -z "$TSIDP_CLIENT_ID" ] || [ -z "$TSIDP_CLIENT_SECRET" ]; then
                msg_error "Incomplete OIDC configuration"
                return 1
            fi
            msg_ok "OIDC configuration validated"
            ;;
        token)
            if [ -z "$SYSTEMMANAGER_SHARED_SECRET" ]; then
                msg_error "Token not configured"
                return 1
            fi
            msg_ok "Token configuration validated"
            ;;
        none)
            msg_ok "No authentication mode validated"
            ;;
        *)
            msg_error "Invalid authentication mode: $SYSTEMMANAGER_AUTH_MODE"
            return 1
            ;;
    esac

    return 0
}

# Export functions
export -f setup_oidc_auth setup_token_auth setup_no_auth
export -f install_tailscale
export -f configure_authentication validate_auth_config
