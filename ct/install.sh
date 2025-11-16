#!/usr/bin/env bash

# Copyright (c) 2024 TailOpsMCP Contributors
# Author: TailOpsMCP Team
# License: MIT
# https://github.com/mdlmarkham/TailOpsMCP

source /dev/stdin <<< "$FUNCTIONS_FILE_PATH"
color
verb_ip6
catch_errors
setting_up_container
network_check
update_os

msg_info "Installing Dependencies"
$STD apt-get install -y \
  curl \
  sudo \
  git \
  make \
  gpg \
  ca-certificates
msg_ok "Installed Dependencies"

msg_info "Installing Python 3.12"
$STD apt-get install -y \
  python3 \
  python3-pip \
  python3-venv \
  python3-dev \
  build-essential
msg_ok "Installed Python 3.12"

msg_info "Installing Docker"
$STD bash <(curl -fsSL https://get.docker.com)
$STD systemctl enable --now docker
msg_ok "Installed Docker"

RELEASE=$(curl -s https://api.github.com/repos/mdlmarkham/TailOpsMCP/releases/latest | grep "tag_name" | awk '{print substr($2, 2, length($2)-3) }')

msg_info "Installing TailOpsMCP ${RELEASE}"
INSTALL_DIR="/opt/systemmanager"
mkdir -p $INSTALL_DIR
cd $INSTALL_DIR

$STD git clone https://github.com/mdlmarkham/TailOpsMCP.git .
$STD python3 -m venv venv
source venv/bin/activate
$STD pip install --upgrade pip
$STD pip install -r requirements.txt
msg_ok "Installed TailOpsMCP"

msg_info "Configuring Authentication"
echo ""
echo -e "\e[1;33mChoose Authentication Method:\e[0m"
echo "  1) Tailscale OAuth (TSIDP) - Recommended"
echo "  2) Token-based - Simple shared secret"
echo ""
read -p "Select [1-2]: " auth_choice

if [[ $auth_choice == "1" ]]; then
  # Check if Tailscale is installed
  if ! command -v tailscale &> /dev/null; then
    msg_error "Tailscale not detected. Please install Tailscale first:"
    echo "  curl -fsSL https://tailscale.com/install.sh | sh"
    exit 1
  fi
  
  AUTH_MODE="oidc"
  
  echo ""
  echo -e "\e[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
  echo -e "\e[1;33mTailscale OAuth Setup Instructions:\e[0m"
  echo ""
  echo "1. Open: https://login.tailscale.com/admin/oauth"
  echo "2. Go to Settings → OAuth → Identity Provider"
  echo "3. Click 'Enable' if not already enabled"
  echo "4. Create a new OAuth application:"
  echo "   • Name: TailOpsMCP"
  echo "   • Redirect URI: https://vscode.dev/redirect"
  echo "   • Scopes: openid, email, profile"
  echo "5. Copy the Client ID and Client Secret"
  echo -e "\e[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
  echo ""
  
  read -p "Have you created the OAuth app? [y/N]: " oauth_ready
  if [[ ! $oauth_ready =~ ^[Yy]$ ]]; then
    msg_error "Please create the OAuth application first, then run installer again"
    exit 1
  fi
  
  echo ""
  read -p "TSIDP URL (e.g., https://tsidp.tail12345.ts.net): " TSIDP_URL
  read -p "Client ID: " TSIDP_CLIENT_ID
  read -sp "Client Secret (hidden): " TSIDP_CLIENT_SECRET
  echo ""
  
  # Auto-detect Tailscale hostname
  TAILSCALE_HOSTNAME=$(tailscale status --json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['Self']['DNSName'].rstrip('.'))" 2>/dev/null || echo "")
  
  if [ -n "$TAILSCALE_HOSTNAME" ]; then
    BASE_URL="http://$TAILSCALE_HOSTNAME:8080"
    msg_ok "Detected server URL: $BASE_URL"
  else
    read -p "Server Base URL (e.g., http://server.tail12345.ts.net:8080): " BASE_URL
  fi
  
  # Create .env file
  cat > $INSTALL_DIR/.env << EOF
SYSTEMMANAGER_AUTH_MODE=oidc
SYSTEMMANAGER_REQUIRE_AUTH=true
TSIDP_URL=$TSIDP_URL
TSIDP_CLIENT_ID=$TSIDP_CLIENT_ID
TSIDP_CLIENT_SECRET=$TSIDP_CLIENT_SECRET
SYSTEMMANAGER_BASE_URL=$BASE_URL
LOG_LEVEL=INFO
EOF

else
  AUTH_MODE="token"
  
  msg_info "Generating secure token..."
  SHARED_SECRET=$(openssl rand -hex 32)
  
  echo ""
  echo -e "\e[1;32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
  echo -e "\e[1;33mIMPORTANT: Save this token securely!\e[0m"
  echo ""
  echo -e "  \e[1;36m$SHARED_SECRET\e[0m"
  echo ""
  echo -e "\e[1;32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
  echo ""
  read -p "Press Enter to continue..."
  
  # Create .env file
  cat > $INSTALL_DIR/.env << EOF
SYSTEMMANAGER_AUTH_MODE=token
SYSTEMMANAGER_REQUIRE_AUTH=true
SYSTEMMANAGER_SHARED_SECRET=$SHARED_SECRET
LOG_LEVEL=INFO
EOF

fi

chmod 600 $INSTALL_DIR/.env
msg_ok "Configured Authentication ($AUTH_MODE)"

msg_info "Creating Inventory Directory"
mkdir -p /var/lib/systemmanager
chown root:root /var/lib/systemmanager
chmod 755 /var/lib/systemmanager
msg_ok "Created Inventory Directory"

msg_info "Creating Systemd Service"
cat > /etc/systemd/system/systemmanager-mcp.service << EOF
[Unit]
Description=TailOpsMCP - Secure MCP control surface for Tailscale homelabs
Documentation=https://github.com/mdlmarkham/TailOpsMCP
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Load secrets from protected environment file
EnvironmentFile=$INSTALL_DIR/.env

ExecStart=$INSTALL_DIR/venv/bin/python -m src.mcp_server
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$INSTALL_DIR /var/lib/systemmanager
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

$STD systemctl daemon-reload
$STD systemctl enable systemmanager-mcp.service
msg_ok "Created Systemd Service"

msg_info "Starting SystemManager MCP Server"
systemctl start systemmanager-mcp.service
sleep 3

if systemctl is-active --quiet systemmanager-mcp.service; then
  msg_ok "SystemManager MCP Server Started"
else
  msg_error "Failed to start service. Check logs: journalctl -u systemmanager-mcp -n 50"
  exit 1
fi

motd_ssh
customize

msg_info "Cleaning up"
$STD apt-get -y autoremove
$STD apt-get -y autoclean
msg_ok "Cleaned"

echo ""
echo -e "\e[1;32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo -e "\e[1;32m  ✓ Installation Complete!\e[0m"
echo -e "\e[1;32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\e[0m"
echo ""
echo -e "\e[1;36mInstallation Summary:\e[0m"
echo "  • Location:   $INSTALL_DIR"
echo "  • Service:    systemmanager-mcp"
echo "  • Auth Mode:  $AUTH_MODE"
if [[ $AUTH_MODE == "oidc" ]]; then
  echo "  • Server URL: $BASE_URL"
fi
echo ""
echo -e "\e[1;36mNext Steps:\e[0m"
echo ""
echo "  1. Check status:  systemctl status systemmanager-mcp"
echo "  2. View logs:     journalctl -u systemmanager-mcp -f"
echo "  3. Test server:   curl http://localhost:8080/.well-known/oauth-protected-resource/mcp"
echo ""
if [[ $AUTH_MODE == "oidc" ]]; then
  echo "  4. Configure MCP client with OAuth"
  echo "     URL: $BASE_URL/mcp"
else
  echo "  4. Configure MCP client with token: $SHARED_SECRET"
fi
echo ""
echo -e "\e[1;36mUseful Commands:\e[0m"
echo "  • Restart:  systemctl restart systemmanager-mcp"
echo "  • Stop:     systemctl stop systemmanager-mcp"
echo "  • Logs:     journalctl -u systemmanager-mcp -n 100"
echo "  • Config:   nano $INSTALL_DIR/.env"
echo ""
echo -e "\e[1;33mDocumentation:\e[0m https://github.com/mdlmarkham/SystemManager"
echo ""
