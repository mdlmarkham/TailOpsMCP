#!/bin/bash
# Secure deployment script for SystemManager MCP Server
# Implements security recommendations from log analysis

set -e

echo "=== SystemManager MCP Server - Secure Deployment ==="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
   echo "ERROR: This script must be run as root"
   exit 1
fi

INSTALL_DIR="/opt/systemmanager"
ENV_FILE="$INSTALL_DIR/.env"

# Step 1: Create environment file if it doesn't exist
if [ ! -f "$ENV_FILE" ]; then
    echo "📝 Creating environment file..."
    cp "$INSTALL_DIR/deploy/.env.template" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    echo "⚠️  IMPORTANT: Edit $ENV_FILE and add your secrets"
    echo "   Then run this script again."
    exit 0
fi

# Verify environment file permissions
ENV_PERMS=$(stat -c "%a" "$ENV_FILE")
if [ "$ENV_PERMS" != "600" ]; then
    echo "⚠️  Fixing environment file permissions..."
    chmod 600 "$ENV_FILE"
fi

# Step 2: Stop any running background processes
echo "🛑 Stopping any existing server processes..."
pkill -f 'python.*mcp_server' 2>/dev/null || echo "   No processes to stop"
sleep 2

# Step 3: Clean Python cache
echo "🧹 Cleaning Python cache..."
cd "$INSTALL_DIR"
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find . -name '*.pyc' -delete 2>/dev/null || true

# Step 4: Install systemd service
echo "📦 Installing systemd service..."
cp "$INSTALL_DIR/deploy/systemd/systemmanager-mcp.service" /etc/systemd/system/
systemctl daemon-reload

# Step 5: Enable and start service
echo "🚀 Starting SystemManager MCP Server..."
systemctl enable systemmanager-mcp.service
systemctl restart systemmanager-mcp.service

# Step 6: Check status
sleep 2
echo ""
echo "✅ Deployment complete!"
echo ""
echo "Service status:"
systemctl status systemmanager-mcp.service --no-pager -l
echo ""
echo "📊 Commands:"
echo "   Status:  sudo systemctl status systemmanager-mcp"
echo "   Logs:    sudo journalctl -u systemmanager-mcp -f"
echo "   Restart: sudo systemctl restart systemmanager-mcp"
echo "   Stop:    sudo systemctl stop systemmanager-mcp"
