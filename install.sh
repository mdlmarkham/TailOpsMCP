#!/bin/bash
# SystemManager MCP Server - Automated Linux Installation Script
# Usage: bash install.sh

set -e

echo "=================================================="
echo "SystemManager MCP Server - Installation"
echo "=================================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use: sudo bash install.sh)"
   exit 1
fi

# Detect Linux distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    echo "Cannot detect Linux distribution"
    exit 1
fi

echo "Detected OS: $OS $VERSION"

# Install system dependencies based on distribution
echo "Installing system dependencies..."

if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
    apt-get update
    apt-get install -y \
        python3 \
        python3-venv \
        python3-pip \
        git \
        curl \
        build-essential
    PYTHON_CMD="python3"
elif [[ "$OS" == "centos" ]] || [[ "$OS" == "rhel" ]] || [[ "$OS" == "fedora" ]]; then
    yum install -y \
        python3 \
        python3-pip \
        git \
        curl \
        gcc
    PYTHON_CMD="python3"
else
    echo "Unsupported OS: $OS"
    exit 1
fi

# Create system user
echo "Creating systemmanager user..."
if ! id -u systemmanager > /dev/null 2>&1; then
    useradd -r -s /bin/bash -d /opt/systemmanager -m systemmanager
    echo "Created user: systemmanager"
else
    echo "User systemmanager already exists"
fi

# Create directories
echo "Creating directories..."
mkdir -p /opt/systemmanager
mkdir -p /var/log/systemmanager
mkdir -p /etc/systemmanager

# Clone/pull repository
echo "Cloning repository..."
if [ -d /opt/systemmanager/.git ]; then
    echo "Repository already exists, pulling latest..."
    cd /opt/systemmanager
    sudo -u systemmanager git pull origin master
else
    cd /tmp
    sudo -u systemmanager git clone https://github.com/mdlmarkham/SystemManager.git /opt/systemmanager
    cd /opt/systemmanager
fi

# Setup Python virtual environment
echo "Setting up Python virtual environment..."
cd /opt/systemmanager
sudo -u systemmanager $PYTHON_CMD -m venv venv
sudo -u systemmanager venv/bin/pip install --upgrade pip
sudo -u systemmanager venv/bin/pip install -r requirements.txt

# Create configuration file
echo "Creating configuration file..."
if [ ! -f /etc/systemmanager/config.yaml ]; then
    cat > /etc/systemmanager/config.yaml << 'EOF'
server:
  host: "0.0.0.0"
  port: 8080
  transport: "http-sse"
  auth_required: true

security:
  auth_tokens:
    - "dev-test-token-12345"
  rate_limit: 100
  max_file_size: 10485760

logging:
  level: "INFO"
  file: "/var/log/systemmanager/mcp.log"

docker:
  socket_path: "/var/run/docker.sock"

filesystem:
  allowed_paths:
    - "/var/log"
    - "/tmp"
    - "/home"
EOF
    echo "Configuration created at /etc/systemmanager/config.yaml"
    echo "⚠️  IMPORTANT: Update the auth token in config.yaml with a secure value"
else
    echo "Configuration already exists at /etc/systemmanager/config.yaml"
fi

# Set permissions
echo "Setting permissions..."
chown -R systemmanager:systemmanager /opt/systemmanager
chown -R systemmanager:systemmanager /var/log/systemmanager
chown -R systemmanager:systemmanager /etc/systemmanager
chmod 755 /var/log/systemmanager
chmod 755 /etc/systemmanager

# Install systemd service
echo "Installing systemd service..."
cp /opt/systemmanager/deploy/systemd/systemmanager-mcp.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable systemmanager-mcp

# Test installation
echo ""
echo "Testing installation..."
cd /opt/systemmanager
sudo -u systemmanager venv/bin/python -c "import src.mcp_server; print('✓ Import successful')"

# Start service
echo ""
echo "Starting systemmanager-mcp service..."
systemctl start systemmanager-mcp

# Wait and check status
sleep 2
if systemctl is-active --quiet systemmanager-mcp; then
    echo "✓ Service started successfully"
else
    echo "✗ Service failed to start. Check logs:"
    echo "  journalctl -u systemmanager-mcp -n 20"
    exit 1
fi

# Verify health endpoint
echo ""
echo "Verifying health endpoint..."
if curl -s http://localhost:8080/health > /dev/null 2>&1; then
    echo "✓ Health endpoint responding"
    curl -s http://localhost:8080/health | python3 -m json.tool
else
    echo "⚠️  Health endpoint not responding yet. Wait a moment and try:"
    echo "  curl http://localhost:8080/health"
fi

# Optional: Setup Tailscale Services
echo ""
echo "Optional: Tailscale Services Integration"
echo "=========================================="
read -p "Do you want to set up Tailscale Services for service discovery? (y/N) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if command -v tailscale &> /dev/null; then
        echo "Setting up Tailscale Services..."
        
        # Check if device is tagged
        TAGS=$(sudo -u systemmanager tailscale status --json 2>/dev/null | python3 -c "import sys, json; data=json.load(sys.stdin); print(','.join(data.get('Self',{}).get('Tags',[])))" || echo "")
        
        if [ -z "$TAGS" ]; then
            echo "⚠️  WARNING: This device is not tagged!"
            echo "   Tailscale Services require tag-based identity."
            echo "   Please tag this device in Tailscale admin console first."
            echo "   Visit: https://login.tailscale.com/admin/machines"
            echo ""
            echo "   Skipping Tailscale Services setup. You can run it later:"
            echo "   sudo /opt/systemmanager/scripts/setup_tailscale_service.sh"
        else
            echo "✓ Device has tags: $TAGS"
            
            # Run setup script
            if [ -f /opt/systemmanager/scripts/setup_tailscale_service.sh ]; then
                chmod +x /opt/systemmanager/scripts/setup_tailscale_service.sh
                sudo -u systemmanager /opt/systemmanager/scripts/setup_tailscale_service.sh
                
                echo ""
                echo "📋 Tailscale Services Next Steps:"
                echo "1. Define service in admin console: https://login.tailscale.com/admin/services"
                echo "2. Approve this host as a service host"
                echo "3. Access via: http://systemmanager-mcp.<tailnet>.ts.net:8080/sse"
                echo ""
                echo "Documentation: /opt/systemmanager/TAILSCALE_SERVICES.md"
            else
                echo "⚠️  Setup script not found. Skipping Tailscale Services setup."
            fi
        fi
    else
        echo "⚠️  Tailscale not installed. Skipping Tailscale Services setup."
        echo "   Install Tailscale: https://tailscale.com/download"
        echo "   Then run: sudo /opt/systemmanager/scripts/setup_tailscale_service.sh"
    fi
fi

echo ""
echo "=================================================="
echo "✓ Installation Complete!"
echo "=================================================="
echo ""
echo "Service Status:"
systemctl status systemmanager-mcp --no-pager | head -10
echo ""
echo "Next Steps:"
echo "==========="
echo "1. 🔐 Update security token in /etc/systemmanager/config.yaml"
echo "   sed -i 's/dev-test-token-12345/YOUR_SECURE_TOKEN/' /etc/systemmanager/config.yaml"
echo "   systemctl restart systemmanager-mcp"
echo ""
echo "2. 🧪 Test the server:"
echo "   curl -H 'Authorization: Bearer YOUR_TOKEN' http://localhost:8080/sse"
echo ""
echo "3. 📡 (Optional) Set up Tailscale Services:"
echo "   sudo /opt/systemmanager/scripts/setup_tailscale_service.sh"
echo "   See: TAILSCALE_SERVICES.md for details"
echo ""
echo "Documentation:"
echo "=============="
echo "  📝 Main: README.md"
echo "  🔧 Configuration: /etc/systemmanager/config.yaml"
echo "  📊 TOON Format: TOON_INTEGRATION.md (15-40% token savings)"
echo "  🌐 Tailscale: TAILSCALE_SERVICES.md (zero-config discovery)"
echo "  📜 Logs: /var/log/systemmanager/mcp.log"
echo "  🔄 Service: systemctl {start|stop|restart|status} systemmanager-mcp"
echo "  📋 Journal: journalctl -u systemmanager-mcp -f"
echo ""
