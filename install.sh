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
        python3.11 \
        python3.11-venv \
        python3-pip \
        git \
        curl \
        build-essential
elif [[ "$OS" == "centos" ]] || [[ "$OS" == "rhel" ]] || [[ "$OS" == "fedora" ]]; then
    yum install -y \
        python3.11 \
        python3-pip \
        git \
        curl \
        gcc
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
sudo -u systemmanager python3.11 -m venv venv
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

echo ""
echo "=================================================="
echo "✓ Installation Complete!"
echo "=================================================="
echo ""
echo "Next steps:"
echo "1. Update security token in /etc/systemmanager/config.yaml"
echo "2. Restart service: systemctl restart systemmanager-mcp"
echo "3. Check status: systemctl status systemmanager-mcp"
echo "4. View logs: journalctl -u systemmanager-mcp -f"
echo ""
echo "Test the server:"
echo "  TOKEN='dev-test-token-12345'"
echo "  curl -H 'Authorization: Bearer \$TOKEN' http://localhost:8080/health"
echo ""
echo "Documentation:"
echo "  - Configuration: /etc/systemmanager/config.yaml"
echo "  - Logs: /var/log/systemmanager/mcp.log"
echo "  - Service: systemctl {start|stop|restart} systemmanager-mcp"
echo ""
