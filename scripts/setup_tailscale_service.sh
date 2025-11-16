#!/bin/bash
# Setup SystemManager MCP as Tailscale Service
# Run this on your MCP server host (e.g., dev1.tailf9480.ts.net)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "🔧 SystemManager MCP - Tailscale Services Setup"
echo "=" "=" | tr -d ' '
echo ""

# Check if Tailscale is installed and running
if ! command -v tailscale &> /dev/null; then
    echo "❌ Tailscale not found. Please install Tailscale first."
    echo "   Visit: https://tailscale.com/download"
    exit 1
fi

if ! tailscale status &> /dev/null; then
    echo "❌ Tailscale is not running. Please start Tailscale and authenticate."
    exit 1
fi

echo "✅ Tailscale is running"
echo ""

# Check if device is tagged (required for service hosts)
TAGS=$(tailscale status --json | jq -r '.Self.Tags // [] | join(", ")')
if [ -z "$TAGS" ] || [ "$TAGS" == "null" ]; then
    echo "⚠️  WARNING: This device is not tagged!"
    echo "   Tailscale Services require tag-based identity."
    echo ""
    echo "   To fix this:"
    echo "   1. Go to https://login.tailscale.com/admin/machines"
    echo "   2. Find this device and add a tag (e.g., 'tag:server' or 'tag:systemmanager')"
    echo "   3. Update your ACL to define the tag"
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    echo "✅ Device tags: $TAGS"
    echo ""
fi

# Check if service is already configured
if tailscale serve status --json 2>/dev/null | jq -e '.services."svc:systemmanager-mcp"' > /dev/null 2>&1; then
    echo "ℹ️  Service already configured:"
    echo ""
    tailscale serve status
    echo ""
    read -p "Reconfigure? (y/N) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
    
    echo "🧹 Clearing existing configuration..."
    tailscale serve clear svc:systemmanager-mcp
fi

# Check if MCP server is running locally
echo "🔍 Checking if MCP server is running on localhost:8080..."
if ! nc -z localhost 8080 2>/dev/null && ! curl -s http://localhost:8080 > /dev/null 2>&1; then
    echo "⚠️  WARNING: No service detected on localhost:8080"
    echo "   Make sure SystemManager MCP server is running before proceeding."
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Start the MCP server first, then run this script again."
        exit 1
    fi
else
    echo "✅ MCP server is running on localhost:8080"
    echo ""
fi

# Configure the Tailscale Service
echo "📡 Configuring Tailscale Service: svc:systemmanager-mcp"
echo "   Endpoint: tcp:8080 → localhost:8080"
echo ""

# Use --tls-terminated-tcp for layer 4 TCP forwarding
tailscale serve \
    --service=svc:systemmanager-mcp \
    --tls-terminated-tcp=8080 \
    tcp://localhost:8080

echo ""
echo "✅ Service configured successfully!"
echo ""

# Check service status
echo "📊 Service Status:"
tailscale serve status
echo ""

# Check if approved
echo "🔐 Checking approval status..."
SERVICE_HOST_STATUS=$(tailscale status --json | jq -r '.Self.CapMap."service-host" // "not configured"')

if [ "$SERVICE_HOST_STATUS" == "not configured" ]; then
    echo "⏳ Service host capability not yet active."
    echo ""
    echo "📋 Next Steps:"
    echo ""
    echo "1. 📝 Define the service in Tailscale admin console (if not already done):"
    echo "   https://login.tailscale.com/admin/services"
    echo "   - Click 'Advertise' → 'Define a Service'"
    echo "   - Name: systemmanager-mcp"
    echo "   - Endpoints: tcp:8080"
    echo "   - (Optional) Tags: tag:systemmanager"
    echo ""
    echo "2. ✅ Approve this host:"
    echo "   - Go to: https://login.tailscale.com/admin/services"
    echo "   - Find 'systemmanager-mcp'"
    echo "   - Click the service name"
    echo "   - Approve pending host"
    echo ""
    echo "3. 🔌 Update your MCP client configuration:"
    echo "   Replace: http://dev1.tailf9480.ts.net:8080/sse"
    echo "   With:    http://systemmanager-mcp.<your-tailnet>.ts.net:8080/sse"
    echo ""
    echo "4. 🧪 Test access:"
    echo "   curl http://systemmanager-mcp.<your-tailnet>.ts.net:8080/sse"
else
    echo "✅ Service host is active!"
    echo ""
    
    # Try to detect tailnet name
    TAILNET_NAME=$(tailscale status --json | jq -r '.MagicDNSSuffix' | sed 's/\\.$//')
    
    if [ -n "$TAILNET_NAME" ] && [ "$TAILNET_NAME" != "null" ]; then
        SERVICE_URL="http://systemmanager-mcp.${TAILNET_NAME}:8080/sse"
        echo "🌐 Service URL: $SERVICE_URL"
        echo ""
        echo "🧪 Test with:"
        echo "   curl -v $SERVICE_URL"
    else
        echo "🌐 Service URL: http://systemmanager-mcp.<your-tailnet>.ts.net:8080/sse"
        echo "   (Replace <your-tailnet> with your actual tailnet name)"
    fi
    echo ""
    echo "✅ Setup complete! Service is ready to use."
fi

echo ""
echo "💡 Tip: Set up auto-approval to avoid manual approval for future hosts:"
echo "   Add to your ACL policy:"
echo "   \"autoApprovers\": {"
echo "     \"services\": {"
echo "       \"svc:systemmanager-mcp\": [\"tag:server\", \"tag:systemmanager\"]"
echo "     }"
echo "   }"
echo ""
