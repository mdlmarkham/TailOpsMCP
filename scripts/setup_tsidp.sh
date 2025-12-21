#!/bin/bash
# TSIDP Setup Script for SystemManager MCP Server

echo "=== SystemManager TSIDP OIDC Setup ==="
echo ""

# Step 1: Verify TSIDP is accessible
TSIDP_URL="${TSIDP_URL:-https://tsidp.tailf9480.ts.net}"
echo "1. Checking TSIDP at $TSIDP_URL..."

if curl -sf "$TSIDP_URL/.well-known/openid-configuration" > /dev/null; then
    echo "   ✓ TSIDP is accessible"
else
    echo "   ✗ TSIDP not accessible. Check your Tailscale connection."
    exit 1
fi

# Step 2: Register client in TSIDP
echo ""
echo "2. Register SystemManager as OIDC client in TSIDP:"
echo "   - Open: $TSIDP_URL"
echo "   - Go to 'Clients' or 'Add Client'"
echo "   - Client Name: SystemManager MCP"

# Add base URL environment variable support
SYSTEMMANAGER_BASE_URL="${SYSTEMMANAGER_BASE_URL:-http://localhost:8080}"
echo "   - Redirect URI: $SYSTEMMANAGER_BASE_URL/auth/callback"
echo "   - Grant Types: authorization_code, refresh_token"
echo "   - Scopes: openid, email, profile"
echo ""
echo "   After registration, you'll receive:"
echo "   - Client ID"
echo "   - Client Secret"
echo ""

read -p "Press Enter when you have the Client ID and Secret..."

# Step 3: Configure environment
echo ""
echo "3. Enter your TSIDP credentials:"
read -p "Client ID: " CLIENT_ID
read -sp "Client Secret: " CLIENT_SECRET
echo ""

# Step 4: Create/update .env file
echo ""
echo "4. Creating environment configuration..."

cat > .env.oidc << EOF
# TSIDP OIDC Configuration
SYSTEMMANAGER_AUTH_MODE=oidc
TSIDP_URL=$TSIDP_URL
TSIDP_CLIENT_ID=$CLIENT_ID
TSIDP_CLIENT_SECRET=$CLIENT_SECRET
SYSTEMMANAGER_BASE_URL=$SYSTEMMANAGER_BASE_URL
EOF

echo "   ✓ Configuration saved to .env.oidc"
echo ""

# Step 5: Instructions
echo "=== Setup Complete ==="
echo ""
echo "To start the server with OIDC authentication:"
echo ""
echo "  source .env.oidc"
echo "  ./venv/bin/python -m src.mcp_server"
echo ""
echo "Your mcp.json should be:"
echo ""
cat << JSONEOF
{
  "Dev1-SystemManager": {
    "type": "sse",
    "url": "$SYSTEMMANAGER_BASE_URL/sse",
    "description": "SystemManager MCP Server with TSIDP OIDC"
  }
}
JSONEOF
echo ""
echo "When you connect, you'll be redirected to TSIDP to authenticate"
echo "with your Tailscale identity. No tokens needed!"
