# TSIDP OIDC Integration - Complete Guide

## Overview

SystemManager now supports **true TSIDP OIDC authentication**! This uses TSIDP as a standard OpenID Connect provider, giving you:

- ✅ **Zero-trust SSO** via Tailscale identity
- ✅ **No manual token management**
- ✅ **Standard OIDC flow** (works with any OIDC client)
- ✅ **Real user identity** in logs and audit trails
- ✅ **Automatic token refresh**

## Quick Setup (5 Minutes)

### 1. Register in TSIDP Admin UI

Open `https://tsidp.tailf9480.ts.net` and create a new OIDC client:

| Field | Value |
|-------|-------|
| Client Name | `SystemManager` |
| Redirect URI | `http://dev1.tailf9480.ts.net:8080/auth/callback` |
| Grant Types | `authorization_code`, `refresh_token` |
| Scopes | `openid`, `email`, `profile` |

Save and copy the **Client ID** and **Client Secret**.

### 2. Configure Server

```bash
ssh dev1.tailf9480.ts.net
cd /opt/systemmanager

# Create environment file
cat > .env.oidc << EOF
export SYSTEMMANAGER_AUTH_MODE=oidc
export TSIDP_URL=https://tsidp.tailf9480.ts.net
export TSIDP_CLIENT_ID=your-client-id-here
export TSIDP_CLIENT_SECRET=your-client-secret-here
export SYSTEMMANAGER_BASE_URL=http://dev1.tailf9480.ts.net:8080
EOF

# Load configuration
source .env.oidc

# Start server
./venv/bin/python -m src.mcp_server
```

### 3. Update Client (mcp.json)

Remove the `Authorization` header - OIDC handles auth:

```json
{
  "Dev1-SystemManager": {
    "type": "sse",
    "url": "http://dev1.tailf9480.ts.net:8080/sse",
    "description": "SystemManager MCP with TSIDP OIDC"
  }
}
```

### 4. Test It

1. Restart VS Code
2. Call any MCP tool
3. Browser opens → TSIDP login
4. Authenticate with Tailscale
5. Tools work with your identity!

## How It Works

```
┌─────────┐          ┌───────────────┐          ┌──────┐
│ VS Code │──────────│ SystemManager │──────────│ TSIDP│
│ Client  │          │  MCP Server   │          │ OIDC │
└─────────┘          └───────────────┘          └──────┘
     │                       │                      │
     │  1. Connect to MCP    │                      │
     ├──────────────────────>│                      │
     │                       │                      │
     │  2. Redirect to OIDC  │                      │
     │<──────────────────────┤                      │
     │                       │                      │
     │  3. Authenticate user │                      │
     ├───────────────────────────────────────────> │
     │                       │                      │
     │  4. Authorization code│                      │
     │<──────────────────────────────────────────── │
     │                       │                      │
     │  5. Exchange for token│                      │
     ├──────────────────────>│──────────────────────>│
     │                       │                      │
     │  6. Access token      │                      │
     │<──────────────────────│<───────────────────── │
     │                       │                      │
     │  7. MCP calls + token │                      │
     ├──────────────────────>│                      │
     │                       │  8. Validate token   │
     │                       │─────────────────────>│
     │                       │<───────────────────── │
     │  9. Response          │                      │
     │<──────────────────────┤                      │
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SYSTEMMANAGER_AUTH_MODE` | Yes | `token` | Set to `oidc` |
| `TSIDP_URL` | Yes | - | TSIDP server URL |
| `TSIDP_CLIENT_ID` | Yes | - | From TSIDP admin |
| `TSIDP_CLIENT_SECRET` | Yes | - | From TSIDP admin |
| `SYSTEMMANAGER_BASE_URL` | Yes | - | This server's URL |

## Production Deployment

For production, use systemd to manage the service:

```bash
# Create systemd service
sudo tee /etc/systemd/system/systemmanager-mcp-oidc.service << EOF
[Unit]
Description=SystemManager MCP Server with TSIDP OIDC
After=network.target

[Service]
Type=simple
User=systemmanager
WorkingDirectory=/opt/systemmanager
Environment=SYSTEMMANAGER_AUTH_MODE=oidc
Environment=TSIDP_URL=https://tsidp.tailf9480.ts.net
Environment=TSIDP_CLIENT_ID=your-client-id
Environment=TSIDP_CLIENT_SECRET=your-client-secret
Environment=SYSTEMMANAGER_BASE_URL=http://dev1.tailf9480.ts.net:8080
ExecStart=/opt/systemmanager/venv/bin/python -m src.mcp_server
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable systemmanager-mcp-oidc
sudo systemctl start systemmanager-mcp-oidc

# Check status
sudo systemctl status systemmanager-mcp-oidc
```

## Comparison: Token vs OIDC

| Feature | Token Auth | OIDC Auth |
|---------|-----------|-----------|
| Setup Complexity | Manual token generation | One-time TSIDP registration |
| User Identity | Generic agent name | Real Tailscale user |
| Token Refresh | Manual regeneration | Automatic via OIDC |
| Revocation | Delete token file | Instant via TSIDP |
| Audit Trail | Basic logging | Full OIDC audit + user identity |
| Standards | Custom HMAC | OpenID Connect / OAuth 2.0 |
| Zero Trust | Partial | Full (via Tailscale) |

## Troubleshooting

### Server won't start with OIDC

```bash
# Check FastMCP has OIDC provider support
./venv/bin/python -c "from fastmcp.server.auth.providers.oidc import OIDCProvider; print('OIDC supported!')"

# If not found, update FastMCP
./venv/bin/pip install --upgrade fastmcp
```

### TSIDP not accessible

```bash
# Verify Tailscale
tailscale status | grep tsidp

# Check OIDC discovery
curl https://tsidp.tailf9480.ts.net/.well-known/openid-configuration | jq .
```

### Redirect URI mismatch

Error: `redirect_uri_mismatch`

**Fix**: In TSIDP admin, ensure redirect URI is exactly:
```
http://dev1.tailf9480.ts.net:8080/auth/callback
```

### Token validation fails

```bash
# Check logs
tail -f /opt/systemmanager/logs/mcp_server.log

# Verify client secret matches TSIDP
echo $TSIDP_CLIENT_SECRET
```

## Migration from Token Auth

Current token-based setup will continue working. To migrate:

1. **Register in TSIDP** (5 min)
2. **Update server env vars** (set OIDC mode)
3. **Update mcp.json** (remove auth header)
4. **Restart server and VS Code**
5. **Test** - authenticate via browser

You can switch back anytime by setting `SYSTEMMANAGER_AUTH_MODE=token`.

## Security Notes

- **Client Secret**: Treat as sensitive - store in secure env vars or secrets manager
- **HTTPS**: For production, use HTTPS endpoints (Tailscale HTTPS certificates)
- **Scopes**: Request minimum required scopes (`openid email profile`)
- **Audience**: TSIDP validates the audience claim matches your server
- **Network**: TSIDP requires Tailscale network access (zero-trust boundary)

## References

- [TSIDP Documentation](https://github.com/tailscale/tsidp)
- [TSIDP Blog: Building an IdP](https://tailscale.com/blog/building-tsidp)
- [FastMCP OIDC Authentication](https://gofastmcp.com/servers/auth/authentication)
- [OpenID Connect Specification](https://openid.net/specs/openid-connect-core-1_0.html)
