# Quick Start - TSIDP Authentication

## Update mcp.json

Replace your existing token-based config:

```json
{
  "Dev1-TailOpsMCP": {
    "type": "sse",
    "url": "https://dev1.tailf9480.ts.net:8080/sse"
  }
}
```

That's it! No more tokens to manage.

## Start Server with OAuth

```bash
ssh dev1.tailf9480.ts.net

cd /opt/systemmanager

# Stop old server
sudo pkill -f "python -m src.mcp_server"

# Start with OAuth
export SYSTEMMANAGER_AUTH_MODE=oauth
export SYSTEMMANAGER_AUTH_SERVER=https://tsidp.tailf9480.ts.net

./venv/bin/python -m src.mcp_server
```

## What Happens

1. **Server starts** and discovers your TSIDP endpoints
2. **Auto-registers** as an OAuth client (one-time)
3. **Client connects** and is redirected to TSIDP for auth
4. **You authenticate** via Tailscale (browser opens)
5. **Token is issued** and automatically refreshed
6. **MCP calls work** with your Tailscale identity

## Benefits

✅ No manual token generation
✅ Automatic token refresh  
✅ Real user identity tracking
✅ Centralized access control via TSIDP
✅ Standard OAuth 2.1 flow
✅ Works with any OAuth-aware MCP client

## Troubleshooting

### Check TSIDP is Running

```bash
curl https://tsidp.tailf9480.ts.net/.well-known/openid-configuration
```

Should return TSIDP metadata with endpoints.

### View Server Logs

```bash
tail -f /opt/systemmanager/logs/mcp_server.log
```

Look for:
- "Using TSIDP OAuth 2.1 authentication"
- "Dynamic Client Registration successful"
- "Client ID: ..." 

### Reset OAuth Registration

```bash
# Remove cached client credentials
rm ~/.systemmanager/oauth-client.json

# Restart server (will re-register)
./venv/bin/python -m src.mcp_server
```
