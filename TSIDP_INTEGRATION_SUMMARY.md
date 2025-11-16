# SystemManager TSIDP Integration - Summary

## What Changed

**Before:** Manual HMAC token authentication
- Generate tokens with shared secret
- Manually sign claims
- Update mcp.json with long token strings
- Tokens expire, need regeneration

**After:** TSIDP OAuth 2.1 authentication
- Server auto-registers with TSIDP
- Standard OAuth flow
- Automatic token refresh
- User identity tracked

## Implementation

### Server Changes

**File:** `src/mcp_server.py`
- Added OAuth mode detection via `SYSTEMMANAGER_AUTH_MODE`
- Integrated `RemoteOAuthProvider` from FastMCP
- Auto-discovery of TSIDP endpoints
- Dynamic Client Registration (DCR)

**New Environment Variables:**
```bash
SYSTEMMANAGER_AUTH_MODE=oauth           # Enable OAuth mode
SYSTEMMANAGER_AUTH_SERVER=https://tsidp.tailf9480.ts.net  # Your TSIDP URL
SYSTEMMANAGER_CLIENT_NAME=...          # Optional client name
SYSTEMMANAGER_REQUIRED_SCOPES=...      # Optional scopes
```

### Client Changes

**File:** `mcp.json`

**Old (Token Mode):**
```json
{
  "Dev1-SystemManager": {
    "type": "sse",
    "url": "http://dev1.tailf9480.ts.net:8080/sse",
    "headers": {
      "Authorization": "Bearer {\"agent\":\"copilot-dev\"...}.f51622..."
    }
  }
}
```

**New (OAuth Mode):**
```json
{
  "Dev1-SystemManager": {
    "type": "sse",
    "url": "https://dev1.tailf9480.ts.net:8080/sse"
  }
}
```

## Features Enabled

### OAuth 2.1 Standards
- ✅ **RFC 7591** - Dynamic Client Registration
- ✅ **RFC 7662** - Token Introspection  
- ✅ **RFC 8693** - Token Exchange (optional)
- ✅ **RFC 9728** - Protected Resource Metadata

### Discovery Endpoints
- `/.well-known/oauth-protected-resource` - Resource metadata
- Automatic discovery of TSIDP authorization server
- No manual endpoint configuration needed

### Security
- Tokens validated in real-time via introspection
- Automatic revocation checking
- Scope-based access control
- Audience validation

## Migration Path

### Phase 1: Dual Mode (Current)
Both authentication modes work:
- Set `SYSTEMMANAGER_AUTH_MODE=oauth` for new OAuth mode
- Set `SYSTEMMANAGER_AUTH_MODE=token` for legacy mode (default)

### Phase 2: Test OAuth (Next)
1. Deploy server with OAuth mode
2. Update mcp.json to remove token
3. Test all MCP tools
4. Verify user identity in logs

### Phase 3: Deprecate Tokens (Future)
1. Remove HMAC token middleware
2. Remove `@secure_tool` decorators
3. OAuth becomes the only mode

## Files Added

1. **src/auth/tailscale_auth.py** - Tailscale identity middleware (for serve mode)
2. **docs/TSIDP_AUTH_GUIDE.md** - Complete OAuth integration guide
3. **TSIDP_QUICKSTART.md** - Quick start instructions
4. **docker-compose.tailscale.yml** - Docker Compose with Tailscale serve
5. **config/serve.json** - Tailscale serve configuration

## Files Modified

1. **src/mcp_server.py** - Added OAuth provider integration
2. **README.md** - Updated authentication section (pending)

## Testing Checklist

- [ ] Start server with `SYSTEMMANAGER_AUTH_MODE=oauth`
- [ ] Verify Dynamic Client Registration succeeds
- [ ] Check client credentials saved to `~/.systemmanager/oauth-client.json`
- [ ] Update mcp.json (remove token)
- [ ] Restart VS Code / Claude Desktop
- [ ] Test MCP tool call (e.g., `get_system_status`)
- [ ] Verify OAuth flow (browser opens for auth)
- [ ] Check token refresh works automatically
- [ ] Verify user identity in server logs

## Next Steps

1. **Deploy to dev1:**
   ```bash
   git pull
   pip install -r requirements.txt
   export SYSTEMMANAGER_AUTH_MODE=oauth
   export SYSTEMMANAGER_AUTH_SERVER=https://tsidp.tailf9480.ts.net
   python -m src.mcp_server
   ```

2. **Update Client:**
   - Edit `mcp.json`
   - Remove `headers` section
   - Restart VS Code

3. **Test:**
   - Call an MCP tool
   - Authenticate via browser
   - Verify it works

4. **Monitor:**
   - Check logs for OAuth flow
   - Verify token refresh
   - Confirm user identity tracking

## Rollback Plan

If OAuth mode has issues:

```bash
# Revert to token mode
export SYSTEMMANAGER_AUTH_MODE=token
export SYSTEMMANAGER_SHARED_SECRET=dev-secret-key-change-in-production

# Restart server
python -m src.mcp_server

# Restore mcp.json with Authorization header
```

## Documentation

- **Full Guide:** `docs/TSIDP_AUTH_GUIDE.md`
- **Quick Start:** `TSIDP_QUICKSTART.md`
- **TSIDP Project:** https://github.com/tailscale/tsidp
- **FastMCP OAuth:** https://fastmcp.wiki/en/servers/auth/authentication

## Benefits Summary

| Feature | Token Mode | OAuth Mode |
|---------|-----------|------------|
| **Setup Complexity** | Generate tokens manually | Automatic registration |
| **Token Management** | Manual refresh | Automatic refresh |
| **User Identity** | Generic agent name | Real Tailscale user |
| **Revocation** | Delete token file | Instant via introspection |
| **Audit Trail** | Basic logging | Full OAuth audit |
| **Standards** | Custom HMAC | OAuth 2.1 RFCs |
| **Client Support** | Any HTTP client | OAuth-aware clients |

## Conclusion

TSIDP integration transforms SystemManager from custom token auth to enterprise-grade OAuth 2.1, leveraging your existing Tailscale identity infrastructure. No more "pesky tokens" - just standard OAuth flows with automatic everything.
