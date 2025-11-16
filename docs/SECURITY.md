# Security Model for Tailnet Deployments

## Overview

# Security Architecture

TailOpsMCP implements **defense-in-depth** security for tailnet deployments:

1. **Network Layer**: Tailscale ACLs control WHO can reach the server
2. **Application Layer**: Bearer tokens + scopes control WHAT they can do
3. **Audit Layer**: Comprehensive logging tracks WHO did WHAT

**Critical**: Tailnet membership ≠ root access. Both layers are required.

## Trust Model

```
┌─────────────────────────────────────────────────────────────┐
│ Threat: Compromised Tailnet Node or Leaked Tailscale Key   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Defense Layer 1: Tailscale ACLs (Network-Level)            │
│ - Tag-based access: only tag:systemmanager-client can      │
│   connect to svc:systemmanager-mcp                          │
│ - Least privilege: minimize who can tag devices            │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼ (if attacker gets network access)
┌─────────────────────────────────────────────────────────────┐
│ Defense Layer 2: Application Auth (Bearer Tokens + Scopes) │
│ - Valid token required for all operations                  │
│ - Scope-based RBAC: readonly vs admin vs critical          │
│ - Token expiry enforced                                    │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼ (if attacker gets token)
┌─────────────────────────────────────────────────────────────┐
│ Defense Layer 3: Approval Gates (High-Risk Operations)     │
│ ⚠️  REQUIRES EXTERNAL WEBHOOK - NOT IMPLEMENTED BY DEFAULT │
│ - Set SYSTEMMANAGER_APPROVAL_WEBHOOK to enable             │
│ - Without webhook: approval-required ops are DENIED         │
│ - Examples: install_package, update_docker_container       │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼ (all operations)
┌─────────────────────────────────────────────────────────────┐
│ Defense Layer 4: Audit Trail (Lateral Movement Detection)  │
│ - Every tool invocation logged with:                       │
│   * Tailscale user + device + tags                         │
│   * Scopes used, risk level, approval status               │
│ - Enables forensics and alerting                           │
└─────────────────────────────────────────────────────────────┘
```

## Security Assumptions

### ⚠️ CRITICAL: Tailscale is MANDATORY

**TailOpsMCP does NOT implement TLS/HTTPS.** The server runs plain HTTP on port 8080.

- ✅ **Safe**: Running inside Tailscale (encrypted tunnel, ACL-protected)
- ❌ **UNSAFE**: Exposing port 8080 to public internet or untrusted networks
- ❌ **UNSAFE**: Port forwarding 8080 through a firewall
- ❌ **UNSAFE**: Running on a network with untrusted devices

**All authentication tokens are sent in plaintext HTTP headers.** Without Tailscale's encryption, tokens can be intercepted.

**Do not bypass this requirement.** If you cannot use Tailscale, you MUST:
1. Place TailOpsMCP behind a TLS-terminating reverse proxy (nginx, Caddy, Traefik)
2. Configure the proxy to add TLS and forward to localhost:8080
3. Never expose port 8080 directly

### What Tailscale Provides ✅
- **Encrypted transport**: TLS-equivalent encryption between nodes (WireGuard-based)
- **Network segmentation**: ACLs limit which nodes can connect
- **Identity-aware networking**: Know WHO is connecting
- **Service discovery**: Stable DNS names via Tailscale Services

### What Tailscale Does NOT Provide ❌
- **Application authorization**: Tailnet member ≠ permitted to do X
- **Audit logging**: Network logs ≠ "who called start_container"
- **Approval workflows**: Network access ≠ approval to destructive ops
- **Secret management**: Tailscale key ≠ Docker root access

## Scope-Based Authorization

### Scope Hierarchy

```
admin                          # Full access (use sparingly!)
├── system:admin              # Install packages, update system
├── docker:admin              # Pull images, manage Docker
├── container:admin           # Update containers
│   └── container:write       # Start/stop containers
│       └── container:read    # List containers, view logs
├── file:write                # Write files (not implemented)
│   └── file:read            # Read files
├── network:diag              # Ping, DNS, port scans
│   └── network:read          # View interfaces, connections
└── system:read               # View metrics, processes

readonly                       # All read-only scopes
├── system:read
├── network:read
├── container:read
└── file:read
```

### Tool Risk Levels

| Risk Level | Examples | Requires Approval |
|------------|----------|-------------------|
| **low** | get_system_status, list_containers | No |
| **moderate** | ping_host, dns_lookup | No |
| **high** | manage_container, file_operations | No (but scoped) |
| **critical** | install_package, pull_docker_image | **Yes** |

## Configuration

### Environment Variables

```bash
# Authentication
SYSTEMMANAGER_REQUIRE_AUTH=true          # Enforce bearer tokens
SYSTEMMANAGER_SHARED_SECRET=your-secret  # HMAC secret for tokens
SYSTEMMANAGER_JWT_SECRET=jwt-secret      # Or use JWT

# Approval System
SYSTEMMANAGER_ENABLE_APPROVAL=true       # Enable approval gates
SYSTEMMANAGER_APPROVAL_WEBHOOK=https://approval.example.com

# Audit Logging
SYSTEMMANAGER_AUDIT_LOG=/var/log/systemmanager/audit.log
```

### Recommended Tailscale ACL

```jsonc
{
  "tagOwners": {
    "tag:systemmanager-server": ["group:ops"],
    "tag:systemmanager-client": ["group:ops", "group:automation"],
  },
  
  "acls": [
    // Only tagged clients can reach the MCP server
    {
      "action": "accept",
      "src": ["tag:systemmanager-client"],
      "dst": ["tag:systemmanager-server:8080"],
    },
    
    // Deny everything else
    {
      "action": "deny",
      "src": ["*"],
      "dst": ["tag:systemmanager-server:*"],
    },
  ],
  
  "services": {
    "svc:systemmanager-mcp": {
      "protocol": "tcp",
      "port": 8080,
      "tags": ["tag:systemmanager-server"],
      "allowedTags": ["tag:systemmanager-client"],
    },
  },
}
```

### Token Generation

Create tokens with scopes using `scripts/mint_token.py`:

```bash
# Read-only token (safe for monitoring)
python scripts/mint_token.py \
  --agent "grafana-datasource" \
  --scopes "readonly" \
  --ttl 30d

# Admin token (use sparingly, short TTL)
python scripts/mint_token.py \
  --agent "ops-automation" \
  --scopes "admin" \
  --ttl 1h

# Custom scopes (principle of least privilege)
python scripts/mint_token.py \
  --agent "container-manager" \
  --scopes "container:read,container:write,network:read" \
  --ttl 7d
```

## Audit Log Analysis

### Example Audit Record

```json
{
  "timestamp": "2025-11-15T20:30:00Z",
  "tool": "install_package",
  "subject": "ops-automation",
  "args": {"package_name": "nginx", "auto_approve": true},
  "result_status": "success",
  "scopes": ["admin"],
  "risk_level": "critical",
  "approved": true,
  "tailscale": {
    "tailscale_node": "dev1",
    "tailscale_user": "alice@example.com",
    "tailscale_tags": ["tag:systemmanager-client"],
    "tailnet": "example.ts.net"
  }
}
```

### Monitoring Queries

```bash
# Find all critical operations
jq 'select(.risk_level == "critical")' /var/log/systemmanager/audit.log

# Find operations by a specific Tailscale user
jq 'select(.tailscale.tailscale_user == "alice@example.com")' audit.log

# Find failed authorization attempts (lateral movement detection)
jq 'select(.result_status == "error" and .error | contains("Insufficient"))' audit.log

# Find unapproved critical operations
jq 'select(.risk_level == "critical" and .approved == false)' audit.log
```

### Integration with Tailscale Flow Logs

Combine application audit logs with Tailscale network logs:

1. Enable Tailscale flow logs in admin console
2. Correlate by timestamp + source IP + tailnet user
3. Detect anomalies:
   - Network connection without successful auth
   - Multiple auth failures from same node
   - Unusual source node for specific tools

## Deployment Checklist

### Minimum Security (Development)

- [x] Deploy behind Tailscale (private network)
- [x] Use Tailscale ACLs to limit access
- [ ] Use `readonly` scope for monitoring tools

### Recommended Security (Production)

- [x] All of minimum security
- [ ] Set `SYSTEMMANAGER_REQUIRE_AUTH=true`
- [ ] Generate scoped tokens with short TTLs
- [ ] Tag server with `tag:systemmanager-server`
- [ ] Only allow `tag:systemmanager-client` to connect
- [ ] Monitor audit logs daily
- [ ] Rotate tokens monthly

### Maximum Security (Critical Infrastructure)

- [x] All of recommended security
- [ ] Set `SYSTEMMANAGER_ENABLE_APPROVAL=true`
- [ ] Implement approval webhook for critical ops
- [ ] Use separate tokens per agent/user
- [ ] Token TTL ≤ 24 hours
- [ ] Send audit logs to SIEM
- [ ] Alert on critical operations
- [ ] Alert on authorization failures
- [ ] Correlate with Tailscale flow logs
- [ ] Review audit trail weekly
- [ ] Implement "break glass" procedure for emergencies

## Threat Scenarios

### 1. Compromised Tailnet Node

**Attack**: Attacker compromises a node already in your tailnet

**Mitigations**:
1. Tailscale ACL denies access (must be tagged appropriately)
2. Bearer token required (attacker doesn't have it)
3. Audit log shows connection from unexpected node

### 2. Leaked Bearer Token

**Attack**: Token leaked via logs, config file, environment variable

**Mitigations**:
1. Token has limited scopes (principle of least privilege)
2. Token expires quickly (short TTL)
3. Audit log shows usage from unexpected Tailscale user/node
4. Approval required for critical operations

### 3. Insider Threat (Legitimate User)

**Attack**: Authorized user attempts malicious operation

**Mitigations**:
1. Scopes limit what token can do
2. Critical operations require approval
3. Audit log records who did what with Tailscale identity
4. Tailscale flow logs provide additional evidence

### 4. SSRF via http_request_test

**Attack**: Use http_request_test to scan internal network

**Mitigations**:
1. Tool requires `network:diag` scope
2. Tool marked as `requires_approval=true`
3. Implement URL allowlist in production
4. Audit log tracks all HTTP requests made

## Incident Response

If you detect suspicious activity:

1. **Immediate**: Revoke compromised token (update `SYSTEMMANAGER_SHARED_SECRET`)
2. **Immediate**: Review recent audit logs for scope of compromise
3. **Within 1 hour**: Check Tailscale flow logs for lateral movement
4. **Within 4 hours**: Rotate all tokens
5. **Within 24 hours**: Review and strengthen ACLs
6. **Post-mortem**: Update monitoring/alerting based on lessons learned

## Future Enhancements

Planned security improvements:

- [ ] mTLS client certificates
- [ ] Integration with external IdP (Okta, Azure AD)
- [ ] Real-time alerting on critical operations
- [ ] Webhook-based approval workflows
- [ ] Path-based file access controls
- [ ] Rate limiting per token
- [ ] Token usage analytics
- [ ] Automated token rotation

## References

- [Tailscale ACLs Documentation](https://tailscale.com/kb/1018/acls/)
- [Tailscale Services Guide](./TAILSCALE_SERVICES.md)
- [Token Authentication Implementation](../src/auth/token_auth.py)
- [Scope Definitions](../src/auth/scopes.py)
- [Audit Logger](../src/utils/audit.py)
