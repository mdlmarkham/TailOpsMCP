# SystemManager Security Configuration Examples

This directory contains example security configurations for different deployment scenarios.

## Configuration Files

- `config.minimal.yaml` - Minimum security (development/testing)
- `config.production.yaml` - Recommended production security
- `config.maximum.yaml` - Maximum security (critical infrastructure)
- `tailscale-acl.minimal.jsonc` - Basic Tailscale ACL
- `tailscale-acl.production.jsonc` - Production Tailscale ACL with service discovery
- `example-tokens.md` - Token generation examples

## Quick Start

### 1. Choose Configuration Level

Copy the appropriate config to `/etc/systemmanager/config.yaml`:

```bash
# Development (Tailscale-only, no tokens)
sudo cp config.minimal.yaml /etc/systemmanager/config.yaml

# Production (Tailscale + tokens + audit)
sudo cp config.production.yaml /etc/systemmanager/config.yaml

# Critical Infrastructure (all security features)
sudo cp config.maximum.yaml /etc/systemmanager/config.yaml
```

### 2. Generate Secrets

```bash
# Generate shared secret for HMAC tokens
openssl rand -hex 32

# Or generate JWT secret
openssl rand -base64 32
```

Update the config file with your secret.

### 3. Apply Tailscale ACL

Copy the appropriate ACL to Tailscale admin console:
https://login.tailscale.com/admin/acls

### 4. Generate Tokens

```bash
# For each client/agent
cd /opt/systemmanager
python scripts/mint_token.py --agent "client-name" --scopes "readonly" --ttl 30d
```

Save tokens securely (password manager, secrets management system).

## Security Posture Comparison

| Feature | Minimal | Production | Maximum |
|---------|---------|------------|---------|
| Network isolation | Tailscale | Tailscale + ACLs | Tailscale + ACLs + Service |
| Authentication | Optional | Required | Required |
| Token scopes | N/A | Yes | Yes + audit |
| Token expiry | N/A | 30 days | 24 hours |
| Approval gates | No | No | Yes |
| Audit logging | No | Yes | Yes + SIEM |
| Tailscale identity | No | Yes | Yes + correlation |
| File path restrictions | No | Yes | Yes + allowlist |

## Migration Path

```
Minimal → Production → Maximum
  (1)         (2)         (3)

(1) Add authentication:
    - Set SYSTEMMANAGER_SHARED_SECRET
    - Set SYSTEMMANAGER_REQUIRE_AUTH=true
    - Generate tokens with appropriate scopes
    
(2) Add approval gates:
    - Set SYSTEMMANAGER_ENABLE_APPROVAL=true
    - Configure approval webhook (or use auto_approve flag)
    
(3) Add SIEM integration:
    - Forward audit logs to SIEM
    - Set up alerting rules
    - Correlate with Tailscale flow logs
```
