# Token Generation Examples

This guide shows how to generate bearer tokens with different scopes for various use cases.

## Prerequisites

```bash
cd /opt/systemmanager

# Set your shared secret (keep this secret!)
export SYSTEMMANAGER_SHARED_SECRET="your-secret-here"

# Or for JWT
export SYSTEMMANAGER_JWT_SECRET="your-jwt-secret"
```

## Common Scenarios

### 1. Read-Only Monitoring (Safest)

For Grafana, Prometheus, observability tools that only need to read metrics:

```bash
python scripts/mint_token.py \
  --agent "grafana-datasource" \
  --scopes "readonly" \
  --ttl 30d

# Output:
# Token: eyJhZ2VudCI6ImdyYWZhbmEtZGF0YXNvdXJjZSIsInNjb3Blcy...
# Expires: 2025-12-15T20:00:00Z
# Scopes: system:read, network:read, container:read, file:read
```

**What this can do:**
- ✅ View system status, processes, metrics
- ✅ List containers and view logs
- ✅ View network interfaces and connections
- ✅ Read allowed files
- ❌ Start/stop containers
- ❌ Install packages
- ❌ Modify anything

### 2. Container Management

For container orchestration tools (Portainer, Kubernetes operators):

```bash
python scripts/mint_token.py \
  --agent "portainer" \
  --scopes "container:read,container:write,docker:read,network:read" \
  --ttl 7d
```

**What this can do:**
- ✅ List containers and images
- ✅ Start, stop, restart containers
- ✅ View container logs
- ✅ View Docker networks
- ❌ Pull images or update containers
- ❌ Install packages

### 3. System Diagnostics

For network troubleshooting and diagnostics:

```bash
python scripts/mint_token.py \
  --agent "network-tools" \
  --scopes "system:read,network:read,network:diag" \
  --ttl 1d
```

**What this can do:**
- ✅ Ping hosts
- ✅ DNS lookups
- ✅ Port connectivity tests
- ✅ SSL certificate checks
- ✅ View network statistics
- ❌ HTTP request testing (SSRF risk)
- ❌ Modify anything

### 4. Automation / CI/CD (Moderate Risk)

For deployment pipelines that need to update containers:

```bash
python scripts/mint_token.py \
  --agent "github-actions" \
  --scopes "container:read,container:write,container:admin,docker:read" \
  --ttl 2h  # Short TTL for automation
```

**What this can do:**
- ✅ Update running containers
- ✅ Pull new Docker images
- ✅ Start/stop containers
- ✅ View container state
- ⚠️ Requires `auto_approve=true` for updates
- ❌ Install system packages

### 5. Full Admin Access (Highest Risk)

For emergency access, break-glass scenarios:

```bash
python scripts/mint_token.py \
  --agent "ops-emergency-alice" \
  --scopes "admin" \
  --ttl 1h  # Very short TTL!
```

**What this can do:**
- ✅ Everything
- ⚠️ Requires approval for critical operations
- ⚠️ Every action logged with Tailscale identity
- 🔥 Use sparingly, rotate quickly

### 6. System Updates (Critical Risk)

For patch management systems:

```bash
python scripts/mint_token.py \
  --agent "ansible-patch-mgmt" \
  --scopes "system:read,system:admin" \
  --ttl 4h
```

**What this can do:**
- ✅ Check for system updates
- ✅ Install packages
- ✅ Update system
- ⚠️ Requires approval for install/update operations
- ❌ Docker operations

## Scope Reference

### Meta Scopes

| Scope | Expands To | Use Case |
|-------|-----------|----------|
| `readonly` | system:read, network:read, container:read, file:read | Monitoring, observability |
| `admin` | All scopes | Emergency access, manual ops |

### Specific Scopes

| Scope | Tools Granted | Risk Level |
|-------|--------------|------------|
| `system:read` | get_system_status, get_top_processes | Low |
| `network:read` | get_network_status, get_active_connections | Low |
| `container:read` | get_container_list, list_docker_images | Low |
| `file:read` | file_operations (read) | Moderate |
| `network:diag` | ping_host, dns_lookup, test_port_connectivity | Moderate |
| `container:write` | manage_container (start/stop/restart) | High |
| `container:admin` | update_docker_container | **Critical** |
| `docker:admin` | pull_docker_image | **Critical** |
| `system:admin` | install_package, update_system_packages | **Critical** |

## Token Management Best Practices

### Generation
```bash
# Always specify agent name (who/what is using this token)
--agent "service-name-or-username"

# Use shortest TTL appropriate for use case
--ttl 1h   # Automation, emergency
--ttl 1d   # Short-lived tasks
--ttl 7d   # Services with rotation
--ttl 30d  # Long-running monitoring (max)

# Grant minimum required scopes
--scopes "scope1,scope2"  # NOT "admin" unless necessary
```

### Storage
```bash
# NEVER commit tokens to git
# NEVER put tokens in config files
# NEVER log tokens

# DO: Use environment variables
export SYSTEMMANAGER_TOKEN="token-here"

# DO: Use secrets management
aws secretsmanager get-secret-value --secret-id systemmanager/token
vault kv get secret/systemmanager/token

# DO: Use secure password manager
pass show systemmanager/grafana-token
```

### Rotation
```bash
# Rotate tokens regularly
# High-risk (admin): Every 24 hours
# Medium-risk (write): Every 7 days
# Low-risk (readonly): Every 30 days

# Emergency rotation (compromised token):
# 1. Generate new SYSTEMMANAGER_SHARED_SECRET
export SYSTEMMANAGER_SHARED_SECRET="$(openssl rand -hex 32)"

# 2. Update config
sudo sed -i "s/old-secret/$SYSTEMMANAGER_SHARED_SECRET/" /etc/systemmanager/config.yaml

# 3. Restart service
sudo systemctl restart systemmanager-mcp

# 4. Generate new tokens for all clients
for agent in grafana portainer automation; do
  python scripts/mint_token.py --agent "$agent" --scopes "..." --ttl ...
done
```

### Revocation
```bash
# Individual token revocation (not implemented yet)
# For now, rotate the shared secret to invalidate ALL tokens

# Planned feature:
# python scripts/revoke_token.py --token <token>
# python scripts/revoke_token.py --agent "github-actions"
```

## Troubleshooting

### Token Rejected (401 Unauthorized)

```bash
# Check token format
echo $TOKEN | base64 -d  # HMAC: should decode to JSON

# Check expiry
# Token includes expiry field, check if expired

# Verify secret matches
# Token signed with different secret = invalid
```

### Insufficient Privileges (403 Forbidden)

```bash
# Check scopes in token
python scripts/verify_token.py --token $TOKEN

# Grant additional scopes
python scripts/mint_token.py --agent "same-agent" --scopes "existing,new" --ttl 7d
```

### Approval Required

```bash
# For critical operations, add auto_approve flag:
curl -H "Authorization: Bearer $TOKEN" \
  -X POST http://server:8080/tool/install_package \
  -d '{"package_name":"nginx","auto_approve":true}'

# Or enable approval webhook in config
```

## Audit Trail

Every token usage is logged:

```bash
# Find operations by token/agent
grep '"subject":"grafana-datasource"' /var/log/systemmanager/audit.log

# Find failed auth attempts
grep '"error".*"Insufficient"' /var/log/systemmanager/audit.log

# Find critical operations
jq 'select(.risk_level == "critical")' /var/log/systemmanager/audit.log
```
