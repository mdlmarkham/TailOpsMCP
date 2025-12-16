# TailOpsMCP Security Advisory (Control Plane Gateway)

## Current Security Limitations

### ⚠️ Approval Webhook Not Implemented

**Status:** Defense Layer 3 (Approval Gates) requires external implementation.

**Impact (Control Plane Gateway):**
- High-risk operations (`install_package`, `update_docker_container`, `update_system_packages`, etc.) are **DENIED by default** across all targets
- Setting `SYSTEMMANAGER_ENABLE_APPROVAL=true` without a webhook will block all approval-required operations on all managed systems
- The gateway middleware will return an error: `"Approval webhook not configured"`
- Target-specific approval constraints in `targets.yaml` will be enforced

**Workaround Options (Gateway Architecture):**

1. **Disable Approval Requirement (Not Recommended)**
   ```bash
   # In gateway environment configuration
   SYSTEMMANAGER_ENABLE_APPROVAL=false
   ```
   This removes Layer 3 defense entirely across all targets. Only do this if you:
   - Fully trust all token holders
   - Have comprehensive audit logging enabled on the gateway
   - Monitor gateway logs actively for suspicious activity
   - Use target-specific capability restrictions in `targets.yaml`

2. **Implement External Approval Webhook**
   ```bash
   # In gateway environment configuration
   SYSTEMMANAGER_ENABLE_APPROVAL=true
   SYSTEMMANAGER_APPROVAL_WEBHOOK=https://your-approval-service.ts.net/approve
   ```

   Your webhook must handle gateway-specific context:
   - Accept POST requests with JSON body:
     ```json
     {
       "tool": "install_package",
       "args": {"package_name": "nginx"},
       "target": "web-server-01",
       "user": "user@tailnet.ts.net",
       "risk_level": "CRITICAL",
       "gateway_id": "gateway-001"
     }
     ```
   - Return HTTP 200 with `{"approved": true}` or `{"approved": false, "reason": "..."}`
   - Implement your own approval logic (Slack notifications, PagerDuty, etc.)
   - Consider target-specific approval policies

3. **Use Target-Specific Capability Restrictions**
   ```yaml
   # In targets.yaml - restrict capabilities per target
   targets:
     production-web:
       id: "production-web"
       capabilities:
         - "system:read"
         - "container:read"
       # No write capabilities for production

     development-web:
       id: "development-web"
       capabilities:
         - "system:read"
         - "system:write"
         - "container:read"
         - "container:write"
       # Allow write operations in development
   ```

4. **Use Scopes to Restrict Access**
   ```bash
   # Mint tokens without dangerous scopes
   python scripts/mint_token.py \
     --agent "monitoring-agent" \
     --scopes "system:read,container:read,network:diag" \
     --ttl 30d
   ```
   This prevents the token from calling high-risk operations entirely.

**Future Plans:**
- Built-in approval UI (web-based)
- Slack/Discord approval bot templates
- Time-based auto-approval windows

---

## Transport Security Requirements

### ⚠️ No Built-in TLS/HTTPS

**TailOpsMCP serves plain HTTP on port 8080.**

**Safe Deployments:**
- ✅ Inside Tailscale network (encrypted WireGuard tunnel)
- ✅ Behind TLS-terminating reverse proxy (nginx, Caddy, Traefik)
- ✅ Localhost-only access (`127.0.0.1:8080`)

**Unsafe Deployments:**
- ❌ Exposed to public internet
- ❌ Port forwarded through firewall
- ❌ On untrusted LANs
- ❌ Mixed Tailscale + non-Tailscale clients

**Why This Matters:**
- Bearer tokens are sent in HTTP `Authorization` headers
- Without TLS, tokens can be intercepted via:
  - Network sniffing (MITM attacks)
  - Compromised routers/switches
  - Malicious devices on the same network

**Mitigation:**
1. **Use Tailscale** (recommended) - provides transparent encryption
2. **Deploy Reverse Proxy:**
   ```nginx
   # nginx example
   server {
       listen 443 ssl;
       server_name tailopsmcp.example.com;

       ssl_certificate /path/to/cert.pem;
       ssl_certificate_key /path/to/key.pem;

       location / {
           proxy_pass http://127.0.0.1:8080;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

3. **Never expose port 8080 directly**

---

## Systemd Service User

### Previous Configuration (Insecure)

Older versions ran as `root` user:
```ini
[Service]
User=root
Group=root
```

**Risk:** If compromised, attacker has full system access.

### Current Configuration (Hardened)

Now runs as dedicated `systemmanager` user:
```ini
[Service]
User=systemmanager
Group=systemmanager
```

**Benefits:**
- Limited blast radius - attacker only gets `systemmanager` user privileges
- Docker access via group membership (not root)
- Cannot modify system files outside `/var/lib/systemmanager`
- Additional systemd sandboxing (ProtectSystem, ProtectHome, etc.)

### Upgrading Existing Installations

If you installed before this change, update manually:

```bash
# 1. Create systemmanager user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin systemmanager
sudo usermod -aG docker systemmanager

# 2. Fix ownership
sudo chown -R systemmanager:systemmanager /opt/systemmanager
sudo chown -R systemmanager:systemmanager /var/lib/systemmanager
sudo chmod 600 /opt/systemmanager/.env

# 3. Update systemd service
sudo nano /etc/systemd/system/systemmanager-mcp.service
# Change User=root to User=systemmanager
# Change Group=root to Group=systemmanager
# Remove /opt/systemmanager from ReadWritePaths

# 4. Reload and restart
sudo systemctl daemon-reload
sudo systemctl restart systemmanager-mcp

# 5. Verify
sudo systemctl status systemmanager-mcp
sudo journalctl -u systemmanager-mcp -n 50
```

---

## Installation Script Supply Chain

### Current Behavior

The installer:
1. Queries GitHub API for latest release tag
2. Clones `master` branch (not the release tag)
3. Fetches and executes `get.docker.com` without verification
4. Fetches and executes `ct/build.func` without verification

**Risks:**
- If GitHub is compromised, malicious code could be injected
- If `get.docker.com` is compromised, Docker installation is malicious
- Reproducibility issues (master != tagged release)

### Recommended Practices

**For Users:**
1. Review scripts before piping to bash:
   ```bash
   curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/install.sh > install.sh
   less install.sh  # Review
   sudo bash install.sh
   ```

2. Pin to specific release:
   ```bash
   git clone --branch v1.0.0 https://github.com/mdlmarkham/TailOpsMCP.git
   cd TailOpsMCP
   sudo bash install.sh
   ```

3. Verify Docker installation separately:
   ```bash
   # Install Docker via package manager instead
   sudo apt-get install docker.io
   ```

**For Project (Future):**
- Sign releases with GPG
- Verify signatures in installer
- Pin Docker installation to specific version
- Provide checksums for release artifacts
- Clone specific release tag instead of master

---

## Audit Logging Gaps

### What's Logged ✅
- Tool invocations
- User identity (if using TSIDP)
- Scopes used
- Timestamps

### What's NOT Logged ❌
- Approval webhook responses
- Token generation events
- Failed authentication attempts
- Rate limiting events
- Session duration

### Recommendations

Enable systemd journal forwarding to SIEM:
```bash
# Forward to syslog
sudo apt-get install rsyslog
sudo systemctl enable rsyslog

# Or to Loki/Grafana
# Install promtail and configure journal input
```

Monitor for suspicious patterns:
```bash
# High-frequency tool calls
journalctl -u systemmanager-mcp -o json | jq '.MESSAGE' | sort | uniq -c | sort -rn

# Calls to high-risk tools
journalctl -u systemmanager-mcp | grep -E "install_package|update_docker_container|update_system_packages"
```

---

## Responsible Disclosure

If you discover a security vulnerability:

1. **Do NOT** open a public GitHub issue
2. Email: [your-security-email@example.com]
3. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
4. Allow 90 days for patch before public disclosure

We will:
- Acknowledge within 48 hours
- Provide status updates every 7 days
- Credit you in security advisory (if desired)
- Issue CVE if applicable

---

## Security Checklist for Production

Before deploying to production:

- [ ] Running inside Tailscale network (or behind TLS proxy)
- [ ] Authentication enabled (`SYSTEMMANAGER_REQUIRE_AUTH=true`)
- [ ] Using TSIDP OIDC (not token-based auth)
- [ ] Systemd service runs as `systemmanager` user (not root)
- [ ] All tokens have expiry dates (`--ttl` or `--expiry`)
- [ ] High-risk scopes restricted to trusted users only
- [ ] Audit logs forwarded to SIEM
- [ ] Tailscale ACLs limit access to tagged devices
- [ ] Approval webhook implemented (or approval disabled with risk acceptance)
- [ ] Regular security updates applied
- [ ] Monitoring alerts configured for suspicious activity

---

**Last Updated:** 2025-01-16
**Applies to:** TailOpsMCP v1.0+
