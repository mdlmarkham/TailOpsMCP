# TailOpsMCP Security Configuration Guide

## Overview

This guide provides comprehensive security configuration recommendations for TailOpsMCP control plane gateways, covering authentication, authorization, network security, and operational security practices.

## Authentication Security

### Tailscale OAuth (Recommended)

**Configuration:**
```bash
# /opt/systemmanager/.env
SYSTEMMANAGER_AUTH_MODE=oauth
SYSTEMMANAGER_REQUIRE_AUTH=true
TSIDP_URL=https://tsidp.yourtailnet.ts.net
```

**Security Benefits:**
- Enterprise-grade OAuth 2.1 authentication
- Automatic user identification via Tailscale
- Token refresh and introspection support
- Integration with existing identity providers

### HMAC Token Authentication (Fallback)

**Configuration:**
```bash
# /opt/systemmanager/.env
SYSTEMMANAGER_AUTH_MODE=token
SYSTEMMANAGER_SHARED_SECRET=your-256-bit-secure-secret
```

**Security Requirements:**
- Use cryptographically secure random secrets
- Rotate secrets every 90 days
- Store secrets securely with limited access
- Use different secrets for different environments

## Authorization and Access Control

### Scope-Based Authorization

**Define Granular Scopes:**
```python
# Example scope definitions
SCOPES = {
    "system:read": "Read system status and metrics",
    "system:write": "Modify system configuration",
    "docker:read": "View container status and logs",
    "docker:write": "Manage containers and stacks",
    "network:read": "View network configuration",
    "network:write": "Modify network settings",
    "file:read": "Read and search files",
    "file:write": "Modify files and directories"
}
```

**Principle of Least Privilege:**
- Grant only necessary scopes for each user/team
- Use separate tokens for different purposes
- Regularly review and update scope assignments

### Policy Gate Enforcement

**Capability-Based Authorization:**
```yaml
# targets.yaml - Least privilege configuration
targets:
  monitoring-target:
    capabilities:
      - "system:read"
      - "container:read"
      - "network:read"

  management-target:
    capabilities:
      - "system:read"
      - "system:control"
      - "container:read"
      - "container:control"
    constraints:
      sudo_policy: "limited"
      timeout: 60
```

## Network Security

### Tailscale Integration

**ACL Configuration:**
```json
{
  "acls": [
    {
      "action": "accept",
      "src": ["group:tailopsmcp-admins"],
      "dst": ["tag:tailopsmcp-gateway:8080"]
    },
    {
      "action": "accept",
      "src": ["tag:tailopsmcp-gateway"],
      "dst": ["tag:managed-targets:*"]
    }
  ],
  "tagOwners": {
    "tag:tailopsmcp-gateway": ["group:tailopsmcp-admins"],
    "tag:managed-targets": ["group:tailopsmcp-admins"]
  }
}
```

**Security Benefits:**
- Encrypted transport layer (WireGuard)
- Fine-grained network access control
- Automatic certificate management
- Integration with existing network policies

### Subnet Route Security

**Secure Subnet Configuration:**
```bash
# Enable subnet routes with proper ACLs
tailscale up --advertise-routes=192.168.1.0/24,10.0.1.0/24

# Verify route configuration
tailscale status --json | jq '.Self.ExitNodeOptions.AllowLANAccess'
```

## Gateway Deployment Security

### Container Isolation

**Proxmox LXC Security:**
```bash
# /etc/pve/lxc/103.conf
# Security-focused configuration
arch: amd64
cores: 2
memory: 2048
net0: name=eth0,bridge=vmbr0,firewall=1,ip=dhcp
rootfs: local-lvm:vm-103-disk-0,size=8G

# Security features
features: nesting=1,keyctl=1
lxc.apparmor.profile: unconfined
lxc.cgroup2.devices.allow: c 10:200 rwm  # /dev/net/tun

# Resource limits
lxc.cgroup2.memory.max: 2G
lxc.cgroup2.cpu.max: 200 200
```

### Service Hardening

**Systemd Service Security:**
```ini
# /etc/systemd/system/systemmanager-mcp.service
[Unit]
Description=TailOpsMCP Control Plane Gateway
After=network.target

[Service]
Type=simple
User=systemmanager
Group=systemmanager
EnvironmentFile=/opt/systemmanager/.env
WorkingDirectory=/opt/systemmanager
ExecStart=/opt/systemmanager/.venv/bin/python -m src.mcp_server

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/systemmanager /var/log/systemmanager
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
SystemCallFilter=@system-service
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
```

## Credential Management

### SSH Key Security

**Best Practices:**
```bash
# Generate secure SSH keys
ssh-keygen -t ed25519 -a 100 -f /opt/systemmanager/secrets/ssh-key

# Secure key storage
chmod 600 /opt/systemmanager/secrets/ssh-key
chown systemmanager:systemmanager /opt/systemmanager/secrets/ssh-key

# Use key passphrases for additional security
ssh-keygen -p -f /opt/systemmanager/secrets/ssh-key
```

### API Token Security

**Token Management:**
- Use short-lived tokens where possible
- Implement token rotation procedures
- Store tokens securely with limited access
- Monitor token usage for anomalies

## Audit and Monitoring

### Comprehensive Logging

**Audit Log Configuration:**
```bash
# /opt/systemmanager/.env
SYSTEMMANAGER_AUDIT_LOG=/var/log/systemmanager/audit.log
SYSTEMMANAGER_AUDIT_LEVEL=detailed
SYSTEMMANAGER_MAX_OUTPUT_BYTES=65536
SYSTEMMANAGER_MAX_OUTPUT_LINES=1000
```

**Log Security:**
```bash
# Secure log directory
mkdir -p /var/log/systemmanager
chown systemmanager:systemmanager /var/log/systemmanager
chmod 750 /var/log/systemmanager

# Log rotation configuration
# /etc/logrotate.d/systemmanager
/var/log/systemmanager/audit.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 systemmanager systemmanager
}
```

### Security Monitoring

**Proactive Security Checks:**
```bash
# Regular security audit script
#!/bin/bash
# /opt/systemmanager/scripts/security-audit.sh

# Check for unauthorized access
grep -i "unauthorized\|denied\|failed" /var/log/systemmanager/audit.log

# Monitor privilege escalation attempts
grep -i "sudo\|root\|privilege" /var/log/systemmanager/audit.log

# Check for unusual activity patterns
# Implement anomaly detection
```

## Operational Security

### Regular Security Reviews

**Monthly Security Checklist:**
- [ ] Review audit logs for suspicious activity
- [ ] Verify target registry configuration
- [ ] Check for outdated dependencies
- [ ] Review Tailscale ACL configuration
- [ ] Test backup and recovery procedures
- [ ] Update security policies as needed

### Incident Response

**Security Incident Procedure:**
1. **Detection**: Identify security incident through monitoring
2. **Containment**: Isolate affected systems
3. **Eradication**: Remove threat and secure systems
4. **Recovery**: Restore normal operations
5. **Lessons Learned**: Update security measures

## Advanced Security Features

### Approval Gates

**High-Risk Operation Approval:**
```bash
# Enable approval requirements
SYSTEMMANAGER_ENABLE_APPROVAL=true
SYSTEMMANAGER_APPROVAL_WEBHOOK=https://your-approval-service/approve
```

**Approval Webhook Requirements:**
- Implement external approval service
- Support JSON payload with operation details
- Return approval decision with reason
- Log all approval decisions

### Dry Run Mode

**Safe Operation Testing:**
```bash
# Enable dry run mode for testing
SYSTEMMANAGER_ENABLE_DRY_RUN=true
```

**Benefits:**
- Test operations without execution
- Validate operation parameters
- Train users safely
- Develop automation scripts

## Compliance and Governance

### Security Policy Documentation

**Required Policies:**
- Access control policy
- Incident response policy
- Backup and recovery policy
- Change management policy
- Security monitoring policy

### Regulatory Compliance

**Common Requirements:**
- Audit trail retention (7+ years)
- Access control documentation
- Security incident reporting
- Regular security assessments
- Third-party risk management

## Security Testing

### Penetration Testing

**Regular Security Assessments:**
- Network penetration testing
- Application security testing
- Social engineering testing
- Physical security testing

### Vulnerability Management

**Vulnerability Scanning:**
```bash
# Regular vulnerability scans
# Use tools like:
# - nmap for network scanning
# - OpenVAS for vulnerability assessment
# - OWASP ZAP for web application testing
```

## Conclusion

Implementing these security configurations will help ensure your TailOpsMCP control plane gateways operate securely in production environments. Regular security reviews, monitoring, and updates are essential for maintaining a strong security posture.

---

*Last updated: $(date)*
