# TailOpsMCP Best Practices Guide

## Overview

This guide provides best practices for deploying, configuring, and operating TailOpsMCP control plane gateways in production environments.

## Gateway Deployment Best Practices

### Isolation and Security

**✅ Recommended:**
- Deploy gateways in isolated LXC containers or dedicated VMs
- Use Proxmox LXC containers with proper resource limits
- Enable container nesting and TUN device for Docker and Tailscale
- Run gateway as non-root user with limited privileges

**❌ Avoid:**
- Running gateways on production target systems
- Deploying gateways with broad network access
- Using shared credentials across multiple gateways

### Network Segmentation

**Segment-Based Deployment:**
```yaml
# Production Segment A
gateway-a:
  segment: "production-a"
  targets: ["web-a-01", "db-a-01", "cache-a-01"]

# Production Segment B  
gateway-b:
  segment: "production-b"
  targets: ["web-b-01", "db-b-01", "cache-b-01"]

# Staging Segment
gateway-staging:
  segment: "staging"
  targets: ["staging-web-01", "staging-db-01"]
```

**Benefits:**
- Limits blast radius in case of gateway compromise
- Provides redundancy and failover capabilities
- Enables different security policies per segment

## Target Registry Configuration

### Least Privilege Principle

**Grant Minimum Required Capabilities:**
```yaml
targets:
  # Read-only monitoring target
  monitoring-target:
    capabilities:
      - "system:read"
      - "container:read"
      - "network:read"

  # Container management target
  docker-host:
    capabilities:
      - "container:read"
      - "container:control"
      - "stack:deploy"

  # Full management target (use sparingly)
  management-host:
    capabilities:
      - "system:read"
      - "system:control"
      - "container:read"
      - "container:control"
      - "network:read"
      - "file:read"
```

### Credential Management

**Secure Credential Storage:**
```bash
# Use environment variables for secrets
SSH_KEY_WEB_SERVER_01="/opt/systemmanager/secrets/ssh-web-01"
DOCKER_HOST_TOKEN="your-secure-token"

# Secure file permissions
chmod 600 /opt/systemmanager/.env
chmod 600 /opt/systemmanager/secrets/*
```

**Credential Rotation:**
- Rotate SSH keys every 90 days
- Use short-lived API tokens where possible
- Implement automated credential rotation

## Security Configuration

### Authentication and Authorization

**Tailscale OAuth (Recommended):**
```bash
# Use TSIDP for enterprise-grade authentication
SYSTEMMANAGER_AUTH_MODE=oauth
TSIDP_URL=https://tsidp.yourtailnet.ts.net
```

**Token Authentication (Fallback):**
```bash
# Use secure HMAC tokens for automation
SYSTEMMANAGER_AUTH_MODE=token
SYSTEMMANAGER_SHARED_SECRET=your-256-bit-secret
```

### Network Security

**Tailscale ACL Configuration:**
```json
{
  "acls": [
    {
      "action": "accept",
      "src": ["group:systemmanager-admins"],
      "dst": ["tag:systemmanager-gateway:8080"]
    }
  ],
  "tagOwners": {
    "tag:systemmanager-gateway": ["group:systemmanager-admins"]
  }
}
```

**Subnet Route Configuration:**
- Configure Tailscale subnet routes for cross-network access
- Use ACLs to restrict gateway-to-target communication
- Implement network segmentation through subnet routing

## Operational Best Practices

### Monitoring and Alerting

**Gateway Health Monitoring:**
```bash
# Monitor service status
sudo systemctl status systemmanager-mcp

# Check resource usage
top -p $(pgrep -f "python.*mcp_server")

# Monitor audit logs
tail -f /var/log/systemmanager/audit.log
```

**Target Connectivity Monitoring:**
```bash
# Regular connectivity tests
python -c "from src.services.target_registry import TargetRegistry; tr = TargetRegistry(); tr.test_all_connectivity()"

# Monitor target response times
# Add to cron job: */5 * * * * /opt/systemmanager/scripts/health-check.sh
```

### Backup and Recovery

**Configuration Backup:**
```bash
# Backup target registry
cp /opt/systemmanager/targets.yaml /backup/targets-$(date +%Y%m%d).yaml

# Backup environment configuration
cp /opt/systemmanager/.env /backup/env-$(date +%Y%m%d)

# Backup service configuration
cp /etc/systemd/system/systemmanager-mcp.service /backup/
```

**Disaster Recovery Plan:**
1. **Gateway Failure**: Deploy new gateway from backup configuration
2. **Target Registry Loss**: Restore from backup targets.yaml
3. **Secrets Loss**: Rotate credentials and update configuration
4. **Network Isolation**: Verify Tailscale connectivity and ACLs

### Performance Optimization

**Resource Limits:**
```yaml
# Set appropriate timeouts and concurrency limits
targets:
  slow-target:
    constraints:
      timeout: 120  # 2-minute timeout for slow targets
      concurrency: 2  # Limit concurrent operations

  fast-target:
    constraints:
      timeout: 30  # 30-second timeout for fast targets
      concurrency: 5  # Allow more concurrent operations
```

**Connection Pooling:**
- Reuse SSH connections where possible
- Implement connection pooling for HTTP targets
- Monitor connection usage and adjust limits

## Maintenance Procedures

### Regular Updates

**Gateway Software Updates:**
```bash
# Update procedure
sudo systemctl stop systemmanager-mcp
cd /opt/systemmanager
git pull
pip install -r requirements.txt
sudo systemctl start systemmanager-mcp

# Verify update
sudo systemctl status systemmanager-mcp
sudo journalctl -u systemmanager-mcp --since "5 minutes ago"
```

**Target Registry Updates:**
- Review and update target configurations monthly
- Test connectivity after configuration changes
- Document changes in version control

### Security Audits

**Regular Security Reviews:**
```bash
# Review audit logs for suspicious activity
grep -i "denied\|failed\|error" /var/log/systemmanager/audit.log

# Check for unauthorized access attempts
grep -i "unauthorized" /var/log/systemmanager/audit.log

# Review target capability usage
python -c "from src.services.target_registry import TargetRegistry; tr = TargetRegistry(); print('Capability usage:', tr.get_capability_usage())"
```

## Multi-Gateway Deployment

### High Availability

**Redundant Gateway Configuration:**
```yaml
# Primary gateway
primary-gateway:
  targets: ["web-01", "db-01", "cache-01", "monitoring-01"]

# Secondary gateway (redundancy)
secondary-gateway:
  targets: ["web-01", "db-01", "cache-01", "logging-01"]

# Load distribution
gateway-a:
  targets: ["web-a-01", "db-a-01"]

gateway-b:
  targets: ["web-b-01", "db-b-01"]
```

### Load Balancing

**Client-Side Load Distribution:**
```json
{
  "mcpServers": {
    "tailopsmcp-primary": {
      "command": "python",
      "args": ["-m", "src.mcp_server"],
      "env": {
        "SYSTEMMANAGER_TARGETS_CONFIG": "/opt/systemmanager/primary/targets.yaml"
      }
    },
    "tailopsmcp-secondary": {
      "command": "python", 
      "args": ["-m", "src.mcp_server"],
      "env": {
        "SYSTEMMANAGER_TARGETS_CONFIG": "/opt/systemmanager/secondary/targets.yaml"
      }
    }
  }
}
```

## Troubleshooting and Diagnostics

### Proactive Monitoring

**Health Check Script:**
```bash
#!/bin/bash
# /opt/systemmanager/scripts/health-check.sh

# Check service status
systemctl is-active systemmanager-mcp

# Check target connectivity
python -c "from src.services.target_registry import TargetRegistry; tr = TargetRegistry(); tr.test_all_connectivity()"

# Check resource usage
top -bn1 | grep "python.*mcp_server"

# Check audit log growth
ls -la /var/log/systemmanager/audit.log
```

### Incident Response

**Gateway Compromise Response:**
1. **Isolate**: Disconnect gateway from network
2. **Investigate**: Review audit logs and system logs
3. **Contain**: Rotate all credentials used by the gateway
4. **Recover**: Deploy new gateway from clean backup
5. **Learn**: Update security policies based on findings

## Compliance and Governance

### Audit Trail Management

**Comprehensive Logging:**
```bash
# Enable detailed audit logging
SYSTEMMANAGER_AUDIT_LOG=/var/log/systemmanager/audit.log
SYSTEMMANAGER_AUDIT_LEVEL=detailed

# Regular log rotation and retention
# Configure in logrotate.d/systemmanager
/var/log/systemmanager/audit.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
}
```

### Policy Enforcement

**Regular Policy Reviews:**
- Review and update security policies quarterly
- Test policy enforcement with simulated attacks
- Document policy exceptions and approvals

## Performance Tuning

### Gateway Optimization

**Resource Allocation:**
```bash
# LXC container configuration
# /etc/pve/lxc/103.conf
cores: 2
memory: 2048
swap: 1024
```

**Database Optimization:**
- Monitor database connection usage
- Implement connection pooling
- Regular database maintenance

### Network Optimization

**Connection Management:**
- Use persistent connections where supported
- Implement connection timeouts
- Monitor network latency and bandwidth

## Conclusion

Following these best practices will help ensure secure, reliable, and efficient operation of your TailOpsMCP control plane gateways. Regular reviews and updates to your deployment strategy will help maintain security and performance over time.

---

*Last updated: $(date)*