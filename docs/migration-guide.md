# TailOpsMCP Migration Guide

## Overview

This guide provides comprehensive migration instructions for users transitioning from previous versions or alternative system management approaches to the TailOpsMCP control plane gateway architecture.

## Migration Scenarios

### Scenario 1: Migrating from Agent-on-Node Deployment

**Previous Architecture:**
- Agents deployed on each target system
- Per-node configuration and management
- Limited centralized control

**New Control Plane Gateway Architecture:**
- Single gateway manages multiple targets
- Centralized target registry configuration
- Enhanced security through capability-based authorization

**Migration Steps:**

1. **Inventory Existing Systems**
```bash
# Document current agent deployments
# List all managed systems and their configurations
# Note current capabilities and access patterns
```

2. **Deploy Control Plane Gateway**
```bash
# Deploy gateway in isolated environment
bash -c "$(wget -qLO - https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/ct/build.func)"
```

3. **Create Target Registry**
```yaml
# Convert agent configurations to target registry
version: "1.0"
targets:
  # Convert each agent to a target entry
  web-server-01:
    id: "web-server-01"
    type: "remote"
    executor: "ssh"
    connection:
      host: "192.168.1.100"
      username: "admin"
      key_path: "${SSH_KEY_WEB_SERVER_01}"
    capabilities:
      - "system:read"
      - "container:read"
      - "network:read"
```

4. **Test and Validate**
```bash
# Test connectivity to all targets
python -c "from src.services.target_registry import TargetRegistry; tr = TargetRegistry(); tr.test_all_connectivity()"

# Verify capability enforcement
# Test operations that should be allowed/denied
```

5. **Decommission Agents**
```bash
# Remove agent software from target systems
# Update monitoring and alerting systems
# Update documentation and procedures
```

### Scenario 2: Migrating from Manual System Management

**Previous Approach:**
- Manual SSH connections to individual systems
- Script-based automation
- Limited centralized visibility

**Migration Benefits:**
- Centralized management through AI assistants
- Automated multi-system operations
- Comprehensive audit logging
- Enhanced security controls

**Migration Steps:**

1. **Document Current Practices**
```bash
# List commonly performed operations
# Document access patterns and credentials
# Identify automation opportunities
```

2. **Deploy Gateway and Configure Targets**
```yaml
# Create target registry based on current access
targets:
  # Convert manual SSH access to target entries
  database-server:
    id: "database-server"
    type: "remote"
    executor: "ssh"
    connection:
      host: "db.example.com"
      username: "dba"
      key_path: "${SSH_KEY_DATABASE}"
    capabilities:
      - "system:read"
      - "container:read"
```

3. **Transition Common Operations**
```bash
# Replace manual commands with MCP tools
# Manual: ssh db.example.com "systemctl status postgresql"
# MCP: system_health_check(target="database-server")

# Manual: scp backup.sql db.example.com:/backups/
# MCP: file_operations(target="database-server", operation="upload")
```

4. **Train Team on New Workflow**
```bash
# Provide training on MCP client usage
# Document new operational procedures
# Establish governance and approval processes
```

### Scenario 3: Migrating from Alternative MCP Servers

**Previous MCP Implementation:**
- Different MCP server with similar functionality
- Alternative configuration approaches
- Varying security models

**Migration Considerations:**
- Configuration format differences
- Security model alignment
- Tool compatibility

**Migration Steps:**

1. **Compare Configuration Formats**
```yaml
# Example: Converting from alternative MCP server configuration
# Previous format might have different structure
# TailOpsMCP uses standardized targets.yaml format
```

2. **Map Capabilities and Tools**
```bash
# Identify equivalent tools and capabilities
# Previous: container_status(host="web-01")
# TailOpsMCP: list_containers(target="web-server-01")
```

3. **Test Compatibility**
```bash
# Verify all required functionality is available
# Test edge cases and error handling
# Validate security controls
```

## Configuration Migration

### Environment Variables Migration

**Previous Configuration:**
```bash
# Example previous environment variables
MCP_SERVER_HOST=localhost
MCP_SERVER_PORT=8080
AUTH_TOKEN=secret-token
ALLOWED_PATHS=/etc,/var/log
```

**TailOpsMCP Configuration:**
```bash
# TailOpsMCP environment variables
SYSTEMMANAGER_AUTH_MODE=token
SYSTEMMANAGER_SHARED_SECRET=your-secure-secret
SYSTEMMANAGER_ALLOWED_PATHS=/etc,/var/log,/home/svcuser/data
SYSTEMMANAGER_ENFORCE_NON_ROOT=true
SYSTEMMANAGER_AUDIT_LOG=/var/log/systemmanager/audit.log
```

### Target Registry Conversion

**Previous Inventory Format:**
```json
{
  "servers": [
    {
      "name": "web-01",
      "host": "192.168.1.100",
      "type": "ssh",
      "credentials": {
        "username": "admin",
        "key_file": "/path/to/key"
      },
      "capabilities": ["monitoring", "container_management"]
    }
  ]
}
```

**TailOpsMCP targets.yaml:**
```yaml
version: "1.0"
targets:
  web-01:
    id: "web-01"
    type: "remote"
    executor: "ssh"
    connection:
      host: "192.168.1.100"
      username: "admin"
      key_path: "${SSH_KEY_WEB_01}"
    capabilities:
      - "system:read"
      - "container:read"
      - "container:control"
```

## Security Migration

### Authentication Migration

**Previous Authentication:**
- Basic token authentication
- Limited scope management
- Simple access control

**TailOpsMCP Authentication:**
- OAuth 2.1 with TSIDP integration
- Fine-grained scope-based authorization
- Comprehensive audit logging

**Migration Steps:**

1. **Audit Current Access Patterns**
```bash
# Review current user access and permissions
# Document required capabilities for each user/team
```

2. **Configure New Authentication**
```bash
# Set up Tailscale OAuth or token authentication
# Define appropriate scopes for different users
# Test authentication flow
```

3. **Update Client Configurations**
```json
{
  "mcpServers": {
    "tailopsmcp": {
      "command": "python",
      "args": ["-m", "src.mcp_server"],
      "env": {
        "SYSTEMMANAGER_TARGETS_CONFIG": "/opt/systemmanager/targets.yaml"
      }
    }
  }
}
```

### Network Security Migration

**Previous Network Configuration:**
- Direct network access
- Limited segmentation
- Basic firewall rules

**TailOpsMCP Network Security:**
- Tailscale encrypted transport
- Fine-grained ACLs
- Segment-based deployment

**Migration Steps:**

1. **Configure Tailscale Integration**
```bash
# Join gateway to Tailscale network
tailscale up --auth-key=tskey-auth-xxxxx

# Configure subnet routes if needed
tailscale up --advertise-routes=192.168.1.0/24
```

2. **Set Up ACLs**
```json
{
  "acls": [
    {
      "action": "accept",
      "src": ["group:tailopsmcp-users"],
      "dst": ["tag:tailopsmcp-gateway:8080"]
    }
  ]
}
```

## Operational Migration

### Monitoring and Alerting

**Previous Monitoring:**
- Agent-based monitoring
- Custom alerting rules
- Limited centralized visibility

**TailOpsMCP Monitoring:**
- Gateway health monitoring
- Target connectivity checks
- Comprehensive audit logging

**Migration Steps:**

1. **Update Monitoring Configuration**
```bash
# Configure gateway health checks
# Set up target connectivity monitoring
# Update alerting rules for new architecture
```

2. **Implement Audit Log Monitoring**
```bash
# Monitor audit logs for security events
# Set up log aggregation and analysis
# Configure alerting for suspicious activity
```

### Backup and Recovery

**Previous Backup Strategy:**
- Per-system backups
- Manual recovery procedures
- Limited automation

**TailOpsMCP Backup Strategy:**
- Centralized configuration backup
- Automated recovery procedures
- Comprehensive disaster recovery plan

**Migration Steps:**

1. **Implement New Backup Procedures**
```bash
# Backup target registry configuration
cp /opt/systemmanager/targets.yaml /backup/targets-$(date +%Y%m%d).yaml

# Backup environment configuration
cp /opt/systemmanager/.env /backup/env-$(date +%Y%m%d)
```

2. **Test Recovery Procedures**
```bash
# Test gateway recovery from backup
# Validate target registry restoration
# Verify authentication configuration
```

## Testing and Validation

### Migration Testing Checklist

**Pre-Migration Testing:**
- [ ] Verify gateway deployment
- [ ] Test target connectivity
- [ ] Validate authentication
- [ ] Test basic operations
- [ ] Verify audit logging

**Post-Migration Testing:**
- [ ] Test all critical operations
- [ ] Verify security controls
- [ ] Validate monitoring
- [ ] Test backup and recovery
- [ ] User acceptance testing

### Rollback Plan

**Rollback Procedures:**

1. **Configuration Rollback**
```bash
# Restore previous configuration files
# Revert to previous authentication method
# Update client configurations
```

2. **Service Rollback**
```bash
# Stop TailOpsMCP gateway
sudo systemctl stop systemmanager-mcp

# Restart previous services
# Verify previous functionality
```

## Common Migration Issues

### Connectivity Problems

**Symptoms:**
- Target connection failures
- SSH key authentication issues
- Network connectivity problems

**Solutions:**
```bash
# Test SSH connectivity manually
ssh -i /path/to/key admin@target-ip

# Verify network connectivity
ping target-ip

# Check firewall rules
sudo iptables -L | grep target-ip
```

### Authentication Issues

**Symptoms:**
- OAuth authentication failures
- Token validation errors
- Scope permission issues

**Solutions:**
```bash
# Test TSIDP connectivity
curl -I https://tsidp.yourtailnet.ts.net

# Verify token generation
python scripts/mint_token.py --agent test-agent --scopes system:read
```

### Performance Issues

**Symptoms:**
- Slow operation execution
- High resource usage
- Timeout errors

**Solutions:**
```bash
# Monitor resource usage
top -p $(pgrep -f "python.*mcp_server")

# Adjust timeout settings
targets:
  slow-target:
    constraints:
      timeout: 120
```

## Post-Migration Optimization

### Performance Tuning

**Optimization Opportunities:**
```yaml
# Adjust concurrency limits
targets:
  high-performance-target:
    constraints:
      concurrency: 10
      timeout: 30
```

### Security Enhancement

**Additional Security Measures:**
- Implement approval gates for high-risk operations
- Enable comprehensive audit logging
- Regular security reviews and updates

## Support and Resources

### Migration Assistance

**Available Resources:**
- [Quick Start Guide](./quickstart.md)
- [Troubleshooting Guide](./troubleshooting.md)
- [Security Configuration Guide](./security-configuration.md)
- [GitHub Issues](https://github.com/mdlmarkham/TailOpsMCP/issues)

### Community Support

**Getting Help:**
- Join [GitHub Discussions](https://github.com/mdlmarkham/TailOpsMCP/discussions)
- Review existing migration examples
- Share your migration experience

---

*Last updated: $(date)*
