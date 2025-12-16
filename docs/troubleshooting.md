# TailOpsMCP Troubleshooting Guide

## Overview

This guide provides solutions for common issues encountered when deploying and using TailOpsMCP control plane gateways.

## Gateway Service Issues

### Gateway Won't Start

**Symptoms:**
- `sudo systemctl status systemmanager-mcp` shows failed status
- Service fails to start with error messages

**Solutions:**

1. **Check Configuration Files**
```bash
# Verify targets.yaml syntax
python -c "from src.services.target_registry import TargetRegistry; tr = TargetRegistry(); print('Valid targets:', list(tr._targets.keys()))"

# Check environment file
cat /opt/systemmanager/.env | grep -v SECRET
```

2. **Check Dependencies**
```bash
# Verify Python dependencies
pip list | grep -E "(fastmcp|pydantic|tailscale)"

# Check Tailscale connectivity
tailscale status
```

3. **View Detailed Logs**
```bash
# Check systemd logs
sudo journalctl -u systemmanager-mcp -n 50

# Check application logs
sudo journalctl -u systemmanager-mcp --since "5 minutes ago" | grep -i error
```

### Gateway Crashes or Restarts

**Symptoms:**
- Service restarts frequently
- Memory or CPU usage spikes

**Solutions:**

1. **Check Resource Limits**
```bash
# Monitor resource usage
top -p $(pgrep -f "python.*mcp_server")

# Check container limits (if running in LXC)
cat /proc/$(pgrep -f "python.*mcp_server")/cgroup
```

2. **Review Target Registry**
```bash
# Check for problematic targets
python -c "from src.services.target_registry import TargetRegistry; tr = TargetRegistry(); print('Target count:', len(tr._targets))"

# Test individual target connectivity
python -c "from src.services.target_registry import TargetRegistry; tr = TargetRegistry(); tr.test_connectivity('target-name')"
```

## Target Connectivity Issues

### SSH Target Connection Failures

**Symptoms:**
- SSH connections timeout or fail
- Permission denied errors

**Solutions:**

1. **Test SSH Connectivity Manually**
```bash
# Test SSH connection
ssh -i /path/to/key admin@target-ip

# Check SSH configuration
ssh -v -i /path/to/key admin@target-ip
```

2. **Verify SSH Key Permissions**
```bash
# Check key file permissions
ls -la /path/to/ssh/key

# Ensure proper ownership
sudo chown systemmanager:systemmanager /path/to/ssh/key
sudo chmod 600 /path/to/ssh/key
```

3. **Check Network Connectivity**
```bash
# Test network connectivity
ping target-ip

# Check firewall rules
sudo iptables -L | grep target-ip
```

### Docker Target Connection Issues

**Symptoms:**
- Docker socket connection failures
- Permission denied on Docker socket

**Solutions:**

1. **Check Docker Socket Permissions**
```bash
# Verify socket permissions
ls -la /var/run/docker.sock

# Add user to docker group
sudo usermod -aG docker systemmanager
```

2. **Test Docker Connectivity**
```bash
# Test Docker connection
sudo docker ps

# Check Docker service status
sudo systemctl status docker
```

## Authentication Issues

### OAuth Authentication Failures

**Symptoms:**
- TSIDP authentication errors
- OAuth flow failures

**Solutions:**

1. **Check TSIDP Configuration**
```bash
# Verify TSIDP URL accessibility
curl -I https://tsidp.yourtailnet.ts.net

# Check environment variables
grep TSIDP /opt/systemmanager/.env
```

2. **Verify Tailscale Connectivity**
```bash
# Check Tailscale status
tailscale status

# Verify Tailscale ACLs
tailscale debug capver
```

### Token Authentication Issues

**Symptoms:**
- HMAC token validation failures
- Invalid token errors

**Solutions:**

1. **Check Token Configuration**
```bash
# Verify shared secret
grep SHARED_SECRET /opt/systemmanager/.env

# Test token generation
python scripts/mint_token.py --agent test-agent --scopes system:read
```

2. **Verify Token Usage**
```bash
# Check token in MCP client configuration
cat ~/.config/claude/mcp_servers.json | grep token
```

## Performance Issues

### Slow Operations

**Symptoms:**
- Operations take longer than expected
- Timeout errors

**Solutions:**

1. **Check Network Latency**
```bash
# Test network latency to targets
ping target-ip

# Check bandwidth
iperf3 -c target-ip
```

2. **Optimize Target Registry**
```yaml
# Add timeout constraints to targets.yaml
targets:
  slow-target:
    constraints:
      timeout: 120  # Increase timeout for slow targets
```

### High Resource Usage

**Symptoms:**
- High CPU or memory usage
- Gateway becomes unresponsive

**Solutions:**

1. **Monitor Resource Usage**
```bash
# Monitor CPU and memory
top -p $(pgrep -f "python.*mcp_server")

# Check for memory leaks
ps aux | grep python | grep mcp_server
```

2. **Optimize Configuration**
```bash
# Reduce concurrent operations
# In targets.yaml constraints
constraints:
  concurrency: 2  # Limit concurrent operations per target
```

## Security Issues

### Policy Gate Enforcement Failures

**Symptoms:**
- Operations blocked unexpectedly
- Capability authorization errors

**Solutions:**

1. **Check Target Capabilities**
```bash
# Verify target capabilities
python -c "from src.services.target_registry import TargetRegistry; tr = TargetRegistry(); print(tr._targets['target-name'].capabilities)"
```

2. **Review Policy Configuration**
```bash
# Check policy configuration
cat config/policy.yaml | grep -A5 -B5 operation-name
```

### Audit Log Issues

**Symptoms:**
- Audit logs not being written
- Missing operation records

**Solutions:**

1. **Check Audit Log Configuration**
```bash
# Verify audit log path
grep AUDIT_LOG /opt/systemmanager/.env

# Check log file permissions
ls -la /var/log/systemmanager/audit.log
```

2. **Test Audit Logging**
```bash
# Perform test operation and check logs
sudo journalctl -u systemmanager-mcp | grep audit
```

## Network Issues

### Tailscale Connectivity Problems

**Symptoms:**
- Tailscale connections fail
- Subnet routes not working

**Solutions:**

1. **Check Tailscale Status**
```bash
# Verify Tailscale is running
tailscale status

# Check subnet routes
tailscale status --json | jq '.Peer[] | select(.TailscaleIPs != null)'
```

2. **Verify ACL Configuration**
```bash
# Check Tailscale ACLs
tailscale debug capver

# Test connectivity to other Tailscale nodes
tailscale ping other-node
```

### Firewall Blocking Connections

**Symptoms:**
- Network connections blocked
- Port access denied

**Solutions:**

1. **Check Firewall Rules**
```bash
# Check iptables rules
sudo iptables -L -n

# Check ufw status (if using ufw)
sudo ufw status
```

2. **Verify Port Access**
```bash
# Test port accessibility
nc -zv target-ip 22  # SSH
nc -zv target-ip 2375  # Docker API
```

## Common Error Messages

### "Target not found in registry"

**Cause:** Target ID not defined in targets.yaml

**Solution:**
```bash
# Check target registry
python -c "from src.services.target_registry import TargetRegistry; tr = TargetRegistry(); print('Available targets:', list(tr._targets.keys()))"
```

### "Operation not permitted for target"

**Cause:** Missing capability authorization

**Solution:**
```yaml
# Add required capability to target
targets:
  target-name:
    capabilities:
      - "system:read"
      - "container:read"
```

### "Connection timeout"

**Cause:** Network connectivity issues or target unresponsive

**Solution:**
```bash
# Test network connectivity
ping target-ip

# Check target service status
ssh admin@target-ip "systemctl status docker"
```

## Getting Help

If you're still experiencing issues:

1. **Check Documentation**
   - [Quick Start Guide](./quickstart.md)
   - [Security Guide](./SECURITY.md)
   - [Gateway Operational Guide](./gateway-operational-guide.md)

2. **Search Existing Issues**
   - [GitHub Issues](https://github.com/mdlmarkham/TailOpsMCP/issues)

3. **Create New Issue**
   - Include detailed error messages and logs
   - Provide your targets.yaml configuration (redact secrets)
   - Include system information (OS, Python version, etc.)

---

*Last updated: $(date)*
