# Control Plane Gateway Operational Guide

## Overview

This guide provides operational procedures for deploying, configuring, and managing SystemManager control plane gateways.

## Gateway Deployment

### **Proxmox LXC Gateway Deployment**

#### **Recommended Gateway Container Configuration**

```bash
# /etc/pve/lxc/103.conf
arch: amd64
cores: 2
memory: 2048
net0: name=eth0,bridge=vmbr0,firewall=1,ip=dhcp
rootfs: local-lvm:vm-103-disk-0,size=8G

# Enable Docker for target management
features: nesting=1,keyctl=1
lxc.apparmor.profile: unconfined
lxc.cgroup2.devices.allow: c 10:200 rwm  # /dev/net/tun for Tailscale
```

#### **Automated Deployment**

```bash
# Deploy single gateway
bash -c "$(wget -qLO - https://raw.githubusercontent.com/mdlmarkham/SystemManager/master/ct/build.func)"

# Deploy multiple gateways for redundancy
./install-proxmox-multi.sh --containers 101,102,103 --auth token
```

### **Gateway Network Configuration**

#### **Tailscale Integration**

```bash
# Join gateway to Tailscale
tailscale up --auth-key=tskey-auth-xxxxx

# Configure Tailscale ACLs for gateway access
{
  "acls": [
    {
      "action": "accept",
      "src": ["tag:systemmanager-client"],
      "dst": ["tag:systemmanager-gateway:8080"]
    }
  ]
}
```

## Target Registry Configuration

### **Target Registry Structure**

Create [`targets.yaml`](targets.yaml:1) configuration file:

```yaml
version: "1.0"
targets:
  # Local gateway management
  local:
    id: "local"
    type: "local"
    executor: "local"
    capabilities:
      - "system:read"
      - "container:read"
      - "network:read"
    constraints:
      timeout: 30
      concurrency: 5

  # SSH target example
  web-server-01:
    id: "web-server-01"
    type: "remote"
    executor: "ssh"
    connection:
      host: "192.168.1.100"
      port: 22
      username: "admin"
      key_path: "${SSH_KEY_WEB_SERVER_01}"
    capabilities:
      - "system:read"
      - "container:read"
      - "network:read"
    constraints:
      timeout: 60
      sudo_policy: "limited"

  # Docker socket target
  docker-host-01:
    id: "docker-host-01"
    type: "remote"
    executor: "docker"
    connection:
      socket_path: "/var/run/docker.sock"
    capabilities:
      - "container:read"
      - "container:control"
      - "stack:deploy"
```

### **Secrets Management**

Store sensitive credentials securely:

```bash
# Create environment file for secrets
cp deploy/.env.template .env
nano .env

# Add SSH keys and credentials
SSH_KEY_WEB_SERVER_01="/opt/systemmanager/secrets/ssh-web-server-01"
DOCKER_HOST_TOKEN="your-docker-api-token"

# Secure the file
chmod 600 .env
```

## Multi-Gateway Deployment Strategy

### **Segment-Based Deployment**

Deploy gateways per network segment to limit blast radius:

```yaml
# Production Segment A
production-a-gateway:
  segment: "production-a"
  targets: ["web-a-01", "db-a-01", "cache-a-01"]

# Production Segment B
production-b-gateway:
  segment: "production-b"
  targets: ["web-b-01", "db-b-01", "cache-b-01"]

# Staging Segment
staging-gateway:
  segment: "staging"
  targets: ["staging-web-01", "staging-db-01"]
```

### **Redundancy Configuration**

Multiple gateways can manage overlapping target sets:

```yaml
# Primary gateway for production
primary-gateway:
  targets: ["web-01", "db-01", "cache-01", "monitoring-01"]

# Secondary gateway for redundancy
secondary-gateway:
  targets: ["web-01", "db-01", "cache-01", "logging-01"]
```

## Gateway Maintenance Procedures

### **Updates & Upgrades**

```bash
# Update gateway software
sudo systemctl stop systemmanager-mcp
cd /opt/systemmanager
git pull
pip install -r requirements.txt
sudo systemctl start systemmanager-mcp

# Verify gateway health
sudo systemctl status systemmanager-mcp
sudo journalctl -u systemmanager-mcp --since "5 minutes ago"
```

### **Target Registry Management**

```bash
# Backup target registry
cp /opt/systemmanager/targets.yaml /opt/systemmanager/targets.yaml.backup

# Validate target configuration
python -c "from src.services.target_registry import TargetRegistry; tr = TargetRegistry(); print('Valid targets:', list(tr._targets.keys()))"

# Reload target registry without restart
sudo systemctl reload systemmanager-mcp
```

### **Gateway Health Monitoring**

```bash
# Check gateway service status
sudo systemctl status systemmanager-mcp

# View gateway logs
sudo journalctl -u systemmanager-mcp -f

# Test gateway connectivity
curl http://localhost:8080/.well-known/oauth-protected-resource/mcp

# Verify target registry loading
sudo journalctl -u systemmanager-mcp | grep "targets.yaml"
```

## Troubleshooting

### **Common Issues**

#### **Target Connectivity Issues**

```bash
# Test SSH connectivity
ssh -i /opt/systemmanager/secrets/ssh-web-server-01 admin@192.168.1.100

# Test Docker socket access
sudo docker --host unix:///var/run/docker.sock ps

# Test HTTP API connectivity
curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com/health
```

#### **Policy Gate Authorization Issues**

```bash
# Check target capabilities
python -c "from src.services.target_registry import TargetRegistry; tr = TargetRegistry(); target = tr.get_target('web-server-01'); print('Capabilities:', target.capabilities)"

# Test policy validation
python -c "from src.services.policy_gate import PolicyGate; pg = PolicyGate(); result = pg.validate_operation('restart_container', 'docker-host-01', {'container': 'nginx'}); print('Validation:', result)"
```

#### **Gateway Performance Issues**

```bash
# Check gateway resource usage
top -p $(pgrep -f "python.*mcp_server")

# Check network connectivity
ping 192.168.1.100

# Check Tailscale status
tailscale status
```

## Monitoring & Alerting

### **Gateway Metrics**

Monitor key gateway metrics:
- CPU and memory usage
- Network connectivity to targets
- Policy Gate authorization success rate
- Target registry loading status
- Audit log volume

### **Alerting Rules**

Set up alerts for:
- Gateway service down
- Target connectivity failures
- Policy Gate authorization failures
- High gateway resource usage
- Audit log anomalies

## Backup & Recovery

### **Gateway Configuration Backup**

```bash
# Backup gateway configuration
sudo tar -czf /backup/systemmanager-gateway-$(date +%Y%m%d).tar.gz \
  /opt/systemmanager/targets.yaml \
  /opt/systemmanager/.env \
  /etc/systemd/system/systemmanager-mcp.service

# Backup audit logs
sudo tar -czf /backup/systemmanager-audit-$(date +%Y%m%d).tar.gz \
  /var/log/systemmanager/audit.log
```

### **Disaster Recovery**

1. **Gateway Failure**: Deploy new gateway from backup configuration
2. **Target Registry Loss**: Restore from backup targets.yaml
3. **Secrets Loss**: Rotate credentials and update configuration
4. **Network Isolation**: Verify Tailscale connectivity and ACLs

## Best Practices

### **Security Best Practices**

- Deploy gateways in isolated LXC containers
- Use least-privilege capabilities for targets
- Rotate SSH keys and API tokens regularly
- Monitor gateway audit logs daily
- Implement segment-based gateway deployment

### **Operational Best Practices**

- Deploy multiple gateways for redundancy
- Test target connectivity regularly
- Validate target registry configuration
- Monitor gateway performance metrics
- Maintain backup and recovery procedures

### **Maintenance Best Practices**

- Schedule regular gateway updates
- Test failover procedures
- Review and update target capabilities
- Monitor gateway resource usage
- Document operational procedures

## Related Documentation

- [Security Model](./SECURITY.md)
- [Target Registry Configuration](../targets.yaml)
- [Installation Guide](../README.md)
- [Troubleshooting Guide](./TROUBLESHOOTING.md)

---

*Last updated: $(date)*
