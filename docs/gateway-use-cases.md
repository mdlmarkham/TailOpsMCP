# Control Plane Gateway Examples & Use Cases

## Overview

This document provides practical examples and use cases for SystemManager control plane gateways, demonstrating how to deploy and configure gateways for different scenarios.

## Use Case 1: Multi-Segment Production Deployment

### **Scenario**
Deploy gateways across multiple production segments to limit blast radius and provide redundancy.

### **Target Registry Configuration**

```yaml
# targets.yaml for production-a gateway
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

  # Production Segment A targets
  web-a-01:
    id: "web-a-01"
    type: "remote"
    executor: "ssh"
    connection:
      host: "10.0.1.100"
      username: "prod-admin"
      key_path: "${SSH_KEY_PRODUCTION_A}"
    capabilities:
      - "system:read"
      - "container:read"
    constraints:
      sudo_policy: "none"

  db-a-01:
    id: "db-a-01"
    type: "remote"
    executor: "ssh"
    connection:
      host: "10.0.1.101"
      username: "prod-admin"
      key_path: "${SSH_KEY_PRODUCTION_A}"
    capabilities:
      - "system:read"
      - "container:read"
    constraints:
      sudo_policy: "none"

  cache-a-01:
    id: "cache-a-01"
    type: "remote"
    executor: "ssh"
    connection:
      host: "10.0.1.102"
      username: "prod-admin"
      key_path: "${SSH_KEY_PRODUCTION_A}"
    capabilities:
      - "system:read"
      - "container:read"
    constraints:
      sudo_policy: "none"
```

### **Gateway Deployment**

```bash
# Deploy production-a gateway
./install-proxmox-multi.sh --containers 101 --config production-a.conf

# Deploy production-b gateway
./install-proxmox-multi.sh --containers 102 --config production-b.conf

# Deploy monitoring gateway (manages shared targets)
./install-proxmox-multi.sh --containers 103 --config monitoring.conf
```

### **AI Assistant Usage**

```python
# Health check across production segment A
health_check(targets=["web-a-01", "db-a-01", "cache-a-01"])

# Security audit across production
security_audit(targets=["web-a-01", "web-b-01", "db-a-01", "db-b-01"])

# Package update across staging
update_packages(targets=["staging-web-01", "staging-db-01"])
```

## Use Case 2: Development & Staging Environment

### **Scenario**
Deploy gateways for development and staging environments with different capability levels.

### **Target Registry Configuration**

```yaml
# targets.yaml for development gateway
version: "1.0"
targets:
  local:
    id: "local"
    type: "local"
    executor: "local"
    capabilities:
      - "system:read"
      - "container:read"
      - "container:control"
      - "system:control"

  # Development targets with full capabilities
  dev-web-01:
    id: "dev-web-01"
    type: "remote"
    executor: "ssh"
    connection:
      host: "10.0.3.100"
      username: "dev-admin"
      key_path: "${SSH_KEY_DEVELOPMENT}"
    capabilities:
      - "system:read"
      - "container:read"
      - "container:control"
      - "system:control"
    constraints:
      sudo_policy: "full"

  # Staging targets with limited capabilities
  staging-web-01:
    id: "staging-web-01"
    type: "remote"
    executor: "ssh"
    connection:
      host: "10.0.2.100"
      username: "stage-admin"
      key_path: "${SSH_KEY_STAGING}"
    capabilities:
      - "system:read"
      - "container:read"
      - "container:control"
    constraints:
      sudo_policy: "limited"
```

### **Gateway Deployment**

```bash
# Deploy development gateway with no authentication
./install-proxmox-multi.sh --containers 301 --auth none

# Deploy staging gateway with token authentication
./install-proxmox-multi.sh --containers 302 --auth token
```

## Use Case 3: Docker-Only Environment

### **Scenario**
Deploy gateways that manage Docker hosts through socket connections.

### **Target Registry Configuration**

```yaml
# targets.yaml for Docker gateway
version: "1.0"
targets:
  local:
    id: "local"
    type: "local"
    executor: "local"
    capabilities:
      - "system:read"
      - "container:read"

  # Docker socket targets
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

  docker-host-02:
    id: "docker-host-02"
    type: "remote"
    executor: "docker"
    connection:
      socket_path: "/var/run/docker.sock"
    capabilities:
      - "container:read"
      - "container:control"
      - "stack:deploy"
```

### **AI Assistant Usage**

```python
# Deploy monitoring stack to all Docker hosts
deploy_stack(
    stack_name="monitoring",
    repo_url="https://github.com/user/prometheus-stack",
    targets=["docker-host-01", "docker-host-02"]
)

# Check container health across all Docker hosts
health_check(targets=["docker-host-01", "docker-host-02"])

# Analyze logs across containers
analyze_container_logs(
    name_or_id="nginx",
    targets=["docker-host-01", "docker-host-02"],
    context="Why are containers restarting?"
)
```

## Use Case 4: Hybrid Environment

### **Scenario**
Deploy gateways that manage a mix of SSH, Docker, and HTTP targets.

### **Target Registry Configuration**

```yaml
# targets.yaml for hybrid gateway
version: "1.0"
targets:
  local:
    id: "local"
    type: "local"
    executor: "local"
    capabilities:
      - "system:read"
      - "container:read"
      - "network:read"

  # SSH target for web server
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

  # Docker target for application stack
  app-docker-01:
    id: "app-docker-01"
    type: "remote"
    executor: "docker"
    connection:
      socket_path: "/var/run/docker.sock"
    capabilities:
      - "container:read"
      - "container:control"
      - "stack:deploy"

  # HTTP API target for monitoring
  monitoring-api:
    id: "monitoring-api"
    type: "remote"
    executor: "http"
    connection:
      base_url: "https://monitoring.example.com/api"
      headers:
        Authorization: "Bearer ${MONITORING_API_TOKEN}"
    capabilities:
      - "system:read"
```

### **AI Assistant Usage**

```python
# Comprehensive health check across all target types
health_check(targets=["web-server-01", "app-docker-01", "monitoring-api"])

# Deploy application stack
deploy_stack(
    stack_name="application",
    repo_url="https://github.com/user/app-stack",
    targets=["app-docker-01"]
)

# Monitor system metrics from all sources
system_status(targets=["web-server-01", "app-docker-01", "monitoring-api"])
```

## Use Case 5: Multi-Gateway Redundancy

### **Scenario**
Deploy multiple gateways that manage overlapping target sets for high availability.

### **Target Registry Configuration**

```yaml
# targets.yaml for primary gateway
version: "1.0"
targets:
  local:
    id: "local"
    type: "local"
    executor: "local"
    capabilities:
      - "system:read"
      - "container:read"

  # Critical production targets
  web-01:
    id: "web-01"
    type: "remote"
    executor: "ssh"
    connection:
      host: "10.0.1.100"
      username: "admin"
      key_path: "${SSH_KEY_PRIMARY}"
    capabilities:
      - "system:read"
      - "container:read"

  db-01:
    id: "db-01"
    type: "remote"
    executor: "ssh"
    connection:
      host: "10.0.1.101"
      username: "admin"
      key_path: "${SSH_KEY_PRIMARY}"
    capabilities:
      - "system:read"
      - "container:read"

  # Shared monitoring target
  monitoring-01:
    id: "monitoring-01"
    type: "remote"
    executor: "ssh"
    connection:
      host: "10.0.1.102"
      username: "admin"
      key_path: "${SSH_KEY_PRIMARY}"
    capabilities:
      - "system:read"
      - "container:read"
```

```yaml
# targets.yaml for secondary gateway
version: "1.0"
targets:
  local:
    id: "local"
    type: "local"
    executor: "local"
    capabilities:
      - "system:read"
      - "container:read"

  # Critical production targets (same as primary)
  web-01:
    id: "web-01"
    type: "remote"
    executor: "ssh"
    connection:
      host: "10.0.1.100"
      username: "admin"
      key_path: "${SSH_KEY_SECONDARY}"
    capabilities:
      - "system:read"
      - "container:read"

  db-01:
    id: "db-01"
    type: "remote"
    executor: "ssh"
    connection:
      host: "10.0.1.101"
      username: "admin"
      key_path: "${SSH_KEY_SECONDARY}"
    capabilities:
      - "system:read"
      - "container:read"

  # Different shared target
  logging-01:
    id: "logging-01"
    type: "remote"
    executor: "ssh"
    connection:
      host: "10.0.1.103"
      username: "admin"
      key_path: "${SSH_KEY_SECONDARY}"
    capabilities:
      - "system:read"
      - "container:read"
```

### **Gateway Deployment**

```bash
# Deploy primary gateway
./install-proxmox-multi.sh --containers 101 --config primary.conf

# Deploy secondary gateway
./install-proxmox-multi.sh --containers 102 --config secondary.conf

# Configure AI assistant to use both gateways
{
  "mcpServers": {
    "systemmanager-primary": {
      "command": "python",
      "args": ["-m", "src.mcp_server"],
      "env": {
        "SYSTEMMANAGER_TARGETS_CONFIG": "/opt/systemmanager/primary/targets.yaml"
      }
    },
    "systemmanager-secondary": {
      "command": "python",
      "args": ["-m", "src.mcp_server"],
      "env": {
        "SYSTEMMANAGER_TARGETS_CONFIG": "/opt/systemmanager/secondary/targets.yaml"
      }
    }
  }
}
```

## Use Case 6: Policy Gate Security Testing

### **Scenario**
Test Policy Gate security controls and capability enforcement.

### **Target Registry Configuration**

```yaml
# targets.yaml for security testing
version: "1.0"
targets:
  local:
    id: "local"
    type: "local"
    executor: "local"
    capabilities:
      - "system:read"
      - "container:read"

  # Target with limited capabilities
  test-limited:
    id: "test-limited"
    type: "remote"
    executor: "ssh"
    connection:
      host: "10.0.99.100"
      username: "test-user"
      key_path: "${SSH_KEY_TEST}"
    capabilities:
      - "system:read"
    constraints:
      sudo_policy: "none"
      allowed_ports: [80, 443]

  # Target with broader capabilities
  test-broad:
    id: "test-broad"
    type: "remote"
    executor: "ssh"
    connection:
      host: "10.0.99.101"
      username: "test-user"
      key_path: "${SSH_KEY_TEST}"
    capabilities:
      - "system:read"
      - "container:read"
      - "container:control"
    constraints:
      sudo_policy: "limited"
```

### **Security Testing**

```python
# Test capability enforcement
# This should succeed (target has system:read capability)
health_check(target="test-limited")

# This should fail (target lacks container:control capability)
try:
    restart_container(target="test-limited", container="nginx")
except PolicyGateError as e:
    print(f"Security control working: {e}")

# Test parameter validation
# This should succeed (port 80 is allowed)
scan_ports(target="test-limited", range="80-80")

# This should fail (port 22 is not allowed)
try:
    scan_ports(target="test-limited", range="22-22")
except PolicyGateError as e:
    print(f"Parameter validation working: {e}")
```

## Best Practices for Use Cases

### **Security Best Practices**

1. **Segment Isolation**: Deploy gateways per network segment
2. **Capability Least Privilege**: Grant only necessary capabilities
3. **Credential Separation**: Use different credentials per gateway
4. **Regular Testing**: Test Policy Gate enforcement regularly
5. **Audit Monitoring**: Monitor gateway audit logs

### **Operational Best Practices**

1. **Redundancy Planning**: Deploy multiple gateways for critical targets
2. **Configuration Management**: Store target registries in version control
3. **Health Monitoring**: Monitor gateway and target connectivity
4. **Backup Procedures**: Regularly backup gateway configurations
5. **Documentation**: Document gateway purposes and target mappings

### **Maintenance Best Practices**

1. **Regular Updates**: Keep gateways and targets updated
2. **Credential Rotation**: Rotate SSH keys and API tokens
3. **Capacity Planning**: Monitor gateway resource usage
4. **Disaster Recovery**: Test failover procedures
5. **Performance Testing**: Test gateway performance under load

## Related Documentation

- [Gateway Operational Guide](./gateway-operational-guide.md)
- [Target Registry Guide](./target-registry-guide.md)
- [Security Model](./SECURITY.md)
- [Installation Guide](../README.md)

---

*Last updated: $(date)*
