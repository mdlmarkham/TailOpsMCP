# Target Registry & Multi-System Management

## Overview

SystemManager's Target Registry provides centralized management of all systems and applications across your infrastructure. Unlike the previous agent-on-node approach, the control plane gateway architecture allows a single trusted gateway to manage multiple targets through a centralized registry.

This system solves the problem of **knowing what's running where** while providing enhanced security through capability-based authorization and Policy Gate enforcement.

## Key Concepts

### Target Registry Architecture

The Target Registry replaces the previous per-node inventory system with a centralized approach:

- **Centralized Registry**: One gateway manages multiple targets through a single configuration file
- **Capability-Based Authorization**: Each target has specific capabilities (read, control, deploy, etc.)
- **Policy Gate Enforcement**: All operations are validated against target capabilities and constraints
- **Network Segmentation**: Gateways are deployed per network segment to limit blast radius

### Target Types

Targets can be managed through different executors:

- **SSH Targets**: Remote systems accessed via SSH
- **Docker Targets**: Docker hosts via socket connections
- **HTTP Targets**: REST APIs and web services
- **Local Target**: The gateway itself for local operations

### Target Capabilities

Each target has specific capabilities that define what operations are allowed:

- **system:read**: Read system information (CPU, memory, disk)
- **container:read**: Read container/application status
- **container:control**: Start/stop/restart containers
- **stack:deploy**: Deploy Docker stacks
- **network:read**: Read network configuration
- **system:control**: Execute system commands (with constraints)

### Target Configuration

Each target in the registry includes:

- **ID**: Unique identifier (e.g., `web-01`, `db-01`)
- **Type**: Target type (`ssh`, `docker`, `http`, `local`)
- **Executor**: Connection method (`ssh`, `docker`, `http`, `local`)
- **Connection Details**: Host, credentials, or socket paths
- **Capabilities**: Authorized operations for this target
- **Constraints**: Security limits (sudo policy, allowed ports, etc.)
- **Application Discovery**: Auto-detection of running applications

## Application Discovery

SystemManager can automatically discover applications running on targets:

| Category | Applications |
|----------|--------------|
| **Media** | Jellyfin, Plex |
| **Network** | Pi-hole, AdGuard Home, WireGuard |
| **Databases** | PostgreSQL, MySQL, MariaDB, MongoDB, Redis |
| **Web Servers** | Nginx, Apache |
| **Home Automation** | Home Assistant |
| **Monitoring** | Prometheus, Grafana |
| **AI/LLM** | Ollama |
| **Cloud** | Nextcloud |
| **Management** | Portainer |

### Discovery Method

The application scanner uses multiple signals to detect applications on targets:

1. **systemd Services**: Checks for running services by name
2. **Processes**: Looks for running processes
3. **Listening Ports**: Detects applications by their default ports
4. **File System**: Checks for config files and directories
5. **Version Commands**: Attempts to query version information

Each detection gets a confidence score (0.0 to 1.0). Applications need at least 0.3 confidence to be reported.

## Target Registry Configuration

The Target Registry is configured through a YAML file (`targets.yaml`) that defines all managed targets:

```yaml
# targets.yaml
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

  # SSH target for web server
  web-01:
    id: "web-01"
    type: "remote"
    executor: "ssh"
    connection:
      host: "10.0.1.100"
      username: "admin"
      key_path: "${SSH_KEY_WEB_01}"
    capabilities:
      - "system:read"
      - "container:read"
      - "container:control"
    constraints:
      sudo_policy: "limited"
      allowed_ports: [80, 443]

  # Docker target for application stack
  docker-01:
    id: "docker-01"
    type: "remote"
    executor: "docker"
    connection:
      socket_path: "/var/run/docker.sock"
    capabilities:
      - "container:read"
      - "container:control"
      - "stack:deploy"
```

## Usage Workflows

### Initial Gateway Setup

1. **Deploy Gateway**: Install SystemManager on a control plane node
2. **Configure Targets**: Create `targets.yaml` with your managed systems
3. **Set Credentials**: Configure SSH keys, API tokens, or other credentials
4. **Test Connectivity**: Verify all targets are accessible
5. **Discover Applications**: Run initial application discovery

### AI Assistant Usage

```python
# Health check across all targets
health_check(targets=["web-01", "docker-01", "local"])

# Deploy stack to Docker target
deploy_stack(
    stack_name="monitoring",
    repo_url="https://github.com/user/prometheus-stack",
    targets=["docker-01"]
)

# Security audit across production targets
security_audit(targets=["web-01", "web-02", "db-01"])
```

### Multi-Segment Management

For larger deployments, deploy multiple gateways per network segment:

```yaml
# Production Segment A gateway
targets:
  web-a-01:
    id: "web-a-01"
    type: "ssh"
    connection:
      host: "10.0.1.100"
      username: "prod-admin"
      key_path: "${SSH_KEY_PRODUCTION_A}"
    capabilities:
      - "system:read"
      - "container:read"

# Production Segment B gateway
targets:
  web-b-01:
    id: "web-b-01"
    type: "ssh"
    connection:
      host: "10.0.2.100"
      username: "prod-admin"
      key_path: "${SSH_KEY_PRODUCTION_B}"
    capabilities:
      - "system:read"
      - "container:read"
```

## Security Model

### Capability-Based Authorization

Each target has specific capabilities that limit what operations can be performed:

- **Read-Only Targets**: Can only read system information
- **Limited Control Targets**: Can control containers but not execute arbitrary commands
- **Full Control Targets**: Can execute system commands with constraints

### Policy Gate Enforcement

The Policy Gate validates all operations against:

1. **Target Capabilities**: Is the operation allowed for this target?
2. **Parameter Constraints**: Are the parameters within allowed ranges?
3. **Security Policies**: Does the operation comply with security rules?

### Example Security Controls

```yaml
# Target with limited capabilities
limited-target:
  capabilities:
    - "system:read"
    - "container:read"
  constraints:
    sudo_policy: "none"
    allowed_ports: [80, 443]

# Target with broader capabilities
broad-target:
  capabilities:
    - "system:read"
    - "container:read"
    - "container:control"
    - "system:control"
  constraints:
    sudo_policy: "limited"
    allowed_ports: [22, 80, 443, 5432, 6379]
```

## Best Practices

### 1. Segment-Based Deployment

- Deploy gateways per network segment to limit blast radius
- Use different credentials for each gateway
- Configure Tailscale ACLs to restrict gateway access

### 2. Capability Least Privilege

- Grant only necessary capabilities to each target
- Use read-only capabilities for monitoring targets
- Limit system:control capabilities to trusted targets

### 3. Credential Management

- Store SSH keys and API tokens securely
- Use environment variables for sensitive configuration
- Rotate credentials regularly

### 4. Monitoring and Auditing

- Monitor gateway connectivity to targets
- Review audit logs for security events
- Test Policy Gate enforcement regularly

## Troubleshooting

### Target Connectivity Issues

1. **Check Network Connectivity**: Verify the gateway can reach the target
2. **Verify Credentials**: Ensure SSH keys or API tokens are valid
3. **Check Firewall Rules**: Confirm ports are accessible
4. **Test Executor**: Use manual commands to test the connection

### Application Discovery Problems

1. **Verify Target Access**: Ensure the gateway has permission to scan the target
2. **Check Application Status**: Confirm applications are running
3. **Manual Discovery**: Use manual commands to verify application detection
4. **Update Detection Rules**: Contribute new detection patterns if needed

### Policy Gate Errors

1. **Check Capabilities**: Verify the target has the required capability
2. **Review Constraints**: Check if parameters violate constraints
3. **Security Audit**: Review the operation for security compliance

## Related Documentation

- [Gateway Operational Guide](./gateway-operational-guide.md)
- [Security Model](./SECURITY.md)
- [Installation Guide](../README.md)
- [Use Cases](./gateway-use-cases.md)

---

*Last updated: $(date)*