# Proxmox VE Integration Guide

## Overview

This guide provides comprehensive documentation for the TailOpsMCP Proxmox VE integration, enabling native Proxmox management capabilities through policy-driven operations, security integration, and comprehensive monitoring.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Installation and Setup](#installation-and-setup)
3. [Configuration](#configuration)
4. [API Integration](#api-integration)
5. [CLI Integration](#cli-integration)
6. [Discovery Pipeline](#discovery-pipeline)
7. [Capability Operations](#capability-operations)
8. [MCP Tools](#mcp-tools)
9. [Security Integration](#security-integration)
10. [Monitoring and Health Checks](#monitoring-and-health-checks)
11. [Best Practices](#best-practices)
12. [Troubleshooting](#troubleshooting)

## Architecture Overview

The Proxmox integration consists of several key components:

```
┌─────────────────────────────────────────────────────────────┐
│                    TailOpsMCP Gateway                       │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │   MCP Tools     │  │   Capabilities  │  │   Discovery  │ │
│  │   Interface     │  │   Executor      │  │   Pipeline   │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │  Proxmox API    │  │   Proxmox CLI   │  │   Security   │ │
│  │   Client        │  │   Wrapper       │  │   & Audit    │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
├─────────────────────────────────────────────────────────────┤
│              Proxmox VE Cluster (Physical)                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │  PVE Node 1     │  │  PVE Node 2     │  │  PVE Node 3  │ │
│  │  Containers/VMs │  │  Containers/VMs │  │  Containers  │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Key Components

- **ProxmoxAPI Client**: HTTP API integration with comprehensive error handling
- **ProxmoxCLI Wrapper**: CLI-based operations for local environments
- **ProxmoxDiscovery**: Enhanced discovery with API and CLI integration
- **ProxmoxCapabilities**: Policy-driven capability operations
- **ProxmoxTools**: High-level MCP tools for user interaction
- **ProxmoxSecurity**: Security integration with audit logging
- **ProxmoxMonitoring**: Health checks, metrics, and alerting

## Installation and Setup

### Prerequisites

- Python 3.8+
- Proxmox VE 6.0+ or 7.0+
- Network access to Proxmox hosts
- Appropriate user permissions on Proxmox hosts

### Installation

1. **Install Dependencies**:
   ```bash
   pip install aiohttp pydantic PyYAML
   ```

2. **Configure Proxmox User**:
   Create a dedicated user for TailOpsMCP:
   ```bash
   # In Proxmox VE GUI or via CLI
   pveum user add tailopsmcp@pve -password
   pveum role add TailOpsMCP -privs VM.Audit,VM.Config.Disk,VM.Config.Network,VM.Config.Options,VM.Clone,VM.Config.CPU,VM.Config.Memory,VM.PowerMgmt,VM.Monitor,Datastore.Audit,Datastore.Content,Pool.Allocate,Pool.Audit
   pveum aclmod / -user tailopsmcp@pve -role TailOpsMCP
   ```

3. **Generate API Token** (Recommended):
   ```bash
   pveum user modify tailopsmcp@pve -enable
   pveum user token add tailopsmcp@pve tailopsmcp-token -privs VM.Audit,VM.Config.Disk,VM.Config.Network,VM.Config.Options,VM.Clone,VM.Config.CPU,VM.Config.Memory,VM.PowerMgmt,VM.Monitor,Datastore.Audit,Datastore.Content,Pool.Allocate,Pool.Audit
   ```

## Configuration

### Basic Configuration

Create a `proxmox-config.yaml` file:

```yaml
# Basic Proxmox Configuration
proxmox:
  hosts:
    - host: "pve.cluster.local"
      username: "tailopsmcp@pve"
      api_token: "${PROXMOX_API_TOKEN}"  # Use environment variable
      token_name: "tailopsmcp-token"
      verify_ssl: true
      port: 8006
      timeout: 30
      tags:
        - "production"
        - "primary"

  defaults:
    storage: "local-lvm"
    network_bridge: "vmbr0"
    default_container_cores: 2
    default_container_memory: 1024
    default_container_disk: 20

  discovery:
    auto_discover: true
    update_interval: 300
    include_templates: true
    include_storage: true

  security:
    api_rate_limit: 100
    ssl_verification: true
    audit_logging:
      enabled: true
      log_file: "/var/log/tailopsmcp/proxmox-audit.log"
```

### Environment Variables

Set up environment variables for sensitive data:

```bash
# Authentication
export PROXMOX_API_TOKEN="your-api-token-here"
export PROXMOX_PASSWORD="your-password-here"

# Security
export PROXMOX_SSL_CA_BUNDLE="/path/to/ca-bundle.crt"

# Monitoring
export PROMETHEUS_PUSHGATEWAY_URL="http://prometheus-pushgateway:9091"
```

### Advanced Configuration

#### Multi-Cluster Setup

```yaml
proxmox:
  hosts:
    - host: "pve-cluster1.local"
      username: "tailopsmcp@pve"
      api_token: "${PROXMOX_CLUSTER1_TOKEN}"
      tags: ["cluster1", "production"]
    - host: "pve-cluster2.local"
      username: "tailopsmcp@pve"
      api_token: "${PROXMOX_CLUSTER2_TOKEN}"
      tags: ["cluster2", "development"]
```

#### Security Hardening

```yaml
proxmox:
  security:
    ssl_verification: true
    ssl_ca_bundle: "/etc/ssl/certs/ca-certificates.crt"

    # Rate limiting
    api_rate_limit: 60  # requests per minute
    burst_limit: 10     # burst requests

    # Access control
    allowed_operations:
      - "create_container"
      - "start_container"
      - "stop_container"
      - "snapshot_create"
      - "backup_create"

    denied_operations:
      - "delete_container"
      - "delete_snapshot"
      - "migrate_container"

  audit_logging:
    enabled: true
    log_level: "INFO"
    include_parameters: false  # Don't log sensitive data
    retention_days: 90
```

#### Monitoring Integration

```yaml
proxmox:
  monitoring:
    health_checks:
      enabled: true
      interval: 60
      timeout: 10

    metrics:
      enabled: true
      endpoint: "/metrics"
      interval: 60

    alerts:
      enabled: true
      webhook_url: "${ALERT_WEBHOOK_URL}"

      conditions:
        - name: "host_down"
          condition: "host_status == 'offline'"
          severity: "critical"
        - name: "high_cpu"
          condition: "cpu_usage > 80"
          severity: "warning"
```

## API Integration

### Basic API Usage

```python
from src.services.proxmox_api import ProxmoxAPI
from src.models.proxmox_models import ProxmoxAPICredentials

# Create credentials
credentials = ProxmoxAPICredentials(
    host="pve.cluster.local",
    username="tailopsmcp@pve",
    api_token="your-api-token"
)

# Use API client
async with ProxmoxAPI(credentials) as api:
    # Test connection
    result = await api.test_connection()
    print(f"Connected: {result.success}")

    # List containers
    containers = await api.list_containers()
    for container in containers:
        print(f"Container {container.vmid}: {container.name}")

    # Create container
    from src.models.proxmox_models import ContainerConfig
    config = ContainerConfig(
        ostemplate="local:vztmpl/debian-12-standard_12.7-1_amd64.tar.gz",
        hostname="my-container",
        cores=2,
        memory=1024
    )

    result = await api.create_container(config)
    print(f"Created container: {result.vmid}")
```

### Advanced API Operations

#### Container Management

```python
# Start container
await api.start_container(100)

# Stop container (with force option)
await api.stop_container(100, force=True)

# Reboot container
await api.reboot_container(100)

# Clone container
from src.models.proxmox_models import CloneConfig
clone_config = CloneConfig(
    hostname="cloned-container",
    full=True
)
await api.clone_container(100, clone_config)

# Update resources
resources = {"cores": 4, "memory": 2048}
await api.update_container_resources(100, resources)
```

#### Snapshot Management

```python
# Create snapshot
await api.create_snapshot(100, "pre-update", "Before system update")

# List snapshots
snapshots = await api.list_snapshots(100)
for snapshot in snapshots:
    print(f"Snapshot: {snapshot.name}")

# Restore snapshot
await api.restore_snapshot(100, "pre-update", rollback=False)

# Delete snapshot
await api.delete_snapshot(100, "pre-update")
```

#### Backup Operations

```python
from src.models.proxmox_models import BackupConfig

# Create backup
backup_config = BackupConfig(
    node="pve-node-01",
    storage="local",
    mode="snapshot"
)
await api.create_backup(100, backup_config)

# List backups
backups = await api.list_backups(storage="local")
for backup in backups:
    print(f"Backup: {backup.filename}")

# Note: Restore operations require additional implementation
```

## CLI Integration

### Local Environment CLI Usage

```python
from src.services.proxmox_cli import ProxmoxCLI

# Create CLI client
cli = ProxmoxCLI()

if cli.is_available():
    # List containers
    containers = await cli.list_containers_cli()

    # Create container
    config = ContainerConfig(
        ostemplate="local:vztmpl/debian-12-standard_12.7-1_amd64.tar.gz",
        hostname="cli-container"
    )
    result = await cli.create_container_cli(config)

    # Container operations
    await cli.start_container_cli(101)
    await cli.stop_container_cli(101, force=True)

    # Snapshot operations
    await cli.create_snapshot_cli(101, "cli-snapshot")
    await cli.restore_snapshot_cli(101, "cli-snapshot")
```

### CLI Command Reference

The CLI wrapper supports the following Proxmox commands:

- `pct list` - List containers
- `pct create` - Create container
- `pct start/stop/reboot` - Container lifecycle
- `pct destroy` - Delete container
- `pct clone` - Clone container
- `pct snapshot` - Create snapshot
- `pct rollback` - Restore snapshot
- `qm list` - List VMs
- `vzdump` - Create backups

## Discovery Pipeline

### Host Discovery

```python
from src.services.proxmox_discovery_enhanced import ProxmoxDiscoveryEnhanced

# Create discovery service
credentials = [ProxmoxAPICredentials(host="pve.cluster.local", ...)]
discovery = ProxmoxDiscoveryEnhanced(api_credentials=credentials)

# Discover hosts
hosts = await discovery.discover_proxmox_hosts()
for host in hosts:
    print(f"Host: {host.hostname} ({host.address})")
    print(f"  Version: {host.version}")
    print(f"  Resources: {host.cpu_cores} cores, {host.memory_mb} MB")
    print(f"  Status: {'Active' if host.is_active else 'Inactive'}")
```

### Container and VM Discovery

```python
# Discover containers on a host
containers = await discovery.discover_containers(host)
for container in containers:
    print(f"Container {container.vmid}: {container.name}")
    print(f"  Status: {container.status}")
    print(f"  Resources: {container.cpu_cores} cores, {container.memory_mb} MB")

# Discover VMs on a host
vms = await discovery.discover_vms(host)
for vm in vms:
    print(f"VM {vm.vmid}: {vm.name}")
    print(f"  Status: {vm.status}")
```

### Storage and Resource Discovery

```python
# Discover storage pools
storage_pools = await discovery.discover_storage_pools(host)
for storage in storage_pools:
    print(f"Storage {storage.storage}: {storage.type.value}")
    print(f"  Content: {', '.join(storage.content)}")
    print(f"  Used: {storage.used} / {storage.total}")

# Discover snapshots
snapshots = await discovery.discover_snapshots(container_node)
for snapshot in snapshots:
    print(f"Snapshot: {snapshot.name}")
    print(f"  Description: {snapshot.description}")
```

## Capability Operations

### Policy-Driven Operations

```python
from src.services.proxmox_capabilities import ProxmoxCapabilityExecutor

# Create capability executor
executor = ProxmoxCapabilityExecutor(api_credentials)

# Execute container creation capability
parameters = {
    "host": "pve.cluster.local",
    "template": "local:vztmpl/debian-12-standard_12.7-1_amd64.tar.gz",
    "hostname": "capability-container",
    "cores": 2,
    "memory": 1024
}

result = await executor.execute_proxmox_container_create(parameters)
if result.success:
    print(f"Container created: {result.output}")
else:
    print(f"Creation failed: {result.error}")
```

### Capability Types

The system supports the following capabilities:

#### Container Operations
- `PROXMOX_CONTAINER_CREATE` - Create containers from templates
- `PROXMOX_CONTAINER_START` - Start containers
- `PROXMOX_CONTAINER_STOP` - Stop containers
- `PROXMOX_CONTAINER_REBOOT` - Reboot containers
- `PROXMOX_CONTAINER_DELETE` - Delete containers
- `PROXMOX_CONTAINER_CLONE` - Clone containers
- `PROXMOX_CONTAINER_STATUS` - Get container status
- `PROXMOX_CONTAINER_RESOURCES` - Update container resources

#### VM Operations
- `PROXMOX_VM_CREATE` - Create VMs
- `PROXMOX_VM_START` - Start VMs
- `PROXMOX_VM_STOP` - Stop VMs
- `PROXMOX_VM_DELETE` - Delete VMs

#### Snapshot Operations
- `PROXMOX_SNAPSHOT_CREATE` - Create snapshots
- `PROXMOX_SNAPSHOT_DELETE` - Delete snapshots
- `PROXMOX_SNAPSHOT_RESTORE` - Restore snapshots
- `PROXMOX_SNAPSHOT_LIST` - List snapshots

#### Backup Operations
- `PROXMOX_BACKUP_CREATE` - Create backups
- `PROXMOX_BACKUP_LIST` - List backups
- `PROXMOX_BACKUP_DELETE` - Delete backups

#### Discovery Operations
- `PROXMOX_DISCOVER_HOSTS` - Discover Proxmox hosts
- `PROXMOX_DISCOVER_CONTAINERS` - Discover containers
- `PROXMOX_DISCOVER_VMS` - Discover VMs
- `PROXMOX_DISCOVER_STORAGE` - Discover storage pools

## MCP Tools

### Tool Registration

```python
from src.tools.proxmox_tools import ProxmoxTools, get_proxmox_tool_definitions

# Create Proxmox tools
tools = ProxmoxTools(api_credentials)

# Get tool definitions for MCP registration
tool_definitions = get_proxmox_tool_definitions()

# Register tools with your MCP server
for tool_def in tool_definitions:
    mcp_server.register_tool(tool_def)
```

### Available MCP Tools

#### Discovery Tools

```javascript
// Discover all Proxmox hosts
{
  "tool": "proxmox_discover",
  "arguments": {}
}

// Discover containers on a specific host
{
  "tool": "proxmox_discover_containers",
  "arguments": {
    "host": "pve.cluster.local"
  }
}

// Discover VMs on a specific host
{
  "tool": "proxmox_discover_vms",
  "arguments": {
    "host": "pve.cluster.local"
  }
}
```

#### Container Management Tools

```javascript
// Create container from template
{
  "tool": "create_ct_from_template",
  "arguments": {
    "template_id": 900,
    "config": {
      "host": "pve.cluster.local",
      "template": "local:vztmpl/debian-12-standard_12.7-1_amd64.tar.gz",
      "hostname": "my-container",
      "cores": 2,
      "memory": 1024,
      "rootfs": "local-lvm:20"
    }
  }
}

// Start container
{
  "tool": "start_ct",
  "arguments": {
    "vmid": 100,
    "host": "pve.cluster.local"
  }
}

// Stop container
{
  "tool": "stop_ct",
  "arguments": {
    "vmid": 100,
    "host": "pve.cluster.local",
    "force": false
  }
}

// Reboot container
{
  "tool": "reboot_ct",
  "arguments": {
    "vmid": 100,
    "host": "pve.cluster.local"
  }
}

// Delete container
{
  "tool": "delete_ct",
  "arguments": {
    "vmid": 100,
    "host": "pve.cluster.local"
  }
}

// Clone container
{
  "tool": "clone_ct",
  "arguments": {
    "source_vmid": 100,
    "clone_config": {
      "host": "pve.cluster.local",
      "new_hostname": "cloned-container",
      "full_clone": true
    }
  }
}
```

#### Snapshot Management Tools

```javascript
// Create snapshot
{
  "tool": "snapshot_ct",
  "arguments": {
    "vmid": 100,
    "snapshot_name": "pre-update",
    "host": "pve.cluster.local",
    "description": "Before system update"
  }
}

// Delete snapshot
{
  "tool": "delete_snapshot",
  "arguments": {
    "vmid": 100,
    "snapshot_name": "pre-update",
    "host": "pve.cluster.local"
  }
}

// Restore snapshot
{
  "tool": "restore_snapshot",
  "arguments": {
    "vmid": 100,
    "snapshot_name": "pre-update",
    "host": "pve.cluster.local",
    "rollback": false
  }
}
```

#### Backup Management Tools

```javascript
// Create backup
{
  "tool": "backup_ct",
  "arguments": {
    "container_id": 100,
    "backup_config": {
      "host": "pve.cluster.local",
      "storage": "local",
      "mode": "snapshot",
      "compress": "gzip"
    }
  }
}
```

#### Resource Management Tools

```javascript
// Update container resources
{
  "tool": "update_ct_resources",
  "arguments": {
    "container_id": 100,
    "resources": {
      "host": "pve.cluster.local",
      "cores": 4,
      "memory": 2048
    }
  }
}
```

#### Status and Monitoring Tools

```javascript
// Get host status
{
  "tool": "get_proxmox_status",
  "arguments": {
    "host": "pve.cluster.local"
  }
}

// Get container status
{
  "tool": "get_container_status",
  "arguments": {
    "vmid": 100,
    "host": "pve.cluster.local"
  }
}
```

## Security Integration

### Security Context

```python
from src.utils.proxmox_security import ProxmoxSecurityContext

# Create security context
security_context = ProxmoxSecurityContext(
    user="admin@company.com",
    source_ip="192.168.1.100",
    mcp_client="tailopsmcp-ui",
    tags=["admin", "production"]
)
```

### Security Logging

```python
from src.utils.proxmox_security import (
    ProxmoxSecurityLogger,
    ProxmoxSecurityEventType,
    SecuritySeverity
)

# Create security logger
security_logger = ProxmoxSecurityLogger()

# Log security event
security_logger.log_security_event(
    event_type=ProxmoxSecurityEventType.CONTAINER_CREATE,
    security_context=security_context,
    target_host="pve.cluster.local",
    operation="create_container",
    resource_type="container",
    resource_id=100,
    authorized=True,
    risk_level=SecuritySeverity.LOW
)
```

### Access Control

```python
from src.utils.proxmox_security import ProxmoxSecurityManager

# Create security manager
security_manager = ProxmoxSecurityManager(security_logger)

# Validate credentials
credentials = ProxmoxAPICredentials(
    host="pve.cluster.local",
    username="tailopsmcp@pve",
    api_token="token"
)

is_valid = security_manager.validate_credentials(credentials, security_context)
if is_valid:
    print("Credentials validated successfully")
else:
    print("Credential validation failed")
```

### Audit Trail

The system maintains comprehensive audit logs including:

- **Authentication events**: Login/logout attempts
- **Authorization decisions**: Policy allow/deny decisions
- **Operation execution**: All Proxmox operations
- **Configuration changes**: System configuration modifications
- **Security events**: Failed operations, suspicious activities

Logs are stored in JSON format with sensitive data redacted:

```json
{
  "timestamp": "2025-12-14T03:00:00.000Z",
  "event_type": "container_create",
  "security_context": {
    "user": "admin@company.com",
    "source_ip": "192.168.1.100",
    "tags": ["admin", "production"]
  },
  "target_host": "pve.cluster.local",
  "operation": "create_container",
  "resource_type": "container",
  "resource_id": 100,
  "authorized": true,
  "risk_level": "low",
  "duration_ms": 2500.5
}
```

## Monitoring and Health Checks

### Health Checks

```python
from src.utils.proxmox_monitoring import ProxmoxHealthChecker

# Create health checker
health_checker = ProxmoxHealthChecker(api_credentials)

# Check host health
result = await health_checker.check_host_health("pve.cluster.local")
print(f"Host status: {result.status.value}")
print(f"Message: {result.message}")
print(f"Response time: {result.response_time_ms}ms")

# Check all hosts
all_results = await health_checker.check_all_hosts()
for host, result in all_results.items():
    print(f"{host}: {result.status.value}")
```

### Metrics Collection

```python
from src.utils.proxmox_monitoring import ProxmoxMetricsCollector

# Create metrics collector
metrics_collector = ProxmoxMetricsCollector(api_credentials)

# Collect metrics
metrics = await metrics_collector.collect_all_metrics()
for metric in metrics:
    print(f"Metric: {metric.name} = {metric.value}")

# Get Prometheus format
prometheus_output = metrics_collector.get_metrics_as_prometheus()
```

### Alerting

```python
from src.utils.proxmox_monitoring import ProxmoxAlertManager, AlertRule, AlertSeverity

# Create custom alert rules
alert_rules = [
    AlertRule(
        name="high_cpu_usage",
        condition="cpu_percent > 80",
        severity=AlertSeverity.WARNING,
        description="High CPU usage detected"
    ),
    AlertRule(
        name="container_error",
        condition="container_status == 'error'",
        severity=AlertSeverity.ERROR,
        description="Container in error state"
    )
]

# Create alert manager
alert_manager = ProxmoxAlertManager(alert_rules)

# Evaluate alerts
alerts = alert_manager.evaluate_alerts(health_results, metrics)
for alert in alerts:
    print(f"Alert: {alert['name']} - {alert['severity']}")
```

### Monitoring Service

```python
from src.utils.proxmox_monitoring import ProxmoxMonitoringService

# Create monitoring service
monitoring_service = ProxmoxMonitoringService(
    api_credentials=api_credentials,
    monitoring_integrations=integrations
)

# Start monitoring
await monitoring_service.start_monitoring()

# Get status
status = await monitoring_service.get_monitoring_status()
print(f"Service running: {status['service_running']}")
print(f"Healthy hosts: {status['health_summary']['healthy_hosts']}")

# Manual health check
health_report = await monitoring_service.manual_health_check()
```

## Best Practices

### Security Best Practices

1. **Use API Tokens**: Always prefer API tokens over passwords
2. **SSL Verification**: Enable SSL verification in production
3. **Least Privilege**: Grant minimal required permissions
4. **Regular Audits**: Review audit logs regularly
5. **Network Segmentation**: Restrict API access to trusted networks
6. **Credential Rotation**: Rotate credentials regularly

### Performance Best Practices

1. **Connection Pooling**: Reuse API connections
2. **Rate Limiting**: Implement appropriate rate limits
3. **Caching**: Cache discovery results
4. **Async Operations**: Use async/await for better concurrency
5. **Timeout Configuration**: Set appropriate timeouts

### Operational Best Practices

1. **Monitoring**: Enable comprehensive monitoring
2. **Backup Strategy**: Implement regular backups
3. **Snapshot Strategy**: Use snapshots for safety
4. **Resource Limits**: Set appropriate resource limits
5. **Template Management**: Maintain good template practices

### Configuration Best Practices

1. **Environment Variables**: Use environment variables for secrets
2. **Configuration Validation**: Validate configuration on startup
3. **Environment Separation**: Use different configs for dev/prod
4. **Documentation**: Keep configuration well documented
5. **Version Control**: Version control configuration files

## Troubleshooting

### Common Issues

#### Connection Issues

```python
# Test connection
async with ProxmoxAPI(credentials) as api:
    result = await api.test_connection()
    if not result.success:
        print(f"Connection failed: {result.message}")
        print(f"Error details: {result.error}")
```

**Common Solutions**:
- Verify network connectivity
- Check firewall rules
- Validate credentials
- Ensure Proxmox VE is running
- Check SSL certificate validity

#### Authentication Issues

```python
# Validate credentials
errors = credentials.validate()
if errors:
    print(f"Credential validation errors: {errors}")
```

**Common Solutions**:
- Verify username format (user@realm)
- Check API token validity
- Ensure user has required permissions
- Verify realm configuration

#### Permission Issues

**Symptoms**: Operations fail with permission denied errors

**Solutions**:
1. Check user role permissions:
   ```bash
   pveum user permissions tailopsmcp@pve
   ```
2. Verify ACL configuration:
   ```bash
   pveum acl list /
   ```
3. Ensure required privileges are granted

#### Performance Issues

**Symptoms**: Slow operations, timeouts

**Solutions**:
1. Increase timeout values
2. Enable connection pooling
3. Implement rate limiting
4. Use caching for discovery
5. Optimize API calls

### Debug Mode

Enable debug logging for troubleshooting:

```python
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('src.services.proxmox_api')
logger.setLevel(logging.DEBUG)
```

### Log Analysis

Check security and audit logs:

```bash
# View security logs
tail -f /var/log/tailopsmcp/proxmox-security.log

# View audit logs
tail -f /var/log/tailopsmcp/audit.log

# Search for specific operations
grep "container_create" /var/log/tailopsmcp/proxmox-security.log
```

### Health Check Script

Create a health check script:

```python
#!/usr/bin/env python3
import asyncio
from src.utils.proxmox_monitoring import ProxmoxMonitoringService
from src.models.proxmox_models import ProxmoxAPICredentials

async def health_check():
    credentials = ProxmoxAPICredentials(
        host="pve.cluster.local",
        username="tailopsmcp@pve",
        api_token="your-token"
    )

    service = ProxmoxMonitoringService([credentials])
    status = await service.manual_health_check()

    print(f"Health Check Report: {status['summary']}")
    return status['summary']['overall_status'] == 'healthy'

if __name__ == "__main__":
    result = asyncio.run(health_check())
    exit(0 if result else 1)
```

### Support and Resources

- **Documentation**: See this guide and inline documentation
- **Logs**: Check application logs for detailed error information
- **Monitoring**: Use built-in monitoring for system health
- **Testing**: Use the comprehensive test suite for validation

---

## Quick Reference

### Essential Configuration

```yaml
proxmox:
  hosts:
    - host: "your-proxmox-host"
      username: "user@realm"
      api_token: "${API_TOKEN}"
  defaults:
    storage: "local-lvm"
    network_bridge: "vmbr0"
```

### Common Operations

```python
# List containers
containers = await api.list_containers()

# Create container
config = ContainerConfig(
    ostemplate="template-path",
    hostname="container-name"
)
result = await api.create_container(config)

# Start container
await api.start_container(vmid)

# Create snapshot
await api.create_snapshot(vmid, "snapshot-name")
```

### Key Metrics

- Host availability
- Container/VM status
- Resource utilization
- Operation success rates
- Security events

This comprehensive guide provides everything needed to successfully deploy and operate the Proxmox VE integration with TailOpsMCP.
