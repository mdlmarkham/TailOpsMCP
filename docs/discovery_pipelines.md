"""
Discovery Pipelines Documentation for Gateway Fleet Orchestrator.

This document provides comprehensive documentation for the discovery pipelines
implementation, including usage examples and configuration guides.
"""

# Discovery Pipelines Documentation

## Overview

The Discovery Pipelines system provides automated discovery and monitoring of
Proxmox hosts and their containers/VMs in a fleet environment. It integrates
seamlessly with the Fleet Inventory Model and supports both API-based and
CLI-based discovery methods.

## Key Components

### 1. Proxmox Discovery Service (`proxmox_discovery.py`)

**Purpose**: Discovers Proxmox hosts and their containers/VMs

**Features**:
- API-based discovery (preferred when configured)
- CLI fallback discovery using `pct` and `qm` commands
- Automatic detection of Proxmox environment
- Resource collection (CPU, memory, disk, IP addresses)

**Usage Example**:
```python
from src.services.proxmox_discovery import ProxmoxDiscovery

# With API configuration
api_config = {
    "host": "proxmox.example.com",
    "username": "root@pam",
    "password": "your_password"
}
discovery = ProxmoxDiscovery(api_config)

# Discover hosts
hosts = discovery.discover_proxmox_hosts()

# Discover nodes from a host
for host in hosts:
    nodes = discovery.discover_nodes(host)
```

### 2. Node Probing Service (`node_probing.py`)

**Purpose**: Tests connections and collects system information from discovered nodes

**Features**:
- Connection testing with priority (Tailscale SSH > Regular SSH)
- System information collection (hostname, OS, uptime, resources)
- Service discovery (systemd, Docker containers, Compose stacks)
- Health checking and status monitoring

**Usage Example**:
```python
from src.services.node_probing import NodeProbing

# With Tailscale configuration
tailscale_config = {
    "enabled": True,
    "ssh_user": "root"
}
probing = NodeProbing(tailscale_config)

# Probe a node
probe_result = probing.probe_node(node)
```

### 3. Discovery Pipeline (`discovery_pipeline.py`)

**Purpose**: Orchestrates the complete discovery cycle

**Features**:
- Automated discovery scheduling
- Concurrent node probing with configurable limits
- Inventory integration and persistence
- Stale entry cleanup
- Event logging and audit trails

**Usage Example**:
```python
from src.services.discovery_pipeline import DiscoveryPipeline

config = {
    "discovery_interval": 300,  # 5 minutes
    "health_check_interval": 60,  # 1 minute
    "max_concurrent_probes": 5
}
pipeline = DiscoveryPipeline(config)

# Run discovery cycle
inventory = await pipeline.run_discovery_cycle()
```

### 4. Discovery Manager (`discovery_manager.py`)

**Purpose**: Manages configuration and provides integration points

**Features**:
- Environment-based configuration loading
- Configuration management API
- Integration with TargetRegistry
- MCP server tool registration

**Usage Example**:
```python
from src.services.discovery_manager import DiscoveryManager

manager = DiscoveryManager()

# Run discovery if needed
if await manager.run_discovery_if_needed():
    print("Discovery completed")

# Force discovery
result = await manager.force_discovery()

# Get configuration
config = manager.get_configuration()
```

## Configuration

### Environment Variables

```bash
# Discovery intervals
SYSTEMMANAGER_DISCOVERY_INTERVAL=300          # 5 minutes
SYSTEMMANAGER_HEALTH_CHECK_INTERVAL=60        # 1 minute

# Concurrency limits
SYSTEMMANAGER_MAX_CONCURRENT_PROBES=5
SYSTEMMANAGER_MAX_FLEET_SIZE=50

# Auto-registration
SYSTEMMANAGER_AUTO_REGISTER=false

# Proxmox API (optional)
PROXMOX_HOST=proxmox.example.com
PROXMOX_USERNAME=root@pam
PROXMOX_PASSWORD=your_password

# Tailscale (optional)
TAILSCALE_ENABLED=true
TAILSCALE_TAILNET=your-tailnet
TAILSCALE_AUTH_KEY=your-auth-key
TAILSCALE_SSH_USER=root
```

### Configuration API

The discovery configuration can be managed programmatically:

```python
# Get current configuration
config = manager.get_configuration()

# Update configuration
new_config = {
    "discovery_interval": 600,
    "health_check_interval": 120,
    "auto_register": True
}
updated_config = manager.update_configuration(new_config)
```

## Integration with Existing Systems

### TargetRegistry Integration

Discovered nodes are automatically registered with the TargetRegistry:

```python
from src.services.discovery_manager import integrate_with_target_registry

# Integrate discovery with target registry
integrate_with_target_registry(discovery_manager, target_registry)
```

### MCP Server Integration

Discovery tools are automatically registered with the MCP server:

```python
# Tools available in MCP server:
- run_discovery() - Run complete discovery cycle
- get_discovery_status() - Get current status
- get_discovery_config() - Get configuration
- update_discovery_config() - Update configuration
```

## Error Handling and Retry Mechanisms

### Retry with Backoff

The system uses a robust retry mechanism with exponential backoff:

```python
from src.utils.retry import retry_with_backoff

@retry_with_backoff(max_retries=3, base_delay=1)
def discover_hosts():
    return discovery.discover_proxmox_hosts()
```

### Error Events

All discovery operations generate audit events:

- **Discovery events**: Host and node discovery
- **Health check events**: Node probing results
- **Error events**: Failed operations with details
- **Cleanup events**: Stale entry removal

## Testing

### Unit Tests

Comprehensive unit tests are available in `tests/test_discovery_pipelines.py`:

```bash
# Run discovery pipeline tests
pytest tests/test_discovery_pipelines.py -v
```

### Integration Testing

The system supports integration testing with mocked dependencies:

```python
# Mock Proxmox discovery
with patch('src.services.proxmox_discovery.ProxmoxDiscovery.discover_proxmox_hosts') as mock:
    mock.return_value = []
    # Test discovery pipeline
```

## Best Practices

### 1. Configuration Management
- Use environment variables for sensitive configuration
- Set appropriate discovery intervals based on fleet size
- Configure concurrency limits to avoid resource exhaustion

### 2. Monitoring and Alerting
- Monitor discovery events for failed operations
- Set up alerts for prolonged connection failures
- Track inventory growth and resource utilization

### 3. Security Considerations
- Use API tokens instead of passwords for Proxmox API
- Secure Tailscale authentication keys
- Implement proper access controls for discovered nodes

### 4. Performance Optimization
- Adjust discovery intervals based on environment stability
- Use appropriate concurrency limits for your infrastructure
- Monitor system resource usage during discovery cycles

## Troubleshooting

### Common Issues

1. **Proxmox API Connection Failures**
   - Verify API credentials and host accessibility
   - Check firewall rules and network connectivity
   - Ensure API token permissions are sufficient

2. **SSH Connection Failures**
   - Verify SSH keys and user permissions
   - Check network connectivity to target nodes
   - Ensure Tailscale is properly configured if used

3. **Discovery Performance Issues**
   - Adjust `max_concurrent_probes` setting
   - Increase discovery intervals for large fleets
   - Monitor system resources during discovery

### Debugging

Enable debug logging for detailed troubleshooting:

```bash
export LOG_LEVEL=DEBUG
python src/mcp_server.py
```

## Example Deployment Scenarios

### Scenario 1: Single Proxmox Host

```python
# Basic configuration for single host
config = {
    "discovery_interval": 300,
    "health_check_interval": 60,
    "max_concurrent_probes": 3
}

# Proxmox API not needed - CLI discovery will be used
pipeline = DiscoveryPipeline(config)
```

### Scenario 2: Multi-Host Proxmox Cluster

```python
# Configuration for cluster with API access
config = {
    "discovery_interval": 600,
    "health_check_interval": 120,
    "max_concurrent_probes": 10,
    "proxmox_api": {
        "host": "proxmox-cluster.example.com",
        "username": "root@pam",
        "token_name": "systemmanager",
        "token_value": "your-token"
    }
}
```

### Scenario 3: Tailscale-Enabled Fleet

```python
# Configuration with Tailscale for secure access
config = {
    "discovery_interval": 300,
    "health_check_interval": 60,
    "tailscale": {
        "enabled": True,
        "tailnet": "your-company.ts.net",
        "auth_key": "tskey-auth-...",
        "ssh_user": "admin"
    }
}
```

## Future Enhancements

### Planned Features

1. **Docker Swarm/Kubernetes Discovery**
   - Extend discovery to container orchestrators
   - Support for multi-node container deployments

2. **Custom Discovery Plugins**
   - Plugin architecture for custom discovery methods
   - Support for cloud providers and virtualization platforms

3. **Advanced Health Checking**
   - Custom health check scripts
   - Service-specific health metrics
   - Predictive failure detection

4. **Discovery Webhooks**
   - Real-time notifications for discovery events
   - Integration with external monitoring systems
   - Automated response triggers

## Conclusion

The Discovery Pipelines system provides a robust foundation for automated
fleet management in Proxmox environments. Its modular design, comprehensive
error handling, and seamless integration with existing systems make it suitable
for both small homelabs and large enterprise deployments.

For additional support or feature requests, refer to the project documentation
or contact the development team.
