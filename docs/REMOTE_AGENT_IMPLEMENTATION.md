# Remote Agent-Like Functions Implementation Guide

## Overview

This document describes the implementation of remote agent-like connectors for TailOpsMCP that provide comprehensive in-guest management capabilities via SSH/Tailscale without requiring MCP agent installation on target systems.

## Architecture

### Core Components

#### 1. Base Framework (`src/connectors/remote_agent_connector.py`)
- **RemoteAgentConnector**: Base class for all agent-like functionality
- Common data models: `LogEntry`, `ServiceStatus`, `DockerContainer`, `FileInfo`, etc.
- Security validation and audit logging
- SSH/Tailscale connection handling

#### 2. Connection Management (`src/services/connection_manager.py`)
- **RemoteConnectionManager**: Manages SSH/Tailscale connections
- Connection pooling with health monitoring
- Automatic reconnection and cleanup
- Performance optimization with connection reuse

#### 3. Resilient Operations (`src/services/remote_operation_executor.py`)
- **ResilientRemoteOperation**: Retry mechanisms and timeout handling
- Circuit breaker pattern for failure prevention
- Comprehensive metrics and monitoring
- Multiple retry strategies (exponential backoff, linear, fixed delay)

#### 4. Specialized Connectors

##### Journald Connector (`src/connectors/journald_connector.py`)
```python
# Get logs from remote target
connector = JournaldConnector(target, connection)
logs = await connector.get_logs(service="nginx", lines=100)

# Follow logs in real-time
async for log in connector.follow_logs(service="nginx"):
    print(f"{log.timestamp}: {log.message}")

# Search logs with advanced filtering
results = await connector.search_logs("error", service="nginx", time_range="1 hour")
```

##### Service Connector (`src/connectors/service_connector.py`)
```python
# Manage systemd services
connector = ServiceConnector(target, connection)
status = await connector.get_service_status("nginx")
result = await connector.restart_service("nginx")

# Check service health
health = await connector.check_service_health("nginx")
print(f"Service is healthy: {health['healthy']}")
```

##### Docker Connector (`src/connectors/docker_connector.py`)
```python
# Manage Docker containers via SSH port forwarding
connector = DockerConnector(target, connection)
containers = await connector.list_containers()
logs = await connector.get_container_logs("container_id", lines=100)
stats = await connector.get_container_stats("container_id")

# Restart container
result = await connector.restart_container("container_id")
```

##### File Connector (`src/connectors/file_connector.py`)
```python
# Secure file operations
connector = FileConnector(target, connection)

# Read file with security validation
content = await connector.read_file("/etc/nginx/nginx.conf")

# Write file with backup creation
result = await connector.write_file("/etc/nginx/nginx.conf", new_config, create_backup=True)

# List directory contents
files = await connector.list_directory("/var/log", include_hidden=False)
```

#### 5. MCP Tools (`src/tools/remote_agent_tools.py`)
High-level tools for easy integration:

```python
# Get journald logs
result = await get_journald_logs(
    target="web-server.example.com",
    service="nginx",
    lines=100,
    since="1 hour ago"
)

# Restart service remotely
result = await restart_remote_service(
    target="web-server.example.com",
    service="nginx",
    timeout=60
)

# Analyze logs across fleet
result = await analyze_service_logs_across_fleet(
    targets=["server1.com", "server2.com", "server3.com"],
    service="nginx",
    time_range="1 hour"
)
```

#### 6. Security Controls (`src/utils/remote_security.py`)
- **RemoteOperationSecurityManager**: Access control and validation
- **RemoteOperationAuditor**: Comprehensive audit logging
- Rate limiting and command injection detection
- Path validation and security context management

#### 7. Policy Integration (`src/services/remote_agent_capabilities.py`)
- Integration with existing policy system
- Capability registry for policy-driven execution
- Role-based access control

## Configuration

### Remote Agents Configuration (`config/remote-agents-config.yaml.example`)

```yaml
remote_agents:
  enabled: true
  
  connection_pool:
    max_connections: 50
    connection_timeout: 30
    idle_timeout: 300
  
  ssh_config:
    port: 22
    username: "root"
    key_path: "~/.ssh/id_rsa"
    verify_host_key: true
  
  tailscale_config:
    enable_port_forwarding: true
    ssh_over_tailscale: true
  
  retry_policy:
    max_retries: 3
    backoff_multiplier: 2
    max_backoff: 30
  
  security:
    rate_limits:
      command_execution:
        max_per_hour: 100
        max_per_minute: 10
    
    access_scopes:
      observe_only:
        operations: ["get_journald_logs", "get_service_status"]
      limited_control:
        operations: ["observe_operations", "restart_remote_service"]
      full_control:
        operations: ["observe_operations", "control_operations"]
      admin:
        operations: ["observe_operations", "control_operations", "admin_operations"]
```

### Target Configuration

```yaml
targets:
  "web-server-01.example.com":
    enabled: true
    connection_type: "ssh"
    host: "web-server-01.example.com"
    port: 22
    username: "deploy"
    key_path: "~/.ssh/deploy_key"
    allowed_operations:
      - "get_journald_logs"
      - "get_service_status"
      - "restart_remote_service"
      - "read_remote_file"
```

## Security Features

### Access Control
- **Scopes**: `observe_only`, `limited_control`, `full_control`, `admin`
- **Rate Limiting**: Per-operation rate limits with time windows
- **Command Validation**: Injection pattern detection
- **Path Security**: Whitelist-based file access control

### Audit Logging
- Comprehensive operation tracking
- Security violation detection
- Performance metrics
- Compliance reporting

### Security Levels
- **Low**: Read-only operations
- **Medium**: Safe control operations
- **High**: Administrative operations
- **Critical**: System-altering operations

## Usage Examples

### Basic Operations

#### Log Analysis Workflow
```python
async def analyze_service_logs_across_fleet():
    # Get production targets
    targets = await inventory_service.get_targets_by_role("production")
    
    # Collect logs from each target
    all_logs = []
    for target in targets:
        try:
            connector = JournaldConnector(target, connection_manager)
            logs = await connector.get_logs("nginx", lines=1000)
            all_logs.extend(logs)
        except Exception as e:
            logger.warning(f"Failed to get logs from {target.name}: {e}")
    
    # Analyze and correlate logs
    analysis = await log_analyzer.analyze_logs(all_logs)
    return analysis
```

#### Service Health Monitoring
```python
async def check_fleet_service_health():
    targets = await inventory_service.get_all_targets()
    health_report = []
    
    for target in targets:
        try:
            connector = ServiceConnector(target, connection_manager)
            status = await connector.get_service_status("nginx")
            
            health_report.append({
                "target": target.name,
                "service": "nginx",
                "status": status.state,
                "active_since": status.active_since,
                "memory_usage": status.memory_usage
            })
        except Exception as e:
            health_report.append({
                "target": target.name,
                "error": str(e)
            })
    
    return health_report
```

#### Container Management
```python
async def restart_failing_containers():
    targets = await inventory_service.get_targets_by_role("production")
    
    for target in targets:
        try:
            connector = DockerConnector(target, connection_manager)
            containers = await connector.list_containers()
            
            for container in containers:
                if container.status != "running":
                    logger.info(f"Restarting container {container.name} on {target.name}")
                    await connector.restart_container(container.container_id)
        except Exception as e:
            logger.error(f"Failed to restart containers on {target.name}: {e}")
```

#### Configuration Management
```python
async def update_nginx_config(targets: List[Target], new_config: str):
    for target in targets:
        try:
            connector = FileConnector(target, connection_manager)
            
            # Read current config
            current_config = await connector.read_file("/etc/nginx/nginx.conf")
            
            # Create backup
            result = await connector.write_file(
                "/etc/nginx/nginx.conf.backup", 
                current_config
            )
            
            # Write new config
            result = await connector.write_file(
                "/etc/nginx/nginx.conf",
                new_config,
                create_backup=True
            )
            
            if result.success:
                # Restart nginx
                service_connector = ServiceConnector(target, connection_manager)
                await service_connector.restart_service("nginx")
                
        except Exception as e:
            logger.error(f"Failed to update config on {target.name}: {e}")
```

### Fleet-Wide Operations

#### Parallel Log Collection
```python
async def collect_logs_parallel(targets: List[Target], service: str):
    import asyncio
    
    async def get_logs_for_target(target):
        try:
            connector = JournaldConnector(target, connection_manager)
            return await connector.get_logs(service, lines=500)
        except Exception as e:
            logger.error(f"Failed to get logs from {target.name}: {e}")
            return []
    
    # Execute log collection in parallel
    tasks = [get_logs_for_target(target) for target in targets]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    all_logs = []
    for logs in results:
        if isinstance(logs, list):
            all_logs.extend(logs)
    
    return all_logs
```

#### Health Check Automation
```python
async def automated_health_checks():
    targets = await inventory_service.get_targets_by_role("production")
    
    # Define services to check
    critical_services = ["nginx", "redis", "postgres"]
    
    for service in critical_services:
        health_report = await check_fleet_service_health()
        
        # Check for unhealthy services
        unhealthy = [h for h in health_report if not h.get("healthy", False)]
        
        if unhealthy:
            # Send alerts
            await alert_service.send_alert(
                f"Service {service} unhealthy on {len(unhealthy)} targets",
                targets=[h["target"] for h in unhealthy]
            )
            
            # Attempt automatic recovery
            for health in unhealthy:
                if "error" not in health:
                    target = next(t for t in targets if t.name == health["target"])
                    connector = ServiceConnector(target, connection_manager)
                    await connector.restart_service(service)
```

## Integration with Existing Systems

### Fleet Inventory Integration
```python
# Automatic target discovery
await inventory_service.discover_targets_via_ssh()
await inventory_service.discover_targets_via_tailscale()

# Connection health monitoring
health_status = await connection_manager.get_all_health_status()
await inventory_service.update_target_health(health_status)
```

### Policy System Integration
```python
# Register remote agent capabilities
from src.services.remote_agent_capabilities import register_remote_agent_capabilities
registry = register_remote_agent_capabilities()

# Execute policy-driven operation
operation = CapabilityOperation(
    operation_type="get_journald_logs",
    target=target,
    parameters={"service": "nginx"},
    security_context=security_context
)

result = await capability_executor.execute_operation(operation)
```

### Observability Integration
```python
# Collect metrics
metrics = {
    "connection_health": await connection_manager.get_all_health_status(),
    "operation_metrics": executor.get_operation_metrics(),
    "security_violations": auditor.get_security_violations()
}

# Send to monitoring system
await observability_client.send_metrics("remote_agents", metrics)
```

## Testing

### Unit Tests
```bash
# Run specific connector tests
pytest tests/test_remote_agent_functionality.py::TestJournaldConnector -v

# Run security tests
pytest tests/test_remote_agent_functionality.py::TestSecurityControls -v

# Run all remote agent tests
pytest tests/test_remote_agent_functionality.py -v
```

### Integration Tests
```bash
# Run integration tests
pytest tests/test_remote_agent_functionality.py::TestIntegration -v

# Run with coverage
pytest tests/test_remote_agent_functionality.py --cov=src/connectors --cov=src/services/remote_operation_executor --cov-report=html
```

## Performance Considerations

### Connection Pooling
- **Max Connections**: 50 total, 10 per target
- **Idle Timeout**: 300 seconds
- **Health Check**: Every 60 seconds

### Caching
- **Read Operations**: Cache for 5 minutes
- **File Statistics**: Cache for 1 minute
- **Service Status**: Cache for 30 seconds

### Parallel Execution
- **Fleet Operations**: Max 10 concurrent targets
- **Batch Size**: 5 targets per batch
- **Timeout**: 60 seconds per target

## Troubleshooting

### Common Issues

#### Connection Failures
```python
# Check connection health
health = await connection_manager.health_check(target)
if not health.healthy:
    print(f"Connection issues: {health.issues}")

# Retry with exponential backoff
result = await resilient_executor.execute_with_retry(
    lambda: connector.get_service_status("nginx"),
    max_retries=3
)
```

#### Permission Errors
```python
# Check security context
security_context = create_security_context(
    user_id="user123",
    session_id="session123",
    scopes=[AccessScope.LIMITED_CONTROL]
)

# Validate operation
is_valid, error = security_manager.validate_operation_security(
    "restart_remote_service",
    {"service": "nginx"},
    security_context
)
```

#### Performance Issues
```python
# Check operation metrics
metrics = executor.get_operation_metrics("get_journald_logs")
print(f"Average duration: {executor.get_average_duration('get_journald_logs')}s")
print(f"Success rate: {executor.get_success_rate('get_journald_logs')}")

# Check connection pool status
pool_health = await connection_manager.health_check(target)
print(f"Healthy connections: {pool_health.healthy}")
```

## Best Practices

### Security
1. **Use SSH Keys**: Prefer key-based authentication
2. **Limit Scopes**: Start with `observe_only` and expand as needed
3. **Monitor Audit Logs**: Regular review of security events
4. **Rate Limiting**: Configure appropriate limits for your environment

### Performance
1. **Connection Pooling**: Reuse connections when possible
2. **Batch Operations**: Use fleet operations for multiple targets
3. **Caching**: Enable caching for read-heavy operations
4. **Timeout Configuration**: Set appropriate timeouts for your network

### Operations
1. **Health Monitoring**: Regular connection health checks
2. **Error Handling**: Implement proper retry logic
3. **Logging**: Comprehensive audit logging
4. **Testing**: Regular testing of remote operations

## Future Enhancements

### Planned Features
1. **WebSocket Support**: Real-time log streaming
2. **GraphQL API**: Query interface for complex operations
3. **Machine Learning**: Anomaly detection in log patterns
4. **Advanced Scheduling**: Cron-like scheduling for operations
5. **Multi-Protocol Support**: Additional protocols beyond SSH/Tailscale

### Extensibility
- Plugin architecture for custom connectors
- Custom security policies
- Integration with external monitoring systems
- Advanced analytics and reporting

This implementation provides a robust, secure, and scalable foundation for remote agent-like operations without requiring agent installation on target systems.