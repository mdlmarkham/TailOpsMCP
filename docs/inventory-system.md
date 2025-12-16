# Enhanced Fleet Inventory System Documentation

## Overview

The Enhanced Fleet Inventory System is a comprehensive solution for managing and monitoring fleet infrastructure with rich metadata, change detection, and advanced querying capabilities. It consolidates existing auto-detection logic into a structured, persistent inventory model that serves as the authoritative source of truth for orchestration and enables advanced fleet management capabilities.

## System Architecture

### Core Components

1. **Enhanced Inventory Models** (`src/models/enhanced_fleet_inventory.py`)
   - Rich metadata capture for targets, services, and stacks
   - Node roles, resource usage, security posture
   - Network topology and health monitoring

2. **Snapshot Management** (`src/models/inventory_snapshot.py`)
   - Point-in-time inventory snapshots
   - Change detection and delta comparison
   - Automated snapshot creation and retention

3. **Enhanced Persistence Layer** (`src/utils/inventory_persistence.py`)
   - SQLite database with optimized schemas
   - JSON fallback for portability
   - Archive management and storage optimization

4. **Inventory Service Layer** (`src/services/inventory_service.py`)
   - Comprehensive inventory operations
   - Discovery pipeline integration
   - Health monitoring and metrics

5. **Enhanced MCP Tools** (`src/tools/enhanced_inventory_tools.py`)
   - Fleet-wide queries and filtering
   - Change detection and drift monitoring
   - Advanced reporting and analytics

## Key Features

### 1. Rich Metadata Capture

- **Node Roles**: Production, development, lab, staging, testing, monitoring, gateway
- **Resource Usage**: CPU, memory, disk, network utilization with status indicators
- **Security Posture**: TLS status, open ports, firewall status, vulnerability tracking
- **Network Topology**: IP ranges, subnets, interface configurations
- **Container Information**: Docker container details, images, ports, volumes
- **Stack Mappings**: Service-to-stack relationships and dependencies

### 2. Persistent Storage

- **SQLite Database**: Optimized schema with indexes for efficient querying
- **JSON Export/Import**: Human-readable format for backups and transfers
- **Archive Management**: Automatic compression and archival of old snapshots
- **Change Tracking**: Full audit trail of inventory modifications

### 3. Change Detection

- **Snapshot Comparison**: Identify differences between point-in-time captures
- **Drift Monitoring**: Track deviations from desired state
- **Health Impact Analysis**: Assess how changes affect fleet health
- **Automated Alerts**: Notify on critical changes or unexpected modifications

### 4. Advanced Querying

- **Role-based Filtering**: Query by node role (production, development, etc.)
- **Health-based Filtering**: Find unhealthy or stale targets
- **Text Search**: Search by name, description, tags, or attributes
- **Runtime-based Filtering**: Group services by runtime type
- **Custom Queries**: Complex queries with multiple criteria

### 5. Health Monitoring

- **Health Scores**: Calculate composite health scores (0.0-1.0)
- **Resource Monitoring**: Track CPU, memory, disk utilization
- **Security Assessment**: Monitor security posture changes
- **Connection Health**: Track last seen timestamps and connectivity
- **Automated Health Checks**: Scheduled health assessments

## Installation and Configuration

### Prerequisites

- Python 3.8+
- SQLite3
- Existing TailOpsMCP installation
- Access to Proxmox environment (optional)

### Configuration

The inventory system can be configured through the main TailOpsMCP configuration or by providing a config dictionary to the `InventoryService`:

```python
config = {
    "db_path": "/var/lib/systemmanager/enhanced_inventory.db",
    "use_sqlite": True,
    "auto_snapshot_enabled": True,
    "snapshot_retention_days": 30,
    "health_check_interval": 300,  # 5 minutes
    "discovery": {
        "discovery_interval": 300,
        "health_check_interval": 60,
        "max_concurrent_probes": 5
    }
}

inventory_service = InventoryService(config)
```

### Database Setup

The system automatically creates the database schema on first use. For production deployments, ensure proper permissions for the database file and directory.

## Usage Guide

### Basic Operations

#### 1. Running Fleet Discovery

```python
from src.services.inventory_service import InventoryService

# Initialize service
inventory_service = InventoryService()

# Run full discovery
inventory = await inventory_service.run_full_discovery()

print(f"Discovered {inventory.total_targets} targets")
print(f"Found {inventory.total_services} services")
```

#### 2. Querying Fleet Information

```python
# Get production targets
production_targets = inventory_service.get_targets_by_role(NodeRole.PRODUCTION)

# Find unhealthy targets
unhealthy_targets = inventory_service.get_unhealthy_targets(threshold=0.7)

# Search for specific targets
search_results = inventory_service.search_targets("web-server")

# Get services by stack
web_services = inventory_service.get_services_by_stack("web-stack")
```

#### 3. Health Monitoring

```python
# Run comprehensive health check
health_results = await inventory_service.run_health_check()

print(f"Health issues found: {len(health_results['issues'])}")

# Check specific target health
target = production_targets[0]
print(f"Target {target.name} health score: {target.health_score}")
```

### Snapshot Management

#### Creating Snapshots

```python
# Manual snapshot
snapshot = await inventory_service.create_snapshot(
    name="pre-deployment-backup",
    description="Backup before production deployment",
    snapshot_type=SnapshotType.PRE_DEPLOYMENT,
    tags=["deployment", "backup"]
)

# Automatic snapshots are created during discovery if enabled
```

#### Comparing Snapshots

```python
# Get two snapshots for comparison
snapshots = inventory_service.list_snapshots(limit=2)
snapshot_a = snapshots[1]  # Older snapshot
snapshot_b = snapshots[0]  # Newer snapshot

# Compare snapshots
diff = inventory_service.compare_snapshots(snapshot_a.id, snapshot_b.id)

# Analyze changes
if diff.entities_created > 0:
    print(f"Created {diff.entities_created} new entities")
if diff.entities_modified > 0:
    print(f"Modified {diff.entities_modified} existing entities")
if diff.entities_deleted > 0:
    print(f"Deleted {diff.entities_deleted} entities")
```

### MCP Tools Usage

The enhanced inventory system provides comprehensive MCP tools:

#### 1. Fleet Discovery and Overview

```python
# Run fleet discovery
result = await run_fleet_discovery()

# Get fleet overview
overview = await get_fleet_overview()
```

#### 2. Target Management

```python
# Get production targets
production = await get_production_targets()

# Find stale targets
stale = await find_stale_targets(hours=48)

# Get unhealthy targets
unhealthy = await get_unhealthy_targets(threshold=0.8)
```

#### 3. Service Analysis

```python
# Get services by runtime
docker_services = await get_services_by_runtime("docker")

# Search fleet inventory
search_results = await search_fleet("nginx", entity_type="service")
```

#### 4. Snapshot Operations

```python
# Create snapshot
snapshot = await create_inventory_snapshot(
    name="daily-backup",
    description="Daily inventory backup",
    snapshot_type="scheduled"
)

# Compare snapshots
changes = await compare_snapshots(
    snapshot_a_id="snapshot-123",
    snapshot_b_id="snapshot-124"
)

# List snapshots
snapshots = await list_snapshots(snapshot_type="manual", limit=10)
```

#### 5. Reporting and Analytics

```python
# Generate comprehensive reports
summary_report = await generate_fleet_report("summary")
health_report = await generate_fleet_report("health")
security_report = await generate_fleet_report("security")
resource_report = await generate_fleet_report("resources")

# Run health check
health_check = await run_comprehensive_health_check()

# Get statistics
stats = await get_inventory_statistics()
```

## Integration Guide

### With Existing Discovery Pipeline

The enhanced inventory system integrates seamlessly with the existing discovery pipeline:

```python
from src.services.discovery_pipeline import DiscoveryPipeline

# Initialize discovery pipeline
discovery = DiscoveryPipeline(config)

# Enhanced discovery with inventory service
inventory_service = InventoryService()

# Run discovery and update enhanced inventory
inventory = await inventory_service.run_full_discovery()
```

### With Security Systems

The inventory system integrates with security hardening:

```python
from src.utils.secure_logging import SecureLogger
from src.auth.middleware import secure_tool

# Secure logging is automatically enabled
logger = SecureLogger("inventory_service")

# All MCP tools use secure decorators
@secure_tool("fleet_discovery")
async def run_fleet_discovery():
    # Secure discovery operation
    pass
```

### With Health Monitoring

```python
from src.utils.monitoring_integration import MonitoringIntegration

# Monitor inventory health
monitor = MonitoringIntegration()

# Track inventory metrics
await monitor.track_metric("fleet_health_score", inventory.average_health_score)
await monitor.track_metric("unhealthy_targets", inventory.unhealthy_targets)
```

## API Reference

### InventoryService Class

#### Methods

- `run_full_discovery()` - Run complete discovery cycle
- `get_targets_by_role(role)` - Get targets by role
- `get_unhealthy_targets(threshold)` - Get unhealthy targets
- `search_targets(query)` - Search targets
- `create_snapshot(name, ...)` - Create inventory snapshot
- `compare_snapshots(a_id, b_id)` - Compare snapshots
- `run_health_check()` - Run health assessment

### Enhanced Inventory Models

#### EnhancedTarget

```python
target = EnhancedTarget(
    name="web-server-01",
    role=NodeRole.PRODUCTION,
    cpu_cores=4,
    memory_mb=8192,
    health_score=0.85
)

# Access enhanced properties
print(target.resource_usage.cpu_percent)
print(target.security_posture.security_status.value)
print(target.container_info.image_name)
```

#### EnhancedService

```python
service = EnhancedService(
    name="nginx",
    target_id="target-123",
    service_type="docker",
    health_check_enabled=True
)

# Access enhanced properties
print(service.health_status)
print(service.stack_name)
print(service.depends_on)
```

#### EnhancedStack

```python
stack = EnhancedStack(
    name="web-stack",
    compose_file_path="/opt/stacks/web/docker-compose.yml"
)

# Access stack properties
print(stack.health_score)
print(stack.services)
print(stack.total_cpu_cores)
```

## Examples

### Example 1: Basic Fleet Monitoring

```python
import asyncio
from src.services.inventory_service import InventoryService

async def monitor_fleet():
    service = InventoryService()

    # Run initial discovery
    inventory = await service.run_full_discovery()

    # Check for issues
    unhealthy = service.get_unhealthy_targets()
    stale = service.get_stale_targets()

    if unhealthy:
        print(f"Found {len(unhealthy)} unhealthy targets")
    if stale:
        print(f"Found {len(stale)} stale targets")

    # Generate health report
    health = await service.run_health_check()
    print(f"Fleet health score: {health['average_health_score']}")

# Run monitoring
asyncio.run(monitor_fleet())
```

### Example 2: Change Detection Workflow

```python
import asyncio
from src.services.inventory_service import InventoryService
from src.models.inventory_snapshot import SnapshotType

async def detect_changes():
    service = InventoryService()

    # Create pre-deployment snapshot
    pre_snapshot = await service.create_snapshot(
        name="pre-deployment",
        snapshot_type=SnapshotType.PRE_DEPLOYMENT
    )

    # Perform deployment operations...
    print("Performing deployment...")

    # Create post-deployment snapshot
    post_snapshot = await service.create_snapshot(
        name="post-deployment",
        snapshot_type=SnapshotType.POST_DEPLOYMENT
    )

    # Compare snapshots
    diff = service.compare_snapshots(pre_snapshot.id, post_snapshot.id)

    # Analyze changes
    summary = diff.get_change_summary()
    print(f"Changes detected: {summary['total_changes']}")
    print(f"Entities created: {summary['entities_created']}")
    print(f"Entities modified: {summary['entities_modified']}")

    # Check health impact
    if diff.health_impact.get('critical_changes'):
        print("WARNING: Critical changes detected!")

asyncio.run(detect_changes())
```

### Example 3: Automated Health Monitoring

```python
import asyncio
from src.services.inventory_service import InventoryService
from datetime import datetime, timedelta

async def automated_monitoring():
    service = InventoryService()

    while True:
        # Run health check
        health = await service.run_health_check()

        # Check for critical issues
        if health['unhealthy_targets'] > 0:
            print(f"ALERT: {health['unhealthy_targets']} unhealthy targets")

            # Get detailed unhealthy targets
            unhealthy = service.get_unhealthy_targets()
            for target in unhealthy[:5]:  # Top 5
                print(f"  - {target.name}: {target.health_score}")

        # Check for stale targets
        stale = service.get_stale_targets(hours=24)
        if stale:
            print(f"WARNING: {len(stale)} targets haven't been seen in 24 hours")

        # Create hourly snapshot
_snapshot(
            name=f"hourly        await service.create-{datetime.now().strftime('%Y%m%d-%H')}",
            description="Automated hourly snapshot"
        )

        # Wait 1 hour
        await asyncio.sleep(3600)

# Start monitoring (for production, use proper scheduling)
# asyncio.run(automated_monitoring())
```

## Best Practices

### 1. Regular Discovery
- Run fleet discovery at regular intervals (5-15 minutes)
- Schedule during low-traffic periods
- Monitor discovery success rates

### 2. Snapshot Management
- Create snapshots before major deployments
- Set appropriate retention policies
- Archive old snapshots to save space

### 3. Health Monitoring
- Set appropriate health score thresholds
- Monitor both individual and fleet-wide health
- Alert on critical health degradations

### 4. Query Optimization
- Use role-based filtering for better performance
- Limit query results for large fleets
- Cache frequently accessed data

### 5. Security
- Use secure logging for all operations
- Implement proper access controls
- Monitor for unauthorized changes

## Troubleshooting

### Common Issues

1. **Database Lock Errors**
   - Check for concurrent access
   - Ensure proper transaction handling
   - Verify file permissions

2. **Discovery Failures**
   - Check network connectivity
   - Verify authentication credentials
   - Review discovery logs

3. **Performance Issues**
   - Optimize database queries
   - Implement proper indexing
   - Consider partitioning large datasets

4. **Memory Usage**
   - Monitor snapshot sizes
   - Implement data archival
   - Limit concurrent operations

### Debug Commands

```python
# Check service status
status = inventory_service.get_service_status()
print(status)

# Get storage statistics
stats = inventory_service.get_storage_stats()
print(f"Database size: {stats['database_size_bytes']} bytes")

# List recent snapshots
snapshots = inventory_service.list_snapshots(limit=10)
for snapshot in snapshots:
    print(f"{snapshot.name}: {snapshot.created_at}")
```

## Future Enhancements

Planned features for future releases:

1. **Machine Learning Integration**
   - Predictive health scoring
   - Anomaly detection
   - Capacity planning

2. **Advanced Analytics**
   - Trend analysis
   - Performance benchmarking
   - Cost optimization

3. **Integration Expansions**
   - Cloud provider APIs
   - Monitoring systems
   - ITSM platforms

4. **Enhanced Security**
   - Compliance reporting
   - Vulnerability scanning
   - Access analytics

## Support and Contribution

For issues, feature requests, or contributions:

1. Check existing documentation and examples
2. Review the troubleshooting section
3. Submit issues with detailed logs
4. Follow the project's contribution guidelines

This enhanced fleet inventory system provides a robust foundation for comprehensive fleet management, enabling advanced monitoring, change detection, and orchestration capabilities.
