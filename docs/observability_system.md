"""
Documentation for the standardized observability system (Control Plane Gateway).
"""

OBSERVABILITY_SYSTEM_DOCS = """
# Standardized Observability System (Control Plane Gateway)

## Overview

The TailOpsMCP control plane gateway observability system provides comprehensive logging, auditing, metrics collection, and health monitoring across all managed targets. It standardizes results, logging, and auditing to ensure consistent observability throughout the entire infrastructure.

## Key Features (Gateway Architecture)

### 1. Enhanced ExecutionResult Model (Multi-Target)
- **Cross-System Status Tracking**: Multiple execution status types across all targets (success, failure, timeout, connection errors, etc.)
- **Structured Error Handling**: Detailed error codes, messages, and context with target-specific information
- **Correlation IDs**: Unique identifiers for traceability across distributed operations and multiple targets
- **Metrics Collection**: Built-in metrics for performance monitoring across the infrastructure
- **Audit Trail**: Complete audit trail for compliance and debugging with target-specific context

### 2. Standardized Audit Logging (Gateway-Centric)
- **Centralized Logging**: All audit logs stored on the gateway with target-specific metadata
- **Multiple Sink Support**: File, console, database, syslog, HTTP endpoints with gateway aggregation
- **Log Rotation**: Automatic log rotation with configurable retention policies for gateway logs
- **Structured Format**: JSONL format for easy parsing and analysis with target identifiers
- **Security Features**: Sensitive data redaction, access controls with gateway-level enforcement

### 3. Consistent Logging Configuration (Gateway Unified)
- **Structured Logging**: Consistent log format across all gateway operations and target interactions
- **Correlation ID Integration**: Trace operations across service boundaries and multiple targets
- **Log Level Management**: Configurable log levels for different environments with gateway-wide settings
- **Multiple Output Formats**: Human-readable and machine-parsable formats with target context

### 4. Metrics Collection (Infrastructure-Wide)
- **Operation Timing**: Automatic timing of operations across all targets
- **Counter Metrics**: Incremental counters for success/failure rates per target and overall
- **Gauge Metrics**: Current value measurements (memory, CPU, etc.) across the infrastructure
- **Batch Metrics**: Aggregated metrics for batch operations across multiple targets

### 5. Health Checking (Gateway and Targets)
- **Gateway Health**: Health checks for the control plane gateway itself
- **Target Health**: Health checks for all managed systems in the target registry
- **Status Reporting**: Comprehensive status reports for the entire infrastructure
- **Alert Integration**: Integration with monitoring systems for gateway and target health
- **Automatic Recovery**: Health-based recovery mechanisms with target-specific policies

### 6. Monitoring System Integration (Gateway Aggregation)
- **Prometheus**: Metrics export to Prometheus pushgateway with target-specific labels
- **Elasticsearch**: Log aggregation and search with gateway and target metadata
- **Datadog**: Comprehensive monitoring and alerting for the entire infrastructure
- **Custom Integrations**: Extensible integration framework with gateway context

## Usage Examples

### Basic Logging
```python
from src.utils import get_logger, generate_correlation_id

logger = get_logger("my_component")
correlation_id = generate_correlation_id()
logger.set_correlation_id(correlation_id)

logger.info("Operation started", operation="data_processing", target="database")
logger.error("Operation failed", error_code="DB_CONN_001", retry_count=3)
```

### Audit Logging
```python
from src.utils import AuditLogger
from src.models.execution import ExecutionStatus

audit_logger = AuditLogger()
audit_logger.log_operation(
    operation="file_upload",
    correlation_id=generate_correlation_id(),
    target="storage_server",
    capability="file_operations",
    status=ExecutionStatus.SUCCESS,
    success=True,
    duration=2.5
)
```

### Metrics Collection
```python
from src.utils import metrics_collector

# Time an operation
metrics_collector.start_timer("data_processing")
# ... perform operation ...
duration = metrics_collector.stop_timer("data_processing")

# Record metrics
metrics_collector.increment_counter("processed_records", 100)
metrics_collector.record_gauge("memory_usage_mb", 256.5)
```

### Health Checking
```python
from src.utils import health_checker

# Run all health checks
health_results = health_checker.run_all_checks()

# Get status report
status_report = health_checker.get_status_report()
print(f"System status: {status_report['overall_status']}")
```

## Configuration

### Environment Variables

```bash
# Logging Configuration
SYSTEMMANAGER_LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR, CRITICAL
SYSTEMMANAGER_LOG_FORMAT=structured  # structured or human
SYSTEMMANAGER_LOG_CONSOLE=true  # Enable console output

# Audit Log Configuration
SYSTEMMANAGER_AUDIT_LOG=./logs/audit.log
SYSTEMMANAGER_LOG_RETENTION_DAYS=90
SYSTEMMANAGER_LOG_MAX_SIZE_MB=100

# Metrics Configuration
SYSTEMMANAGER_METRICS_ENABLED=true
SYSTEMMANAGER_METRICS_INTERVAL=60
SYSTEMMANAGER_LATENCY_THRESHOLD=5.0

# Health Check Configuration
SYSTEMMANAGER_HEALTH_CHECKS_ENABLED=true
SYSTEMMANAGER_HEALTH_CHECK_INTERVAL=300

# Monitoring Integration
PROMETHEUS_ENABLED=false
PROMETHEUS_PUSHGATEWAY_URL=http://localhost:9091
ELASTICSEARCH_ENABLED=false
ELASTICSEARCH_HOST=localhost
DATADOG_ENABLED=false
DATADOG_API_KEY=your_api_key
```

### Configuration Files

For advanced configuration, create a YAML configuration file:

```yaml
sinks:
  - type: file
    enabled: true
    path: ./logs/audit.log
    max_size: 10485760  # 10MB
    backup_count: 5
    retention_days: 30
  - type: console
    enabled: true
    format: human

retention:
  enabled: true
  max_age_days: 90
  max_size_mb: 100
  compression: false

format:
  timestamp_format: iso
  include_metadata: true
  redact_sensitive: true
```

## Integration with Existing Components

### Legacy Audit Logger Compatibility

The system provides backward compatibility with the existing `AuditLogger`:

```python
from src.utils import LegacyAuditLoggerAdapter

# Use the adapter for legacy code
legacy_adapter = LegacyAuditLoggerAdapter()
legacy_adapter.log(
    tool="file_operation",
    args={"path": "/tmp/test.txt"},
    result={"success": True, "output": "File created"}
)
```

### Tool Integration

Wrap existing tool functions with observability features:

```python
from src.utils import ToolIntegration

# Original tool function
def my_tool(param1, param2, target="local"):
    # Tool implementation
    return {"success": True, "result": "Operation completed"}

# Wrapped version with observability
wrapped_tool = ToolIntegration.wrap_tool_execution(
    my_tool,
    tool_name="my_tool",
    capability="data_processing"
)

# Use the wrapped tool
result = wrapped_tool("param1", "param2", target="remote")
```

## Monitoring and Dashboard Integration

### Prometheus Metrics

Enable Prometheus integration to export metrics:

```bash
export PROMETHEUS_ENABLED=true
export PROMETHEUS_PUSHGATEWAY_URL=http://localhost:9091
```

### Elasticsearch Logs

Send logs to Elasticsearch for centralized logging:

```bash
export ELASTICSEARCH_ENABLED=true
export ELASTICSEARCH_HOST=localhost
export ELASTICSEARCH_PORT=9200
```

### Dashboard Export

Export data in dashboard-friendly formats:

```python
from src.utils import DashboardExporter

# Export metrics for dashboards
dashboard_metrics = DashboardExporter.export_metrics_for_dashboard(metrics)

# Export health data
dashboard_health = DashboardExporter.export_health_for_dashboard(health_data)
```

## Best Practices

1. **Always Use Correlation IDs**: Generate and propagate correlation IDs for traceability
2. **Structured Logging**: Use structured logging instead of string concatenation
3. **Meaningful Metrics**: Collect metrics that provide actionable insights
4. **Health Check Coverage**: Implement health checks for critical components
5. **Security Considerations**: Redact sensitive data in logs and audit trails
6. **Performance Monitoring**: Monitor key performance indicators
7. **Error Handling**: Use structured errors for better debugging

## Troubleshooting

### Common Issues

1. **Logs Not Appearing**: Check log level configuration and sink enabled status
2. **Metrics Not Collected**: Verify metrics collection is enabled
3. **Health Checks Failing**: Review health check implementation and dependencies
4. **Monitoring Integration Issues**: Check connection settings and API keys

### Debugging Tips

- Use correlation IDs to trace operations across components
- Enable debug logging for detailed troubleshooting
- Check health check results for component status
- Review audit logs for operation history

## Migration Guide

### From Legacy System

1. **Update Imports**: Replace `from src.utils.audit import AuditLogger` with `from src.utils import AuditLogger`
2. **Use Enhanced Models**: Migrate from simple result dictionaries to `ExecutionResult` objects
3. **Add Correlation IDs**: Generate and use correlation IDs for all operations
4. **Enable Structured Logging**: Configure structured logging format
5. **Implement Health Checks**: Add health checks for critical components

### Gradual Migration

The system supports gradual migration through compatibility adapters. Start with high-priority components and gradually migrate others.

## API Reference

See the individual module documentation for detailed API references:

- `src/models/execution.py` - Enhanced execution models
- `src/utils/audit_enhanced.py` - Audit logging system
- `src/utils/logging_config.py` - Logging configuration
- `src/utils/observability_config.py` - Configuration management
- `src/utils/monitoring_integration.py` - Monitoring integrations
- `src/utils/observability_integration.py` - Integration utilities
"""


def get_observability_docs() -> str:
    """Get the observability system documentation."""
    return OBSERVABILITY_SYSTEM_DOCS


if __name__ == "__main__":
    print(get_observability_docs())
