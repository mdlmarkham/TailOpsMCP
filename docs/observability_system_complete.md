# TailOpsMCP Observability System

## Overview

The TailOpsMCP Observability System is a comprehensive platform that consolidates all system signals into a normalized event model, enabling efficient LLM summaries, trend detection, early warnings, and change tracking across your entire infrastructure.

## Architecture

The observability system consists of several interconnected components:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Event Models  │    │ Event Collection│    │ Event Storage   │
│                 │    │                 │    │                 │
│ • Normalized    │────│ • Fleet Health  │────│ • SQLite DB     │
│   Event Schema  │    │ • Security      │    │ • Full-text     │
│ • Event Types   │    │ • Operations    │    │   Search        │
│ • Filtering     │    │ • Lifecycle     │    │ • Indexing      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Event Analysis  │    │ Event Processing│    │ Event Alerting  │
│                 │    │                 │    │                 │
│ • Trend Detect. │────│ • Real-time     │────│ • Alert Rules   │
│ • Pattern Recog.│    │   Streaming     │    │ • Notifications │
│ • Insights      │    │ • WebSocket     │    │ • Escalation    │
│ • Predictions   │    │ • Batch Process │    │ • Suppression   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Event Reporting │    │  Dashboard      │    │ System Integ.   │
│                 │    │                 │    │                 │
│ • Health Reports│────│ • Web UI        │────│ • Fleet Inv.    │
│ • Security      │    │ • Real-time     │    │ • Policy Eng.   │
│ • Operational   │    │   Updates       │    │ • Security Aud. │
│ • Compliance    │    │ • Charts        │    │ • Remote Agents │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Key Features

### 1. Normalized Event Model
- **Unified Schema**: All system signals follow a consistent event model
- **Rich Metadata**: Correlation IDs, user context, resource usage
- **Event Types**: Health checks, security events, operations, lifecycle events
- **Severity Levels**: Critical, Error, Warning, Info, Debug
- **Source Attribution**: Fleet inventory, policy engine, security audit, etc.

### 2. Comprehensive Event Collection
- **Multi-Source Collection**: Integrates with all TailOpsMCP components
- **Automatic Discovery**: Finds and monitors new systems
- **Health Monitoring**: Continuous health checks and status monitoring
- **Security Monitoring**: Policy violations, security alerts, audit events
- **Operational Monitoring**: Operation tracking, performance metrics

### 3. Persistent Event Storage
- **SQLite Database**: Reliable, ACID-compliant storage
- **Full-Text Search**: Fast search across event content
- **Efficient Indexing**: Optimized for common query patterns
- **Data Retention**: Configurable retention policies
- **Backup Support**: Automated backup and restore capabilities

### 4. Advanced Event Analysis
- **Trend Detection**: Identifies patterns and trends in event data
- **Anomaly Detection**: Finds unusual patterns and outliers
- **Pattern Recognition**: Discovers recurring event patterns
- **Predictive Analytics**: Forecasts potential issues
- **Machine Learning**: Optional ML-powered insights

### 5. Real-Time Event Processing
- **Event Streaming**: Real-time event processing pipeline
- **WebSocket Support**: Live updates to dashboards and clients
- **Batch Processing**: Efficient processing of event batches
- **Event Filtering**: Configurable filtering rules
- **Performance Monitoring**: Real-time processing statistics

### 6. Intelligent Alerting
- **Configurable Rules**: Flexible alert rule definitions
- **Multiple Channels**: Email, Slack, webhooks, console
- **Escalation Policies**: Automatic alert escalation
- **Alert Suppression**: Prevent alert fatigue
- **Alert Management**: Acknowledge, resolve, suppress alerts

### 7. Comprehensive Reporting
- **Health Reports**: System health and status reports
- **Security Reports**: Security posture and incident reports
- **Operational Reports**: Performance and operational metrics
- **Compliance Reports**: Compliance status and audit reports
- **Export Formats**: JSON, HTML, and custom formats

### 8. Web Dashboard
- **Real-Time Dashboard**: Live system monitoring dashboard
- **Interactive Charts**: Visual representation of trends and metrics
- **Event Browsing**: Search and filter events
- **Alert Management**: View and manage active alerts
- **System Status**: Overall system health overview

### 9. System Integration
- **Fleet Inventory**: Automatic health monitoring
- **Policy Engine**: Policy violation tracking
- **Security Audit**: Security event collection
- **Remote Agents**: Service status monitoring
- **Discovery Pipeline**: New system discovery
- **Proxmox API**: Container and VM monitoring

## Installation & Setup

### Prerequisites
- Python 3.8+
- SQLite 3.31+
- aiohttp (for dashboard)
- jinja2 (for templates)
- websockets (for real-time features)

### Installation
```bash
# Install dependencies
pip install aiohttp jinja2 websockets pyyaml

# Or add to requirements.txt
echo "aiohttp>=3.8.0" >> requirements.txt
echo "jinja2>=3.0.0" >> requirements.txt
echo "websockets>=10.0" >> requirements.txt
echo "pyyaml>=6.0" >> requirements.txt
```

### Configuration
Create a configuration file at `config/observability.yaml`:

```yaml
system_name: "TailOpsMCP"
version: "1.0.0"
debug: false
log_level: "INFO"

event_collection:
  enabled: true
  interval: 60
  batch_size: 100
  sources:
    - fleet_inventory
    - policy_engine
    - security_audit
    - remote_agent
    - discovery_pipeline
    - proxmox_api

event_storage:
  database_path: "./data/events.db"
  max_events: 1000000
  retention_days: 90
  compression: true
  auto_cleanup: true

event_analysis:
  enabled: true
  trend_analysis: true
  anomaly_detection: true
  pattern_recognition: true
  predictive_analytics: true

event_processing:
  enabled: true
  websocket_enabled: true
  websocket_port: 8765
  buffer_size: 1000

alerting:
  enabled: true
  evaluation_interval: 60
  email_enabled: false
  slack_enabled: false
  console_enabled: true

reporting:
  enabled: true
  auto_generate_reports: true
  export_formats: ["json", "html"]
  export_directory: "./reports"
```

### Environment Variables
You can also configure the system using environment variables:

```bash
export OBSERVABILITY_DEBUG=true
export EVENT_COLLECTION_INTERVAL=30
export EVENT_DB_PATH="/var/lib/tailops/events.db"
export WEBSOCKET_PORT=8765
export ALERTING_ENABLED=true
export SMTP_HOST="smtp.example.com"
export SMTP_USERNAME="alerts@example.com"
export SMTP_PASSWORD="your-password"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."
```

## Usage

### Basic Usage

#### 1. Initialize the System
```python
import asyncio
from src.services.system_integration import initialize_system_integrations
from src.services.event_processor import start_realtime_event_processing
from src.utils.observability_config_manager import get_observability_config

async def main():
    # Load configuration
    config = get_observability_config()

    # Initialize system integrations
    manager = await initialize_system_integrations()

    # Start real-time event processing
    processor = await start_realtime_event_processing()

    # Run integration cycle
    result = await manager.run_integration_cycle()
    print(f"Integration cycle result: {result}")

if __name__ == "__main__":
    asyncio.run(main())
```

#### 2. Using MCP Tools
```python
from src.tools.event_management_tools import (
    mcp_get_recent_events,
    mcp_get_health_summary,
    mcp_get_security_events,
    mcp_get_active_alerts,
    mcp_generate_comprehensive_report
)

# Get recent events
events_result = await mcp_get_recent_events(hours=24)
print(f"Found {events_result['total_count']} events")

# Get health summary
health_result = await mcp_get_health_summary(hours=24)
print(f"System health: {health_result['health_summary']['health_status']}")

# Get active alerts
alerts_result = await mcp_get_active_alerts()
print(f"Active alerts: {alerts_result['total_active_alerts']}")

# Generate comprehensive report
report_result = await mcp_generate_comprehensive_report(time_range="24h")
print(f"Report generated: {report_result['success']}")
```

#### 3. Event Management
```python
from src.models.event_models import EventBuilder, EventType, EventSeverity, EventSource
from src.services.event_store import get_event_store

async def create_and_store_event():
    # Create an event
    event = EventBuilder.health_check(
        EventSource.FLEET_INVENTORY,
        "web-server-01",
        "healthy",
        {"cpu": "45%", "memory": "60%"}
    )

    # Store the event
    store = get_event_store()
    event_id = await store.store_event(event)
    print(f"Stored event with ID: {event_id}")

    # Query events
    from src.models.event_models import EventFilters
    filters = EventFilters(
        targets=["web-server-01"],
        event_types=[EventType.HEALTH_CHECK]
    )

    events = await store.get_events(filters)
    print(f"Found {len(events)} events for web-server-01")
```

### Advanced Usage

#### 1. Custom Event Analysis
```python
from src.services.event_analyzer import get_event_analyzer

async def analyze_events():
    analyzer = get_event_analyzer()

    # Get events for analysis
    store = get_event_store()
    events = await store.get_events()

    # Detect trends
    trends = await analyzer.detect_trends(events)
    for trend in trends:
        print(f"Trend: {trend.name} - {trend.direction} (confidence: {trend.confidence:.2f})")

    # Generate insights
    insights = await analyzer.generate_insights(events)
    for insight in insights:
        print(f"Insight: {insight.title} - {insight.description}")

    # Predict issues
    predictions = await analyzer.predict_issues(events)
    for prediction in predictions:
        print(f"Prediction: {prediction.description} (probability: {prediction.probability:.2f})")
```

#### 2. Custom Alerting Rules
```python
from src.services.event_alerting import (
    EventAlerting, AlertRule, NotificationChannel
)

async def setup_custom_alerts():
    alerting = EventAlerting()

    # Create custom alert rule
    rule = AlertRule(
        name="high_cpu_usage",
        description="Alert when CPU usage is consistently high",
        condition="event_type == 'resource_threshold' and details.get('resource_type') == 'cpu' and details.get('usage_percent') > 90",
        severity=EventSeverity.WARNING,
        channels=[NotificationChannel.EMAIL, NotificationChannel.CONSOLE],
        recipients=["ops@example.com"],
        threshold_count=3,
        threshold_time_window=300  # 5 minutes
    )

    await alerting.add_alert_rule(rule)
    print("Custom alert rule added")

    # Evaluate alerts
    events = await get_event_store().get_events()
    alerts = await alerting.evaluate_alert_rules(events)
    print(f"Generated {len(alerts)} alerts")
```

#### 3. Custom Reporting
```python
from src.services.event_reporting import get_event_reporting, TimeRange

async def generate_custom_report():
    reporting = get_event_reporting()

    # Generate health report
    time_range = TimeRange.from_hours(24)
    health_report = await reporting.generate_health_report(time_range)

    print(f"Health score: {health_report.fleet_health_score:.1f}%")
    print(f"Healthy systems: {health_report.healthy_systems}/{health_report.total_systems}")

    # Export report
    await reporting.export_report(health_report, "html", "./reports/health_report.html")
    print("Health report exported to ./reports/health_report.html")
```

### Dashboard Usage

#### Starting the Dashboard
```python
from src.utils.event_dashboard import start_event_dashboard

async def start_dashboard():
    # Start the web dashboard
    dashboard = await start_event_dashboard(host="0.0.0.0", port=8080)

    # Dashboard will be available at http://localhost:8080
    print("Dashboard started at http://localhost:8080")

# Or run standalone
# python -m src.utils.event_dashboard --host 0.0.0.0 --port 8080
```

#### Dashboard Features
- **Real-time Updates**: Live event stream via WebSocket
- **System Health**: Overall system health score and status
- **Event Statistics**: Event counts by severity, source, type
- **Active Alerts**: Current alerts requiring attention
- **Event Browser**: Search and filter recent events
- **Charts**: Visual representation of trends and distributions

## API Reference

### Event Models

#### SystemEvent
```python
class SystemEvent:
    event_id: str
    timestamp: datetime
    event_type: EventType
    severity: EventSeverity
    source: EventSource
    target: Optional[str]
    category: EventCategory
    title: str
    description: str
    details: Dict[str, Any]
    health_score: Optional[float]
    resource_usage: Optional[ResourceUsage]
    metadata: EventMetadata
```

#### EventFilters
```python
class EventFilters:
    event_types: Optional[List[EventType]]
    severities: Optional[List[EventSeverity]]
    sources: Optional[List[EventSource]]
    categories: Optional[List[EventCategory]]
    targets: Optional[List[str]]
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    search_text: Optional[str]
    limit: Optional[int]
    offset: Optional[int]
```

### MCP Tools

#### Event Management
- `mcp_get_recent_events(hours, event_type)` - Get recent events
- `mcp_get_events_by_source(source, hours)` - Get events by source
- `mcp_get_events_by_target(target, hours)` - Get events by target
- `mcp_search_events(query, hours)` - Search events
- `mcp_get_event_statistics(time_range)` - Get event statistics

#### Health & Security
- `mcp_get_health_summary(hours)` - Get health summary
- `mcp_get_security_events(hours)` - Get security events
- `mcp_get_error_summary(hours)` - Get error summary
- `mcp_get_operation_summary(hours)` - Get operational summary

#### Alerts
- `mcp_get_active_alerts()` - Get active alerts
- `mcp_acknowledge_alert(alert_id, user_id, note)` - Acknowledge alert
- `mcp_resolve_alert(alert_id, user_id, note)` - Resolve alert

#### Reporting
- `mcp_generate_comprehensive_report(time_range)` - Generate report
- `mcp_export_report(report_type, time_range, format)` - Export report
- `mcp_get_event_trends(days)` - Get event trends

#### System
- `mcp_start_event_monitoring()` - Start monitoring
- `mcp_get_system_status()` - Get system status

### Configuration

#### ObservabilityConfig
```python
@dataclass
class ObservabilityConfig:
    system_name: str
    debug: bool
    log_level: str
    event_collection: EventCollectionConfig
    event_storage: EventStorageConfig
    event_analysis: EventAnalysisConfig
    event_processing: EventProcessingConfig
    alerting: AlertingConfig
    reporting: ReportingConfig
    security: Dict[str, Any]
    performance: Dict[str, Any]
    integrations: Dict[str, Any]
```

## Examples

### Complete Integration Example
See `examples/observability_demo.py` for a complete working example that demonstrates:
- System initialization
- Event collection and processing
- Alert rule creation
- Report generation
- Dashboard startup

### Health Monitoring Example
See `examples/health_monitoring_example.py` for a health monitoring focused example that shows:
- Fleet health monitoring
- Resource usage tracking
- Health score calculation
- Health trend analysis

### Security Monitoring Example
See `examples/security_monitoring_example.py` for a security monitoring example that demonstrates:
- Security event collection
- Policy violation detection
- Security trend analysis
- Compliance reporting

## Testing

Run the comprehensive test suite:

```bash
# Run all tests
python -m pytest tests/test_observability_system.py -v

# Run specific test categories
python -m pytest tests/test_observability_system.py::TestEventModels -v
python -m pytest tests/test_observability_system.py::TestEventStore -v
python -m pytest tests/test_observability_system.py::TestEndToEndScenarios -v

# Run with coverage
python -m pytest tests/test_observability_system.py --cov=src --cov-report=html
```

## Performance

The observability system is designed for high performance:

- **Event Storage**: Can handle 1000+ events/second
- **Event Retrieval**: Sub-second query performance with proper indexing
- **Real-time Processing**: Low-latency event streaming (< 100ms)
- **Memory Usage**: Efficient memory management with configurable buffers
- **Disk Usage**: Configurable compression and retention policies

## Monitoring the Observability System

The system includes built-in monitoring for itself:

- **Processing Statistics**: Events processed, batches handled, errors encountered
- **Storage Statistics**: Database size, query performance, index efficiency
- **Alert Statistics**: Alerts generated, notifications sent, escalation levels
- **System Integration Status**: Health of each integrated system

## Troubleshooting

### Common Issues

1. **Database Connection Errors**
   - Check database file permissions
   - Ensure sufficient disk space
   - Verify SQLite installation

2. **WebSocket Connection Failures**
   - Check firewall settings
   - Verify port availability
   - Ensure aiohttp dependency is installed

3. **High Memory Usage**
   - Reduce buffer sizes in configuration
   - Increase cleanup frequency
   - Check for memory leaks in custom integrations

4. **Missing Events**
   - Verify integration status
   - Check log files for collection errors
   - Validate event source configurations

### Debug Mode

Enable debug mode for detailed logging:

```python
config = ObservabilityConfig(debug=True)
# or
os.environ["OBSERVABILITY_DEBUG"] = "true"
```

### Log Analysis

Check logs for common patterns:
- `Integration.*initialized` - System integration status
- `Stored event.*` - Event storage confirmation
- `Generated.*alerts` - Alert generation
- `Error.*` - System errors requiring attention

## Contributing

To extend the observability system:

1. **Add New Event Sources**: Implement integration in `src/services/system_integration.py`
2. **Custom Analysis**: Extend `src/services/event_analyzer.py`
3. **New Alert Rules**: Add rules in `src/services/event_alerting.py`
4. **Dashboard Widgets**: Extend `src/utils/event_dashboard.py`
5. **MCP Tools**: Add tools in `src/tools/event_management_tools.py`

## License

This observability system is part of the TailOpsMCP project and follows the same licensing terms.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review logs for error messages
3. Test with debug mode enabled
4. Create an issue with detailed reproduction steps
