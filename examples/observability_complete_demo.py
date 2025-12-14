#!/usr/bin/env python3
"""
TailOpsMCP Observability System - Complete Example

This example demonstrates the complete observability system including:
- System initialization
- Event collection from multiple sources
- Real-time event processing
- Alert rule management
- Report generation
- Dashboard startup

Run this example to see the observability system in action.
"""

import asyncio
import json
import os
import time
from datetime import datetime, timedelta
from pathlib import Path

# Import observability system components
from src.models.event_models import (
    SystemEvent, EventType, EventSeverity, EventSource, EventCategory,
    EventBuilder, ResourceUsage
)
from src.services.event_collector import EventCollector, EventAggregator, collect_and_aggregate_events
from src.services.event_store import get_event_store, initialize_event_storage
from src.services.event_analyzer import get_event_analyzer
from src.services.event_processor import (
    get_event_stream_processor, EventStreamConfig, start_realtime_event_processing
)
from src.services.event_alerting import (
    get_event_alerting, AlertRule, NotificationChannel, create_default_alert_rules
)
from src.services.event_reporting import (
    get_event_reporting, generate_comprehensive_report, TimeRange
)
from src.services.system_integration import (
    get_system_integration_manager, initialize_system_integrations
)
from src.tools.event_management_tools import (
    get_event_management_tools,
    mcp_get_recent_events,
    mcp_get_health_summary,
    mcp_get_security_events,
    mcp_get_active_alerts,
    mcp_generate_comprehensive_report,
    mcp_get_system_status
)
from src.utils.observability_config_manager import (
    get_config_manager, create_sample_config_file
)
from src.utils.logging_config import setup_logging, get_logger


class ObservabilityDemo:
    """Demonstration of the complete observability system."""
    
    def __init__(self):
        self.logger = get_logger("observability_demo")
        self.event_store = None
        self.event_collector = None
        self.event_analyzer = None
        self.event_alerting = None
        self.event_reporting = None
        self.integration_manager = None
        self.tools = None
        self.processor = None
    
    async def setup(self):
        """Initialize all observability components."""
        self.logger.info("Setting up TailOpsMCP Observability System...")
        
        # 1. Load configuration
        config_manager = get_config_manager()
        config = config_manager.get_config()
        self.logger.info(f"Configuration loaded: {config.system_name} v{config.version}")
        
        # 2. Initialize event storage
        await initialize_event_storage()
        self.event_store = get_event_store()
        self.logger.info("Event storage initialized")
        
        # 3. Initialize event collector
        self.event_collector = EventCollector()
        self.logger.info("Event collector initialized")
        
        # 4. Initialize event analyzer
        self.event_analyzer = get_event_analyzer()
        self.logger.info("Event analyzer initialized")
        
        # 5. Initialize alerting system
        self.event_alerting = get_event_alerting()
        
        # Add default alert rules
        default_rules = create_default_alert_rules()
        for rule in default_rules:
            await self.event_alerting.add_alert_rule(rule)
        self.logger.info(f"Added {len(default_rules)} default alert rules")
        
        # 6. Initialize reporting system
        self.event_reporting = get_event_reporting()
        self.logger.info("Reporting system initialized")
        
        # 7. Initialize system integrations
        self.integration_manager = get_system_integration_manager()
        integration_status = await self.integration_manager.initialize_integrations()
        active_integrations = sum(1 for status in integration_status.values() if status)
        self.logger.info(f"Initialized {active_integrations}/{len(integration_status)} integrations")
        
        # 8. Initialize event management tools
        self.tools = get_event_management_tools()
        self.logger.info("Event management tools initialized")
        
        # 9. Initialize real-time event processing
        processor_config = EventStreamConfig(
            buffer_size=100,
            batch_size=10,
            websocket_enabled=True,
            websocket_port=8765
        )
        self.processor = get_event_stream_processor(processor_config)
        self.logger.info("Real-time event processor initialized")
        
        self.logger.info("Observability system setup complete!")
    
    async def generate_sample_events(self, count: int = 50):
        """Generate sample events for demonstration."""
        self.logger.info(f"Generating {count} sample events...")
        
        events = []
        current_time = datetime.utcnow()
        
        # Create diverse sample events
        for i in range(count):
            # Vary event types, severities, and sources
            event_type = list(EventType)[i % len(EventType)]
            severity = list(EventSeverity)[i % len(EventSeverity)]
            source = list(EventSource)[i % len(EventSource)]
            
            # Create different types of events
            if event_type == EventType.HEALTH_CHECK:
                event = EventBuilder.health_check(
                    source,
                    f"target-{i % 5}",
                    "healthy" if i % 4 != 0 else "unhealthy",
                    {"cpu": f"{30 + i % 70}%", "memory": f"{40 + i % 60}%"}
                )
            elif event_type == EventType.RESOURCE_THRESHOLD:
                event = EventBuilder()
                event.event_type = EventType.RESOURCE_THRESHOLD
                event.severity = EventSeverity.WARNING if i % 3 != 0 else EventSeverity.ERROR
                event.source = source
                event.target = f"target-{i % 5}"
                event.category = EventCategory.PERFORMANCE
                event.title = f"High resource usage on target-{i % 5}"
                event.description = f"CPU usage at {85 + i % 15}%"
                event.resource_usage = ResourceUsage(
                    cpu_percent=85 + i % 15,
                    memory_percent=70 + i % 25
                )
                event.details = {
                    "resource_type": "cpu",
                    "usage_percent": 85 + i % 15,
                    "threshold": 80.0
                }
                event.add_tag("resource_threshold")
                event = event.build()
            elif event_type == EventType.SECURITY_ALERT:
                event = EventBuilder.security_alert(
                    source,
                    f"Security event {i}",
                    f"Security alert for target-{i % 5}",
                    severity if severity in [EventSeverity.ERROR, EventSeverity.WARNING] else EventSeverity.WARNING
                )
                event.target = f"target-{i % 5}"
            elif event_type == EventType.OPERATION_COMPLETED:
                event = EventBuilder.operation_completed(
                    source,
                    f"operation-{i % 3}",
                    f"target-{i % 5}",
                    duration=1.0 + (i % 10) * 0.5
                )
            else:
                # Generic event
                event = SystemEvent(
                    event_type=event_type,
                    severity=severity,
                    source=source,
                    target=f"target-{i % 5}",
                    title=f"Event {i}: {event_type.value}",
                    description=f"Description for event {i}",
                    details={"index": i, "sample": True}
                )
            
            # Set timestamp (some in the past, some recent)
            if i < count * 0.8:  # 80% in the past 24 hours
                event.timestamp = current_time - timedelta(
                    hours=i % 24,
                    minutes=i % 60
                )
            
            # Set health score for some events
            if event_type == EventType.HEALTH_CHECK:
                event.set_health_score(100 - (i % 30))
            
            events.append(event)
        
        # Store all events
        await self.event_store.store_events(events)
        self.logger.info(f"Generated and stored {len(events)} sample events")
        
        # Send to event processor
        await self.processor.add_events(events)
        
        return events
    
    async def demonstrate_event_analysis(self, events):
        """Demonstrate event analysis capabilities."""
        self.logger.info("Demonstrating event analysis...")
        
        # 1. Detect trends
        self.logger.info("Detecting trends...")
        trends = await self.event_analyzer.detect_trends(events)
        self.logger.info(f"Found {len(trends)} trends:")
        for trend in trends[:3]:  # Show first 3
            self.logger.info(f"  - {trend.name}: {trend.direction} (confidence: {trend.confidence:.2f})")
        
        # 2. Detect patterns
        self.logger.info("Detecting patterns...")
        patterns = await self.event_analyzer.detect_patterns(events)
        self.logger.info(f"Found {len(patterns)} patterns:")
        for pattern in patterns[:3]:  # Show first 3
            self.logger.info(f"  - {pattern.name}: {pattern.pattern_type} (frequency: {pattern.frequency})")
        
        # 3. Generate insights
        self.logger.info("Generating insights...")
        insights = await self.event_analyzer.generate_insights(events)
        self.logger.info(f"Generated {len(insights)} insights:")
        for insight in insights[:3]:  # Show first 3
            self.logger.info(f"  - {insight.title}: {insight.description}")
        
        # 4. Predict issues
        self.logger.info("Predicting issues...")
        predictions = await self.event_analyzer.predict_issues(events)
        self.logger.info(f"Generated {len(predictions)} predictions:")
        for prediction in predictions[:3]:  # Show first 3
            self.logger.info(f"  - {prediction.description} (probability: {prediction.probability:.2f})")
    
    async def demonstrate_alerting(self, events):
        """Demonstrate alerting capabilities."""
        self.logger.info("Demonstrating alerting system...")
        
        # 1. Evaluate alerts
        self.logger.info("Evaluating alert rules...")
        alerts = await self.event_alerting.evaluate_alert_rules(events)
        self.logger.info(f"Generated {len(alerts)} alerts:")
        
        for alert in alerts[:5]:  # Show first 5
            self.logger.info(f"  - Alert {alert.id}: {alert.title} ({alert.severity.value})")
            
            # Demonstrate alert management
            if len(alerts) > 0 and alert == alerts[0]:
                # Acknowledge first alert
                await self.event_alerting.acknowledge_alert(
                    alert.id, "demo_user", "Acknowledged during demo"
                )
                self.logger.info(f"  - Acknowledged alert {alert.id}")
        
        # 2. Show alert statistics
        alert_stats = await self.event_alerting.get_alert_statistics()
        self.logger.info(f"Alert statistics: {alert_stats}")
    
    async def demonstrate_reporting(self):
        """Demonstrate reporting capabilities."""
        self.logger.info("Demonstrating reporting system...")
        
        # 1. Generate health report
        self.logger.info("Generating health report...")
        time_range = TimeRange.last_24_hours()
        health_report = await self.event_reporting.generate_health_report(time_range)
        
        self.logger.info(f"Health Report:")
        self.logger.info(f"  - Fleet health score: {health_report.fleet_health_score:.1f}%")
        self.logger.info(f"  - Health status: {health_report.system_health_status}")
        self.logger.info(f"  - Systems: {health_report.healthy_systems}/{health_report.total_systems} healthy")
        
        # 2. Generate security report
        self.logger.info("Generating security report...")
        security_report = await self.event_reporting.generate_security_report(time_range)
        
        self.logger.info(f"Security Report:")
        self.logger.info(f"  - Security score: {security_report.security_score:.1f}%")
        self.logger.info(f"  - Security status: {security_report.security_status}")
        self.logger.info(f"  - Security events: {security_report.total_security_events}")
        
        # 3. Generate operational report
        self.logger.info("Generating operational report...")
        operational_report = await self.event_reporting.generate_operational_report(time_range)
        
        self.logger.info(f"Operational Report:")
        self.logger.info(f"  - Operational score: {operational_report.operational_score:.1f}%")
        self.logger.info(f"  - Operations: {operational_report.successful_operations}/{operational_report.total_operations} successful")
        self.logger.info(f"  - Success rate: {operational_report.operation_success_rate:.1f}%")
        
        # 4. Generate comprehensive report
        self.logger.info("Generating comprehensive report...")
        comprehensive_report = await generate_comprehensive_report(time_range)
        
        self.logger.info("Comprehensive Report generated with:")
        self.logger.info(f"  - Health report: {'health_report' in comprehensive_report}")
        self.logger.info(f"  - Security report: {'security_report' in comprehensive_report}")
        self.logger.info(f"  - Operational report: {'operational_report' in comprehensive_report}")
        self.logger.info(f"  - Dashboard data: {'dashboard_data' in comprehensive_report}")
    
    async def demonstrate_mcp_tools(self):
        """Demonstrate MCP event management tools."""
        self.logger.info("Demonstrating MCP event management tools...")
        
        # 1. Get recent events
        self.logger.info("Getting recent events...")
        events_result = await mcp_get_recent_events(hours=24)
        if events_result['success']:
            self.logger.info(f"  - Found {events_result['total_count']} recent events")
        
        # 2. Get health summary
        self.logger.info("Getting health summary...")
        health_result = await mcp_get_health_summary(hours=24)
        if health_result['success']:
            health_summary = health_result['health_summary']
            self.logger.info(f"  - Health status: {health_summary['health_status']}")
            self.logger.info(f"  - Health score: {health_summary['fleet_health_score']:.1f}%")
        
        # 3. Get security events
        self.logger.info("Getting security events...")
        security_result = await mcp_get_security_events(hours=24)
        if security_result['success']:
            security_summary = security_result['security_summary']
            self.logger.info(f"  - Security status: {security_summary['security_status']}")
            self.logger.info(f"  - Security events: {security_summary['total_security_events']}")
        
        # 4. Get active alerts
        self.logger.info("Getting active alerts...")
        alerts_result = await mcp_get_active_alerts()
        if alerts_result['success']:
            self.logger.info(f"  - Active alerts: {alerts_result['total_active_alerts']}")
        
        # 5. Get system status
        self.logger.info("Getting system status...")
        status_result = await mcp_get_system_status()
        if status_result['success']:
            system_status = status_result['system_status']
            self.logger.info(f"  - Overall status: {system_status['overall_status']}")
            self.logger.info(f"  - Health score: {system_status['health_score']:.1f}%")
            self.logger.info(f"  - Active alerts: {system_status['active_alerts']}")
    
    async def demonstrate_real_time_processing(self):
        """Demonstrate real-time event processing."""
        self.logger.info("Demonstrating real-time event processing...")
        
        # 1. Add events to processor
        for i in range(5):
            event = SystemEvent(
                event_type=EventType.HEALTH_CHECK,
                severity=EventSeverity.INFO,
                source=EventSource.FLEET_INVENTORY,
                target=f"realtime-target-{i}",
                title=f"Real-time event {i}",
                description=f"Demonstrating real-time processing {i}"
            )
            
            await self.processor.add_event(event)
            self.logger.info(f"  - Added real-time event {i}")
            await asyncio.sleep(0.5)  # Small delay between events
        
        # 2. Show processing statistics
        stats = self.processor.get_stats()
        buffer_status = self.processor.get_buffer_status()
        
        self.logger.info(f"Processing statistics:")
        self.logger.info(f"  - Events processed: {stats['events_processed']}")
        self.logger.info(f"  - Batches processed: {stats['batches_processed']}")
        self.logger.info(f"  - Current buffer size: {buffer_status['buffer_size']}")
        self.logger.info(f"  - WebSocket clients: {buffer_status['websocket_clients']}")
    
    async def demonstrate_system_integration(self):
        """Demonstrate system integration."""
        self.logger.info("Demonstrating system integration...")
        
        # 1. Check integration status
        integration_status = self.integration_manager.get_integration_status()
        self.logger.info(f"Integration status:")
        self.logger.info(f"  - Active integrations: {integration_status['active_count']}/{integration_status['total_count']}")
        self.logger.info(f"  - Health score: {integration_status['health_score']:.1f}%")
        
        # 2. Run integration cycle
        self.logger.info("Running integration cycle...")
        cycle_result = await self.integration_manager.run_integration_cycle()
        
        if cycle_result['success']:
            self.logger.info(f"Integration cycle completed:")
            self.logger.info(f"  - Events collected: {cycle_result['events_collected']}")
            self.logger.info(f"  - Active integrations: {cycle_result['active_integrations']}")
        else:
            self.logger.warning(f"Integration cycle failed: {cycle_result.get('error', 'Unknown error')}")
    
    async def run_complete_demo(self):
        """Run the complete observability system demonstration."""
        self.logger.info("=" * 60)
        self.logger.info("TailOpsMCP Observability System - Complete Demo")
        self.logger.info("=" * 60)
        
        try:
            # Setup
            await self.setup()
            
            # Generate sample data
            events = await self.generate_sample_events(50)
            
            # Demonstrate features
            await self.demonstrate_event_analysis(events)
            await self.demonstrate_alerting(events)
            await self.demonstrate_reporting()
            await self.demonstrate_mcp_tools()
            await self.demonstrate_real_time_processing()
            await self.demonstrate_system_integration()
            
            # Final status
            self.logger.info("=" * 60)
            final_status = await mcp_get_system_status()
            if final_status['success']:
                system_status = final_status['system_status']
                self.logger.info(f"Final System Status: {system_status['overall_status']}")
                self.logger.info(f"Health Score: {system_status['health_score']:.1f}%")
                self.logger.info(f"Active Alerts: {system_status['active_alerts']}")
                self.logger.info(f"Total Events (24h): {system_status['total_events_24h']}")
            self.logger.info("=" * 60)
            self.logger.info("Demo completed successfully!")
            
        except Exception as e:
            self.logger.error(f"Demo failed with error: {e}")
            raise


async def main():
    """Main demo function."""
    # Setup logging
    setup_logging()
    
    # Create output directories
    os.makedirs("./reports", exist_ok=True)
    os.makedirs("./data", exist_ok=True)
    os.makedirs("./logs", exist_ok=True)
    
    # Create sample configuration if it doesn't exist
    if not os.path.exists("./config/observability.yaml"):
        create_sample_config_file("./config/observability.yaml")
        print("Created sample configuration file at ./config/observability.yaml")
    
    # Run the demo
    demo = ObservabilityDemo()
    await demo.run_complete_demo()


if __name__ == "__main__":
    print("TailOpsMCP Observability System - Complete Example")
    print("This demo will showcase all features of the observability system.")
    print("Starting demo...")
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nDemo interrupted by user.")
    except Exception as e:
        print(f"\nDemo failed with error: {e}")
        import traceback
        traceback.print_exc()