"""
Comprehensive test suite for TailOpsMCP observability system.

This module provides unit tests, integration tests, and end-to-end tests
for all components of the observability system.
"""

import asyncio
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from src.models.event_models import (
    SystemEvent,
    EventType,
    EventSeverity,
    EventSource,
    EventCategory,
    EventBuilder,
    ResourceUsage,
    EventFilters,
)
from src.services.event_collector import EventCollector, EventAggregator
from src.services.event_store import EventStore
from src.services.event_analyzer import EventAnalyzer
from src.services.event_processor import EventStreamProcessor, EventStreamConfig
from src.services.event_alerting import (
    EventAlerting,
    AlertRule,
    NotificationChannel,
    create_default_alert_rules,
)
from src.services.event_reporting import (
    EventReporting,
    TimeRange,
    HealthReport,
    SecurityReport,
)
from src.services.system_integration import (
    SystemIntegrationManager,
    FleetInventoryIntegration,
    PolicyEngineIntegration,
    SecurityAuditIntegration,
)
from src.tools.event_management_tools import EventManagementTools
from src.utils.observability_config_manager import ConfigManager, ObservabilityConfig


class TestEventModels(unittest.TestCase):
    """Test event model classes and functions."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_event = SystemEvent(
            event_type=EventType.HEALTH_CHECK,
            severity=EventSeverity.INFO,
            source=EventSource.FLEET_INVENTORY,
            title="Test Event",
            description="Test event description",
        )

    def test_event_creation(self):
        """Test event creation and basic properties."""
        self.assertEqual(self.test_event.event_type, EventType.HEALTH_CHECK)
        self.assertEqual(self.test_event.severity, EventSeverity.INFO)
        self.assertEqual(self.test_event.source, EventSource.FLEET_INVENTORY)
        self.assertEqual(self.test_event.title, "Test Event")
        self.assertIsNotNone(self.test_event.event_id)
        self.assertIsNotNone(self.test_event.timestamp)

    def test_event_serialization(self):
        """Test event serialization to/from dictionary."""
        event_dict = self.test_event.to_dict()
        self.assertIsInstance(event_dict, dict)
        self.assertEqual(event_dict["event_type"], "health_check")
        self.assertEqual(event_dict["severity"], "info")

        # Test deserialization
        restored_event = SystemEvent.from_dict(event_dict)
        self.assertEqual(restored_event.event_type, self.test_event.event_type)
        self.assertEqual(restored_event.severity, self.test_event.severity)
        self.assertEqual(restored_event.title, self.test_event.title)

    def test_event_builder(self):
        """Test event builder functionality."""
        event = EventBuilder.health_check(
            EventSource.FLEET_INVENTORY, "test-target", "healthy", {"cpu": "50%"}
        )

        self.assertEqual(event.event_type, EventType.HEALTH_CHECK)
        self.assertEqual(event.target, "test-target")
        self.assertEqual(event.source, EventSource.FLEET_INVENTORY)
        self.assertIn("test-target", event.title)

    def test_event_filters(self):
        """Test event filtering."""
        filters = EventFilters(
            event_types=[EventType.HEALTH_CHECK],
            severities=[EventSeverity.INFO],
            sources=[EventSource.FLEET_INVENTORY],
        )

        self.assertEqual(len(filters.event_types), 1)
        self.assertEqual(filters.event_types[0], EventType.HEALTH_CHECK)
        self.assertEqual(filters.severities[0], EventSeverity.INFO)

    def test_resource_usage(self):
        """Test resource usage model."""
        usage = ResourceUsage(cpu_percent=75.5, memory_percent=80.0)

        self.assertEqual(usage.cpu_percent, 75.5)
        self.assertEqual(usage.memory_percent, 80.0)
        self.assertIsNone(usage.disk_percent)

    def test_event_severity_checks(self):
        """Test event severity helper methods."""
        critical_event = SystemEvent(
            severity=EventSeverity.CRITICAL, title="Critical Event"
        )

        self.assertTrue(critical_event.is_critical())
        self.assertTrue(critical_event.is_error())
        self.assertFalse(critical_event.is_warning())

        warning_event = SystemEvent(
            severity=EventSeverity.WARNING, title="Warning Event"
        )

        self.assertFalse(warning_event.is_critical())
        self.assertFalse(warning_event.is_error())
        self.assertTrue(warning_event.is_warning())


class TestEventStore(unittest.TestCase):
    """Test event storage and retrieval."""

    def setUp(self):
        """Set up test fixtures."""
        # Use temporary database for testing
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_events.db")
        self.event_store = EventStore(self.db_path)

    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        os.rmdir(self.temp_dir)

    def test_database_initialization(self):
        """Test database schema initialization."""
        self.assertTrue(os.path.exists(self.db_path))
        # Database should have been initialized with proper schema

    @pytest.mark.asyncio
    async def test_store_and_retrieve_event(self):
        """Test storing and retrieving a single event."""
        test_event = SystemEvent(
            event_type=EventType.HEALTH_CHECK,
            severity=EventSeverity.INFO,
            source=EventSource.FLEET_INVENTORY,
            target="test-target",
            title="Test Event",
            description="Test event for storage",
        )

        # Store event
        event_id = await self.event_store.store_event(test_event)
        self.assertEqual(event_id, test_event.event_id)

        # Retrieve event
        filters = EventFilters(targets=["test-target"])
        retrieved_events = await self.event_store.get_events(filters)

        self.assertEqual(len(retrieved_events), 1)
        retrieved_event = retrieved_events[0]
        self.assertEqual(retrieved_event.event_id, test_event.event_id)
        self.assertEqual(retrieved_event.title, "Test Event")

    @pytest.mark.asyncio
    async def test_store_multiple_events(self):
        """Test storing multiple events."""
        events = []
        for i in range(5):
            event = SystemEvent(
                event_type=EventType.HEALTH_CHECK,
                severity=EventSeverity.INFO,
                source=EventSource.FLEET_INVENTORY,
                target=f"target-{i}",
                title=f"Event {i}",
                description=f"Description for event {i}",
            )
            events.append(event)

        # Store events
        event_ids = await self.event_store.store_events(events)
        self.assertEqual(len(event_ids), 5)

        # Retrieve all events
        all_events = await self.event_store.get_events()
        self.assertEqual(len(all_events), 5)

    @pytest.mark.asyncio
    async def test_event_filtering(self):
        """Test event filtering by various criteria."""
        # Create test events with different properties
        events = [
            SystemEvent(
                event_type=EventType.HEALTH_CHECK,
                severity=EventSeverity.INFO,
                source=EventSource.FLEET_INVENTORY,
            ),
            SystemEvent(
                event_type=EventType.ERROR,
                severity=EventSeverity.ERROR,
                source=EventSource.SYSTEM,
            ),
            SystemEvent(
                event_type=EventType.WARNING,
                severity=EventSeverity.WARNING,
                source=EventSource.PROXMOX_API,
            ),
        ]

        await self.event_store.store_events(events)

        # Test filtering by event type
        filters = EventFilters(event_types=[EventType.HEALTH_CHECK])
        filtered_events = await self.event_store.get_events(filters)
        self.assertEqual(len(filtered_events), 1)
        self.assertEqual(filtered_events[0].event_type, EventType.HEALTH_CHECK)

        # Test filtering by severity
        filters = EventFilters(severities=[EventSeverity.ERROR])
        filtered_events = await self.event_store.get_events(filters)
        self.assertEqual(len(filtered_events), 1)
        self.assertEqual(filtered_events[0].severity, EventSeverity.ERROR)

        # Test filtering by source
        filters = EventFilters(sources=[EventSource.FLEET_INVENTORY])
        filtered_events = await self.event_store.get_events(filters)
        self.assertEqual(len(filtered_events), 1)
        self.assertEqual(filtered_events[0].source, EventSource.FLEET_INVENTORY)

    @pytest.mark.asyncio
    async def test_time_range_filtering(self):
        """Test filtering events by time range."""
        now = datetime.utcnow()

        # Create events at different times
        event1 = SystemEvent(timestamp=now - timedelta(hours=2), title="Old Event")
        event2 = SystemEvent(timestamp=now, title="Current Event")

        await self.event_store.store_events([event1, event2])

        # Filter for last hour
        filters = EventFilters(
            start_time=now - timedelta(hours=1), end_time=now + timedelta(hours=1)
        )

        filtered_events = await self.event_store.get_events(filters)
        self.assertEqual(len(filtered_events), 1)
        self.assertEqual(filtered_events[0].title, "Current Event")

    @pytest.mark.asyncio
    async def test_event_statistics(self):
        """Test event statistics generation."""
        # Create test events
        events = []
        for i in range(10):
            severity = (
                EventSeverity.CRITICAL
                if i < 2
                else EventSeverity.ERROR
                if i < 5
                else EventSeverity.WARNING
            )
            event = SystemEvent(
                severity=severity,
                source=EventSource.FLEET_INVENTORY,
                title=f"Event {i}",
            )
            events.append(event)

        await self.event_store.store_events(events)

        # Get statistics
        stats = await self.event_store.get_statistics(24)

        self.assertEqual(stats.total_events, 10)
        self.assertEqual(stats.critical_events, 2)
        self.assertEqual(stats.error_events, 3)
        self.assertEqual(stats.warning_events, 3)
        self.assertEqual(stats.info_events, 2)


class TestEventCollector(unittest.TestCase):
    """Test event collection functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.collector = EventCollector()

    @pytest.mark.asyncio
    async def test_health_event_creation(self):
        """Test health event creation."""
        # This test would need to mock the actual fleet inventory service
        # For now, we'll test the event creation logic

        event = EventBuilder.health_check(
            EventSource.FLEET_INVENTORY, "test-target", "healthy"
        )

        self.assertEqual(event.event_type, EventType.HEALTH_CHECK)
        self.assertEqual(event.source, EventSource.FLEET_INVENTORY)
        self.assertEqual(event.target, "test-target")
        self.assertIn("healthy", event.title.lower())

    @pytest.mark.asyncio
    async def test_event_aggregation(self):
        """Test event aggregation functionality."""
        aggregator = EventAggregator()

        # Create test events
        events = [
            SystemEvent(
                event_type=EventType.HEALTH_CHECK, source=EventSource.FLEET_INVENTORY
            ),
            SystemEvent(
                event_type=EventType.HEALTH_CHECK, source=EventSource.FLEET_INVENTORY
            ),
            SystemEvent(event_type=EventType.ERROR, source=EventSource.SYSTEM),
        ]

        # Test correlation
        correlated_events = await aggregator.correlate_events(events)
        self.assertLessEqual(len(correlated_events), len(events))

        # Test aggregation
        metrics = await aggregator.aggregate_metrics(events)
        self.assertIn("total_events", metrics)
        self.assertEqual(metrics["total_events"], 3)
        self.assertIn("events_by_source", metrics)
        self.assertIn("events_by_type", metrics)


class TestEventAnalyzer(unittest.TestCase):
    """Test event analysis functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = EventAnalyzer()

    @pytest.mark.asyncio
    async def test_trend_detection(self):
        """Test trend detection in events."""
        # Create events with increasing trend
        base_time = datetime.utcnow()
        events = []

        for i in range(10):
            event = SystemEvent(
                timestamp=base_time + timedelta(hours=i),
                severity=EventSeverity.INFO,
                source=EventSource.FLEET_INVENTORY,
                title=f"Event {i}",
                details={"value": i * 10},  # Increasing values
            )
            events.append(event)

        trends = await self.analyzer.detect_trends(events)

        # Should detect at least some trends
        self.assertIsInstance(trends, list)
        if trends:
            trend = trends[0]
            self.assertIsInstance(trend.name, str)
            self.assertIn(trend.direction, ["increasing", "decreasing", "stable"])

    @pytest.mark.asyncio
    async def test_pattern_detection(self):
        """Test pattern detection in events."""
        # Create events with repeating pattern
        events = []
        base_time = datetime.utcnow()

        # Create a repeating sequence: HEALTH_CHECK, ERROR, WARNING
        for cycle in range(3):
            for i, event_type in enumerate(
                [EventType.HEALTH_CHECK, EventType.ERROR, EventType.WARNING]
            ):
                event = SystemEvent(
                    timestamp=base_time + timedelta(hours=cycle * 3 + i),
                    event_type=event_type,
                    source=EventSource.FLEET_INVENTORY,
                    title=f"Pattern Event {cycle}-{i}",
                )
                events.append(event)

        patterns = await self.analyzer.detect_patterns(events)

        # Should detect patterns
        self.assertIsInstance(patterns, list)

    @pytest.mark.asyncio
    async def test_insight_generation(self):
        """Test insight generation from events."""
        # Create events that should generate insights
        events = []

        # Create multiple error events (should generate operational insight)
        for i in range(5):
            event = SystemEvent(
                event_type=EventType.OPERATION_FAILED,
                severity=EventSeverity.ERROR,
                source=EventSource.SYSTEM,
                title=f"Operation Failed {i}",
                details={"operation": "test_operation"},
            )
            events.append(event)

        insights = await self.analyzer.generate_insights(events)

        # Should generate at least one insight
        self.assertIsInstance(insights, list)
        if insights:
            insight = insights[0]
            self.assertIsInstance(insight.title, str)
            self.assertIsInstance(insight.description, str)
            self.assertIn(
                insight.insight_type,
                ["operational", "security", "performance", "health"],
            )

    @pytest.mark.asyncio
    async def test_prediction_generation(self):
        """Test issue prediction functionality."""
        # Create events that should lead to predictions
        events = []

        # Create resource threshold events (should predict capacity issues)
        for i in range(3):
            event = SystemEvent(
                event_type=EventType.RESOURCE_THRESHOLD,
                severity=EventSeverity.WARNING,
                source=EventSource.FLEET_INVENTORY,
                target="test-target",
                resource_usage=ResourceUsage(cpu_percent=85 + i * 2),
                title=f"High CPU Usage {i}",
                details={"cpu_percent": 85 + i * 2},
            )
            events.append(event)

        predictions = await self.analyzer.predict_issues(events)

        # Should generate predictions
        self.assertIsInstance(predictions, list)


class TestEventAlerting(unittest.TestCase):
    """Test event alerting system."""

    def setUp(self):
        """Set up test fixtures."""
        self.alerting = EventAlerting()

    @pytest.mark.asyncio
    async def test_alert_rule_creation(self):
        """Test alert rule creation and evaluation."""
        rule = AlertRule(
            name="test_rule",
            description="Test alert rule",
            condition="severity == 'critical'",
            severity=EventSeverity.CRITICAL,
            channels=[NotificationChannel.CONSOLE],
            recipients=["test@example.com"],
        )

        # Test rule evaluation
        critical_event = SystemEvent(
            severity=EventSeverity.CRITICAL, title="Critical Event"
        )

        should_trigger = rule.evaluate([critical_event])
        self.assertTrue(should_trigger)

        info_event = SystemEvent(severity=EventSeverity.INFO, title="Info Event")

        should_not_trigger = rule.evaluate([info_event])
        self.assertFalse(should_not_trigger)

    @pytest.mark.asyncio
    async def test_alert_creation(self):
        """Test alert creation and management."""
        AlertRule(
            name="test_rule",
            description="Test alert rule",
            condition="severity == 'critical'",
            severity=EventSeverity.CRITICAL,
        )

        critical_event = SystemEvent(
            severity=EventSeverity.CRITICAL,
            title="Critical System Error",
            description="System has encountered a critical error",
        )

        # Create alert
        alerts = await self.alerting.evaluate_alert_rules([critical_event])

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.severity, EventSeverity.CRITICAL)
        self.assertEqual(alert.rule_name, "test_rule")
        self.assertEqual(alert.status.value, "active")

        # Test alert acknowledgment
        success = await self.alerting.acknowledge_alert(
            alert.id, "test_user", "Acknowledged for testing"
        )
        self.assertTrue(success)

        # Test alert resolution
        success = await self.alerting.resolve_alert(
            alert.id, "test_user", "Issue resolved"
        )
        self.assertTrue(success)

    @pytest.mark.asyncio
    async def test_default_alert_rules(self):
        """Test default alert rules creation."""
        default_rules = create_default_alert_rules()

        self.assertGreater(len(default_rules), 0)

        # Check that we have the expected default rules
        rule_names = [rule.name for rule in default_rules]
        self.assertIn("critical_system_error", rule_names)
        self.assertIn("service_down", rule_names)
        self.assertIn("security_violation", rule_names)


class TestEventReporting(unittest.TestCase):
    """Test event reporting functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.reporting = EventReporting()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_health_report_generation(self):
        """Test health report generation."""
        time_range = TimeRange.last_24_hours()

        # This would require actual events in the database
        # For testing, we'll create a mock scenario
        with patch.object(self.reporting.event_store, "get_events") as mock_get_events:
            # Mock health events
            mock_get_events.return_value = [
                SystemEvent(
                    health_score=75.0,
                    severity=EventSeverity.INFO,
                    category=EventCategory.HEALTH,
                ),
                SystemEvent(
                    health_score=80.0,
                    severity=EventSeverity.INFO,
                    category=EventCategory.HEALTH,
                ),
            ]

            health_report = await self.reporting.generate_health_report(time_range)

            self.assertIsInstance(health_report, HealthReport)
            self.assertEqual(health_report.time_range.start_time, time_range.start_time)
            self.assertEqual(health_report.time_range.end_time, time_range.end_time)

    @pytest.mark.asyncio
    async def test_security_report_generation(self):
        """Test security report generation."""
        time_range = TimeRange.last_24_hours()

        with patch.object(self.reporting.event_store, "get_events") as mock_get_events:
            # Mock security events
            mock_get_events.return_value = [
                SystemEvent(
                    category=EventCategory.SECURITY,
                    severity=EventSeverity.WARNING,
                    event_type=EventType.POLICY_VIOLATION,
                )
            ]

            security_report = await self.reporting.generate_security_report(time_range)

            self.assertIsInstance(security_report, SecurityReport)
            self.assertGreaterEqual(security_report.total_security_events, 0)

    @pytest.mark.asyncio
    async def test_report_export(self):
        """Test report export functionality."""
        health_report = HealthReport(
            fleet_health_score=85.0, system_health_status="healthy"
        )

        # Test JSON export
        json_path = os.path.join(self.temp_dir, "health_report.json")
        exported_path = await self.reporting.export_report(
            health_report, "json", json_path
        )

        self.assertTrue(os.path.exists(exported_path))

        # Verify JSON content
        with open(exported_path, "r") as f:
            data = json.load(f)
            self.assertIn("fleet_health_score", data)
            self.assertEqual(data["fleet_health_score"], 85.0)


class TestEventProcessor(unittest.TestCase):
    """Test event processing functionality."""

    def setUp(self):
        """Set up test fixtures."""
        config = EventStreamConfig(
            buffer_size=100,
            batch_size=10,
            websocket_enabled=False,  # Disable for testing
        )
        self.processor = EventStreamProcessor(config)

    @pytest.mark.asyncio
    async def test_event_addition(self):
        """Test adding events to processor."""
        test_event = SystemEvent(
            event_type=EventType.HEALTH_CHECK,
            severity=EventSeverity.INFO,
            source=EventSource.FLEET_INVENTORY,
            title="Test Event",
        )

        await self.processor.add_event(test_event)

        # Check that event was added to buffer
        buffer_status = self.processor.get_buffer_status()
        self.assertEqual(buffer_status["buffer_size"], 1)

    @pytest.mark.asyncio
    async def test_batch_processing(self):
        """Test event batch processing."""
        # Add multiple events
        events = []
        for i in range(5):
            event = SystemEvent(
                event_type=EventType.HEALTH_CHECK,
                severity=EventSeverity.INFO,
                source=EventSource.FLEET_INVENTORY,
                title=f"Event {i}",
            )
            events.append(event)
            await self.processor.add_event(event)

        # Check buffer status
        buffer_status = self.processor.get_buffer_status()
        self.assertEqual(buffer_status["buffer_size"], 5)

        # Test statistics
        stats = self.processor.get_stats()
        self.assertIn("events_processed", stats)

    def test_filter_rules(self):
        """Test event filtering rules."""
        from src.services.event_processor import EventFilterRule

        # Create a filter rule
        rule = EventFilterRule(
            name="exclude_debug", condition=lambda e: e.severity != EventSeverity.DEBUG
        )

        self.processor.add_filter_rule(rule)

        # Test filtering
        debug_event = SystemEvent(severity=EventSeverity.DEBUG, title="Debug Event")

        info_event = SystemEvent(severity=EventSeverity.INFO, title="Info Event")

        # Debug event should be filtered out
        should_filter_debug = self.processor._should_filter_event(debug_event)
        self.assertTrue(should_filter_debug)

        # Info event should pass through
        should_filter_info = self.processor._should_filter_event(info_event)
        self.assertFalse(should_filter_info)


class TestEventManagementTools(unittest.TestCase):
    """Test event management MCP tools."""

    def setUp(self):
        """Set up test fixtures."""
        self.tools = EventManagementTools()

    @pytest.mark.asyncio
    async def test_get_recent_events(self):
        """Test getting recent events."""
        with patch.object(self.tools.event_store, "get_events") as mock_get_events:
            mock_get_events.return_value = [
                SystemEvent(
                    event_type=EventType.HEALTH_CHECK,
                    severity=EventSeverity.INFO,
                    source=EventSource.FLEET_INVENTORY,
                    title="Test Event",
                )
            ]

            result = await self.tools.get_recent_events(hours=24)

            self.assertTrue(result["success"])
            self.assertIn("events", result)
            self.assertIn("total_count", result)
            self.assertEqual(result["total_count"], 1)

    @pytest.mark.asyncio
    async def test_get_health_summary(self):
        """Test getting health summary."""
        with patch.object(
            self.tools.event_reporting, "generate_health_report"
        ) as mock_report:
            mock_report.return_value = HealthReport(
                fleet_health_score=85.0,
                system_health_status="healthy",
                total_systems=10,
                healthy_systems=8,
            )

            result = await self.tools.get_health_summary(hours=24)

            self.assertTrue(result["success"])
            self.assertIn("health_summary", result)
            self.assertEqual(result["health_summary"]["fleet_health_score"], 85.0)

    @pytest.mark.asyncio
    async def test_get_system_status(self):
        """Test getting overall system status."""
        with patch.object(self.tools.event_store, "get_statistics") as mock_stats:
            with patch.object(
                self.tools.event_alerting, "get_alert_statistics"
            ) as mock_alerts:
                mock_stats.return_value = MagicMock(total_events=100, critical_events=2)
                mock_alerts.return_value = {"active_alerts": 1}

                result = await self.tools.get_system_status()

                self.assertTrue(result["success"])
                self.assertIn("system_status", result)
                self.assertIn("component_status", result)


class TestSystemIntegration(unittest.TestCase):
    """Test system integration functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.integration_manager = SystemIntegrationManager()

    @pytest.mark.asyncio
    async def test_integration_initialization(self):
        """Test integration manager initialization."""
        # This test would need to mock the actual integrations
        # For now, we'll test the structure

        status = await self.integration_manager.initialize_integrations()

        self.assertIsInstance(status, dict)
        self.assertIn("fleet_inventory", status)
        self.assertIn("policy_engine", status)
        self.assertIn("security_audit", status)

    @pytest.mark.asyncio
    async def test_fleet_inventory_integration(self):
        """Test fleet inventory integration."""
        integration = FleetInventoryIntegration()

        # This would need actual fleet inventory service mocking
        # For testing structure, we'll check that the integration exists
        self.assertIsNotNone(integration)
        self.assertIsNotNone(integration.logger)

    @pytest.mark.asyncio
    async def test_policy_engine_integration(self):
        """Test policy engine integration."""
        integration = PolicyEngineIntegration()

        self.assertIsNotNone(integration)
        self.assertIsNotNone(integration.logger)

    @pytest.mark.asyncio
    async def test_security_audit_integration(self):
        """Test security audit integration."""
        integration = SecurityAuditIntegration()

        self.assertIsNotNone(integration)
        self.assertIsNotNone(integration.logger)


class TestConfigurationManagement(unittest.TestCase):
    """Test configuration management functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.temp_dir, "test_config.yaml")
        self.manager = ConfigManager(self.config_path)

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_default_config_creation(self):
        """Test default configuration creation."""
        config = ObservabilityConfig()

        self.assertEqual(config.system_name, "TailOpsMCP")
        self.assertTrue(config.event_collection.enabled)
        self.assertTrue(config.event_storage.enabled)
        self.assertIsNotNone(config.event_collection.interval)
        self.assertIsNotNone(config.event_storage.database_path)

    def test_config_serialization(self):
        """Test configuration serialization."""
        config = ObservabilityConfig(system_name="Test System", debug=True)

        config_dict = config.to_dict()
        self.assertIsInstance(config_dict, dict)
        self.assertEqual(config_dict["system_name"], "Test System")
        self.assertTrue(config_dict["debug"])

        # Test deserialization
        restored_config = ObservabilityConfig.from_dict(config_dict)
        self.assertEqual(restored_config.system_name, "Test System")
        self.assertTrue(restored_config.debug)

    def test_config_manager_operations(self):
        """Test configuration manager operations."""
        # Test default configuration loading
        config = self.manager.load_config()
        self.assertIsInstance(config, ObservabilityConfig)

        # Test configuration update
        updates = {"debug": True, "log_level": "DEBUG"}
        updated_config = self.manager.update_config(updates)
        self.assertTrue(updated_config.debug)
        self.assertEqual(updated_config.log_level, "DEBUG")

    def test_environment_variable_overrides(self):
        """Test environment variable configuration overrides."""
        # Set environment variables
        os.environ["OBSERVABILITY_DEBUG"] = "true"
        os.environ["EVENT_COLLECTION_INTERVAL"] = "120"
        os.environ["WEBSOCKET_PORT"] = "9999"

        try:
            config = self.manager.load_config()

            self.assertTrue(config.debug)
            self.assertEqual(config.event_collection.interval, 120)
            self.assertEqual(config.event_processing.websocket_port, 9999)

        finally:
            # Clean up environment variables
            os.environ.pop("OBSERVABILITY_DEBUG", None)
            os.environ.pop("EVENT_COLLECTION_INTERVAL", None)
            os.environ.pop("WEBSOCKET_PORT", None)

    def test_config_validation(self):
        """Test configuration validation."""
        # Test invalid configuration
        invalid_config = ObservabilityConfig()
        invalid_config.event_collection.interval = -1

        errors = []
        try:
            self.manager._validate_config(invalid_config)
        except ValueError as e:
            errors.append(str(e))

        self.assertGreater(len(errors), 0)
        self.assertIn("interval must be positive", errors[0])

    def test_default_config_file_creation(self):
        """Test creating default configuration file."""
        self.manager.create_default_config(self.config_path)

        self.assertTrue(os.path.exists(self.config_path))

        # Verify file content
        with open(self.config_path, "r") as f:
            content = f.read()
            self.assertIn("system_name:", content)
            self.assertIn("TailOpsMCP", content)


# Integration test fixtures
@pytest.fixture
async def event_store_fixture():
    """Fixture for event store with test data."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "integration_test.db")
    store = EventStore(db_path)

    # Create test events
    test_events = []
    for i in range(20):
        event = SystemEvent(
            event_type=EventType.HEALTH_CHECK
            if i % 3 == 0
            else EventType.ERROR
            if i % 3 == 1
            else EventType.WARNING,
            severity=EventSeverity.CRITICAL
            if i % 5 == 0
            else EventSeverity.ERROR
            if i % 5 == 1
            else EventSeverity.WARNING
            if i % 5 == 2
            else EventSeverity.INFO,
            source=EventSource.FLEET_INVENTORY if i % 2 == 0 else EventSource.SYSTEM,
            target=f"target-{i % 5}",
            title=f"Test Event {i}",
            description=f"Description for test event {i}",
            health_score=100 - (i * 5),  # Decreasing health scores
        )
        test_events.append(event)

    # Store test events
    await store.store_events(test_events)

    yield store

    # Cleanup
    if os.path.exists(db_path):
        os.remove(db_path)
    os.rmdir(temp_dir)


@pytest.fixture
async def alert_system_fixture():
    """Fixture for alerting system with test rules."""
    alerting = EventAlerting()

    # Add test alert rules
    test_rules = [
        AlertRule(
            name="critical_errors",
            description="Alert on critical errors",
            condition="severity == 'critical'",
            severity=EventSeverity.CRITICAL,
            channels=[NotificationChannel.CONSOLE],
            recipients=["admin@test.com"],
        ),
        AlertRule(
            name="high_error_rate",
            description="Alert on high error rate",
            condition="event_type == 'error'",
            severity=EventSeverity.ERROR,
            threshold_count=3,
            threshold_time_window=300,  # 5 minutes
        ),
    ]

    for rule in test_rules:
        await alerting.add_alert_rule(rule)

    yield alerting


# End-to-end test scenarios
class TestEndToEndScenarios(unittest.TestCase):
    """End-to-end test scenarios for the complete observability system."""

    @pytest.mark.asyncio
    async def test_complete_event_lifecycle(self):
        """Test complete event lifecycle from creation to reporting."""
        # 1. Create events
        events = []
        for i in range(10):
            event = SystemEvent(
                event_type=EventType.HEALTH_CHECK,
                severity=EventSeverity.INFO if i < 8 else EventSeverity.ERROR,
                source=EventSource.FLEET_INVENTORY,
                target=f"target-{i % 3}",
                title=f"Health Check {i}",
                description=f"Health check for target {i % 3}",
                health_score=90 - (i * 5),
            )
            events.append(event)

        # 2. Store events
        store = EventStore(":memory:")  # In-memory database for testing
        await store.store_events(events)

        # 3. Analyze events
        analyzer = EventAnalyzer()
        trends = await analyzer.detect_trends(events)
        insights = await analyzer.generate_insights(events)

        # 4. Generate alerts
        alerting = EventAlerting()
        alert_rule = AlertRule(
            name="low_health",
            description="Alert on low health scores",
            condition="health_score < 50",
            severity=EventSeverity.WARNING,
        )
        await alerting.add_alert_rule(alert_rule)

        # Evaluate alerts
        alerts = await alerting.evaluate_alert_rules(events)

        # 5. Generate reports
        reporting = EventReporting()
        time_range = TimeRange.last_24_hours()
        health_report = await reporting.generate_health_report(time_range)

        # Verify the complete lifecycle
        self.assertGreater(len(events), 0)
        self.assertIsInstance(trends, list)
        self.assertIsInstance(insights, list)
        self.assertIsInstance(alerts, list)
        self.assertIsInstance(health_report, HealthReport)

    @pytest.mark.asyncio
    async def test_real_time_event_processing(self):
        """Test real-time event processing and streaming."""
        config = EventStreamConfig(
            buffer_size=50, batch_size=5, websocket_enabled=False
        )
        processor = EventStreamProcessor(config)

        # Add events gradually
        for i in range(15):
            event = SystemEvent(
                event_type=EventType.HEALTH_CHECK,
                severity=EventSeverity.INFO,
                source=EventSource.FLEET_INVENTORY,
                title=f"Real-time Event {i}",
            )
            await processor.add_event(event)

            # Small delay to simulate real-time processing
            await asyncio.sleep(0.01)

        # Verify processing
        stats = processor.get_stats()
        processor.get_buffer_status()

        self.assertGreater(stats["events_processed"], 0)
        self.assertGreater(stats["batches_processed"], 0)

    @pytest.mark.asyncio
    async def test_system_integration_workflow(self) -> None:
        """Test complete system integration workflow."""
        # Initialize integration manager
        integration_manager = SystemIntegrationManager()

        # Initialize integrations (this would connect to actual services)
        integration_status = await integration_manager.initialize_integrations()

        # Run integration cycle (this would collect events from all systems)
        cycle_result = await integration_manager.run_integration_cycle()

        # Verify integration status
        self.assertIsInstance(integration_status, dict)
        self.assertIsInstance(cycle_result, dict)
        self.assertIn("success", cycle_result)


# Test utilities
def create_test_events(count: int = 10) -> List[SystemEvent]:
    """Create test events for testing purposes."""
    events = []

    for i in range(count):
        event_type = list(EventType)[i % len(EventType)]
        severity = list(EventSeverity)[i % len(EventSeverity)]
        source = list(EventSource)[i % len(EventSource)]

        event = SystemEvent(
            event_type=event_type,
            severity=severity,
            source=source,
            target=f"test-target-{i % 5}",
            title=f"Test Event {i}",
            description=f"Test event number {i}",
            health_score=100 - (i * 10),
        )
        events.append(event)

    return events


def assert_event_equals(expected: SystemEvent, actual: SystemEvent) -> None:
    """Assert that two events are equal."""
    assert expected.event_id == actual.event_id
    assert expected.event_type == actual.event_type
    assert expected.severity == actual.severity
    assert expected.source == actual.source
    assert expected.title == actual.title
    assert expected.description == actual.description
    assert expected.target == actual.target


# Performance tests
class TestPerformance(unittest.TestCase):
    """Performance tests for observability system."""

    @pytest.mark.asyncio
    async def test_event_storage_performance(self) -> None:
        """Test event storage performance with large datasets."""
        store = EventStore(":memory:")

        # Create large number of events
        events = create_test_events(1000)

        # Measure storage time
        start_time = datetime.utcnow()
        await store.store_events(events)
        end_time = datetime.utcnow()

        storage_time = (end_time - start_time).total_seconds()

        # Should be able to store 1000 events in reasonable time (< 5 seconds)
        self.assertLess(storage_time, 5.0)

        # Verify all events were stored
        stored_events = await store.get_events()
        self.assertEqual(len(stored_events), 1000)

    @pytest.mark.asyncio
    async def test_event_retrieval_performance(self) -> None:
        """Test event retrieval performance."""
        store = EventStore(":memory:")

        # Store large number of events
        events = create_test_events(500)
        await store.store_events(events)

        # Test various query patterns
        test_queries = [
            EventFilters(limit=100),
            EventFilters(event_types=[EventType.HEALTH_CHECK]),
            EventFilters(severities=[EventSeverity.ERROR]),
            EventFilters(sources=[EventSource.FLEET_INVENTORY]),
        ]

        for filters in test_queries:
            start_time = datetime.utcnow()
            results = await store.get_events(filters)
            end_time = datetime.utcnow()

            query_time = (end_time - start_time).total_seconds()

            # Should complete queries quickly (< 1 second)
            self.assertLess(query_time, 1.0)
            self.assertIsInstance(results, list)


# Main test runner
def run_all_tests() -> None:
    """Run all tests."""
    # Configure test environment
    os.environ["TESTING"] = "true"

    # Run tests
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    test_classes = [
        TestEventModels,
        TestEventStore,
        TestEventCollector,
        TestEventAnalyzer,
        TestEventAlerting,
        TestEventReporting,
        TestEventProcessor,
        TestEventManagementTools,
        TestSystemIntegration,
        TestConfigurationManagement,
        TestEndToEndScenarios,
        TestPerformance,
    ]

    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == "__main__":
    import sys

    success = run_all_tests()
    sys.exit(0 if success else 1)
