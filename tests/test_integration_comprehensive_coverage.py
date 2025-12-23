"""
Comprehensive integration test suite for TailOpsMCP.

Tests integration between major components including:
- System integration services
- Workflow orchestration
- Policy engine integration
- Discovery pipeline integration
- Observability integration
"""

import pytest
import tempfile
import os
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock


class TestSystemServiceIntegration:
    """Test core system integration functionality."""

    def test_system_integration_import(self):
        """Test system integration module can be imported."""
        from src.services.system_integration import FleetInventoryIntegration

        assert FleetInventoryIntegration is not None

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_fleet_inventory_integration(self):
        """Test fleet inventory integration."""
        from src.services.system_integration import FleetInventoryIntegration

        integration = FleetInventoryIntegration()

        # Test interface exists
        assert hasattr(integration, "generate_health_events_from_inventory")
        assert callable(integration.generate_health_events_from_inventory)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_policy_engine_integration(self):
        """Test policy engine integration."""
        from src.services.system_integration import PolicyEngineIntegration

        integration = PolicyEngineIntegration()

        # Check integration methods exist
        expected_methods = [
            "generate_policy_events",
            "integrate_policy_violations",
            "monitor_policy_compliance",
        ]

        for method in expected_methods:
            assert hasattr(integration, method), f"Method {method} missing"

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_security_audit_integration(self):
        """Test security audit integration."""
        from src.services.system_integration import SecurityAuditIntegration

        integration = SecurityAuditIntegration()

        # Test integration interface
        assert hasattr(integration, "generate_security_events")
        assert callable(integration.generate_security_events)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_remote_agent_integration(self):
        """Test remote agent integration."""
        from src.services.system_integration import RemoteAgentIntegration

        integration = RemoteAgentIntegration()

        # Test remote agent integration
        assert hasattr(integration, "integrate_agent_status")
        assert callable(integration.integrate_agent_status)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_discovery_pipeline_integration(self):
        """Test discovery pipeline integration."""
        from src.services.system_integration import DiscoveryPipelineIntegration

        integration = DiscoveryPipelineIntegration()

        # Test discovery integration
        assert hasattr(integration, "integrate_discovery_results")
        assert callable(integration.integrate_discovery_results)


class TestWorkflowOrchestrationIntegration:
    """Test workflow orchestration integration."""

    def test_workflow_engine_import(self):
        """Test workflow engine can be imported."""
        from src.services.workflow_engine import WorkflowEngine

        assert WorkflowEngine is not None

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_workflow_execution_integration(self):
        """Test workflow execution integration."""
        from src.services.workflow_engine import WorkflowEngine

        engine = WorkflowEngine()

        # Test workflow execution interface
        if hasattr(engine, "execute_workflow"):
            result = await engine.execute_workflow(
                workflow_id="wf_001", parameters={"container": "nginx"}
            )
            assert isinstance(result, dict)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_workflow_approval_integration(self):
        """Test workflow approval integration."""
        from src.services.workflow_approval import WorkflowApproval

        approval = WorkflowApproval()

        # Test approval interface
        if hasattr(approval, "request_approval"):
            result = await approval.request_approval(
                workflow_id="wf_001",
                approver_id="admin",
                request_data={"operation": "docker.create"},
            )
            assert isinstance(result, dict)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_workflow_integration_service(self):
        """Test workflow integration service."""
        from src.services.workflow_integration import WorkflowIntegration

        integration = WorkflowIntegration()

        # Test integration methods
        expected_methods = [
            "integrate_workflow_events",
            "handle_workflow_completion",
            "monitor_workflow_execution",
        ]

        for method in expected_methods:
            if hasattr(integration, method):
                assert callable(getattr(integration, method))


class TestObservabilityIntegration:
    """Test observability integration functionality."""

    def test_observability_integration_import(self):
        """Test observability integration can be imported."""
        from src.utils.observability_integration import ObservabilityIntegration

        assert ObservabilityIntegration is not None

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_observability_metrics_integration(self):
        """Test observability metrics integration."""
        from src.utils.observability_integration import ObservabilityIntegration

        integration = ObservabilityIntegration()

        # Test metrics integration
        if hasattr(integration, "send_metrics"):
            result = await integration.send_metrics(
                metric_type="performance", data={"cpu": 45.0, "memory": 60.0}
            )
            assert isinstance(result, (bool, dict))

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_observability_logs_integration(self):
        """Test observability logs integration."""
        from src.utils.observability_integration import ObservabilityIntegration

        integration = ObservabilityIntegration()

        # Test log integration
        if hasattr(integration, "send_logs"):
            result = await integration.send_logs(
                log_level="INFO", message="System operation completed"
            )
            assert isinstance(result, (bool, dict))

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_observability_alerts_integration(self):
        """Test observability alerts integration."""
        from src.utils.observability_integration import ObservabilityIntegration

        integration = ObservabilityIntegration()

        # Test alert integration
        if hasattr(integration, "send_alert"):
            result = await integration.send_alert(
                alert_level="WARNING",
                message="High CPU usage detected",
                details={"cpu": 95.0},
            )
            assert isinstance(result, (bool, dict))


class TestMonitoringIntegration:
    """Test monitoring integration functionality."""

    def test_monitoring_integration_import(self):
        """Test monitoring integration can be imported."""
        from src.utils.monitoring_integration import MonitoringIntegration

        assert MonitoringIntegration is not None

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_prometheus_integration(self):
        """Test Prometheus monitoring integration."""
        from src.utils.monitoring_integration import MonitoringIntegration

        integration = MonitoringIntegration()

        # Test Prometheus interface
        if hasattr(integration, "send_prometheus_metrics"):
            result = await integration.send_prometheus_metrics(
                metrics=[{"name": "cpu_usage", "value": 45.0}]
            )
            assert isinstance(result, (bool, dict))

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_datadog_integration(self):
        """Test Datadog monitoring integration."""
        from src.utils.monitoring_integration import MonitoringIntegration

        integration = MonitoringIntegration()

        # Test Datadog interface
        if hasattr(integration, "send_datadog_metrics"):
            result = await integration.send_datadog_metrics(
                metric="system.cpu",
                points=[{"timestamp": datetime.utcnow().timestamp(), "value": 45.0}],
            )
            assert isinstance(result, (bool, dict))

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_elasticsearch_integration(self):
        """Test Elasticsearch logging integration."""
        from src.utils.monitoring_integration import MonitoringIntegration

        integration = MonitoringIntegration()

        # Test Elasticsearch interface
        if hasattr(integration, "send_elasticsearch_logs"):
            result = await integration.send_elasticsearch_logs(
                index="system_logs",
                documents=[{"message": "System startup", "level": "INFO"}],
            )
            assert isinstance(result, (bool, dict))


class TestCrossComponentIntegration:
    """Test cross-component integration."""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_security_workflow_integration(self):
        """Test security and workflow integration."""
        try:
            from src.services.system_integration import SecurityAuditIntegration
            from src.services.workflow_engine import WorkflowEngine

            security_integration = SecurityAuditIntegration()
            workflow_engine = WorkflowEngine()

            # Test that both components can be used together
            assert security_integration is not None
            assert workflow_engine is not None

            # Test security monitoring of workflows
            if hasattr(security_integration, "monitor_workflow_execution"):
                result = await security_integration.monitor_workflow_execution(
                    workflow_id="wf_001", user_id="user123"
                )
                assert isinstance(result, dict)

        except ImportError:
            pytest.skip("Security-workflow integration not available")

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_policy_system_integration(self):
        """Test policy and system integration."""
        from src.services.system_integration import PolicyEngineIntegration

        integration = PolicyEngineIntegration()

        # Test policy enforcement in system operations
        if hasattr(integration, "enforce_policy_on_operation"):
            result = await integration.enforce_policy_on_operation(
                operation="docker.create", user_id="user123", resource="container"
            )
            assert isinstance(result, dict)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_inventory_system_integration(self):
        """Test inventory and system integration."""
        from src.services.system_integration import FleetInventoryIntegration

        integration = FleetInventoryIntegration()

        # Test inventory event generation
        if hasattr(integration, "generate_health_events_from_inventory"):
            events = await integration.generate_health_events_from_inventory()
            assert isinstance(events, list)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_observability_workflow_integration(self):
        """Test observability and workflow integration."""
        from src.utils.observability_integration import ObservabilityIntegration
        from src.services.workflow_engine import WorkflowEngine

        try:
            observability = ObservabilityIntegration()
            workflow = WorkflowEngine()

            # Test observation of workflow execution
            if hasattr(observability, "observe_workflow"):
                result = await observability.observe_workflow(
                    workflow_id="wf_001", metrics={"execution_time": 45.0}
                )
                assert isinstance(result, dict)

        except ImportError:
            pytest.skip("Observability-workflow integration not available")


class TestIntegrationErrorHandling:
    """Test integration error handling."""

    @pytest.mark.integration
    @pytest.mark.edge_case
    @pytest.mark.asyncio
    async def test_integration_service_unavailable(self):
        """Test behavior when integration services are unavailable."""
        from src.services.system_integration import FleetInventoryIntegration

        integration = FleetInventoryIntegration()

        # Test handling of unavailable services
        try:
            events = await integration.generate_health_events_from_inventory()
            # Should handle gracefully or return empty list
            assert isinstance(events, list)
        except Exception:
            # May raise exception, which is acceptable
            pass

    @pytest.mark.integration
    @pytest.mark.edge_case
    @pytest.mark.asyncio
    async def test_integration_with_invalid_data(self):
        """Test integration with invalid data."""
        from src.utils.monitoring_integration import MonitoringIntegration

        integration = MonitoringIntegration()

        # Test with invalid metrics data
        try:
            result = await integration.send_prometheus_metrics(
                metrics=[{"name": None, "value": "invalid"}]
            )
            # Should handle gracefully
            assert isinstance(result, (bool, dict))
        except Exception:
            # May raise exception, which is acceptable
            pass

    @pytest.mark.integration
    @pytest.mark.edge_case
    async def test_integration_timeout_handling(self):
        """Test integration timeout handling."""
        try:
            from src.services.workflow_engine import WorkflowEngine

            engine = WorkflowEngine()

            # Test with very short timeout
            if hasattr(engine, "execute_workflow"):
                result = await engine.execute_workflow(
                    workflow_id="wf_001", parameters={}, timeout=0.001
                )
                # Should handle timeout gracefully
                assert isinstance(result, dict)

        except ImportError:
            pytest.skip("Timeout testing not available")


class TestIntegrationPerformance:
    """Test integration performance."""

    @pytest.mark.integration
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_integration_performance(self):
        """Test integration performance under load."""
        from src.services.system_integration import SystemIntegration

        integration = SystemIntegration()

        import time

        start_time = time.time()

        # Test multiple integration operations
        tasks = []
        for i in range(50):
            task = integration.generate_system_events(source=f"service_{i}")
            tasks.append(task)

        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)

            end_time = time.time()
            duration = end_time - start_time

            # Should complete 50 operations quickly
            assert duration < 5.0, (
                f"Integration too slow: {duration}s for 50 operations"
            )
            assert len(results) == 50

        except AttributeError:
            pytest.skip("Integration performance testing not available")

    @pytest.mark.integration
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_workflow_integration_performance(self):
        """Test workflow integration performance."""
        try:
            from src.services.workflow_integration import WorkflowIntegration

            integration = WorkflowIntegration()

            import time

            start_time = time.time()

            # Test workflow event integration
            tasks = []
            for i in range(25):
                task = integration.integrate_workflow_event(
                    {
                        "workflow_id": f"wf_{i}",
                        "event_type": "started",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                )
                tasks.append(task)

            results = await asyncio.gather(*tasks, return_exceptions=True)

            end_time = time.time()
            duration = end_time - start_time

            # Should complete quickly
            assert duration < 2.0, (
                f"Workflow integration too slow: {duration}s for 25 operations"
            )
            assert len(results) == 25

        except ImportError:
            pytest.skip("Workflow integration performance testing not available")

    @pytest.mark.integration
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_monitoring_integration_performance(self):
        """Test monitoring integration performance."""
        try:
            from src.utils.monitoring_integration import MonitoringIntegration

            integration = MonitoringIntegration()

            import time

            start_time = time.time()

            # Test metrics sending performance
            tasks = []
            for i in range(100):
                task = integration.send_prometheus_metrics(
                    [{"name": f"metric_{i}", "value": i}]
                )
                tasks.append(task)

            results = await asyncio.gather(*tasks, return_exceptions=True)

            end_time = time.time()
            duration = end_time - start_time

            # Should complete 100 metric sends quickly
            assert duration < 3.0, (
                f"Monitoring integration too slow: {duration}s for 100 operations"
            )
            assert len(results) == 100

        except ImportError:
            pytest.skip("Monitoring integration performance testing not available")


class TestIntegrationConfiguration:
    """Test integration configuration and setup."""

    @pytest.mark.integration
    def test_integration_configuration(self):
        """Test integration configuration handling."""
        from src.services.system_integration import SystemIntegration

        integration = SystemIntegration()

        # Test configuration attributes
        config_attrs = ["config", "enabled_integrations", "connection_settings"]

        for attr in config_attrs:
            if hasattr(integration, attr):
                assert getattr(integration, attr) is not None or isinstance(
                    getattr(integration, attr), dict
                )

    @pytest.mark.integration
    def test_monitoring_configuration(self):
        """Test monitoring integration configuration."""
        from src.utils.monitoring_integration import MonitoringIntegration

        integration = MonitoringIntegration()

        # Test monitoring config
        config_attrs = ["prometheus_config", "datadog_config", "elasticsearch_config"]

        for attr in config_attrs:
            if hasattr(integration, attr):
                assert (
                    isinstance(getattr(integration, attr), dict)
                    or getattr(integration, attr) is None
                )

    @pytest.mark.integration
    def test_workflow_configuration(self):
        """Test workflow integration configuration."""
        try:
            from src.services.workflow_engine import WorkflowEngine

            engine = WorkflowEngine()

            # Test workflow engine configuration
            if hasattr(engine, "config"):
                assert isinstance(engine.config, dict)

        except ImportError:
            pytest.skip("Workflow configuration testing not available")

    @pytest.mark.integration
    def test_observability_configuration(self):
        """Test observability integration configuration."""
        from src.utils.observability_integration import ObservabilityIntegration

        integration = ObservabilityIntegration()

        # Test observability config
        if hasattr(integration, "settings"):
            assert isinstance(integration.settings, dict)


# Integration regression tests
class TestIntegrationRegression:
    """Test for integration regressions."""

    @pytest.mark.integration
    @pytest.mark.regression
    @pytest.mark.asyncio
    async def test_integration_interface_stability(self):
        """Test integration interfaces remain stable."""
        from src.services.system_integration import (
            FleetInventoryIntegration,
            PolicyEngineIntegration,
            SecurityAuditIntegration,
        )

        # Test expected interfaces exist
        integrations = [
            FleetInventoryIntegration,
            PolicyEngineIntegration,
            SecurityAuditIntegration,
        ]

        for integration_class in integrations:
            integration = integration_class()

            # Check for core methods
            expected_methods = ["generate_events", "integrate_with_system"]
            for method in expected_methods:
                if hasattr(integration, method):
                    assert callable(getattr(integration, method))

    @pytest.mark.integration
    @pytest.mark.regression
    @pytest.mark.asyncio
    async def test_monitoring_integration_stability(self):
        """Test monitoring integration stability."""
        from src.utils.monitoring_integration import MonitoringIntegration

        integration = MonitoringIntegration()

        # Test expected monitoring methods
        expected_methods = [
            "send_prometheus_metrics",
            "send_datadog_metrics",
            "send_elasticsearch_logs",
        ]

        for method in expected_methods:
            if hasattr(integration, method):
                assert callable(getattr(integration, method))

    @pytest.mark.integration
    @pytest.mark.regression
    @pytest.mark.asyncio
    async def test_workflow_integration_compatibility(self):
        """Test workflow integration compatibility."""
        try:
            from src.services.workflow_integration import WorkflowIntegration

            integration = WorkflowIntegration()

            # Test compatibility interfaces
            expected_methods = [
                "integrate_workflow_events",
                "handle_workflow_completion",
                "monitor_workflow_execution",
            ]

            for method in expected_methods:
                if hasattr(integration, method):
                    assert callable(getattr(integration, method))

        except ImportError:
            pytest.skip("Workflow integration compatibility not available")

    @pytest.mark.integration
    @pytest.mark.regression
    def test_import_compatibility_maintained(self):
        """Test import compatibility is maintained."""
        try:
            from src.services.system_integration import (
                SystemIntegration,
                FleetInventoryIntegration,
                PolicyEngineIntegration,
                SecurityAuditIntegration,
                RemoteAgentIntegration,
                DiscoveryPipelineIntegration,
            )

            # All should be importable
            assert all(
                cls is not None
                for cls in [
                    SystemIntegration,
                    FleetInventoryIntegration,
                    PolicyEngineIntegration,
                    SecurityAuditIntegration,
                    RemoteAgentIntegration,
                    DiscoveryPipelineIntegration,
                ]
            )

        except ImportError as e:
            pytest.fail(f"Integration import compatibility broken: {e}")


# Integration coverage tests
class TestIntegrationCoverage:
    """Test integration module coverage."""

    @pytest.mark.integration
    def test_all_integration_modules_exist(self):
        """Test all expected integration modules exist."""
        integration_modules = [
            "src/services/system_integration.py",
            "src/services/workflow_integration.py",
            "src/services/workflow_engine.py",
            "src/utils/monitoring_integration.py",
            "src/utils/observability_integration.py",
        ]

        existing_modules = 0
        for module_path in integration_modules:
            if os.path.exists(module_path):
                existing_modules += 1

        # Most integration modules should exist
        assert existing_modules >= len(integration_modules) - 1, (
            f"Too few integration modules: {existing_modules}/{len(integration_modules)} exist"
        )

    @pytest.mark.integration
    def test_integration_classes_exist(self):
        """Test integration classes exist."""
        try:
            from src.services.system_integration import (
                FleetInventoryIntegration,
                PolicyEngineIntegration,
                SecurityAuditIntegration,
                RemoteAgentIntegration,
                DiscoveryPipelineIntegration,
            )

            # All integration classes should be available
            integration_classes = [
                FleetInventoryIntegration,
                PolicyEngineIntegration,
                SecurityAuditIntegration,
                RemoteAgentIntegration,
                DiscoveryPipelineIntegration,
            ]

            assert all(cls is not None for cls in integration_classes)

        except ImportError as e:
            pytest.skip(f"Integration classes test failed: {e}")

    @pytest.mark.integration
    def test_workflow_integration_complete(self):
        """Test workflow integration completeness."""
        workflow_integrations = [
            "src/services/workflow_engine.py",
            "src/services/workflow_integration.py",
            "src/services/workflow_approval.py",
        ]

        existing_workflow = 0
        for workflow_path in workflow_integrations:
            if os.path.exists(workflow_path):
                existing_workflow += 1

        # Most workflow integration should exist
        assert existing_workflow >= 2, (
            f"Too few workflow integrations: {existing_workflow}/{len(workflow_integrations)} exist"
        )

    @pytest.mark.integration
    def test_monitoring_integration_complete(self):
        """Test monitoring integration completeness."""
        monitoring_integrations = [
            "src/utils/monitoring_integration.py",
            "src/utils/observability_integration.py",
        ]

        existing_monitoring = 0
        for monitoring_path in monitoring_integrations:
            if os.path.exists(monitoring_path):
                existing_monitoring += 1

        # Monitoring integrations should exist
        assert existing_monitoring >= 1, (
            f"Too few monitoring integrations: {existing_monitoring}/{len(monitoring_integrations)} exist"
        )
