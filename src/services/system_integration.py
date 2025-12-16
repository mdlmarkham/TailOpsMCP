"""
System integration module for TailOpsMCP observability system.

This module provides integration between the new observability system and existing
TailOpsMCP components including fleet inventory, policy engine, security audit,
remote agents, and discovery pipelines.
"""

from datetime import datetime
from typing import Any, Dict, List

from src.models.event_models import (
    SystemEvent,
    EventType,
    EventSeverity,
    EventSource,
    EventCategory,
    EventBuilder,
    ResourceUsage,
    create_health_event,
    create_security_event,
    create_operation_event,
)
from src.services.event_store import get_event_store
from src.services.event_processor import get_event_stream_processor
from src.utils.logging_config import get_logger


class FleetInventoryIntegration:
    """Integration with fleet inventory system."""

    def __init__(self):
        self.logger = get_logger("fleet_inventory_integration")
        self.event_store = get_event_store()

    async def generate_health_events_from_inventory(self) -> List[SystemEvent]:
        """Generate health events from fleet inventory."""
        events = []

        try:
            # Import and use the enhanced inventory tools
            from src.tools.enhanced_inventory_tools import EnhancedInventoryTools

            inventory_tools = EnhancedInventoryTools()

            # Get fleet status
            fleet_data = await inventory_tools.get_fleet_status()

            if fleet_data and "targets" in fleet_data:
                for target_name, target_data in fleet_data["targets"].items():
                    # Check target health
                    health_status = target_data.get("health_status", "unknown")
                    health_score = target_data.get("health_score")

                    # Create health event
                    event = create_health_event(
                        source=EventSource.FLEET_INVENTORY,
                        target=target_name,
                        status=health_status,
                        health_score=health_score,
                        details={
                            "connection_status": target_data.get("connection_status"),
                            "last_seen": target_data.get("last_seen"),
                            "capabilities": target_data.get("capabilities", []),
                            "metadata": target_data.get("metadata", {}),
                        },
                    )

                    events.append(event)

                    # Check for resource usage events
                    if "resources" in target_data:
                        resources = target_data["resources"]

                        # CPU threshold check
                        cpu_percent = resources.get("cpu_percent", 0)
                        if cpu_percent > 80:
                            cpu_event = EventBuilder()
                            cpu_event.event_type = EventType.RESOURCE_THRESHOLD
                            cpu_event.severity = EventSeverity.WARNING
                            cpu_event.source = EventSource.FLEET_INVENTORY
                            cpu_event.target = target_name
                            cpu_event.category = EventCategory.PERFORMANCE
                            cpu_event.title = f"High CPU usage on {target_name}"
                            cpu_event.description = f"CPU usage at {cpu_percent:.1f}%"
                            cpu_event.resource_usage = ResourceUsage(
                                cpu_percent=cpu_percent
                            )
                            cpu_event.details = {
                                "resource_type": "cpu",
                                "usage_percent": cpu_percent,
                                "threshold": 80.0,
                            }
                            cpu_event.add_tag("resource_threshold")
                            events.append(cpu_event.build())

                        # Memory threshold check
                        memory_percent = resources.get("memory_percent", 0)
                        if memory_percent > 80:
                            memory_event = EventBuilder()
                            memory_event.event_type = EventType.RESOURCE_THRESHOLD
                            memory_event.severity = EventSeverity.WARNING
                            memory_event.source = EventSource.FLEET_INVENTORY
                            memory_event.target = target_name
                            memory_event.category = EventCategory.PERFORMANCE
                            memory_event.title = f"High memory usage on {target_name}"
                            memory_event.description = (
                                f"Memory usage at {memory_percent:.1f}%"
                            )
                            memory_event.resource_usage = ResourceUsage(
                                memory_percent=memory_percent
                            )
                            memory_event.details = {
                                "resource_type": "memory",
                                "usage_percent": memory_percent,
                                "threshold": 80.0,
                            }
                            memory_event.add_tag("resource_threshold")
                            events.append(memory_event.build())

            # Store events
            if events:
                await self.event_store.store_events(events)
                self.logger.info(
                    f"Generated {len(events)} health events from fleet inventory"
                )

            return events

        except Exception as e:
            self.logger.error(f"Failed to generate health events from inventory: {e}")
            # Create error event
            error_event = EventBuilder.error(
                EventSource.FLEET_INVENTORY,
                "Health event generation failed",
                str(e),
                {"integration": "fleet_inventory"},
            )
            await self.event_store.store_event(error_event)
            return [error_event]

    async def generate_fleet_update_events(self) -> List[SystemEvent]:
        """Generate events for fleet updates and changes."""
        events = []

        try:
            # This would integrate with the fleet inventory change detection
            # For now, create a placeholder event
            event = EventBuilder()
            event.event_type = EventType.FLEET_UPDATED
            event.severity = EventSeverity.INFO
            event.source = EventSource.FLEET_INVENTORY
            event.category = EventCategory.FLEET_MANAGEMENT
            event.title = "Fleet inventory updated"
            event.description = (
                "Fleet inventory has been updated with new target information"
            )
            event.details = {
                "update_type": "inventory_sync",
                "timestamp": datetime.utcnow().isoformat(),
            }
            events.append(event.build())

            await self.event_store.store_events(events)
            return events

        except Exception as e:
            self.logger.error(f"Failed to generate fleet update events: {e}")
            return []


class PolicyEngineIntegration:
    """Integration with policy engine."""

    def __init__(self):
        self.logger = get_logger("policy_engine_integration")
        self.event_store = get_event_store()

    async def generate_policy_violation_events(self) -> List[SystemEvent]:
        """Generate events from policy violations."""
        events = []

        try:
            from src.tools.fleet_policy import FleetPolicyTools

            policy_tools = FleetPolicyTools()

            # Get recent policy violations
            violations = await policy_tools.get_recent_violations()

            for violation in violations:
                # Create security alert event
                event = create_security_event(
                    source=EventSource.POLICY_ENGINE,
                    event_type=EventType.POLICY_VIOLATION,
                    title=f"Policy violation: {violation.operation}",
                    description=violation.reason,
                    severity=EventSeverity.ERROR,
                    details={
                        "operation": violation.operation,
                        "policy_name": violation.policy_name,
                        "violation_type": violation.violation_type,
                        "target": violation.target,
                        "timestamp": datetime.utcnow().isoformat(),
                    },
                )

                event.target = violation.target
                event.add_tag("policy_violation")
                event.add_tag("security")

                events.append(event)

            # Store events
            if events:
                await self.event_store.store_events(events)
                self.logger.info(f"Generated {len(events)} policy violation events")

            return events

        except Exception as e:
            self.logger.error(f"Failed to generate policy violation events: {e}")
            error_event = EventBuilder.error(
                EventSource.POLICY_ENGINE,
                "Policy violation event generation failed",
                str(e),
                {"integration": "policy_engine"},
            )
            await self.event_store.store_event(error_event)
            return [error_event]

    async def generate_policy_audit_events(self) -> List[SystemEvent]:
        """Generate events from policy audit results."""
        events = []

        try:
            # Get audit results (placeholder implementation)
            audit_results = []  # This would come from actual audit system

            for result in audit_results:
                if not result.compliant:
                    # Create compliance violation event
                    event = EventBuilder()
                    event.event_type = EventType.POLICY_VIOLATION
                    event.severity = EventSeverity.WARNING
                    event.source = EventSource.POLICY_ENGINE
                    event.category = EventCategory.COMPLIANCE
                    event.title = f"Compliance violation: {result.policy_name}"
                    event.description = (
                        f"System is not compliant with policy: {result.reason}"
                    )
                    event.details = {
                        "policy_name": result.policy_name,
                        "compliance_status": result.compliant,
                        "violations": result.violations,
                        "audit_timestamp": result.audit_timestamp.isoformat(),
                    }
                    event.add_tag("compliance")
                    event.add_tag("audit")

                    events.append(event.build())

            if events:
                await self.event_store.store_events(events)

            return events

        except Exception as e:
            self.logger.error(f"Failed to generate policy audit events: {e}")
            return []


class SecurityAuditIntegration:
    """Integration with security audit system."""

    def __init__(self):
        self.logger = get_logger("security_audit_integration")
        self.event_store = get_event_store()

    async def generate_security_events(self) -> List[SystemEvent]:
        """Generate security events from audit logs."""
        events = []

        try:
            from src.utils.audit import AuditLogger, LogLevel

            audit_logger = AuditLogger()

            # Get recent security audit events
            audit_events = await audit_logger.get_recent_events(hours=24)

            for audit_event in audit_events:
                # Convert audit event to system event
                severity = EventSeverity.INFO
                if audit_event.level == LogLevel.ERROR:
                    severity = EventSeverity.ERROR
                elif audit_event.level == LogLevel.WARNING:
                    severity = EventSeverity.WARNING
                elif audit_event.level == LogLevel.CRITICAL:
                    severity = EventSeverity.CRITICAL

                event = EventBuilder()
                event.event_type = EventType.SECURITY_ALERT
                event.severity = severity
                event.source = EventSource.SECURITY_AUDIT
                event.category = EventCategory.SECURITY
                event.title = f"Security audit: {audit_event.operation}"
                event.description = audit_event.message
                event.metadata.correlation_id = audit_event.correlation_id
                event.details = {
                    "operation": audit_event.operation,
                    "level": audit_event.level.value,
                    "subject": audit_event.subject,
                    "success": audit_event.success,
                    "risk_level": audit_event.risk_level,
                    "scopes": audit_event.scopes,
                }

                if audit_event.risk_level and audit_event.risk_level.lower() in [
                    "high",
                    "critical",
                ]:
                    event.add_tag("high_risk")

                if not audit_event.success:
                    event.add_tag("failed_operation")

                events.append(event.build())

            if events:
                await self.event_store.store_events(events)
                self.logger.info(f"Generated {len(events)} security audit events")

            return events

        except Exception as e:
            self.logger.error(f"Failed to generate security events: {e}")
            error_event = EventBuilder.error(
                EventSource.SECURITY_AUDIT,
                "Security event generation failed",
                str(e),
                {"integration": "security_audit"},
            )
            await self.event_store.store_event(error_event)
            return [error_event]


class RemoteAgentIntegration:
    """Integration with remote agent system."""

    def __init__(self):
        self.logger = get_logger("remote_agent_integration")
        self.event_store = get_event_store()

    async def generate_service_status_events(self) -> List[SystemEvent]:
        """Generate service status events from remote agents."""
        events = []

        try:
            from src.tools.remote_agent_tools import RemoteAgentTools

            remote_tools = RemoteAgentTools()

            # Get all service statuses
            service_statuses = await remote_tools.get_all_service_statuses()

            for status in service_statuses:
                if status.state != "active":
                    severity = (
                        EventSeverity.ERROR
                        if status.state == "failed"
                        else EventSeverity.WARNING
                    )

                    event = EventBuilder()
                    event.event_type = EventType.SERVICE_STATUS
                    event.severity = severity
                    event.source = EventSource.REMOTE_AGENT
                    event.target = status.target
                    event.category = EventCategory.LIFECYCLE
                    event.title = f"Service {status.service} is {status.state}"
                    event.description = status.message
                    event.details = {
                        "service": status.service,
                        "target": status.target,
                        "state": status.state,
                        "message": status.message,
                        "details": status.details,
                    }

                    if status.state == "failed":
                        event.add_tag("service_failure")

                    events.append(event.build())

            if events:
                await self.event_store.store_events(events)
                self.logger.info(f"Generated {len(events)} service status events")

            return events

        except Exception as e:
            self.logger.error(f"Failed to generate service status events: {e}")
            error_event = EventBuilder.error(
                EventSource.REMOTE_AGENT,
                "Service status event generation failed",
                str(e),
                {"integration": "remote_agent"},
            )
            await self.event_store.store_event(error_event)
            return [error_event]

    async def generate_operation_events(
        self, operation_results: List[Dict[str, Any]]
    ) -> List[SystemEvent]:
        """Generate operation events from remote agent results."""
        events = []

        try:
            from src.models.execution import ExecutionStatus

            for result_data in operation_results:
                # Convert to ExecutionResult if needed
                if isinstance(result_data, dict):
                    success = result_data.get("success", False)
                    status = (
                        ExecutionStatus.SUCCESS if success else ExecutionStatus.FAILURE
                    )

                    event = create_operation_event(
                        source=EventSource.REMOTE_AGENT,
                        event_type=EventType.OPERATION_COMPLETED
                        if success
                        else EventType.OPERATION_FAILED,
                        operation=result_data.get("operation", "unknown"),
                        target=result_data.get("target"),
                        success=success,
                        duration=result_data.get("duration"),
                        error=result_data.get("error"),
                    )

                    events.append(event)

            if events:
                await self.event_store.store_events(events)

            return events

        except Exception as e:
            self.logger.error(f"Failed to generate operation events: {e}")
            return []


class DiscoveryPipelineIntegration:
    """Integration with discovery pipeline system."""

    def __init__(self):
        self.logger = get_logger("discovery_pipeline_integration")
        self.event_store = get_event_store()

    async def generate_discovery_events(self) -> List[SystemEvent]:
        """Generate events from discovery pipeline."""
        events = []

        try:
            from src.services.discovery_pipeline import DiscoveryPipeline

            pipeline = DiscoveryPipeline()

            # Get pipeline status
            status = await pipeline.get_status()

            if status.get("errors"):
                # Create discovery failed event
                for error in status["errors"]:
                    event = EventBuilder.error(
                        EventSource.DISCOVERY_PIPELINE,
                        "Discovery pipeline error",
                        error,
                        {
                            "pipeline_id": status.get("pipeline_id"),
                            "discovery_type": status.get("discovery_type"),
                            "timestamp": datetime.utcnow().isoformat(),
                        },
                    )
                    event.category = EventCategory.DISCOVERY
                    events.append(event.build())

            if status.get("targets_discovered", 0) > 0:
                # Create discovery completed event
                event = EventBuilder()
                event.event_type = EventType.TARGET_DISCOVERED
                event.severity = EventSeverity.INFO
                event.source = EventSource.DISCOVERY_PIPELINE
                event.category = EventCategory.DISCOVERY
                event.title = f"Discovered {status['targets_discovered']} new targets"
                event.description = f"Discovery pipeline found {status['targets_discovered']} new targets"
                event.details = {
                    "targets_discovered": status["targets_discovered"],
                    "discovery_type": status.get("discovery_type"),
                    "discovery_duration": status.get("duration"),
                    "pipeline_id": status.get("pipeline_id"),
                }
                event.add_tag("discovery")
                event.add_tag("new_targets")
                events.append(event.build())

            if events:
                await self.event_store.store_events(events)
                self.logger.info(f"Generated {len(events)} discovery events")

            return events

        except Exception as e:
            self.logger.error(f"Failed to generate discovery events: {e}")
            error_event = EventBuilder.error(
                EventSource.DISCOVERY_PIPELINE,
                "Discovery event generation failed",
                str(e),
                {"integration": "discovery_pipeline"},
            )
            await self.event_store.store_event(error_event)
            return [error_event]


class ProxmoxIntegration:
    """Integration with Proxmox API."""

    def __init__(self):
        self.logger = get_logger("proxmox_integration")
        self.event_store = get_event_store()

    async def generate_proxmox_events(self) -> List[SystemEvent]:
        """Generate events from Proxmox API."""
        events = []

        try:
            from src.tools.proxmox_tools import ProxmoxTools

            proxmox_tools = ProxmoxTools()

            # Get container status
            containers = await proxmox_tools.list_containers()

            for container in containers:
                if container.get("status") != "running":
                    # Create container status event
                    severity = (
                        EventSeverity.ERROR
                        if container.get("status") == "stopped"
                        else EventSeverity.WARNING
                    )

                    event = EventBuilder()
                    event.event_type = EventType.SERVICE_STATUS
                    event.severity = severity
                    event.source = EventSource.PROXMOX_API
                    event.target = container.get("name", container.get("vmid"))
                    event.category = EventCategory.LIFECYCLE
                    event.title = f"Container {container.get('name')} status: {container.get('status')}"
                    event.description = f"Container {container.get('name')} is {container.get('status')}"
                    event.details = {
                        "container_id": container.get("vmid"),
                        "name": container.get("name"),
                        "status": container.get("status"),
                        "node": container.get("node"),
                        "type": "lxc" if container.get("type") == "lxc" else "qemu",
                    }
                    event.add_tag("container")
                    event.add_tag("proxmox")

                    events.append(event.build())

            # Get resource usage
            nodes = await proxmox_tools.get_nodes()
            for node in nodes:
                if "maxcpu" in node and "cpu" in node:
                    cpu_usage = (
                        (node["cpu"] / node["maxcpu"]) * 100
                        if node["maxcpu"] > 0
                        else 0
                    )
                    if cpu_usage > 80:
                        event = EventBuilder()
                        event.event_type = EventType.RESOURCE_THRESHOLD
                        event.severity = EventSeverity.WARNING
                        event.source = EventSource.PROXMOX_API
                        event.target = node["node"]
                        event.category = EventCategory.PERFORMANCE
                        event.title = f"High CPU usage on Proxmox node {node['node']}"
                        event.description = (
                            f"CPU usage at {cpu_usage:.1f}% on node {node['node']}"
                        )
                        event.resource_usage = ResourceUsage(cpu_percent=cpu_usage)
                        event.details = {
                            "node": node["node"],
                            "cpu_usage": cpu_usage,
                            "maxcpu": node["maxcpu"],
                            "current_cpu": node["cpu"],
                        }
                        event.add_tag("resource_threshold")
                        event.add_tag("proxmox")
                        events.append(event.build())

            if events:
                await self.event_store.store_events(events)
                self.logger.info(f"Generated {len(events)} Proxmox events")

            return events

        except Exception as e:
            self.logger.error(f"Failed to generate Proxmox events: {e}")
            error_event = EventBuilder.error(
                EventSource.PROXMOX_API,
                "Proxmox event generation failed",
                str(e),
                {"integration": "proxmox"},
            )
            await self.event_store.store_event(error_event)
            return [error_event]


class SystemIntegrationManager:
    """Main integration manager for all TailOpsMCP components."""

    def __init__(self):
        self.logger = get_logger("system_integration_manager")
        self.event_store = get_event_store()

        # Initialize integrations
        self.fleet_inventory = FleetInventoryIntegration()
        self.policy_engine = PolicyEngineIntegration()
        self.security_audit = SecurityAuditIntegration()
        self.remote_agent = RemoteAgentIntegration()
        self.discovery_pipeline = DiscoveryPipelineIntegration()
        self.proxmox = ProxmoxIntegration()

        # Integration status
        self.integration_status = {
            "fleet_inventory": False,
            "policy_engine": False,
            "security_audit": False,
            "remote_agent": False,
            "discovery_pipeline": False,
            "proxmox": False,
        }

    async def initialize_integrations(self) -> Dict[str, bool]:
        """Initialize all integrations."""
        try:
            self.logger.info("Initializing system integrations")

            # Test each integration
            integrations = [
                ("fleet_inventory", self._test_fleet_inventory_integration),
                ("policy_engine", self._test_policy_engine_integration),
                ("security_audit", self._test_security_audit_integration),
                ("remote_agent", self._test_remote_agent_integration),
                ("discovery_pipeline", self._test_discovery_pipeline_integration),
                ("proxmox", self._test_proxmox_integration),
            ]

            for name, test_func in integrations:
                try:
                    await test_func()
                    self.integration_status[name] = True
                    self.logger.info(f"Integration {name} initialized successfully")
                except Exception as e:
                    self.integration_status[name] = False
                    self.logger.warning(
                        f"Integration {name} initialization failed: {e}"
                    )

            active_integrations = sum(
                1 for status in self.integration_status.values() if status
            )
            self.logger.info(
                f"Initialized {active_integrations}/{len(integrations)} integrations"
            )

            return self.integration_status

        except Exception as e:
            self.logger.error(f"Failed to initialize integrations: {e}")
            return self.integration_status

    async def _test_fleet_inventory_integration(self) -> None:
        """Test fleet inventory integration."""
        # Simple test - try to get fleet status
        from src.tools.enhanced_inventory_tools import EnhancedInventoryTools

        inventory_tools = EnhancedInventoryTools()
        await inventory_tools.get_fleet_status()

    async def _test_policy_engine_integration(self) -> None:
        """Test policy engine integration."""
        # Simple test - try to get policy violations
        from src.tools.fleet_policy import FleetPolicyTools

        policy_tools = FleetPolicyTools()
        await policy_tools.get_recent_violations()

    async def _test_security_audit_integration(self) -> None:
        """Test security audit integration."""
        # Simple test - try to get audit events
        from src.utils.audit import AuditLogger

        audit_logger = AuditLogger()
        await audit_logger.get_recent_events(hours=1)

    async def _test_remote_agent_integration(self) -> None:
        """Test remote agent integration."""
        # Simple test - try to get service statuses
        from src.tools.remote_agent_tools import RemoteAgentTools

        remote_tools = RemoteAgentTools()
        await remote_tools.get_all_service_statuses()

    async def _test_discovery_pipeline_integration(self) -> None:
        """Test discovery pipeline integration."""
        # Simple test - try to get pipeline status
        from src.services.discovery_pipeline import DiscoveryPipeline

        pipeline = DiscoveryPipeline()
        await pipeline.get_status()

    async def _test_proxmox_integration(self) -> None:
        """Test Proxmox integration."""
        # Simple test - try to list containers
        from src.tools.proxmox_tools import ProxmoxTools

        proxmox_tools = ProxmoxTools()
        await proxmox_tools.list_containers()

    async def collect_all_events(self) -> List[SystemEvent]:
        """Collect events from all integrated systems."""
        all_events = []

        try:
            # Collect from each integration if active
            if self.integration_status["fleet_inventory"]:
                events = (
                    await self.fleet_inventory.generate_health_events_from_inventory()
                )
                all_events.extend(events)

                # Also get fleet update events
                fleet_events = await self.fleet_inventory.generate_fleet_update_events()
                all_events.extend(fleet_events)

            if self.integration_status["policy_engine"]:
                policy_events = (
                    await self.policy_engine.generate_policy_violation_events()
                )
                all_events.extend(policy_events)

                audit_events = await self.policy_engine.generate_policy_audit_events()
                all_events.extend(audit_events)

            if self.integration_status["security_audit"]:
                security_events = await self.security_audit.generate_security_events()
                all_events.extend(security_events)

            if self.integration_status["remote_agent"]:
                service_events = (
                    await self.remote_agent.generate_service_status_events()
                )
                all_events.extend(service_events)

            if self.integration_status["discovery_pipeline"]:
                discovery_events = (
                    await self.discovery_pipeline.generate_discovery_events()
                )
                all_events.extend(discovery_events)

            if self.integration_status["proxmox"]:
                proxmox_events = await self.proxmox.generate_proxmox_events()
                all_events.extend(proxmox_events)

            self.logger.info(
                f"Collected {len(all_events)} events from all integrations"
            )
            return all_events

        except Exception as e:
            self.logger.error(f"Failed to collect events from integrations: {e}")
            return []

    async def send_events_to_processor(self, events: List[SystemEvent]) -> None:
        """Send collected events to the event stream processor."""
        try:
            processor = get_event_stream_processor()

            # Add events to processor
            await processor.add_events(events)

            self.logger.info(f"Sent {len(events)} events to event processor")

        except Exception as e:
            self.logger.error(f"Failed to send events to processor: {e}")

    async def run_integration_cycle(self) -> Dict[str, Any]:
        """Run a complete integration cycle."""
        try:
            # Collect events from all systems
            events = await self.collect_all_events()

            # Send to processor
            if events:
                await self.send_events_to_processor(events)

            # Return summary
            return {
                "success": True,
                "events_collected": len(events),
                "active_integrations": sum(
                    1 for status in self.integration_status.values() if status
                ),
                "total_integrations": len(self.integration_status),
                "integration_status": self.integration_status.copy(),
                "timestamp": datetime.utcnow().isoformat(),
            }

        except Exception as e:
            self.logger.error(f"Integration cycle failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }

    def get_integration_status(self) -> Dict[str, Any]:
        """Get current integration status."""
        return {
            "integrations": self.integration_status.copy(),
            "active_count": sum(
                1 for status in self.integration_status.values() if status
            ),
            "total_count": len(self.integration_status),
            "health_score": (
                sum(1 for status in self.integration_status.values() if status)
                / len(self.integration_status)
            )
            * 100,
        }


# Global instance
_system_integration_manager_instance = None


def get_system_integration_manager() -> SystemIntegrationManager:
    """Get the global system integration manager instance."""
    global _system_integration_manager_instance
    if _system_integration_manager_instance is None:
        _system_integration_manager_instance = SystemIntegrationManager()
    return _system_integration_manager_instance


async def initialize_system_integrations() -> SystemIntegrationManager:
    """Initialize all system integrations."""
    manager = get_system_integration_manager()
    await manager.initialize_integrations()
    return manager


async def run_system_integration_cycle() -> Dict[str, Any]:
    """Run a complete system integration cycle."""
    manager = get_system_integration_manager()
    return await manager.run_integration_cycle()
