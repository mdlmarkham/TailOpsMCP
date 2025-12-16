"""
Enhanced Inventory Service Layer

Provides comprehensive inventory management services with:
- Discovery pipeline integration
- Change detection and snapshots
- Health monitoring
- Advanced querying
- Secure operations
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional, Any

from src.models.enhanced_fleet_inventory import (
    EnhancedFleetInventory,
    EnhancedTarget,
    EnhancedService,
    EnhancedStack,
    NodeRole,
    ResourceStatus,
    SecurityStatus,
)
from src.models.inventory_snapshot import (
    InventorySnapshot,
    SnapshotManager,
    SnapshotType,
    SnapshotDiff,
)
from src.utils.inventory_persistence import EnhancedInventoryPersistence
from src.services.discovery_pipeline import DiscoveryPipeline
from src.services.docker_manager import DockerManager
from src.services.compose_manager import ComposeStackManager
from src.services.network_status import NetworkStatus
from src.utils.secure_logging import SecureLogger


class InventoryService:
    """Comprehensive inventory service with advanced capabilities."""

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize inventory service.

        Args:
            config: Service configuration
        """
        self.config = config or {}

        # Core components
        self.persistence = EnhancedInventoryPersistence(
            db_path=self.config.get("db_path"),
            use_sqlite=self.config.get("use_sqlite", True),
        )
        self.snapshot_manager = SnapshotManager(self.persistence)
        self.discovery_pipeline = DiscoveryPipeline(self.config.get("discovery", {}))

        # Service components
        self.docker_manager = DockerManager()
        self.compose_manager = ComposeStackManager()
        self.network_status = NetworkStatus()

        # Secure logging
        self.logger = SecureLogger("inventory_service")

        # Current inventory
        self.current_inventory = self.persistence.load_inventory()

        # Health monitoring
        self.health_check_interval = self.config.get(
            "health_check_interval", 300
        )  # 5 minutes
        self.last_health_check = None

        # Change detection settings
        self.auto_snapshot_enabled = self.config.get("auto_snapshot_enabled", True)
        self.snapshot_retention_days = self.config.get("snapshot_retention_days", 30)

        # Metrics
        self.operation_counts = {
            "discoveries": 0,
            "snapshots": 0,
            "queries": 0,
            "health_checks": 0,
        }

    async def run_full_discovery(self) -> EnhancedFleetInventory:
        """Run complete discovery cycle and update inventory.

        Returns:
            Updated fleet inventory
        """
        try:
            self.logger.info("Starting full inventory discovery")

            # Run discovery pipeline
            discovered_inventory = await self.discovery_pipeline.run_discovery_cycle()

            # Convert to enhanced inventory if needed
            enhanced_inventory = self._convert_to_enhanced_inventory(
                discovered_inventory
            )

            # Enhance with additional discovery
            await self._enhance_inventory_discovery(enhanced_inventory)

            # Update health metrics
            await self._update_health_metrics(enhanced_inventory)

            # Save updated inventory
            self.persistence.save_inventory(enhanced_inventory)
            self.current_inventory = enhanced_inventory

            # Auto-create snapshot if enabled
            if self.auto_snapshot_enabled:
                await self._create_auto_snapshot("discovery", enhanced_inventory)

            self.operation_counts["discoveries"] += 1
            self.logger.info(
                f"Discovery completed: {enhanced_inventory.total_targets} targets, "
                f"{enhanced_inventory.total_services} services"
            )

            return enhanced_inventory

        except Exception as e:
            self.logger.error(f"Discovery failed: {e}")
            raise

    async def _enhance_inventory_discovery(
        self, inventory: EnhancedFleetInventory
    ) -> None:
        """Enhance inventory with additional discovery information."""
        try:
            # Enhance targets with Docker/container information
            await self._enhance_targets_with_docker_info(inventory)

            # Enhance with stack information
            await self._enhance_with_stack_info(inventory)

            # Update network topology
            await self._update_network_topology(inventory)

            # Update security posture
            await self._update_security_posture(inventory)

        except Exception as e:
            self.logger.warning(f"Enhancement discovery failed: {e}")

    async def _enhance_targets_with_docker_info(
        self, inventory: EnhancedFleetInventory
    ) -> None:
        """Enhance targets with Docker/container information."""
        try:
            # Get Docker containers
            containers_result = await self.docker_manager.list_containers(show_all=True)

            if containers_result["success"]:
                for container in containers_result["data"]:
                    container_id = container["id"]
                    container_name = container["name"]

                    # Find target that matches this container
                    for target in inventory.targets.values():
                        if (
                            target.container_info
                            and target.container_info.container_id == container_id
                        ) or target.name == container_name:
                            # Update container info
                            if not target.container_info:
                                from src.models.enhanced_fleet_inventory import (
                                    ContainerInfo,
                                )

                                target.container_info = ContainerInfo()

                            target.container_info.container_id = container_id
                            target.container_info.image_name = container.get(
                                "image", ""
                            )
                            target.container_info.status = container.get("status", "")

                            # Update target status
                            target.status = (
                                "running"
                                if container.get("status") == "running"
                                else "stopped"
                            )

                            # Update resource usage
                            await self._update_container_resource_usage(
                                target, container
                            )

                            break

        except Exception as e:
            self.logger.warning(f"Docker info enhancement failed: {e}")

    async def _update_container_resource_usage(
        self, target: EnhancedTarget, container: Dict[str, Any]
    ) -> None:
        """Update container resource usage metrics."""
        try:
            # Get container stats
            stats_result = await self.docker_manager.get_container_stats(
                container["id"]
            )

            if stats_result["success"]:
                stats = stats_result["data"]

                # Update resource usage
                target.resource_usage.cpu_percent = stats.get("cpu_percent", 0.0)
                target.resource_usage.memory_percent = stats.get("memory_percent", 0.0)
                target.resource_usage.network_rx_bytes = stats.get(
                    "network_rx_bytes", 0
                )
                target.resource_usage.network_tx_bytes = stats.get(
                    "network_tx_bytes", 0
                )

                # Update status based on resource usage
                if target.resource_usage.memory_percent > 90:
                    target.resource_usage.status = ResourceStatus.CRITICAL
                elif target.resource_usage.memory_percent > 75:
                    target.resource_usage.status = ResourceStatus.WARNING
                else:
                    target.resource_usage.status = ResourceStatus.HEALTHY

                target.resource_usage.measured_at = datetime.utcnow().isoformat() + "Z"

        except Exception as e:
            self.logger.warning(f"Resource usage update failed for {target.name}: {e}")

    async def _enhance_with_stack_info(self, inventory: EnhancedFleetInventory) -> None:
        """Enhance inventory with stack information."""
        try:
            # Get compose stacks
            stacks_result = await self.compose_manager.list_stacks()

            if stacks_result["success"]:
                for stack_data in stacks_result["data"]:
                    stack_name = stack_data["name"]

                    # Create enhanced stack
                    enhanced_stack = EnhancedStack(
                        name=stack_name,
                        compose_file_path=stack_data.get("path", ""),
                        stack_status=stack_data.get("status", "unknown"),
                        last_deployed=stack_data.get("deployed_at"),
                        services=stack_data.get("services", []),
                        targets=[],  # Will be populated based on services
                    )

                    # Add to inventory
                    inventory.add_stack(enhanced_stack)

                    # Link services to this stack
                    for service_name in stack_data.get("services", []):
                        for service in inventory.services.values():
                            if service.name == service_name:
                                service.stack_name = stack_name
                                enhanced_stack.services.append(service.id)
                                break

        except Exception as e:
            self.logger.warning(f"Stack info enhancement failed: {e}")

    async def _update_network_topology(self, inventory: EnhancedFleetInventory) -> None:
        """Update network topology information."""
        try:
            # Get network status
            network_info = self.network_status.get_network_info()

            # Update targets with network information
            for target in inventory.targets.values():
                if target.ip_address:
                    # Add network interface
                    from src.models.enhanced_fleet_inventory import NetworkInterface

                    interface = NetworkInterface(
                        name="eth0",
                        ip_address=target.ip_address,
                        subnet_mask=network_info.get("subnet_mask", "255.255.255.0"),
                        gateway=network_info.get("gateway"),
                        dns_servers=network_info.get("dns_servers", []),
                        is_active=True,
                    )

                    target.network_interfaces.append(interface)

                    # Add subnet information
                    if network_info.get("subnet"):
                        target.subnets.append(network_info["subnet"])

        except Exception as e:
            self.logger.warning(f"Network topology update failed: {e}")

    async def _update_security_posture(self, inventory: EnhancedFleetInventory) -> None:
        """Update security posture information."""
        try:
            for target in inventory.targets.values():
                # Basic security checks
                target.security_posture.tls_enabled = await self._check_tls_status(
                    target
                )
                target.security_posture.open_ports = await self._scan_open_ports(target)
                target.security_posture.firewall_status = (
                    await self._check_firewall_status(target)
                )

                # Update security status
                if (
                    target.security_posture.tls_enabled
                    and len(target.security_posture.open_ports) <= 5
                ):
                    target.security_posture.security_status = SecurityStatus.SECURE
                elif (
                    target.security_posture.tls_enabled
                    or len(target.security_posture.open_ports) <= 10
                ):
                    target.security_posture.security_status = SecurityStatus.WARNING
                else:
                    target.security_posture.security_status = SecurityStatus.VULNERABLE

        except Exception as e:
            self.logger.warning(
                f"Security posture update failed for {target.name}: {e}"
            )

    async def _check_tls_status(self, target: EnhancedTarget) -> bool:
        """Check if target has TLS enabled."""
        # Simplified check - in reality would test HTTPS endpoints
        return target.port in [443, 8443] if target.port else False

    async def _scan_open_ports(self, target: EnhancedTarget) -> List[int]:
        """Scan for open ports on target."""
        # Simplified port scan - in reality would be more comprehensive
        common_ports = [22, 80, 443, 8080, 3000, 5000, 5432, 6379]
        return [port for port in common_ports if target.port == port]

    async def _check_firewall_status(self, target: EnhancedTarget) -> str:
        """Check firewall status on target."""
        # Simplified check - would need actual firewall inspection
        return "active" if len(target.security_posture.open_ports) < 10 else "inactive"

    def _convert_to_enhanced_inventory(self, base_inventory) -> EnhancedFleetInventory:
        """Convert base inventory to enhanced inventory."""
        enhanced = EnhancedFleetInventory()

        # Convert Proxmox hosts
        for host_id, host in base_inventory.proxmox_hosts.items():
            enhanced.add_proxmox_host(host)

        # Convert nodes to enhanced targets
        for node_id, node in base_inventory.nodes.items():
            enhanced_target = self._node_to_enhanced_target(node)
            enhanced.add_target(enhanced_target)

        # Convert services
        for service_id, service in base_inventory.services.items():
            enhanced_service = self._service_to_enhanced_service(service)
            enhanced.add_service(enhanced_service)

        # Copy events
        for event_id, event in base_inventory.events.items():
            enhanced.add_event(event)

        return enhanced

    def _node_to_enhanced_target(self, node) -> EnhancedTarget:
        """Convert Node to EnhancedTarget."""
        enhanced = EnhancedTarget(
            id=node.id,
            name=node.name,
            node_type=node.node_type,
            host_id=node.host_id,
            runtime=node.runtime,
            connection_method=node.connection_method,
            cpu_cores=node.cpu_cores,
            memory_mb=node.memory_mb,
            disk_gb=node.disk_gb,
            ip_address=node.ip_address,
            mac_address=node.mac_address,
            vmid=node.vmid,
            status=node.status,
            created_at=node.created_at,
            last_updated=node.last_updated,
            is_managed=node.is_managed,
            tags=node.tags,
        )

        # Set default role based on naming or other heuristics
        if "prod" in node.name.lower():
            enhanced.role = NodeRole.PRODUCTION
        elif "dev" in node.name.lower():
            enhanced.role = NodeRole.DEVELOPMENT
        elif "staging" in node.name.lower():
            enhanced.role = NodeRole.STAGING
        else:
            enhanced.role = NodeRole.DEVELOPMENT

        return enhanced

    def _service_to_enhanced_service(self, service) -> EnhancedService:
        """Convert Service to EnhancedService."""
        return EnhancedService(
            id=service.id,
            name=service.name,
            target_id=service.node_id,
            service_type=service.service_type,
            status=service.status,
            version=service.version,
            port=service.port,
            config_path=service.config_path,
            data_path=service.data_path,
            health_endpoint=service.health_endpoint,
            created_at=service.created_at,
            last_checked=service.last_checked,
            is_monitored=service.is_monitored,
            tags=service.tags,
        )

    async def _update_health_metrics(self, inventory: EnhancedFleetInventory) -> None:
        """Update health metrics for all targets."""
        for target in inventory.targets.values():
            # Calculate health score based on various factors
            health_score = self._calculate_health_score(target)
            target.health_score = health_score

            # Update last health check timestamp
            target.last_health_check = datetime.utcnow().isoformat() + "Z"

        self.operation_counts["health_checks"] += 1

    def _calculate_health_score(self, target: EnhancedTarget) -> float:
        """Calculate health score for a target."""
        score = 1.0

        # Deduct for poor resource usage
        if target.resource_usage.cpu_percent > 90:
            score -= 0.3
        elif target.resource_usage.cpu_percent > 75:
            score -= 0.1

        if target.resource_usage.memory_percent > 90:
            score -= 0.3
        elif target.resource_usage.memory_percent > 75:
            score -= 0.1

        # Deduct for security issues
        if target.security_posture.security_status == SecurityStatus.VULNERABLE:
            score -= 0.4
        elif target.security_posture.security_status == SecurityStatus.WARNING:
            score -= 0.2

        # Deduct for stale data
        if target.last_seen:
            last_seen = datetime.fromisoformat(target.last_seen.replace("Z", "+00:00"))
            hours_since_seen = (datetime.utcnow() - last_seen).total_seconds() / 3600
            if hours_since_seen > 24:
                score -= 0.5
            elif hours_since_seen > 12:
                score -= 0.2

        return max(0.0, min(1.0, score))

    async def _create_auto_snapshot(
        self, reason: str, inventory: EnhancedFleetInventory
    ) -> None:
        """Create automatic snapshot."""
        try:
            snapshot_name = (
                f"Auto-{reason}-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
            )

            self.snapshot_manager.create_snapshot(
                inventory=inventory,
                name=snapshot_name,
                snapshot_type=SnapshotType.SCHEDULED,
                description=f"Automatic snapshot triggered by {reason}",
                tags=["auto", reason],
            )

            self.operation_counts["snapshots"] += 1
            self.logger.info(f"Created auto snapshot: {snapshot_name}")

        except Exception as e:
            self.logger.warning(f"Auto snapshot creation failed: {e}")

    # Query and filter methods
    def get_targets_by_role(self, role: NodeRole) -> List[EnhancedTarget]:
        """Get targets by role."""
        return self.persistence.get_targets_by_role(role)

    def get_targets_by_status(self, status: str) -> List[EnhancedTarget]:
        """Get targets by status."""
        return self.persistence.get_targets_by_status(status)

    def get_unhealthy_targets(self, threshold: float = 0.7) -> List[EnhancedTarget]:
        """Get unhealthy targets."""
        return self.persistence.get_unhealthy_targets(threshold)

    def get_stale_targets(self, hours: int = 24) -> List[EnhancedTarget]:
        """Get stale targets."""
        return self.persistence.get_stale_targets(hours)

    def search_targets(self, query: str) -> List[EnhancedTarget]:
        """Search targets by name, description, or tags."""
        return self.persistence.search_targets(query)

    def get_services_by_stack(self, stack_name: str) -> List[EnhancedService]:
        """Get services by stack name."""
        return self.persistence.get_services_by_stack(stack_name)

    # Snapshot management methods
    async def create_snapshot(
        self,
        name: str,
        description: Optional[str] = None,
        snapshot_type: SnapshotType = SnapshotType.MANUAL,
        created_by: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> InventorySnapshot:
        """Create a manual snapshot."""
        snapshot = self.snapshot_manager.create_snapshot(
            inventory=self.current_inventory,
            name=name,
            snapshot_type=snapshot_type,
            description=description,
            created_by=created_by,
            tags=tags,
        )

        self.operation_counts["snapshots"] += 1
        self.logger.info(f"Created snapshot: {name}")

        return snapshot

    def compare_snapshots(
        self, snapshot_a_id: str, snapshot_b_id: str
    ) -> Optional[SnapshotDiff]:
        """Compare two snapshots."""
        try:
            snapshot_a = self.snapshot_manager.get_snapshot(snapshot_a_id)
            snapshot_b = self.snapshot_manager.get_snapshot(snapshot_b_id)

            if not snapshot_a or not snapshot_b:
                return None

            return self.snapshot_manager.compare_snapshots(snapshot_a, snapshot_b)

        except Exception as e:
            self.logger.error(f"Snapshot comparison failed: {e}")
            return None

    def list_snapshots(
        self, snapshot_type: Optional[SnapshotType] = None, limit: Optional[int] = None
    ) -> List[InventorySnapshot]:
        """List snapshots with optional filtering."""
        return self.snapshot_manager.list_snapshots(snapshot_type, limit)

    def delete_snapshot(self, snapshot_id: str) -> bool:
        """Delete a snapshot."""
        return self.snapshot_manager.delete_snapshot(snapshot_id)

    # Health monitoring methods
    async def run_health_check(self) -> Dict[str, Any]:
        """Run comprehensive health check."""
        try:
            health_results = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "total_targets": self.current_inventory.total_targets,
                "healthy_targets": self.current_inventory.healthy_targets,
                "unhealthy_targets": self.current_inventory.unhealthy_targets,
                "average_health_score": self.current_inventory.average_health_score,
                "issues": [],
            }

            # Check for critical issues
            for target in self.current_inventory.targets.values():
                if target.health_score < 0.3:
                    health_results["issues"].append(
                        {
                            "type": "critical_health",
                            "target_id": target.id,
                            "target_name": target.name,
                            "health_score": target.health_score,
                            "description": f"Target {target.name} has critical health score",
                        }
                    )

                # Check for stale targets
                if target.last_seen:
                    last_seen = datetime.fromisoformat(
                        target.last_seen.replace("Z", "+00:00")
                    )
                    hours_since_seen = (
                        datetime.utcnow() - last_seen
                    ).total_seconds() / 3600

                    if hours_since_seen > 48:
                        health_results["issues"].append(
                            {
                                "type": "stale_target",
                                "target_id": target.id,
                                "target_name": target.name,
                                "hours_since_seen": hours_since_seen,
                                "description": f"Target {target.name} not seen for {hours_since_seen:.1f} hours",
                            }
                        )

            self.last_health_check = datetime.utcnow()
            self.logger.info(
                f"Health check completed: {len(health_results['issues'])} issues found"
            )

            return health_results

        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            return {"error": str(e)}

    # Maintenance methods
    async def cleanup_expired_snapshots(self) -> int:
        """Clean up expired snapshots."""
        cleaned_count = self.snapshot_manager.cleanup_expired_snapshots()
        if cleaned_count > 0:
            self.logger.info(f"Cleaned up {cleaned_count} expired snapshots")
        return cleaned_count

    async def archive_old_snapshots(self, days: int = 30) -> int:
        """Archive old snapshots."""
        archived_count = self.persistence.archive_old_snapshots(days)
        if archived_count > 0:
            self.logger.info(f"Archived {archived_count} old snapshots")
        return archived_count

    def get_storage_stats(self) -> Dict[str, Any]:
        """Get storage statistics."""
        return self.persistence.get_storage_stats()

    def get_service_status(self) -> Dict[str, Any]:
        """Get service status and metrics."""
        return {
            "service": "inventory_service",
            "version": "2.0.0",
            "status": "running",
            "last_discovery": self.discovery_pipeline.last_discovery.isoformat()
            if self.discovery_pipeline.last_discovery
            else None,
            "last_health_check": self.last_health_check.isoformat()
            if self.last_health_check
            else None,
            "current_inventory": {
                "targets": self.current_inventory.total_targets,
                "services": self.current_inventory.total_services,
                "stacks": self.current_inventory.total_stacks,
                "healthy_targets": self.current_inventory.healthy_targets,
                "average_health_score": self.current_inventory.average_health_score,
            },
            "operation_counts": self.operation_counts.copy(),
            "configuration": {
                "auto_snapshot_enabled": self.auto_snapshot_enabled,
                "health_check_interval": self.health_check_interval,
                "snapshot_retention_days": self.snapshot_retention_days,
            },
        }
