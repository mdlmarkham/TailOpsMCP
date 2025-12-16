"""
Discovery Pipeline Service for Gateway Fleet Orchestrator.

Orchestrates Proxmox discovery and node probing to maintain fleet inventory.
"""

import logging
import asyncio
from typing import Dict, List, Any
from datetime import datetime, timedelta

from src.models.fleet_inventory import FleetInventory, ProxmoxHost, Node, Service, Event
from src.models.fleet_inventory_persistence import FleetInventoryPersistence
from src.services.proxmox_discovery import ProxmoxDiscovery
from src.services.node_probing import NodeProbing
from src.utils.retry import retry_with_backoff

logger = logging.getLogger(__name__)


class DiscoveryPipeline:
    """Discovery pipeline that orchestrates Proxmox discovery and node probing."""

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize discovery pipeline.

        Args:
            config: Discovery configuration including intervals, methods, etc.
        """
        self.config = config or {}
        self.proxmox_discovery = ProxmoxDiscovery(
            api_config=self.config.get("proxmox_api")
        )
        self.node_probing = NodeProbing(tailscale_config=self.config.get("tailscale"))
        self.persistence = FleetInventoryPersistence()
        self.inventory = self.persistence.load_inventory()

        # Discovery state
        self.last_discovery = None
        self.discovery_interval = self.config.get(
            "discovery_interval", 300
        )  # 5 minutes
        self.health_check_interval = self.config.get(
            "health_check_interval", 60
        )  # 1 minute

    async def run_discovery_cycle(self) -> FleetInventory:
        """Run a complete discovery cycle."""
        logger.info("Starting discovery cycle")

        # Create discovery event
        discovery_event = self._create_discovery_event(
            "start", "Discovery cycle started"
        )
        self.inventory.add_event(discovery_event)

        try:
            # Step 1: Discover Proxmox hosts
            hosts = await self._discover_proxmox_hosts()

            # Step 2: Discover nodes from each host
            for host in hosts:
                await self._discover_nodes_from_host(host)

            # Step 3: Probe discovered nodes
            await self._probe_discovered_nodes()

            # Step 4: Clean up stale entries
            self._cleanup_stale_entries()

            # Update inventory metrics
            self._update_inventory_metrics()

            # Save inventory
            self.persistence.save_inventory(self.inventory)

            # Create success event
            success_event = self._create_discovery_event(
                "complete",
                f"Discovery cycle completed: {len(hosts)} hosts, {self.inventory.total_nodes} nodes",
            )
            self.inventory.add_event(success_event)

            logger.info(
                f"Discovery cycle completed: {len(hosts)} hosts, {self.inventory.total_nodes} nodes"
            )

        except Exception as e:
            # Create error event
            error_event = self._create_discovery_event(
                "error", f"Discovery cycle failed: {e}", severity="error"
            )
            self.inventory.add_event(error_event)
            logger.error(f"Discovery cycle failed: {e}")

        self.last_discovery = datetime.utcnow()
        return self.inventory

    async def _discover_proxmox_hosts(self) -> List[ProxmoxHost]:
        """Discover Proxmox hosts."""
        logger.info("Discovering Proxmox hosts")

        # Use retry mechanism for discovery
        hosts = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: retry_with_backoff(
                lambda: self.proxmox_discovery.discover_proxmox_hosts(),
                max_retries=2,
                base_delay=1,
            ),
        )

        # Add/update hosts in inventory
        for host in hosts:
            if host.id in self.inventory.proxmox_hosts:
                # Update existing host
                existing_host = self.inventory.proxmox_hosts[host.id]
                existing_host.last_seen = datetime.utcnow().isoformat() + "Z"
                existing_host.is_active = True
            else:
                # Add new host
                self.inventory.add_proxmox_host(host)

                # Create host discovery event
                host_event = self.proxmox_discovery.create_discovery_event(
                    "proxmox_discovery",
                    f"Discovered Proxmox host: {host.hostname}",
                    target_id=host.id,
                    target_type="proxmox_host",
                )
                self.inventory.add_event(host_event)

        logger.info(f"Discovered {len(hosts)} Proxmox hosts")
        return hosts

    async def _discover_nodes_from_host(self, host: ProxmoxHost) -> None:
        """Discover nodes from a Proxmox host."""
        logger.info(f"Discovering nodes from host {host.hostname}")

        try:
            # Discover nodes with retry
            nodes = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: retry_with_backoff(
                    lambda: self.proxmox_discovery.discover_nodes(host),
                    max_retries=2,
                    base_delay=1,
                ),
            )

            # Add/update nodes in inventory
            for node in nodes:
                # Set the correct host ID
                node.host_id = host.id

                if node.id in self.inventory.nodes:
                    # Update existing node
                    existing_node = self.inventory.nodes[node.id]
                    existing_node.last_updated = datetime.utcnow().isoformat() + "Z"
                    existing_node.status = node.status
                    existing_node.ip_address = (
                        node.ip_address or existing_node.ip_address
                    )
                else:
                    # Add new node
                    self.inventory.add_node(node)

                    # Create node discovery event
                    node_event = self.proxmox_discovery.create_discovery_event(
                        "node_discovery",
                        f"Discovered {node.node_type.value} node: {node.name}",
                        target_id=node.id,
                        target_type="node",
                    )
                    self.inventory.add_event(node_event)

            logger.info(f"Discovered {len(nodes)} nodes from host {host.hostname}")

        except Exception as e:
            logger.error(f"Failed to discover nodes from host {host.hostname}: {e}")

            # Create error event
            error_event = self.proxmox_discovery.create_discovery_event(
                "node_discovery_error",
                f"Failed to discover nodes from host {host.hostname}: {e}",
                severity="error",
                target_id=host.id,
                target_type="proxmox_host",
            )
            self.inventory.add_event(error_event)

    async def _probe_discovered_nodes(self) -> None:
        """Probe all discovered nodes."""
        logger.info("Probing discovered nodes")

        # Get nodes that need probing (active and recently updated)
        nodes_to_probe = self._get_nodes_for_probing()

        if not nodes_to_probe:
            logger.info("No nodes need probing")
            return

        # Probe nodes concurrently with limited concurrency
        semaphore = asyncio.Semaphore(self.config.get("max_concurrent_probes", 5))

        async def probe_node(node: Node):
            async with semaphore:
                await self._probe_single_node(node)

        # Run probes concurrently
        await asyncio.gather(*[probe_node(node) for node in nodes_to_probe])

        logger.info(f"Probed {len(nodes_to_probe)} nodes")

    async def _probe_single_node(self, node: Node) -> None:
        """Probe a single node."""
        try:
            # Probe node with retry
            probe_result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: retry_with_backoff(
                    lambda: self.node_probing.probe_node(node),
                    max_retries=2,
                    base_delay=2,
                ),
            )

            # Update node with probe results
            self._update_node_from_probe(node, probe_result)

            # Update services from probe
            self._update_services_from_probe(node, probe_result)

            # Create probe event
            probe_event = self.node_probing.create_probe_event(node, probe_result)
            self.inventory.add_event(probe_event)

            logger.debug(f"Successfully probed node {node.name}")

        except Exception as e:
            logger.error(f"Failed to probe node {node.name}: {e}")

            # Create probe error event
            error_event = self.node_probing.create_probe_event(
                node, {"errors": [str(e)]}, severity="error"
            )
            self.inventory.add_event(error_event)

    def _get_nodes_for_probing(self) -> List[Node]:
        """Get nodes that need probing based on last update time."""
        now = datetime.utcnow()
        nodes_to_probe = []

        for node in self.inventory.nodes.values():
            # Skip nodes that are not active
            if node.status == "stopped":
                continue

            # Check if node needs probing
            last_probe = (
                datetime.fromisoformat(node.last_updated.replace("Z", "+00:00"))
                if node.last_updated
                else None
            )

            if not last_probe or (now - last_probe) > timedelta(
                seconds=self.health_check_interval
            ):
                nodes_to_probe.append(node)

        return nodes_to_probe

    def _update_node_from_probe(self, node: Node, probe_result: Dict[str, Any]) -> None:
        """Update node information from probe results."""
        # Update last_updated timestamp
        node.last_updated = probe_result["timestamp"]

        # Update connection status
        connection_results = probe_result.get("connection_tests", {})
        successful_connections = [
            conn for conn, result in connection_results.items() if result.get("success")
        ]

        if successful_connections:
            # Update connection method if a better one is available
            best_connection = successful_connections[
                0
            ]  # First successful (highest priority)
            if best_connection == "tailscale_ssh":
                node.connection_method = "tailscale_ssh"
            elif best_connection == "ssh" and node.connection_method != "tailscale_ssh":
                node.connection_method = "ssh"

        # Update system information if available
        system_info = probe_result.get("system_info", {}).get("parsed", {})
        if system_info:
            # Update hostname if different
            new_hostname = system_info.get("hostname")
            if new_hostname and new_hostname != "unknown" and new_hostname != node.name:
                node.name = new_hostname

    def _update_services_from_probe(
        self, node: Node, probe_result: Dict[str, Any]
    ) -> None:
        """Update services from probe results."""
        discovered_services = probe_result.get("services", [])

        # Remove old services for this node
        services_to_remove = [
            service_id
            for service_id, service in self.inventory.services.items()
            if service.node_id == node.id
        ]

        for service_id in services_to_remove:
            del self.inventory.services[service_id]

        # Add discovered services
        for service_data in discovered_services:
            # Convert service data to Service object if needed
            if isinstance(service_data, dict):
                service = Service(
                    name=service_data["name"],
                    node_id=node.id,
                    service_type=service_data["service_type"],
                    status=service_data["status"],
                    version=service_data.get("version"),
                    tags=service_data.get("tags", []),
                )
            else:
                service = service_data

            self.inventory.add_service(service)

    def _cleanup_stale_entries(self) -> None:
        """Clean up stale hosts and nodes."""
        now = datetime.utcnow()
        stale_threshold = timedelta(hours=24)  # 24 hours

        # Clean up stale hosts
        hosts_to_remove = []
        for host_id, host in self.inventory.proxmox_hosts.items():
            last_seen = (
                datetime.fromisoformat(host.last_seen.replace("Z", "+00:00"))
                if host.last_seen
                else None
            )

            if last_seen and (now - last_seen) > stale_threshold:
                hosts_to_remove.append(host_id)

                # Create cleanup event
                cleanup_event = self._create_discovery_event(
                    "cleanup",
                    f"Removed stale Proxmox host: {host.hostname}",
                    target_id=host_id,
                    target_type="proxmox_host",
                )
                self.inventory.add_event(cleanup_event)

        for host_id in hosts_to_remove:
            del self.inventory.proxmox_hosts[host_id]

        # Clean up stale nodes
        nodes_to_remove = []
        for node_id, node in self.inventory.nodes.items():
            last_updated = (
                datetime.fromisoformat(node.last_updated.replace("Z", "+00:00"))
                if node.last_updated
                else None
            )

            if last_updated and (now - last_updated) > stale_threshold:
                nodes_to_remove.append(node_id)

                # Create cleanup event
                cleanup_event = self._create_discovery_event(
                    "cleanup",
                    f"Removed stale node: {node.name}",
                    target_id=node_id,
                    target_type="node",
                )
                self.inventory.add_event(cleanup_event)

        for node_id in nodes_to_remove:
            del self.inventory.nodes[node_id]

    def _update_inventory_metrics(self) -> None:
        """Update inventory metrics."""
        self.inventory.total_hosts = len(self.inventory.proxmox_hosts)
        self.inventory.total_nodes = len(self.inventory.nodes)
        self.inventory.total_services = len(self.inventory.services)
        self.inventory.last_updated = datetime.utcnow().isoformat() + "Z"

    def _create_discovery_event(
        self,
        action: str,
        message: str,
        severity: str = "info",
        target_id: str = None,
        target_type: str = None,
    ) -> Event:
        """Create a discovery event."""
        from src.models.fleet_inventory import EventSeverity

        return Event(
            event_type="discovery",
            severity=EventSeverity(severity),
            source="discovery_pipeline",
            target_id=target_id,
            target_type=target_type,
            message=message,
            details={
                "action": action,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            },
        )

    def should_run_discovery(self) -> bool:
        """Check if discovery should run based on interval."""
        if not self.last_discovery:
            return True

        time_since_last = datetime.utcnow() - self.last_discovery
        return time_since_last.total_seconds() >= self.discovery_interval

    def get_discovery_status(self) -> Dict[str, Any]:
        """Get discovery pipeline status."""
        return {
            "last_discovery": self.last_discovery.isoformat()
            if self.last_discovery
            else None,
            "discovery_interval": self.discovery_interval,
            "health_check_interval": self.health_check_interval,
            "inventory_stats": {
                "hosts": self.inventory.total_hosts,
                "nodes": self.inventory.total_nodes,
                "services": self.inventory.total_services,
            },
            "should_run": self.should_run_discovery(),
        }
