"""
Enhanced Proxmox Discovery Service

Comprehensive Proxmox environment discovery using both API and CLI methods.
Integrates with the fleet inventory system to provide rich metadata,
health monitoring, and change detection for Proxmox environments.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

from src.models.fleet_inventory import (
    ProxmoxHost,
    Node,
    ConnectionMethod,
    Runtime,
    NodeType,
    Event,
    EventType,
    EventSeverity,
)
from src.models.proxmox_models import (
    ProxmoxAPICredentials,
    ProxmoxStorage,
    ProxmoxSnapshot,
    ProxmoxBackup,
)
from src.services.proxmox_api import ProxmoxAPI, ProxmoxAPIError
from src.services.proxmox_cli import ProxmoxCLI, ProxmoxCLIError
from src.services.inventory_service import InventoryService

logger = logging.getLogger(__name__)


class ProxmoxDiscoveryEnhanced:
    """Enhanced Proxmox discovery service with API and CLI integration."""

    def __init__(
        self,
        api_credentials: Optional[List[ProxmoxAPICredentials]] = None,
        inventory_service: Optional[InventoryService] = None,
    ):
        """Initialize enhanced Proxmox discovery service.

        Args:
            api_credentials: List of Proxmox API credentials for remote discovery
            inventory_service: Inventory service for integration
        """
        self.api_credentials = api_credentials or []
        self.inventory_service = inventory_service
        self._api_clients: Dict[str, ProxmoxAPI] = {}
        self._cli_clients: Dict[str, ProxmoxCLI] = {}

        # Discovery state
        self._last_discovery: Dict[str, datetime] = {}
        self._discovered_hosts: Dict[str, ProxmoxHost] = {}
        self._discovered_nodes: Dict[str, List[Node]] = {}
        self._change_detection_enabled = True

        # Initialize CLI clients for local discovery
        self._setup_cli_clients()

    def _setup_cli_clients(self):
        """Setup CLI clients for local discovery."""
        try:
            # Create CLI client for local environment
            cli_client = ProxmoxCLI()
            if cli_client.is_available():
                self._cli_clients["local"] = cli_client
                logger.info("Initialized local Proxmox CLI client")
        except Exception as e:
            logger.warning(f"Failed to initialize local CLI client: {e}")

    async def discover_proxmox_hosts(
        self, force_refresh: bool = False
    ) -> List[ProxmoxHost]:
        """Discover all Proxmox hosts in the environment.

        Args:
            force_refresh: Force refresh even if recently discovered

        Returns:
            List of discovered Proxmox hosts
        """
        discovered_hosts = []

        # API-based discovery
        for credentials in self.api_credentials:
            try:
                host = await self._discover_host_via_api(credentials, force_refresh)
                if host:
                    discovered_hosts.append(host)
                    self._discovered_hosts[host.hostname] = host
            except Exception as e:
                logger.error(f"API discovery failed for {credentials.host}: {e}")

        # CLI-based discovery (local environment)
        for hostname, cli_client in self._cli_clients.items():
            try:
                host = await self._discover_host_via_cli(cli_client, force_refresh)
                if host:
                    discovered_hosts.append(host)
                    self._discovered_hosts[host.hostname] = host
            except Exception as e:
                logger.error(f"CLI discovery failed for {hostname}: {e}")

        # Update discovery timestamp
        for host in discovered_hosts:
            self._last_discovery[host.hostname] = datetime.utcnow()

        logger.info(f"Discovered {len(discovered_hosts)} Proxmox hosts")
        return discovered_hosts

    async def _discover_host_via_api(
        self, credentials: ProxmoxAPICredentials, force_refresh: bool = False
    ) -> Optional[ProxmoxHost]:
        """Discover Proxmox host via API.

        Args:
            credentials: API credentials
            force_refresh: Force refresh

        Returns:
            ProxmoxHost object or None if discovery fails
        """
        host_key = credentials.host

        # Check if recently discovered
        if (
            not force_refresh
            and host_key in self._last_discovery
            and datetime.utcnow() - self._last_discovery[host_key]
            < timedelta(minutes=5)
        ):
            return self._discovered_hosts.get(host_key)

        try:
            # Create or reuse API client
            if host_key not in self._api_clients:
                self._api_clients[host_key] = ProxmoxAPI(credentials)

            api_client = self._api_clients[host_key]

            # Test connection
            connection_result = await api_client.test_connection()
            if not connection_result.success:
                logger.warning(
                    f"API connection failed for {credentials.host}: {connection_result.message}"
                )
                return None

            # Get cluster information
            nodes = await api_client.list_nodes()
            if not nodes:
                logger.warning(f"No nodes found for {credentials.host}")
                return None

            # Use first node as representative host
            primary_node = nodes[0]

            # Get detailed host information
            storage_pools = await api_client.list_storage(primary_node.node)

            host = ProxmoxHost(
                hostname=primary_node.node,
                address=credentials.host,
                username=credentials.username,
                node_name=primary_node.node,
                port=credentials.port,
                realm=credentials.realm,
                version=connection_result.data.get("version")
                if connection_result.data
                else None,
                cpu_cores=int(primary_node.maxcpu) if primary_node.maxcpu else 0,
                memory_mb=int(primary_node.maxmem // 1024 // 1024)
                if primary_node.maxmem
                else 0,
                storage_gb=int(
                    sum(s.total for s in storage_pools if s.total)
                    // 1024
                    // 1024
                    // 1024
                )
                if storage_pools
                else 0,
                tags=["api-discovered", "cluster"]
                + ([f"storage-{s.type.value}" for s in storage_pools[:3]]),
                is_active=primary_node.status == "online",
            )

            # Validate host configuration
            validation_errors = host.validate()
            if validation_errors:
                logger.error(
                    f"Host validation failed for {credentials.host}: {validation_errors}"
                )
                return None

            logger.info(f"Successfully discovered host {credentials.host} via API")
            return host

        except ProxmoxAPIError as e:
            logger.error(f"Proxmox API error for {credentials.host}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error discovering {credentials.host}: {e}")
            return None

    async def _discover_host_via_cli(
        self, cli_client: ProxmoxCLI, force_refresh: bool = False
    ) -> Optional[ProxmoxHost]:
        """Discover Proxmox host via CLI.

        Args:
            cli_client: CLI client
            force_refresh: Force refresh

        Returns:
            ProxmoxHost object or None if discovery fails
        """
        host_key = "local"

        # Check if recently discovered
        if (
            not force_refresh
            and host_key in self._last_discovery
            and datetime.utcnow() - self._last_discovery[host_key]
            < timedelta(minutes=5)
        ):
            return self._discovered_hosts.get(host_key)

        try:
            # Test CLI availability
            connection_result = await cli_client.test_connection()
            if not connection_result.success:
                logger.warning(f"CLI connection failed: {connection_result.message}")
                return None

            # Get system information
            system_info = await cli_client.get_system_info_cli()
            storage_info = await cli_client.get_storage_info_cli()

            # Extract node information
            node_info = system_info.get("node", {})
            resources = system_info.get("resources", {})

            # Calculate total storage
            total_storage_gb = 0
            for storage in storage_info:
                if storage.total:
                    total_storage_gb += storage.total // 1024 // 1024 // 1024

            host = ProxmoxHost(
                hostname=node_info.get("node", "localhost"),
                address="localhost",
                username="root@pam",
                node_name=node_info.get("node", "localhost"),
                cpu_cores=resources.get("maxcpu", 0),
                memory_mb=resources.get("maxmem", 0) // 1024 // 1024,
                storage_gb=total_storage_gb,
                version=system_info.get("version", ""),
                tags=["cli-discovered", "local"]
                + ([f"storage-{s.type.value}" for s in storage_info[:3]]),
                is_active=True,
            )

            # Validate host configuration
            validation_errors = host.validate()
            if validation_errors:
                logger.error(f"Host validation failed for local: {validation_errors}")
                return None

            logger.info("Successfully discovered local host via CLI")
            return host

        except ProxmoxCLIError as e:
            logger.error(f"Proxmox CLI error: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error discovering local host: {e}")
            return None

    async def discover_containers(
        self, host: ProxmoxHost, force_refresh: bool = False
    ) -> List[Node]:
        """Discover containers on a Proxmox host.

        Args:
            host: Proxmox host to discover from
            force_refresh: Force refresh

        Returns:
            List of discovered container nodes
        """
        host_key = f"{host.hostname}:{host.address}"

        # Check if recently discovered
        if (
            not force_refresh
            and host_key in self._last_discovery
            and datetime.utcnow() - self._last_discovery[host_key]
            < timedelta(minutes=2)
        ):
            return self._discovered_nodes.get(host_key, [])

        discovered_containers = []

        try:
            # Try API discovery first
            if host.address in [c.host for c in self._api_clients.values()]:
                discovered_containers = await self._discover_containers_via_api(host)

            # Fallback to CLI discovery
            if not discovered_containers and host.address == "localhost":
                discovered_containers = await self._discover_containers_via_cli(host)

            # Update discovery cache
            self._discovered_nodes[host_key] = discovered_containers
            self._last_discovery[host_key] = datetime.utcnow()

            # Update inventory if available
            if self.inventory_service and discovered_containers:
                await self._update_inventory_with_containers(
                    host, discovered_containers
                )

            logger.info(
                f"Discovered {len(discovered_containers)} containers on {host.hostname}"
            )
            return discovered_containers

        except Exception as e:
            logger.error(f"Failed to discover containers on {host.hostname}: {e}")
            return []

    async def _discover_containers_via_api(self, host: ProxmoxHost) -> List[Node]:
        """Discover containers via API.

        Args:
            host: Proxmox host

        Returns:
            List of container nodes
        """
        containers = []

        # Find API client for this host
        api_client = None
        for client in self._api_clients.values():
            if client.credentials.host == host.address:
                api_client = client
                break

        if not api_client:
            logger.warning(f"No API client found for {host.address}")
            return []

        try:
            # Get containers from API
            proxmox_containers = await api_client.list_containers()

            for container in proxmox_containers:
                # Convert to Node model
                node = Node(
                    name=container.name,
                    node_type=NodeType.CONTAINER,
                    host_id=host.id,
                    vmid=container.vmid,
                    status=container.status.value,
                    cpu_cores=container.cores,
                    memory_mb=container.memory,
                    disk_gb=container.disk // 1024 // 1024 // 1024
                    if container.disk
                    else 0,
                    ip_address=None,  # Would need additional API call to get IP
                    runtime=Runtime.PROXMOX,
                    connection_method=ConnectionMethod.PROXMOX_API,
                    tags=["lxc", "proxmox", "api-discovered"],
                    is_managed=True,
                )

                # Add Proxmox-specific metadata
                if container.ostemplate:
                    node.tags.append(f"template-{container.ostemplate}")
                if container.hostname != container.name:
                    node.tags.append(f"hostname-{container.hostname}")

                containers.append(node)

            return containers

        except ProxmoxAPIError as e:
            logger.error(f"API container discovery failed for {host.address}: {e}")
            return []
        except Exception as e:
            logger.error(
                f"Unexpected error in API container discovery for {host.address}: {e}"
            )
            return []

    async def _discover_containers_via_cli(self, host: ProxmoxHost) -> List[Node]:
        """Discover containers via CLI.

        Args:
            host: Proxmox host

        Returns:
            List of container nodes
        """
        containers = []

        # Find CLI client for this host
        cli_client = self._cli_clients.get(host.address)
        if not cli_client:
            logger.warning(f"No CLI client found for {host.address}")
            return []

        try:
            # Get containers from CLI
            proxmox_containers = await cli_client.list_containers_cli()

            for container in proxmox_containers:
                # Get detailed configuration
                config = await cli_client.get_container_config_cli(container.vmid)

                # Convert to Node model
                node = Node(
                    name=container.name,
                    node_type=NodeType.CONTAINER,
                    host_id=host.id,
                    vmid=container.vmid,
                    status=container.status.value,
                    cpu_cores=int(config.get("cores", 1)) if config else 1,
                    memory_mb=int(config.get("memory", 512)) if config else 512,
                    disk_gb=self._extract_disk_size(config.get("rootfs", ""))
                    if config
                    else 10,
                    ip_address=self._extract_ip_address(config) if config else None,
                    runtime=Runtime.PROXMOX,
                    connection_method=ConnectionMethod.PROXMOX_API,
                    tags=["lxc", "proxmox", "cli-discovered"],
                    is_managed=True,
                )

                # Add Proxmox-specific metadata
                if config:
                    if config.get("ostemplate"):
                        node.tags.append(f"template-{config['ostemplate']}")
                    if (
                        config.get("hostname")
                        and config.get("hostname") != container.name
                    ):
                        node.tags.append(f"hostname-{config['hostname']}")

                    # Add network information
                    for key, value in config.items():
                        if key.startswith("net"):
                            node.tags.append(f"net-{key}")

                containers.append(node)

            return containers

        except ProxmoxCLIError as e:
            logger.error(f"CLI container discovery failed for {host.address}: {e}")
            return []
        except Exception as e:
            logger.error(
                f"Unexpected error in CLI container discovery for {host.address}: {e}"
            )
            return []

    async def discover_vms(
        self, host: ProxmoxHost, force_refresh: bool = False
    ) -> List[Node]:
        """Discover VMs on a Proxmox host.

        Args:
            host: Proxmox host to discover from
            force_refresh: Force refresh

        Returns:
            List of discovered VM nodes
        """
        discovered_vms = []

        try:
            # Try API discovery first
            if host.address in [c.host for c in self._api_clients.values()]:
                discovered_vms = await self._discover_vms_via_api(host)

            # Fallback to CLI discovery
            if not discovered_vms and host.address == "localhost":
                discovered_vms = await self._discover_vms_via_cli(host)

            # Update inventory if available
            if self.inventory_service and discovered_vms:
                await self._update_inventory_with_vms(host, discovered_vms)

            logger.info(f"Discovered {len(discovered_vms)} VMs on {host.hostname}")
            return discovered_vms

        except Exception as e:
            logger.error(f"Failed to discover VMs on {host.hostname}: {e}")
            return []

    async def _discover_vms_via_api(self, host: ProxmoxHost) -> List[Node]:
        """Discover VMs via API.

        Args:
            host: Proxmox host

        Returns:
            List of VM nodes
        """
        vms = []

        # Find API client for this host
        api_client = None
        for client in self._api_clients.values():
            if client.credentials.host == host.address:
                api_client = client
                break

        if not api_client:
            return []

        try:
            # Get VMs from API
            proxmox_vms = await api_client.list_vms()

            for vm in proxmox_vms:
                # Convert to Node model
                node = Node(
                    name=vm.name,
                    node_type=NodeType.VM,
                    host_id=host.id,
                    vmid=vm.vmid,
                    status=vm.status.value,
                    cpu_cores=vm.cores,
                    memory_mb=vm.memory,
                    disk_gb=vm.disk // 1024 // 1024 // 1024 if vm.disk else 0,
                    runtime=Runtime.PROXMOX,
                    connection_method=ConnectionMethod.PROXMOX_API,
                    tags=["vm", "qemu", "proxmox", "api-discovered"],
                    is_managed=True,
                )

                # Add Proxmox-specific metadata
                if vm.ostype:
                    node.tags.append(f"os-{vm.ostype}")
                if vm.vga:
                    node.tags.append(f"vga-{vm.vga}")

                vms.append(node)

            return vms

        except Exception as e:
            logger.error(f"API VM discovery failed for {host.address}: {e}")
            return []

    async def _discover_vms_via_cli(self, host: ProxmoxHost) -> List[Node]:
        """Discover VMs via CLI.

        Args:
            host: Proxmox host

        Returns:
            List of VM nodes
        """
        vms = []

        # Find CLI client for this host
        cli_client = self._cli_clients.get(host.address)
        if not cli_client:
            return []

        try:
            # Get VMs from CLI
            proxmox_vms = await cli_client.list_vms_cli()

            for vm in proxmox_vms:
                # Convert to Node model
                node = Node(
                    name=vm.name,
                    node_type=NodeType.VM,
                    host_id=host.id,
                    vmid=vm.vmid,
                    status=vm.status.value,
                    cpu_cores=1,  # CLI doesn't easily provide this
                    memory_mb=512,  # CLI doesn't easily provide this
                    disk_gb=20,  # CLI doesn't easily provide this
                    runtime=Runtime.PROXMOX,
                    connection_method=ConnectionMethod.PROXMOX_API,
                    tags=["vm", "qemu", "proxmox", "cli-discovered"],
                    is_managed=True,
                )

                vms.append(node)

            return vms

        except Exception as e:
            logger.error(f"CLI VM discovery failed for {host.address}: {e}")
            return []

    async def discover_storage_pools(self, host: ProxmoxHost) -> List[ProxmoxStorage]:
        """Discover storage pools on a Proxmox host.

        Args:
            host: Proxmox host

        Returns:
            List of storage pools
        """
        try:
            # Try API discovery first
            if host.address in [c.host for c in self._api_clients.values()]:
                return await self._discover_storage_via_api(host)

            # Fallback to CLI discovery
            if host.address == "localhost":
                return await self._discover_storage_via_cli(host)

            return []

        except Exception as e:
            logger.error(f"Failed to discover storage pools on {host.hostname}: {e}")
            return []

    async def _discover_storage_via_api(
        self, host: ProxmoxHost
    ) -> List[ProxmoxStorage]:
        """Discover storage pools via API.

        Args:
            host: Proxmox host

        Returns:
            List of storage pools
        """
        # Find API client for this host
        api_client = None
        for client in self._api_clients.values():
            if client.credentials.host == host.address:
                api_client = client
                break

        if not api_client:
            return []

        try:
            return await api_client.list_storage()
        except Exception as e:
            logger.error(f"API storage discovery failed for {host.address}: {e}")
            return []

    async def _discover_storage_via_cli(
        self, host: ProxmoxHost
    ) -> List[ProxmoxStorage]:
        """Discover storage pools via CLI.

        Args:
            host: Proxmox host

        Returns:
            List of storage pools
        """
        # Find CLI client for this host
        cli_client = self._cli_clients.get(host.address)
        if not cli_client:
            return []

        try:
            return await cli_client.get_storage_info_cli()
        except Exception as e:
            logger.error(f"CLI storage discovery failed for {host.address}: {e}")
            return []

    async def discover_snapshots(self, node: Node) -> List[ProxmoxSnapshot]:
        """Discover snapshots for a node.

        Args:
            node: Node to discover snapshots for

        Returns:
            List of snapshots
        """
        if not node.vmid:
            return []

        try:
            # Find appropriate client
            api_client = None
            for client in self._api_clients.values():
                if client.credentials.host in [
                    h.address for h in self._discovered_hosts.values()
                ]:
                    try:
                        snapshots = await client.list_snapshots(node.vmid)
                        if snapshots:
                            return snapshots
                    except:
                        continue

            # Fallback to CLI
            if "local" in self._cli_clients:
                return await self._cli_clients["local"].list_snapshots_cli(node.vmid)

            return []

        except Exception as e:
            logger.error(f"Failed to discover snapshots for {node.vmid}: {e}")
            return []

    async def discover_backups(
        self, host: ProxmoxHost, storage: Optional[str] = None
    ) -> List[ProxmoxBackup]:
        """Discover backups on a Proxmox host.

        Args:
            host: Proxmox host
            storage: Specific storage to check

        Returns:
            List of backups
        """
        try:
            # Try API discovery first
            if host.address in [c.host for c in self._api_clients.values()]:
                return await self._discover_backups_via_api(host, storage)

            # CLI discovery for backups is more complex, skip for now
            return []

        except Exception as e:
            logger.error(f"Failed to discover backups on {host.hostname}: {e}")
            return []

    async def _discover_backups_via_api(
        self, host: ProxmoxHost, storage: Optional[str] = None
    ) -> List[ProxmoxBackup]:
        """Discover backups via API.

        Args:
            host: Proxmox host
            storage: Specific storage to check

        Returns:
            List of backups
        """
        # Find API client for this host
        api_client = None
        for client in self._api_clients.values():
            if client.credentials.host == host.address:
                api_client = client
                break

        if not api_client:
            return []

        try:
            return await api_client.list_backups(node=host.node_name, storage=storage)
        except Exception as e:
            logger.error(f"API backup discovery failed for {host.address}: {e}")
            return []

    async def update_fleet_inventory(self, inventory_service: InventoryService) -> bool:
        """Update fleet inventory with discovered Proxmox resources.

        Args:
            inventory_service: Inventory service to update

        Returns:
            True if update successful
        """
        try:
            updated_hosts = 0
            updated_nodes = 0

            # Update discovered hosts
            for host in self._discovered_hosts.values():
                try:
                    inventory_service.upsert_host(host)
                    updated_hosts += 1
                except Exception as e:
                    logger.error(
                        f"Failed to update host {host.hostname} in inventory: {e}"
                    )

            # Update discovered nodes
            for host_key, nodes in self._discovered_nodes.items():
                for node in nodes:
                    try:
                        inventory_service.upsert_node(node)
                        updated_nodes += 1
                    except Exception as e:
                        logger.error(
                            f"Failed to update node {node.name} in inventory: {e}"
                        )

            logger.info(
                f"Updated inventory: {updated_hosts} hosts, {updated_nodes} nodes"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to update fleet inventory: {e}")
            return False

    async def _update_inventory_with_containers(
        self, host: ProxmoxHost, containers: List[Node]
    ):
        """Update inventory with container information.

        Args:
            host: Proxmox host
            containers: List of container nodes
        """
        if not self.inventory_service:
            return

        try:
            # Ensure host is in inventory first
            self.inventory_service.upsert_host(host)

            # Add containers
            for container in containers:
                self.inventory_service.upsert_node(container)

        except Exception as e:
            logger.error(f"Failed to update inventory with containers: {e}")

    async def _update_inventory_with_vms(self, host: ProxmoxHost, vms: List[Node]):
        """Update inventory with VM information.

        Args:
            host: Proxmox host
            vms: List of VM nodes
        """
        if not self.inventory_service:
            return

        try:
            # Ensure host is in inventory first
            self.inventory_service.upsert_host(host)

            # Add VMs
            for vm in vms:
                self.inventory_service.upsert_node(vm)

        except Exception as e:
            logger.error(f"Failed to update inventory with VMs: {e}")

    def create_discovery_event(
        self,
        source: str,
        message: str,
        severity: EventSeverity = EventSeverity.INFO,
        target_id: str = None,
        target_type: str = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Event:
        """Create a discovery event.

        Args:
            source: Event source
            message: Event message
            severity: Event severity
            target_id: Target ID
            target_type: Target type
            details: Additional event details

        Returns:
            Discovery event
        """
        return Event(
            event_type=EventType.DISCOVERY,
            severity=severity,
            source=source,
            target_id=target_id,
            target_type=target_type,
            message=message,
            details=details or {},
            timestamp=datetime.utcnow().isoformat() + "Z",
        )

    def _extract_disk_size(self, rootfs_config: str) -> int:
        """Extract disk size from rootfs configuration.

        Args:
            rootfs_config: Rootfs configuration string

        Returns:
            Disk size in GB
        """
        if not rootfs_config:
            return 10

        # Parse format like "local-lvm:20" or "local-lvm:20G"
        parts = rootfs_config.split(":")
        if len(parts) < 2:
            return 10

        size_part = parts[1]

        # Extract numeric part
        import re

        match = re.search(r"(\d+)", size_part)
        if match:
            size_gb = int(match.group(1))
            # Check if size is in MB (small values)
            if size_gb < 50:
                return size_gb // 1024  # Convert MB to GB
            return size_gb

        return 10

    def _extract_ip_address(self, config: Optional[Dict[str, Any]]) -> Optional[str]:
        """Extract IP address from container configuration.

        Args:
            config: Container configuration

        Returns:
            IP address or None
        """
        if not config:
            return None

        # Look for net configuration
        for key, value in config.items():
            if key.startswith("net") and "=" in str(value):
                # Parse network configuration
                parts = str(value).split(",")
                for part in parts:
                    if part.startswith("ip="):
                        return part.split("=", 1)[1]

        return None

    async def get_discovery_status(self) -> Dict[str, Any]:
        """Get discovery service status.

        Returns:
            Discovery status information
        """
        return {
            "api_clients": len(self._api_clients),
            "cli_clients": len(self._cli_clients),
            "discovered_hosts": len(self._discovered_hosts),
            "discovered_nodes": sum(
                len(nodes) for nodes in self._discovered_nodes.values()
            ),
            "last_discovery": {
                host: timestamp.isoformat()
                for host, timestamp in self._last_discovery.items()
            },
            "change_detection_enabled": self._change_detection_enabled,
        }

    def enable_change_detection(self, enabled: bool = True):
        """Enable or disable change detection.

        Args:
            enabled: Whether to enable change detection
        """
        self._change_detection_enabled = enabled
        logger.info(f"Change detection {'enabled' if enabled else 'disabled'}")

    async def cleanup(self):
        """Cleanup discovery resources."""
        # Close API clients
        for api_client in self._api_clients.values():
            await api_client.disconnect()

        self._api_clients.clear()
        self._cli_clients.clear()
        self._discovered_hosts.clear()
        self._discovered_nodes.clear()
        self._last_discovery.clear()

        logger.info("Proxmox discovery service cleaned up")
