"""
Proxmox Discovery Service for Gateway Fleet Orchestrator.

Provides both API-based and CLI-based discovery of Proxmox hosts and their containers/VMs.
"""

import logging
import subprocess
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from datetime import timezone, timezone

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
from src.utils.retry import retry_with_backoff

logger = logging.getLogger(__name__)


class ProxmoxDiscovery:
    """Proxmox discovery service with API and CLI fallback."""

    def __init__(self, api_config: Dict[str, Any] = None):
        """Initialize Proxmox discovery service.

        Args:
            api_config: Proxmox API configuration (host, username, password/token, etc.)
        """
        self.api_config = api_config or {}
        self._api_client = None

    def discover_proxmox_hosts(self) -> List[ProxmoxHost]:
        """Discover Proxmox hosts in the environment.

        Returns:
            List of discovered Proxmox hosts
        """
        hosts = []

        # Try API discovery first if configured
        if self.api_config:
            try:
                hosts.extend(self._discover_via_api())
                logger.info("Discovered Proxmox hosts via API")
                return hosts
            except Exception as e:
                logger.warning(f"API discovery failed: {e}, falling back to CLI")

        # Fallback to CLI discovery
        try:
            hosts.extend(self._discover_via_cli())
            logger.info("Discovered Proxmox hosts via CLI")
        except Exception as e:
            logger.error(f"CLI discovery failed: {e}")

        return hosts

    @retry_with_backoff(max_retries=3, base_delay=1)
    def _discover_via_api(self) -> List[ProxmoxHost]:
        """Discover Proxmox hosts using the Proxmox API."""
        # This would use the proxmoxer library or direct HTTP requests
        # For now, implement a placeholder that can be extended

        if not self.api_config.get("host"):
            raise ValueError("API host configuration required")

        # Placeholder implementation - would need proxmoxer integration
        # For now, return empty list to trigger CLI fallback
        return []

    def _discover_via_cli(self) -> List[ProxmoxHost]:
        """Discover Proxmox hosts using local CLI commands."""
        hosts = []

        # Check if we're running on/near a Proxmox host
        if self._is_proxmox_environment():
            # Get local host information
            host_info = self._get_local_proxmox_info()
            if host_info:
                hosts.append(host_info)

        return hosts

    def _is_proxmox_environment(self) -> bool:
        """Check if running in a Proxmox environment."""
        try:
            # Check for Proxmox-specific files and processes
            checks = [
                # Check for Proxmox VE installation
                subprocess.run(
                    ["pvesh", "get", "/version"], capture_output=True, text=True
                ),
                # Check for Proxmox-specific directories
                subprocess.run(["ls", "/etc/pve"], capture_output=True, text=True),
                # Check for pct/qm commands
                subprocess.run(["which", "pct"], capture_output=True, text=True),
                subprocess.run(["which", "qm"], capture_output=True, text=True),
            ]

            # If any of these succeed, we're likely in a Proxmox environment
            return any(check.returncode == 0 for check in checks)
        except Exception:
            return False

    def _get_local_proxmox_info(self) -> Optional[ProxmoxHost]:
        """Get information about the local Proxmox host."""
        try:
            # Get hostname
            hostname_result = subprocess.run(
                ["hostname"], capture_output=True, text=True
            )
            hostname = (
                hostname_result.stdout.strip()
                if hostname_result.returncode == 0
                else "unknown"
            )

            # Get node name from Proxmox
            node_result = subprocess.run(
                ["pvesh", "get", "/nodes/$(hostname)"], capture_output=True, text=True
            )
            if node_result.returncode == 0:
                node_info = json.loads(node_result.stdout)
                node_name = node_info.get("node", hostname)

                # Get system resources
                cpu_cores = self._get_cpu_cores()
                memory_mb = self._get_total_memory()
                storage_gb = self._get_total_storage()

                return ProxmoxHost(
                    hostname=hostname,
                    address="localhost",
                    username="root@pam",
                    node_name=node_name,
                    cpu_cores=cpu_cores,
                    memory_mb=memory_mb,
                    storage_gb=storage_gb,
                    version=self._get_proxmox_version(),
                    tags=["local", "cli-discovered"],
                )
        except Exception as e:
            logger.error(f"Failed to get local Proxmox info: {e}")

        return None

    def _get_cpu_cores(self) -> int:
        """Get number of CPU cores."""
        try:
            result = subprocess.run(["nproc"], capture_output=True, text=True)
            return int(result.stdout.strip()) if result.returncode == 0 else 1
        except Exception:
            return 1

    def _get_total_memory(self) -> int:
        """Get total memory in MB."""
        try:
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        kb = int(line.split()[1])
                        return kb // 1024  # Convert KB to MB
        except Exception:
            pass
        return 4096  # Default fallback

    def _get_total_storage(self) -> int:
        """Get total storage in GB."""
        try:
            result = subprocess.run(["df", "-BG", "/"], capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                if len(lines) > 1:
                    size_str = lines[1].split()[1]
                    return int(size_str.rstrip("G"))
        except Exception:
            pass
        return 100  # Default fallback

    def _get_proxmox_version(self) -> str:
        """Get Proxmox VE version."""
        try:
            result = subprocess.run(["pveversion"], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return "unknown"

    def discover_nodes(self, host: ProxmoxHost) -> List[Node]:
        """Discover containers and VMs on a Proxmox host.

        Args:
            host: Proxmox host to discover nodes from

        Returns:
            List of discovered nodes (containers/VMs)
        """
        nodes = []

        # Try API discovery first
        if self.api_config and host.address != "localhost":
            try:
                nodes.extend(self._discover_nodes_via_api(host))
                return nodes
            except Exception as e:
                logger.warning(f"API node discovery failed for {host.hostname}: {e}")

        # Fallback to CLI discovery
        if host.address == "localhost":
            try:
                nodes.extend(self._discover_nodes_via_cli())
            except Exception as e:
                logger.error(f"CLI node discovery failed: {e}")

        return nodes

    def _discover_nodes_via_cli(self) -> List[Node]:
        """Discover nodes using local CLI commands."""
        nodes = []

        # Discover LXC containers
        try:
            result = subprocess.run(["pct", "list"], capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")[1:]  # Skip header
                for line in lines:
                    if line.strip():
                        node = self._parse_pct_list_line(line, NodeType.CONTAINER)
                        if node:
                            nodes.append(node)
        except Exception as e:
            logger.error(f"Failed to discover LXC containers: {e}")

        # Discover VMs
        try:
            result = subprocess.run(["qm", "list"], capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")[1:]  # Skip header
                for line in lines:
                    if line.strip():
                        node = self._parse_qm_list_line(line, NodeType.VM)
                        if node:
                            nodes.append(node)
        except Exception as e:
            logger.error(f"Failed to discover VMs: {e}")

        return nodes

    def _parse_pct_list_line(self, line: str, node_type: NodeType) -> Optional[Node]:
        """Parse a line from 'pct list' output."""
        try:
            parts = line.split()
            if len(parts) >= 5:
                vmid = int(parts[0])
                status = parts[1]
                name = parts[2]

                # Get detailed info for IP and resources
                ip_address = self._get_container_ip(vmid)
                cpu_cores = self._get_container_cpu(vmid)
                memory_mb = self._get_container_memory(vmid)
                disk_gb = self._get_container_disk(vmid)

                return Node(
                    name=name,
                    node_type=node_type,
                    host_id="local",  # Will be updated when added to inventory
                    vmid=vmid,
                    status=status,
                    cpu_cores=cpu_cores,
                    memory_mb=memory_mb,
                    disk_gb=disk_gb,
                    ip_address=ip_address,
                    runtime=Runtime.SYSTEMD,  # LXC containers typically use systemd
                    connection_method=ConnectionMethod.SSH,
                    tags=["lxc", "proxmox"],
                )
        except Exception as e:
            logger.error(f"Failed to parse pct list line: {e}")

        return None

    def _parse_qm_list_line(self, line: str, node_type: NodeType) -> Optional[Node]:
        """Parse a line from 'qm list' output."""
        try:
            parts = line.split()
            if len(parts) >= 5:
                vmid = int(parts[0])
                status = parts[2]
                name = parts[1]

                # Get detailed info for resources
                cpu_cores = self._get_vm_cpu(vmid)
                memory_mb = self._get_vm_memory(vmid)
                disk_gb = self._get_vm_disk(vmid)

                return Node(
                    name=name,
                    node_type=node_type,
                    host_id="local",  # Will be updated when added to inventory
                    vmid=vmid,
                    status=status,
                    cpu_cores=cpu_cores,
                    memory_mb=memory_mb,
                    disk_gb=disk_gb,
                    runtime=Runtime.SYSTEMD,  # VMs typically use systemd
                    connection_method=ConnectionMethod.SSH,
                    tags=["vm", "proxmox"],
                )
        except Exception as e:
            logger.error(f"Failed to parse qm list line: {e}")

        return None

    def _get_container_ip(self, vmid: int) -> Optional[str]:
        """Get container IP address."""
        try:
            result = subprocess.run(
                ["pct", "config", str(vmid)], capture_output=True, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if line.startswith("net"):
                        # Extract IP from net configuration
                        parts = line.split("=")
                        if len(parts) > 1:
                            net_config = parts[1].strip()
                            if "ip=" in net_config:
                                ip_part = net_config.split("ip=")[1].split(",")[0]
                                return ip_part
        except Exception:
            pass
        return None

    def _get_container_cpu(self, vmid: int) -> int:
        """Get container CPU cores."""
        try:
            result = subprocess.run(
                ["pct", "config", str(vmid)], capture_output=True, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if line.startswith("cores"):
                        return int(line.split("=")[1].strip())
        except Exception:
            pass
        return 1

    def _get_container_memory(self, vmid: int) -> int:
        """Get container memory in MB."""
        try:
            result = subprocess.run(
                ["pct", "config", str(vmid)], capture_output=True, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if line.startswith("memory"):
                        return (
                            int(line.split("=")[1].strip()) // 1024
                        )  # Convert KB to MB
        except Exception:
            pass
        return 512

    def _get_container_disk(self, vmid: int) -> int:
        """Get container disk size in GB."""
        try:
            result = subprocess.run(
                ["pct", "config", str(vmid)], capture_output=True, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if line.startswith("rootfs"):
                        size_part = line.split("size=")[1].split(",")[0]
                        if size_part.endswith("G"):
                            return int(size_part.rstrip("G"))
                        elif size_part.endswith("M"):
                            return int(size_part.rstrip("M")) // 1024
        except Exception:
            pass
        return 10

    def _get_vm_cpu(self, vmid: int) -> int:
        """Get VM CPU cores."""
        try:
            result = subprocess.run(
                ["qm", "config", str(vmid)], capture_output=True, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if line.startswith("cores"):
                        return int(line.split("=")[1].strip())
        except Exception:
            pass
        return 1

    def _get_vm_memory(self, vmid: int) -> int:
        """Get VM memory in MB."""
        try:
            result = subprocess.run(
                ["qm", "config", str(vmid)], capture_output=True, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if line.startswith("memory"):
                        return int(line.split("=")[1].strip())
        except Exception:
            pass
        return 1024

    def _get_vm_disk(self, vmid: int) -> int:
        """Get VM disk size in GB."""
        try:
            result = subprocess.run(
                ["qm", "config", str(vmid)], capture_output=True, text=True
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if line.startswith("scsi"):
                        if "size=" in line:
                            size_part = line.split("size=")[1].split(",")[0]
                            if size_part.endswith("G"):
                                return int(size_part.rstrip("G"))
        except Exception:
            pass
        return 20

    def create_discovery_event(
        self,
        source: str,
        message: str,
        severity: EventSeverity = EventSeverity.INFO,
        target_id: str = None,
        target_type: str = None,
    ) -> Event:
        """Create a discovery event."""
        return Event(
            event_type=EventType.DISCOVERY,
            severity=severity,
            source=source,
            target_id=target_id,
            target_type=target_type,
            message=message,
            details={"timestamp": datetime.now(timezone.utc).isoformat() + "Z"},
        )
