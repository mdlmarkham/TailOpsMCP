"""
Discovery Tools for Populating Allowlists

Provides discovery tools to populate allowlists with current system state:
- list_services(target) - discover available services
- list_containers(target) - discover running containers
- list_stacks(target) - discover compose stacks
- list_ports(target) - discover open ports
"""

import socket
from typing import Dict

from src.services.docker_manager import DockerManager
from src.services.compose_manager import ComposeStackManager
from src.services.network_status import NetworkStatus
from src.inventory import Inventory


class DiscoveryTools:
    """Discovery tools for populating allowlists with current system state."""

    def __init__(self):
        self.docker_manager = DockerManager()
        self.compose_manager = ComposeStackManager()
        self.network_status = NetworkStatus()
        self.inventory = Inventory()

    async def list_services(self, target: str) -> Dict:
        """Discover available services on a target system.

        Args:
            target: Target system identifier

        Returns:
            Dictionary with list of services
        """
        try:
            # For now, use inventory services - can be extended with systemd/service discovery
            services = self.inventory.list_services()

            # Convert to standardized format
            service_list = []
            for service_id, service_data in services.items():
                service_list.append(
                    {
                        "name": service_id,
                        "type": service_data.get("type", "unknown"),
                        "status": service_data.get("status", "unknown"),
                        "port": service_data.get("port"),
                        "description": service_data.get("description", ""),
                    }
                )

            return {
                "success": True,
                "data": service_list,
                "target": target,
                "count": len(service_list),
            }

        except Exception as e:
            return {"success": False, "error": str(e), "target": target}

    async def list_containers(self, target: str) -> Dict:
        """Discover running containers on a target system.

        Args:
            target: Target system identifier

        Returns:
            Dictionary with list of containers
        """
        try:
            # Use Docker manager to list containers
            result = await self.docker_manager.list_containers(show_all=True)

            if not result["success"]:
                return result

            # Standardize container format
            containers = []
            for container in result["data"]:
                containers.append(
                    {
                        "name": container["name"],
                        "id": container["id"],
                        "status": container["status"],
                        "image": container["image"],
                        "created": container["created"],
                    }
                )

            return {
                "success": True,
                "data": containers,
                "target": target,
                "count": len(containers),
            }

        except Exception as e:
            return {"success": False, "error": str(e), "target": target}

    async def list_stacks(self, target: str) -> Dict:
        """Discover Docker Compose stacks on a target system.

        Args:
            target: Target system identifier

        Returns:
            Dictionary with list of stacks
        """
        try:
            # Use inventory to get stacks
            stacks = self.inventory.list_stacks()

            # Standardize stack format
            stack_list = []
            for stack_id, stack_data in stacks.items():
                stack_list.append(
                    {
                        "name": stack_id,
                        "path": stack_data.get("path"),
                        "repo_url": stack_data.get("repo_url"),
                        "services": stack_data.get("services", []),
                        "status": stack_data.get("status", "unknown"),
                        "deployed_at": stack_data.get("deployed_at"),
                    }
                )

            return {
                "success": True,
                "data": stack_list,
                "target": target,
                "count": len(stack_list),
            }

        except Exception as e:
            return {"success": False, "error": str(e), "target": target}

    async def list_ports(self, target: str) -> Dict:
        """Discover open ports on a target system.

        Args:
            target: Target system identifier

        Returns:
            Dictionary with list of open ports
        """
        try:
            # Scan common ports (can be extended with full port scanning)
            common_ports = [22, 80, 443, 8080, 3000, 5000, 5432, 6379, 27017]
            open_ports = []

            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex(("127.0.0.1", port))
                    sock.close()

                    if result == 0:
                        open_ports.append(
                            {
                                "port": port,
                                "service": self._get_service_name(port),
                                "status": "open",
                            }
                        )
                except Exception:
                    pass

            return {
                "success": True,
                "data": open_ports,
                "target": target,
                "count": len(open_ports),
            }

        except Exception as e:
            return {"success": False, "error": str(e), "target": target}

    def _get_service_name(self, port: int) -> str:
        """Get common service name for a port."""
        service_map = {
            22: "ssh",
            80: "http",
            443: "https",
            8080: "http-alt",
            3000: "nodejs",
            5000: "flask",
            5432: "postgresql",
            6379: "redis",
            27017: "mongodb",
        }
        return service_map.get(port, "unknown")
