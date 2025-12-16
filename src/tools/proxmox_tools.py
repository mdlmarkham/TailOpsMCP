"""
Proxmox Management MCP Tools

Provides comprehensive MCP tools for Proxmox VE management, including container/VM
operations, snapshot management, backup/restore, discovery, and monitoring.
"""

import logging
from typing import Dict, List, Optional, Any

from src.models.proxmox_models import ProxmoxAPICredentials
from src.services.proxmox_api import ProxmoxAPI
from src.services.proxmox_discovery_enhanced import ProxmoxDiscoveryEnhanced
from src.services.proxmox_capabilities import ProxmoxCapabilityExecutor

logger = logging.getLogger(__name__)


class ProxmoxTools:
    """High-level Proxmox management tools for MCP integration."""

    def __init__(self, api_credentials: Optional[List[ProxmoxAPICredentials]] = None):
        """Initialize Proxmox MCP tools.

        Args:
            api_credentials: List of Proxmox API credentials
        """
        self.api_credentials = api_credentials or []
        self.capability_executor = ProxmoxCapabilityExecutor(self.api_credentials)
        self.discovery_service: Optional[ProxmoxDiscoveryEnhanced] = None
        self._initialized = False

    async def initialize(self):
        """Initialize Proxmox tools and services."""
        if self._initialized:
            return

        try:
            # Initialize discovery service
            self.discovery_service = ProxmoxDiscoveryEnhanced(
                api_credentials=self.api_credentials
            )

            self._initialized = True
            logger.info("Proxmox MCP tools initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize Proxmox MCP tools: {e}")
            raise

    # Discovery Tools

    async def proxmox_discover(self) -> Dict[str, Any]:
        """Discover Proxmox hosts and resources.

        Returns:
            Dictionary with discovery results
        """
        try:
            await self.initialize()

            # Discover hosts
            hosts = await self.discovery_service.discover_proxmox_hosts()

            result = {"success": True, "hosts_discovered": len(hosts), "hosts": []}

            for host in hosts:
                host_info = {
                    "hostname": host.hostname,
                    "address": host.address,
                    "node_name": host.node_name,
                    "version": host.version,
                    "cpu_cores": host.cpu_cores,
                    "memory_mb": host.memory_mb,
                    "storage_gb": host.storage_gb,
                    "is_active": host.is_active,
                    "tags": host.tags,
                    "last_seen": host.last_seen,
                }
                result["hosts"].append(host_info)

                # Discover containers for each host
                containers = await self.discovery_service.discover_containers(host)
                host_info["containers"] = len(containers)

                # Discover VMs for each host
                vms = await self.discovery_service.discover_vms(host)
                host_info["vms"] = len(vms)

            return result

        except Exception as e:
            logger.error(f"Proxmox discovery failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "hosts_discovered": 0,
                "hosts": [],
            }

    async def proxmox_discover_containers(self, host: str) -> Dict[str, Any]:
        """Discover containers on a specific Proxmox host.

        Args:
            host: Proxmox host address

        Returns:
            Dictionary with container discovery results
        """
        try:
            await self.initialize()

            # Find the host
            hosts = await self.discovery_service.discover_proxmox_hosts()
            target_host = None
            for h in hosts:
                if h.address == host or h.hostname == host:
                    target_host = h
                    break

            if not target_host:
                return {
                    "success": False,
                    "error": f"Host {host} not found",
                    "containers": [],
                }

            # Discover containers
            containers = await self.discovery_service.discover_containers(target_host)

            container_list = []
            for container in containers:
                container_info = {
                    "name": container.name,
                    "vmid": container.vmid,
                    "status": container.status,
                    "cpu_cores": container.cpu_cores,
                    "memory_mb": container.memory_mb,
                    "disk_gb": container.disk_gb,
                    "ip_address": container.ip_address,
                    "runtime": container.runtime.value,
                    "tags": container.tags,
                    "is_managed": container.is_managed,
                }
                container_list.append(container_info)

            return {
                "success": True,
                "host": host,
                "containers_discovered": len(container_list),
                "containers": container_list,
            }

        except Exception as e:
            logger.error(f"Container discovery failed for {host}: {e}")
            return {"success": False, "error": str(e), "host": host, "containers": []}

    async def proxmox_discover_vms(self, host: str) -> Dict[str, Any]:
        """Discover VMs on a specific Proxmox host.

        Args:
            host: Proxmox host address

        Returns:
            Dictionary with VM discovery results
        """
        try:
            await self.initialize()

            # Find the host
            hosts = await self.discovery_service.discover_proxmox_hosts()
            target_host = None
            for h in hosts:
                if h.address == host or h.hostname == host:
                    target_host = h
                    break

            if not target_host:
                return {"success": False, "error": f"Host {host} not found", "vms": []}

            # Discover VMs
            vms = await self.discovery_service.discover_vms(target_host)

            vm_list = []
            for vm in vms:
                vm_info = {
                    "name": vm.name,
                    "vmid": vm.vmid,
                    "status": vm.status,
                    "cpu_cores": vm.cpu_cores,
                    "memory_mb": vm.memory_mb,
                    "disk_gb": vm.disk_gb,
                    "runtime": vm.runtime.value,
                    "tags": vm.tags,
                    "is_managed": vm.is_managed,
                }
                vm_list.append(vm_info)

            return {
                "success": True,
                "host": host,
                "vms_discovered": len(vm_list),
                "vms": vm_list,
            }

        except Exception as e:
            logger.error(f"VM discovery failed for {host}: {e}")
            return {"success": False, "error": str(e), "host": host, "vms": []}

    # Container Management Tools

    async def create_ct_from_template(
        self, template_id: int, config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create container from template.

        Args:
            template_id: Template container ID
            config: Container configuration

        Returns:
            Dictionary with creation results
        """
        try:
            await self.initialize()

            # Validate required parameters
            required_params = ["host", "template", "hostname"]
            for param in required_params:
                if param not in config:
                    return {
                        "success": False,
                        "error": f"Required parameter '{param}' missing",
                    }

            # Execute capability
            result = await self.capability_executor.execute_proxmox_container_create(
                config
            )

            if result.success:
                return {
                    "success": True,
                    "message": result.output,
                    "vmid": result.metadata.get("vmid") if result.metadata else None,
                    "task_id": result.metadata.get("task_id")
                    if result.metadata
                    else None,
                }
            else:
                return {
                    "success": False,
                    "error": result.error,
                    "message": result.output,
                }

        except Exception as e:
            logger.error(f"Container creation failed: {e}")
            return {"success": False, "error": str(e)}

    async def start_ct(self, vmid: int, host: str) -> Dict[str, Any]:
        """Start container.

        Args:
            vmid: Container VMID
            host: Proxmox host address

        Returns:
            Dictionary with start results
        """
        try:
            await self.initialize()

            parameters = {"vmid": vmid, "host": host}

            result = await self.capability_executor.execute_proxmox_container_start(
                parameters
            )

            if result.success:
                return {
                    "success": True,
                    "message": result.output,
                    "vmid": vmid,
                    "task_id": result.metadata.get("task_id")
                    if result.metadata
                    else None,
                }
            else:
                return {
                    "success": False,
                    "error": result.error,
                    "message": result.output,
                }

        except Exception as e:
            logger.error(f"Container start failed: {e}")
            return {"success": False, "error": str(e)}

    async def stop_ct(
        self, vmid: int, host: str, force: bool = False
    ) -> Dict[str, Any]:
        """Stop container.

        Args:
            vmid: Container VMID
            host: Proxmox host address
            force: Force stop

        Returns:
            Dictionary with stop results
        """
        try:
            await self.initialize()

            parameters = {"vmid": vmid, "host": host, "force": force}

            result = await self.capability_executor.execute_proxmox_container_stop(
                parameters
            )

            if result.success:
                return {"success": True, "message": result.output, "vmid": vmid}
            else:
                return {
                    "success": False,
                    "error": result.error,
                    "message": result.output,
                }

        except Exception as e:
            logger.error(f"Container stop failed: {e}")
            return {"success": False, "error": str(e)}

    async def reboot_ct(self, vmid: int, host: str) -> Dict[str, Any]:
        """Reboot container.

        Args:
            vmid: Container VMID
            host: Proxmox host address

        Returns:
            Dictionary with reboot results
        """
        try:
            await self.initialize()

            parameters = {"vmid": vmid, "host": host}

            result = await self.capability_executor.execute_proxmox_container_reboot(
                parameters
            )

            if result.success:
                return {
                    "success": True,
                    "message": result.output,
                    "vmid": vmid,
                    "task_id": result.metadata.get("task_id")
                    if result.metadata
                    else None,
                }
            else:
                return {
                    "success": False,
                    "error": result.error,
                    "message": result.output,
                }

        except Exception as e:
            logger.error(f"Container reboot failed: {e}")
            return {"success": False, "error": str(e)}

    async def delete_ct(self, vmid: int, host: str) -> Dict[str, Any]:
        """Delete container.

        Args:
            vmid: Container VMID to delete
            host: Proxmox host address

        Returns:
            Dictionary with deletion results
        """
        try:
            await self.initialize()

            parameters = {"vmid": vmid, "host": host}

            result = await self.capability_executor.execute_proxmox_container_delete(
                parameters
            )

            if result.success:
                return {"success": True, "message": result.output, "vmid": vmid}
            else:
                return {
                    "success": False,
                    "error": result.error,
                    "message": result.output,
                }

        except Exception as e:
            logger.error(f"Container deletion failed: {e}")
            return {"success": False, "error": str(e)}

    async def clone_ct(
        self, source_vmid: int, clone_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Clone container.

        Args:
            source_vmid: Source container VMID
            clone_config: Clone configuration

        Returns:
            Dictionary with clone results
        """
        try:
            await self.initialize()

            # Validate required parameters
            required_params = ["host", "new_hostname"]
            for param in required_params:
                if param not in clone_config:
                    return {
                        "success": False,
                        "error": f"Required parameter '{param}' missing",
                    }

            parameters = {
                "source_vmid": source_vmid,
                "host": clone_config["host"],
                "new_hostname": clone_config["new_hostname"],
            }

            # Add optional parameters
            if "new_vmid" in clone_config:
                parameters["new_vmid"] = clone_config["new_vmid"]
            if "full_clone" in clone_config:
                parameters["full_clone"] = clone_config["full_clone"]

            result = await self.capability_executor.execute_proxmox_container_clone(
                parameters
            )

            if result.success:
                return {
                    "success": True,
                    "message": result.output,
                    "source_vmid": source_vmid,
                    "new_vmid": result.metadata.get("new_vmid")
                    if result.metadata
                    else None,
                    "task_id": result.metadata.get("task_id")
                    if result.metadata
                    else None,
                }
            else:
                return {
                    "success": False,
                    "error": result.error,
                    "message": result.output,
                }

        except Exception as e:
            logger.error(f"Container clone failed: {e}")
            return {"success": False, "error": str(e)}

    # Snapshot Management Tools

    async def snapshot_ct(
        self,
        vmid: int,
        snapshot_name: str,
        host: str,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create snapshot of container/VM.

        Args:
            vmid: VM or container VMID
            snapshot_name: Snapshot name
            host: Proxmox host address
            description: Optional description

        Returns:
            Dictionary with snapshot creation results
        """
        try:
            await self.initialize()

            parameters = {"vmid": vmid, "snapshot_name": snapshot_name, "host": host}

            if description:
                parameters["description"] = description

            result = await self.capability_executor.execute_proxmox_snapshot_create(
                parameters
            )

            if result.success:
                return {
                    "success": True,
                    "message": result.output,
                    "vmid": vmid,
                    "snapshot_name": snapshot_name,
                    "task_id": result.metadata.get("task_id")
                    if result.metadata
                    else None,
                }
            else:
                return {
                    "success": False,
                    "error": result.error,
                    "message": result.output,
                }

        except Exception as e:
            logger.error(f"Snapshot creation failed: {e}")
            return {"success": False, "error": str(e)}

    async def delete_snapshot(
        self, vmid: int, snapshot_name: str, host: str
    ) -> Dict[str, Any]:
        """Delete snapshot.

        Args:
            vmid: VM or container VMID
            snapshot_name: Snapshot name to delete
            host: Proxmox host address

        Returns:
            Dictionary with deletion results
        """
        try:
            await self.initialize()

            parameters = {"vmid": vmid, "snapshot_name": snapshot_name, "host": host}

            result = await self.capability_executor.execute_proxmox_snapshot_delete(
                parameters
            )

            if result.success:
                return {
                    "success": True,
                    "message": result.output,
                    "vmid": vmid,
                    "snapshot_name": snapshot_name,
                }
            else:
                return {
                    "success": False,
                    "error": result.error,
                    "message": result.output,
                }

        except Exception as e:
            logger.error(f"Snapshot deletion failed: {e}")
            return {"success": False, "error": str(e)}

    async def restore_snapshot(
        self, vmid: int, snapshot_name: str, host: str, rollback: bool = False
    ) -> Dict[str, Any]:
        """Restore snapshot.

        Args:
            vmid: VM or container VMID
            snapshot_name: Snapshot name to restore
            host: Proxmox host address
            rollback: Rollback to snapshot (destroy current state)

        Returns:
            Dictionary with restore results
        """
        try:
            await self.initialize()

            parameters = {
                "vmid": vmid,
                "snapshot_name": snapshot_name,
                "host": host,
                "rollback": rollback,
            }

            result = await self.capability_executor.execute_proxmox_snapshot_restore(
                parameters
            )

            if result.success:
                return {
                    "success": True,
                    "message": result.output,
                    "vmid": vmid,
                    "snapshot_name": snapshot_name,
                    "task_id": result.metadata.get("task_id")
                    if result.metadata
                    else None,
                }
            else:
                return {
                    "success": False,
                    "error": result.error,
                    "message": result.output,
                }

        except Exception as e:
            logger.error(f"Snapshot restore failed: {e}")
            return {"success": False, "error": str(e)}

    # Backup Management Tools

    async def backup_ct(
        self, container_id: int, backup_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create backup of container/VM.

        Args:
            container_id: VM or container VMID
            backup_config: Backup configuration

        Returns:
            Dictionary with backup results
        """
        try:
            await self.initialize()

            # Validate required parameters
            required_params = ["host", "storage"]
            for param in required_params:
                if param not in backup_config:
                    return {
                        "success": False,
                        "error": f"Required parameter '{param}' missing",
                    }

            parameters = {
                "vmid": container_id,
                "host": backup_config["host"],
                "storage": backup_config["storage"],
            }

            # Add optional parameters
            if "mode" in backup_config:
                parameters["mode"] = backup_config["mode"]
            if "compress" in backup_config:
                parameters["compress"] = backup_config["compress"]

            result = await self.capability_executor.execute_proxmox_backup_create(
                parameters
            )

            if result.success:
                return {
                    "success": True,
                    "message": result.output,
                    "vmid": container_id,
                    "backup_id": result.metadata.get("backup_id")
                    if result.metadata
                    else None,
                    "filename": result.metadata.get("filename")
                    if result.metadata
                    else None,
                    "size": result.metadata.get("size") if result.metadata else None,
                    "task_id": result.metadata.get("task_id")
                    if result.metadata
                    else None,
                }
            else:
                return {
                    "success": False,
                    "error": result.error,
                    "message": result.output,
                }

        except Exception as e:
            logger.error(f"Backup creation failed: {e}")
            return {"success": False, "error": str(e)}

    # Resource Management Tools

    async def update_ct_resources(
        self, container_id: int, resources: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update container resource allocation.

        Args:
            container_id: Container VMID
            resources: Resource configuration updates

        Returns:
            Dictionary with update results
        """
        try:
            await self.initialize()

            # Find API client for the host
            api_client = None
            for creds in self.api_credentials:
                if creds.host in resources.get("host", ""):
                    api_client = ProxmoxAPI(creds)
                    break

            if not api_client:
                return {
                    "success": False,
                    "error": "No API client available for resource update",
                }

            # Prepare resource updates
            resource_updates = {}
            if "cores" in resources:
                resource_updates["cores"] = resources["cores"]
            if "memory" in resources:
                resource_updates["memory"] = resources["memory"]
            if "cpu_limit" in resources:
                resource_updates["cpu"] = resources["cpu_limit"]

            result = await api_client.update_container_resources(
                container_id, resource_updates
            )

            if result.status == "updated":
                return {
                    "success": True,
                    "message": result.message,
                    "container_id": container_id,
                }
            else:
                return {"success": False, "error": result.message}

        except Exception as e:
            logger.error(f"Resource update failed: {e}")
            return {"success": False, "error": str(e)}

    # Status and Monitoring Tools

    async def get_proxmox_status(self, host: str) -> Dict[str, Any]:
        """Get Proxmox host status.

        Args:
            host: Proxmox host address

        Returns:
            Dictionary with host status information
        """
        try:
            await self.initialize()

            # Find API client for the host
            api_client = None
            for creds in self.api_credentials:
                if creds.host == host:
                    api_client = ProxmoxAPI(creds)
                    break

            if not api_client:
                return {
                    "success": False,
                    "error": f"No API client found for host {host}",
                }

            # Test connection
            connection_result = await api_client.test_connection()

            if not connection_result.success:
                return {
                    "success": False,
                    "error": connection_result.message,
                    "host": host,
                }

            # Get cluster information
            nodes = await api_client.list_nodes()
            storage = await api_client.list_storage()

            status_info = {
                "success": True,
                "host": host,
                "connected": True,
                "version": connection_result.data.get("version")
                if connection_result.data
                else None,
                "nodes": len(nodes),
                "storage_pools": len(storage),
                "nodes_info": [],
            }

            for node in nodes:
                node_info = {
                    "name": node.node,
                    "status": node.status,
                    "uptime": node.uptime,
                    "cpu_usage": node.cpu,
                    "memory_usage": node.mem,
                    "disk_usage": node.disk,
                }
                status_info["nodes_info"].append(node_info)

            return status_info

        except Exception as e:
            logger.error(f"Status check failed for {host}: {e}")
            return {"success": False, "error": str(e), "host": host}

    async def get_container_status(self, vmid: int, host: str) -> Dict[str, Any]:
        """Get container status.

        Args:
            vmid: Container VMID
            host: Proxmox host address

        Returns:
            Dictionary with container status information
        """
        try:
            await self.initialize()

            # Find API client for the host
            api_client = None
            for creds in self.api_credentials:
                if creds.host == host:
                    api_client = ProxmoxAPI(creds)
                    break

            if not api_client:
                return {
                    "success": False,
                    "error": f"No API client found for host {host}",
                }

            status_info = await api_client.get_container_status(vmid)

            return {"success": True, "vmid": vmid, "host": host, "status": status_info}

        except Exception as e:
            logger.error(f"Container status check failed for {vmid}: {e}")
            return {"success": False, "error": str(e), "vmid": vmid, "host": host}

    # Migration Tools

    async def migrate_ct(self, container_id: int, target_host: str) -> Dict[str, Any]:
        """Migrate container to target host.

        Args:
            container_id: Container VMID
            target_host: Target host address

        Returns:
            Dictionary with migration results
        """
        try:
            await self.initialize()

            # This is a complex operation that would require:
            # 1. Finding the source host
            # 2. Checking if migration is possible
            # 3. Initiating the migration
            # For now, return a placeholder response

            return {
                "success": False,
                "error": "Container migration not yet implemented",
                "container_id": container_id,
                "target_host": target_host,
            }

        except Exception as e:
            logger.error(f"Container migration failed: {e}")
            return {"success": False, "error": str(e)}

    # Utility Methods

    async def cleanup(self):
        """Cleanup Proxmox tools resources."""
        try:
            if self.capability_executor:
                await self.capability_executor.cleanup()

            if self.discovery_service:
                await self.discovery_service.cleanup()

            logger.info("Proxmox MCP tools cleaned up")

        except Exception as e:
            logger.error(f"Cleanup failed: {e}")


# MCP Tool Definitions for Registration


def get_proxmox_tool_definitions() -> List[Dict[str, Any]]:
    """Get Proxmox tool definitions for MCP registration.

    Returns:
        List of tool definitions
    """
    return [
        {
            "name": "proxmox_discover",
            "description": "Discover Proxmox hosts and their resources",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "proxmox_discover_containers",
            "description": "Discover containers on a specific Proxmox host",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Proxmox host address"}
                },
                "required": ["host"],
            },
        },
        {
            "name": "proxmox_discover_vms",
            "description": "Discover VMs on a specific Proxmox host",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Proxmox host address"}
                },
                "required": ["host"],
            },
        },
        {
            "name": "create_ct_from_template",
            "description": "Create a container from a template",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "template_id": {
                        "type": "integer",
                        "description": "Template container ID",
                    },
                    "config": {
                        "type": "object",
                        "properties": {
                            "host": {
                                "type": "string",
                                "description": "Proxmox host address",
                            },
                            "template": {
                                "type": "string",
                                "description": "Container template path",
                            },
                            "hostname": {
                                "type": "string",
                                "description": "Container hostname",
                            },
                            "cores": {
                                "type": "integer",
                                "description": "Number of CPU cores",
                            },
                            "memory": {
                                "type": "integer",
                                "description": "Memory in MB",
                            },
                            "rootfs": {
                                "type": "string",
                                "description": "Root filesystem configuration",
                            },
                            "network_bridge": {
                                "type": "string",
                                "description": "Network bridge",
                            },
                            "ip_address": {
                                "type": "string",
                                "description": "IP address",
                            },
                            "password": {
                                "type": "string",
                                "description": "Root password",
                            },
                            "ssh_keys": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "SSH public keys",
                            },
                        },
                        "required": ["host", "template", "hostname"],
                    },
                },
                "required": ["template_id", "config"],
            },
        },
        {
            "name": "start_ct",
            "description": "Start a container",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vmid": {"type": "integer", "description": "Container VMID"},
                    "host": {"type": "string", "description": "Proxmox host address"},
                },
                "required": ["vmid", "host"],
            },
        },
        {
            "name": "stop_ct",
            "description": "Stop a container",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vmid": {"type": "integer", "description": "Container VMID"},
                    "host": {"type": "string", "description": "Proxmox host address"},
                    "force": {
                        "type": "boolean",
                        "description": "Force stop",
                        "default": False,
                    },
                },
                "required": ["vmid", "host"],
            },
        },
        {
            "name": "reboot_ct",
            "description": "Reboot a container",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vmid": {"type": "integer", "description": "Container VMID"},
                    "host": {"type": "string", "description": "Proxmox host address"},
                },
                "required": ["vmid", "host"],
            },
        },
        {
            "name": "delete_ct",
            "description": "Delete a container",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vmid": {"type": "integer", "description": "Container VMID"},
                    "host": {"type": "string", "description": "Proxmox host address"},
                },
                "required": ["vmid", "host"],
            },
        },
        {
            "name": "clone_ct",
            "description": "Clone a container",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "source_vmid": {
                        "type": "integer",
                        "description": "Source container VMID",
                    },
                    "clone_config": {
                        "type": "object",
                        "properties": {
                            "host": {
                                "type": "string",
                                "description": "Proxmox host address",
                            },
                            "new_hostname": {
                                "type": "string",
                                "description": "New container hostname",
                            },
                            "new_vmid": {"type": "integer", "description": "New VMID"},
                            "full_clone": {
                                "type": "boolean",
                                "description": "Full clone",
                                "default": True,
                            },
                        },
                        "required": ["host", "new_hostname"],
                    },
                },
                "required": ["source_vmid", "clone_config"],
            },
        },
        {
            "name": "snapshot_ct",
            "description": "Create snapshot of container/VM",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vmid": {"type": "integer", "description": "VM or container VMID"},
                    "snapshot_name": {"type": "string", "description": "Snapshot name"},
                    "host": {"type": "string", "description": "Proxmox host address"},
                    "description": {
                        "type": "string",
                        "description": "Optional description",
                    },
                },
                "required": ["vmid", "snapshot_name", "host"],
            },
        },
        {
            "name": "delete_snapshot",
            "description": "Delete a snapshot",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vmid": {"type": "integer", "description": "VM or container VMID"},
                    "snapshot_name": {
                        "type": "string",
                        "description": "Snapshot name to delete",
                    },
                    "host": {"type": "string", "description": "Proxmox host address"},
                },
                "required": ["vmid", "snapshot_name", "host"],
            },
        },
        {
            "name": "restore_snapshot",
            "description": "Restore a snapshot",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vmid": {"type": "integer", "description": "VM or container VMID"},
                    "snapshot_name": {
                        "type": "string",
                        "description": "Snapshot name to restore",
                    },
                    "host": {"type": "string", "description": "Proxmox host address"},
                    "rollback": {
                        "type": "boolean",
                        "description": "Rollback to snapshot",
                        "default": False,
                    },
                },
                "required": ["vmid", "snapshot_name", "host"],
            },
        },
        {
            "name": "backup_ct",
            "description": "Create backup of container/VM",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "container_id": {
                        "type": "integer",
                        "description": "VM or container VMID",
                    },
                    "backup_config": {
                        "type": "object",
                        "properties": {
                            "host": {
                                "type": "string",
                                "description": "Proxmox host address",
                            },
                            "storage": {
                                "type": "string",
                                "description": "Storage pool for backup",
                            },
                            "mode": {
                                "type": "string",
                                "enum": ["snapshot", "suspend", "stop"],
                                "description": "Backup mode",
                            },
                            "compress": {
                                "type": "string",
                                "enum": ["gzip", "lzo", "zstd"],
                                "description": "Compression",
                            },
                        },
                        "required": ["host", "storage"],
                    },
                },
                "required": ["container_id", "backup_config"],
            },
        },
        {
            "name": "update_ct_resources",
            "description": "Update container resource allocation",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "container_id": {
                        "type": "integer",
                        "description": "Container VMID",
                    },
                    "resources": {
                        "type": "object",
                        "properties": {
                            "host": {
                                "type": "string",
                                "description": "Proxmox host address",
                            },
                            "cores": {
                                "type": "integer",
                                "description": "Number of CPU cores",
                            },
                            "memory": {
                                "type": "integer",
                                "description": "Memory in MB",
                            },
                            "cpu_limit": {"type": "number", "description": "CPU limit"},
                        },
                        "required": ["host"],
                    },
                },
                "required": ["container_id", "resources"],
            },
        },
        {
            "name": "get_proxmox_status",
            "description": "Get Proxmox host status",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Proxmox host address"}
                },
                "required": ["host"],
            },
        },
        {
            "name": "get_container_status",
            "description": "Get container status",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vmid": {"type": "integer", "description": "Container VMID"},
                    "host": {"type": "string", "description": "Proxmox host address"},
                },
                "required": ["vmid", "host"],
            },
        },
        {
            "name": "migrate_ct",
            "description": "Migrate container to target host",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "container_id": {
                        "type": "integer",
                        "description": "Container VMID",
                    },
                    "target_host": {
                        "type": "string",
                        "description": "Target host address",
                    },
                },
                "required": ["container_id", "target_host"],
            },
        },
    ]
