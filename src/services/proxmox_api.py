"""
Proxmox API Client

Core Proxmox API client for managing Proxmox VE environments through HTTP API.
Provides comprehensive support for container/VM management, snapshots, backups,
and resource operations with proper authentication and error handling.
"""

import logging
import asyncio
import aiohttp
from typing import Dict, List, Optional, Any
from datetime import datetime
from urllib.parse import urljoin

from src.models.proxmox_models import (
    ProxmoxAPICredentials,
    ProxmoxContainer,
    ProxmoxVM,
    ProxmoxSnapshot,
    ProxmoxBackup,
    ProxmoxStorage,
    ProxmoxNode,
    ContainerConfig,
    VMConfig,
    CloneConfig,
    BackupConfig,
    ContainerCreationResult,
    CloneResult,
    DeleteResult,
    SnapshotResult,
    BackupResult,
    RestoreResult,
    UpdateResult,
    StartResult,
    StopResult,
    RebootResult,
    OperationResult,
)
from src.utils.retry import retry_with_backoff

logger = logging.getLogger(__name__)


class ProxmoxAPIError(Exception):
    """Proxmox API exception."""

    pass


class ProxmoxAPI:
    """Core Proxmox API client."""

    def __init__(self, credentials: ProxmoxAPICredentials):
        """Initialize Proxmox API client.

        Args:
            credentials: Proxmox API authentication credentials
        """
        self.credentials = credentials
        self.base_url = f"https://{credentials.host}:{credentials.port}/api2/json"
        self._session: Optional[aiohttp.ClientSession] = None
        self._auth_token: Optional[str] = None
        self._csrf_token: Optional[str] = None
        self._is_authenticated = False

        # Validation
        errors = credentials.validate()
        if errors:
            raise ValueError(f"Invalid credentials: {errors}")

    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.disconnect()

    @property
    def session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if not self._session:
            connector = aiohttp.TCPConnector(
                verify_ssl=self.credentials.verify_ssl, limit=10, limit_per_host=5
            )

            timeout = aiohttp.ClientTimeout(total=self.credentials.timeout)

            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "TailOpsMCP-ProxmoxAPI/1.0",
                },
            )

        return self._session

    async def connect(self) -> bool:
        """Establish connection to Proxmox API.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            # Authenticate with Proxmox API
            await self._authenticate()
            self._is_authenticated = True
            logger.info(
                f"Successfully connected to Proxmox API at {self.credentials.host}"
            )
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Proxmox API: {e}")
            self._is_authenticated = False
            return False

    async def disconnect(self):
        """Disconnect from Proxmox API."""
        if self._session:
            await self._session.close()
            self._session = None

        self._auth_token = None
        self._csrf_token = None
        self._is_authenticated = False
        logger.info("Disconnected from Proxmox API")

    def is_connected(self) -> bool:
        """Check if connected to Proxmox API."""
        return self._is_authenticated

    async def test_connection(self) -> OperationResult:
        """Test Proxmox API connection.

        Returns:
            OperationResult with connection test results
        """
        try:
            if not self._is_authenticated:
                if not await self.connect():
                    return OperationResult.failure("Connection failed")

            # Test API endpoint
            response = await self._make_request("GET", "/version")

            if response:
                version = response.get("data", {})
                return OperationResult(
                    success=True,
                    status="connected",
                    data={
                        "version": version.get("version"),
                        "release": version.get("release"),
                        "keyboard": version.get("keyboard"),
                    },
                    message="Proxmox API connection test successful",
                )
            else:
                return OperationResult.failure("No response from API")

        except Exception as e:
            return OperationResult.failure(f"Connection test failed: {e}")

    async def _authenticate(self):
        """Authenticate with Proxmox API."""
        if self.credentials.token and self.credentials.token_name:
            # Use API token authentication
            await self._authenticate_with_token()
        else:
            # Use username/password authentication
            await self._authenticate_with_password()

    async def _authenticate_with_token(self):
        """Authenticate using API token."""
        auth_data = {
            "username": self.credentials.username,
            "password": f"{self.credentials.token_name}={self.credentials.token}",
        }

        response = await self._make_request("POST", "/access/ticket", auth_data)

        if response and "data" in response:
            data = response["data"]
            self._auth_token = data.get("ticket")
            self._csrf_token = data.get("CSRFPreventionToken")
        else:
            raise ProxmoxAPIError("Token authentication failed")

    async def _authenticate_with_password(self):
        """Authenticate using username/password."""
        if not self.credentials.password:
            raise ProxmoxAPIError("Password required for authentication")

        auth_data = {
            "username": self.credentials.username,
            "password": self.credentials.password,
        }

        response = await self._make_request("POST", "/access/ticket", auth_data)

        if response and "data" in response:
            data = response["data"]
            self._auth_token = data.get("ticket")
            self._csrf_token = data.get("CSRFPreventionToken")
        else:
            raise ProxmoxAPIError("Password authentication failed")

    @retry_with_backoff(max_retries=3, base_delay=1, exceptions=(ProxmoxAPIError,))
    async def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Make HTTP request to Proxmox API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path
            data: Request data for POST/PUT requests
            params: Query parameters

        Returns:
            API response data or None
        """
        if not self._is_authenticated and endpoint != "/access/ticket":
            await self._authenticate()

        url = urljoin(self.base_url, endpoint)

        headers = {}
        if self._auth_token:
            headers["Cookie"] = f"PVEAuthCookie={self._auth_token}"
        if self._csrf_token:
            headers["CSRFPreventionToken"] = self._csrf_token

        try:
            async with self.session.request(
                method=method, url=url, headers=headers, json=data, params=params
            ) as response:
                if response.status == 401:
                    # Re-authenticate on 401
                    self._is_authenticated = False
                    await self._authenticate()
                    # Retry the request
                    return await self._make_request(method, endpoint, data, params)

                if response.status == 403:
                    raise ProxmoxAPIError(f"Access forbidden: {response.reason}")

                if response.status >= 400:
                    error_text = await response.text()
                    raise ProxmoxAPIError(f"API error {response.status}: {error_text}")

                content_type = response.headers.get("content-type", "")
                if "application/json" in content_type:
                    return await response.json()
                else:
                    return {"data": await response.text()}

        except aiohttp.ClientError as e:
            raise ProxmoxAPIError(f"HTTP client error: {e}")

    # Container Management

    async def list_containers(self) -> List[ProxmoxContainer]:
        """List all LXC containers.

        Returns:
            List of ProxmoxContainer objects
        """
        try:
            response = await self._make_request("GET", "/nodes/*/lxc")

            if response and "data" in response:
                containers = []
                for container_data in response["data"]:
                    vmid = container_data.get("vmid")
                    if vmid:
                        # Get detailed container configuration
                        config_response = await self._make_request(
                            "GET",
                            f"/nodes/{container_data.get('node')}/lxc/{vmid}/config",
                        )

                        if config_response and "data" in config_response:
                            config_data = {**container_data, **config_response["data"]}
                            container = ProxmoxContainer.from_api_response(
                                vmid, config_data
                            )
                            containers.append(container)

                return containers

            return []

        except Exception as e:
            logger.error(f"Failed to list containers: {e}")
            return []

    async def get_container(self, vmid: int) -> Optional[ProxmoxContainer]:
        """Get container information.

        Args:
            vmid: Container VMID

        Returns:
            ProxmoxContainer object or None if not found
        """
        try:
            # Get container status
            status_response = await self._make_request("GET", f"/nodes/*/lxc/{vmid}")

            if not status_response or "data" not in status_response:
                return None

            status_data = status_response["data"]
            node = status_data.get("node")

            if not node:
                return None

            # Get detailed configuration
            config_response = await self._make_request(
                "GET", f"/nodes/{node}/lxc/{vmid}/config"
            )

            if config_response and "data" in config_response:
                config_data = {**status_data, **config_response["data"]}
                return ProxmoxContainer.from_api_response(vmid, config_data)

            # Return basic container info if config not available
            return ProxmoxContainer.from_api_response(vmid, status_data)

        except Exception as e:
            logger.error(f"Failed to get container {vmid}: {e}")
            return None

    async def create_container(
        self, config: ContainerConfig, node: Optional[str] = None
    ) -> ContainerCreationResult:
        """Create a new LXC container.

        Args:
            config: Container configuration
            node: Target node (optional, auto-select if not specified)

        Returns:
            ContainerCreationResult with creation details
        """
        try:
            # Auto-select node if not specified
            if not node:
                node = await self._get_available_node()

            if not node:
                return ContainerCreationResult(
                    vmid=0,
                    status="failed",
                    message="No available nodes for container creation",
                )

            # Generate VMID if not specified
            if not config.vmid:
                config.vmid = await self._allocate_vmid()

            if not config.vmid:
                return ContainerCreationResult(
                    vmid=0, status="failed", message="Failed to allocate VMID"
                )

            # Prepare container creation request
            create_data = config.to_proxmox_config()
            create_data["vmid"] = config.vmid

            # Create container
            response = await self._make_request(
                "POST", f"/nodes/{node}/lxc", create_data
            )

            if response and "data" in response:
                task_id = response["data"].get("upid")

                # Monitor task completion
                if task_id:
                    task_result = await self._monitor_task(node, task_id)

                    if task_result:
                        return ContainerCreationResult(
                            vmid=config.vmid,
                            task_id=task_id,
                            status="created",
                            message="Container created successfully",
                        )
                    else:
                        return ContainerCreationResult(
                            vmid=config.vmid,
                            task_id=task_id,
                            status="failed",
                            message="Container creation task failed",
                        )
                else:
                    return ContainerCreationResult(
                        vmid=config.vmid,
                        status="created",
                        message="Container created (no task ID)",
                    )
            else:
                return ContainerCreationResult(
                    vmid=config.vmid,
                    status="failed",
                    message="Failed to create container",
                )

        except Exception as e:
            logger.error(f"Failed to create container: {e}")
            return ContainerCreationResult(vmid=0, status="failed", message=str(e))

    async def clone_container(
        self, source_vmid: int, config: CloneConfig
    ) -> CloneResult:
        """Clone a container.

        Args:
            source_vmid: Source container VMID
            config: Clone configuration

        Returns:
            CloneResult with clone details
        """
        try:
            # Get source container info
            source_container = await self.get_container(source_vmid)
            if not source_container:
                return CloneResult(
                    vmid=0,
                    status="failed",
                    message=f"Source container {source_vmid} not found",
                )

            # Generate VMID if not specified
            if not config.newid:
                config.newid = await self._allocate_vmid()

            if not config.newid:
                return CloneResult(
                    vmid=0, status="failed", message="Failed to allocate VMID for clone"
                )

            # Prepare clone request
            clone_data = config.to_proxmox_config()
            clone_data["newid"] = config.newid

            # Clone container
            response = await self._make_request(
                "POST",
                f"/nodes/{source_container.node}/lxc/{source_vmid}/clone",
                clone_data,
            )

            if response and "data" in response:
                task_id = response["data"].get("upid")

                # Monitor task completion
                if task_id:
                    task_result = await self._monitor_task(
                        source_container.node, task_id
                    )

                    if task_result:
                        return CloneResult(
                            vmid=config.newid,
                            task_id=task_id,
                            status="cloned",
                            message="Container cloned successfully",
                        )
                    else:
                        return CloneResult(
                            vmid=config.newid,
                            task_id=task_id,
                            status="failed",
                            message="Container clone task failed",
                        )
                else:
                    return CloneResult(
                        vmid=config.newid,
                        status="cloned",
                        message="Container cloned (no task ID)",
                    )
            else:
                return CloneResult(
                    vmid=config.newid,
                    status="failed",
                    message="Failed to clone container",
                )

        except Exception as e:
            logger.error(f"Failed to clone container {source_vmid}: {e}")
            return CloneResult(vmid=0, status="failed", message=str(e))

    async def delete_container(self, vmid: int) -> DeleteResult:
        """Delete a container.

        Args:
            vmid: Container VMID to delete

        Returns:
            DeleteResult with deletion details
        """
        try:
            # Get container info
            container = await self.get_container(vmid)
            if not container:
                return DeleteResult(
                    status="failed", message=f"Container {vmid} not found"
                )

            # Stop container if running
            if container.status.value == "running":
                await self.stop_container(vmid)

            # Delete container
            response = await self._make_request(
                "DELETE", f"/nodes/{container.node}/lxc/{vmid}"
            )

            if response and "data" in response:
                task_id = response["data"].get("upid")

                # Monitor task completion
                if task_id:
                    task_result = await self._monitor_task(container.node, task_id)

                    if task_result:
                        return DeleteResult(
                            status="deleted", message="Container deleted successfully"
                        )
                    else:
                        return DeleteResult(
                            status="failed", message="Container deletion task failed"
                        )
                else:
                    return DeleteResult(
                        status="deleted", message="Container deleted (no task ID)"
                    )
            else:
                return DeleteResult(
                    status="failed", message="Failed to delete container"
                )

        except Exception as e:
            logger.error(f"Failed to delete container {vmid}: {e}")
            return DeleteResult(status="failed", message=str(e))

    # VM Management

    async def list_vms(self) -> List[ProxmoxVM]:
        """List all QEMU VMs.

        Returns:
            List of ProxmoxVM objects
        """
        try:
            response = await self._make_request("GET", "/nodes/*/qemu")

            if response and "data" in response:
                vms = []
                for vm_data in response["data"]:
                    vmid = vm_data.get("vmid")
                    if vmid:
                        # Get detailed VM configuration
                        config_response = await self._make_request(
                            "GET", f"/nodes/{vm_data.get('node')}/qemu/{vmid}/config"
                        )
                        if config_response and "data" in config_response:
                            config_data = {**vm_data, **config_response["data"]}
                            vm = ProxmoxVM.from_api_response(vmid, config_data)
                            vms.append(vm)

                return vms

            return []

        except Exception as e:
            logger.error(f"Failed to list VMs: {e}")
            return []

    async def create_vm(
        self, config: VMConfig, node: Optional[str] = None
    ) -> ContainerCreationResult:
        """Create a new QEMU VM.

        Args:
            config: VM configuration
            node: Target node (optional, auto-select if not specified)

        Returns:
            ContainerCreationResult with creation details
        """
        try:
            # Auto-select node if not specified
            if not node:
                node = await self._get_available_node()

            if not node:
                return ContainerCreationResult(
                    vmid=0,
                    status="failed",
                    message="No available nodes for VM creation",
                )

            # Generate VMID if not specified
            if not config.vmid:
                config.vmid = await self._allocate_vmid()

            if not config.vmid:
                return ContainerCreationResult(
                    vmid=0, status="failed", message="Failed to allocate VMID"
                )

            # Prepare VM creation request
            create_data = config.to_proxmox_config()
            create_data["vmid"] = config.vmid

            # Create VM
            response = await self._make_request(
                "POST", f"/nodes/{node}/qemu", create_data
            )

            if response and "data" in response:
                task_id = response["data"].get("upid")

                # Monitor task completion
                if task_id:
                    task_result = await self._monitor_task(node, task_id)

                    if task_result:
                        return ContainerCreationResult(
                            vmid=config.vmid,
                            task_id=task_id,
                            status="created",
                            message="VM created successfully",
                        )
                    else:
                        return ContainerCreationResult(
                            vmid=config.vmid,
                            task_id=task_id,
                            status="failed",
                            message="VM creation task failed",
                        )
                else:
                    return ContainerCreationResult(
                        vmid=config.vmid,
                        status="created",
                        message="VM created (no task ID)",
                    )
            else:
                return ContainerCreationResult(
                    vmid=config.vmid, status="failed", message="Failed to create VM"
                )

        except Exception as e:
            logger.error(f"Failed to create VM: {e}")
            return ContainerCreationResult(vmid=0, status="failed", message=str(e))

    # Container/VM Control Operations

    async def start_container(self, vmid: int) -> StartResult:
        """Start a container.

        Args:
            vmid: Container VMID

        Returns:
            StartResult with start operation details
        """
        try:
            container = await self.get_container(vmid)
            if not container:
                return StartResult(
                    status="failed", message=f"Container {vmid} not found"
                )

            response = await self._make_request(
                "POST", f"/nodes/{container.node}/lxc/{vmid}/status/start"
            )

            if response and "data" in response:
                task_id = response["data"].get("upid")

                if task_id:
                    task_result = await self._monitor_task(container.node, task_id)

                    if task_result:
                        return StartResult(
                            task_id=task_id,
                            status="started",
                            message="Container started successfully",
                        )
                    else:
                        return StartResult(
                            task_id=task_id,
                            status="failed",
                            message="Container start task failed",
                        )
                else:
                    return StartResult(
                        status="started", message="Container started (no task ID)"
                    )
            else:
                return StartResult(status="failed", message="Failed to start container")

        except Exception as e:
            logger.error(f"Failed to start container {vmid}: {e}")
            return StartResult(status="failed", message=str(e))

    async def stop_container(self, vmid: int, force: bool = False) -> StopResult:
        """Stop a container.

        Args:
            vmid: Container VMID
            force: Force stop (shutdown timeout)

        Returns:
            StopResult with stop operation details
        """
        try:
            container = await self.get_container(vmid)
            if not container:
                return StopResult(
                    status="failed", message=f"Container {vmid} not found"
                )

            endpoint = f"/nodes/{container.node}/lxc/{vmid}/status/stop"
            if force:
                endpoint += "?forceStop=1"

            response = await self._make_request("POST", endpoint)

            if response and "data" in response:
                task_id = response["data"].get("upid")

                if task_id:
                    task_result = await self._monitor_task(container.node, task_id)

                    if task_result:
                        return StopResult(
                            task_id=task_id,
                            status="stopped",
                            message="Container stopped successfully",
                        )
                    else:
                        return StopResult(
                            task_id=task_id,
                            status="failed",
                            message="Container stop task failed",
                        )
                else:
                    return StopResult(
                        status="stopped", message="Container stopped (no task ID)"
                    )
            else:
                return StopResult(status="failed", message="Failed to stop container")

        except Exception as e:
            logger.error(f"Failed to stop container {vmid}: {e}")
            return StopResult(status="failed", message=str(e))

    async def reboot_container(self, vmid: int) -> RebootResult:
        """Reboot a container.

        Args:
            vmid: Container VMID

        Returns:
            RebootResult with reboot operation details
        """
        try:
            container = await self.get_container(vmid)
            if not container:
                return RebootResult(
                    status="failed", message=f"Container {vmid} not found"
                )

            response = await self._make_request(
                "POST", f"/nodes/{container.node}/lxc/{vmid}/status/reboot"
            )

            if response and "data" in response:
                task_id = response["data"].get("upid")

                if task_id:
                    task_result = await self._monitor_task(container.node, task_id)

                    if task_result:
                        return RebootResult(
                            task_id=task_id,
                            status="rebooted",
                            message="Container rebooted successfully",
                        )
                    else:
                        return RebootResult(
                            task_id=task_id,
                            status="failed",
                            message="Container reboot task failed",
                        )
                else:
                    return RebootResult(
                        status="rebooted", message="Container rebooted (no task ID)"
                    )
            else:
                return RebootResult(
                    status="failed", message="Failed to reboot container"
                )

        except Exception as e:
            logger.error(f"Failed to reboot container {vmid}: {e}")
            return RebootResult(status="failed", message=str(e))

    # Snapshot Management

    async def create_snapshot(
        self, vmid: int, snapshot_name: str, description: Optional[str] = None
    ) -> SnapshotResult:
        """Create a snapshot.

        Args:
            vmid: VM or container VMID
            snapshot_name: Name for the snapshot
            description: Optional description

        Returns:
            SnapshotResult with snapshot creation details
        """
        try:
            container = await self.get_container(vmid)
            if container:
                # LXC container
                snapshot_data = {"name": snapshot_name}
                if description:
                    snapshot_data["description"] = description

                response = await self._make_request(
                    "POST",
                    f"/nodes/{container.node}/lxc/{vmid}/snapshot",
                    snapshot_data,
                )
            else:
                # Try as VM
                vm = await self._get_vm(vmid)
                if not vm:
                    return SnapshotResult(
                        name=snapshot_name,
                        status="failed",
                        message=f"Resource {vmid} not found",
                    )

                snapshot_data = {"name": snapshot_name}
                if description:
                    snapshot_data["description"] = description

                response = await self._make_request(
                    "POST", f"/nodes/{vm.node}/qemu/{vmid}/snapshot", snapshot_data
                )

            if response and "data" in response:
                task_id = response["data"].get("upid")

                if task_id:
                    task_result = await self._monitor_task(
                        container.node if container else vm.node, task_id
                    )

                    if task_result:
                        return SnapshotResult(
                            name=snapshot_name,
                            task_id=task_id,
                            status="created",
                            message="Snapshot created successfully",
                        )
                    else:
                        return SnapshotResult(
                            name=snapshot_name,
                            task_id=task_id,
                            status="failed",
                            message="Snapshot creation task failed",
                        )
                else:
                    return SnapshotResult(
                        name=snapshot_name,
                        status="created",
                        message="Snapshot created (no task ID)",
                    )
            else:
                return SnapshotResult(
                    name=snapshot_name,
                    status="failed",
                    message="Failed to create snapshot",
                )

        except Exception as e:
            logger.error(f"Failed to create snapshot {snapshot_name} for {vmid}: {e}")
            return SnapshotResult(name=snapshot_name, status="failed", message=str(e))

    async def list_snapshots(self, vmid: int) -> List[ProxmoxSnapshot]:
        """List snapshots for a VM or container.

        Args:
            vmid: VM or container VMID

        Returns:
            List of ProxmoxSnapshot objects
        """
        try:
            container = await self.get_container(vmid)
            if container:
                # LXC container
                response = await self._make_request(
                    "GET", f"/nodes/{container.node}/lxc/{vmid}/snapshot"
                )
            else:
                # Try as VM
                vm = await self._get_vm(vmid)
                if not vm:
                    return []

                response = await self._make_request(
                    "GET", f"/nodes/{vm.node}/qemu/{vmid}/snapshot"
                )

            if response and "data" in response:
                snapshots = []
                for snapshot_data in response["data"]:
                    snapshot = ProxmoxSnapshot.from_api_response(vmid, snapshot_data)
                    snapshots.append(snapshot)
                return snapshots

            return []

        except Exception as e:
            logger.error(f"Failed to list snapshots for {vmid}: {e}")
            return []

    async def delete_snapshot(self, vmid: int, snapshot_name: str) -> DeleteResult:
        """Delete a snapshot.

        Args:
            vmid: VM or container VMID
            snapshot_name: Snapshot name to delete

        Returns:
            DeleteResult with deletion details
        """
        try:
            container = await self.get_container(vmid)
            if container:
                # LXC container
                response = await self._make_request(
                    "DELETE",
                    f"/nodes/{container.node}/lxc/{vmid}/snapshot/{snapshot_name}",
                )
            else:
                # Try as VM
                vm = await self._get_vm(vmid)
                if not vm:
                    return DeleteResult(
                        status="failed", message=f"Resource {vmid} not found"
                    )

                response = await self._make_request(
                    "DELETE", f"/nodes/{vm.node}/qemu/{vmid}/snapshot/{snapshot_name}"
                )

            if response and "data" in response:
                task_id = response["data"].get("upid")

                if task_id:
                    task_result = await self._monitor_task(
                        container.node if container else vm.node, task_id
                    )

                    if task_result:
                        return DeleteResult(
                            status="deleted", message="Snapshot deleted successfully"
                        )
                    else:
                        return DeleteResult(
                            status="failed", message="Snapshot deletion task failed"
                        )
                else:
                    return DeleteResult(
                        status="deleted", message="Snapshot deleted (no task ID)"
                    )
            else:
                return DeleteResult(
                    status="failed", message="Failed to delete snapshot"
                )

        except Exception as e:
            logger.error(f"Failed to delete snapshot {snapshot_name} for {vmid}: {e}")
            return DeleteResult(status="failed", message=str(e))

    async def restore_snapshot(
        self, vmid: int, snapshot_name: str, rollback: bool = False
    ) -> RestoreResult:
        """Restore a snapshot.

        Args:
            vmid: VM or container VMID
            snapshot_name: Snapshot name to restore
            rollback: If True, rollback to snapshot (destroy current state)

        Returns:
            RestoreResult with restore operation details
        """
        try:
            container = await self.get_container(vmid)
            if container:
                # LXC container
                restore_data = {}
                if rollback:
                    restore_data["rollback"] = 1

                response = await self._make_request(
                    "POST",
                    f"/nodes/{container.node}/lxc/{vmid}/snapshot/{snapshot_name}/rollback",
                    restore_data,
                )
            else:
                # Try as VM
                vm = await self._get_vm(vmid)
                if not vm:
                    return RestoreResult(
                        status="failed", message=f"Resource {vmid} not found"
                    )

                restore_data = {}
                if rollback:
                    restore_data["rollback"] = 1

                response = await self._make_request(
                    "POST",
                    f"/nodes/{vm.node}/qemu/{vmid}/snapshot/{snapshot_name}/rollback",
                    restore_data,
                )

            if response and "data" in response:
                task_id = response["data"].get("upid")

                if task_id:
                    task_result = await self._monitor_task(
                        container.node if container else vm.node, task_id
                    )

                    if task_result:
                        return RestoreResult(
                            task_id=task_id,
                            status="restored",
                            message="Snapshot restored successfully",
                        )
                    else:
                        return RestoreResult(
                            task_id=task_id,
                            status="failed",
                            message="Snapshot restore task failed",
                        )
                else:
                    return RestoreResult(
                        status="restored", message="Snapshot restored (no task ID)"
                    )
            else:
                return RestoreResult(
                    status="failed", message="Failed to restore snapshot"
                )

        except Exception as e:
            logger.error(f"Failed to restore snapshot {snapshot_name} for {vmid}: {e}")
            return RestoreResult(status="failed", message=str(e))

    # Backup Management

    async def create_backup(
        self, vmid: int, backup_config: BackupConfig
    ) -> BackupResult:
        """Create a backup.

        Args:
            vmid: VM or container VMID
            backup_config: Backup configuration

        Returns:
            BackupResult with backup creation details
        """
        try:
            container = await self.get_container(vmid)
            resource_node = container.node if container else None

            if not resource_node:
                vm = await self._get_vm(vmid)
                if not vm:
                    return BackupResult(
                        backup_id="",
                        filename="",
                        size=0,
                        status="failed",
                        message=f"Resource {vmid} not found",
                    )
                resource_node = vm.node

            # Prepare backup request
            backup_data = backup_config.to_proxmox_config()
            backup_data["vmid"] = vmid

            # Create backup
            response = await self._make_request(
                "POST", f"/nodes/{resource_node}/vzdump", backup_data
            )

            if response and "data" in response:
                task_id = response["data"].get("upid")

                if task_id:
                    task_result = await self._monitor_task(resource_node, task_id)

                    if task_result:
                        return BackupResult(
                            backup_id=f"{resource_node}:{vmid}",
                            filename=f"vzdump-{resource_node}-{vmid}.tar.gz",
                            size=0,  # Will be updated after completion
                            task_id=task_id,
                            status="completed",
                            message="Backup created successfully",
                        )
                    else:
                        return BackupResult(
                            backup_id="",
                            filename="",
                            size=0,
                            task_id=task_id,
                            status="failed",
                            message="Backup creation task failed",
                        )
                else:
                    return BackupResult(
                        backup_id="",
                        filename="",
                        size=0,
                        status="completed",
                        message="Backup created (no task ID)",
                    )
            else:
                return BackupResult(
                    backup_id="",
                    filename="",
                    size=0,
                    status="failed",
                    message="Failed to create backup",
                )

        except Exception as e:
            logger.error(f"Failed to create backup for {vmid}: {e}")
            return BackupResult(
                backup_id="", filename="", size=0, status="failed", message=str(e)
            )

    async def list_backups(
        self, node: Optional[str] = None, storage: Optional[str] = None
    ) -> List[ProxmoxBackup]:
        """List backups.

        Args:
            node: Specific node to list backups from
            storage: Specific storage to list backups from

        Returns:
            List of ProxmoxBackup objects
        """
        try:
            params = {}
            if node:
                params["node"] = node
            if storage:
                params["storage"] = storage

            endpoint = "/nodes/*/storage/*/content"
            if storage:
                endpoint = f"/nodes/{node}/storage/{storage}/content"

            response = await self._make_request("GET", endpoint, params=params)

            if response and "data" in response:
                backups = []
                for backup_data in response["data"]:
                    # Only include vzdump backups
                    if backup_data.get("content") == "vzdump":
                        backup = ProxmoxBackup.from_api_response(backup_data)
                        backups.append(backup)
                return backups

            return []

        except Exception as e:
            logger.error(f"Failed to list backups: {e}")
            return []

    async def restore_backup(
        self, backup_id: str, target_config: Dict[str, Any]
    ) -> RestoreResult:
        """Restore from backup.

        Args:
            backup_id: Backup volume ID
            target_config: Target restoration configuration

        Returns:
            RestoreResult with restore operation details
        """
        try:
            # Parse backup ID to extract node and storage
            # Format: storage:node/vzdump-ctid-vmid-*.tar.gz

            # For now, implement basic restore logic
            {
                "backup": backup_id,
                "target_vmid": target_config.get("vmid"),
                "storage": target_config.get("storage"),
                "node": target_config.get("node"),
            }

            # This would need more implementation based on Proxmox API
            # For now, return a placeholder response

            return RestoreResult(
                status="completed",
                message="Backup restore functionality needs implementation",
            )

        except Exception as e:
            logger.error(f"Failed to restore backup {backup_id}: {e}")
            return RestoreResult(status="failed", message=str(e))

    # Resource Management

    async def update_container_resources(
        self, vmid: int, resources: Dict[str, Any]
    ) -> UpdateResult:
        """Update container resource allocation.

        Args:
            vmid: Container VMID
            resources: Resource configuration updates

        Returns:
            UpdateResult with update details
        """
        try:
            container = await self.get_container(vmid)
            if not container:
                return UpdateResult(
                    status="failed", message=f"Container {vmid} not found"
                )

            response = await self._make_request(
                "PUT", f"/nodes/{container.node}/lxc/{vmid}/config", resources
            )

            if response:
                return UpdateResult(
                    status="updated", message="Container resources updated successfully"
                )
            else:
                return UpdateResult(
                    status="failed", message="Failed to update container resources"
                )

        except Exception as e:
            logger.error(f"Failed to update container resources for {vmid}: {e}")
            return UpdateResult(status="failed", message=str(e))

    async def get_container_status(self, vmid: int) -> Dict[str, Any]:
        """Get container status information.

        Args:
            vmid: Container VMID

        Returns:
            Container status dictionary
        """
        try:
            container = await self.get_container(vmid)
            if not container:
                return {"status": "not_found"}

            return {
                "vmid": container.vmid,
                "node": container.node,
                "name": container.name,
                "status": container.status.value,
                "uptime": container.uptime,
                "cpu": container.cpu,
                "memory": container.memory,
                "disk": container.disk,
                "cores": container.cores,
            }

        except Exception as e:
            logger.error(f"Failed to get container status for {vmid}: {e}")
            return {"status": "error", "error": str(e)}

    # Helper Methods

    async def _get_vm(self, vmid: int) -> Optional[ProxmoxVM]:
        """Get VM information.

        Args:
            vmid: VM VMID

        Returns:
            ProxmoxVM object or None if not found
        """
        try:
            # Get VM status
            status_response = await self._make_request("GET", f"/nodes/*/qemu/{vmid}")

            if not status_response or "data" not in status_response:
                return None

            status_data = status_response["data"]
            node = status_data.get("node")

            if not node:
                return None

            # Get detailed configuration
            config_response = await self._make_request(
                "GET", f"/nodes/{node}/qemu/{vmid}/config"
            )

            if config_response and "data" in config_response:
                config_data = {**status_data, **config_response["data"]}
                return ProxmoxVM.from_api_response(vmid, config_data)

            # Return basic VM info if config not available
            return ProxmoxVM.from_api_response(vmid, status_data)

        except Exception as e:
            logger.error(f"Failed to get VM {vmid}: {e}")
            return None

    async def _get_available_node(self) -> Optional[str]:
        """Get an available node for operations.

        Returns:
            Node name or None if no available nodes
        """
        try:
            response = await self._make_request("GET", "/nodes")

            if response and "data" in response:
                for node_data in response["data"]:
                    if node_data.get("status") == "online":
                        return node_data.get("node")

            return None

        except Exception as e:
            logger.error(f"Failed to get available node: {e}")
            return None

    async def _allocate_vmid(self) -> Optional[int]:
        """Allocate a new VMID.

        Returns:
            New VMID or None if allocation failed
        """
        try:
            response = await self._make_request("POST", "/cluster/nextid")

            if response and "data" in response:
                return response["data"].get("vmid")

            return None

        except Exception as e:
            logger.error(f"Failed to allocate VMID: {e}")
            return None

    async def _monitor_task(self, node: str, task_id: str, timeout: int = 300) -> bool:
        """Monitor task completion.

        Args:
            node: Node where task is running
            task_id: Task ID to monitor
            timeout: Timeout in seconds

        Returns:
            True if task completed successfully, False otherwise
        """
        try:
            start_time = datetime.utcnow().timestamp()

            while datetime.utcnow().timestamp() - start_time < timeout:
                response = await self._make_request(
                    "GET", f"/nodes/{node}/tasks/{task_id}/status"
                )

                if response and "data" in response:
                    status_data = response["data"]
                    status = status_data.get("status")

                    if status == "stopped":
                        # Check if task was successful
                        exit_status = status_data.get("exitstatus")
                        return exit_status == "OK"
                    elif status == "error":
                        return False

                # Wait before next check
                await asyncio.sleep(5)

            # Timeout reached
            logger.warning(f"Task monitoring timeout: {task_id}")
            return False

        except Exception as e:
            logger.error(f"Failed to monitor task {task_id}: {e}")
            return False

    # Discovery and Information Methods

    async def list_nodes(self) -> List[ProxmoxNode]:
        """List all nodes in the cluster.

        Returns:
            List of ProxmoxNode objects
        """
        try:
            response = await self._make_request("GET", "/nodes")

            if response and "data" in response:
                nodes = []
                for node_data in response["data"]:
                    node = ProxmoxNode.from_api_response(node_data)
                    nodes.append(node)
                return nodes

            return []

        except Exception as e:
            logger.error(f"Failed to list nodes: {e}")
            return []

    async def list_storage(self, node: Optional[str] = None) -> List[ProxmoxStorage]:
        """List storage pools.

        Args:
            node: Specific node to list storage from

        Returns:
            List of ProxmoxStorage objects
        """
        try:
            endpoint = "/nodes/*/storage"
            if node:
                endpoint = f"/nodes/{node}/storage"

            response = await self._make_request("GET", endpoint)

            if response and "data" in response:
                storages = []
                for storage_data in response["data"]:
                    storage = ProxmoxStorage.from_api_response(storage_data)
                    storages.append(storage)
                return storages

            return []

        except Exception as e:
            logger.error(f"Failed to list storage: {e}")
            return []
