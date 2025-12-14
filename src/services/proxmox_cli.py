"""
Proxmox CLI Wrapper

Provides CLI-based operations for Proxmox environments, serving as both
a fallback for operations not available via API and additional functionality
for specific Proxmox operations that work better through CLI.
"""

import logging
import subprocess
import asyncio
import json
import re
from typing import Dict, List, Optional, Any, Tuple, Union
from datetime import datetime
from pathlib import Path

from src.models.proxmox_models import (
    ProxmoxAPICredentials, ProxmoxContainer, ProxmoxVM, ProxmoxSnapshot,
    ProxmoxBackup, ProxmoxStorage, ProxmoxNode,
    ContainerConfig, VMConfig, CloneConfig, BackupConfig,
    ContainerCreationResult, CloneResult, DeleteResult, SnapshotResult,
    BackupResult, RestoreResult, UpdateResult, StartResult, StopResult,
    RebootResult, OperationResult
)
from src.utils.retry import retry_with_backoff
from src.utils.audit import audit_operation

logger = logging.getLogger(__name__)


class ProxmoxCLIError(Exception):
    """Proxmox CLI exception."""
    pass


class ProxmoxCLI:
    """Proxmox CLI wrapper for operations not available via API."""
    
    def __init__(self, credentials: Optional[ProxmoxAPICredentials] = None):
        """Initialize Proxmox CLI wrapper.
        
        Args:
            credentials: Proxmox API credentials (optional for local operations)
        """
        self.credentials = credentials
        self._is_local = credentials is None
        
        # Check if we're in a Proxmox environment
        self._proxmox_environment = self._detect_proxmox_environment()
        
        if not self._proxmox_environment and not self._is_local:
            logger.warning("Not running in Proxmox environment and no remote credentials provided")
    
    def _detect_proxmox_environment(self) -> bool:
        """Detect if running in a Proxmox environment."""
        try:
            # Check for Proxmox-specific commands
            commands = ["pvesh", "pct", "qm", "pveversion"]
            return all(subprocess.run(["which", cmd], capture_output=True).returncode == 0 
                      for cmd in commands)
        except Exception:
            return False
    
    def is_available(self) -> bool:
        """Check if Proxmox CLI is available."""
        return self._proxmox_environment
    
    async def test_connection(self) -> OperationResult:
        """Test Proxmox CLI availability.
        
        Returns:
            OperationResult with connection test results
        """
        try:
            if not self._proxmox_environment:
                return OperationResult.failure(
                    "Proxmox CLI not available",
                    "Not running in Proxmox environment"
                )
            
            # Test basic Proxmox commands
            version_result = await self._run_command(["pveversion"])
            if version_result.returncode != 0:
                return OperationResult.failure(
                    "Proxmox version command failed",
                    version_result.stderr
                )
            
            return OperationResult(
                success=True,
                status="available",
                data={"version": version_result.stdout.strip()},
                message="Proxmox CLI is available"
            )
        
        except Exception as e:
            return OperationResult.failure(f"Proxmox CLI test failed: {e}")
    
    async def _run_command(self, command: List[str], 
                         timeout: int = 300,
                         check: bool = True) -> subprocess.CompletedProcess:
        """Run a Proxmox CLI command.
        
        Args:
            command: Command and arguments to execute
            timeout: Command timeout in seconds
            check: Whether to raise exception on non-zero exit code
            
        Returns:
            CompletedProcess result
        """
        try:
            logger.debug(f"Running command: {' '.join(command)}")
            
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd="/"
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=timeout
            )
            
            result = subprocess.CompletedProcess(
                args=command,
                returncode=process.returncode,
                stdout=stdout.decode().strip(),
                stderr=stderr.decode().strip()
            )
            
            if check and result.returncode != 0:
                raise ProxmoxCLIError(f"Command failed: {result.stderr}")
            
            logger.debug(f"Command completed with return code {result.returncode}")
            return result
        
        except asyncio.TimeoutError:
            raise ProxmoxCLIError(f"Command timed out after {timeout} seconds")
        except Exception as e:
            raise ProxmoxCLIError(f"Command execution failed: {e}")
    
    # Container Management via CLI
    
    async def list_containers_cli(self) -> List[ProxmoxContainer]:
        """List containers using CLI commands.
        
        Returns:
            List of ProxmoxContainer objects
        """
        try:
            result = await self._run_command(["pct", "list"])
            
            if result.returncode != 0:
                logger.error(f"Failed to list containers: {result.stderr}")
                return []
            
            containers = []
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            
            for line in lines:
                if line.strip():
                    container = self._parse_pct_list_line(line)
                    if container:
                        containers.append(container)
            
            return containers
        
        except Exception as e:
            logger.error(f"Failed to list containers via CLI: {e}")
            return []
    
    async def get_container_config_cli(self, vmid: int) -> Optional[Dict[str, Any]]:
        """Get container configuration using CLI.
        
        Args:
            vmid: Container VMID
            
        Returns:
            Container configuration dictionary
        """
        try:
            result = await self._run_command(["pct", "config", str(vmid)])
            
            if result.returncode != 0:
                return None
            
            config = self._parse_pct_config_output(result.stdout)
            config["vmid"] = vmid
            return config
        
        except Exception as e:
            logger.error(f"Failed to get container config for {vmid}: {e}")
            return None
    
    async def create_container_cli(self, config: ContainerConfig, 
                                 node: Optional[str] = None) -> ContainerCreationResult:
        """Create container using CLI.
        
        Args:
            config: Container configuration
            node: Target node (ignored for CLI, uses local node)
            
        Returns:
            ContainerCreationResult with creation details
        """
        try:
            # Generate VMID if not specified
            if not config.vmid:
                config.vmid = await self._allocate_vmid_cli()
            
            if not config.vmid:
                return ContainerCreationResult(
                    vmid=0,
                    status="failed",
                    message="Failed to allocate VMID"
                )
            
            # Build pct create command
            cmd = ["pct", "create", str(config.vmid), config.ostemplate]
            
            # Add configuration options
            config_options = self._build_pct_config_options(config)
            cmd.extend(config_options)
            
            result = await self._run_command(cmd)
            
            if result.returncode == 0:
                return ContainerCreationResult(
                    vmid=config.vmid,
                    status="created",
                    message="Container created successfully via CLI"
                )
            else:
                return ContainerCreationResult(
                    vmid=config.vmid,
                    status="failed",
                    message=f"Container creation failed: {result.stderr}"
                )
        
        except Exception as e:
            logger.error(f"Failed to create container via CLI: {e}")
            return ContainerCreationResult(
                vmid=0,
                status="failed",
                message=str(e)
            )
    
    async def clone_container_cli(self, source_vmid: int, 
                                config: CloneConfig) -> CloneResult:
        """Clone container using CLI.
        
        Args:
            source_vmid: Source container VMID
            config: Clone configuration
            
        Returns:
            CloneResult with clone details
        """
        try:
            # Generate VMID if not specified
            if not config.newid:
                config.newid = await self._allocate_vmid_cli()
            
            if not config.newid:
                return CloneResult(
                    vmid=0,
                    status="failed",
                    message="Failed to allocate VMID for clone"
                )
            
            # Build pct clone command
            cmd = ["pct", "clone", str(source_vmid), str(config.newid)]
            
            if config.full:
                cmd.append("--full")
            if config.hostname:
                cmd.extend(["--hostname", config.hostname])
            
            result = await self._run_command(cmd)
            
            if result.returncode == 0:
                return CloneResult(
                    vmid=config.newid,
                    status="cloned",
                    message="Container cloned successfully via CLI"
                )
            else:
                return CloneResult(
                    vmid=config.newid,
                    status="failed",
                    message=f"Container clone failed: {result.stderr}"
                )
        
        except Exception as e:
            logger.error(f"Failed to clone container {source_vmid} via CLI: {e}")
            return CloneResult(
                vmid=0,
                status="failed",
                message=str(e)
            )
    
    async def delete_container_cli(self, vmid: int) -> DeleteResult:
        """Delete container using CLI.
        
        Args:
            vmid: Container VMID to delete
            
        Returns:
            DeleteResult with deletion details
        """
        try:
            # Stop container if running
            await self.stop_container_cli(vmid, force=True)
            
            # Destroy container
            result = await self._run_command(["pct", "destroy", str(vmid)])
            
            if result.returncode == 0:
                return DeleteResult(
                    status="deleted",
                    message="Container deleted successfully via CLI"
                )
            else:
                return DeleteResult(
                    status="failed",
                    message=f"Container deletion failed: {result.stderr}"
                )
        
        except Exception as e:
            logger.error(f"Failed to delete container {vmid} via CLI: {e}")
            return DeleteResult(
                status="failed",
                message=str(e)
            )
    
    # VM Management via CLI
    
    async def list_vms_cli(self) -> List[ProxmoxVM]:
        """List VMs using CLI commands.
        
        Returns:
            List of ProxmoxVM objects
        """
        try:
            result = await self._run_command(["qm", "list"])
            
            if result.returncode != 0:
                logger.error(f"Failed to list VMs: {result.stderr}")
                return []
            
            vms = []
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            
            for line in lines:
                if line.strip():
                    vm = self._parse_qm_list_line(line)
                    if vm:
                        vms.append(vm)
            
            return vms
        
        except Exception as e:
            logger.error(f"Failed to list VMs via CLI: {e}")
            return []
    
    # Container/VM Control via CLI
    
    async def start_container_cli(self, vmid: int) -> StartResult:
        """Start container using CLI.
        
        Args:
            vmid: Container VMID
            
        Returns:
            StartResult with start operation details
        """
        try:
            result = await self._run_command(["pct", "start", str(vmid)])
            
            if result.returncode == 0:
                return StartResult(
                    status="started",
                    message="Container started successfully via CLI"
                )
            else:
                return StartResult(
                    status="failed",
                    message=f"Container start failed: {result.stderr}"
                )
        
        except Exception as e:
            logger.error(f"Failed to start container {vmid} via CLI: {e}")
            return StartResult(
                status="failed",
                message=str(e)
            )
    
    async def stop_container_cli(self, vmid: int, force: bool = False) -> StopResult:
        """Stop container using CLI.
        
        Args:
            vmid: Container VMID
            force: Force stop
            
        Returns:
            StopResult with stop operation details
        """
        try:
            cmd = ["pct", "stop", str(vmid)]
            if force:
                cmd.append("--force")
            
            result = await self._run_command(cmd)
            
            if result.returncode == 0:
                return StopResult(
                    status="stopped",
                    message="Container stopped successfully via CLI"
                )
            else:
                return StopResult(
                    status="failed",
                    message=f"Container stop failed: {result.stderr}"
                )
        
        except Exception as e:
            logger.error(f"Failed to stop container {vmid} via CLI: {e}")
            return StopResult(
                status="failed",
                message=str(e)
            )
    
    async def reboot_container_cli(self, vmid: int) -> RebootResult:
        """Reboot container using CLI.
        
        Args:
            vmid: Container VMID
            
        Returns:
            RebootResult with reboot operation details
        """
        try:
            result = await self._run_command(["pct", "reboot", str(vmid)])
            
            if result.returncode == 0:
                return RebootResult(
                    status="rebooted",
                    message="Container rebooted successfully via CLI"
                )
            else:
                return RebootResult(
                    status="failed",
                    message=f"Container reboot failed: {result.stderr}"
                )
        
        except Exception as e:
            logger.error(f"Failed to reboot container {vmid} via CLI: {e}")
            return RebootResult(
                status="failed",
                message=str(e)
            )
    
    # Snapshot Management via CLI
    
    async def create_snapshot_cli(self, vmid: int, snapshot_name: str, 
                                description: Optional[str] = None) -> SnapshotResult:
        """Create snapshot using CLI.
        
        Args:
            vmid: VM or container VMID
            snapshot_name: Name for the snapshot
            description: Optional description
            
        Returns:
            SnapshotResult with snapshot creation details
        """
        try:
            # Try container first
            cmd = ["pct", "snapshot", str(vmid), snapshot_name]
            if description:
                cmd.extend(["--description", description])
            
            result = await self._run_command(cmd)
            
            # If container command fails, try VM
            if result.returncode != 0:
                cmd = ["qm", "snapshot", str(vmid), snapshot_name]
                if description:
                    cmd.extend(["--description", description])
                
                result = await self._run_command(cmd)
            
            if result.returncode == 0:
                return SnapshotResult(
                    name=snapshot_name,
                    status="created",
                    message="Snapshot created successfully via CLI"
                )
            else:
                return SnapshotResult(
                    name=snapshot_name,
                    status="failed",
                    message=f"Snapshot creation failed: {result.stderr}"
                )
        
        except Exception as e:
            logger.error(f"Failed to create snapshot {snapshot_name} for {vmid} via CLI: {e}")
            return SnapshotResult(
                name=snapshot_name,
                status="failed",
                message=str(e)
            )
    
    async def list_snapshots_cli(self, vmid: int) -> List[ProxmoxSnapshot]:
        """List snapshots using CLI.
        
        Args:
            vmid: VM or container VMID
            
        Returns:
            List of ProxmoxSnapshot objects
        """
        try:
            # Try container first
            result = await self._run_command(["pct", "listsnapshots", str(vmid)])
            
            if result.returncode != 0:
                # Try VM
                result = await self._run_command(["qm", "listsnapshots", str(vmid)])
            
            if result.returncode != 0:
                logger.error(f"Failed to list snapshots for {vmid}: {result.stderr}")
                return []
            
            return self._parse_snapshot_output(result.stdout, vmid)
        
        except Exception as e:
            logger.error(f"Failed to list snapshots for {vmid} via CLI: {e}")
            return []
    
    async def delete_snapshot_cli(self, vmid: int, snapshot_name: str) -> DeleteResult:
        """Delete snapshot using CLI.
        
        Args:
            vmid: VM or container VMID
            snapshot_name: Snapshot name to delete
            
        Returns:
            DeleteResult with deletion details
        """
        try:
            # Try container first
            result = await self._run_command(["pct", "delsnapshot", str(vmid), snapshot_name])
            
            # If container command fails, try VM
            if result.returncode != 0:
                result = await self._run_command(["qm", "delsnapshot", str(vmid), snapshot_name])
            
            if result.returncode == 0:
                return DeleteResult(
                    status="deleted",
                    message="Snapshot deleted successfully via CLI"
                )
            else:
                return DeleteResult(
                    status="failed",
                    message=f"Snapshot deletion failed: {result.stderr}"
                )
        
        except Exception as e:
            logger.error(f"Failed to delete snapshot {snapshot_name} for {vmid} via CLI: {e}")
            return DeleteResult(
                status="failed",
                message=str(e)
            )
    
    async def restore_snapshot_cli(self, vmid: int, snapshot_name: str) -> RestoreResult:
        """Restore snapshot using CLI.
        
        Args:
            vmid: VM or container VMID
            snapshot_name: Snapshot name to restore
            
        Returns:
            RestoreResult with restore operation details
        """
        try:
            # Try container first
            result = await self._run_command(["pct", "rollback", str(vmid), snapshot_name])
            
            # If container command fails, try VM
            if result.returncode != 0:
                result = await self._run_command(["qm", "rollback", str(vmid), snapshot_name])
            
            if result.returncode == 0:
                return RestoreResult(
                    status="restored",
                    message="Snapshot restored successfully via CLI"
                )
            else:
                return RestoreResult(
                    status="failed",
                    message=f"Snapshot restore failed: {result.stderr}"
                )
        
        except Exception as e:
            logger.error(f"Failed to restore snapshot {snapshot_name} for {vmid} via CLI: {e}")
            return RestoreResult(
                status="failed",
                message=str(e)
            )
    
    # Backup Management via CLI
    
    async def create_backup_cli(self, vmid: int, backup_config: BackupConfig) -> BackupResult:
        """Create backup using CLI.
        
        Args:
            vmid: VM or container VMID
            backup_config: Backup configuration
            
        Returns:
            BackupResult with backup creation details
        """
        try:
            # Build vzdump command
            cmd = [
                "vzdump",
                str(vmid),
                "--storage", backup_config.storage,
                "--mode", backup_config.mode.value,
                "--compress", backup_config.compress
            ]
            
            if backup_config.keep:
                cmd.extend(["--keep", str(backup_config.keep)])
            if backup_config.quiet:
                cmd.append("--quiet")
            
            result = await self._run_command(cmd)
            
            if result.returncode == 0:
                return BackupResult(
                    backup_id=f"local:{vmid}",
                    filename=f"vzdump-{vmid}.tar.gz",
                    size=0,  # CLI doesn't easily provide size
                    status="completed",
                    message="Backup created successfully via CLI"
                )
            else:
                return BackupResult(
                    backup_id="",
                    filename="",
                    size=0,
                    status="failed",
                    message=f"Backup creation failed: {result.stderr}"
                )
        
        except Exception as e:
            logger.error(f"Failed to create backup for {vmid} via CLI: {e}")
            return BackupResult(
                backup_id="",
                filename="",
                size=0,
                status="failed",
                message=str(e)
            )
    
    # System Information via CLI
    
    async def get_system_info_cli(self) -> Dict[str, Any]:
        """Get system information using CLI.
        
        Returns:
            System information dictionary
        """
        try:
            info = {}
            
            # Get Proxmox version
            version_result = await self._run_command(["pveversion"])
            if version_result.returncode == 0:
                info["version"] = version_result.stdout.strip()
            
            # Get node info
            node_result = await self._run_command(["pvesh", "get", "/nodes/localhost"])
            if node_result.returncode == 0:
                info["node"] = json.loads(node_result.stdout)
            
            # Get resources
            resources_result = await self._run_command(["pvesh", "get", "/nodes/localhost/resources"])
            if resources_result.returncode == 0:
                info["resources"] = json.loads(resources_result.stdout)
            
            return info
        
        except Exception as e:
            logger.error(f"Failed to get system info via CLI: {e}")
            return {}
    
    async def get_storage_info_cli(self) -> List[ProxmoxStorage]:
        """Get storage information using CLI.
        
        Returns:
            List of ProxmoxStorage objects
        """
        try:
            result = await self._run_command(["pvesh", "get", "/storage"])
            
            if result.returncode != 0:
                return []
            
            storage_data = json.loads(result.stdout)
            storages = []
            
            for storage_info in storage_data.get("data", []):
                storage = ProxmoxStorage(
                    storage=storage_info.get("storage", ""),
                    type=storage_info.get("type", "dir"),
                    node=storage_info.get("node", ""),
                    enabled=storage_info.get("enabled", True),
                    content=storage_info.get("content", "").split(",") if storage_info.get("content") else [],
                    shared=storage_info.get("shared", False),
                    maxfiles=storage_info.get("maxfiles"),
                    used=storage_info.get("used"),
                    total=storage_info.get("total")
                )
                storages.append(storage)
            
            return storages
        
        except Exception as e:
            logger.error(f"Failed to get storage info via CLI: {e}")
            return []
    
    # Helper Methods
    
    async def _allocate_vmid_cli(self) -> Optional[int]:
        """Allocate a new VMID using CLI.
        
        Returns:
            New VMID or None if allocation failed
        """
        try:
            result = await self._run_command(["pvesh", "get", "/cluster/nextid"])
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                return data.get("data", {}).get("vmid")
            
            # Fallback: find next available ID manually
            return await self._find_next_vmid_cli()
        
        except Exception as e:
            logger.error(f"Failed to allocate VMID via CLI: {e}")
            return await self._find_next_vmid_cli()
    
    async def _find_next_vmid_cli(self) -> Optional[int]:
        """Find next available VMID manually.
        
        Returns:
            Next available VMID or None if none found
        """
        try:
            # Get list of existing containers and VMs
            containers = await self.list_containers_cli()
            vms = await self.list_vms_cli()
            
            # Collect all used VMIDs
            used_ids = set()
            for container in containers:
                used_ids.add(container.vmid)
            for vm in vms:
                used_ids.add(vm.vmid)
            
            # Find next available ID (start from 100 to avoid conflicts with system VMs)
            for vmid in range(100, 999999):
                if vmid not in used_ids:
                    return vmid
            
            return None
        
        except Exception as e:
            logger.error(f"Failed to find next VMID via CLI: {e}")
            return None
    
    def _parse_pct_list_line(self, line: str) -> Optional[ProxmoxContainer]:
        """Parse a line from 'pct list' output."""
        try:
            parts = line.split()
            if len(parts) >= 5:
                vmid = int(parts[0])
                status = parts[1]
                name = parts[2]
                
                # Create basic container object
                return ProxmoxContainer(
                    vmid=vmid,
                    node="localhost",
                    name=name,
                    status=status,  # Will be converted to enum
                    tags=["lxc", "proxmox", "cli"]
                )
        except Exception as e:
            logger.error(f"Failed to parse pct list line: {e}")
        
        return None
    
    def _parse_qm_list_line(self, line: str) -> Optional[ProxmoxVM]:
        """Parse a line from 'qm list' output."""
        try:
            parts = line.split()
            if len(parts) >= 5:
                vmid = int(parts[0])
                status = parts[2]
                name = parts[1]
                
                # Create basic VM object
                return ProxmoxVM(
                    vmid=vmid,
                    node="localhost",
                    name=name,
                    status=status,  # Will be converted to enum
                    tags=["vm", "qemu", "proxmox", "cli"]
                )
        except Exception as e:
            logger.error(f"Failed to parse qm list line: {e}")
        
        return None
    
    def _parse_pct_config_output(self, config_output: str) -> Dict[str, Any]:
        """Parse pct config output."""
        config = {}
        
        for line in config_output.split('\n'):
            line = line.strip()
            if '=' in line and not line.startswith('#'):
                key, value = line.split('=', 1)
                config[key] = value.strip()
        
        return config
    
    def _parse_snapshot_output(self, snapshot_output: str, vmid: int) -> List[ProxmoxSnapshot]:
        """Parse snapshot output from CLI."""
        snapshots = []
        
        for line in snapshot_output.split('\n'):
            if line.strip() and not line.startswith('Name'):
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    description = ' '.join(parts[2:]) if len(parts) > 2 else None
                    
                    snapshot = ProxmoxSnapshot(
                        name=name,
                        vmid=vmid,
                        node="localhost",
                        description=description
                    )
                    snapshots.append(snapshot)
        
        return snapshots
    
    def _build_pct_config_options(self, config: ContainerConfig) -> List[str]:
        """Build pct configuration options from ContainerConfig.
        
        Args:
            config: Container configuration
            
        Returns:
            List of command line options
        """
        options = []
        
        # Basic options
        if config.hostname:
            options.extend(["--hostname", config.hostname])
        if config.password:
            options.extend(["--password", config.password])
        if config.cores != 1:
            options.extend(["--cores", str(config.cores)])
        if config.memory != 512:
            options.extend(["--memory", str(config.memory)])
        if config.rootfs:
            options.extend(["--rootfs", config.rootfs])
        if config.swap > 0:
            options.extend(["--swap", str(config.swap)])
        
        # Network configuration
        if config.net:
            for net in config.net:
                net_config = f"name={net.name},bridge={net.bridge}"
                if net.ip:
                    net_config += f",ip={net.ip}"
                if net.gateway:
                    net_config += f",gw={net.gateway}"
                if net.firewall:
                    net_config += ",firewall=1"
                options.extend(["--net0", net_config])
        
        # Features
        for feature, enabled in config.features.items():
            if enabled:
                options.append(f"--features={feature}=1")
        
        # Boot and startup
        if config.onboot:
            options.append("--onboot")
        if config.backup:
            options.append("--backup")
        
        return options