"""
Proxmox-Specific Capability Operations

Provides comprehensive Proxmox capability operations that integrate with the
policy-driven execution system, enabling secure and controlled Proxmox operations
through capability-driven interfaces.
"""

import logging
import asyncio
from typing import Dict, List, Optional, Any, Union, Tuple
from datetime import datetime

from src.models.policy_models import (
    OperationType, TargetRole, ParameterConstraint, create_default_policy_config
)
from src.models.proxmox_models import (
    ProxmoxAPICredentials, ContainerConfig, VMConfig, CloneConfig, BackupConfig,
    ProxmoxNetworkConfig, ProxmoxResourceConfig,
    ContainerCreationResult, CloneResult, DeleteResult, SnapshotResult,
    BackupResult, RestoreResult, UpdateResult, StartResult, StopResult,
    RebootResult, OperationResult
)
from src.services.proxmox_api import ProxmoxAPI, ProxmoxAPIError
from src.services.proxmox_cli import ProxmoxCLI, ProxmoxCLIError
from src.services.capability_executor import CapabilityValidator, CapabilityExecutor
from src.models.execution import ExecutionResult, ExecutionStatus, ExecutionSeverity
from src.utils.audit import audit_operation
from src.utils.retry import retry_with_backoff

logger = logging.getLogger(__name__)


# Extended OperationType enum for Proxmox-specific operations
class ProxmoxOperationType(OperationType):
    """Extended operations for Proxmox-specific functionality."""
    
    # Proxmox-specific container operations
    PROXMOX_CONTAINER_CREATE = "proxmox_container_create"
    PROXMOX_CONTAINER_DELETE = "proxmox_container_delete"
    PROXMOX_CONTAINER_CLONE = "proxmox_container_clone"
    PROXMOX_CONTAINER_START = "proxmox_container_start"
    PROXMOX_CONTAINER_STOP = "proxmox_container_stop"
    PROXMOX_CONTAINER_REBOOT = "proxmox_container_reboot"
    PROXMOX_CONTAINER_STATUS = "proxmox_container_status"
    PROXMOX_CONTAINER_RESOURCES = "proxmox_container_resources"
    
    # Proxmox-specific VM operations
    PROXMOX_VM_CREATE = "proxmox_vm_create"
    PROXMOX_VM_DELETE = "proxmox_vm_delete"
    PROXMOX_VM_CLONE = "proxmox_vm_clone"
    PROXMOX_VM_START = "proxmox_vm_start"
    PROXMOX_VM_STOP = "proxmox_vm_stop"
    PROXMOX_VM_REBOOT = "proxmox_vm_reboot"
    PROXMOX_VM_STATUS = "proxmox_vm_status"
    PROXMOX_VM_RESOURCES = "proxmox_vm_resources"
    
    # Snapshot operations
    PROXMOX_SNAPSHOT_CREATE = "proxmox_snapshot_create"
    PROXMOX_SNAPSHOT_DELETE = "proxmox_snapshot_delete"
    PROXMOX_SNAPSHOT_RESTORE = "proxmox_snapshot_restore"
    PROXMOX_SNAPSHOT_LIST = "proxmox_snapshot_list"
    
    # Backup operations
    PROXMOX_BACKUP_CREATE = "proxmox_backup_create"
    PROXMOX_BACKUP_RESTORE = "proxmox_backup_restore"
    PROXMOX_BACKUP_LIST = "proxmox_backup_list"
    PROXMOX_BACKUP_DELETE = "proxmox_backup_delete"
    
    # Discovery operations
    PROXMOX_DISCOVER_HOSTS = "proxmox_discover_hosts"
    PROXMOX_DISCOVER_CONTAINERS = "proxmox_discover_containers"
    PROXMOX_DISCOVER_VMS = "proxmox_discover_vms"
    PROXMOX_DISCOVER_STORAGE = "proxmox_discover_storage"
    
    # Migration operations
    PROXMOX_MIGRATE_CONTAINER = "proxmox_migrate_container"
    PROXMOX_MIGRATE_VM = "proxmox_migrate_vm"
    
    # Template operations
    PROXMOX_CREATE_TEMPLATE = "proxmox_create_template"
    PROXMOX_LIST_TEMPLATES = "proxmox_list_templates"


class ProxmoxCapabilityValidator(CapabilityValidator):
    """Proxmox-specific capability parameter validator."""
    
    def _load_parameter_schemas(self) -> Dict[OperationType, Dict[str, Any]]:
        """Load Proxmox-specific parameter schemas."""
        schemas = super()._load_parameter_schemas()
        
        # Proxmox container creation schema
        schemas[ProxmoxOperationType.PROXMOX_CONTAINER_CREATE] = {
            "host": {
                "type": "string",
                "required": True,
                "max_length": 255,
                "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$",
                "description": "Proxmox host address"
            },
            "template": {
                "type": "string",
                "required": True,
                "max_length": 128,
                "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9_./-]*$",
                "description": "Container template path"
            },
            "hostname": {
                "type": "string",
                "required": True,
                "max_length": 64,
                "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$",
                "description": "Container hostname"
            },
            "vmid": {
                "type": "int",
                "required": False,
                "min": 100,
                "max": 999999,
                "description": "Specific VMID (auto-assigned if not provided)"
            },
            "cores": {
                "type": "int",
                "required": False,
                "min": 1,
                "max": 128,
                "default": 1,
                "description": "Number of CPU cores"
            },
            "memory": {
                "type": "int",
                "required": False,
                "min": 128,
                "max": 1048576,
                "default": 512,
                "description": "Memory in MB"
            },
            "rootfs": {
                "type": "string",
                "required": False,
                "max_length": 128,
                "default": "local-lvm:10",
                "description": "Root filesystem configuration"
            },
            "network_bridge": {
                "type": "string",
                "required": False,
                "max_length": 32,
                "default": "vmbr0",
                "description": "Network bridge"
            },
            "ip_address": {
                "type": "string",
                "required": False,
                "pattern": r"^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$",
                "description": "IP address with optional CIDR"
            },
            "password": {
                "type": "string",
                "required": False,
                "max_length": 128,
                "description": "Root password for container"
            },
            "ssh_keys": {
                "type": "list",
                "required": False,
                "max_length": 10,
                "description": "SSH public keys for authentication"
            }
        }
        
        # Proxmox container management schemas
        schemas[ProxmoxOperationType.PROXMOX_CONTAINER_START] = {
            "vmid": {
                "type": "int",
                "required": True,
                "min": 100,
                "max": 999999,
                "description": "Container VMID"
            },
            "host": {
                "type": "string",
                "required": True,
                "max_length": 255,
                "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$",
                "description": "Proxmox host address"
            }
        }
        
        schemas[ProxmoxOperationType.PROXMOX_CONTAINER_STOP] = {
            "vmid": {
                "type": "int",
                "required": True,
                "min": 100,
                "max": 999999,
                "description": "Container VMID"
            },
            "host": {
                "type": "string",
                "required": True,
                "max_length": 255,
                "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$",
                "description": "Proxmox host address"
            },
            "force": {
                "type": "bool",
                "required": False,
                "default": False,
                "description": "Force stop container"
            }
        }
        
        schemas[ProxmoxOperationType.PROXMOX_CONTAINER_REBOOT] = {
            "vmid": {
                "type": "int",
                "required": True,
                "min": 100,
                "max": 999999,
                "description": "Container VMID"
            },
            "host": {
                "type": "string",
                "required": True,
                "max_length": 255,
                "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$",
                "description": "Proxmox host address"
            }
        }
        
        schemas[ProxmoxOperationType.PROXMOX_CONTAINER_DELETE] = {
            "vmid": {
                "type": "int",
                "required": True,
                "min": 100,
                "max": 999999,
                "description": "Container VMID to delete"
            },
            "host": {
                "type": "string",
                "required": True,
                "max_length": 255,
                "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$",
                "description": "Proxmox host address"
            }
        }
        
        schemas[ProxmoxOperationType.PROXMOX_CONTAINER_CLONE] = {
            "source_vmid": {
                "type": "int",
                "required": True,
                "min": 100,
                "max": 999999,
                "description": "Source container VMID"
            },
            "new_hostname": {
                "type": "string",
                "required": True,
                "max_length": 64,
                "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$",
                "description": "New container hostname"
            },
            "new_vmid": {
                "type": "int",
                "required": False,
                "min": 100,
                "max": 999999,
                "description": "New VMID (auto-assigned if not provided)"
            },
            "host": {
                "type": "string",
                "required": True,
                "max_length": 255,
                "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$",
                "description": "Proxmox host address"
            },
            "full_clone": {
                "type": "bool",
                "required": False,
                "default": True,
                "description": "Create full clone or linked clone"
            }
        }
        
        # Snapshot operation schemas
        schemas[ProxmoxOperationType.PROXMOX_SNAPSHOT_CREATE] = {
            "vmid": {
                "type": "int",
                "required": True,
                "min": 100,
                "max": 999999,
                "description": "VM or container VMID"
            },
            "snapshot_name": {
                "type": "string",
                "required": True,
                "max_length": 64,
                "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$",
                "description": "Snapshot name"
            },
            "description": {
                "type": "string",
                "required": False,
                "max_length": 255,
                "description": "Snapshot description"
            },
            "host": {
                "type": "string",
                "required": True,
                "max_length": 255,
                "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$",
                "description": "Proxmox host address"
            }
        }
        
        schemas[ProxmoxOperationType.PROXMOX_SNAPSHOT_DELETE] = {
            "vmid": {
                "type": "int",
                "required": True,
                "min": 100,
                "max": 999999,
                "description": "VM or container VMID"
            },
            "snapshot_name": {
                "type": "string",
                "required": True,
                "max_length": 64,
                "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$",
                "description": "Snapshot name to delete"
            },
            "host": {
                "type": "string",
                "required": True,
                "max_length": 255,
                "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$",
                "description": "Proxmox host address"
            }
        }
        
        schemas[ProxmoxOperationType.PROXMOX_SNAPSHOT_RESTORE] = {
            "vmid": {
                "type": "int",
                "required": True,
                "min": 100,
                "max": 999999,
                "description": "VM or container VMID"
            },
            "snapshot_name": {
                "type": "string",
                "required": True,
                "max_length": 64,
                "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$",
                "description": "Snapshot name to restore"
            },
            "host": {
                "type": "string",
                "required": True,
                "max_length": 255,
                "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$",
                "description": "Proxmox host address"
            },
            "rollback": {
                "type": "bool",
                "required": False,
                "default": False,
                "description": "Rollback to snapshot (destroy current state)"
            }
        }
        
        # Backup operation schemas
        schemas[ProxmoxOperationType.PROXMOX_BACKUP_CREATE] = {
            "vmid": {
                "type": "int",
                "required": True,
                "min": 100,
                "max": 999999,
                "description": "VM or container VMID"
            },
            "storage": {
                "type": "string",
                "required": True,
                "max_length": 64,
                "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$",
                "description": "Storage pool for backup"
            },
            "host": {
                "type": "string",
                "required": True,
                "max_length": 255,
                "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$",
                "description": "Proxmox host address"
            },
            "mode": {
                "type": "string",
                "required": False,
                "allowed_values": ["snapshot", "suspend", "stop"],
                "default": "snapshot",
                "description": "Backup mode"
            },
            "compress": {
                "type": "string",
                "required": False,
                "allowed_values": ["gzip", "lzo", "zstd"],
                "default": "gzip",
                "description": "Compression algorithm"
            }
        }
        
        # Discovery operation schemas
        schemas[ProxmoxOperationType.PROXMOX_DISCOVER_HOSTS] = {
            "force_refresh": {
                "type": "bool",
                "required": False,
                "default": False,
                "description": "Force refresh discovery"
            }
        }
        
        schemas[ProxmoxOperationType.PROXMOX_DISCOVER_CONTAINERS] = {
            "host": {
                "type": "string",
                "required": True,
                "max_length": 255,
                "pattern": r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$",
                "description": "Proxmox host address"
            },
            "force_refresh": {
                "type": "bool",
                "required": False,
                "default": False,
                "description": "Force refresh discovery"
            }
        }
        
        return schemas


class ProxmoxCapabilityExecutor:
    """Proxmox-specific capability executor."""
    
    def __init__(self, api_credentials: Optional[List[ProxmoxAPICredentials]] = None):
        """Initialize Proxmox capability executor.
        
        Args:
            api_credentials: List of Proxmox API credentials
        """
        self.api_credentials = api_credentials or []
        self.validator = ProxmoxCapabilityValidator()
        self._api_clients: Dict[str, ProxmoxAPI] = {}
        self._cli_client: Optional[ProxmoxCLI] = None
        
        # Initialize CLI client for local operations
        self._initialize_cli_client()
    
    def _initialize_cli_client(self):
        """Initialize CLI client for local Proxmox operations."""
        try:
            self._cli_client = ProxmoxCLI()
            if self._cli_client.is_available():
                logger.info("Initialized Proxmox CLI client for local operations")
            else:
                self._cli_client = None
        except Exception as e:
            logger.warning(f"Failed to initialize CLI client: {e}")
            self._cli_client = None
    
    def _get_api_client(self, host: str) -> Optional[ProxmoxAPI]:
        """Get or create API client for host.
        
        Args:
            host: Proxmox host address
            
        Returns:
            ProxmoxAPI client or None
        """
        if host in self._api_clients:
            return self._api_clients[host]
        
        # Find matching credentials
        credentials = None
        for creds in self.api_credentials:
            if creds.host == host:
                credentials = creds
                break
        
        if not credentials:
            logger.warning(f"No API credentials found for host {host}")
            return None
        
        try:
            api_client = ProxmoxAPI(credentials)
            self._api_clients[host] = api_client
            return api_client
        except Exception as e:
            logger.error(f"Failed to create API client for {host}: {e}")
            return None
    
    async def execute_proxmox_container_create(self, parameters: Dict[str, Any]) -> ExecutionResult:
        """Execute Proxmox container creation capability.
        
        Args:
            parameters: Capability parameters
            
        Returns:
            ExecutionResult with operation details
        """
        try:
            host = parameters["host"]
            template = parameters["template"]
            hostname = parameters["hostname"]
            
            # Create container configuration
            config = ContainerConfig(
                ostemplate=template,
                hostname=hostname,
                cores=parameters.get("cores", 1),
                memory=parameters.get("memory", 512),
                rootfs=parameters.get("rootfs", "local-lvm:10"),
                vmid=parameters.get("vmid")
            )
            
            # Add network configuration
            if parameters.get("ip_address") or parameters.get("network_bridge"):
                network_config = ProxmoxNetworkConfig(
                    bridge=parameters.get("network_bridge", "vmbr0"),
                    ip=parameters.get("ip_address")
                )
                config.net = [network_config]
            
            # Add password if provided
            if parameters.get("password"):
                config.password = parameters["password"]
            
            # Add SSH keys if provided
            if parameters.get("ssh_keys"):
                config.ssh_public_keys = parameters["ssh_keys"]
            
            # Try API first, then CLI fallback
            api_client = self._get_api_client(host)
            if api_client and await api_client.connect():
                result = await api_client.create_container(config)
            elif self._cli_client and host == "localhost":
                result = await self._cli_client.create_container_cli(config)
            else:
                return ExecutionResult(
                    status=ExecutionStatus.CONFIGURATION_ERROR,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error="No suitable client available for container creation",
                    duration=0.0
                )
            
            if result.status == "created":
                return ExecutionResult(
                    status=ExecutionStatus.SUCCESS,
                    success=True,
                    severity=ExecutionSeverity.INFO,
                    output=f"Container {result.vmid} created successfully",
                    duration=0.0,
                    metadata={
                        "vmid": result.vmid,
                        "task_id": result.task_id
                    }
                )
            else:
                return ExecutionResult(
                    status=ExecutionStatus.FAILURE,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error=f"Container creation failed: {result.message}",
                    duration=0.0
                )
        
        except Exception as e:
            logger.error(f"Failed to execute container create capability: {e}")
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                success=False,
                severity=ExecutionSeverity.ERROR,
                error=str(e),
                duration=0.0
            )
    
    async def execute_proxmox_container_start(self, parameters: Dict[str, Any]) -> ExecutionResult:
        """Execute Proxmox container start capability.
        
        Args:
            parameters: Capability parameters
            
        Returns:
            ExecutionResult with operation details
        """
        try:
            vmid = parameters["vmid"]
            host = parameters["host"]
            
            # Try API first, then CLI fallback
            api_client = self._get_api_client(host)
            if api_client and await api_client.connect():
                result = await api_client.start_container(vmid)
            elif self._cli_client and host == "localhost":
                result = await self._cli_client.start_container_cli(vmid)
            else:
                return ExecutionResult(
                    status=ExecutionStatus.CONFIGURATION_ERROR,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error="No suitable client available for container start",
                    duration=0.0
                )
            
            if result.status == "started":
                return ExecutionResult(
                    status=ExecutionStatus.SUCCESS,
                    success=True,
                    severity=ExecutionSeverity.INFO,
                    output=f"Container {vmid} started successfully",
                    duration=0.0,
                    metadata={
                        "vmid": vmid,
                        "task_id": result.task_id
                    }
                )
            else:
                return ExecutionResult(
                    status=ExecutionStatus.FAILURE,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error=f"Container start failed: {result.message}",
                    duration=0.0
                )
        
        except Exception as e:
            logger.error(f"Failed to execute container start capability: {e}")
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                success=False,
                severity=ExecutionSeverity.ERROR,
                error=str(e),
                duration=0.0
            )
    
    async def execute_proxmox_container_stop(self, parameters: Dict[str, Any]) -> ExecutionResult:
        """Execute Proxmox container stop capability.
        
        Args:
            parameters: Capability parameters
            
        Returns:
            ExecutionResult with operation details
        """
        try:
            vmid = parameters["vmid"]
            host = parameters["host"]
            force = parameters.get("force", False)
            
            # Try API first, then CLI fallback
            api_client = self._get_api_client(host)
            if api_client and await api_client.connect():
                result = await api_client.stop_container(vmid, force)
            elif self._cli_client and host == "localhost":
                result = await self._cli_client.stop_container_cli(vmid, force)
            else:
                return ExecutionResult(
                    status=ExecutionStatus.CONFIGURATION_ERROR,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error="No suitable client available for container stop",
                    duration=0.0
                )
            
            if result.status == "stopped":
                return ExecutionResult(
                    status=ExecutionStatus.SUCCESS,
                    success=True,
                    severity=ExecutionSeverity.INFO,
                    output=f"Container {vmid} stopped successfully",
                    duration=0.0,
                    metadata={
                        "vmid": vmid,
                        "task_id": result.task_id
                    }
                )
            else:
                return ExecutionResult(
                    status=ExecutionStatus.FAILURE,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error=f"Container stop failed: {result.message}",
                    duration=0.0
                )
        
        except Exception as e:
            logger.error(f"Failed to execute container stop capability: {e}")
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                success=False,
                severity=ExecutionSeverity.ERROR,
                error=str(e),
                duration=0.0
            )
    
    async def execute_proxmox_container_reboot(self, parameters: Dict[str, Any]) -> ExecutionResult:
        """Execute Proxmox container reboot capability.
        
        Args:
            parameters: Capability parameters
            
        Returns:
            ExecutionResult with operation details
        """
        try:
            vmid = parameters["vmid"]
            host = parameters["host"]
            
            # Try API first, then CLI fallback
            api_client = self._get_api_client(host)
            if api_client and await api_client.connect():
                result = await api_client.reboot_container(vmid)
            elif self._cli_client and host == "localhost":
                result = await self._cli_client.reboot_container_cli(vmid)
            else:
                return ExecutionResult(
                    status=ExecutionStatus.CONFIGURATION_ERROR,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error="No suitable client available for container reboot",
                    duration=0.0
                )
            
            if result.status == "rebooted":
                return ExecutionResult(
                    status=ExecutionStatus.SUCCESS,
                    success=True,
                    severity=ExecutionSeverity.INFO,
                    output=f"Container {vmid} rebooted successfully",
                    duration=0.0,
                    metadata={
                        "vmid": vmid,
                        "task_id": result.task_id
                    }
                )
            else:
                return ExecutionResult(
                    status=ExecutionStatus.FAILURE,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error=f"Container reboot failed: {result.message}",
                    duration=0.0
                )
        
        except Exception as e:
            logger.error(f"Failed to execute container reboot capability: {e}")
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                success=False,
                severity=ExecutionSeverity.ERROR,
                error=str(e),
                duration=0.0
            )
    
    async def execute_proxmox_container_delete(self, parameters: Dict[str, Any]) -> ExecutionResult:
        """Execute Proxmox container delete capability.
        
        Args:
            parameters: Capability parameters
            
        Returns:
            ExecutionResult with operation details
        """
        try:
            vmid = parameters["vmid"]
            host = parameters["host"]
            
            # Try API first, then CLI fallback
            api_client = self._get_api_client(host)
            if api_client and await api_client.connect():
                result = await api_client.delete_container(vmid)
            elif self._cli_client and host == "localhost":
                result = await self._cli_client.delete_container_cli(vmid)
            else:
                return ExecutionResult(
                    status=ExecutionStatus.CONFIGURATION_ERROR,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error="No suitable client available for container deletion",
                    duration=0.0
                )
            
            if result.status == "deleted":
                return ExecutionResult(
                    status=ExecutionStatus.SUCCESS,
                    success=True,
                    severity=ExecutionSeverity.WARNING,
                    output=f"Container {vmid} deleted successfully",
                    duration=0.0
                )
            else:
                return ExecutionResult(
                    status=ExecutionStatus.FAILURE,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error=f"Container deletion failed: {result.message}",
                    duration=0.0
                )
        
        except Exception as e:
            logger.error(f"Failed to execute container delete capability: {e}")
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                success=False,
                severity=ExecutionSeverity.ERROR,
                error=str(e),
                duration=0.0
            )
    
    async def execute_proxmox_container_clone(self, parameters: Dict[str, Any]) -> ExecutionResult:
        """Execute Proxmox container clone capability.
        
        Args:
            parameters: Capability parameters
            
        Returns:
            ExecutionResult with operation details
        """
        try:
            source_vmid = parameters["source_vmid"]
            new_hostname = parameters["new_hostname"]
            host = parameters["host"]
            
            # Create clone configuration
            clone_config = CloneConfig(
                hostname=new_hostname,
                newid=parameters.get("new_vmid"),
                full=parameters.get("full_clone", True)
            )
            
            # Try API first, then CLI fallback
            api_client = self._get_api_client(host)
            if api_client and await api_client.connect():
                result = await api_client.clone_container(source_vmid, clone_config)
            elif self._cli_client and host == "localhost":
                result = await self._cli_client.clone_container_cli(source_vmid, clone_config)
            else:
                return ExecutionResult(
                    status=ExecutionStatus.CONFIGURATION_ERROR,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error="No suitable client available for container cloning",
                    duration=0.0
                )
            
            if result.status == "cloned":
                return ExecutionResult(
                    status=ExecutionStatus.SUCCESS,
                    success=True,
                    severity=ExecutionSeverity.INFO,
                    output=f"Container cloned successfully to {result.vmid}",
                    duration=0.0,
                    metadata={
                        "source_vmid": source_vmid,
                        "new_vmid": result.vmid,
                        "task_id": result.task_id
                    }
                )
            else:
                return ExecutionResult(
                    status=ExecutionStatus.FAILURE,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error=f"Container clone failed: {result.message}",
                    duration=0.0
                )
        
        except Exception as e:
            logger.error(f"Failed to execute container clone capability: {e}")
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                success=False,
                severity=ExecutionSeverity.ERROR,
                error=str(e),
                duration=0.0
            )
    
    async def execute_proxmox_snapshot_create(self, parameters: Dict[str, Any]) -> ExecutionResult:
        """Execute Proxmox snapshot creation capability.
        
        Args:
            parameters: Capability parameters
            
        Returns:
            ExecutionResult with operation details
        """
        try:
            vmid = parameters["vmid"]
            snapshot_name = parameters["snapshot_name"]
            host = parameters["host"]
            description = parameters.get("description")
            
            # Try API first, then CLI fallback
            api_client = self._get_api_client(host)
            if api_client and await api_client.connect():
                result = await api_client.create_snapshot(vmid, snapshot_name, description)
            elif self._cli_client and host == "localhost":
                result = await self._cli_client.create_snapshot_cli(vmid, snapshot_name, description)
            else:
                return ExecutionResult(
                    status=ExecutionStatus.CONFIGURATION_ERROR,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error="No suitable client available for snapshot creation",
                    duration=0.0
                )
            
            if result.status == "created":
                return ExecutionResult(
                    status=ExecutionStatus.SUCCESS,
                    success=True,
                    severity=ExecutionSeverity.INFO,
                    output=f"Snapshot {snapshot_name} created successfully for {vmid}",
                    duration=0.0,
                    metadata={
                        "vmid": vmid,
                        "snapshot_name": snapshot_name,
                        "task_id": result.task_id
                    }
                )
            else:
                return ExecutionResult(
                    status=ExecutionStatus.FAILURE,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error=f"Snapshot creation failed: {result.message}",
                    duration=0.0
                )
        
        except Exception as e:
            logger.error(f"Failed to execute snapshot create capability: {e}")
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                success=False,
                severity=ExecutionSeverity.ERROR,
                error=str(e),
                duration=0.0
            )
    
    async def execute_proxmox_snapshot_delete(self, parameters: Dict[str, Any]) -> ExecutionResult:
        """Execute Proxmox snapshot deletion capability.
        
        Args:
            parameters: Capability parameters
            
        Returns:
            ExecutionResult with operation details
        """
        try:
            vmid = parameters["vmid"]
            snapshot_name = parameters["snapshot_name"]
            host = parameters["host"]
            
            # Try API first, then CLI fallback
            api_client = self._get_api_client(host)
            if api_client and await api_client.connect():
                result = await api_client.delete_snapshot(vmid, snapshot_name)
            elif self._cli_client and host == "localhost":
                result = await self._cli_client.delete_snapshot_cli(vmid, snapshot_name)
            else:
                return ExecutionResult(
                    status=ExecutionStatus.CONFIGURATION_ERROR,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error="No suitable client available for snapshot deletion",
                    duration=0.0
                )
            
            if result.status == "deleted":
                return ExecutionResult(
                    status=ExecutionStatus.SUCCESS,
                    success=True,
                    severity=ExecutionSeverity.WARNING,
                    output=f"Snapshot {snapshot_name} deleted successfully for {vmid}",
                    duration=0.0
                )
            else:
                return ExecutionResult(
                    status=ExecutionStatus.FAILURE,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error=f"Snapshot deletion failed: {result.message}",
                    duration=0.0
                )
        
        except Exception as e:
            logger.error(f"Failed to execute snapshot delete capability: {e}")
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                success=False,
                severity=ExecutionSeverity.ERROR,
                error=str(e),
                duration=0.0
            )
    
    async def execute_proxmox_snapshot_restore(self, parameters: Dict[str, Any]) -> ExecutionResult:
        """Execute Proxmox snapshot restore capability.
        
        Args:
            parameters: Capability parameters
            
        Returns:
            ExecutionResult with operation details
        """
        try:
            vmid = parameters["vmid"]
            snapshot_name = parameters["snapshot_name"]
            host = parameters["host"]
            rollback = parameters.get("rollback", False)
            
            # Try API first, then CLI fallback
            api_client = self._get_api_client(host)
            if api_client and await api_client.connect():
                result = await api_client.restore_snapshot(vmid, snapshot_name, rollback)
            elif self._cli_client and host == "localhost":
                result = await self._cli_client.restore_snapshot_cli(vmid, snapshot_name)
            else:
                return ExecutionResult(
                    status=ExecutionStatus.CONFIGURATION_ERROR,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error="No suitable client available for snapshot restore",
                    duration=0.0
                )
            
            if result.status == "restored":
                return ExecutionResult(
                    status=ExecutionStatus.SUCCESS,
                    success=True,
                    severity=ExecutionSeverity.WARNING,
                    output=f"Snapshot {snapshot_name} restored successfully for {vmid}",
                    duration=0.0,
                    metadata={
                        "vmid": vmid,
                        "snapshot_name": snapshot_name,
                        "task_id": result.task_id
                    }
                )
            else:
                return ExecutionResult(
                    status=ExecutionStatus.FAILURE,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error=f"Snapshot restore failed: {result.message}",
                    duration=0.0
                )
        
        except Exception as e:
            logger.error(f"Failed to execute snapshot restore capability: {e}")
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                success=False,
                severity=ExecutionSeverity.ERROR,
                error=str(e),
                duration=0.0
            )
    
    async def execute_proxmox_backup_create(self, parameters: Dict[str, Any]) -> ExecutionResult:
        """Execute Proxmox backup creation capability.
        
        Args:
            parameters: Capability parameters
            
        Returns:
            ExecutionResult with operation details
        """
        try:
            vmid = parameters["vmid"]
            storage = parameters["storage"]
            host = parameters["host"]
            
            # Create backup configuration
            backup_config = BackupConfig(
                node=host.split('.')[0] if '.' in host else host,
                storage=storage,
                mode=parameters.get("mode", "snapshot"),
                compress=parameters.get("compress", "gzip")
            )
            
            # Try API first, then CLI fallback
            api_client = self._get_api_client(host)
            if api_client and await api_client.connect():
                result = await api_client.create_backup(vmid, backup_config)
            elif self._cli_client and host == "localhost":
                result = await self._cli_client.create_backup_cli(vmid, backup_config)
            else:
                return ExecutionResult(
                    status=ExecutionStatus.CONFIGURATION_ERROR,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error="No suitable client available for backup creation",
                    duration=0.0
                )
            
            if result.status == "completed":
                return ExecutionResult(
                    status=ExecutionStatus.SUCCESS,
                    success=True,
                    severity=ExecutionSeverity.INFO,
                    output=f"Backup created successfully for {vmid}",
                    duration=0.0,
                    metadata={
                        "vmid": vmid,
                        "backup_id": result.backup_id,
                        "filename": result.filename,
                        "size": result.size,
                        "task_id": result.task_id
                    }
                )
            else:
                return ExecutionResult(
                    status=ExecutionStatus.FAILURE,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error=f"Backup creation failed: {result.message}",
                    duration=0.0
                )
        
        except Exception as e:
            logger.error(f"Failed to execute backup create capability: {e}")
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                success=False,
                severity=ExecutionSeverity.ERROR,
                error=str(e),
                duration=0.0
            )
    
    # Discovery capability methods
    
    async def execute_proxmox_discover_hosts(self, parameters: Dict[str, Any]) -> ExecutionResult:
        """Execute Proxmox host discovery capability.
        
        Args:
            parameters: Capability parameters
            
        Returns:
            ExecutionResult with operation details
        """
        try:
            from src.services.proxmox_discovery_enhanced import ProxmoxDiscoveryEnhanced
            
            force_refresh = parameters.get("force_refresh", False)
            
            # Create discovery service
            discovery = ProxmoxDiscoveryEnhanced(
                api_credentials=self.api_credentials
            )
            
            # Discover hosts
            hosts = await discovery.discover_proxmox_hosts(force_refresh)
            
            host_list = []
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
                    "tags": host.tags
                }
                host_list.append(host_info)
            
            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                success=True,
                severity=ExecutionSeverity.INFO,
                output=f"Discovered {len(host_list)} Proxmox hosts",
                duration=0.0,
                data={"hosts": host_list}
            )
        
        except Exception as e:
            logger.error(f"Failed to execute host discovery capability: {e}")
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                success=False,
                severity=ExecutionSeverity.ERROR,
                error=str(e),
                duration=0.0
            )
    
    async def execute_proxmox_discover_containers(self, parameters: Dict[str, Any]) -> ExecutionResult:
        """Execute Proxmox container discovery capability.
        
        Args:
            parameters: Capability parameters
            
        Returns:
            ExecutionResult with operation details
        """
        try:
            from src.services.proxmox_discovery_enhanced import ProxmoxDiscoveryEnhanced
            
            host_address = parameters["host"]
            force_refresh = parameters.get("force_refresh", False)
            
            # Find host in discovered hosts
            discovery = ProxmoxDiscoveryEnhanced(
                api_credentials=self.api_credentials
            )
            hosts = await discovery.discover_proxmox_hosts()
            
            target_host = None
            for host in hosts:
                if host.address == host_address:
                    target_host = host
                    break
            
            if not target_host:
                return ExecutionResult(
                    status=ExecutionStatus.FAILURE,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error=f"Host {host_address} not found",
                    duration=0.0
                )
            
            # Discover containers
            containers = await discovery.discover_containers(target_host, force_refresh)
            
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
                    "tags": container.tags
                }
                container_list.append(container_info)
            
            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                success=True,
                severity=ExecutionSeverity.INFO,
                output=f"Discovered {len(container_list)} containers on {host_address}",
                duration=0.0,
                data={"containers": container_list}
            )
        
        except Exception as e:
            logger.error(f"Failed to execute container discovery capability: {e}")
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                success=False,
                severity=ExecutionSeverity.ERROR,
                error=str(e),
                duration=0.0
            )
    
    def get_capability_map(self) -> Dict[OperationType, callable]:
        """Get mapping of Proxmox operations to their execution methods.
        
        Returns:
            Dictionary mapping operations to methods
        """
        return {
            ProxmoxOperationType.PROXMOX_CONTAINER_CREATE: self.execute_proxmox_container_create,
            ProxmoxOperationType.PROXMOX_CONTAINER_START: self.execute_proxmox_container_start,
            ProxmoxOperationType.PROXMOX_CONTAINER_STOP: self.execute_proxmox_container_stop,
            ProxmoxOperationType.PROXMOX_CONTAINER_REBOOT: self.execute_proxmox_container_reboot,
            ProxmoxOperationType.PROXMOX_CONTAINER_DELETE: self.execute_proxmox_container_delete,
            ProxmoxOperationType.PROXMOX_CONTAINER_CLONE: self.execute_proxmox_container_clone,
            ProxmoxOperationType.PROXMOX_SNAPSHOT_CREATE: self.execute_proxmox_snapshot_create,
            ProxmoxOperationType.PROXMOX_SNAPSHOT_DELETE: self.execute_proxmox_snapshot_delete,
            ProxmoxOperationType.PROXMOX_SNAPSHOT_RESTORE: self.execute_proxmox_snapshot_restore,
            ProxmoxOperationType.PROXMOX_BACKUP_CREATE: self.execute_proxmox_backup_create,
            ProxmoxOperationType.PROXMOX_DISCOVER_HOSTS: self.execute_proxmox_discover_hosts,
            ProxmoxOperationType.PROXMOX_DISCOVER_CONTAINERS: self.execute_proxmox_discover_containers,
        }
    
    async def cleanup(self):
        """Cleanup Proxmox capability executor resources."""
        # Close API clients
        for api_client in self._api_clients.values():
            await api_client.disconnect()
        
        self._api_clients.clear()
        logger.info("Proxmox capability executor cleaned up")


# Capability operation helpers for easier integration

class ProxmoxCapability:
    """Static helper class for Proxmox capability operations."""
    
    @staticmethod
    async def create_ct_from_template(template_id: int, config: ContainerConfig) -> OperationResult:
        """Create container from template.
        
        Args:
            template_id: Template container ID
            config: Container configuration
            
        Returns:
            OperationResult with creation details
        """
        try:
            # This would use the capability executor
            # Implementation would depend on how capabilities are invoked
            return OperationResult.failure("Not implemented", "Use ProxmoxCapabilityExecutor")
        except Exception as e:
            return OperationResult.failure(str(e))
    
    @staticmethod
    async def backup_ct(container_id: int, backup_config: BackupConfig) -> OperationResult:
        """Backup container.
        
        Args:
            container_id: Container ID
            backup_config: Backup configuration
            
        Returns:
            OperationResult with backup details
        """
        try:
            return OperationResult.failure("Not implemented", "Use ProxmoxCapabilityExecutor")
        except Exception as e:
            return OperationResult.failure(str(e))
    
    @staticmethod
    async def restore_ct(backup_id: str, target_config: Dict[str, Any]) -> OperationResult:
        """Restore container from backup.
        
        Args:
            backup_id: Backup ID
            target_config: Target restoration configuration
            
        Returns:
            OperationResult with restore details
        """
        try:
            return OperationResult.failure("Not implemented", "Use ProxmoxCapabilityExecutor")
        except Exception as e:
            return OperationResult.failure(str(e))
    
    @staticmethod
    async def snapshot_ct(container_id: int, snapshot_name: str) -> OperationResult:
        """Create snapshot of container.
        
        Args:
            container_id: Container ID
            snapshot_name: Snapshot name
            
        Returns:
            OperationResult with snapshot details
        """
        try:
            return OperationResult.failure("Not implemented", "Use ProxmoxCapabilityExecutor")
        except Exception as e:
            return OperationResult.failure(str(e))
    
    @staticmethod
    async def clone_ct(source_id: int, clone_config: CloneConfig) -> OperationResult:
        """Clone container.
        
        Args:
            source_id: Source container ID
            clone_config: Clone configuration
            
        Returns:
            OperationResult with clone details
        """
        try:
            return OperationResult.failure("Not implemented", "Use ProxmoxCapabilityExecutor")
        except Exception as e:
            return OperationResult.failure(str(e))
    
    @staticmethod
    async def migrate_ct(container_id: int, target_host: str) -> OperationResult:
        """Migrate container to target host.
        
        Args:
            container_id: Container ID
            target_host: Target host address
            
        Returns:
            OperationResult with migration details
        """
        try:
            return OperationResult.failure("Not implemented", "Use ProxmoxCapabilityExecutor")
        except Exception as e:
            return OperationResult.failure(str(e))