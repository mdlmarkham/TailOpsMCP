"""
Proxmox-specific data models for API responses and configurations.

This module provides comprehensive data models for working with Proxmox VE API,
including container/VM configurations, backup settings, snapshot metadata, and
API response structures.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from datetime import timezone, timezone
from enum import Enum
from typing import Dict, List, Optional, Any


class ProxmoxResourceType(str, Enum):
    """Proxmox resource types."""

    NODE = "node"
    LXC_CONTAINER = "lxc"
    QEMU_VM = "qemu"
    STORAGE = "storage"
    NETWORK = "net"
    SNAPSHOT = "snapshot"
    BACKUP = "backup"


class ProxmoxStatus(str, Enum):
    """Proxmox resource status values."""

    STOPPED = "stopped"
    RUNNING = "running"
    PAUSED = "paused"
    ERROR = "error"
    UNKNOWN = "unknown"
    STARTING = "starting"
    STOPPING = "stopping"
    MIGRATING = "migrating"
    FROZEN = "frozen"


class BackupType(str, Enum):
    """Backup types."""

    STOPPED = "stopped"
    SUSPEND = "suspend"
    SNAPSHOT = "snapshot"


class StorageType(str, Enum):
    """Storage pool types."""

    DIR = "dir"
    NFS = "nfs"
    CIFS = "cifs"
    LVM = "lvm"
    LVM_THIN = "lvm-thin"
    ZFS = "zfs"
    BTRFS = "btrfs"


@dataclass
class ProxmoxAPICredentials:
    """Proxmox API authentication credentials."""

    host: str
    username: str
    password: Optional[str] = None
    token: Optional[str] = None
    token_name: Optional[str] = None
    realm: str = "pam"
    port: int = 8006
    verify_ssl: bool = True
    timeout: int = 30
    max_retries: int = 3

    def validate(self) -> List[str]:
        """Validate credentials configuration."""
        errors = []

        if not self.host:
            errors.append("Host is required")
        if not self.username:
            errors.append("Username is required")
        if not self.password and not self.token:
            errors.append("Either password or API token must be provided")
        if self.token and not self.token_name:
            errors.append("Token name is required when using API token")
        if self.port <= 0 or self.port > 65535:
            errors.append("Port must be between 1 and 65535")

        return errors


@dataclass
class ProxmoxNetworkConfig:
    """Network configuration for containers/VMs."""

    name: str = "eth0"
    bridge: str = "vmbr0"
    ip: Optional[str] = None
    ip6: Optional[str] = None
    netmask: Optional[str] = None
    gateway: Optional[str] = None
    gateway6: Optional[str] = None
    firewall: bool = False
    rate_limit: Optional[str] = None


@dataclass
class ProxmoxResourceConfig:
    """Resource allocation configuration."""

    cores: int = 1
    memory: int = 512  # MB
    memory_limit: Optional[int] = None  # MB
    cpu: float = 1.0
    cpu_units: int = 1024


@dataclass
class ContainerConfig:
    """LXC Container configuration."""

    ostemplate: str
    hostname: str
    vmid: Optional[int] = None
    password: Optional[str] = None
    ssh_public_keys: Optional[List[str]] = None
    ssh_key_urls: Optional[List[str]] = None

    # Resource allocation
    cores: int = 1
    memory: int = 512  # MB
    rootfs: str = "local-lvm:10"
    swap: int = 0  # MB

    # Network configuration
    net: Optional[List[ProxmoxNetworkConfig]] = None

    # Container features
    features: Dict[str, bool] = field(
        default_factory=lambda: {"nesting": False, "keyctl": False, "mount": "nfs"}
    )

    # Boot order and auto-start
    boot: str = "c"
    bootorder: Optional[str] = None
    onboot: bool = True
    startup: str = ""

    # Backup and snapshot settings
    backup: bool = True
    freeze: bool = False

    def to_proxmox_config(self) -> Dict[str, Any]:
        """Convert to Proxmox API configuration format."""
        config = {}

        # Basic settings
        if self.ostemplate:
            config["ostemplate"] = self.ostemplate
        if self.hostname:
            config["hostname"] = self.hostname
        if self.password:
            config["password"] = self.password
        if self.ssh_public_keys:
            config["ssh-public-keys"] = "\n".join(self.ssh_public_keys)
        if self.ssh_key_urls:
            config["ssh-key-urls"] = ",".join(self.ssh_key_urls)

        # Resource allocation
        config["cores"] = self.cores
        config["memory"] = self.memory
        config["rootfs"] = self.rootfs
        if self.swap > 0:
            config["swap"] = self.swap

        # Network configuration
        if self.net:
            networks = []
            for net in self.net:
                net_config = f"name={net.name},bridge={net.bridge}"
                if net.ip:
                    net_config += f",ip={net.ip}"
                if net.gateway:
                    net_config += f",gw={net.gateway}"
                if net.firewall:
                    net_config += ",firewall=1"
                networks.append(net_config)
            config["net"] = networks

        # Features
        for feature, enabled in self.features.items():
            config[f"features.{feature}"] = 1 if enabled else 0

        # Boot and startup
        config["boot"] = self.boot
        config["onboot"] = 1 if self.onboot else 0
        if self.startup:
            config["startup"] = self.startup

        # Backup settings
        config["backup"] = 1 if self.backup else 0
        config["freeze"] = 1 if self.freeze else 0

        return config


@dataclass
class VMConfig:
    """QEMU VM configuration."""

    name: str
    vmid: Optional[int] = None
    ostype: str = "l26"  # Linux kernel 2.6+
    vga: str = "qxl"
    memory: int = 512  # MB
    cores: int = 1
    sockets: int = 1
    cpu: str = "host"

    # Storage configuration
    scsi0: Optional[str] = None  # e.g., "local-lvm:10"
    scsihw: str = "virtio-scsi-pci"

    # Network configuration
    net0: Optional[str] = None  # e.g., "virtio,bridge=vmbr0"

    # Boot and startup
    boot: str = "cdn"
    bootdisk: Optional[str] = None
    onboot: bool = True
    startup: str = ""

    # Display and console
    display: str = "qxl"
    serial0: Optional[str] = "socket"

    # Backup settings
    backup: bool = True

    def to_proxmox_config(self) -> Dict[str, Any]:
        """Convert to Proxmox API configuration format."""
        config = {}

        # Basic settings
        config["name"] = self.name
        config["ostype"] = self.ostype
        config["vga"] = self.vga

        # Resource allocation
        config["memory"] = self.memory
        config["cores"] = self.cores
        config["sockets"] = self.sockets
        config["cpu"] = self.cpu

        # Storage
        if self.scsi0:
            config["scsi0"] = self.scsi0
        config["scsihw"] = self.scsihw

        # Network
        if self.net0:
            config["net0"] = self.net0

        # Boot and startup
        config["boot"] = self.boot
        if self.bootdisk:
            config["bootdisk"] = self.bootdisk
        config["onboot"] = 1 if self.onboot else 0
        if self.startup:
            config["startup"] = self.startup

        # Display and console
        config["display"] = self.display
        if self.serial0:
            config["serial0"] = self.serial0

        # Backup settings
        config["backup"] = 1 if self.backup else 0

        return config


@dataclass
class CloneConfig:
    """Container/VM cloning configuration."""

    newid: Optional[int] = None
    name: Optional[str] = None
    hostname: Optional[str] = None
    full: bool = True
    storage: Optional[str] = None
    format: str = "qcow2"
    pool: Optional[str] = None

    # Resource modifications for clone
    memory: Optional[int] = None
    cores: Optional[int] = None

    def to_proxmox_config(self) -> Dict[str, Any]:
        """Convert to Proxmox API configuration format."""
        config = {}

        if self.newid:
            config["newid"] = self.newid
        if self.name:
            config["name"] = self.name
        if self.hostname:
            config["hostname"] = self.hostname
        if self.full is not None:
            config["full"] = 1 if self.full else 0
        if self.storage:
            config["storage"] = self.storage
        if self.format:
            config["format"] = self.format
        if self.pool:
            config["pool"] = self.pool

        if self.memory:
            config["memory"] = self.memory
        if self.cores:
            config["cores"] = self.cores

        return config


@dataclass
class BackupConfig:
    """Backup configuration."""

    node: str
    storage: str
    backup_type: BackupType = BackupType.STOPPED
    compress: str = "gzip"  # gzip, lzo, zstd
    mode: str = "snapshot"  # snapshot, suspend, stop
    quiet: bool = False
    mailto: Optional[List[str]] = None
    notification: str = "always"

    # Retention settings
    keep: Optional[int] = None  # Number of backups to keep

    # Schedule
    schedule: Optional[str] = None  # e.g., "01:00"

    def to_proxmox_config(self) -> Dict[str, Any]:
        """Convert to Proxmox API configuration format."""
        config = {
            "node": self.node,
            "storage": self.storage,
            "compress": self.compress,
            "mode": self.mode,
            "notification": self.notification,
        }

        if self.keep:
            config["keep"] = self.keep
        if self.schedule:
            config["schedule"] = self.schedule
        if self.mailto:
            config["mailto"] = ",".join(self.mailto)
        if self.quiet:
            config["quiet"] = 1

        return config


@dataclass
class ProxmoxContainer:
    """Proxmox container information from API."""

    vmid: int
    node: str
    name: str
    status: ProxmoxStatus
    uptime: Optional[int] = None
    cpu: Optional[float] = None
    maxcpu: Optional[float] = None
    mem: Optional[int] = None
    maxmem: Optional[int] = None
    disk: Optional[int] = None
    maxdisk: Optional[int] = None

    # Configuration details
    ostemplate: Optional[str] = None
    hostname: Optional[str] = None
    password: Optional[str] = None
    ssh_public_keys: Optional[str] = None
    cores: int = 1
    memory: int = 512
    rootfs: str = ""
    swap: int = 0

    # Network details
    net: Optional[str] = None

    # Discovery metadata
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z"
    )
    last_seen: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    @classmethod
    def from_api_response(cls, vmid: int, data: Dict[str, Any]) -> ProxmoxContainer:
        """Create from Proxmox API response."""
        return cls(
            vmid=vmid,
            node=data.get("node", ""),
            name=data.get("name", ""),
            status=ProxmoxStatus(data.get("status", "unknown")),
            uptime=data.get("uptime"),
            cpu=data.get("cpu"),
            maxcpu=data.get("maxcpu"),
            mem=data.get("mem"),
            maxmem=data.get("maxmem"),
            disk=data.get("disk"),
            maxdisk=data.get("maxdisk"),
            ostemplate=data.get("ostemplate"),
            hostname=data.get("hostname"),
            password=data.get("password"),
            ssh_public_keys=data.get("ssh-public-keys"),
            cores=data.get("cores", 1),
            memory=data.get("memory", 512),
            rootfs=data.get("rootfs", ""),
            swap=data.get("swap", 0),
            net=data.get("net"),
            tags=["lxc", "proxmox"],
        )


@dataclass
class ProxmoxVM:
    """Proxmox VM information from API."""

    vmid: int
    node: str
    name: str
    status: ProxmoxStatus
    uptime: Optional[int] = None
    cpu: Optional[float] = None
    maxcpu: Optional[float] = None
    mem: Optional[int] = None
    maxmem: Optional[int] = None
    disk: Optional[int] = None
    maxdisk: Optional[int] = None

    # Configuration details
    ostype: Optional[str] = None
    vga: Optional[str] = None
    memory: int = 512
    cores: int = 1
    sockets: int = 1
    scsi0: Optional[str] = None

    # Network details
    net0: Optional[str] = None

    # Discovery metadata
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z"
    )
    last_seen: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    @classmethod
    def from_api_response(cls, vmid: int, data: Dict[str, Any]) -> ProxmoxVM:
        """Create from Proxmox API response."""
        return cls(
            vmid=vmid,
            node=data.get("node", ""),
            name=data.get("name", ""),
            status=ProxmoxStatus(data.get("status", "unknown")),
            uptime=data.get("uptime"),
            cpu=data.get("cpu"),
            maxcpu=data.get("maxcpu"),
            mem=data.get("mem"),
            maxmem=data.get("maxmem"),
            disk=data.get("disk"),
            maxdisk=data.get("maxdisk"),
            ostype=data.get("ostype"),
            vga=data.get("vga"),
            memory=data.get("memory", 512),
            cores=data.get("cores", 1),
            sockets=data.get("sockets", 1),
            scsi0=data.get("scsi0"),
            net0=data.get("net0"),
            tags=["vm", "qemu", "proxmox"],
        )


@dataclass
class ProxmoxSnapshot:
    """Proxmox snapshot information."""

    name: str
    vmid: int
    node: str
    parent: Optional[str] = None
    timestamp: Optional[int] = None
    description: Optional[str] = None
    size: Optional[int] = None

    @classmethod
    def from_api_response(cls, vmid: int, data: Dict[str, Any]) -> ProxmoxSnapshot:
        """Create from Proxmox API response."""
        return cls(
            name=data.get("name", ""),
            vmid=vmid,
            node=data.get("node", ""),
            parent=data.get("parent"),
            timestamp=data.get("timestamp"),
            description=data.get("description"),
            size=data.get("size"),
        )


@dataclass
class ProxmoxBackup:
    """Proxmox backup information."""

    backup_id: str
    vmid: int
    node: str
    storage: str
    filename: str
    size: int
    ctime: int  # Creation timestamp
    content: str
    protected: bool = False

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> ProxmoxBackup:
        """Create from Proxmox API response."""
        return cls(
            backup_id=data.get("volid", ""),
            vmid=data.get("vmid", 0),
            node=data.get("node", ""),
            storage=data.get("storage", ""),
            filename=data.get("filename", ""),
            size=data.get("size", 0),
            ctime=data.get("ctime", 0),
            content=data.get("content", ""),
            protected=data.get("protected", False),
        )


@dataclass
class ProxmoxStorage:
    """Proxmox storage pool information."""

    storage: str
    type: StorageType
    node: str
    enabled: bool = True
    content: List[str] = field(default_factory=list)
    shared: bool = False
    maxfiles: Optional[int] = None
    used: Optional[int] = None
    total: Optional[int] = None

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> ProxmoxStorage:
        """Create from Proxmox API response."""
        return cls(
            storage=data.get("storage", ""),
            type=StorageType(data.get("type", "dir")),
            node=data.get("node", ""),
            enabled=data.get("enabled", True),
            content=data.get("content", "").split(",") if data.get("content") else [],
            shared=data.get("shared", False),
            maxfiles=data.get("maxfiles"),
            used=data.get("used"),
            total=data.get("total"),
        )


@dataclass
class ProxmoxNode:
    """Proxmox node information."""

    node: str
    status: str
    uptime: Optional[int] = None
    cpu: Optional[float] = None
    maxcpu: Optional[float] = None
    mem: Optional[int] = None
    maxmem: Optional[int] = None
    disk: Optional[int] = None
    maxdisk: Optional[int] = None
    level: Optional[str] = None

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> ProxmoxNode:
        """Create from Proxmox API response."""
        return cls(
            node=data.get("node", ""),
            status=data.get("status", ""),
            uptime=data.get("uptime"),
            cpu=data.get("cpu"),
            maxcpu=data.get("maxcpu"),
            mem=data.get("mem"),
            maxmem=data.get("maxmem"),
            disk=data.get("disk"),
            maxdisk=data.get("maxdisk"),
            level=data.get("level"),
        )


# API Response Models


@dataclass
class ProxmoxAPIResponse:
    """Generic Proxmox API response wrapper."""

    data: Optional[Any] = None
    errors: List[str] = field(default_factory=list)
    success: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class ContainerCreationResult:
    """Result of container creation operation."""

    vmid: int
    task_id: Optional[str] = None
    status: str = "created"
    message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class CloneResult:
    """Result of cloning operation."""

    vmid: int
    task_id: Optional[str] = None
    status: str = "cloned"
    message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class DeleteResult:
    """Result of deletion operation."""

    status: str = "deleted"
    message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class SnapshotResult:
    """Result of snapshot operation."""

    name: str
    task_id: Optional[str] = None
    status: str = "created"
    message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class BackupResult:
    """Result of backup operation."""

    backup_id: str
    filename: str
    size: int
    task_id: Optional[str] = None
    status: str = "completed"
    message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class RestoreResult:
    """Result of restore operation."""

    task_id: Optional[str] = None
    status: str = "restored"
    message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class UpdateResult:
    """Result of update operation."""

    status: str = "updated"
    message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class StartResult:
    """Result of start operation."""

    task_id: Optional[str] = None
    status: str = "started"
    message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class StopResult:
    """Result of stop operation."""

    task_id: Optional[str] = None
    status: str = "stopped"
    message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class RebootResult:
    """Result of reboot operation."""

    task_id: Optional[str] = None
    status: str = "rebooted"
    message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class OperationResult:
    """Generic operation result."""

    success: bool = True
    status: str = "completed"
    message: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        # Remove None values
        return {k: v for k, v in result.items() if v is not None}

    @classmethod
    def failure(cls, error: str, message: Optional[str] = None) -> OperationResult:
        """Create a failure result."""
        return cls(
            success=False, status="failed", error=error, message=message or error
        )
