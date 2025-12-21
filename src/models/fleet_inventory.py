"""
Fleet Inventory Model for Gateway Fleet Orchestrator.

This module provides the canonical data model for representing the entire fleet state,
including Proxmox hosts, containers/VMs, services, snapshots, and events.

ENHANCED: This file now contains all fleet inventory functionality including:
- Core data models (ProxmoxHost, Node, Service, Snapshot, Event)
- Enhanced models with rich metadata (EnhancedTarget, EnhancedService)
- Network, security, and resource management
- Health monitoring and stack management
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from datetime import timezone, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
from uuid import uuid4

from pydantic import BaseModel, Field


class ConnectionMethod(str, Enum):
    """Connection methods for nodes."""

    SSH = "ssh"
    TAILSCALE_SSH = "tailscale_ssh"
    PROXMOX_API = "proxmox_api"
    DOCKER_API = "docker_api"


class Runtime(str, Enum):
    """Runtime environments on nodes."""

    DOCKER = "docker"
    SYSTEMD = "systemd"
    PROXMOX = "proxmox"
    BARE_METAL = "bare_metal"


class NodeType(str, Enum):
    """Node types (containers vs VMs)."""

    CONTAINER = "container"
    VM = "vm"
    BARE_METAL = "bare_metal"


class ServiceStatus(str, Enum):
    """Service status values."""

    RUNNING = "running"
    STOPPED = "stopped"
    FAILED = "failed"
    UNKNOWN = "unknown"


class SnapshotType(str, Enum):
    """Snapshot types."""

    FULL = "full"
    INCREMENTAL = "incremental"
    APPLICATION = "application"
    SYSTEM = "system"


class EventType(str, Enum):
    """Event types for audit and system events."""

    DISCOVERY = "discovery"
    HEALTH_CHECK = "health_check"
    BACKUP = "backup"
    SNAPSHOT = "snapshot"
    DEPLOYMENT = "deployment"
    SECURITY = "security"
    POLICY = "policy"
    ERROR = "error"


class EventSeverity(str, Enum):
    """Event severity levels."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


# Enhanced enums for rich metadata
class NodeRole(str, Enum):
    """Node roles in the fleet."""

    PRODUCTION = "production"
    DEVELOPMENT = "development"
    LAB = "lab"
    STAGING = "staging"
    TESTING = "testing"
    MONITORING = "monitoring"
    GATEWAY = "gateway"


class ResourceStatus(str, Enum):
    """Resource utilization status."""

    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class SecurityStatus(str, Enum):
    """Security posture status."""

    SECURE = "secure"
    WARNING = "warning"
    VULNERABLE = "vulnerable"
    UNKNOWN = "unknown"


class NodeStatus(str, Enum):
    """Node status values."""

    ONLINE = "online"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass
class ProxmoxHost:
    """Represents a Proxmox host with its metadata."""

    hostname: str
    address: str
    username: str
    node_name: str
    cpu_cores: int
    memory_mb: int
    storage_gb: int
    id: str = field(default_factory=lambda: str(uuid4()))
    port: int = 8006
    realm: str = "pam"
    cluster_name: Optional[str] = None
    version: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z"
    )
    last_seen: Optional[str] = None
    is_active: bool = True

    def validate(self) -> List[str]:
        """Validate Proxmox host configuration."""
        errors = []

        if not self.hostname:
            errors.append("Hostname is required")
        if not self.address:
            errors.append("Address is required")
        if not self.username:
            errors.append("Username is required")
        if not self.node_name:
            errors.append("Node name is required")
        if self.cpu_cores <= 0:
            errors.append("CPU cores must be positive")
        if self.memory_mb <= 0:
            errors.append("Memory must be positive")
        if self.storage_gb <= 0:
            errors.append("Storage must be positive")

        return errors

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ProxmoxHost:
        """Create from dictionary."""
        return cls(**data)


@dataclass
class Node:
    """Represents individual containers/VMs with their properties."""

    name: str
    node_type: NodeType
    host_id: str  # Reference to ProxmoxHost.id
    runtime: Runtime
    connection_method: ConnectionMethod
    id: str = field(default_factory=lambda: str(uuid4()))
    vmid: Optional[int] = None  # Proxmox VM/CT ID
    status: str = "stopped"
    cpu_cores: int = 1
    memory_mb: int = 512
    disk_gb: int = 10
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z")
    last_updated: Optional[str] = None
    is_managed: bool = False

    def validate(self) -> List[str]:
        """Validate node configuration."""
        errors = []

        if not self.name:
            errors.append("Node name is required")
        if not self.host_id:
            errors.append("Host ID is required")
        if self.cpu_cores <= 0:
            errors.append("CPU cores must be positive")
        if self.memory_mb <= 0:
            errors.append("Memory must be positive")
        if self.disk_gb <= 0:
            errors.append("Disk size must be positive")

        return errors

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Node:
        """Create from dictionary."""
        return cls(**data)


@dataclass
class Service:
    """Represents applications/services running on nodes."""

    name: str
    node_id: str  # Reference to Node.id
    service_type: str  # e.g., "docker", "systemd", "application"
    id: str = field(default_factory=lambda: str(uuid4()))
    status: ServiceStatus = ServiceStatus.UNKNOWN
    version: Optional[str] = None
    port: Optional[int] = None
    config_path: Optional[str] = None
    data_path: Optional[str] = None
    health_endpoint: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z")
    last_checked: Optional[str] = None
    is_monitored: bool = True

    def validate(self) -> List[str]:
        """Validate service configuration."""
        errors = []

        if not self.name:
            errors.append("Service name is required")
        if not self.node_id:
            errors.append("Node ID is required")

        return errors

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Service:
        """Create from dictionary."""
        return cls(**data)


@dataclass
class Snapshot:
    """Represents backup and snapshot information."""

    name: str
    snapshot_type: SnapshotType
    target_id: str  # Can be Node.id or Service.id
    target_type: str  # "node", "service"
    id: str = field(default_factory=lambda: str(uuid4()))
    size_mb: Optional[int] = None
    storage_path: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z")
    expires_at: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> List[str]:
        """Validate snapshot configuration."""
        errors = []

        if not self.name:
            errors.append("Snapshot name is required")
        if not self.target_id:
            errors.append("Target ID is required")
        if self.target_type not in ["node", "service"]:
            errors.append("Target type must be 'node' or 'service'")

        return errors

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Snapshot:
        """Create from dictionary."""
        return cls(**data)


@dataclass
class Event:
    """Represents system events and audit records."""

    event_type: EventType
    source: str  # e.g., "gateway", "discovery", "backup"
    message: str
    id: str = field(default_factory=lambda: str(uuid4()))
    severity: EventSeverity = EventSeverity.INFO
    target_id: Optional[str] = None  # Reference to Node.id, Service.id, etc.
    target_type: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z")
    user: Optional[str] = None
    correlation_id: Optional[str] = None

    def validate(self) -> List[str]:
        """Validate event data."""
        errors = []

        if not self.source:
            errors.append("Event source is required")
        if not self.message:
            errors.append("Event message is required")

        return errors

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Event:
        """Create from dictionary."""
        return cls(**data)


# Enhanced Pydantic models for rich metadata
class NetworkInterface(BaseModel):
    """Network interface configuration."""

    name: str
    ip_address: str
    subnet_mask: str
    gateway: Optional[str] = None
    dns_servers: List[str] = Field(default_factory=list)
    is_active: bool = True
    interface_type: str = "ethernet"  # ethernet, wireless, bridge, etc.


class ResourceUsage(BaseModel):
    """Resource utilization metrics."""

    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    disk_percent: float = 0.0
    network_rx_bytes: int = 0
    network_tx_bytes: int = 0
    status: ResourceStatus = ResourceStatus.UNKNOWN
    measured_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z"
    )


class SecurityPosture(BaseModel):
    """Security assessment and posture."""

    tls_enabled: bool = False
    tls_version: Optional[str] = None
    open_ports: List[int] = Field(default_factory=list)
    exposed_services: List[str] = Field(default_factory=list)
    firewall_status: str = "unknown"
    audit_enabled: bool = False
    last_audit: Optional[str] = None
    vulnerability_count: int = 0
    security_status: SecurityStatus = SecurityStatus.UNKNOWN


class ContainerInfo(BaseModel):
    """Enhanced container information."""

    container_id: Optional[str] = None
    image_name: Optional[str] = None
    image_tag: Optional[str] = None
    ports: Dict[int, int] = Field(default_factory=dict)  # container_port -> host_port
    volumes: List[str] = Field(default_factory=list)
    environment: Dict[str, str] = Field(default_factory=dict)
    command: Optional[str] = None
    restart_policy: str = "unless-stopped"


class StackInfo(BaseModel):
    """Docker Compose stack information."""

    stack_name: str
    compose_file_path: str
    services: List[str] = Field(default_factory=list)
    networks: List[str] = Field(default_factory=list)
    volumes: List[str] = Field(default_factory=list)
    stack_status: str = "unknown"
    last_deployed: Optional[str] = None


@dataclass
class EnhancedTarget:
    """Enhanced target with rich metadata."""

    # Base target information (extends existing Node)
    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    node_type: NodeType = NodeType.CONTAINER
    host_id: str = ""
    runtime: Runtime = Runtime.DOCKER
    connection_method: ConnectionMethod = ConnectionMethod.SSH

    # Enhanced metadata
    role: NodeRole = NodeRole.DEVELOPMENT
    description: Optional[str] = None
    environment: Dict[str, Any] = Field(default_factory=dict)

    # Resource information
    cpu_cores: int = 1
    memory_mb: int = 512
    disk_gb: int = 10
    resource_usage: ResourceUsage = Field(default_factory=ResourceUsage)

    # Network topology
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    network_interfaces: List[NetworkInterface] = Field(default_factory=list)
    subnets: List[str] = field(default_factory=list)

    # Security posture
    security_posture: SecurityPosture = Field(default_factory=SecurityPosture)

    # Container information
    container_info: Optional[ContainerInfo] = None
    vmid: Optional[int] = None

    # Service mappings
    services: List[str] = field(default_factory=list)
    stacks: List[str] = field(default_factory=list)

    # Health monitoring
    status: str = "stopped"
    last_seen: Optional[str] = None
    last_health_check: Optional[str] = None
    health_score: float = 0.0

    # Lifecycle
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z")
    last_updated: Optional[str] = None
    is_managed: bool = False
    is_active: bool = True

    # Tags and metadata
    tags: List[str] = field(default_factory=list)
    custom_attributes: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> List[str]:
        """Validate enhanced target configuration."""
        errors = []

        if not self.name:
            errors.append("Target name is required")
        if not self.host_id:
            errors.append("Host ID is required")
        if self.cpu_cores <= 0:
            errors.append("CPU cores must be positive")
        if self.memory_mb <= 0:
            errors.append("Memory must be positive")
        if self.disk_gb <= 0:
            errors.append("Disk size must be positive")

        return errors

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "node_type": self.node_type.value,
            "host_id": self.host_id,
            "runtime": self.runtime.value,
            "connection_method": self.connection_method.value,
            "role": self.role.value,
            "description": self.description,
            "environment": self.environment,
            "cpu_cores": self.cpu_cores,
            "memory_mb": self.memory_mb,
            "disk_gb": self.disk_gb,
            "resource_usage": self.resource_usage.dict(),
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "network_interfaces": [ni.dict() for ni in self.network_interfaces],
            "subnets": self.subnets,
            "security_posture": self.security_posture.dict(),
            "container_info": self.container_info.dict()
            if self.container_info
            else None,
            "vmid": self.vmid,
            "services": self.services,
            "stacks": self.stacks,
            "status": self.status,
            "last_seen": self.last_seen,
            "last_health_check": self.last_health_check,
            "health_score": self.health_score,
            "created_at": self.created_at,
            "last_updated": self.last_updated,
            "is_managed": self.is_managed,
            "is_active": self.is_active,
            "tags": self.tags,
            "custom_attributes": self.custom_attributes,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EnhancedTarget:
        """Create EnhancedTarget from dictionary."""
        # Convert basic fields
        target = cls(
            id=data["id"],
            name=data["name"],
            node_type=NodeType(data["node_type"]),
            host_id=data["host_id"],
            runtime=Runtime(data["runtime"]),
            connection_method=ConnectionMethod(data["connection_method"]),
            role=NodeRole(data.get("role", "development")),
            description=data.get("description"),
            environment=data.get("environment", {}),
            cpu_cores=data.get("cpu_cores", 1),
            memory_mb=data.get("memory_mb", 512),
            disk_gb=data.get("disk_gb", 10),
            ip_address=data.get("ip_address"),
            mac_address=data.get("mac_address"),
            vmid=data.get("vmid"),
            services=data.get("services", []),
            stacks=data.get("stacks", []),
            status=data.get("status", "stopped"),
            last_seen=data.get("last_seen"),
            last_health_check=data.get("last_health_check"),
            health_score=data.get("health_score", 0.0),
            created_at=data.get("created_at"),
            last_updated=data.get("last_updated"),
            is_managed=data.get("is_managed", False),
            is_active=data.get("is_active", True),
            tags=data.get("tags", []),
            custom_attributes=data.get("custom_attributes", {}),
        )

        # Convert nested objects
        if "resource_usage" in data:
            target.resource_usage = ResourceUsage(**data["resource_usage"])

        if "network_interfaces" in data:
            target.network_interfaces = [
                NetworkInterface(**ni) for ni in data["network_interfaces"]
            ]

        if "security_posture" in data:
            target.security_posture = SecurityPosture(**data["security_posture"])

        if "container_info" in data and data["container_info"]:
            target.container_info = ContainerInfo(**data["container_info"])

        return target


@dataclass
class EnhancedService:
    """Enhanced service with stack mappings and health monitoring."""

    # Base service information
    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    target_id: str = ""  # Reference to EnhancedTarget.id
    service_type: str = "application"  # docker, systemd, application, etc.
    status: ServiceStatus = ServiceStatus.UNKNOWN

    # Enhanced metadata
    version: Optional[str] = None
    port: Optional[int] = None
    protocol: str = "tcp"
    config_path: Optional[str] = None
    data_path: Optional[str] = None
    health_endpoint: Optional[str] = None

    # Stack mappings
    stack_name: Optional[str] = None
    depends_on: List[str] = field(default_factory=list)
    environment: Dict[str, str] = Field(default_factory=dict)

    # Resource requirements
    cpu_limit: Optional[float] = None
    memory_limit: Optional[int] = None
    restart_policy: str = "unless-stopped"

    # Health monitoring
    health_check_enabled: bool = True
    health_check_interval: int = 30  # seconds
    health_check_timeout: int = 5  # seconds
    health_check_retries: int = 3
    last_health_check: Optional[str] = None
    health_status: str = "unknown"

    # Security
    tls_enabled: bool = False
    tls_port: Optional[int] = None
    exposed_ports: List[int] = Field(default_factory=list)
    security_context: Dict[str, Any] = Field(default_factory=dict)

    # Lifecycle
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z")
    last_checked: Optional[str] = None
    last_updated: Optional[str] = None
    is_monitored: bool = True
    is_managed: bool = False

    # Tags and metadata
    tags: List[str] = field(default_factory=list)
    custom_attributes: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> List[str]:
        """Validate enhanced service configuration."""
        errors = []

        if not self.name:
            errors.append("Service name is required")
        if not self.target_id:
            errors.append("Target ID is required")

        return errors

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "target_id": self.target_id,
            "service_type": self.service_type,
            "status": self.status.value,
            "version": self.version,
            "port": self.port,
            "protocol": self.protocol,
            "config_path": self.config_path,
            "data_path": self.data_path,
            "health_endpoint": self.health_endpoint,
            "stack_name": self.stack_name,
            "depends_on": self.depends_on,
            "environment": self.environment,
            "cpu_limit": self.cpu_limit,
            "memory_limit": self.memory_limit,
            "restart_policy": self.restart_policy,
            "health_check_enabled": self.health_check_enabled,
            "health_check_interval": self.health_check_interval,
            "health_check_timeout": self.health_check_timeout,
            "health_check_retries": self.health_check_retries,
            "last_health_check": self.last_health_check,
            "health_status": self.health_status,
            "tls_enabled": self.tls_enabled,
            "tls_port": self.tls_port,
            "exposed_ports": self.exposed_ports,
            "security_context": self.security_context,
            "created_at": self.created_at,
            "last_checked": self.last_checked,
            "last_updated": self.last_updated,
            "is_monitored": self.is_monitored,
            "is_managed": self.is_managed,
            "tags": self.tags,
            "custom_attributes": self.custom_attributes,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EnhancedService:
        """Create EnhancedService from dictionary."""
        return cls(
            id=data["id"],
            name=data["name"],
            target_id=data["target_id"],
            service_type=data.get("service_type", "application"),
            status=ServiceStatus(data.get("status", "unknown")),
            version=data.get("version"),
            port=data.get("port"),
            protocol=data.get("protocol", "tcp"),
            config_path=data.get("config_path"),
            data_path=data.get("data_path"),
            health_endpoint=data.get("health_endpoint"),
            stack_name=data.get("stack_name"),
            depends_on=data.get("depends_on", []),
            environment=data.get("environment", {}),
            cpu_limit=data.get("cpu_limit"),
            memory_limit=data.get("memory_limit"),
            restart_policy=data.get("restart_policy", "unless-stopped"),
            health_check_enabled=data.get("health_check_enabled", True),
            health_check_interval=data.get("health_check_interval", 30),
            health_check_timeout=data.get("health_check_timeout", 5),
            health_check_retries=data.get("health_check_retries", 3),
            last_health_check=data.get("last_health_check"),
            health_status=data.get("health_status", "unknown"),
            tls_enabled=data.get("tls_enabled", False),
            tls_port=data.get("tls_port"),
            exposed_ports=data.get("exposed_ports", []),
            security_context=data.get("security_context", {}),
            created_at=data.get("created_at"),
            last_checked=data.get("last_checked"),
            last_updated=data.get("last_updated"),
            is_monitored=data.get("is_monitored", True),
            is_managed=data.get("is_managed", False),
            tags=data.get("tags", []),
            custom_attributes=data.get("custom_attributes", {}),
        )


class FleetInventory(BaseModel):
    """Comprehensive fleet inventory model that aggregates all entities."""

    # Core entities
    proxmox_hosts: Dict[str, ProxmoxHost] = Field(default_factory=dict)
    nodes: Dict[str, Node] = Field(default_factory=dict)
    services: Dict[str, Service] = Field(default_factory=dict)
    snapshots: Dict[str, Snapshot] = Field(default_factory=dict)
    events: Dict[str, Event] = Field(default_factory=dict)

    # Enhanced entities
    enhanced_targets: Dict[str, EnhancedTarget] = Field(default_factory=dict)
    enhanced_services: Dict[str, EnhancedService] = Field(default_factory=dict)

    # Metadata
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z")
    last_updated: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z"
    )
    version: str = "1.0.0"

    # Fleet metrics
    total_hosts: int = 0
    total_nodes: int = 0
    total_services: int = 0
    total_snapshots: int = 0
    total_enhanced_targets: int = 0
    total_enhanced_services: int = 0

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {datetime: lambda v: v.isoformat()}

    def add_proxmox_host(self, host: ProxmoxHost) -> None:
        """Add a Proxmox host to the inventory."""
        self.proxmox_hosts[host.id] = host
        self.total_hosts = len(self.proxmox_hosts)
        self.last_updated = datetime.now(timezone.utc).isoformat() + "Z"

    def add_node(self, node: Node) -> None:
        """Add a node to the inventory."""
        self.nodes[node.id] = node
        self.total_nodes = len(self.nodes)
        self.last_updated = datetime.now(timezone.utc).isoformat() + "Z"

    def add_service(self, service: Service) -> None:
        """Add a service to the inventory."""
        self.services[service.id] = service
        self.total_services = len(self.services)
        self.last_updated = datetime.now(timezone.utc).isoformat() + "Z"

    def add_snapshot(self, snapshot: Snapshot) -> None:
        """Add a snapshot to the inventory."""
        self.snapshots[snapshot.id] = snapshot
        self.total_snapshots = len(self.snapshots)
        self.last_updated = datetime.now(timezone.utc).isoformat() + "Z"

    def add_event(self, event: Event) -> None:
        """Add an event to the inventory."""
        self.events[event.id] = event
        self.last_updated = datetime.now(timezone.utc).isoformat() + "Z"

    def add_enhanced_target(self, target: EnhancedTarget) -> None:
        """Add an enhanced target to the inventory."""
        self.enhanced_targets[target.id] = target
        self.total_enhanced_targets = len(self.enhanced_targets)
        self.last_updated = datetime.now(timezone.utc).isoformat() + "Z"

    def add_enhanced_service(self, service: EnhancedService) -> None:
        """Add an enhanced service to the inventory."""
        self.enhanced_services[service.id] = service
        self.total_enhanced_services = len(self.enhanced_services)
        self.last_updated = datetime.now(timezone.utc).isoformat() + "Z"

    def to_dict(self) -> Dict[str, Any]:
        """Convert entire inventory to dictionary for serialization."""
        return {
            "proxmox_hosts": {k: v.to_dict() for k, v in self.proxmox_hosts.items()},
            "nodes": {k: v.to_dict() for k, v in self.nodes.items()},
            "services": {k: v.to_dict() for k, v in self.services.items()},
            "snapshots": {k: v.to_dict() for k, v in self.snapshots.items()},
            "events": {k: v.to_dict() for k, v in self.events.items()},
            "enhanced_targets": {
                k: v.to_dict() for k, v in self.enhanced_targets.items()
            },
            "enhanced_services": {
                k: v.to_dict() for k, v in self.enhanced_services.items()
            },
            "created_at": self.created_at,
            "last_updated": self.last_updated,
            "version": self.version,
            "total_hosts": self.total_hosts,
            "total_nodes": self.total_nodes,
            "total_services": self.total_services,
            "total_snapshots": self.total_snapshots,
            "total_enhanced_targets": self.total_enhanced_targets,
            "total_enhanced_services": self.total_enhanced_services,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FleetInventory:
        """Create FleetInventory from dictionary."""
        inventory = cls()

        # Load Proxmox hosts
        for host_id, host_data in data.get("proxmox_hosts", {}).items():
            inventory.proxmox_hosts[host_id] = ProxmoxHost.from_dict(host_data)

        # Load nodes
        for node_id, node_data in data.get("nodes", {}).items():
            inventory.nodes[node_id] = Node.from_dict(node_data)

        # Load services
        for service_id, service_data in data.get("services", {}).items():
            inventory.services[service_id] = Service.from_dict(service_data)

        # Load snapshots
        for snapshot_id, snapshot_data in data.get("snapshots", {}).items():
            inventory.snapshots[snapshot_id] = Snapshot.from_dict(snapshot_data)

        # Load events
        for event_id, event_data in data.get("events", {}).items():
            inventory.events[event_id] = Event.from_dict(event_data)

        # Load enhanced targets
        for target_id, target_data in data.get("enhanced_targets", {}).items():
            inventory.enhanced_targets[target_id] = EnhancedTarget.from_dict(
                target_data
            )

        # Load enhanced services
        for service_id, service_data in data.get("enhanced_services", {}).items():
            inventory.enhanced_services[service_id] = EnhancedService.from_dict(
                service_data
            )

        # Set metadata
        inventory.created_at = data.get("created_at", inventory.created_at)
        inventory.last_updated = data.get("last_updated", inventory.last_updated)
        inventory.version = data.get("version", inventory.version)
        inventory.total_hosts = len(inventory.proxmox_hosts)
        inventory.total_nodes = len(inventory.nodes)
        inventory.total_services = len(inventory.services)
        inventory.total_snapshots = len(inventory.snapshots)
        inventory.total_enhanced_targets = len(inventory.enhanced_targets)
        inventory.total_enhanced_services = len(inventory.enhanced_services)

        return inventory


# Pydantic models for enhanced validation and serialization
class ConnectionMethodModel(BaseModel):
    """Enhanced connection method model with Pydantic validation."""

    method: ConnectionMethod
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    key_path: Optional[str] = None
    socket_path: Optional[str] = None
    timeout: int = 30

    class Config:
        use_enum_values = True


class RuntimeModel(BaseModel):
    """Enhanced runtime model with Pydantic validation."""

    runtime: Runtime
    version: Optional[str] = None
    config_path: Optional[str] = None

    class Config:
        use_enum_values = True
