"""
Fleet Inventory Model for Gateway Fleet Orchestrator.

This module provides the canonical data model for representing the entire fleet state,
including Proxmox hosts, containers/VMs, services, snapshots, and events.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from uuid import uuid4

from pydantic import BaseModel, Field, validator

from src.models.target_registry import (
    TargetMetadata, TargetConnection, TargetConstraints, ExecutorType, SudoPolicy
)


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
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
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
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
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
    
    id: str = field(default_factory=lambda: str(uuid4()))
    name: str
    node_id: str  # Reference to Node.id
    service_type: str  # e.g., "docker", "systemd", "application"
    status: ServiceStatus = ServiceStatus.UNKNOWN
    version: Optional[str] = None
    port: Optional[int] = None
    config_path: Optional[str] = None
    data_path: Optional[str] = None
    health_endpoint: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
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
    
    id: str = field(default_factory=lambda: str(uuid4()))
    name: str
    snapshot_type: SnapshotType
    target_id: str  # Can be Node.id or Service.id
    target_type: str  # "node", "service"
    size_mb: Optional[int] = None
    storage_path: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
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
    
    id: str = field(default_factory=lambda: str(uuid4()))
    event_type: EventType
    severity: EventSeverity = EventSeverity.INFO
    source: str  # e.g., "gateway", "discovery", "backup"
    target_id: Optional[str] = None  # Reference to Node.id, Service.id, etc.
    target_type: Optional[str] = None
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
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


class FleetInventory(BaseModel):
    """Comprehensive fleet inventory model that aggregates all entities."""
    
    # Core entities
    proxmox_hosts: Dict[str, ProxmoxHost] = Field(default_factory=dict)
    nodes: Dict[str, Node] = Field(default_factory=dict)
    services: Dict[str, Service] = Field(default_factory=dict)
    snapshots: Dict[str, Snapshot] = Field(default_factory=dict)
    events: Dict[str, Event] = Field(default_factory=dict)
    
    # Metadata
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    last_updated: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    version: str = "1.0.0"
    
    # Fleet metrics
    total_hosts: int = 0
    total_nodes: int = 0
    total_services: int = 0
    total_snapshots: int = 0
    
    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    def add_proxmox_host(self, host: ProxmoxHost) -> None:
        """Add a Proxmox host to the inventory."""
        self.proxmox_hosts[host.id] = host
        self.total_hosts = len(self.proxmox_hosts)
        self.last_updated = datetime.utcnow().isoformat() + "Z"
    
    def add_node(self, node: Node) -> None:
        """Add a node to the inventory."""
        self.nodes[node.id] = node
        self.total_nodes = len(self.nodes)
        self.last_updated = datetime.utcnow().isoformat() + "Z"
    
    def add_service(self, service: Service) -> None:
        """Add a service to the inventory."""
        self.services[service.id] = service
        self.total_services = len(self.services)
        self.last_updated = datetime.utcnow().isoformat() + "Z"
    
    def add_snapshot(self, snapshot: Snapshot) -> None:
        """Add a snapshot to the inventory."""
        self.snapshots[snapshot.id] = snapshot
        self.total_snapshots = len(self.snapshots)
        self.last_updated = datetime.utcnow().isoformat() + "Z"
    
    def add_event(self, event: Event) -> None:
        """Add an event to the inventory."""
        self.events[event.id] = event
        self.last_updated = datetime.utcnow().isoformat() + "Z"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert entire inventory to dictionary for serialization."""
        return {
            "proxmox_hosts": {k: v.to_dict() for k, v in self.proxmox_hosts.items()},
            "nodes": {k: v.to_dict() for k, v in self.nodes.items()},
            "services": {k: v.to_dict() for k, v in self.services.items()},
            "snapshots": {k: v.to_dict() for k, v in self.snapshots.items()},
            "events": {k: v.to_dict() for k, v in self.events.items()},
            "created_at": self.created_at,
            "last_updated": self.last_updated,
            "version": self.version,
            "total_hosts": self.total_hosts,
            "total_nodes": self.total_nodes,
            "total_services": self.total_services,
            "total_snapshots": self.total_snapshots
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
        
        # Set metadata
        inventory.created_at = data.get("created_at", inventory.created_at)
        inventory.last_updated = data.get("last_updated", inventory.last_updated)
        inventory.version = data.get("version", inventory.version)
        inventory.total_hosts = len(inventory.proxmox_hosts)
        inventory.total_nodes = len(inventory.nodes)
        inventory.total_services = len(inventory.services)
        inventory.total_snapshots = len(inventory.snapshots)
        
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