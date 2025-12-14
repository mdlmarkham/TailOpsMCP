"""
Enhanced Fleet Inventory Model with Rich Metadata

Extends the base fleet inventory models with comprehensive metadata for:
- Node roles and resource usage
- Service and stack mappings
- Network topology
- Security posture
- Health monitoring
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from uuid import uuid4

from pydantic import BaseModel, Field, validator

from src.models.fleet_inventory import (
    ProxmoxHost, Node, Service, Event, EventType, EventSeverity,
    NodeType, Runtime, ConnectionMethod, ServiceStatus
)


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
    measured_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


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
    subnets: List[str] = Field(default_factory=list)
    
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
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
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
            "container_info": self.container_info.dict() if self.container_info else None,
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
            "custom_attributes": self.custom_attributes
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
            custom_attributes=data.get("custom_attributes", {})
        )
        
        # Convert nested objects
        if "resource_usage" in data:
            target.resource_usage = ResourceUsage(**data["resource_usage"])
        
        if "network_interfaces" in data:
            target.network_interfaces = [NetworkInterface(**ni) for ni in data["network_interfaces"]]
        
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
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
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
            "custom_attributes": self.custom_attributes
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
            custom_attributes=data.get("custom_attributes", {})
        )


@dataclass
class EnhancedStack:
    """Enhanced stack with comprehensive metadata."""
    
    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: Optional[str] = None
    
    # Stack configuration
    compose_file_path: str
    stack_file_content: Optional[str] = None
    variables: Dict[str, str] = Field(default_factory=dict)
    
    # Stack relationships
    services: List[str] = field(default_factory=list)  # Service IDs
    targets: List[str] = field(default_factory=list)  # Target IDs
    
    # Deployment information
    stack_status: str = "unknown"
    last_deployed: Optional[str] = None
    deployment_method: str = "docker-compose"
    namespace: Optional[str] = None
    
    # Stack health
    health_score: float = 0.0
    last_health_check: Optional[str] = None
    
    # Security and compliance
    security_scan_results: Dict[str, Any] = Field(default_factory=dict)
    compliance_status: str = "unknown"
    
    # Resource tracking
    total_cpu_cores: float = 0.0
    total_memory_mb: int = 0
    total_disk_gb: int = 0
    
    # Lifecycle
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    last_updated: Optional[str] = None
    is_active: bool = True
    
    # Tags and metadata
    tags: List[str] = field(default_factory=list)
    custom_attributes: Dict[str, Any] = field(default_factory=dict)
    
    def validate(self) -> List[str]:
        """Validate enhanced stack configuration."""
        errors = []
        
        if not self.name:
            errors.append("Stack name is required")
        if not self.compose_file_path:
            errors.append("Compose file path is required")
        
        return errors
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "compose_file_path": self.compose_file_path,
            "stack_file_content": self.stack_file_content,
            "variables": self.variables,
            "services": self.services,
            "targets": self.targets,
            "stack_status": self.stack_status,
            "last_deployed": self.last_deployed,
            "deployment_method": self.deployment_method,
            "namespace": self.namespace,
            "health_score": self.health_score,
            "last_health_check": self.last_health_check,
            "security_scan_results": self.security_scan_results,
            "compliance_status": self.compliance_status,
            "total_cpu_cores": self.total_cpu_cores,
            "total_memory_mb": self.total_memory_mb,
            "total_disk_gb": self.total_disk_gb,
            "created_at": self.created_at,
            "last_updated": self.last_updated,
            "is_active": self.is_active,
            "tags": self.tags,
            "custom_attributes": self.custom_attributes
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EnhancedStack:
        """Create EnhancedStack from dictionary."""
        return cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description"),
            compose_file_path=data["compose_file_path"],
            stack_file_content=data.get("stack_file_content"),
            variables=data.get("variables", {}),
            services=data.get("services", []),
            targets=data.get("targets", []),
            stack_status=data.get("stack_status", "unknown"),
            last_deployed=data.get("last_deployed"),
            deployment_method=data.get("deployment_method", "docker-compose"),
            namespace=data.get("namespace"),
            health_score=data.get("health_score", 0.0),
            last_health_check=data.get("last_health_check"),
            security_scan_results=data.get("security_scan_results", {}),
            compliance_status=data.get("compliance_status", "unknown"),
            total_cpu_cores=data.get("total_cpu_cores", 0.0),
            total_memory_mb=data.get("total_memory_mb", 0),
            total_disk_gb=data.get("total_disk_gb", 0),
            created_at=data.get("created_at"),
            last_updated=data.get("last_updated"),
            is_active=data.get("is_active", True),
            tags=data.get("tags", []),
            custom_attributes=data.get("custom_attributes", {})
        )


class EnhancedFleetInventory(BaseModel):
    """Enhanced fleet inventory model with comprehensive metadata."""
    
    # Core entities
    targets: Dict[str, EnhancedTarget] = Field(default_factory=dict)
    services: Dict[str, EnhancedService] = Field(default_factory=dict)
    stacks: Dict[str, EnhancedStack] = Field(default_factory=dict)
    proxmox_hosts: Dict[str, ProxmoxHost] = Field(default_factory=dict)
    events: Dict[str, Event] = Field(default_factory=dict)
    
    # Metadata
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    last_updated: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    version: str = "2.0.0"
    
    # Fleet metrics
    total_targets: int = 0
    total_services: int = 0
    total_stacks: int = 0
    total_hosts: int = 0
    
    # Health metrics
    healthy_targets: int = 0
    unhealthy_targets: int = 0
    average_health_score: float = 0.0
    
    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
    
    def add_target(self, target: EnhancedTarget) -> None:
        """Add a target to the inventory."""
        self.targets[target.id] = target
        self._update_metrics()
        self.last_updated = datetime.utcnow().isoformat() + "Z"
    
    def add_service(self, service: EnhancedService) -> None:
        """Add a service to the inventory."""
        self.services[service.id] = service
        self._update_metrics()
        self.last_updated = datetime.utcnow().isoformat() + "Z"
    
    def add_stack(self, stack: EnhancedStack) -> None:
        """Add a stack to the inventory."""
        self.stacks[stack.id] = stack
        self._update_metrics()
        self.last_updated = datetime.utcnow().isoformat() + "Z"
    
    def add_proxmox_host(self, host: ProxmoxHost) -> None:
        """Add a Proxmox host to the inventory."""
        self.proxmox_hosts[host.id] = host
        self._update_metrics()
        self.last_updated = datetime.utcnow().isoformat() + "Z"
    
    def add_event(self, event: Event) -> None:
        """Add an event to the inventory."""
        self.events[event.id] = event
        self.last_updated = datetime.utcnow().isoformat() + "Z"
    
    def _update_metrics(self) -> None:
        """Update fleet metrics."""
        self.total_targets = len(self.targets)
        self.total_services = len(self.services)
        self.total_stacks = len(self.stacks)
        self.total_hosts = len(self.proxmox_hosts)
        
        # Health metrics
        healthy_count = 0
        total_health_score = 0.0
        
        for target in self.targets.values():
            if target.health_score >= 0.7:
                healthy_count += 1
            total_health_score += target.health_score
        
        self.healthy_targets = healthy_count
        self.unhealthy_targets = self.total_targets - healthy_count
        self.average_health_score = (
            total_health_score / self.total_targets if self.total_targets > 0 else 0.0
        )
    
    def get_targets_by_role(self, role: NodeRole) -> List[EnhancedTarget]:
        """Get targets by role."""
        return [target for target in self.targets.values() if target.role == role]
    
    def get_targets_by_status(self, status: str) -> List[EnhancedTarget]:
        """Get targets by status."""
        return [target for target in self.targets.values() if target.status == status]
    
    def get_unhealthy_targets(self, threshold: float = 0.7) -> List[EnhancedTarget]:
        """Get targets with health score below threshold."""
        return [target for target in self.targets.values() if target.health_score < threshold]
    
    def get_services_by_stack(self, stack_name: str) -> List[EnhancedService]:
        """Get services by stack name."""
        return [service for service in self.services.values() if service.stack_name == stack_name]
    
    def get_stale_targets(self, hours: int = 24) -> List[EnhancedTarget]:
        """Get targets not seen within specified hours."""
        from datetime import datetime, timedelta
        
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        stale_targets = []
        
        for target in self.targets.values():
            if target.last_seen:
                last_seen = datetime.fromisoformat(target.last_seen.replace('Z', '+00:00'))
                if last_seen < cutoff:
                    stale_targets.append(target)
        
        return stale_targets
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert entire inventory to dictionary."""
        return {
            "targets": {k: v.to_dict() for k, v in self.targets.items()},
            "services": {k: v.to_dict() for k, v in self.services.items()},
            "stacks": {k: v.to_dict() for k, v in self.stacks.items()},
            "proxmox_hosts": {k: v.to_dict() for k, v in self.proxmox_hosts.items()},
            "events": {k: v.to_dict() for k, v in self.events.items()},
            "created_at": self.created_at,
            "last_updated": self.last_updated,
            "version": self.version,
            "total_targets": self.total_targets,
            "total_services": self.total_services,
            "total_stacks": self.total_stacks,
            "total_hosts": self.total_hosts,
            "healthy_targets": self.healthy_targets,
            "unhealthy_targets": self.unhealthy_targets,
            "average_health_score": self.average_health_score
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EnhancedFleetInventory:
        """Create EnhancedFleetInventory from dictionary."""
        inventory = cls()
        
        # Load targets
        for target_id, target_data in data.get("targets", {}).items():
            inventory.targets[target_id] = EnhancedTarget.from_dict(target_data)
        
        # Load services
        for service_id, service_data in data.get("services", {}).items():
            inventory.services[service_id] = EnhancedService.from_dict(service_data)
        
        # Load stacks
        for stack_id, stack_data in data.get("stacks", {}).items():
            inventory.stacks[stack_id] = EnhancedStack.from_dict(stack_data)
        
        # Load Proxmox hosts
        for host_id, host_data in data.get("proxmox_hosts", {}).items():
            inventory.proxmox_hosts[host_id] = ProxmoxHost.from_dict(host_data)
        
        # Load events
        for event_id, event_data in data.get("events", {}).items():
            inventory.events[event_id] = Event.from_dict(event_data)
        
        # Set metadata
        inventory.created_at = data.get("created_at", inventory.created_at)
        inventory.last_updated = data.get("last_updated", inventory.last_updated)
        inventory.version = data.get("version", inventory.version)
        
        # Update metrics
        inventory._update_metrics()
        
        return inventory