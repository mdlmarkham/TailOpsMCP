"""
Gateway-specific data models for SystemManager control plane.

Extends the existing target registry system to support gateway mode operations
including fleet discovery, state consolidation, and multi-target management.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from datetime import timezone, timezone
from enum import Enum
from typing import Dict, List, Optional, Any

from src.models.target_registry import TargetMetadata


class OperationMode(str, Enum):
    """System operation modes."""

    LOCAL = "local"
    GATEWAY = "gateway"


class GatewayRole(str, Enum):
    """Gateway role types."""

    PRIMARY = "primary"
    SECONDARY = "secondary"
    STANDALONE = "standalone"


class DiscoveryMethod(str, Enum):
    """Target discovery methods."""

    MANUAL = "manual"
    PROXMOX_API = "proxmox_api"
    NETWORK_SCAN = "network_scan"
    DOCKER_API = "docker_api"


@dataclass
class GatewayMetadata:
    """Extended metadata for gateway targets."""

    # Inherit from TargetMetadata
    target: TargetMetadata

    # Gateway-specific fields
    gateway_id: str = field(default_factory=lambda: f"gateway-{uuid.uuid4().hex[:8]}")
    role: GatewayRole = GatewayRole.STANDALONE
    mode: OperationMode = OperationMode.LOCAL

    # Discovery configuration
    discovery_method: DiscoveryMethod = DiscoveryMethod.MANUAL
    discovery_interval: int = 300  # seconds
    auto_register: bool = False

    # Fleet management
    managed_targets: List[str] = field(default_factory=list)  # List of target IDs
    max_fleet_size: int = 50

    # Security settings
    require_gateway_auth: bool = True
    gateway_token: Optional[str] = None

    # Monitoring
    health_check_interval: int = 60  # seconds
    state_sync_interval: int = 30  # seconds

    def validate(self) -> List[str]:
        """Validate gateway metadata and return list of errors."""
        errors = []

        # Validate target
        errors.extend(self.target.validate())

        # Validate gateway-specific fields
        if not self.gateway_id:
            errors.append("Gateway ID is required")

        if self.discovery_interval <= 0:
            errors.append("Discovery interval must be positive")

        if self.max_fleet_size <= 0:
            errors.append("Max fleet size must be positive")

        if self.health_check_interval <= 0:
            errors.append("Health check interval must be positive")

        if self.state_sync_interval <= 0:
            errors.append("State sync interval must be positive")

        # Validate managed targets don't exceed max fleet size
        if len(self.managed_targets) > self.max_fleet_size:
            errors.append(
                f"Managed targets exceed max fleet size of {self.max_fleet_size}"
            )

        return errors

    def is_gateway_mode(self) -> bool:
        """Check if this gateway is operating in gateway mode."""
        return self.mode == OperationMode.GATEWAY

    def can_manage_target(self, target_id: str) -> bool:
        """Check if this gateway can manage the specified target."""
        if not self.is_gateway_mode():
            return False

        # If auto-register is enabled, any target can be managed
        if self.auto_register:
            return True

        # Otherwise, only explicitly managed targets
        return target_id in self.managed_targets

    def add_managed_target(self, target_id: str) -> bool:
        """Add a target to managed targets list."""
        if (
            target_id not in self.managed_targets
            and len(self.managed_targets) < self.max_fleet_size
        ):
            self.managed_targets.append(target_id)
            return True
        return False

    def remove_managed_target(self, target_id: str) -> bool:
        """Remove a target from managed targets list."""
        if target_id in self.managed_targets:
            self.managed_targets.remove(target_id)
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "target": self.target.to_dict(),
            "gateway_id": self.gateway_id,
            "role": self.role.value,
            "mode": self.mode.value,
            "discovery_method": self.discovery_method.value,
            "discovery_interval": self.discovery_interval,
            "auto_register": self.auto_register,
            "managed_targets": self.managed_targets,
            "max_fleet_size": self.max_fleet_size,
            "require_gateway_auth": self.require_gateway_auth,
            "gateway_token": self.gateway_token,
            "health_check_interval": self.health_check_interval,
            "state_sync_interval": self.state_sync_interval,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> GatewayMetadata:
        """Create GatewayMetadata from dictionary."""
        return cls(
            target=TargetMetadata.from_dict(data["target"]),
            gateway_id=data.get("gateway_id", f"gateway-{uuid.uuid4().hex[:8]}"),
            role=GatewayRole(data.get("role", GatewayRole.STANDALONE.value)),
            mode=OperationMode(data.get("mode", OperationMode.LOCAL.value)),
            discovery_method=DiscoveryMethod(
                data.get("discovery_method", DiscoveryMethod.MANUAL.value)
            ),
            discovery_interval=data.get("discovery_interval", 300),
            auto_register=data.get("auto_register", False),
            managed_targets=data.get("managed_targets", []),
            max_fleet_size=data.get("max_fleet_size", 50),
            require_gateway_auth=data.get("require_gateway_auth", True),
            gateway_token=data.get("gateway_token"),
            health_check_interval=data.get("health_check_interval", 60),
            state_sync_interval=data.get("state_sync_interval", 30),
        )


@dataclass
class FleetState:
    """Consolidated state for a fleet of targets."""

    gateway_id: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z")

    # Target states
    target_states: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Fleet-level metrics
    total_targets: int = 0
    healthy_targets: int = 0
    unhealthy_targets: int = 0

    # Resource utilization
    total_memory_mb: int = 0
    total_cpu_cores: int = 0
    memory_utilization_percent: float = 0.0
    cpu_utilization_percent: float = 0.0

    # Service status
    running_services: int = 0
    stopped_services: int = 0

    # Security status
    security_issues: List[str] = field(default_factory=list)

    def update_target_state(self, target_id: str, state: Dict[str, Any]) -> None:
        """Update state for a specific target."""
        self.target_states[target_id] = state
        self.total_targets = len(self.target_states)

        # Update fleet metrics based on target states
        self._recalculate_metrics()

    def _recalculate_metrics(self) -> None:
        """Recalculate fleet-level metrics from target states."""
        self.healthy_targets = 0
        self.unhealthy_targets = 0
        self.total_memory_mb = 0
        self.total_cpu_cores = 0
        self.running_services = 0
        self.stopped_services = 0

        for state in self.target_states.values():
            # Health status
            if state.get("healthy", False):
                self.healthy_targets += 1
            else:
                self.unhealthy_targets += 1

            # Resource metrics
            self.total_memory_mb += state.get("memory_mb", 0)
            self.total_cpu_cores += state.get("cpu_cores", 0)

            # Service metrics
            self.running_services += state.get("running_services", 0)
            self.stopped_services += state.get("stopped_services", 0)

        # Calculate utilization percentages (simplified)
        if self.total_memory_mb > 0:
            self.memory_utilization_percent = min(
                100.0, (self.total_memory_mb / (self.total_memory_mb * 1.1)) * 100
            )

        if self.total_cpu_cores > 0:
            self.cpu_utilization_percent = min(
                100.0, (self.total_cpu_cores / (self.total_cpu_cores * 1.1)) * 100
            )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "gateway_id": self.gateway_id,
            "timestamp": self.timestamp,
            "target_states": self.target_states,
            "total_targets": self.total_targets,
            "healthy_targets": self.healthy_targets,
            "unhealthy_targets": self.unhealthy_targets,
            "total_memory_mb": self.total_memory_mb,
            "total_cpu_cores": self.total_cpu_cores,
            "memory_utilization_percent": self.memory_utilization_percent,
            "cpu_utilization_percent": self.cpu_utilization_percent,
            "running_services": self.running_services,
            "stopped_services": self.stopped_services,
            "security_issues": self.security_issues,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FleetState:
        """Create FleetState from dictionary."""
        fleet_state = cls(
            gateway_id=data["gateway_id"],
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat() + "Z"),
        )

        # Update target states
        for target_id, state in data.get("target_states", {}).items():
            fleet_state.update_target_state(target_id, state)

        # Set security issues
        fleet_state.security_issues = data.get("security_issues", [])

        return fleet_state
