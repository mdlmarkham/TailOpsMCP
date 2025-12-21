"""
Target Registry data models for SystemManager control plane.

Extends the existing inventory system to support both local and remote targets
with SSH and Docker socket executors.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from datetime import datetime
from datetime import timezone, timezone
from enum import Enum
from typing import Dict, List, Optional, Any

from src.auth.scopes import Scope


class ExecutorType(str, Enum):
    """Supported executor types for target connections."""

    LOCAL = "local"
    SSH = "ssh"
    DOCKER = "docker"


class SudoPolicy(str, Enum):
    """Sudo policy levels for SSH targets."""

    NONE = "none"
    LIMITED = "limited"
    FULL = "full"


@dataclass
class TargetConnection:
    """Connection configuration for remote targets."""

    executor: ExecutorType
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    key_path: Optional[str] = None
    socket_path: Optional[str] = None
    timeout: int = 30

    def validate(self) -> List[str]:
        """Validate connection configuration and return list of errors."""
        errors = []

        if self.executor == ExecutorType.SSH:
            if not self.host:
                errors.append("SSH executor requires host")
            if not self.username:
                errors.append("SSH executor requires username")
            if not self.key_path and not os.getenv(self.key_path or ""):
                errors.append("SSH executor requires key_path or environment variable")

        elif self.executor == ExecutorType.DOCKER:
            if not self.socket_path and not self.host:
                errors.append("Docker executor requires socket_path or host")

        elif self.executor == ExecutorType.LOCAL:
            # Local executor doesn't require connection details
            pass

        return errors


@dataclass
class TargetConstraints:
    """Operational constraints per target."""

    timeout: int = 60
    concurrency: int = 1
    sudo_policy: SudoPolicy = SudoPolicy.NONE
    max_memory: Optional[int] = None
    max_cpu: Optional[float] = None

    def validate(self) -> List[str]:
        """Validate constraints and return list of errors."""
        errors = []

        if self.timeout <= 0:
            errors.append("Timeout must be positive")
        if self.concurrency <= 0:
            errors.append("Concurrency must be positive")
        if self.max_memory and self.max_memory <= 0:
            errors.append("Max memory must be positive")
        if self.max_cpu and self.max_cpu <= 0:
            errors.append("Max CPU must be positive")

        return errors


@dataclass
class TargetMetadata:
    """Extended metadata for targets."""

    id: str
    type: str  # "local", "remote"
    executor: ExecutorType
    connection: TargetConnection
    capabilities: List[str]  # Based on Scope enum
    constraints: TargetConstraints
    metadata: Dict[str, Any]
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z"
    )
    last_verified: Optional[str] = None

    def validate(self) -> List[str]:
        """Validate target metadata and return list of errors."""
        errors = []

        if not self.id:
            errors.append("Target ID is required")

        if self.type not in ["local", "remote"]:
            errors.append("Target type must be 'local' or 'remote'")

        # Validate connection
        errors.extend(self.connection.validate())

        # Validate constraints
        errors.extend(self.constraints.validate())

        # Validate capabilities
        for capability in self.capabilities:
            if capability not in [scope.value for scope in Scope]:
                errors.append(f"Invalid capability: {capability}")

        return errors

    def has_capability(self, scope: Scope) -> bool:
        """Check if target has the specified capability."""
        return scope.value in self.capabilities

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "type": self.type,
            "executor": self.executor.value,
            "connection": asdict(self.connection),
            "capabilities": self.capabilities,
            "constraints": asdict(self.constraints),
            "metadata": self.metadata,
            "discovered_at": self.discovered_at,
            "last_verified": self.last_verified,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TargetMetadata:
        """Create TargetMetadata from dictionary."""
        return cls(
            id=data["id"],
            type=data["type"],
            executor=ExecutorType(data["executor"]),
            connection=TargetConnection(**data["connection"]),
            capabilities=data["capabilities"],
            constraints=TargetConstraints(**data["constraints"]),
            metadata=data["metadata"],
            discovered_at=data.get(
                "discovered_at", datetime.now(timezone.utc).isoformat() + "Z"
            ),
            last_verified=data.get("last_verified"),
        )
