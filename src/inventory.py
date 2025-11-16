from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class SystemIdentity:
    """Identity of this system/container."""
    hostname: str
    container_id: Optional[str] = None  # Proxmox VMID/CTID
    container_type: Optional[str] = None  # "lxc", "vm", "bare-metal"
    mcp_server_name: Optional[str] = None  # Override for multi-system setups
    
    def get_display_name(self) -> str:
        """Get display name for MCP server."""
        if self.mcp_server_name:
            return self.mcp_server_name
        if self.container_id:
            return f"{self.hostname}-{self.container_id}"
        return self.hostname


@dataclass
class ApplicationMetadata:
    """Application running directly on LXC (not in Docker)."""
    name: str
    type: str  # "jellyfin", "pihole", "ollama", "postgresql", etc.
    version: Optional[str] = None
    port: Optional[int] = None
    service_name: Optional[str] = None  # systemd service name
    config_path: Optional[str] = None
    data_path: Optional[str] = None
    auto_detected: bool = False
    notes: Optional[str] = None
    added_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


@dataclass
class HostMetadata:
    hostname: str
    platform: str
    tags: List[str] = field(default_factory=list)
    added_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


@dataclass
class StackMetadata:
    name: str
    path: str
    repo_url: Optional[str] = None
    branch: Optional[str] = None
    last_deployed: Optional[str] = None


class Inventory:
    """Simple on-disk inventory for hosts, stacks, applications, and system identity.

    This is intentionally lightweight: JSON sink with helper APIs. For
    multi-host production uses, replace with a service-backed store.
    """

    def __init__(self, path: Optional[str] = None):
        self.path = path or os.getenv("SYSTEMMANAGER_INVENTORY", "./inventory.json")
        self._data: Dict = {
            "system": None,
            "hosts": {}, 
            "stacks": {},
            "applications": {}
        }
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    # Migrate old format
                    self._data = {
                        "system": loaded.get("system"),
                        "hosts": loaded.get("hosts", {}),
                        "stacks": loaded.get("stacks", {}),
                        "applications": loaded.get("applications", {})
                    }
            except Exception:
                # start fresh on error
                self._data = {"system": None, "hosts": {}, "stacks": {}, "applications": {}}

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, ensure_ascii=False)

    # Host helpers
    def add_host(self, host_id: str, metadata: HostMetadata) -> None:
        self._data.setdefault("hosts", {})[host_id] = asdict(metadata)
        self.save()

    def remove_host(self, host_id: str) -> None:
        self._data.get("hosts", {}).pop(host_id, None)
        self.save()

    def list_hosts(self) -> Dict[str, Dict]:
        return self._data.get("hosts", {})

    # Stack helpers
    def add_stack(self, stack_id: str, metadata: StackMetadata) -> None:
        self._data.setdefault("stacks", {})[stack_id] = asdict(metadata)
        self.save()

    def remove_stack(self, stack_id: str) -> None:
        self._data.get("stacks", {}).pop(stack_id, None)
        self.save()

    def list_stacks(self) -> Dict[str, Dict]:
        return self._data.get("stacks", {})

    # System identity helpers
    def set_system_identity(self, identity: SystemIdentity) -> None:
        self._data["system"] = asdict(identity)
        self.save()

    def get_system_identity(self) -> Optional[SystemIdentity]:
        if self._data.get("system"):
            return SystemIdentity(**self._data["system"])
        return None

    # Application helpers
    def add_application(self, app_id: str, metadata: ApplicationMetadata) -> None:
        self._data.setdefault("applications", {})[app_id] = asdict(metadata)
        self.save()

    def remove_application(self, app_id: str) -> None:
        self._data.get("applications", {}).pop(app_id, None)
        self.save()

    def list_applications(self) -> Dict[str, Dict]:
        return self._data.get("applications", {})

    def get_application(self, app_id: str) -> Optional[ApplicationMetadata]:
        app_data = self._data.get("applications", {}).get(app_id)
        if app_data:
            return ApplicationMetadata(**app_data)
        return None
