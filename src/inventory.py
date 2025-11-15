from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


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
    """Simple on-disk inventory for hosts and stacks.

    This is intentionally lightweight: JSON sink with helper APIs. For
    multi-host production uses, replace with a service-backed store.
    """

    def __init__(self, path: Optional[str] = None):
        self.path = path or os.getenv("SYSTEMMANAGER_INVENTORY", "./inventory.json")
        self._data: Dict = {"hosts": {}, "stacks": {}}
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    self._data = json.load(f)
            except Exception:
                # start fresh on error
                self._data = {"hosts": {}, "stacks": {}}

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
