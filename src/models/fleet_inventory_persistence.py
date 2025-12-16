"""
Fleet Inventory Persistence Module.

This module provides persistence capabilities for fleet inventory data.
"""

from typing import Dict, Any
import json
import os
from datetime import datetime


class FleetInventoryPersistence:
    """Fleet inventory persistence manager."""

    def __init__(self, storage_path: str = "fleet_inventory.json"):
        self.storage_path = storage_path
        self.data = {}

    def save_inventory(self, inventory_data: Dict[str, Any]) -> bool:
        """Save inventory data to persistent storage."""
        try:
            with open(self.storage_path, "w") as f:
                json.dump(inventory_data, f, indent=2, default=str)
            return True
        except Exception:
            return False

    def load_inventory(self) -> Dict[str, Any]:
        """Load inventory data from persistent storage."""
        try:
            if os.path.exists(self.storage_path):
                with open(self.storage_path, "r") as f:
                    return json.load(f)
            return {}
        except Exception:
            return {}

    def backup_inventory(self, backup_path: str = None) -> bool:
        """Create a backup of the inventory."""
        if backup_path is None:
            backup_path = f"fleet_inventory_backup_{datetime.now().isoformat()}.json"
        return self.save_inventory_to_path(backup_path)

    def save_inventory_to_path(self, path: str) -> bool:
        """Save inventory to a specific path."""
        try:
            with open(path, "w") as f:
                json.dump(self.data, f, indent=2, default=str)
            return True
        except Exception:
            return False
