"""
Fleet Inventory Persistence Module.

This module provides persistence capabilities for fleet inventory data.
"""

import json
import os
from datetime import datetime
from datetime import timezone, timezone

from src.models.fleet_inventory import FleetInventory


class FleetInventoryPersistence:
    """Fleet inventory persistence manager."""

    def __init__(self, storage_path: str = "fleet_inventory.json"):
        self.storage_path = storage_path

    def save_inventory(self, inventory: FleetInventory) -> bool:
        """Save inventory data to persistent storage."""
        try:
            with open(self.storage_path, "w") as f:
                json.dump(inventory.to_dict(), f, indent=2, default=str)
            return True
        except Exception:
            return False

    def load_inventory(self) -> FleetInventory:
        """Load inventory data from persistent storage."""
        try:
            if os.path.exists(self.storage_path):
                with open(self.storage_path, "r") as f:
                    data = json.load(f)
                    return FleetInventory.from_dict(data)
            return FleetInventory()
        except Exception:
            return FleetInventory()

    def backup_inventory(
        self, backup_path: str = None, inventory: FleetInventory = None
    ) -> bool:
        """Create a backup of the inventory."""
        if backup_path is None:
            backup_path = f"fleet_inventory_backup_{datetime.now().isoformat()}.json"
        if inventory is None:
            return False
        return self.save_inventory_to_path(backup_path, inventory)

    def save_inventory_to_path(self, path: str, inventory: FleetInventory) -> bool:
        """Save inventory to a specific path."""
        try:
            with open(path, "w") as f:
                json.dump(inventory.to_dict(), f, indent=2, default=str)
            return True
        except Exception:
            return False
