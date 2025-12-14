"""
TOON Integration Module for MCP Tools

This module provides TOON serialization integration for MCP tools,
allowing compact, structured output for LLM consumption.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Union

from src.models.fleet_inventory import FleetInventory
from src.models.fleet_inventory_serialization import TOONSerializer
from src.utils.toon import (
    model_to_toon, compute_delta, apply_delta, 
    _compact_json, _to_toon_tabular, _from_toon_tabular
)


class TOONIntegration:
    """TOON integration for MCP tools and fleet operations."""
    
    def __init__(self, use_toon: bool = True):
        """Initialize TOON integration.
        
        Args:
            use_toon: Whether to use TOON format (default: True)
        """
        self.use_toon = use_toon
    
    def serialize_inventory(self, inventory: FleetInventory) -> str:
        """Serialize fleet inventory to TOON or JSON format.
        
        Args:
            inventory: Fleet inventory to serialize
            
        Returns:
            Serialized inventory in TOON or JSON format
        """
        if self.use_toon:
            return TOONSerializer.to_toon(inventory, compact=True)
        else:
            return TOONSerializer.to_toon(inventory, compact=False)
    
    def serialize_operation_result(self, result: Dict[str, Any]) -> str:
        """Serialize operation result to compact format.
        
        Args:
            result: Operation result dictionary
            
        Returns:
            Compact serialized result
        """
        if self.use_toon:
            return model_to_toon(result)
        else:
            return json.dumps(result, indent=2, ensure_ascii=False)
    
    def create_inventory_diff(self, prev_inventory: FleetInventory, new_inventory: FleetInventory) -> str:
        """Create a compact diff between two inventory states.
        
        Args:
            prev_inventory: Previous inventory state
            new_inventory: New inventory state
            
        Returns:
            Compact diff representation
        """
        return TOONSerializer.compute_diff(prev_inventory, new_inventory)
    
    def tabularize_entities(self, inventory: FleetInventory, entity_type: str) -> str:
        """Convert entities to TOON tabular format.
        
        Args:
            inventory: Fleet inventory
            entity_type: Type of entities ("hosts", "nodes", "services", "snapshots", "events")
            
        Returns:
            TOON tabular string or JSON array
        """
        if self.use_toon:
            return TOONSerializer.to_tabular(inventory, entity_type)
        else:
            entities = []
            if entity_type == "hosts":
                entities = [TOONSerializer._host_to_toon(host) for host in inventory.proxmox_hosts.values()]
            elif entity_type == "nodes":
                entities = [TOONSerializer._node_to_toon(node) for node in inventory.nodes.values()]
            elif entity_type == "services":
                entities = [TOONSerializer._service_to_toon(service) for service in inventory.services.values()]
            elif entity_type == "snapshots":
                entities = [TOONSerializer._snapshot_to_toon(snapshot) for snapshot in inventory.snapshots.values()]
            elif entity_type == "events":
                entities = [TOONSerializer._event_to_toon(event) for event in inventory.events.values()]
            
            return json.dumps(entities, indent=2, ensure_ascii=False)
    
    def serialize_snapshot(self, snapshot_data: Dict[str, Any]) -> str:
        """Serialize inventory snapshot to compact format.
        
        Args:
            snapshot_data: Snapshot data dictionary
            
        Returns:
            Compact serialized snapshot
        """
        if self.use_toon:
            return _compact_json(snapshot_data)
        else:
            return json.dumps(snapshot_data, indent=2, ensure_ascii=False)


def get_toon_integration(config: Optional[Dict[str, Any]] = None) -> TOONIntegration:
    """Get TOON integration instance based on configuration.
    
    Args:
        config: Configuration dictionary (default: use TOON)
        
    Returns:
        TOONIntegration instance
    """
    use_toon = True
    if config and "use_toon" in config:
        use_toon = config["use_toon"]
    
    return TOONIntegration(use_toon=use_toon)


# Example usage and configuration
TOON_CONFIG = {
    "use_toon": True,
    "compact_mode": True,
    "enable_tabular": True,
    "enable_diffs": True
}


def configure_toon(config: Dict[str, Any]) -> None:
    """Configure TOON integration settings.
    
    Args:
        config: Configuration dictionary
    """
    global TOON_CONFIG
    TOON_CONFIG.update(config)


def get_toon_config() -> Dict[str, Any]:
    """Get current TOON configuration.
    
    Returns:
        Current TOON configuration
    """
    return TOON_CONFIG.copy()