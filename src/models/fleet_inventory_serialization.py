"""
Fleet Inventory Serialization Module

Provides serialization and deserialization functionality for fleet inventory data.
"""

from typing import Any, Dict, Union
import json


class FleetInventorySerializer:
    """Serializer for fleet inventory data."""

    @staticmethod
    def serialize_inventory(inventory_data: Dict[str, Any]) -> str:
        """Serialize inventory data to JSON string."""
        return json.dumps(inventory_data, indent=2, default=str)

    @staticmethod
    def deserialize_inventory(json_str: str) -> Dict[str, Any]:
        """Deserialize JSON string to inventory data."""
        return json.loads(json_str)

    @staticmethod
    def serialize_node(node_data: Dict[str, Any]) -> str:
        """Serialize node data to JSON string."""
        return json.dumps(node_data, indent=2, default=str)

    @staticmethod
    def deserialize_node(json_str: str) -> Dict[str, Any]:
        """Deserialize JSON string to node data."""
        return json.loads(json_str)

    @staticmethod
    def serialize_service(service_data: Dict[str, Any]) -> str:
        """Serialize service data to JSON string."""
        return json.dumps(service_data, indent=2, default=str)

    @staticmethod
    def deserialize_service(json_str: str) -> Dict[str, Any]:
        """Deserialize JSON string to service data."""
        return json.loads(json_str)


class FleetInventoryDeserializer:
    """Deserializer for fleet inventory data."""

    @staticmethod
    def from_json(json_data: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Create inventory from JSON data."""
        if isinstance(json_data, str):
            return json.loads(json_data)
        return json_data

    @staticmethod
    def validate_inventory_structure(data: Dict[str, Any]) -> bool:
        """Validate that inventory data has required structure."""
        required_fields = ["nodes", "services"]
        return all(field in data for field in required_fields)


# Convenience functions
def serialize_fleet_inventory(data: Dict[str, Any]) -> str:
    """Serialize fleet inventory to JSON."""
    return FleetInventorySerializer.serialize_inventory(data)


def deserialize_fleet_inventory(json_str: str) -> Dict[str, Any]:
    """Deserialize fleet inventory from JSON."""
    return FleetInventorySerializer.deserialize_inventory(json_str)
