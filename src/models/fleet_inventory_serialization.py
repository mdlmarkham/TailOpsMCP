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


class TOONSerializer:
    """TOON (Typed Object Oriented Notation) serializer for fleet inventory."""

    @staticmethod
    def to_toon(inventory) -> str:
        """Convert FleetInventory to TOON format."""
        from src.models.fleet_inventory import FleetInventory, ProxmoxHost

        if not isinstance(inventory, FleetInventory):
            raise TypeError("Expected FleetInventory instance")

        toon_data = {
            "type": "FleetInventory",
            "proxmox_hosts": [],
            "nodes": [],
            "services": [],
        }

        for host in inventory.proxmox_hosts.values():
            host_dict = host.to_dict() if hasattr(host, "to_dict") else vars(host)
            host_dict["type"] = "ProxmoxHost"
            toon_data["proxmox_hosts"].append(host_dict)

        for node in inventory.nodes.values():
            node_dict = node.to_dict() if hasattr(node, "to_dict") else vars(node)
            node_dict["type"] = "Node"
            toon_data["nodes"].append(node_dict)

        for service in inventory.services.values():
            service_dict = (
                service.to_dict() if hasattr(service, "to_dict") else vars(service)
            )
            service_dict["type"] = "Service"
            toon_data["services"].append(service_dict)

        return json.dumps(toon_data, indent=2, default=str)

    @staticmethod
    def from_toon(toon_str: str):
        """Convert TOON format to FleetInventory."""
        from src.models.fleet_inventory import FleetInventory, ProxmoxHost

        toon_data = json.loads(toon_str)

        if toon_data.get("type") != "FleetInventory":
            raise ValueError("Invalid TOON format: expected FleetInventory type")

        inventory = FleetInventory()

        for host_data in toon_data.get("proxmox_hosts", []):
            if host_data.get("type") == "ProxmoxHost":
                host_dict = {k: v for k, v in host_data.items() if k != "type"}
                host = ProxmoxHost.from_dict(host_dict)
                inventory.add_proxmox_host(host)

        return inventory


class FleetInventoryAdapter:
    """Adapter for converting between different inventory formats."""

    @staticmethod
    def target_metadata_to_node(target) -> dict:
        """Convert TargetMetadata to Node dictionary."""
        return {
            "id": target.id,
            "name": target.name,
            "type": target.type.value
            if hasattr(target.type, "value")
            else str(target.type),
            "executor": target.executor.value
            if hasattr(target.executor, "value")
            else str(target.executor),
            "capabilities": target.capabilities,
            "constraints": (
                target.constraints.to_dict()
                if hasattr(target, "constraints") and target.constraints
                else {}
            ),
            "connection": (
                target.connection.to_dict()
                if hasattr(target, "connection") and target.connection
                else {}
            ),
        }

    @staticmethod
    def node_to_target_metadata(node_dict: dict):
        """Convert Node dictionary to TargetMetadata."""
        from src.models.target_registry import (
            TargetMetadata,
            ExecutorType,
            TargetConnection,
        )

        return TargetMetadata(
            id=node_dict.get("id", ""),
            name=node_dict.get("name", ""),
            type="local",
            executor=ExecutorType.LOCAL,
            connection=TargetConnection(executor=ExecutorType.LOCAL),
            capabilities=node_dict.get("capabilities", []),
        )


# Convenience functions
def serialize_fleet_inventory(data: Dict[str, Any]) -> str:
    """Serialize fleet inventory to JSON."""
    return FleetInventorySerializer.serialize_inventory(data)


def deserialize_fleet_inventory(json_str: str) -> Dict[str, Any]:
    """Deserialize fleet inventory from JSON."""
    return FleetInventorySerializer.deserialize_inventory(json_str)
