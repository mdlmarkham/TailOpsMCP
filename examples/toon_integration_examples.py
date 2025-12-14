"""
TOON Integration Examples and Documentation

This module provides examples and documentation for TOON integration
in the SystemManager fleet orchestration system.
"""

from __future__ import annotations

import json
import sys
import os
from typing import Dict, Any

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.models.fleet_inventory import FleetInventory, ProxmoxHost, Node, Service
from src.models.fleet_inventory_serialization import TOONSerializer
from src.integration.toon_integration import TOONIntegration, get_toon_integration


def example_basic_serialization() -> None:
    """Example: Basic TOON serialization of fleet inventory."""
    print("=== Basic TOON Serialization Example ===")
    
    # Create a simple inventory
    inventory = FleetInventory()
    
    # Add a Proxmox host
    host = ProxmoxHost(
        hostname="proxmox-01",
        address="192.168.1.100",
        username="root",
        node_name="pve",
        cpu_cores=8,
        memory_mb=16384,
        storage_gb=500
    )
    inventory.add_proxmox_host(host)
    
    # Add a node
    node = Node(
        name="web-server-01",
        node_type="container",
        host_id=host.id,
        vmid=100,
        status="running",
        cpu_cores=2,
        memory_mb=2048,
        disk_gb=20,
        runtime="docker",
        connection_method="ssh"
    )
    inventory.add_node(node)
    
    # Add a service
    service = Service(
        name="nginx",
        node_id=node.id,
        service_type="web-server",
        status="running",
        port=80
    )
    inventory.add_service(service)
    
    # Serialize to TOON
    toon_output = TOONSerializer.to_toon(inventory, compact=True)
    print("Compact TOON Output:")
    print(toon_output)
    print("\n" + "="*50 + "\n")
    
    # Serialize to JSON (fallback)
    json_output = TOONSerializer.to_toon(inventory, compact=False)
    print("JSON Output (fallback):")
    print(json_output[:200] + "...")  # Show first 200 chars
    print("\n" + "="*50 + "\n")


def example_tabular_format() -> None:
    """Example: TOON tabular format for entities."""
    print("=== TOON Tabular Format Example ===")
    
    # Create inventory with multiple hosts
    inventory = FleetInventory()
    
    hosts = [
        ProxmoxHost(
            hostname=f"proxmox-{i:02d}",
            address=f"192.168.1.{100 + i}",
            username="root",
            node_name=f"pve-{i:02d}",
            cpu_cores=8 + i,
            memory_mb=16384 + (i * 2048),
            storage_gb=500 + (i * 100)
        ) for i in range(3)
    ]
    
    for host in hosts:
        inventory.add_proxmox_host(host)
    
    # Get tabular representation
    tabular_hosts = TOONSerializer.to_tabular(inventory, "hosts")
    print("TOON Tabular Hosts:")
    print(tabular_hosts)
    print("\n" + "="*50 + "\n")


def example_inventory_diff() -> None:
    """Example: Computing inventory diffs."""
    print("=== Inventory Diff Example ===")
    
    # Create initial inventory
    inventory1 = FleetInventory()
    host1 = ProxmoxHost(
        hostname="proxmox-01",
        address="192.168.1.100",
        username="root",
        node_name="pve",
        cpu_cores=8,
        memory_mb=16384,
        storage_gb=500
    )
    inventory1.add_proxmox_host(host1)
    
    # Create updated inventory (host added)
    inventory2 = FleetInventory()
    inventory2.add_proxmox_host(host1)
    
    host2 = ProxmoxHost(
        hostname="proxmox-02",
        address="192.168.1.101",
        username="root",
        node_name="pve-02",
        cpu_cores=12,
        memory_mb=24576,
        storage_gb=750
    )
    inventory2.add_proxmox_host(host2)
    
    # Compute diff
    diff = TOONSerializer.compute_diff(inventory1, inventory2)
    print("Inventory Diff:")
    print(diff)
    print("\n" + "="*50 + "\n")


def example_mcp_integration() -> None:
    """Example: TOON integration with MCP tools."""
    print("=== MCP Integration Example ===")
    
    # Get TOON integration
    toon = get_toon_integration()
    
    # Create sample operation result
    operation_result = {
        "operation": "deploy_stack",
        "target": "proxmox-01",
        "stack_name": "web-app",
        "status": "success",
        "services_deployed": ["nginx", "api", "database"],
        "metrics": {
            "duration_seconds": 45.2,
            "memory_used_mb": 512,
            "containers_created": 3
        }
    }
    
    # Serialize operation result
    serialized_result = toon.serialize_operation_result(operation_result)
    print("Serialized Operation Result:")
    print(serialized_result)
    print("\n" + "="*50 + "\n")


def example_configuration() -> None:
    """Example: TOON configuration options."""
    print("=== TOON Configuration Example ===")
    
    # Configure TOON to use JSON fallback
    from src.integration.toon_integration import configure_toon
    configure_toon({"use_toon": False})
    
    # Get integration with JSON fallback
    toon_json = get_toon_integration()
    
    # Create sample data
    sample_data = {
        "system": "proxmox-01",
        "status": "healthy",
        "resources": {
            "cpu_usage": 15.5,
            "memory_usage": 2048,
            "disk_usage": 150
        }
    }
    
    # Serialize with JSON fallback
    json_output = toon_json.serialize_operation_result(sample_data)
    print("JSON Fallback Output:")
    print(json_output)
    print("\n" + "="*50 + "\n")
    
    # Reconfigure to use TOON
    configure_toon({"use_toon": True})


def main() -> None:
    """Run all TOON integration examples."""
    print("TOON Integration Examples for SystemManager")
    print("="*60)
    
    example_basic_serialization()
    example_tabular_format()
    example_inventory_diff()
    example_mcp_integration()
    example_configuration()
    
    print("Examples completed successfully!")


if __name__ == "__main__":
    main()