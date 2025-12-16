"""
Fleet Inventory Model Implementation Summary

This module provides a comprehensive data model for the Gateway Fleet Orchestrator
that represents the entire fleet state with efficient serialization and persistence.
"""

from src.models.fleet_inventory import (
    FleetInventory,
    ProxmoxHost,
    Node,
    Service,
    Snapshot,
    Event,
    ConnectionMethod,
    Runtime,
    NodeType,
    ServiceStatus,
    SnapshotType,
    EventType,
    EventSeverity,
)
from src.models.fleet_inventory_persistence import FleetInventoryPersistence
from src.models.fleet_inventory_serialization import (
    TOONSerializer,
    FleetInventoryAdapter,
)


# Example usage demonstrating the complete fleet inventory system
def create_sample_fleet() -> FleetInventory:
    """Create a sample fleet inventory for demonstration."""

    # Create Proxmox host
    host = ProxmoxHost(
        hostname="proxmox-cluster-01",
        address="192.168.1.100",
        username="root@pam",
        node_name="pve01",
        cluster_name="homelab-cluster",
        cpu_cores=32,
        memory_mb=65536,
        storage_gb=2000,
        version="7.4",
        tags=["production", "primary"],
    )

    # Create nodes (containers/VMs)
    web_node = Node(
        name="web-server-01",
        node_type=NodeType.CONTAINER,
        host_id=host.id,
        vmid=100,
        status="running",
        cpu_cores=2,
        memory_mb=2048,
        disk_gb=20,
        ip_address="192.168.1.101",
        runtime=Runtime.DOCKER,
        connection_method=ConnectionMethod.SSH,
        tags=["web", "nginx"],
        is_managed=True,
    )

    db_node = Node(
        name="database-01",
        node_type=NodeType.CONTAINER,
        host_id=host.id,
        vmid=101,
        status="running",
        cpu_cores=4,
        memory_mb=4096,
        disk_gb=50,
        ip_address="192.168.1.102",
        runtime=Runtime.DOCKER,
        connection_method=ConnectionMethod.SSH,
        tags=["database", "postgresql"],
        is_managed=True,
    )

    # Create services
    nginx_service = Service(
        name="nginx",
        node_id=web_node.id,
        service_type="docker",
        status=ServiceStatus.RUNNING,
        version="1.24",
        port=80,
        config_path="/etc/nginx",
        health_endpoint="/health",
        tags=["reverse-proxy", "web-server"],
        is_monitored=True,
    )

    postgres_service = Service(
        name="postgresql",
        node_id=db_node.id,
        service_type="docker",
        status=ServiceStatus.RUNNING,
        version="15",
        port=5432,
        data_path="/var/lib/postgresql/data",
        tags=["database", "persistent"],
        is_monitored=True,
    )

    # Create snapshots
    daily_snapshot = Snapshot(
        name="daily-backup-20231213",
        snapshot_type=SnapshotType.FULL,
        target_id=host.id,
        target_type="node",
        size_mb=5000,
        storage_path="/backups/daily",
        tags=["daily", "automated"],
        metadata={"backup_type": "incremental"},
    )

    # Create events
    discovery_event = Event(
        event_type=EventType.DISCOVERY,
        severity=EventSeverity.INFO,
        source="gateway",
        target_id=host.id,
        target_type="host",
        message="Discovered new Proxmox host",
        details={"method": "network_scan", "address": host.address},
    )

    # Build inventory
    inventory = FleetInventory()
    inventory.add_proxmox_host(host)
    inventory.add_node(web_node)
    inventory.add_node(db_node)
    inventory.add_service(nginx_service)
    inventory.add_service(postgres_service)
    inventory.add_snapshot(daily_snapshot)
    inventory.add_event(discovery_event)

    return inventory


def demonstrate_persistence() -> None:
    """Demonstrate persistence operations."""

    # Create sample fleet
    inventory = create_sample_fleet()

    # Save to SQLite
    sqlite_persistence = FleetInventoryPersistence(
        "fleet_inventory.db", use_sqlite=True
    )
    sqlite_persistence.save_inventory(inventory)
    print("✓ Inventory saved to SQLite")

    # Load from SQLite
    loaded_inventory = sqlite_persistence.load_inventory()
    print(
        f"✓ Loaded inventory: {loaded_inventory.total_hosts} hosts, {loaded_inventory.total_nodes} nodes"
    )

    # Save to JSON
    json_persistence = FleetInventoryPersistence(
        "fleet_inventory.json", use_sqlite=False
    )
    json_persistence.save_inventory(inventory)
    print("✓ Inventory saved to JSON")


def demonstrate_serialization() -> None:
    """Demonstrate serialization operations."""

    # Create sample fleet
    inventory = create_sample_fleet()

    # Convert to TOON
    toon_str = TOONSerializer.to_toon(inventory)
    print("✓ Inventory converted to TOON format")

    # Convert back from TOON
    restored_inventory = TOONSerializer.from_toon(toon_str)
    print(f"✓ TOON deserialized: {restored_inventory.total_nodes} nodes restored")

    # Convert to JSON
    json_data = inventory.to_dict()
    print("✓ Inventory converted to JSON")


def demonstrate_integration() -> None:
    """Demonstrate integration with TargetRegistry."""

    from src.models.target_registry import (
        TargetMetadata,
        TargetConnection,
        TargetConstraints,
        ExecutorType,
    )

    # Create sample TargetRegistry target
    target = TargetMetadata(
        id="gateway-01",
        type="local",
        executor=ExecutorType.LOCAL,
        connection=TargetConnection(executor=ExecutorType.LOCAL),
        capabilities=["discovery", "health_check"],
        constraints=TargetConstraints(),
        metadata={"role": "gateway"},
    )

    # Convert to Node
    node = FleetInventoryAdapter.target_metadata_to_node(target)
    print(f"✓ Target converted to Node: {node.name} ({node.runtime.value})")

    # Convert back to TargetMetadata
    restored_target = FleetInventoryAdapter.node_to_target_metadata(node)
    print(
        f"✓ Node converted back to Target: {restored_target.id} ({restored_target.type})"
    )


if __name__ == "__main__":
    """Run demonstration when executed directly."""

    print("=== Fleet Inventory Model Demonstration ===\n")

    # Create and display sample fleet
    inventory = create_sample_fleet()
    print("Sample Fleet Created:")
    print(f"- {inventory.total_hosts} Proxmox hosts")
    print(f"- {inventory.total_nodes} nodes")
    print(f"- {inventory.total_services} services")
    print(f"- {inventory.total_snapshots} snapshots")
    print(f"- {len(inventory.events)} events\n")

    # Demonstrate persistence
    print("=== Persistence Demonstration ===")
    demonstrate_persistence()
    print()

    # Demonstrate serialization
    print("=== Serialization Demonstration ===")
    demonstrate_serialization()
    print()

    # Demonstrate integration
    print("=== Integration Demonstration ===")
    demonstrate_integration()
    print()

    print("=== Demonstration Complete ===")
    print(
        "The Fleet Inventory Model is ready for use in the Gateway Fleet Orchestrator!"
    )
