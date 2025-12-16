"""
Example usage of Discovery Pipelines for Gateway Fleet Orchestrator.

This module provides practical examples of how to use the discovery pipelines
in different scenarios.
"""

import asyncio
import os
from src.services.discovery_manager import DiscoveryManager
from src.services.discovery_pipeline import DiscoveryPipeline
from src.services.proxmox_discovery import ProxmoxDiscovery
from src.services.node_probing import NodeProbing


async def example_basic_discovery():
    """Example 1: Basic discovery with default configuration."""
    print("=== Example 1: Basic Discovery ===")

    # Create discovery manager with default configuration
    manager = DiscoveryManager()

    # Run discovery
    result = await manager.force_discovery()

    print(f"Discovery completed: {result['success']}")
    print(f"Hosts discovered: {result['inventory']['total_hosts']}")
    print(f"Nodes discovered: {result['inventory']['total_nodes']}")
    print(f"Services discovered: {result['inventory']['total_services']}")

    return result


async def example_custom_configuration():
    """Example 2: Discovery with custom configuration."""
    print("\n=== Example 2: Custom Configuration ===")

    # Create discovery manager
    manager = DiscoveryManager()

    # Update configuration
    new_config = {
        "discovery_interval": 600,  # 10 minutes
        "health_check_interval": 120,  # 2 minutes
        "max_concurrent_probes": 3,
        "auto_register": True,
    }

    updated_config = manager.update_configuration(new_config)
    print("Updated configuration:")
    print(f"  Discovery interval: {updated_config['intervals']['discovery']}s")
    print(f"  Health check interval: {updated_config['intervals']['health_check']}s")
    print(
        f"  Max concurrent probes: {updated_config['limits']['max_concurrent_probes']}"
    )
    print(f"  Auto register: {updated_config['features']['auto_register']}")

    return updated_config


async def example_proxmox_api_discovery():
    """Example 3: Discovery with Proxmox API configuration."""
    print("\n=== Example 3: Proxmox API Discovery ===")

    # Set up Proxmox API configuration
    api_config = {
        "host": os.getenv("PROXMOX_HOST", "proxmox.example.com"),
        "username": os.getenv("PROXMOX_USERNAME", "root@pam"),
        "password": os.getenv("PROXMOX_PASSWORD", ""),
        "verify_ssl": False,  # Set to True for production
    }

    # Create Proxmox discovery service
    discovery = ProxmoxDiscovery(api_config)

    # Discover hosts
    hosts = discovery.discover_proxmox_hosts()
    print(f"Discovered {len(hosts)} Proxmox hosts")

    for host in hosts:
        print(f"  Host: {host.hostname} ({host.address})")
        print(f"    Node: {host.node_name}")
        print(f"    CPU: {host.cpu_cores} cores")
        print(f"    Memory: {host.memory_mb} MB")
        print(f"    Storage: {host.storage_gb} GB")

        # Discover nodes from this host
        nodes = discovery.discover_nodes(host)
        print(f"    Nodes: {len(nodes)}")

        for node in nodes:
            print(f"      Node: {node.name} (ID: {node.vmid})")
            print(f"        Type: {node.node_type.value}")
            print(f"        Status: {node.status}")
            print(f"        IP: {node.ip_address}")

    return hosts


async def example_node_probing():
    """Example 4: Node probing with connection testing."""
    print("\n=== Example 4: Node Probing ===")

    # Create node probing service
    tailscale_config = {
        "enabled": os.getenv("TAILSCALE_ENABLED", "false").lower() == "true",
        "ssh_user": "root",
    }

    probing = NodeProbing(tailscale_config)

    # Create a test node (in practice, this would come from discovery)
    from src.models.fleet_inventory import Node, NodeType, Runtime, ConnectionMethod

    test_node = Node(
        name="test-node",
        node_type=NodeType.CONTAINER,
        host_id="test-host",
        runtime=Runtime.SYSTEMD,
        connection_method=ConnectionMethod.SSH,
        ip_address="192.168.1.100",  # Example IP
    )

    # Probe the node
    probe_result = probing.probe_node(test_node)

    print(f"Probed node: {test_node.name}")
    print(f"Connection tests: {len(probe_result['connection_tests'])}")

    for method, result in probe_result["connection_tests"].items():
        status = "✓" if result.get("success") else "✗"
        print(f"  {method}: {status} {result.get('error', '')}")

    if probe_result["system_info"].get("parsed"):
        system_info = probe_result["system_info"]["parsed"]
        print("System information:")
        print(f"  Hostname: {system_info.get('hostname', 'unknown')}")
        print(f"  OS: {system_info.get('os', {}).get('NAME', 'unknown')}")
        print(f"  Uptime: {system_info.get('uptime', {}).get('uptime', 'unknown')}")
        print(
            f"  Docker: {'installed' if system_info.get('docker', {}).get('installed') else 'not installed'}"
        )

    print(f"Services discovered: {len(probe_result['services'])}")

    return probe_result


async def example_discovery_pipeline():
    """Example 5: Complete discovery pipeline usage."""
    print("\n=== Example 5: Discovery Pipeline ===")

    # Create discovery pipeline with custom configuration
    config = {
        "discovery_interval": 300,
        "health_check_interval": 60,
        "max_concurrent_probes": 5,
        "auto_register": True,
    }

    pipeline = DiscoveryPipeline(config)

    # Check if discovery should run
    should_run = pipeline.should_run_discovery()
    print(f"Should run discovery: {should_run}")

    # Get current status
    status = pipeline.get_discovery_status()
    print(f"Last discovery: {status.get('last_discovery', 'Never')}")
    print(f"Inventory stats: {status['inventory_stats']}")

    # Run discovery cycle
    if should_run:
        inventory = await pipeline.run_discovery_cycle()
        print("Discovery completed successfully")
        print(f"  Total hosts: {inventory.total_hosts}")
        print(f"  Total nodes: {inventory.total_nodes}")
        print(f"  Total services: {inventory.total_services}")

        # Print recent events
        recent_events = list(inventory.events.values())[-5:]  # Last 5 events
        print(f"Recent events: {len(recent_events)}")
        for event in recent_events:
            print(f"  {event.timestamp}: {event.message}")

    return pipeline


async def example_integration_with_target_registry():
    """Example 6: Integration with TargetRegistry."""
    print("\n=== Example 6: TargetRegistry Integration ===")

    from src.services.discovery_manager import integrate_with_target_registry
    from src.services.target_registry import TargetRegistry

    # Create discovery manager
    manager = DiscoveryManager()

    # Create target registry
    target_registry = TargetRegistry()

    # Integrate discovery with target registry
    integrate_with_target_registry(manager, target_registry)

    # Run discovery to populate targets
    await manager.force_discovery()

    # List discovered targets
    targets = target_registry.list_targets()
    print(f"Discovered targets: {len(targets)}")

    for target_id, target in targets.items():
        if "discovered" in target.metadata.get("tags", []):
            print(f"  Target: {target_id}")
            print(f"    Hostname: {target.metadata.get('hostname')}")
            print(f"    Type: {target.metadata.get('node_type')}")
            print(f"    Runtime: {target.metadata.get('runtime')}")

    return targets


async def main():
    """Run all examples."""
    print("Discovery Pipelines Examples")
    print("=" * 50)

    try:
        # Example 1: Basic discovery
        await example_basic_discovery()

        # Example 2: Custom configuration
        await example_custom_configuration()

        # Example 3: Proxmox API discovery
        await example_proxmox_api_discovery()

        # Example 4: Node probing
        await example_node_probing()

        # Example 5: Discovery pipeline
        await example_discovery_pipeline()

        # Example 6: TargetRegistry integration
        await example_integration_with_target_registry()

        print("\nAll examples completed successfully!")

    except Exception as e:
        print(f"Error running examples: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    # Run the examples
    asyncio.run(main())
