"""
Unit tests for Fleet Inventory models and persistence layer.
"""

import json
import os
import tempfile
import unittest
from datetime import datetime

from src.models.fleet_inventory import (
    FleetInventory, ProxmoxHost, Node, Service, Snapshot, Event,
    ConnectionMethod, Runtime, NodeType, ServiceStatus, SnapshotType, EventType, EventSeverity
)
from src.models.fleet_inventory_persistence import FleetInventoryPersistence
from src.models.fleet_inventory_serialization import TOONSerializer, FleetInventoryAdapter
from src.models.target_registry import TargetMetadata, TargetConnection, TargetConstraints, ExecutorType


class TestFleetInventoryModels(unittest.TestCase):
    """Test cases for Fleet Inventory data models."""
    
    def setUp(self):
        """Set up test data."""
        self.proxmox_host = ProxmoxHost(
            hostname="proxmox-01",
            address="192.168.1.100",
            username="root",
            node_name="pve",
            cpu_cores=16,
            memory_mb=32768,
            storage_gb=1000
        )
        
        self.node = Node(
            name="web-server-01",
            node_type=NodeType.CONTAINER,
            host_id=self.proxmox_host.id,
            vmid=100,
            runtime=Runtime.DOCKER,
            connection_method=ConnectionMethod.SSH
        )
        
        self.service = Service(
            name="nginx",
            node_id=self.node.id,
            service_type="docker",
            status=ServiceStatus.RUNNING,
            port=80
        )
        
        self.snapshot = Snapshot(
            name="backup-20231213",
            snapshot_type=SnapshotType.FULL,
            target_id=self.node.id,
            target_type="node"
        )
        
        self.event = Event(
            event_type=EventType.HEALTH_CHECK,
            source="gateway",
            message="Health check completed",
            target_id=self.node.id,
            target_type="node"
        )
    
    def test_proxmox_host_validation(self):
        """Test ProxmoxHost validation."""
        # Valid host
        errors = self.proxmox_host.validate()
        self.assertEqual(len(errors), 0)
        
        # Invalid host (missing required fields)
        invalid_host = ProxmoxHost(
            hostname="",
            address="",
            username="",
            node_name="",
            cpu_cores=0,
            memory_mb=0,
            storage_gb=0
        )
        errors = invalid_host.validate()
        self.assertGreater(len(errors), 0)
    
    def test_node_validation(self):
        """Test Node validation."""
        # Valid node
        errors = self.node.validate()
        self.assertEqual(len(errors), 0)
        
        # Invalid node (missing required fields)
        invalid_node = Node(
            name="",
            node_type=NodeType.CONTAINER,
            host_id="",
            runtime=Runtime.DOCKER,
            connection_method=ConnectionMethod.SSH
        )
        errors = invalid_node.validate()
        self.assertGreater(len(errors), 0)
    
    def test_service_validation(self):
        """Test Service validation."""
        # Valid service
        errors = self.service.validate()
        self.assertEqual(len(errors), 0)
        
        # Invalid service (missing required fields)
        invalid_service = Service(
            name="",
            node_id="",
            service_type="docker"
        )
        errors = invalid_service.validate()
        self.assertGreater(len(errors), 0)
    
    def test_snapshot_validation(self):
        """Test Snapshot validation."""
        # Valid snapshot
        errors = self.snapshot.validate()
        self.assertEqual(len(errors), 0)
        
        # Invalid snapshot (missing required fields)
        invalid_snapshot = Snapshot(
            name="",
            snapshot_type=SnapshotType.FULL,
            target_id="",
            target_type="invalid"
        )
        errors = invalid_snapshot.validate()
        self.assertGreater(len(errors), 0)
    
    def test_event_validation(self):
        """Test Event validation."""
        # Valid event
        errors = self.event.validate()
        self.assertEqual(len(errors), 0)
        
        # Invalid event (missing required fields)
        invalid_event = Event(
            event_type=EventType.HEALTH_CHECK,
            source="",
            message=""
        )
        errors = invalid_event.validate()
        self.assertGreater(len(errors), 0)
    
    def test_fleet_inventory_operations(self):
        """Test FleetInventory operations."""
        inventory = FleetInventory()
        
        # Add entities
        inventory.add_proxmox_host(self.proxmox_host)
        inventory.add_node(self.node)
        inventory.add_service(self.service)
        inventory.add_snapshot(self.snapshot)
        inventory.add_event(self.event)
        
        # Verify counts
        self.assertEqual(inventory.total_hosts, 1)
        self.assertEqual(inventory.total_nodes, 1)
        self.assertEqual(inventory.total_services, 1)
        self.assertEqual(inventory.total_snapshots, 1)
        
        # Verify entities exist
        self.assertIn(self.proxmox_host.id, inventory.proxmox_hosts)
        self.assertIn(self.node.id, inventory.nodes)
        self.assertIn(self.service.id, inventory.services)
        self.assertIn(self.snapshot.id, inventory.snapshots)
        self.assertIn(self.event.id, inventory.events)
    
    def test_serialization_deserialization(self):
        """Test serialization and deserialization."""
        inventory = FleetInventory()
        inventory.add_proxmox_host(self.proxmox_host)
        inventory.add_node(self.node)
        
        # Convert to dict and back
        data = inventory.to_dict()
        restored_inventory = FleetInventory.from_dict(data)
        
        # Verify data integrity
        self.assertEqual(len(restored_inventory.proxmox_hosts), 1)
        self.assertEqual(len(restored_inventory.nodes), 1)
        
        restored_host = list(restored_inventory.proxmox_hosts.values())[0]
        self.assertEqual(restored_host.hostname, self.proxmox_host.hostname)
        self.assertEqual(restored_host.address, self.proxmox_host.address)


class TestFleetInventoryPersistence(unittest.TestCase):
    """Test cases for Fleet Inventory persistence layer."""
    
    def setUp(self):
        """Set up temporary database for testing."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_inventory.db")
        self.json_path = os.path.join(self.temp_dir, "test_inventory.json")
        
        # Create test inventory
        self.inventory = FleetInventory()
        
        self.proxmox_host = ProxmoxHost(
            hostname="test-proxmox",
            address="192.168.1.200",
            username="root",
            node_name="pve-test",
            cpu_cores=8,
            memory_mb=16384,
            storage_gb=500
        )
        
        self.node = Node(
            name="test-node",
            node_type=NodeType.CONTAINER,
            host_id=self.proxmox_host.id,
            runtime=Runtime.DOCKER,
            connection_method=ConnectionMethod.SSH
        )
        
        self.inventory.add_proxmox_host(self.proxmox_host)
        self.inventory.add_node(self.node)
    
    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_sqlite_persistence(self):
        """Test SQLite persistence."""
        persistence = FleetInventoryPersistence(self.db_path, use_sqlite=True)
        
        # Save inventory
        persistence.save_inventory(self.inventory)
        
        # Load inventory
        loaded_inventory = persistence.load_inventory()
        
        # Verify data integrity
        self.assertEqual(len(loaded_inventory.proxmox_hosts), 1)
        self.assertEqual(len(loaded_inventory.nodes), 1)
        
        loaded_host = list(loaded_inventory.proxmox_hosts.values())[0]
        self.assertEqual(loaded_host.hostname, self.proxmox_host.hostname)
        self.assertEqual(loaded_host.address, self.proxmox_host.address)
    
    def test_json_persistence(self):
        """Test JSON persistence."""
        persistence = FleetInventoryPersistence(self.json_path, use_sqlite=False)
        
        # Save inventory
        persistence.save_inventory(self.inventory)
        
        # Load inventory
        loaded_inventory = persistence.load_inventory()
        
        # Verify data integrity
        self.assertEqual(len(loaded_inventory.proxmox_hosts), 1)
        self.assertEqual(len(loaded_inventory.nodes), 1)
        
        loaded_host = list(loaded_inventory.proxmox_hosts.values())[0]
        self.assertEqual(loaded_host.hostname, self.proxmox_host.hostname)
        self.assertEqual(loaded_host.address, self.proxmox_host.address)
    
    def test_query_methods(self):
        """Test query methods."""
        persistence = FleetInventoryPersistence(self.db_path, use_sqlite=True)
        persistence.save_inventory(self.inventory)
        
        # Test get_nodes_by_host
        nodes = persistence.get_nodes_by_host(self.proxmox_host.id)
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0].name, self.node.name)
        
        # Test get_events_by_type (empty for now)
        events = persistence.get_events_by_type("health_check")
        self.assertEqual(len(events), 0)


class TestTOONSerialization(unittest.TestCase):
    """Test cases for TOON serialization."""
    
    def setUp(self):
        """Set up test data."""
        self.inventory = FleetInventory()
        
        self.proxmox_host = ProxmoxHost(
            hostname="toon-test",
            address="192.168.1.300",
            username="root",
            node_name="pve-toon",
            cpu_cores=4,
            memory_mb=8192,
            storage_gb=250
        )
        
        self.inventory.add_proxmox_host(self.proxmox_host)
    
    def test_toon_serialization(self):
        """Test TOON serialization."""
        toon_str = TOONSerializer.to_toon(self.inventory)
        
        # Verify it's valid JSON
        toon_data = json.loads(toon_str)
        self.assertEqual(toon_data["type"], "FleetInventory")
        self.assertEqual(len(toon_data["proxmox_hosts"]), 1)
        
        # Verify host data
        host_data = toon_data["proxmox_hosts"][0]
        self.assertEqual(host_data["type"], "ProxmoxHost")
        self.assertEqual(host_data["hostname"], self.proxmox_host.hostname)
    
    def test_toon_deserialization(self):
        """Test TOON deserialization."""
        # Serialize to TOON
        toon_str = TOONSerializer.to_toon(self.inventory)
        
        # Deserialize from TOON
        restored_inventory = TOONSerializer.from_toon(toon_str)
        
        # Verify data integrity
        self.assertEqual(len(restored_inventory.proxmox_hosts), 1)
        
        restored_host = list(restored_inventory.proxmox_hosts.values())[0]
        self.assertEqual(restored_host.hostname, self.proxmox_host.hostname)
        self.assertEqual(restored_host.address, self.proxmox_host.address)


class TestFleetInventoryAdapter(unittest.TestCase):
    """Test cases for Fleet Inventory adapter."""
    
    def test_target_metadata_to_node(self):
        """Test conversion from TargetMetadata to Node."""
        target = TargetMetadata(
            id="test-target",
            type="local",
            executor=ExecutorType.LOCAL,
            connection=TargetConnection(executor=ExecutorType.LOCAL),
            capabilities=[],
            constraints=TargetConstraints(),
            metadata={}
        )
        
        node = FleetInventoryAdapter.target_metadata_to_node(target)
        
        self.assertEqual(node.id, target.id)
        self.assertEqual(node.name, target.id)
        self.assertEqual(node.node_type, NodeType.BARE_METAL)
        self.assertEqual(node.host_id, "local")
        self.assertEqual(node.runtime, Runtime.BARE_METAL)
        self.assertEqual(node.connection_method, ConnectionMethod.SSH)
    
    def test_node_to_target_metadata(self):
        """Test conversion from Node to TargetMetadata."""
        node = Node(
            id="test-node",
            name="test-node",
            node_type=NodeType.BARE_METAL,
            host_id="local",
            runtime=Runtime.BARE_METAL,
            connection_method=ConnectionMethod.SSH
        )
        
        target = FleetInventoryAdapter.node_to_target_metadata(node)
        
        self.assertEqual(target.id, node.id)
        self.assertEqual(target.type, "local")
        self.assertEqual(target.executor, ExecutorType.LOCAL)
        self.assertIsNotNone(target.connection)


if __name__ == "__main__":
    unittest.main()