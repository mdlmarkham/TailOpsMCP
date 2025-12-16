"""
Comprehensive Test Suite for Enhanced Fleet Inventory System

Tests the complete enhanced fleet inventory implementation including:
- Enhanced inventory models
- Snapshot management
- Persistence layer
- Inventory service
- Change detection
- Query capabilities
"""

import asyncio
import os
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

# Import the enhanced inventory system components
from src.models.enhanced_fleet_inventory import (
    EnhancedFleetInventory,
    EnhancedTarget,
    EnhancedService,
    EnhancedStack,
    NodeRole,
    ResourceStatus,
    SecurityStatus,
    ResourceUsage,
    SecurityPosture,
    ContainerInfo,
)
from src.models.inventory_snapshot import (
    InventorySnapshot,
    SnapshotManager,
    SnapshotType,
    ChangeType,
)
from src.utils.inventory_persistence import EnhancedInventoryPersistence
from src.services.inventory_service import InventoryService
from src.models.fleet_inventory import ProxmoxHost


class TestEnhancedInventoryModels(unittest.TestCase):
    """Test enhanced inventory data models."""

    def setUp(self):
        """Set up test data."""
        self.now = datetime.utcnow().isoformat() + "Z"

        # Create sample targets
        self.target1 = EnhancedTarget(
            name="prod-web-01",
            node_type="container",
            host_id="host-123",
            runtime="docker",
            connection_method="ssh",
            role=NodeRole.PRODUCTION,
            cpu_cores=4,
            memory_mb=8192,
            disk_gb=100,
            ip_address="192.168.1.10",
            resource_usage=ResourceUsage(
                cpu_percent=45.2,
                memory_percent=67.8,
                disk_percent=23.1,
                status=ResourceStatus.HEALTHY,
            ),
            security_posture=SecurityPosture(
                tls_enabled=True,
                open_ports=[80, 443, 22],
                security_status=SecurityStatus.SECURE,
            ),
            container_info=ContainerInfo(
                container_id="abc123",
                image_name="nginx:latest",
                ports={80: 8080, 443: 8443},
            ),
        )

        self.target2 = EnhancedTarget(
            name="dev-api-01",
            node_type="container",
            host_id="host-456",
            runtime="docker",
            connection_method="ssh",
            role=NodeRole.DEVELOPMENT,
            cpu_cores=2,
            memory_mb=4096,
            disk_gb=50,
            ip_address="192.168.1.20",
            resource_usage=ResourceUsage(
                cpu_percent=12.5,
                memory_percent=34.2,
                disk_percent=15.7,
                status=ResourceStatus.HEALTHY,
            ),
            security_posture=SecurityPosture(
                tls_enabled=False,
                open_ports=[22, 3000],
                security_status=SecurityStatus.WARNING,
            ),
        )

        # Create sample services
        self.service1 = EnhancedService(
            name="nginx",
            target_id="target-123",
            service_type="docker",
            status="running",
            port=80,
            stack_name="web-stack",
            health_check_enabled=True,
        )

        self.service2 = EnhancedService(
            name="api-server",
            target_id="target-456",
            service_type="docker",
            status="running",
            port=3000,
            stack_name="api-stack",
            health_check_enabled=True,
        )

        # Create sample stack
        self.stack1 = EnhancedStack(
            name="web-stack",
            compose_file_path="/opt/stacks/web/docker-compose.yml",
            services=["nginx", "redis"],
            targets=["target-123"],
            stack_status="running",
        )

    def test_enhanced_target_creation(self):
        """Test EnhancedTarget creation and validation."""
        # Test valid target
        self.assertEqual(self.target1.name, "prod-web-01")
        self.assertEqual(self.target1.role, NodeRole.PRODUCTION)
        self.assertEqual(self.target1.resource_usage.status, ResourceStatus.HEALTHY)
        self.assertEqual(
            self.target1.security_posture.security_status, SecurityStatus.SECURE
        )

        # Test validation
        errors = self.target1.validate()
        self.assertEqual(len(errors), 0)  # No validation errors

        # Test invalid target
        invalid_target = EnhancedTarget(name="")
        errors = invalid_target.validate()
        self.assertGreater(len(errors), 0)

    def test_enhanced_service_creation(self):
        """Test EnhancedService creation and validation."""
        self.assertEqual(self.service1.name, "nginx")
        self.assertEqual(self.service1.stack_name, "web-stack")
        self.assertTrue(self.service1.health_check_enabled)

        # Test validation
        errors = self.service1.validate()
        self.assertEqual(len(errors), 0)

    def test_enhanced_stack_creation(self):
        """Test EnhancedStack creation and validation."""
        self.assertEqual(self.stack1.name, "web-stack")
        self.assertEqual(len(self.stack1.services), 2)
        self.assertEqual(self.stack1.stack_status, "running")

        # Test validation
        errors = self.stack1.validate()
        self.assertEqual(len(errors), 0)

    def test_serialization(self):
        """Test serialization and deserialization."""
        # Test target serialization
        target_dict = self.target1.to_dict()
        restored_target = EnhancedTarget.from_dict(target_dict)

        self.assertEqual(restored_target.name, self.target1.name)
        self.assertEqual(restored_target.role, self.target1.role)
        self.assertEqual(
            restored_target.resource_usage.cpu_percent,
            self.target1.resource_usage.cpu_percent,
        )

        # Test service serialization
        service_dict = self.service1.to_dict()
        restored_service = EnhancedService.from_dict(service_dict)

        self.assertEqual(restored_service.name, self.service1.name)
        self.assertEqual(restored_service.stack_name, self.service1.stack_name)

        # Test stack serialization
        stack_dict = self.stack1.to_dict()
        restored_stack = EnhancedStack.from_dict(stack_dict)

        self.assertEqual(restored_stack.name, self.stack1.name)
        self.assertEqual(len(restored_stack.services), len(self.stack1.services))


class TestFleetInventory(unittest.TestCase):
    """Test EnhancedFleetInventory management."""

    def setUp(self):
        """Set up test inventory."""
        self.inventory = EnhancedFleetInventory()

        # Create and add targets
        self.target1 = EnhancedTarget(
            name="prod-web-01", role=NodeRole.PRODUCTION, health_score=0.9
        )
        self.target2 = EnhancedTarget(
            name="dev-api-01", role=NodeRole.DEVELOPMENT, health_score=0.7
        )
        self.target3 = EnhancedTarget(
            name="staging-db-01", role=NodeRole.STAGING, health_score=0.3
        )

        self.inventory.add_target(self.target1)
        self.inventory.add_target(self.target2)
        self.inventory.add_target(self.target3)

        # Add services
        self.service1 = EnhancedService(
            name="nginx", target_id=self.target1.id, service_type="docker"
        )
        self.service2 = EnhancedService(
            name="api-server", target_id=self.target2.id, service_type="docker"
        )

        self.inventory.add_service(self.service1)
        self.inventory.add_service(self.service2)

        # Add stack
        self.stack1 = EnhancedStack(
            name="web-stack", compose_file_path="/opt/stacks/web/docker-compose.yml"
        )
        self.inventory.add_stack(self.stack1)

    def test_inventory_management(self):
        """Test inventory entity management."""
        self.assertEqual(self.inventory.total_targets, 3)
        self.assertEqual(self.inventory.total_services, 2)
        self.assertEqual(self.inventory.total_stacks, 1)

        # Test metrics update
        self.assertEqual(self.inventory.healthy_targets, 2)  # target1 and target2
        self.assertEqual(self.inventory.unhealthy_targets, 1)  # target3
        self.assertAlmostEqual(self.inventory.average_health_score, 0.633, places=2)

    def test_role_filtering(self):
        """Test filtering by role."""
        prod_targets = self.inventory.get_targets_by_role(NodeRole.PRODUCTION)
        self.assertEqual(len(prod_targets), 1)
        self.assertEqual(prod_targets[0].name, "prod-web-01")

        dev_targets = self.inventory.get_targets_by_role(NodeRole.DEVELOPMENT)
        self.assertEqual(len(dev_targets), 1)
        self.assertEqual(dev_targets[0].name, "dev-api-01")

    def test_status_filtering(self):
        """Test filtering by status."""
        # All targets should have default status
        stopped_targets = self.inventory.get_targets_by_status("stopped")
        self.assertEqual(len(stopped_targets), 3)

    def test_health_filtering(self):
        """Test filtering by health score."""
        unhealthy_targets = self.inventory.get_unhealthy_targets(threshold=0.7)
        self.assertEqual(len(unhealthy_targets), 1)
        self.assertEqual(unhealthy_targets[0].name, "staging-db-01")

    def test_stale_detection(self):
        """Test stale target detection."""
        # Make one target stale
        stale_time = datetime.utcnow() - timedelta(hours=25)
        self.target3.last_seen = stale_time.isoformat() + "Z"

        stale_targets = self.inventory.get_stale_targets(hours=24)
        self.assertEqual(len(stale_targets), 1)
        self.assertEqual(stale_targets[0].name, "staging-db-01")

    def test_serialization(self):
        """Test inventory serialization."""
        # Test to_dict
        inventory_dict = self.inventory.to_dict()
        self.assertIn("targets", inventory_dict)
        self.assertIn("services", inventory_dict)
        self.assertIn("stacks", inventory_dict)

        # Test from_dict
        restored_inventory = EnhancedFleetInventory.from_dict(inventory_dict)
        self.assertEqual(restored_inventory.total_targets, self.inventory.total_targets)
        self.assertEqual(
            restored_inventory.total_services, self.inventory.total_services
        )
        self.assertEqual(restored_inventory.total_stacks, self.inventory.total_stacks)


class TestSnapshotManagement(unittest.TestCase):
    """Test snapshot management and change detection."""

    def setUp(self):
        """Set up test snapshots."""
        self.snapshot_manager = SnapshotManager()

        # Create first inventory
        self.inventory1 = EnhancedFleetInventory()
        target1 = EnhancedTarget(
            name="server-01", role=NodeRole.PRODUCTION, health_score=0.9
        )
        self.inventory1.add_target(target1)

        # Create second inventory with changes
        self.inventory2 = EnhancedFleetInventory()
        target1_modified = EnhancedTarget(
            name="server-01",
            role=NodeRole.PRODUCTION,
            health_score=0.8,  # Changed
            cpu_cores=8,  # Changed
        )
        target2_new = EnhancedTarget(
            name="server-02", role=NodeRole.DEVELOPMENT, health_score=0.7
        )
        self.inventory2.add_target(target1_modified)
        self.inventory2.add_target(target2_new)

    def test_snapshot_creation(self):
        """Test snapshot creation."""
        snapshot = self.snapshot_manager.create_snapshot(
            inventory=self.inventory1,
            name="test-snapshot",
            snapshot_type=SnapshotType.MANUAL,
            description="Test snapshot",
        )

        self.assertEqual(snapshot.name, "test-snapshot")
        self.assertEqual(snapshot.snapshot_type, SnapshotType.MANUAL)
        self.assertEqual(snapshot.total_targets, 1)

        # Verify snapshot was stored
        retrieved_snapshot = self.snapshot_manager.get_snapshot(snapshot.id)
        self.assertIsNotNone(retrieved_snapshot)
        self.assertEqual(retrieved_snapshot.name, "test-snapshot")

    def test_snapshot_comparison(self):
        """Test snapshot comparison and change detection."""
        # Create snapshots
        snapshot1 = self.snapshot_manager.create_snapshot(
            inventory=self.inventory1, name="snapshot-1", description="First snapshot"
        )

        snapshot2 = self.snapshot_manager.create_snapshot(
            inventory=self.inventory2, name="snapshot-2", description="Second snapshot"
        )

        # Compare snapshots
        diff = self.snapshot_manager.compare_snapshots(snapshot1, snapshot2)

        self.assertEqual(diff.snapshot_a_id, snapshot1.id)
        self.assertEqual(diff.snapshot_b_id, snapshot2.id)
        self.assertEqual(diff.entities_created, 1)  # server-02 created
        self.assertEqual(diff.entities_modified, 1)  # server-01 modified
        self.assertEqual(diff.entities_deleted, 0)

        # Verify change details
        self.assertEqual(len(diff.target_changes), 2)  # 1 created, 1 modified
        created_changes = [
            c for c in diff.target_changes if c.change_type == ChangeType.CREATED
        ]
        modified_changes = [
            c for c in diff.target_changes if c.change_type == ChangeType.MODIFIED
        ]

        self.assertEqual(len(created_changes), 1)
        self.assertEqual(len(modified_changes), 1)

        # Check health impact analysis
        self.assertIn("health_score_change", diff.health_impact)
        self.assertIn("healthy_targets_change", diff.health_impact)

    def test_snapshot_listing(self):
        """Test snapshot listing and filtering."""
        # Create multiple snapshots
        self.snapshot_manager.create_snapshot(
            inventory=self.inventory1,
            name="snapshot-manual",
            snapshot_type=SnapshotType.MANUAL,
        )

        self.snapshot_manager.create_snapshot(
            inventory=self.inventory1,
            name="snapshot-scheduled",
            snapshot_type=SnapshotType.SCHEDULED,
        )

        # List all snapshots
        all_snapshots = self.snapshot_manager.list_snapshots()
        self.assertEqual(len(all_snapshots), 2)

        # Filter by type
        manual_snapshots = self.snapshot_manager.list_snapshots(
            snapshot_type=SnapshotType.MANUAL
        )
        self.assertEqual(len(manual_snapshots), 1)
        self.assertEqual(manual_snapshots[0].name, "snapshot-manual")

        # Apply limit
        limited_snapshots = self.snapshot_manager.list_snapshots(limit=1)
        self.assertEqual(len(limited_snapshots), 1)


class TestPersistenceLayer(unittest.TestCase):
    """Test enhanced persistence layer."""

    def setUp(self):
        """Set up test database."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_inventory.db")
        self.persistence = EnhancedInventoryPersistence(
            db_path=self.db_path, use_sqlite=True
        )

        # Create test inventory
        self.inventory = EnhancedFleetInventory()
        target = EnhancedTarget(
            name="test-server",
            role=NodeRole.PRODUCTION,
            cpu_cores=4,
            memory_mb=8192,
            resource_usage=ResourceUsage(cpu_percent=50.0, memory_percent=60.0),
        )
        self.inventory.add_target(target)

        service = EnhancedService(
            name="test-service", target_id=target.id, service_type="docker", port=8080
        )
        self.inventory.add_service(service)

        stack = EnhancedStack(
            name="test-stack", compose_file_path="/test/docker-compose.yml"
        )
        self.inventory.add_stack(stack)

    def tearDown(self):
        """Clean up test files."""
        import shutil

        shutil.rmtree(self.temp_dir)

    def test_save_and_load_inventory(self):
        """Test saving and loading inventory."""
        # Save inventory
        self.persistence.save_inventory(self.inventory)

        # Load inventory
        loaded_inventory = self.persistence.load_inventory()

        # Verify data integrity
        self.assertEqual(loaded_inventory.total_targets, 1)
        self.assertEqual(loaded_inventory.total_services, 1)
        self.assertEqual(loaded_inventory.total_stacks, 1)

        # Verify target data
        target = list(loaded_inventory.targets.values())[0]
        self.assertEqual(target.name, "test-server")
        self.assertEqual(target.role, NodeRole.PRODUCTION)
        self.assertEqual(target.cpu_cores, 4)
        self.assertEqual(target.resource_usage.cpu_percent, 50.0)

        # Verify service data
        service = list(loaded_inventory.services.values())[0]
        self.assertEqual(service.name, "test-service")
        self.assertEqual(service.port, 8080)

        # Verify stack data
        stack = list(loaded_inventory.stacks.values())[0]
        self.assertEqual(stack.name, "test-stack")

    def test_query_methods(self):
        """Test query methods."""
        # Save inventory
        self.persistence.save_inventory(self.inventory)

        # Test role-based query
        prod_targets = self.persistence.get_targets_by_role(NodeRole.PRODUCTION)
        self.assertEqual(len(prod_targets), 1)
        self.assertEqual(prod_targets[0].name, "test-server")

        # Test status-based query
        stopped_targets = self.persistence.get_targets_by_status("stopped")
        self.assertEqual(len(stopped_targets), 1)

        # Test search
        search_results = self.persistence.search_targets("test")
        self.assertEqual(len(search_results), 1)
        self.assertEqual(search_results[0].name, "test-server")

    def test_snapshot_persistence(self):
        """Test snapshot save/load."""
        # Create snapshot
        snapshot = InventorySnapshot(name="test-snapshot", description="Test snapshot")
        snapshot.set_inventory(self.inventory)

        # Save snapshot
        self.persistence.save_snapshot(snapshot)

        # Load snapshot
        loaded_snapshot = self.persistence.load_snapshot(snapshot.id)

        # Verify snapshot data
        self.assertIsNotNone(loaded_snapshot)
        self.assertEqual(loaded_snapshot.name, "test-snapshot")
        self.assertEqual(loaded_snapshot.total_targets, 1)

        # Verify inventory data in snapshot
        loaded_inventory = loaded_snapshot.get_inventory()
        self.assertEqual(loaded_inventory.total_targets, 1)


class TestInventoryService(unittest.TestCase):
    """Test inventory service functionality."""

    def setUp(self):
        """Set up test service."""
        self.temp_dir = tempfile.mkdtemp()
        config = {
            "db_path": os.path.join(self.temp_dir, "test_service.db"),
            "use_sqlite": True,
            "auto_snapshot_enabled": False,  # Disable for testing
        }
        self.service = InventoryService(config)

    def tearDown(self):
        """Clean up test files."""
        import shutil

        shutil.rmtree(self.temp_dir)

    def test_service_initialization(self):
        """Test service initialization."""
        status = self.service.get_service_status()

        self.assertEqual(status["service"], "inventory_service")
        self.assertEqual(status["version"], "2.0.0")
        self.assertEqual(status["status"], "running")

    def test_query_methods(self):
        """Test query methods on empty inventory."""
        # Test empty queries
        prod_targets = self.service.get_targets_by_role(NodeRole.PRODUCTION)
        self.assertEqual(len(prod_targets), 0)

        unhealthy_targets = self.service.get_unhealthy_targets()
        self.assertEqual(len(unhealthy_targets), 0)

        search_results = self.service.search_targets("test")
        self.assertEqual(len(search_results), 0)

    @patch(
        "src.services.inventory_service.InventoryService._convert_to_enhanced_inventory"
    )
    def test_full_discovery(self, mock_convert):
        """Test full discovery method."""
        # Mock the conversion method
        mock_convert.return_value = EnhancedFleetInventory()

        # Run discovery
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            inventory = loop.run_until_complete(self.service.run_full_discovery())
            self.assertIsNotNone(inventory)
        finally:
            loop.close()

    def test_health_check(self):
        """Test health check on empty inventory."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            health_results = loop.run_until_complete(self.service.run_health_check())
            self.assertIn("timestamp", health_results)
            self.assertIn("total_targets", health_results)
            self.assertEqual(health_results["total_targets"], 0)
        finally:
            loop.close()

    def test_storage_stats(self):
        """Test storage statistics."""
        stats = self.service.get_storage_stats()

        self.assertIn("database_size_bytes", stats)
        self.assertIn("snapshot_count", stats)
        self.assertIn("total_targets", stats)


class TestIntegration(unittest.TestCase):
    """Integration tests for the complete system."""

    def setUp(self):
        """Set up integration test."""
        self.temp_dir = tempfile.mkdtemp()
        self.config = {
            "db_path": os.path.join(self.temp_dir, "integration_test.db"),
            "use_sqlite": True,
            "auto_snapshot_enabled": True,
        }

    def tearDown(self):
        """Clean up test files."""
        import shutil

        shutil.rmtree(self.temp_dir)

    def test_complete_workflow(self):
        """Test complete workflow from creation to querying."""
        # 1. Create enhanced inventory
        inventory = EnhancedFleetInventory()

        # Add Proxmox host
        host = ProxmoxHost(
            hostname="proxmox-01",
            address="192.168.1.100",
            username="root",
            node_name="pve-node-01",
            cpu_cores=16,
            memory_mb=32768,
            storage_gb=1000,
        )
        inventory.add_proxmox_host(host)

        # Add targets
        target1 = EnhancedTarget(
            name="web-prod-01",
            node_type="container",
            host_id=host.id,
            runtime="docker",
            connection_method="ssh",
            role=NodeRole.PRODUCTION,
            cpu_cores=4,
            memory_mb=8192,
            resource_usage=ResourceUsage(
                cpu_percent=45.0, memory_percent=60.0, status=ResourceStatus.HEALTHY
            ),
        )
        inventory.add_target(target1)

        target2 = EnhancedTarget(
            name="api-dev-01",
            node_type="container",
            host_id=host.id,
            runtime="docker",
            connection_method="ssh",
            role=NodeRole.DEVELOPMENT,
            cpu_cores=2,
            memory_mb=4096,
            resource_usage=ResourceUsage(
                cpu_percent=25.0, memory_percent=40.0, status=ResourceStatus.HEALTHY
            ),
        )
        inventory.add_target(target2)

        # Add services
        service1 = EnhancedService(
            name="nginx",
            target_id=target1.id,
            service_type="docker",
            status="running",
            port=80,
            stack_name="web-stack",
        )
        inventory.add_service(service1)

        service2 = EnhancedService(
            name="node-api",
            target_id=target2.id,
            service_type="docker",
            status="running",
            port=3000,
            stack_name="api-stack",
        )
        inventory.add_service(service2)

        # Add stacks
        stack1 = EnhancedStack(
            name="web-stack",
            compose_file_path="/opt/stacks/web/docker-compose.yml",
            services=[service1.id],
            targets=[target1.id],
            stack_status="running",
        )
        inventory.add_stack(stack1)

        # 2. Save to persistence
        persistence = EnhancedInventoryPersistence(
            db_path=self.config["db_path"], use_sqlite=True
        )
        persistence.save_inventory(inventory)

        # 3. Test queries
        prod_targets = persistence.get_targets_by_role(NodeRole.PRODUCTION)
        self.assertEqual(len(prod_targets), 1)
        self.assertEqual(prod_targets[0].name, "web-prod-01")

        dev_targets = persistence.get_targets_by_role(NodeRole.DEVELOPMENT)
        self.assertEqual(len(dev_targets), 1)
        self.assertEqual(dev_targets[0].name, "api-dev-01")

        web_services = persistence.get_services_by_stack("web-stack")
        self.assertEqual(len(web_services), 1)
        self.assertEqual(web_services[0].name, "nginx")

        # 4. Create snapshots
        snapshot_manager = SnapshotManager(persistence)
        snapshot1 = snapshot_manager.create_snapshot(
            inventory=inventory, name="baseline", description="Baseline snapshot"
        )

        # 5. Modify inventory
        target1.health_score = 0.6  # Reduce health score
        target1.resource_usage.cpu_percent = 90.0  # Increase CPU usage
        inventory.add_target(target1)  # Re-add to update

        # Create new target
        target3 = EnhancedTarget(
            name="db-prod-01",
            node_type="container",
            host_id=host.id,
            runtime="docker",
            connection_method="ssh",
            role=NodeRole.PRODUCTION,
            cpu_cores=8,
            memory_mb=16384,
        )
        inventory.add_target(target3)

        # 6. Create second snapshot
        snapshot2 = snapshot_manager.create_snapshot(
            inventory=inventory,
            name="after-changes",
            description="Snapshot after changes",
        )

        # 7. Compare snapshots
        diff = snapshot_manager.compare_snapshots(snapshot1, snapshot2)

        self.assertEqual(diff.entities_created, 1)  # db-prod-01 created
        self.assertEqual(diff.entities_modified, 1)  # web-prod-01 modified
        self.assertEqual(diff.total_changes, 2)

        # 8. Test health impact analysis
        self.assertIn("health_impact", diff)
        self.assertIn("health_score_change", diff.health_impact)

        # Verify health score decreased
        self.assertLess(diff.health_impact["health_score_change"], 0)

        print("✓ Integration test completed successfully")
        print(f"  - Created {inventory.total_targets} targets")
        print(f"  - Created {inventory.total_services} services")
        print(f"  - Created {inventory.total_stacks} stacks")
        print(f"  - Detected {diff.total_changes} changes between snapshots")


def run_comprehensive_tests():
    """Run all tests and return results."""
    # Create test suite
    test_classes = [
        TestEnhancedInventoryModels,
        TestFleetInventory,
        TestSnapshotManagement,
        TestPersistenceLayer,
        TestInventoryService,
        TestIntegration,
    ]

    suite = unittest.TestSuite()

    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        suite.addTests(tests)

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result


if __name__ == "__main__":
    print("🚀 Running Enhanced Fleet Inventory System Tests")
    print("=" * 60)

    # Run comprehensive tests
    test_result = run_comprehensive_tests()

    # Print summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Tests run: {test_result.testsRun}")
    print(
        f"Successes: {test_result.testsRun - len(test_result.failures) - len(test_result.errors)}"
    )
    print(f"Failures: {len(test_result.failures)}")
    print(f"Errors: {len(test_result.errors)}")

    if test_result.wasSuccessful():
        print(
            "\n✅ All tests passed! The Enhanced Fleet Inventory System is working correctly."
        )
    else:
        print("\n❌ Some tests failed. Please review the output above.")

        if test_result.failures:
            print("\nFAILURES:")
            for test, traceback in test_result.failures:
                print(f"  - {test}: {traceback}")

        if test_result.errors:
            print("\nERRORS:")
            for test, traceback in test_result.errors:
                print(f"  - {test}: {traceback}")
