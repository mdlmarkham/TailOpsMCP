"""
Basic Test for Enhanced Fleet Inventory System

Simplified test to validate core functionality without import conflicts.
"""

import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Direct imports to avoid __init__.py issues
try:
    from models.enhanced_fleet_inventory import (
        EnhancedFleetInventory, EnhancedTarget, EnhancedService, EnhancedStack,
        NodeRole, ResourceStatus, SecurityStatus, ResourceUsage, SecurityPosture
    )
    from models.inventory_snapshot import (
        InventorySnapshot, SnapshotManager, SnapshotType, ChangeType
    )
    from utils.inventory_persistence import EnhancedInventoryPersistence
    print("✓ Successfully imported enhanced inventory modules")
except ImportError as e:
    print(f"✗ Import error: {e}")
    sys.exit(1)


class TestBasicInventoryFunctionality(unittest.TestCase):
    """Test basic inventory functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_inventory.db")
    
    def tearDown(self):
        """Clean up test files."""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_enhanced_target_creation(self):
        """Test EnhancedTarget creation and properties."""
        # Create a basic target
        target = EnhancedTarget(
            name="test-server-01",
            role=NodeRole.PRODUCTION,
            cpu_cores=4,
            memory_mb=8192,
            resource_usage=ResourceUsage(
                cpu_percent=45.0,
                memory_percent=60.0,
                status=ResourceStatus.HEALTHY
            )
        )
        
        # Verify basic properties
        self.assertEqual(target.name, "test-server-01")
        self.assertEqual(target.role, NodeRole.PRODUCTION)
        self.assertEqual(target.cpu_cores, 4)
        self.assertEqual(target.resource_usage.cpu_percent, 45.0)
        self.assertEqual(target.resource_usage.status, ResourceStatus.HEALTHY)
        
        # Test validation
        errors = target.validate()
        self.assertEqual(len(errors), 0)  # Should have no errors
    
    def test_enhanced_service_creation(self):
        """Test EnhancedService creation and properties."""
        service = EnhancedService(
            name="nginx",
            target_id="target-123",
            service_type="docker",
            port=80,
            health_check_enabled=True
        )
        
        self.assertEqual(service.name, "nginx")
        self.assertEqual(service.service_type, "docker")
        self.assertEqual(service.port, 80)
        self.assertTrue(service.health_check_enabled)
    
    def test_fleet_inventory_management(self):
        """Test EnhancedFleetInventory management."""
        inventory = EnhancedFleetInventory()
        
        # Add targets
        target1 = EnhancedTarget(
            name="prod-web-01",
            role=NodeRole.PRODUCTION,
            health_score=0.9
        )
        target2 = EnhancedTarget(
            name="dev-api-01",
            role=NodeRole.DEVELOPMENT,
            health_score=0.7
        )
        
        inventory.add_target(target1)
        inventory.add_target(target2)
        
        # Add services
        service1 = EnhancedService(
            name="nginx",
            target_id=target1.id,
            service_type="docker"
        )
        
        inventory.add_service(service1)
        
        # Verify metrics
        self.assertEqual(inventory.total_targets, 2)
        self.assertEqual(inventory.total_services, 1)
        self.assertEqual(inventory.healthy_targets, 2)
        
        # Test filtering
        prod_targets = inventory.get_targets_by_role(NodeRole.PRODUCTION)
        self.assertEqual(len(prod_targets), 1)
        self.assertEqual(prod_targets[0].name, "prod-web-01")
        
        # Test health filtering
        unhealthy_targets = inventory.get_unhealthy_targets(threshold=0.8)
        self.assertEqual(len(unhealthy_targets), 1)
        self.assertEqual(unhealthy_targets[0].name, "dev-api-01")
    
    def test_serialization(self):
        """Test serialization and deserialization."""
        # Create inventory
        inventory = EnhancedFleetInventory()
        target = EnhancedTarget(
            name="test-target",
            role=NodeRole.DEVELOPMENT,
            cpu_cores=2,
            memory_mb=4096
        )
        inventory.add_target(target)
        
        # Test to_dict
        inventory_dict = inventory.to_dict()
        self.assertIn("targets", inventory_dict)
        self.assertIn("services", inventory_dict)
        self.assertEqual(len(inventory_dict["targets"]), 1)
        
        # Test from_dict
        restored_inventory = EnhancedFleetInventory.from_dict(inventory_dict)
        self.assertEqual(restored_inventory.total_targets, 1)
        self.assertEqual(restored_inventory.total_services, 0)
        
        # Verify target data
        restored_target = list(restored_inventory.targets.values())[0]
        self.assertEqual(restored_target.name, "test-target")
        self.assertEqual(restored_target.role, NodeRole.DEVELOPMENT)
    
    def test_persistence_layer(self):
        """Test persistence layer functionality."""
        persistence = EnhancedInventoryPersistence(
            db_path=self.db_path,
            use_sqlite=True
        )
        
        # Create test inventory
        inventory = EnhancedFleetInventory()
        target = EnhancedTarget(
            name="persistent-server",
            role=NodeRole.PRODUCTION,
            cpu_cores=8,
            memory_mb=16384
        )
        inventory.add_target(target)
        
        service = EnhancedService(
            name="web-service",
            target_id=target.id,
            service_type="docker",
            port=8080
        )
        inventory.add_service(service)
        
        # Save inventory
        persistence.save_inventory(inventory)
        
        # Load inventory
        loaded_inventory = persistence.load_inventory()
        
        # Verify data integrity
        self.assertEqual(loaded_inventory.total_targets, 1)
        self.assertEqual(loaded_inventory.total_services, 1)
        
        # Verify target data
        loaded_target = list(loaded_inventory.targets.values())[0]
        self.assertEqual(loaded_target.name, "persistent-server")
        self.assertEqual(loaded_target.cpu_cores, 8)
        
        # Verify service data
        loaded_service = list(loaded_inventory.services.values())[0]
        self.assertEqual(loaded_service.name, "web-service")
        self.assertEqual(loaded_service.port, 8080)
    
    def test_query_methods(self):
        """Test query methods."""
        persistence = EnhancedInventoryPersistence(
            db_path=self.db_path,
            use_sqlite=True
        )
        
        # Create and save inventory
        inventory = EnhancedFleetInventory()
        
        # Add targets with different roles
        prod_target = EnhancedTarget(
            name="prod-server",
            role=NodeRole.PRODUCTION
        )
        dev_target = EnhancedTarget(
            name="dev-server",
            role=NodeRole.DEVELOPMENT
        )
        staging_target = EnhancedTarget(
            name="staging-server",
            role=NodeRole.STAGING
        )
        
        inventory.add_target(prod_target)
        inventory.add_target(dev_target)
        inventory.add_target(staging_target)
        
        persistence.save_inventory(inventory)
        
        # Test role-based queries
        prod_targets = persistence.get_targets_by_role(NodeRole.PRODUCTION)
        self.assertEqual(len(prod_targets), 1)
        self.assertEqual(prod_targets[0].name, "prod-server")
        
        dev_targets = persistence.get_targets_by_role(NodeRole.DEVELOPMENT)
        self.assertEqual(len(dev_targets), 1)
        self.assertEqual(dev_targets[0].name, "dev-server")
        
        # Test search
        search_results = persistence.search_targets("prod")
        self.assertEqual(len(search_results), 1)
        self.assertEqual(search_results[0].name, "prod-server")
    
    def test_snapshot_creation(self):
        """Test snapshot creation and management."""
        snapshot_manager = SnapshotManager()
        
        # Create test inventory
        inventory = EnhancedFleetInventory()
        target = EnhancedTarget(
            name="snapshot-server",
            role=NodeRole.PRODUCTION,
            health_score=0.85
        )
        inventory.add_target(target)
        
        # Create snapshot
        snapshot = snapshot_manager.create_snapshot(
            inventory=inventory,
            name="test-snapshot",
            snapshot_type=SnapshotType.MANUAL,
            description="Test snapshot for validation"
        )
        
        # Verify snapshot properties
        self.assertEqual(snapshot.name, "test-snapshot")
        self.assertEqual(snapshot.snapshot_type, SnapshotType.MANUAL)
        self.assertEqual(snapshot.total_targets, 1)
        
        # Verify snapshot storage
        retrieved_snapshot = snapshot_manager.get_snapshot(snapshot.id)
        self.assertIsNotNone(retrieved_snapshot)
        self.assertEqual(retrieved_snapshot.name, "test-snapshot")
    
    def test_snapshot_comparison(self):
        """Test snapshot comparison and change detection."""
        snapshot_manager = SnapshotManager()
        
        # Create first inventory
        inventory1 = EnhancedFleetInventory()
        target1 = EnhancedTarget(
            name="server-01",
            role=NodeRole.PRODUCTION,
            cpu_cores=4,
            health_score=0.9
        )
        inventory1.add_target(target1)
        
        # Create second inventory with changes
        inventory2 = EnhancedFleetInventory()
        target1_modified = EnhancedTarget(
            name="server-01",
            role=NodeRole.PRODUCTION,
            cpu_cores=8,  # Changed
            health_score=0.8  # Changed
        )
        target2_new = EnhancedTarget(
            name="server-02",
            role=NodeRole.DEVELOPMENT,
            cpu_cores=2,
            health_score=0.7
        )
        inventory2.add_target(target1_modified)
        inventory2.add_target(target2_new)
        
        # Create snapshots
        snapshot1 = snapshot_manager.create_snapshot(
            inventory=inventory1,
            name="snapshot-before",
            description="Before changes"
        )
        
        snapshot2 = snapshot_manager.create_snapshot(
            inventory=inventory2,
            name="snapshot-after",
            description="After changes"
        )
        
        # Compare snapshots
        diff = snapshot_manager.compare_snapshots(snapshot1, snapshot2)
        
        # Verify change detection
        self.assertEqual(diff.entities_created, 1)  # server-02 created
        self.assertEqual(diff.entities_modified, 1)  # server-01 modified
        self.assertEqual(diff.entities_deleted, 0)
        self.assertEqual(diff.total_changes, 2)
        
        # Verify change details
        self.assertEqual(len(diff.target_changes), 2)
        created_changes = [c for c in diff.target_changes if c.change_type == ChangeType.CREATED]
        modified_changes = [c for c in diff.target_changes if c.change_type == ChangeType.MODIFIED]
        
        self.assertEqual(len(created_changes), 1)
        self.assertEqual(len(modified_changes), 1)
        
        # Verify health impact analysis
        self.assertIn("health_impact", diff)
        self.assertIn("health_score_change", diff.health_impact)


def run_basic_tests():
    """Run basic functionality tests."""
    print("🚀 Running Basic Enhanced Fleet Inventory Tests")
    print("=" * 60)
    
    # Create test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(TestBasicInventoryFunctionality)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.wasSuccessful():
        print("\n✅ Basic functionality tests passed!")
        print("The Enhanced Fleet Inventory System core components are working correctly.")
    else:
        print("\n❌ Some tests failed. Please review the output above.")
        
        if result.failures:
            print("\nFAILURES:")
            for test, traceback in result.failures:
                print(f"  - {test}: {traceback}")
        
        if result.errors:
            print("\nERRORS:")
            for test, traceback in result.errors:
                print(f"  - {test}: {traceback}")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_basic_tests()
    sys.exit(0 if success else 1)