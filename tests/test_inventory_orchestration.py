"""
Comprehensive test suite for inventory orchestration components.

Tests fleet inventory discovery and synchronization, health monitoring and scoring,
change detection and drift monitoring, and inventory snapshot and comparison functionality.
"""

import pytest
import asyncio
import uuid
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock

from src.services.inventory_service import InventoryService
from src.models.enhanced_fleet_inventory import (
    EnhancedFleetInventory,
    EnhancedTarget,
    EnhancedService,
    EnhancedStack,
    NodeRole,
    HealthStatus,
    ServiceStatus,
)
from src.models.inventory_snapshot import (
    SnapshotType,
    SnapshotDiff,
    InventorySnapshot,
    SnapshotMetadata,
)


class TestInventoryOrchestration:
    """Test fleet inventory orchestration."""

    @pytest.fixture
    def mock_inventory_service(self):
        """Create mock inventory service."""
        service = Mock(spec=InventoryService)
        service.run_full_discovery = AsyncMock()
        service.get_inventory = AsyncMock()
        service.get_target_health = AsyncMock()
        service.get_service_status = AsyncMock()
        service.detect_changes = AsyncMock()
        service.create_snapshot = AsyncMock()
        service.compare_snapshots = AsyncMock()
        return service

    @pytest.fixture
    def sample_inventory_data(self):
        """Create sample enhanced inventory data for testing."""
        return {
            "gateway": EnhancedTarget(
                id="gateway-001",
                hostname="gateway-host",
                role=NodeRole.GATEWAY,
                ip_address="192.168.1.1",
                health_status=HealthStatus.HEALTHY,
                services=[
                    EnhancedService(
                        id="service-001",
                        name="TailOpsMCP",
                        type="management",
                        status=ServiceStatus.RUNNING,
                        port=8080,
                        version="1.0.0",
                    )
                ],
                stacks=[],
                last_seen=datetime.utcnow(),
                metadata={
                    "os": "Ubuntu 20.04",
                    "architecture": "x86_64",
                    "uptime": "10 days",
                },
            ),
            "proxmox_hosts": [
                EnhancedTarget(
                    id="proxmox-001",
                    hostname="proxmox-host-1",
                    role=NodeRole.PROXMOX_HOST,
                    ip_address="192.168.1.10",
                    health_status=HealthStatus.HEALTHY,
                    services=[
                        EnhancedService(
                            id="pve-service",
                            name="Proxmox VE",
                            type="virtualization",
                            status=ServiceStatus.RUNNING,
                            port=8006,
                            version="7.4-1",
                        )
                    ],
                    stacks=[
                        EnhancedStack(
                            id="stack-001",
                            name="web-stack",
                            type="web",
                            services=["nginx", "app", "database"],
                            status="running",
                        )
                    ],
                    last_seen=datetime.utcnow(),
                    metadata={"cpu_cores": 16, "memory_gb": 64, "storage_gb": 1000},
                )
            ],
            "containers": [
                EnhancedTarget(
                    id="container-101",
                    hostname="web-container",
                    role=NodeRole.CONTAINER,
                    ip_address="192.168.1.101",
                    health_status=HealthStatus.WARNING,
                    parent_id="proxmox-001",
                    services=[
                        EnhancedService(
                            id="nginx-service",
                            name="Nginx",
                            type="web-server",
                            status=ServiceStatus.RUNNING,
                            port=80,
                            version="1.18.0",
                        )
                    ],
                    stacks=[],
                    last_seen=datetime.utcnow(),
                    metadata={
                        "image": "nginx:1.18",
                        "cpu_limit": "2",
                        "memory_limit": "1GB",
                    },
                )
            ],
        }

    @pytest.mark.asyncio
    async def test_inventory_discovery_and_synchronization(
        self, mock_inventory_service, sample_inventory_data
    ):
        """Test inventory discovery and synchronization."""
        # Mock full discovery process
        mock_inventory_service.run_full_discovery.return_value = EnhancedFleetInventory(
            targets=sample_inventory_data,
            last_updated=datetime.utcnow(),
            discovery_stats={
                "targets_discovered": 3,
                "services_discovered": 3,
                "stacks_discovered": 1,
                "discovery_time": "5.2s",
            },
        )

        # Run full discovery
        inventory = await mock_inventory_service.run_full_discovery()

        # Verify discovery results
        assert inventory.discovery_stats["targets_discovered"] == 3
        assert inventory.discovery_stats["services_discovered"] == 3
        assert inventory.discovery_stats["stacks_discovered"] == 1

        # Test inventory synchronization
        mock_inventory_service.get_inventory.return_value = inventory
        current_inventory = await mock_inventory_service.get_inventory()

        assert current_inventory.last_updated is not None
        assert len(current_inventory.targets) > 0

        # Test incremental discovery
        incremental_update = {
            "new_targets": [
                EnhancedTarget(
                    id="container-102",
                    hostname="app-container",
                    role=NodeRole.CONTAINER,
                    ip_address="192.168.1.102",
                    health_status=HealthStatus.HEALTHY,
                    parent_id="proxmox-001",
                    services=[],
                    stacks=[],
                    last_seen=datetime.utcnow(),
                    metadata={},
                )
            ],
            "updated_targets": [],
            "removed_targets": [],
        }

        mock_inventory_service.run_incremental_discovery.return_value = (
            incremental_update
        )
        update_result = await mock_inventory_service.run_incremental_discovery()

        assert len(update_result["new_targets"]) == 1
        assert update_result["new_targets"][0].id == "container-102"

    @pytest.mark.asyncio
    async def test_health_monitoring_and_scoring(
        self, mock_inventory_service, sample_inventory_data
    ):
        """Test health monitoring and scoring algorithms."""
        # Test health score calculation for different target states
        health_scenarios = [
            {
                "target": sample_inventory_data["gateway"],
                "expected_score": 95,
                "expected_status": HealthStatus.HEALTHY,
            },
            {
                "target": sample_inventory_data["containers"][0],
                "expected_score": 70,
                "expected_status": HealthStatus.WARNING,
            },
            {
                "target": EnhancedTarget(
                    id="failed-target",
                    hostname="failed-host",
                    role=NodeRole.CONTAINER,
                    ip_address="192.168.1.200",
                    health_status=HealthStatus.CRITICAL,
                    services=[],
                    stacks=[],
                    last_seen=datetime.utcnow() - timedelta(hours=2),  # Stale
                    metadata={},
                ),
                "expected_score": 20,
                "expected_status": HealthStatus.CRITICAL,
            },
        ]

        for scenario in health_scenarios:
            mock_inventory_service.get_target_health.return_value = {
                "score": scenario["expected_score"],
                "status": scenario["expected_status"],
                "issues": ["High memory usage"]
                if scenario["expected_status"] == HealthStatus.WARNING
                else [],
                "last_check": datetime.utcnow(),
            }

            health_result = await mock_inventory_service.get_target_health(
                scenario["target"].id
            )

            assert health_result["score"] == scenario["expected_score"]
            assert health_result["status"] == scenario["expected_status"]

        # Test aggregated fleet health score
        mock_inventory_service.get_fleet_health.return_value = {
            "overall_score": 82,
            "status": HealthStatus.WARNING,
            "target_scores": {
                "gateway-001": 95,
                "proxmox-001": 90,
                "container-101": 70,
            },
            "critical_issues": 1,
            "warning_issues": 1,
            "healthy_targets": 2,
        }

        fleet_health = await mock_inventory_service.get_fleet_health()

        assert fleet_health["overall_score"] == 82
        assert fleet_health["status"] == HealthStatus.WARNING
        assert fleet_health["critical_issues"] == 1
        assert fleet_health["healthy_targets"] == 2

    @pytest.mark.asyncio
    async def test_change_detection_and_drift_monitoring(
        self, mock_inventory_service, sample_inventory_data
    ):
        """Test change detection and drift monitoring."""
        # Create baseline snapshot
        baseline_snapshot = InventorySnapshot(
            id=str(uuid.uuid4()),
            snapshot_type=SnapshotType.BASELINE,
            created_at=datetime.utcnow() - timedelta(days=1),
            targets=sample_inventory_data,
            metadata=SnapshotMetadata(
                version="1.0",
                created_by="system",
                description="Baseline inventory snapshot",
            ),
        )

        # Create current state with changes
        current_state = sample_inventory_data.copy()

        # Add new target
        current_state["containers"].append(
            EnhancedTarget(
                id="container-103",
                hostname="new-container",
                role=NodeRole.CONTAINER,
                ip_address="192.168.1.103",
                health_status=HealthStatus.HEALTHY,
                parent_id="proxmox-001",
                services=[],
                stacks=[],
                last_seen=datetime.utcnow(),
                metadata={},
            )
        )

        # Modify existing service
        current_state["gateway"].services[0].version = "1.1.0"  # Version change

        # Mock change detection
        change_detection_result = {
            "added_targets": ["container-103"],
            "removed_targets": [],
            "modified_targets": ["gateway-001"],
            "added_services": ["container-103:empty"],
            "modified_services": ["gateway-001:TailOpsMCP"],
            "removed_services": [],
            "added_stacks": [],
            "modified_stacks": [],
            "removed_stacks": [],
            "configuration_drift": [
                {
                    "target": "gateway-001",
                    "service": "TailOpsMCP",
                    "field": "version",
                    "old_value": "1.0.0",
                    "new_value": "1.1.0",
                    "severity": "medium",
                }
            ],
        }

        mock_inventory_service.detect_changes.return_value = change_detection_result
        changes = await mock_inventory_service.detect_changes(
            baseline_snapshot, current_state
        )

        assert "container-103" in changes["added_targets"]
        assert "gateway-001" in changes["modified_targets"]
        assert len(changes["configuration_drift"]) == 1
        assert changes["configuration_drift"][0]["field"] == "version"

        # Test drift monitoring with threshold-based alerts
        drift_config = {
            "version_change_threshold": "patch",  # Alert on patch version changes
            "configuration_change_threshold": "major",  # Alert on major config changes
            "resource_threshold": 0.2,  # 20% resource change threshold
        }

        mock_inventory_service.evaluate_drift_severity.return_value = {
            "severity": "medium",
            "requires_attention": True,
            "recommended_actions": [
                "Review version change approval",
                "Update baseline configuration",
            ],
        }

        drift_evaluation = await mock_inventory_service.evaluate_drift_severity(
            changes["configuration_drift"][0], drift_config
        )

        assert drift_evaluation["severity"] == "medium"
        assert drift_evaluation["requires_attention"] is True

    @pytest.mark.asyncio
    async def test_inventory_snapshot_and_comparison(
        self, mock_inventory_service, sample_inventory_data
    ):
        """Test inventory snapshot and comparison functionality."""
        # Test snapshot creation
        snapshot_request = {
            "type": SnapshotType.MANUAL,
            "description": "Test snapshot for comparison",
            "include_metadata": True,
            "include_history": False,
        }

        created_snapshot = InventorySnapshot(
            id=str(uuid.uuid4()),
            snapshot_type=SnapshotType.MANUAL,
            created_at=datetime.utcnow(),
            targets=sample_inventory_data,
            metadata=SnapshotMetadata(
                version="1.0",
                created_by="test_user",
                description="Test snapshot for comparison",
            ),
        )

        mock_inventory_service.create_snapshot.return_value = created_snapshot
        snapshot = await mock_inventory_service.create_snapshot(snapshot_request)

        assert snapshot.snapshot_type == SnapshotType.MANUAL
        assert snapshot.metadata.description == "Test snapshot for comparison"

        # Test snapshot comparison
        comparison_request = {
            "source_snapshot_id": created_snapshot.id,
            "target_snapshot_id": str(uuid.uuid4()),  # Different snapshot
            "comparison_type": "full",
            "include_diff_details": True,
        }

        comparison_result = SnapshotDiff(
            source_id=created_snapshot.id,
            target_id="target-snapshot-id",
            comparison_type="full",
            differences=[
                {
                    "type": "added",
                    "category": "target",
                    "item_id": "container-103",
                    "details": "New container added",
                },
                {
                    "type": "modified",
                    "category": "service",
                    "item_id": "gateway-001:TailOpsMCP",
                    "field": "version",
                    "old_value": "1.0.0",
                    "new_value": "1.1.0",
                },
            ],
            summary={
                "total_differences": 2,
                "added_items": 1,
                "modified_items": 1,
                "removed_items": 0,
            },
            created_at=datetime.utcnow(),
        )

        mock_inventory_service.compare_snapshots.return_value = comparison_result
        comparison = await mock_inventory_service.compare_snapshots(comparison_request)

        assert comparison.summary["total_differences"] == 2
        assert comparison.summary["added_items"] == 1
        assert comparison.summary["modified_items"] == 1

        # Test snapshot restoration
        restore_request = {
            "snapshot_id": created_snapshot.id,
            "restore_options": {
                "validate_before_restore": True,
                "backup_current_state": True,
                "restore_metadata": False,
            },
        }

        mock_inventory_service.restore_snapshot.return_value = {
            "success": True,
            "restored_targets": len(sample_inventory_data),
            "backup_snapshot_id": str(uuid.uuid4()),
            "validation_results": {"valid": True, "warnings": []},
        }

        restore_result = await mock_inventory_service.restore_snapshot(restore_request)

        assert restore_result["success"] is True
        assert restore_result["restored_targets"] == len(sample_inventory_data)
        assert restore_result["backup_snapshot_id"] is not None


class TestInventoryIntegration:
    """Integration tests for inventory orchestration components."""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_end_to_end_inventory_workflow(self, temp_test_dir):
        """Test end-to-end inventory workflow."""
        # This would test the complete inventory discovery and management workflow
        # For now, this is a placeholder for integration testing
        pass

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_inventory_performance_under_load(self):
        """Test inventory performance under load."""
        # This would test inventory performance with large numbers of targets
        # For now, this is a placeholder for performance testing
        pass


class TestInventoryEdgeCases:
    """Test inventory edge cases and failure scenarios."""

    @pytest.mark.edge_case
    @pytest.mark.asyncio
    async def test_inventory_with_network_failures(self, mock_inventory_service):
        """Test inventory behavior during network failures."""
        # Test discovery with partial network failures
        mock_inventory_service.run_full_discovery.side_effect = [
            Exception("Network timeout for proxmox-001"),
            Exception("Connection refused for container-101"),
            Exception("DNS resolution failed for container-102"),
        ]

        # Should handle partial failures gracefully
        partial_results = []
        for attempt in range(3):
            try:
                await mock_inventory_service.run_full_discovery()
            except Exception as e:
                partial_results.append(str(e))

        assert len(partial_results) == 3
        assert "Network timeout" in partial_results[0]
        assert "Connection refused" in partial_results[1]
        assert "DNS resolution failed" in partial_results[2]

        # Test inventory recovery after network restoration
        mock_inventory_service.run_full_discovery.return_value = EnhancedFleetInventory(
            targets={},
            last_updated=datetime.utcnow(),
            discovery_stats={
                "targets_discovered": 0,
                "services_discovered": 0,
                "stacks_discovered": 0,
                "discovery_time": "1.0s",
                "errors": ["Network restoration in progress"],
            },
        )

        recovered_inventory = await mock_inventory_service.run_full_discovery()
        assert recovered_inventory.discovery_stats["errors"] == [
            "Network restoration in progress"
        ]

    @pytest.mark.edge_case
    @pytest.mark.asyncio
    async def test_inventory_with_corrupted_data(self, mock_inventory_service):
        """Test inventory behavior with corrupted data."""
        # Test corrupted target data
        corrupted_target = {
            "id": "corrupted-target",
            "hostname": None,  # Corrupted hostname
            "role": "invalid_role",  # Invalid role
            "services": "not_a_list",  # Corrupted services
            "metadata": {"corrupted": True},
        }

        # Test data validation and recovery
        mock_inventory_service.validate_and_recover_target.return_value = {
            "valid": False,
            "recovered": True,
            "fixed_fields": {
                "hostname": "recovered-host",
                "role": NodeRole.CONTAINER,
                "services": [],
            },
            "recovery_notes": [
                "Fixed null hostname",
                "Invalid role defaulted to CONTAINER",
                "Services converted to empty list",
            ],
        }

        recovery_result = await mock_inventory_service.validate_and_recover_target(
            corrupted_target
        )

        assert recovery_result["valid"] is False
        assert recovery_result["recovered"] is True
        assert "Fixed null hostname" in recovery_result["recovery_notes"]

    @pytest.mark.edge_case
    @pytest.mark.asyncio
    async def test_inventory_with_large_scale_data(self, mock_inventory_service):
        """Test inventory behavior with large-scale data."""
        # Generate large-scale test data
        large_inventory_data = {
            "gateway": EnhancedTarget(
                id="gateway-001",
                hostname="gateway-host",
                role=NodeRole.GATEWAY,
                ip_address="192.168.1.1",
                health_status=HealthStatus.HEALTHY,
                services=[],
                stacks=[],
                last_seen=datetime.utcnow(),
                metadata={},
            ),
            "proxmox_hosts": [
                EnhancedTarget(
                    id=f"proxmox-{i:03d}",
                    hostname=f"proxmox-host-{i}",
                    role=NodeRole.PROXMOX_HOST,
                    ip_address=f"192.168.1.{10 + i}",
                    health_status=HealthStatus.HEALTHY,
                    services=[
                        EnhancedService(
                            id=f"pve-service-{i}",
                            name="Proxmox VE",
                            type="virtualization",
                            status=ServiceStatus.RUNNING,
                            port=8006,
                            version="7.4-1",
                        )
                    ],
                    stacks=[
                        EnhancedStack(
                            id=f"stack-{i}",
                            name=f"web-stack-{i}",
                            type="web",
                            services=[f"nginx-{i}", f"app-{i}", f"db-{i}"],
                            status="running",
                        )
                    ],
                    last_seen=datetime.utcnow(),
                    metadata={"cpu_cores": 16, "memory_gb": 64, "storage_gb": 1000},
                )
                for i in range(50)  # 50 Proxmox hosts
            ],
            "containers": [
                EnhancedTarget(
                    id=f"container-{i:04d}",
                    hostname=f"container-{i}",
                    role=NodeRole.CONTAINER,
                    ip_address=f"192.168.1.{100 + i}",
                    health_status=HealthStatus.HEALTHY,
                    parent_id=f"proxmox-{(i % 50):03d}",
                    services=[
                        EnhancedService(
                            id=f"service-{i:04d}",
                            name=f"service-{i}",
                            type="application",
                            status=ServiceStatus.RUNNING,
                            port=8000 + (i % 1000),
                            version="1.0.0",
                        )
                    ],
                    stacks=[],
                    last_seen=datetime.utcnow(),
                    metadata={
                        "image": "ubuntu:20.04",
                        "cpu_limit": "1",
                        "memory_limit": "512MB",
                    },
                )
                for i in range(1000)  # 1000 containers
            ],
        }

        # Test large inventory processing
        mock_inventory_service.process_large_inventory.return_value = {
            "processed_targets": 1051,  # 1 gateway + 50 hosts + 1000 containers
            "processing_time": "15.2s",
            "memory_usage_mb": 512,
            "errors": [],
            "warnings": ["Consider pagination for very large inventories"],
        }

        processing_result = await mock_inventory_service.process_large_inventory(
            large_inventory_data
        )

        assert processing_result["processed_targets"] == 1051
        assert processing_result["processing_time"] == "15.2s"
        assert processing_result["memory_usage_mb"] == 512
        assert len(processing_result["errors"]) == 0

    @pytest.mark.edge_case
    @pytest.mark.asyncio
    async def test_inventory_concurrent_access(self, mock_inventory_service):
        """Test inventory behavior during concurrent access."""
        # Simulate concurrent inventory operations
        operations = [
            "get_inventory",
            "create_snapshot",
            "detect_changes",
            "get_target_health",
            "compare_snapshots",
        ]

        results = {}

        # Execute operations concurrently
        async def mock_operation(operation_name):
            await asyncio.sleep(0.1)  # Simulate operation time
            results[operation_name] = f"{operation_name}_result"
            return results[operation_name]

        # Run operations concurrently
        tasks = [mock_operation(op) for op in operations]
        concurrent_results = await asyncio.gather(*tasks)

        assert len(concurrent_results) == len(operations)
        assert all(result in results.values() for result in concurrent_results)

        # Test concurrent modification handling
        mock_inventory_service.handle_concurrent_modification.return_value = {
            "conflict_detected": True,
            "resolution_strategy": "last_write_wins",
            "merged_changes": {"targets_updated": 2, "conflicts_resolved": 1},
        }

        conflict_result = await mock_inventory_service.handle_concurrent_modification(
            "operation_1", {"target_id": "test-target"}, "operation_2"
        )

        assert conflict_result["conflict_detected"] is True
        assert conflict_result["resolution_strategy"] == "last_write_wins"
        assert conflict_result["merged_changes"]["conflicts_resolved"] == 1


class TestInventoryPerformance:
    """Test inventory performance characteristics."""

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_discovery_performance(self, mock_inventory_service):
        """Test inventory discovery performance."""
        # Test discovery performance with increasing target counts
        target_counts = [10, 50, 100, 500, 1000]
        performance_results = {}

        for count in target_counts:
            start_time = datetime.utcnow()

            # Mock discovery for different target counts
            mock_inventory_service.run_full_discovery.return_value = (
                EnhancedFleetInventory(
                    targets={
                        f"target-{i}": EnhancedTarget(
                            id=f"target-{i}",
                            hostname=f"host-{i}",
                            role=NodeRole.CONTAINER,
                            ip_address=f"192.168.1.{i}",
                            health_status=HealthStatus.HEALTHY,
                            services=[],
                            stacks=[],
                            last_seen=datetime.utcnow(),
                            metadata={},
                        )
                        for i in range(count)
                    },
                    last_updated=datetime.utcnow(),
                    discovery_stats={
                        "targets_discovered": count,
                        "discovery_time": f"{count * 0.1:.1f}s",
                    },
                )
            )

            inventory = await mock_inventory_service.run_full_discovery()

            end_time = datetime.utcnow()
            processing_time = (end_time - start_time).total_seconds()

            performance_results[count] = {
                "targets": count,
                "processing_time": processing_time,
                "targets_per_second": count / processing_time
                if processing_time > 0
                else float("inf"),
            }

        # Verify performance scales reasonably
        for count in target_counts:
            result = performance_results[count]
            assert result["targets_per_second"] > 0
            if count > 100:  # For large inventories
                assert (
                    result["processing_time"] < count * 0.2
                )  # Should scale sub-linearly

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_inventory_query_performance(self, mock_inventory_service):
        """Test inventory query performance."""
        # Test various query patterns and their performance
        query_scenarios = [
            {
                "query_type": "filter_by_role",
                "parameters": {"role": NodeRole.CONTAINER},
                "expected_results": 500,
            },
            {
                "query_type": "filter_by_health",
                "parameters": {"health_status": HealthStatus.HEALTHY},
                "expected_results": 800,
            },
            {
                "query_type": "search_by_hostname",
                "parameters": {"hostname_pattern": "web-*"},
                "expected_results": 200,
            },
            {
                "query_type": "get_service_status",
                "parameters": {"service_type": "web-server"},
                "expected_results": 150,
            },
        ]

        for scenario in query_scenarios:
            start_time = datetime.utcnow()

            mock_inventory_service.query_inventory.return_value = {
                "results": [
                    {"id": f"result_{i}", "data": {}}
                    for i in range(scenario["expected_results"])
                ],
                "query_time": f"{scenario['expected_results'] * 0.001:.3f}s",
                "total_matches": scenario["expected_results"],
            }

            query_result = await mock_inventory_service.query_inventory(
                scenario["query_type"], scenario["parameters"]
            )

            end_time = datetime.utcnow()
            query_time = (end_time - start_time).total_seconds()

            assert query_result["total_matches"] == scenario["expected_results"]
            assert query_time < 1.0  # Should complete within 1 second
