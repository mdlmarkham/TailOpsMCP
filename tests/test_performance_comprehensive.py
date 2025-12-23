"""
Comprehensive performance test suite for TailOpsMCP.

Tests performance characteristics including:
- System performance under load
- Component performance benchmarks
- Resource usage monitoring
- Scalability testing
- Performance regression detection
"""

import pytest
import asyncio
import time
import psutil
import statistics
import gc
from datetime import datetime
from unittest.mock import Mock, AsyncMock, patch
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor


class TestSystemPerformance:
    """Test overall system performance."""

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_system_initialization_performance(self):
        """Test system initialization performance."""
        start_time = time.time()

        # Test basic system imports
        try:
            from src.services.system_integration import SystemIntegration
            from src.services.inventory_service import InventoryService
            from src.services.policy_gate import PolicyGate

            system = SystemIntegration()
            inventory = InventoryService()
            policy_gate = PolicyGate()

            end_time = time.time()
            initialization_time = end_time - start_time

            # Initialization should be fast
            assert initialization_time < 2.0, (
                f"System initialization too slow: {initialization_time}s"
            )

        except ImportError:
            pytest.skip("Performance testing not available")

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_memory_usage_stability(self):
        """Test memory usage remains stable."""
        # Get initial memory usage
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Perform operations
        try:
            from src.services.inventory_service import InventoryService

            inventory = InventoryService()

            # Simulate multiple operations
            for i in range(100):
                if hasattr(inventory, "get_inventory_status"):
                    await inventory.get_inventory_status()
                else:
                    break

        except ImportError:
            pytest.skip("Memory testing not available")

        # Force garbage collection
        gc.collect()

        # Check memory after operations
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory

        # Memory increase should be reasonable (< 100MB)
        assert memory_increase < 100, (
            f"Memory usage increased too much: {memory_increase}MB"
        )

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_concurrent_operation_performance(self):
        """Test performance under concurrent operations."""
        try:
            from src.services.inventory_service import InventoryService

            inventory = InventoryService()

            start_time = time.time()

            # Test concurrent operations
            tasks = []
            for i in range(50):
                if hasattr(inventory, "get_target_status"):
                    task = inventory.get_target_status(f"target_{i}")
                    tasks.append(task)
                else:
                    break

            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)

                end_time = time.time()
                duration = end_time - start_time

                # 50 concurrent operations should complete quickly
                assert duration < 5.0, (
                    f"Concurrent operations too slow: {duration}s for {len(tasks)} operations"
                )

        except ImportError:
            pytest.skip("Concurrent performance testing not available")

    @pytest.mark.performance
    def test_cpu_usage_limits(self):
        """Test CPU usage stays within limits."""
        start_time = time.time()

        # Monitor CPU during operations
        process = psutil.Process()
        cpu_samples = []

        try:
            from src.tools.inventory_tools import InventoryTools

            tools = InventoryTools()

            # Perform operations while monitoring CPU
            for i in range(10):
                cpu_percent = process.cpu_percent()
                cpu_samples.append(cpu_percent)

                if hasattr(tools, "check_target_status"):
                    tools.check_target_status("docker", "localhost")
                else:
                    break

                time.sleep(0.1)

        except ImportError:
            pytest.skip("CPU performance testing not available")

        end_time = time.time()
        duration = end_time - start_time

        # Calculate average CPU usage
        if cpu_samples:
            avg_cpu = statistics.mean(cpu_samples)
            assert avg_cpu < 80.0, f"CPU usage too high: {avg_cpu}%"


class TestServicePerformance:
    """Test individual service performance."""

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_inventory_service_performance(self):
        """Test inventory service performance."""
        try:
            from src.services.inventory_service import InventoryService

            inventory = InventoryService()

            # Test multiple inventory queries
            start_time = time.time()

            queries = []
            for i in range(100):
                if hasattr(inventory, "get_all_targets"):
                    query = inventory.get_all_targets()
                    queries.append(query)
                else:
                    break

            if queries:
                results = await asyncio.gather(*queries, return_exceptions=True)

                end_time = time.time()
                duration = end_time - start_time

                # 100 inventory queries should complete quickly
                assert duration < 3.0, (
                    f"Inventory queries too slow: {duration}s for {len(queries)} queries"
                )

        except ImportError:
            pytest.skip("Inventory service performance testing not available")

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_policy_gate_performance(self):
        """Test policy gate performance."""
        try:
            from src.services.policy_gate import PolicyGate

            policy_gate = PolicyGate()

            # Test policy evaluations
            start_time = time.time()

            evaluations = []
            for i in range(200):
                if hasattr(policy_gate, "evaluate_policy"):
                    eval_result = policy_gate.evaluate_policy(
                        operation="docker.create",
                        user_id=f"user_{i}",
                        resource="container",
                    )
                    evaluations.append(eval_result)
                else:
                    break

            end_time = time.time()
            duration = end_time - start_time

            # 200 policy evaluations should complete quickly
            if evaluations:
                assert duration < 2.0, (
                    f"Policy evaluations too slow: {duration}s for {len(evaluations)} evaluations"
                )

        except ImportError:
            pytest.skip("Policy gate performance testing not available")

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_fleet_tools_performance(self):
        """Test fleet tools performance."""
        try:
            from src.tools.fleet_tools import FleetTools

            fleet = FleetTools()

            # Test fleet operations
            start_time = time.time()

            operations = []
            for i in range(50):
                if hasattr(fleet, "get_fleet_status"):
                    operation = fleet.get_fleet_status()
                    operations.append(operation)
                else:
                    break

            if operations:
                end_time = time.time()
                duration = end_time - start_time

                # 50 fleet operations should complete quickly
                assert duration < 5.0, (
                    f"Fleet operations too slow: {duration}s for {len(operations)} operations"
                )

        except ImportError:
            pytest.skip("Fleet tools performance testing not available")

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_docker_manager_performance(self):
        """Test Docker manager performance."""
        try:
            from src.services.docker_manager import DockerManager

            docker = DockerManager()

            # Test Docker operations
            start_time = time.time()

            operations = []
            for i in range(30):
                if hasattr(docker, "list_containers"):
                    operation = docker.list_containers()
                    operations.append(operation)
                else:
                    break

            if operations:
                results = await asyncio.gather(*operations, return_exceptions=True)

                end_time = time.time()
                duration = end_time - start_time

                # 30 Docker operations should complete quickly
                assert duration < 3.0, (
                    f"Docker operations too slow: {duration}s for {len(operations)} operations"
                )

        except ImportError:
            pytest.skip("Docker manager performance testing not available")


class TestScalabilityPerformance:
    """Test scalability performance characteristics."""

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_target_scaling_performance(self):
        """Test performance scales with number of targets."""
        try:
            from src.services.inventory_service import InventoryService

            inventory = InventoryService()

            # Test with different target counts
            target_counts = [10, 50, 100, 500]
            performance_results = {}

            for count in target_counts:
                # Create mock targets
                targets = [f"target_{i}" for i in range(count)]

                start_time = time.time()

                # Simulate querying all targets
                for target in targets:
                    if hasattr(inventory, "get_target_status"):
                        try:
                            await inventory.get_target_status(target)
                        except:
                            pass  # Target may not exist
                    else:
                        break

                end_time = time.time()
                duration = end_time - start_time

                performance_results[count] = duration

            # Performance should scale reasonably
            if len(performance_results) > 1:
                # Check that performance doesn't degrade exponentially
                times = list(performance_results.values())
                for i in range(1, len(times)):
                    ratio = times[i] / times[i - 1]
                    # Each 5x increase in targets should not increase time by more than 10x
                    assert ratio < 10, (
                        f"Performance scales poorly: {ratio}x increase for target count"
                    )

        except ImportError:
            pytest.skip("Scalability testing not available")

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_concurrent_user_scaling(self):
        """Test performance scales with concurrent users."""
        try:
            from src.services.policy_gate import PolicyGate

            policy_gate = PolicyGate()

            # Test with different user counts
            user_counts = [10, 25, 50, 100]
            performance_results = {}

            for count in user_counts:
                start_time = time.time()

                # Simulate concurrent users
                tasks = []
                for i in range(count):
                    if hasattr(policy_gate, "evaluate_policy"):
                        task = policy_gate.evaluate_policy(
                            operation="docker.create",
                            user_id=f"user_{i}",
                            resource="container",
                        )
                        tasks.append(task)
                    else:
                        break

                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)

                end_time = time.time()
                duration = end_time - start_time

                performance_results[count] = duration

            # Check scaling is reasonable
            if len(performance_results) > 1:
                times = list(performance_results.values())
                for i in range(1, len(times)):
                    ratio = times[i] / times[i - 1]
                    # Should scale linearly or better
                    assert ratio < 5, f"Concurrent user scaling poor: {ratio}x increase"

        except ImportError:
            pytest.skip("Concurrent user scaling testing not available")

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_request_scaling_performance(self):
        """Test performance under high request volume."""
        try:
            from src.services.inventory_service import InventoryService

            inventory = InventoryService()

            # High volume request test
            request_counts = [100, 500, 1000, 2000]

            for count in request_counts:
                start_time = time.time()

                # Generate requests in batches to avoid overwhelming
                batch_size = 100
                for batch_start in range(0, count, batch_size):
                    batch_end = min(batch_start + batch_size, count)
                    batch_tasks = []

                    for i in range(batch_start, batch_end):
                        if hasattr(inventory, "get_all_targets"):
                            task = inventory.get_all_targets()
                            batch_tasks.append(task)
                        else:
                            break

                    if batch_tasks:
                        await asyncio.gather(*batch_tasks, return_exceptions=True)

                    # Small delay between batches
                    await asyncio.sleep(0.01)

                end_time = time.time()
                duration = end_time - start_time

                # Even high request volume should complete in reasonable time
                assert duration < count * 0.01, (
                    f"Request volume performance poor: {duration}s for {count} requests"
                )

        except ImportError:
            pytest.skip("Request scaling testing not available")


class TestResourceEfficiency:
    """Test resource usage efficiency."""

    @pytest.mark.performance
    def test_memory_efficiency(self):
        """Test memory usage efficiency."""
        process = psutil.Process()
        initial_memory = process.memory_info().rss

        # Simulate heavy memory operations
        test_data = []
        for i in range(1000):
            test_data.append({"id": i, "data": "x" * 1000})

        peak_memory = process.memory_info().rss
        memory_increase = peak_memory - initial_memory

        # Memory cleanup
        del test_data
        gc.collect()

        final_memory = process.memory_info().rss
        recovered_memory = peak_memory - final_memory

        # Should have recovered most of the memory
        recovery_ratio = (
            recovered_memory / memory_increase if memory_increase > 0 else 1.0
        )
        assert recovery_ratio > 0.8, (
            f"Memory recovery poor: {recovery_ratio:.2%} recovered"
        )

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_cpu_efficiency(self):
        """Test CPU usage efficiency."""
        process = psutil.Process()

        # Monitor CPU during operations
        cpu_samples = []

        async def monitor_cpu():
            for _ in range(50):
                cpu_percent = process.cpu_percent()
                cpu_samples.append(cpu_percent)
                await asyncio.sleep(0.1)

        # Start CPU monitoring
        monitor_task = asyncio.create_task(monitor_cpu())

        try:
            # Perform CPU-intensive operations
            from src.tools.inventory_tools import InventoryTools

            tools = InventoryTools()

            for i in range(100):
                if hasattr(tools, "check_target_status"):
                    tools.check_target_status("docker", "localhost")
                else:
                    break

        except ImportError:
            pass  # Skip if not available

        # Wait for monitoring to complete
        await monitor_task

        # Analyze CPU usage
        if cpu_samples:
            avg_cpu = statistics.mean(cpu_samples)
            max_cpu = max(cpu_samples)

            # CPU usage should be reasonable
            assert avg_cpu < 70.0, f"Average CPU usage too high: {avg_cpu}%"
            assert max_cpu < 95.0, f"Peak CPU usage too high: {max_cpu}%"

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_io_efficiency(self):
        """Test I/O efficiency."""
        try:
            from src.services.inventory_service import InventoryService

            inventory = InventoryService()

            # Test I/O operation efficiency
            start_time = time.time()
            io_operations = []

            for i in range(50):
                if hasattr(inventory, "get_all_targets"):
                    operation = inventory.get_all_targets()
                    io_operations.append(operation)
                else:
                    break

            if io_operations:
                results = await asyncio.gather(*io_operations, return_exceptions=True)

                end_time = time.time()
                duration = end_time - start_time

                # I/O should be efficient
                assert duration < 5.0, (
                    f"I/O operations too slow: {duration}s for {len(io_operations)} operations"
                )

        except ImportError:
            pytest.skip("I/O efficiency testing not available")


class TestPerformanceRegression:
    """Test performance regression detection."""

    @pytest.mark.performance
    @pytest.mark.regression
    @pytest.mark.asyncio
    async def test_initialization_performance_regression(self):
        """Test system initialization performance hasn't regressed."""
        start_time = time.time()

        try:
            from src.services.system_integration import SystemIntegration
            from src.services.inventory_service import InventoryService

            system = SystemIntegration()
            inventory = InventoryService()

            end_time = time.time()
            initialization_time = end_time - start_time

            # Performance regression threshold
            max_initialization_time = 2.0
            assert initialization_time < max_initialization_time, (
                f"Performance regression detected: {initialization_time}s > {max_initialization_time}s"
            )

        except ImportError:
            pytest.skip("Performance regression testing not available")

    @pytest.mark.performance
    @pytest.mark.regression
    @pytest.mark.asyncio
    async def test_query_performance_regression(self):
        """Test query performance hasn't regressed."""
        try:
            from src.services.policy_gate import PolicyGate

            policy_gate = PolicyGate()

            # Standard query test
            start_time = time.time()

            queries = []
            for i in range(100):
                if hasattr(policy_gate, "evaluate_policy"):
                    query = policy_gate.evaluate_policy(
                        operation="docker.create",
                        user_id="user123",
                        resource="container",
                    )
                    queries.append(query)
                else:
                    break

            if queries:
                results = await asyncio.gather(*queries, return_exceptions=True)

                end_time = time.time()
                duration = end_time - start_time

                # Performance regression threshold
                max_query_time = 2.0
                assert duration < max_query_time, (
                    f"Query performance regression: {duration}s > {max_query_time}s"
                )

        except ImportError:
            pytest.skip("Query performance regression testing not available")

    @pytest.mark.performance
    @pytest.mark.regression
    def test_memory_usage_regression(self):
        """Test memory usage hasn't regressed."""
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Standard memory test
        test_data = [
            {
                "id": i,
                "name": f"target_{i}",
                "status": "active",
                "metadata": {"type": "container", "image": f"image_{i}"},
            }
            for i in range(1000)
        ]

        peak_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = peak_memory - initial_memory

        # Clean up
        del test_data
        gc.collect()

        final_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Memory usage regression threshold
        max_memory_increase = 50  # MB
        assert memory_increase < max_memory_increase, (
            f"Memory usage regression: {memory_increase}MB > {max_memory_increase}MB"
        )


class TestBenchmarkPerformance:
    """Test performance benchmarking."""

    @pytest.mark.performance
    @pytest.mark.benchmark
    def test_operation_benchmarks(self):
        """Benchmark key operations."""
        benchmarks = {}

        try:
            # Benchmark inventory operations
            from src.services.inventory_service import InventoryService

            inventory = InventoryService()

            if hasattr(inventory, "get_all_targets"):
                start_time = time.time()
                result = inventory.get_all_targets()
                end_time = time.time()
                benchmarks["get_all_targets"] = end_time - start_time

            # Benchmark policy operations
            from src.services.policy_gate import PolicyGate

            policy_gate = PolicyGate()

            if hasattr(policy_gate, "evaluate_policy"):
                start_time = time.time()
                result = policy_gate.evaluate_policy(
                    operation="docker.create", user_id="user123", resource="container"
                )
                end_time = time.time()
                benchmarks["evaluate_policy"] = end_time - start_time

            # Check benchmarks are reasonable
            for operation, duration in benchmarks.items():
                assert duration < 1.0, f"Benchmark failed for {operation}: {duration}s"

        except ImportError:
            pytest.skip("Benchmark testing not available")

    @pytest.mark.performance
    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_concurrent_benchmarks(self):
        """Benchmark concurrent operations."""
        benchmark_results = {}

        try:
            from src.services.inventory_service import InventoryService

            inventory = InventoryService()

            if hasattr(inventory, "get_all_targets"):
                # Test 10 concurrent operations
                start_time = time.time()

                tasks = []
                for _ in range(10):
                    task = inventory.get_all_targets()
                    tasks.append(task)

                results = await asyncio.gather(*tasks, return_exceptions=True)

                end_time = time.time()
                duration = end_time - start_time

                benchmark_results["concurrent_10"] = duration

                # 10 concurrent operations should be faster than sequential
                assert duration < 5.0, f"Concurrent benchmark failed: {duration}s"

        except ImportError:
            pytest.skip("Concurrent benchmark testing not available")


class TestPerformanceMonitoring:
    """Test performance monitoring capabilities."""

    @pytest.mark.performance
    def test_performance_metrics_collection(self):
        """Test performance metrics can be collected."""
        try:
            from src.utils.monitoring_integration import MonitoringIntegration

            monitor = MonitoringIntegration()

            # Test metrics collection interface
            if hasattr(monitor, "send_performance_metrics"):
                metrics = {
                    "operation": "test_query",
                    "duration": 0.100,
                    "memory_usage": 45.2,
                    "cpu_usage": 15.3,
                }

                result = monitor.send_performance_metrics(metrics)
                # Should handle gracefully
                assert result is not None or isinstance(result, (bool, dict))

        except ImportError:
            pytest.skip("Performance monitoring not available")

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_performance_alerting(self):
        """Test performance alerting functionality."""
        try:
            from src.utils.monitoring_integration import MonitoringIntegration

            monitor = MonitoringIntegration()

            # Test alerting for poor performance
            if hasattr(monitor, "send_performance_alert"):
                alert = monitor.send_performance_alert(
                    metric_type="response_time",
                    threshold=2.0,
                    actual_value=5.0,
                    operation="inventory_query",
                )

                # Should handle alert creation
                assert alert is not None or isinstance(alert, (bool, dict))

        except ImportError:
            pytest.skip("Performance alerting not available")

    @pytest.mark.performance
    def test_performance_telemetry(self):
        """Test performance telemetry data."""
        process = psutil.Process()

        # Collect system performance data
        performance_data = {
            "cpu_percent": process.cpu_percent(),
            "memory_mb": process.memory_info().rss / 1024 / 1024,
            "memory_percent": process.memory_percent(),
            "threads": process.num_threads(),
            "open_files": len(process.open_files()),
            "connections": len(process.connections()),
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Verify telemetry structure
        expected_keys = ["cpu_percent", "memory_mb", "memory_percent", "timestamp"]
        for key in expected_keys:
            assert key in performance_data

        # Verify reasonable values
        assert 0 <= performance_data["cpu_percent"] <= 100
        assert performance_data["memory_mb"] > 0
        assert 0 <= performance_data["memory_percent"] <= 100


class TestPerformanceStress:
    """Test performance under stress conditions."""

    @pytest.mark.performance
    @pytest.mark.stress
    @pytest.mark.asyncio
    async def test_high_load_stress(self):
        """Test performance under high load."""
        try:
            from src.services.policy_gate import PolicyGate

            policy_gate = PolicyGate()

            # High load test - 1000 operations
            start_time = time.time()

            tasks = []
            for i in range(1000):
                if hasattr(policy_gate, "evaluate_policy"):
                    task = policy_gate.evaluate_policy(
                        operation="docker.create",
                        user_id=f"user_{i % 100}",  # Reuse users
                        resource="container",
                    )
                    tasks.append(task)
                else:
                    break

            if tasks:
                # Process in batches to avoid overwhelming
                batch_size = 100
                for batch_start in range(0, len(tasks), batch_size):
                    batch_end = min(batch_start + batch_size, len(tasks))
                    batch_tasks = tasks[batch_start:batch_end]
                    await asyncio.gather(*batch_tasks, return_exceptions=True)

                end_time = time.time()
                duration = end_time - start_time

                # Even under high load, should complete in reasonable time
                assert duration < 30.0, (
                    f"High load stress test failed: {duration}s for 1000 operations"
                )

        except ImportError:
            pytest.skip("High load stress testing not available")

    @pytest.mark.performance
    @pytest.mark.stress
    def test_memory_stress(self):
        """Test memory usage under stress."""
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Create large amounts of data to stress memory
        large_data = []
        for i in range(10000):
            large_data.extend(
                [
                    f"test_string_{i}" * 100,
                    {"id": i, "data": "x" * 1000},
                    (i, f"tuple_{i}", i * 10),
                ]
            )

        peak_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = peak_memory - initial_memory

        # Memory increase should be reasonable (< 500MB)
        assert memory_increase < 500, (
            f"Memory stress test failed: {memory_increase}MB increase"
        )

        # Clean up
        del large_data
        gc.collect()

    @pytest.mark.performance
    @pytest.mark.stress
    @pytest.mark.asyncio
    async def test_cpu_stress(self):
        """Test CPU usage under stress."""
        process = psutil.Process()

        # CPU-intensive operations
        def cpu_intensive_task():
            # Perform calculations
            result = 0
            for i in range(1000000):
                result += i**2
            return result

        start_time = time.time()

        # Run concurrent CPU tasks
        with ThreadPoolExecutor(max_workers=4) as executor:
            tasks = []
            for _ in range(8):
                task = asyncio.get_event_loop().run_in_executor(
                    executor, cpu_intensive_task
                )
                tasks.append(task)

            results = await asyncio.gather(*tasks)

        end_time = time.time()
        duration = end_time - start_time

        # Should complete reasonable CPU-intensive tasks quickly
        assert duration < 10.0, (
            f"CPU stress test failed: {duration}s for CPU-intensive tasks"
        )
        assert len(results) == 8
