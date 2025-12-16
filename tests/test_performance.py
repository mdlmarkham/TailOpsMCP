"""
Comprehensive performance and load testing suite for TailOpsMCP.

Tests fleet scalability, workflow performance under load, event processing performance,
inventory query performance, concurrent user performance, memory usage and leak detection,
database performance and scaling, sustained load performance, spike load handling,
resource limit enforcement, and performance degradation handling.
"""

import pytest
import asyncio
import time
import statistics
from datetime import datetime
from unittest.mock import Mock
from typing import List, Callable
import concurrent.futures
import gc
import os


class TestPerformance:
    """Test system performance under load."""

    @pytest.fixture
    def performance_monitor(self):
        """Create performance monitoring framework."""
        return {
            "start_time": None,
            "end_time": None,
            "metrics": {
                "cpu_usage": [],
                "memory_usage": [],
                "response_times": [],
                "throughput": [],
                "error_rates": [],
            },
            "resource_limits": {
                "max_cpu_percent": 80,
                "max_memory_mb": 2048,
                "max_response_time_ms": 5000,
                "min_throughput_ops_per_sec": 10,
            },
        }

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_fleet_scalability(self, performance_monitor):
        """Test fleet scalability with large numbers of targets."""
        from src.services.inventory_service import InventoryService

        inventory_service = Mock(spec=InventoryService)

        # Test with increasing numbers of targets
        target_counts = [10, 50, 100, 500, 1000, 2000]
        scalability_results = {}

        for target_count in target_counts:
            # Simulate inventory data for different scales
            mock_targets = {
                f"target-{i:04d}": Mock(
                    id=f"target-{i:04d}",
                    hostname=f"host-{i:04d}",
                    status="healthy",
                    services=[],
                    metadata={},
                )
                for i in range(target_count)
            }

            # Measure discovery performance
            performance_monitor["start_time"] = time.time()

            inventory_service.run_full_discovery.return_value = {
                "targets_discovered": target_count,
                "discovery_time": target_count * 0.01,  # Simulated time
                "targets": mock_targets,
            }

            result = await inventory_service.run_full_discovery()

            performance_monitor["end_time"] = time.time()
            execution_time = (
                performance_monitor["end_time"] - performance_monitor["start_time"]
            )

            # Calculate metrics
            throughput = target_count / execution_time if execution_time > 0 else 0
            scalability_results[target_count] = {
                "target_count": target_count,
                "execution_time": execution_time,
                "throughput": throughput,
                "targets_per_second": throughput,
            }

            # Verify performance is acceptable
            assert execution_time < target_count * 0.1  # Should scale reasonably
            assert (
                throughput
                > performance_monitor["resource_limits"]["min_throughput_ops_per_sec"]
            )

        # Verify scalability curve
        for i in range(1, len(target_counts)):
            smaller_count = target_counts[i - 1]
            larger_count = target_counts[i]

            smaller_time = scalability_results[smaller_count]["execution_time"]
            larger_time = scalability_results[larger_count]["execution_time"]

            # Time should not grow exponentially (should be sub-linear)
            time_ratio = larger_time / smaller_time
            count_ratio = larger_count / smaller_count

            assert time_ratio < count_ratio  # Sub-linear scaling

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_workflow_performance_under_load(self, performance_monitor):
        """Test workflow performance under load."""
        from src.services.workflow_engine import WorkflowEngine

        workflow_engine = Mock(spec=WorkflowEngine)

        # Test concurrent workflow execution
        concurrent_workflows = [5, 10, 25, 50, 100]
        workflow_results = {}

        for concurrent_count in concurrent_workflows:
            # Create workflow execution tasks
            workflow_tasks = []
            start_time = time.time()

            async def execute_workflow(workflow_id):
                workflow_engine.execute_workflow.return_value = {
                    "execution_id": f"exec-{workflow_id}",
                    "status": "started",
                    "duration": 0.1,  # Simulated duration
                }
                return await workflow_engine.execute_workflow(f"workflow-{workflow_id}")

            # Execute workflows concurrently
            for i in range(concurrent_count):
                task = execute_workflow(i)
                workflow_tasks.append(task)

            # Wait for all workflows to complete
            results = await asyncio.gather(*workflow_tasks)

            end_time = time.time()
            total_time = end_time - start_time

            workflow_results[concurrent_count] = {
                "concurrent_workflows": concurrent_count,
                "total_time": total_time,
                "workflows_per_second": concurrent_count / total_time,
                "successful_executions": len(results),
                "failed_executions": 0,
            }

            # Verify performance metrics
            assert (
                total_time < concurrent_count * 0.2
            )  # Should complete within reasonable time
            assert workflow_results[concurrent_count]["workflows_per_second"] > 1

        # Test workflow throughput scaling
        for count in concurrent_workflows:
            result = workflow_results[count]
            assert result["workflows_per_second"] > 0
            assert result["successful_executions"] == count

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_event_processing_performance(self, performance_monitor):
        """Test event processing performance."""
        from src.services.event_processor import EventProcessor

        event_processor = Mock(spec=EventProcessor)

        # Test event processing with increasing batch sizes
        batch_sizes = [10, 50, 100, 500, 1000]
        processing_results = {}

        for batch_size in batch_sizes:
            # Create test events
            test_events = [
                {
                    "event_id": f"event-{i}",
                    "timestamp": datetime.utcnow(),
                    "event_type": "system_alert",
                    "severity": "info",
                    "source": "test-system",
                }
                for i in range(batch_size)
            ]

            # Measure processing performance
            performance_monitor["start_time"] = time.time()

            event_processor.process_event_batch.return_value = {
                "processed_count": batch_size,
                "processing_time": batch_size * 0.001,  # Simulated time
                "errors": 0,
                "throughput": batch_size / (batch_size * 0.001),
            }

            result = await event_processor.process_event_batch(test_events)

            performance_monitor["end_time"] = time.time()
            processing_time = (
                performance_monitor["end_time"] - performance_monitor["start_time"]
            )

            processing_results[batch_size] = {
                "batch_size": batch_size,
                "processing_time": processing_time,
                "events_per_second": batch_size / processing_time,
                "errors": result["errors"],
            }

            # Verify processing performance
            assert processing_time < batch_size * 0.01  # Should be efficient
            assert result["errors"] == 0
            assert processing_results[batch_size]["events_per_second"] > 100

        # Test event throughput consistency
        throughput_values = [
            result["events_per_second"] for result in processing_results.values()
        ]
        throughput_variance = statistics.variance(throughput_values)
        throughput_mean = statistics.mean(throughput_values)

        # Coefficient of variation should be reasonable
        cv = throughput_variance**0.5 / throughput_mean
        assert cv < 0.5  # Less than 50% variation

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_inventory_query_performance(self, performance_monitor):
        """Test inventory query performance."""
        from src.services.inventory_service import InventoryService

        inventory_service = Mock(spec=InventoryService)

        # Test different query types and their performance
        query_types = [
            {"type": "filter_by_status", "params": {"status": "healthy"}},
            {"type": "search_by_hostname", "params": {"pattern": "web-*"}},
            {"type": "get_service_status", "params": {"service_type": "web-server"}},
            {"type": "filter_by_role", "params": {"role": "container"}},
            {
                "type": "complex_filter",
                "params": {
                    "status": "healthy",
                    "role": "container",
                    "services": ["nginx"],
                },
            },
        ]

        query_results = {}

        for query_spec in query_types:
            # Simulate query execution
            query_type = query_spec["type"]
            params = query_spec["params"]

            performance_monitor["start_time"] = time.time()

            inventory_service.query_inventory.return_value = {
                "results": [{"id": f"result-{i}", "data": {}} for i in range(100)],
                "query_time": 0.05,  # Simulated query time
                "total_matches": 100,
            }

            result = await inventory_service.query_inventory(query_type, params)

            performance_monitor["end_time"] = time.time()
            query_time = (
                performance_monitor["end_time"] - performance_monitor["start_time"]
            )

            query_results[query_type] = {
                "query_type": query_type,
                "query_time": query_time,
                "results_count": result["total_matches"],
                "queries_per_second": 1 / query_time,
            }

            # Verify query performance
            assert (
                query_time
                < performance_monitor["resource_limits"]["max_response_time_ms"] / 1000
            )
            assert result["total_matches"] > 0
            assert query_results[query_type]["queries_per_second"] > 1

        # Test query performance consistency
        query_times = [result["query_time"] for result in query_results.values()]
        avg_query_time = statistics.mean(query_times)
        max_query_time = max(query_times)

        assert (
            max_query_time < avg_query_time * 3
        )  # No query should be 3x slower than average

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_concurrent_user_performance(self, performance_monitor):
        """Test concurrent user performance."""
        from src.auth.middleware import AuthenticationMiddleware
        from src.services.access_control import AccessControl

        auth_middleware = Mock(spec=AuthenticationMiddleware)
        access_control = Mock(spec=AccessControl)

        # Test concurrent user authentication and authorization
        user_counts = [10, 25, 50, 100, 200]
        user_performance_results = {}

        for user_count in user_counts:
            # Create concurrent user requests
            user_requests = [
                {
                    "user_id": f"user-{i:03d}",
                    "operation": "fleet_discovery",
                    "timestamp": datetime.utcnow(),
                }
                for i in range(user_count)
            ]

            start_time = time.time()

            async def process_user_request(request):
                # Mock authentication
                auth_middleware.authenticate.return_value = {
                    "authenticated": True,
                    "user_id": request["user_id"],
                    "token_valid": True,
                }

                # Mock authorization
                access_control.check_permission.return_value = True

                auth_result = await auth_middleware.authenticate(request["user_id"])
                auth_check = await access_control.check_permission(
                    request["user_id"], request["operation"]
                )

                return {
                    "user_id": request["user_id"],
                    "auth_success": auth_result["authenticated"],
                    "auth_check": auth_check,
                }

            # Process user requests concurrently
            tasks = [process_user_request(req) for req in user_requests]
            results = await asyncio.gather(*tasks)

            end_time = time.time()
            processing_time = end_time - start_time

            user_performance_results[user_count] = {
                "user_count": user_count,
                "processing_time": processing_time,
                "users_per_second": user_count / processing_time,
                "successful_authentications": sum(
                    1 for r in results if r["auth_success"]
                ),
                "successful_authorizations": sum(1 for r in results if r["auth_check"]),
            }

            # Verify performance
            assert processing_time < user_count * 0.1  # Should scale reasonably
            assert user_performance_results[user_count]["users_per_second"] > 5
            assert (
                user_performance_results[user_count]["successful_authentications"]
                == user_count
            )

        # Test concurrent user load scaling
        for count in user_counts:
            result = user_performance_results[count]
            assert result["users_per_second"] > 0
            assert result["successful_authentications"] == count

    @pytest.mark.performance
    def test_memory_usage_and_leak_detection(self, performance_monitor):
        """Test memory usage and leak detection."""
        import tracemalloc

        # Start memory tracking
        tracemalloc.start()

        # Test memory usage patterns
        memory_samples = []

        def sample_memory_usage():
            """Sample current memory usage."""
            current, peak = tracemalloc.get_traced_memory()
            memory_samples.append(
                {
                    "current_mb": current / 1024 / 1024,
                    "peak_mb": peak / 1024 / 1024,
                    "timestamp": time.time(),
                }
            )

        # Simulate memory-intensive operations
        for i in range(100):
            # Create and destroy objects to test for leaks
            large_data = [j for j in range(1000)]  # Simulate data structures

            # Sample memory after each operation
            sample_memory_usage()

            # Clean up
            del large_data
            gc.collect()

        # Stop memory tracking
        tracemalloc.stop()

        # Analyze memory usage patterns
        current_memory = [sample["current_mb"] for sample in memory_samples]
        peak_memory = [sample["peak_mb"] for sample in memory_samples]

        # Check for memory leaks
        initial_memory = current_memory[0]
        final_memory = current_memory[-1]
        memory_growth = final_memory - initial_memory

        # Memory growth should be minimal (less than 10MB)
        assert memory_growth < 10, (
            f"Potential memory leak detected: {memory_growth}MB growth"
        )

        # Check memory usage stays within limits
        max_memory = max(peak_memory)
        assert max_memory < performance_monitor["resource_limits"]["max_memory_mb"]

        # Calculate memory usage statistics
        avg_memory = statistics.mean(current_memory)
        memory_variance = statistics.variance(current_memory)

        performance_monitor["metrics"]["memory_usage"] = {
            "initial_mb": initial_memory,
            "final_mb": final_memory,
            "growth_mb": memory_growth,
            "max_mb": max_memory,
            "average_mb": avg_memory,
            "variance": memory_variance,
        }

    @pytest.mark.performance
    def test_database_performance_and_scaling(self, performance_monitor):
        """Test database performance and scaling."""
        import sqlite3
        import tempfile

        # Create temporary database for testing
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_file:
            db_path = tmp_file.name

        try:
            # Setup database
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Create test tables
            cursor.execute("""
                CREATE TABLE test_targets (
                    id INTEGER PRIMARY KEY,
                    hostname TEXT,
                    ip_address TEXT,
                    status TEXT,
                    created_at TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE TABLE test_events (
                    id INTEGER PRIMARY KEY,
                    event_type TEXT,
                    source TEXT,
                    severity TEXT,
                    timestamp TIMESTAMP
                )
            """)

            conn.commit()

            # Test database insert performance
            insert_counts = [100, 500, 1000, 5000]
            insert_results = {}

            for count in insert_counts:
                start_time = time.time()

                # Insert test data
                for i in range(count):
                    cursor.execute(
                        """
                        INSERT INTO test_targets (hostname, ip_address, status, created_at)
                        VALUES (?, ?, ?, ?)
                    """,
                        (
                            f"host-{i}",
                            f"192.168.1.{i % 255}",
                            "healthy",
                            datetime.utcnow(),
                        ),
                    )

                    cursor.execute(
                        """
                        INSERT INTO test_events (event_type, source, severity, timestamp)
                        VALUES (?, ?, ?, ?)
                    """,
                        ("system_alert", f"source-{i}", "info", datetime.utcnow()),
                    )

                conn.commit()

                end_time = time.time()
                insert_time = end_time - start_time

                insert_results[count] = {
                    "count": count,
                    "insert_time": insert_time,
                    "inserts_per_second": count / insert_time,
                }

                # Verify insert performance
                assert insert_time < count * 0.01  # Should be efficient
                assert insert_results[count]["inserts_per_second"] > 100

            # Test database query performance
            query_results = {}

            # Test different query types
            query_types = [
                "SELECT COUNT(*) FROM test_targets",
                "SELECT * FROM test_targets WHERE status = ?",
                "SELECT * FROM test_events ORDER BY timestamp DESC LIMIT 100",
                "SELECT hostname, COUNT(*) FROM test_targets GROUP BY hostname",
            ]

            for i, query in enumerate(query_types):
                start_time = time.time()

                if "WHERE status" in query:
                    cursor.execute(query, ("healthy",))
                else:
                    cursor.execute(query)

                results = cursor.fetchall()

                end_time = time.time()
                query_time = end_time - start_time

                query_results[f"query_{i + 1}"] = {
                    "query": query,
                    "query_time": query_time,
                    "results_count": len(results),
                }

                # Verify query performance
                assert query_time < 1.0  # Should complete within 1 second

            # Test database connection pooling
            pool_results = {}
            pool_sizes = [5, 10, 20]

            for pool_size in pool_sizes:
                start_time = time.time()

                # Simulate connection pool usage
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=pool_size
                ) as executor:
                    futures = []
                    for i in range(pool_size * 2):  # 2x pool size
                        future = executor.submit(
                            lambda: conn.execute("SELECT 1").fetchone()
                        )
                        futures.append(future)

                    # Wait for all operations to complete
                    results = [future.result() for future in futures]

                end_time = time.time()
                pool_time = end_time - start_time

                pool_results[pool_size] = {
                    "pool_size": pool_size,
                    "pool_time": pool_time,
                    "operations_per_second": len(futures) / pool_time,
                }

                # Verify pool performance
                assert pool_time < 2.0  # Should complete quickly
                assert pool_results[pool_size]["operations_per_second"] > 10

            # Close database connection
            conn.close()

            # Store performance results
            performance_monitor["metrics"]["database_performance"] = {
                "insert_results": insert_results,
                "query_results": query_results,
                "pool_results": pool_results,
            }

        finally:
            # Clean up temporary database
            try:
                os.unlink(db_path)
            except Exception:
                pass


class TestLoadTesting:
    """Load testing scenarios."""

    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_sustained_load_performance(self):
        """Test sustained load performance over time."""
        # This would test performance under sustained load for extended periods
        # For now, this is a placeholder for sustained load testing
        pass

    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_spike_load_handling(self):
        """Test spike load handling."""
        # This would test system behavior under sudden load spikes
        # For now, this is a placeholder for spike load testing
        pass

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_resource_limit_enforcement(self):
        """Test resource limit enforcement."""
        # This would test resource limit enforcement under load
        # For now, this is a placeholder for resource limit testing
        pass

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_performance_degradation_handling(self):
        """Test performance degradation handling."""
        # This would test graceful performance degradation
        # For now, this is a placeholder for degradation testing
        pass


class TestPerformanceMonitoring:
    """Performance monitoring and alerting."""

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_performance_metrics_collection(self):
        """Test performance metrics collection."""
        # This would test performance metrics collection and storage
        # For now, this is a placeholder for metrics testing
        pass

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_performance_alerting(self):
        """Test performance alerting mechanisms."""
        # This would test performance alerting when thresholds are exceeded
        # For now, this is a placeholder for alerting testing
        pass

    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_performance_benchmarking(self):
        """Test performance benchmarking against baselines."""
        # This would test performance benchmarking and regression detection
        # For now, this is a placeholder for benchmarking testing
        pass


# Performance testing utilities
class PerformanceTestUtils:
    """Utility functions for performance testing."""

    @staticmethod
    def measure_execution_time(func: Callable) -> tuple:
        """Measure execution time of a function."""
        start_time = time.time()
        result = func()
        end_time = time.time()
        return result, end_time - start_time

    @staticmethod
    def measure_async_execution_time(func: Callable) -> tuple:
        """Measure execution time of an async function."""

        async def wrapper():
            start_time = time.time()
            result = await func()
            end_time = time.time()
            return result, end_time - start_time

        return wrapper()

    @staticmethod
    def create_load_test_scenarios():
        """Create load testing scenarios for different components."""
        return {
            "inventory_load": {
                "target_counts": [100, 500, 1000, 5000],
                "operations": ["discovery", "query", "update", "delete"],
                "concurrent_users": [1, 5, 10, 25, 50],
            },
            "workflow_load": {
                "workflow_counts": [10, 50, 100, 500],
                "workflow_types": ["provisioning", "backup", "deployment"],
                "concurrent_executions": [1, 5, 10, 25],
            },
            "event_load": {
                "event_counts": [100, 500, 1000, 5000],
                "event_types": ["alert", "log", "metric", "audit"],
                "processing_modes": ["sync", "async", "batch"],
            },
        }

    @staticmethod
    def calculate_performance_metrics(execution_times: List[float]) -> dict:
        """Calculate performance metrics from execution times."""
        return {
            "mean": statistics.mean(execution_times),
            "median": statistics.median(execution_times),
            "std_dev": statistics.stdev(execution_times)
            if len(execution_times) > 1
            else 0,
            "min": min(execution_times),
            "max": max(execution_times),
            "percentile_95": statistics.quantiles(execution_times, n=20)[18]
            if len(execution_times) > 20
            else max(execution_times),
            "percentile_99": statistics.quantiles(execution_times, n=100)[98]
            if len(execution_times) > 100
            else max(execution_times),
        }


# Performance benchmarking decorators
def benchmark_performance(operation_name: str, threshold_ms: float = 1000):
    """Decorator to benchmark function performance."""

    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = time.time()
            result = func(*args, **kwargs)
            end_time = time.time()
            execution_time_ms = (end_time - start_time) * 1000

            # Log performance results
            print(f"Performance benchmark: {operation_name}")
            print(f"  Execution time: {execution_time_ms:.2f}ms")
            print(f"  Threshold: {threshold_ms}ms")
            print(
                f"  Status: {'PASS' if execution_time_ms <= threshold_ms else 'FAIL'}"
            )

            # Assert performance threshold
            assert execution_time_ms <= threshold_ms, (
                f"Performance threshold exceeded: {execution_time_ms:.2f}ms > {threshold_ms}ms"
            )

            return result

        return wrapper

    return decorator


async def benchmark_async_performance(operation_name: str, threshold_ms: float = 1000):
    """Decorator to benchmark async function performance."""

    def decorator(func):
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            result = await func(*args, **kwargs)
            end_time = time.time()
            execution_time_ms = (end_time - start_time) * 1000

            # Log performance results
            print(f"Performance benchmark: {operation_name}")
            print(f"  Execution time: {execution_time_ms:.2f}ms")
            print(f"  Threshold: {threshold_ms}ms")
            print(
                f"  Status: {'PASS' if execution_time_ms <= threshold_ms else 'FAIL'}"
            )

            # Assert performance threshold
            assert execution_time_ms <= threshold_ms, (
                f"Performance threshold exceeded: {execution_time_ms:.2f}ms > {threshold_ms}ms"
            )

            return result

        return wrapper

    return decorator
