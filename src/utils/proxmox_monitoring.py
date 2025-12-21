"""
Proxmox Monitoring and Health Check Integration

Provides comprehensive monitoring and health check capabilities for Proxmox environments,
integrating with existing TailOpsMCP monitoring infrastructure including Prometheus,
Elasticsearch, and observability systems.
"""

import logging
import asyncio
import time
from datetime import datetime
from datetime import timezone, timezone
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, deque

from src.models.proxmox_models import ProxmoxAPICredentials
from src.services.proxmox_api import ProxmoxAPI
from src.utils.monitoring_integration import MonitoringIntegration

logger = logging.getLogger(__name__)


class HealthStatus(str, Enum):
    """Health check status levels."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class AlertSeverity(str, Enum):
    """Alert severity levels."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class HealthCheckResult:
    """Health check result data."""

    component: str
    status: HealthStatus
    message: str
    timestamp: str
    response_time_ms: float
    details: Dict[str, Any] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}
        if self.metadata is None:
            self.metadata = {}


@dataclass
class ProxmoxMetric:
    """Proxmox-specific metric data."""

    name: str
    value: Union[int, float, str]
    labels: Dict[str, str]
    timestamp: str
    metric_type: str = "gauge"  # gauge, counter, histogram
    help_text: str = ""

    def to_prometheus_format(self) -> str:
        """Convert metric to Prometheus format."""
        # Convert metric name to Prometheus format
        prom_name = self.name.replace(".", "_").replace("-", "_")

        # Add labels
        label_str = ""
        if self.labels:
            label_parts = [f'{k}="{v}"' for k, v in self.labels.items()]
            label_str = "{" + ",".join(label_parts) + "}"

        # Format metric line
        if self.metric_type == "counter":
            metric_line = f"{prom_name}_total{label_str} {self.value}"
        elif self.metric_type == "histogram":
            metric_line = f"{prom_name}{label_str} {self.value}"
        else:  # gauge
            metric_line = f"{prom_name}{label_str} {self.value}"

        # Add help and type as comments
        help_line = f"# HELP {prom_name} {self.help_text}" if self.help_text else ""
        type_line = f"# TYPE {prom_name} {self.metric_type}"

        lines = [type_line, help_line, metric_line]
        return "\n".join(line for line in lines if line)


@dataclass
class AlertRule:
    """Alert rule definition."""

    name: str
    condition: str  # Python expression to evaluate
    severity: AlertSeverity
    description: str
    enabled: bool = True
    labels: Dict[str, str] = None
    annotations: Dict[str, str] = None

    def __post_init__(self):
        if self.labels is None:
            self.labels = {}
        if self.annotations is None:
            self.annotations = {}


class ProxmoxHealthChecker:
    """Comprehensive health checker for Proxmox environments."""

    def __init__(self, api_credentials: List[ProxmoxAPICredentials]):
        """Initialize Proxmox health checker.

        Args:
            api_credentials: List of Proxmox API credentials
        """
        self.api_credentials = api_credentials
        self.health_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.last_check: Dict[str, datetime] = {}

        # Health check configuration
        self.check_interval = 60  # seconds
        self.timeout = 10  # seconds
        self.max_response_time = 5000  # milliseconds

        logger.info("Proxmox health checker initialized")

    async def check_host_health(self, host: str) -> HealthCheckResult:
        """Check health of a specific Proxmox host.

        Args:
            host: Proxmox host address

        Returns:
            HealthCheckResult with host health status
        """
        start_time = time.time()

        try:
            # Find API credentials for host
            credentials = None
            for creds in self.api_credentials:
                if creds.host == host:
                    credentials = creds
                    break

            if not credentials:
                return HealthCheckResult(
                    component=f"proxmox_host_{host}",
                    status=HealthStatus.UNKNOWN,
                    message=f"No API credentials found for host {host}",
                    timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                    response_time_ms=(time.time() - start_time) * 1000,
                )

            # Create API client and test connection
            async with ProxmoxAPI(credentials) as api_client:
                # Test API connection
                connection_result = await api_client.test_connection()

                if not connection_result.success:
                    return HealthCheckResult(
                        component=f"proxmox_host_{host}",
                        status=HealthStatus.UNHEALTHY,
                        message=f"API connection failed: {connection_result.message}",
                        timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                        response_time_ms=(time.time() - start_time) * 1000,
                        details={"connection_error": connection_result.message},
                    )

                # Get cluster information
                nodes = await api_client.list_nodes()
                if not nodes:
                    return HealthCheckResult(
                        component=f"proxmox_host_{host}",
                        status=HealthStatus.DEGRADED,
                        message="No nodes found in cluster",
                        timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                        response_time_ms=(time.time() - start_time) * 1000,
                    )

                # Check node health
                healthy_nodes = sum(1 for node in nodes if node.status == "online")
                total_nodes = len(nodes)

                # Get storage information
                storage_pools = await api_client.list_storage()

                # Determine overall health status
                response_time = (time.time() - start_time) * 1000

                if response_time > self.max_response_time:
                    status = HealthStatus.DEGRADED
                    message = f"Host responding slowly ({response_time:.0f}ms)"
                elif healthy_nodes == total_nodes:
                    status = HealthStatus.HEALTHY
                    message = f"All {total_nodes} nodes online"
                elif healthy_nodes > 0:
                    status = HealthStatus.DEGRADED
                    message = f"{healthy_nodes}/{total_nodes} nodes online"
                else:
                    status = HealthStatus.CRITICAL
                    message = "No nodes online"

                return HealthCheckResult(
                    component=f"proxmox_host_{host}",
                    status=status,
                    message=message,
                    timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                    response_time_ms=response_time,
                    details={
                        "total_nodes": total_nodes,
                        "healthy_nodes": healthy_nodes,
                        "storage_pools": len(storage_pools),
                        "version": connection_result.data.get("version")
                        if connection_result.data
                        else None,
                    },
                )

        except Exception as e:
            logger.error(f"Health check failed for {host}: {e}")
            return HealthCheckResult(
                component=f"proxmox_host_{host}",
                status=HealthStatus.CRITICAL,
                message=f"Health check failed: {str(e)}",
                timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                response_time_ms=(time.time() - start_time) * 1000,
                details={"error": str(e)},
            )

    async def check_container_health(self, host: str, vmid: int) -> HealthCheckResult:
        """Check health of a specific container.

        Args:
            host: Proxmox host address
            vmid: Container VMID

        Returns:
            HealthCheckResult with container health status
        """
        start_time = time.time()

        try:
            # Find API credentials for host
            credentials = None
            for creds in self.api_credentials:
                if creds.host == host:
                    credentials = creds
                    break

            if not credentials:
                return HealthCheckResult(
                    component=f"proxmox_container_{vmid}",
                    status=HealthStatus.UNKNOWN,
                    message=f"No API credentials found for host {host}",
                    timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                    response_time_ms=(time.time() - start_time) * 1000,
                )

            async with ProxmoxAPI(credentials) as api_client:
                # Get container status
                status_info = await api_client.get_container_status(vmid)

                if not status_info or status_info.get("status") == "not_found":
                    return HealthCheckResult(
                        component=f"proxmox_container_{vmid}",
                        status=HealthStatus.UNHEALTHY,
                        message="Container not found",
                        timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                        response_time_ms=(time.time() - start_time) * 1000,
                    )

                container_status = status_info.get("status", "unknown")
                response_time = (time.time() - start_time) * 1000

                # Determine health status based on container state
                if container_status == "running":
                    status = HealthStatus.HEALTHY
                    message = "Container is running"
                elif container_status == "stopped":
                    status = HealthStatus.DEGRADED
                    message = "Container is stopped"
                elif container_status == "error":
                    status = HealthStatus.CRITICAL
                    message = "Container is in error state"
                else:
                    status = HealthStatus.UNKNOWN
                    message = f"Container status: {container_status}"

                return HealthCheckResult(
                    component=f"proxmox_container_{vmid}",
                    status=status,
                    message=message,
                    timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                    response_time_ms=response_time,
                    details=status_info,
                )

        except Exception as e:
            logger.error(f"Container health check failed for {vmid}: {e}")
            return HealthCheckResult(
                component=f"proxmox_container_{vmid}",
                status=HealthStatus.CRITICAL,
                message=f"Health check failed: {str(e)}",
                timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                response_time_ms=(time.time() - start_time) * 1000,
                details={"error": str(e)},
            )

    async def check_all_hosts(self) -> Dict[str, HealthCheckResult]:
        """Check health of all configured Proxmox hosts.

        Returns:
            Dictionary mapping host addresses to health check results
        """
        results = {}

        # Create tasks for all hosts
        tasks = []
        for credentials in self.api_credentials:
            task = self.check_host_health(credentials.host)
            tasks.append(task)

        # Execute all health checks concurrently
        host_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for credentials, result in zip(self.api_credentials, host_results):
            if isinstance(result, Exception):
                logger.error(f"Health check exception for {credentials.host}: {result}")
                results[credentials.host] = HealthCheckResult(
                    component=f"proxmox_host_{credentials.host}",
                    status=HealthStatus.CRITICAL,
                    message=f"Health check exception: {str(result)}",
                    timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                    response_time_ms=0,
                    details={"exception": str(result)},
                )
            else:
                results[credentials.host] = result

                # Store in history
                self.health_history[credentials.host].append(result)
                self.last_check[credentials.host] = datetime.now(timezone.utc)

        return results

    def get_health_summary(self) -> Dict[str, Any]:
        """Get overall health summary.

        Returns:
            Dictionary with health summary statistics
        """
        total_hosts = len(self.api_credentials)
        if total_hosts == 0:
            return {
                "total_hosts": 0,
                "healthy_hosts": 0,
                "degraded_hosts": 0,
                "unhealthy_hosts": 0,
                "overall_status": HealthStatus.UNKNOWN,
            }

        # Count hosts by status
        status_counts = defaultdict(int)

        for host, history in self.health_history.items():
            if history:
                latest_result = history[-1]
                status_counts[latest_result.status] += 1
            else:
                status_counts[HealthStatus.UNKNOWN] += 1

        # Determine overall status
        if status_counts[HealthStatus.CRITICAL] > 0:
            overall_status = HealthStatus.CRITICAL
        elif status_counts[HealthStatus.UNHEALTHY] > 0:
            overall_status = HealthStatus.UNHEALTHY
        elif status_counts[HealthStatus.DEGRADED] > 0:
            overall_status = HealthStatus.DEGRADED
        elif status_counts[HealthStatus.HEALTHY] > total_hosts:
            overall_status = HealthStatus.HEALTHY
        else:
            overall_status = HealthStatus.UNKNOWN

        return {
            "total_hosts": total_hosts,
            "healthy_hosts": status_counts[HealthStatus.HEALTHY],
            "degraded_hosts": status_counts[HealthStatus.DEGRADED],
            "unhealthy_hosts": status_counts[HealthStatus.UNHEALTHY],
            "critical_hosts": status_counts[HealthStatus.CRITICAL],
            "unknown_hosts": status_counts[HealthStatus.UNKNOWN],
            "overall_status": overall_status,
            "last_check": max(self.last_check.values()).isoformat() + "Z"
            if self.last_check
            else None,
        }


class ProxmoxMetricsCollector:
    """Collects and manages Proxmox-specific metrics."""

    def __init__(self, api_credentials: List[ProxmoxAPICredentials]):
        """Initialize Proxmox metrics collector.

        Args:
            api_credentials: List of Proxmox API credentials
        """
        self.api_credentials = api_credentials
        self.metrics_buffer: List[ProxmoxMetric] = []
        self.metrics_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))

        # Metrics collection configuration
        self.collection_interval = 60  # seconds
        self.max_buffer_size = 10000

        logger.info("Proxmox metrics collector initialized")

    async def collect_host_metrics(self, host: str) -> List[ProxmoxMetric]:
        """Collect metrics for a specific Proxmox host.

        Args:
            host: Proxmox host address

        Returns:
            List of collected metrics
        """
        metrics = []

        try:
            # Find API credentials for host
            credentials = None
            for creds in self.api_credentials:
                if creds.host == host:
                    credentials = creds
                    break

            if not credentials:
                return metrics

            async with ProxmoxAPI(credentials) as api_client:
                # Test connection first
                connection_result = await api_client.test_connection()
                if not connection_result.success:
                    # Add connection error metric
                    metrics.append(
                        ProxmoxMetric(
                            name="proxmox_host_up",
                            value=0,
                            labels={"host": host},
                            timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                            metric_type="gauge",
                            help_text="Whether the Proxmox host is reachable (1=up, 0=down)",
                        )
                    )
                    return metrics

            # Host is reachable
            metrics.append(
                ProxmoxMetric(
                    name="proxmox_host_up",
                    value=1,
                    labels={"host": host},
                    timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                    metric_type="gauge",
                    help_text="Whether the Proxmox host is reachable (1=up, 0=down)",
                )
            )

            # Get cluster information
            nodes = await api_client.list_nodes()
            if nodes:
                # Node count metrics
                metrics.append(
                    ProxmoxMetric(
                        name="proxmox_cluster_nodes_total",
                        value=len(nodes),
                        labels={"host": host},
                        timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                        metric_type="gauge",
                        help_text="Total number of nodes in the cluster",
                    )
                )

                # Online node count
                online_nodes = sum(1 for node in nodes if node.status == "online")
                metrics.append(
                    ProxmoxMetric(
                        name="proxmox_cluster_nodes_online",
                        value=online_nodes,
                        labels={"host": host},
                        timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                        metric_type="gauge",
                        help_text="Number of online nodes in the cluster",
                    )
                )

                # Node resource metrics
                for node in nodes:
                    node_labels = {"host": host, "node": node.node}

                    if node.cpu is not None:
                        metrics.append(
                            ProxmoxMetric(
                                name="proxmox_node_cpu_usage_percent",
                                value=node.cpu * 100,
                                labels=node_labels,
                                timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                                metric_type="gauge",
                                help_text="CPU usage percentage for the node",
                            )
                        )

                    if (
                        node.mem is not None
                        and node.maxmem is not None
                        and node.maxmem > 0
                    ):
                        memory_percent = (node.mem / node.maxmem) * 100
                        metrics.append(
                            ProxmoxMetric(
                                name="proxmox_node_memory_usage_percent",
                                value=memory_percent,
                                labels=node_labels,
                                timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                                metric_type="gauge",
                                help_text="Memory usage percentage for the node",
                            )
                        )

            # Get containers and VMs
            containers = await api_client.list_containers()
            vms = await api_client.list_vms()

            if containers:
                metrics.append(
                    ProxmoxMetric(
                        name="proxmox_containers_total",
                        value=len(containers),
                        labels={"host": host},
                        timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                        metric_type="gauge",
                        help_text="Total number of containers",
                    )
                )

                # Container status metrics
                running_containers = sum(
                    1 for c in containers if c.status.value == "running"
                )
                metrics.append(
                    ProxmoxMetric(
                        name="proxmox_containers_running",
                        value=running_containers,
                        labels={"host": host},
                        timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                        metric_type="gauge",
                        help_text="Number of running containers",
                    )
                )

            if vms:
                metrics.append(
                    ProxmoxMetric(
                        name="proxmox_vms_total",
                        value=len(vms),
                        labels={"host": host},
                        timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                        metric_type="gauge",
                        help_text="Total number of VMs",
                    )
                )

                # VM status metrics
                running_vms = sum(1 for vm in vms if vm.status.value == "running")
                metrics.append(
                    ProxmoxMetric(
                        name="proxmox_vms_running",
                        value=running_vms,
                        labels={"host": host},
                        timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                        metric_type="gauge",
                        help_text="Number of running VMs",
                    )
                )

            # Get storage information
            storage_pools = await api_client.list_storage()
            if storage_pools:
                metrics.append(
                    ProxmoxMetric(
                        name="proxmox_storage_pools_total",
                        value=len(storage_pools),
                        labels={"host": host},
                        timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                        metric_type="gauge",
                        help_text="Total number of storage pools",
                    )
                )

        except Exception as e:
            logger.error(f"Failed to collect metrics for {host}: {e}")

            # Add error metric
            metrics.append(
                ProxmoxMetric(
                    name="proxmox_metrics_collection_errors_total",
                    value=1,
                    labels={"host": host, "error_type": "collection_failed"},
                    timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                    metric_type="counter",
                    help_text="Total number of metrics collection errors",
                )
            )

        return metrics

    async def collect_all_metrics(self) -> List[ProxmoxMetric]:
        """Collect metrics from all configured hosts.

        Returns:
            List of all collected metrics
        """
        all_metrics = []

        # Collect metrics from all hosts concurrently
        tasks = []
        for credentials in self.api_credentials:
            task = self.collect_host_metrics(credentials.host)
            tasks.append(task)

        host_metrics = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for credentials, metrics in zip(self.api_credentials, host_metrics):
            if isinstance(metrics, Exception):
                logger.error(
                    f"Metrics collection failed for {credentials.host}: {metrics}"
                )
                # Add error metric
                all_metrics.append(
                    ProxmoxMetric(
                        name="proxmox_host_metrics_error",
                        value=1,
                        labels={"host": credentials.host},
                        timestamp=datetime.now(timezone.utc).isoformat() + "Z",
                        metric_type="counter",
                        help_text="Whether metrics collection failed for the host",
                    )
                )
            else:
                all_metrics.extend(metrics)

                # Store in history
                for metric in metrics:
                    self.metrics_history[metric.name].append(metric)

        return all_metrics

    def get_metrics_as_prometheus(self) -> str:
        """Get all metrics in Prometheus exposition format.

        Returns:
            String containing metrics in Prometheus format
        """
        metric_lines = []

        # Group metrics by name
        metric_groups = defaultdict(list)
        for metric in self.metrics_buffer:
            metric_groups[metric.name].append(metric)

        for metric_name, metrics in metric_groups.items():
            if metrics:
                # Use the first metric for type and help
                first_metric = metrics[0]

                # Add type and help comments
                metric_lines.append(f"# TYPE {metric_name} {first_metric.metric_type}")
                if first_metric.help_text:
                    metric_lines.append(
                        f"# HELP {metric_name} {first_metric.help_text}"
                    )

                # Add metric lines
                for metric in metrics:
                    metric_lines.append(metric.to_prometheus_format())

                metric_lines.append("")  # Empty line between metric groups

        return "\n".join(metric_lines)

    def add_metrics(self, metrics: List[ProxmoxMetric]):
        """Add metrics to the buffer.

        Args:
            metrics: List of metrics to add
        """
        self.metrics_buffer.extend(metrics)

        # Trim buffer if too large
        if len(self.metrics_buffer) > self.max_buffer_size:
            self.metrics_buffer = self.metrics_buffer[-self.max_buffer_size :]

    def clear_buffer(self):
        """Clear the metrics buffer."""
        self.metrics_buffer.clear()


class ProxmoxAlertManager:
    """Manages alerting for Proxmox environments."""

    def __init__(self, alert_rules: List[AlertRule] = None):
        """Initialize Proxmox alert manager.

        Args:
            alert_rules: List of alert rules
        """
        self.alert_rules = alert_rules or []
        self.active_alerts: Dict[str, Dict[str, Any]] = {}
        self.alert_history: List[Dict[str, Any]] = []

        # Default alert rules
        if not self.alert_rules:
            self._setup_default_alert_rules()

        logger.info(
            f"Proxmox alert manager initialized with {len(self.alert_rules)} rules"
        )

    def _setup_default_alert_rules(self):
        """Setup default alert rules."""
        self.alert_rules = [
            AlertRule(
                name="host_down",
                condition="status in ['unhealthy', 'critical']",
                severity=AlertSeverity.CRITICAL,
                description="Proxmox host is down or unreachable",
                labels={"alert_type": "host", "severity": "critical"},
            ),
            AlertRule(
                name="high_cpu_usage",
                condition="cpu_percent > 80",
                severity=AlertSeverity.WARNING,
                description="High CPU usage on Proxmox node",
                labels={"alert_type": "resource", "severity": "warning"},
            ),
            AlertRule(
                name="high_memory_usage",
                condition="memory_percent > 85",
                severity=AlertSeverity.WARNING,
                description="High memory usage on Proxmox node",
                labels={"alert_type": "resource", "severity": "warning"},
            ),
            AlertRule(
                name="container_error",
                condition="container_status == 'error'",
                severity=AlertSeverity.ERROR,
                description="Container is in error state",
                labels={"alert_type": "container", "severity": "error"},
            ),
            AlertRule(
                name="no_online_nodes",
                condition="online_nodes == 0",
                severity=AlertSeverity.CRITICAL,
                description="No nodes are online in the cluster",
                labels={"alert_type": "cluster", "severity": "critical"},
            ),
        ]

    def evaluate_alerts(
        self, health_results: Dict[str, HealthCheckResult], metrics: List[ProxmoxMetric]
    ) -> List[Dict[str, Any]]:
        """Evaluate alert conditions and generate alerts.

        Args:
            health_results: Health check results
            metrics: Current metrics

        Returns:
            List of triggered alerts
        """
        triggered_alerts = []

        # Create a context dictionary for evaluation
        context = {}

        # Add health check results to context
        for host, result in health_results.items():
            context[f"{host}_status"] = result.status.value
            context[f"{host}_message"] = result.message

            # Add details to context
            for key, value in result.details.items():
                context[f"{host}_{key}"] = value

        # Add metrics to context
        for metric in metrics:
            # Convert metric name to context key
            context_key = metric.name.replace(".", "_")
            if metric.metric_type == "gauge":
                context[context_key] = metric.value

        # Evaluate each alert rule
        for rule in self.alert_rules:
            if not rule.enabled:
                continue

            try:
                # Evaluate the condition
                alert_triggered = self._evaluate_condition(rule.condition, context)

                if alert_triggered:
                    alert = self._create_alert(rule, context, health_results, metrics)
                    triggered_alerts.append(alert)

                    # Update active alerts
                    alert_key = (
                        f"{rule.name}:{alert.get('labels', {}).get('host', 'unknown')}"
                    )
                    self.active_alerts[alert_key] = alert

            except Exception as e:
                logger.error(f"Failed to evaluate alert rule {rule.name}: {e}")

        # Clean up resolved alerts
        self._cleanup_resolved_alerts(triggered_alerts)

        # Store alert history
        self.alert_history.extend(triggered_alerts)

        return triggered_alerts

    def _evaluate_condition(self, condition: str, context: Dict[str, Any]) -> bool:
        """Evaluate a condition expression.

        Args:
            condition: Condition expression to evaluate
            context: Context dictionary for evaluation

        Returns:
            True if condition is triggered
        """
        try:
            # Simple evaluation - in production, use a safer expression evaluator
            # This is a basic implementation for demonstration
            for key, value in context.items():
                # Replace variable references with actual values
                condition = condition.replace(key, repr(value))

            # Evaluate the expression
            return eval(condition, {"__builtins__": {}}, {})

        except Exception as e:
            logger.error(f"Failed to evaluate condition '{condition}': {e}")
            return False

    def _create_alert(
        self,
        rule: AlertRule,
        context: Dict[str, Any],
        health_results: Dict[str, HealthCheckResult],
        metrics: List[ProxmoxMetric],
    ) -> Dict[str, Any]:
        """Create an alert from a triggered rule.

        Args:
            rule: Triggered alert rule
            context: Evaluation context
            health_results: Health check results
            metrics: Current metrics

        Returns:
            Alert dictionary
        """
        # Determine the affected host
        affected_host = "unknown"
        for host in health_results.keys():
            if any(key.startswith(host) for key in context.keys()):
                affected_host = host
                break

        # Create alert
        alert = {
            "name": rule.name,
            "description": rule.description,
            "severity": rule.severity,
            "labels": rule.labels.copy(),
            "annotations": rule.annotations.copy(),
            "status": "firing",
            "active_at": datetime.now(timezone.utc).isoformat() + "Z",
            "affected_host": affected_host,
        }

        # Add labels
        alert["labels"]["host"] = affected_host
        alert["labels"]["triggered_at"] = alert["active_at"]

        # Add annotations with current values
        if rule.name == "high_cpu_usage":
            cpu_key = f"{affected_host}_cpu_percent"
            if cpu_key in context:
                alert["annotations"]["current_value"] = f"{context[cpu_key]:.1f}%"
                alert["annotations"]["threshold"] = "80%"

        elif rule.name == "high_memory_usage":
            mem_key = f"{affected_host}_memory_percent"
            if mem_key in context:
                alert["annotations"]["current_value"] = f"{context[mem_key]:.1f}%"
                alert["annotations"]["threshold"] = "85%"

        return alert

    def _cleanup_resolved_alerts(self, triggered_alerts: List[Dict[str, Any]]):
        """Remove alerts that are no longer triggered.

        Args:
            triggered_alerts: Currently triggered alerts
        """
        triggered_keys = {
            f"{alert['name']}:{alert.get('labels', {}).get('host', 'unknown')}"
            for alert in triggered_alerts
        }

        # Find alerts that should be resolved
        resolved_keys = []
        for alert_key in self.active_alerts.keys():
            if alert_key not in triggered_keys:
                resolved_keys.append(alert_key)

        # Mark resolved alerts
        for key in resolved_keys:
            alert = self.active_alerts[key]
            alert["status"] = "resolved"
            alert["resolved_at"] = datetime.now(timezone.utc).isoformat() + "Z"

            # Move to history
            self.alert_history.append(alert)

            # Remove from active alerts
            del self.active_alerts[key]

    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get currently active alerts.

        Returns:
            List of active alerts
        """
        return list(self.active_alerts.values())

    def get_alert_summary(self) -> Dict[str, Any]:
        """Get alert summary statistics.

        Returns:
            Dictionary with alert statistics
        """
        active_counts = defaultdict(int)
        for alert in self.active_alerts.values():
            active_counts[alert["severity"]] += 1

        return {
            "total_active_alerts": len(self.active_alerts),
            "active_alerts_by_severity": dict(active_counts),
            "total_alert_rules": len(self.alert_rules),
            "enabled_alert_rules": sum(1 for rule in self.alert_rules if rule.enabled),
        }


class ProxmoxMonitoringService:
    """Comprehensive monitoring service for Proxmox environments."""

    def __init__(
        self,
        api_credentials: List[ProxmoxAPICredentials],
        monitoring_integrations: List[MonitoringIntegration] = None,
        alert_rules: List[AlertRule] = None,
    ):
        """Initialize Proxmox monitoring service.

        Args:
            api_credentials: List of Proxmox API credentials
            monitoring_integrations: External monitoring system integrations
            alert_rules: Custom alert rules
        """
        self.api_credentials = api_credentials
        self.monitoring_integrations = monitoring_integrations or []

        # Initialize components
        self.health_checker = ProxmoxHealthChecker(api_credentials)
        self.metrics_collector = ProxmoxMetricsCollector(api_credentials)
        self.alert_manager = ProxmoxAlertManager(alert_rules)

        # Service state
        self.running = False
        self.monitoring_task: Optional[asyncio.Task] = None

        logger.info("Proxmox monitoring service initialized")

    async def start_monitoring(self):
        """Start the monitoring service."""
        if self.running:
            logger.warning("Monitoring service is already running")
            return

        self.running = True
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        logger.info("Proxmox monitoring service started")

    async def stop_monitoring(self):
        """Stop the monitoring service."""
        if not self.running:
            return

        self.running = False
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass

        logger.info("Proxmox monitoring service stopped")

    async def _monitoring_loop(self):
        """Main monitoring loop."""
        while self.running:
            try:
                # Perform health checks
                health_results = await self.health_checker.check_all_hosts()

                # Collect metrics
                metrics = await self.metrics_collector.collect_all_metrics()

                # Evaluate alerts
                alerts = self.alert_manager.evaluate_alerts(health_results, metrics)

                # Send data to monitoring integrations
                await self._send_to_monitoring_systems(health_results, metrics, alerts)

                # Wait for next cycle
                await asyncio.sleep(self.health_checker.check_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(60)  # Wait before retrying

    async def _send_to_monitoring_systems(
        self,
        health_results: Dict[str, HealthCheckResult],
        metrics: List[ProxmoxMetric],
        alerts: List[Dict[str, Any]],
    ):
        """Send monitoring data to external systems.

        Args:
            health_results: Health check results
            metrics: Collected metrics
            alerts: Triggered alerts
        """
        for integration in self.monitoring_integrations:
            try:
                # Send metrics
                if metrics and integration.send_metrics:
                    metrics_data = {metric.name: metric.value for metric in metrics}
                    integration.send_metrics(metrics_data)

                # Send health checks
                if health_results and integration.send_health_check:
                    health_data = {
                        host: {
                            "status": result.status.value,
                            "message": result.message,
                            "response_time_ms": result.response_time_ms,
                        }
                        for host, result in health_results.items()
                    }
                    integration.send_health_check(health_data)

                # Send alerts
                if alerts and hasattr(integration, "send_alerts"):
                    integration.send_alerts(alerts)

            except Exception as e:
                logger.error(f"Failed to send data to {integration.name}: {e}")

    async def get_monitoring_status(self) -> Dict[str, Any]:
        """Get current monitoring service status.

        Returns:
            Dictionary with monitoring status
        """
        health_summary = self.health_checker.get_health_summary()
        alert_summary = self.alert_manager.get_alert_summary()

        return {
            "service_running": self.running,
            "health_summary": health_summary,
            "alert_summary": alert_summary,
            "metrics_buffer_size": len(self.metrics_collector.metrics_buffer),
            "monitoring_integrations": len(self.monitoring_integrations),
            "last_check": max(self.health_checker.last_check.values()).isoformat() + "Z"
            if self.health_checker.last_check
            else None,
        }

    async def manual_health_check(self) -> Dict[str, Any]:
        """Perform a manual health check.

        Returns:
            Dictionary with health check results
        """
        health_results = await self.health_checker.check_all_hosts()

        return {
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "results": {
                host: asdict(result) for host, result in health_results.items()
            },
            "summary": self.health_checker.get_health_summary(),
        }

    async def manual_metrics_collection(self) -> Dict[str, Any]:
        """Perform manual metrics collection.

        Returns:
            Dictionary with collected metrics
        """
        metrics = await self.metrics_collector.collect_all_metrics()

        return {
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "metrics_count": len(metrics),
            "metrics": [asdict(metric) for metric in metrics],
            "prometheus_format": self.metrics_collector.get_metrics_as_prometheus(),
        }


# Integration utilities


def create_proxmox_monitoring_service(
    config: Dict[str, Any],
) -> ProxmoxMonitoringService:
    """Create a Proxmox monitoring service from configuration.

    Args:
        config: Monitoring configuration

    Returns:
        Configured ProxmoxMonitoringService
    """
    # Parse API credentials
    api_credentials = []
    for host_config in config.get("hosts", []):
        credentials = ProxmoxAPICredentials(
            host=host_config["host"],
            username=host_config["username"],
            password=host_config.get("password"),
            token=host_config.get("api_token"),
            token_name=host_config.get("token_name"),
            verify_ssl=host_config.get("verify_ssl", True),
            port=host_config.get("port", 8006),
            timeout=host_config.get("timeout", 30),
        )
        api_credentials.append(credentials)

    # Create monitoring integrations
    integrations = []
    for integration_config in config.get("monitoring_integrations", []):
        integration_type = integration_config.get("type", "").lower()

        if integration_type == "prometheus":
            from src.utils.monitoring_integration import PrometheusIntegration

            integration = PrometheusIntegration(integration_config)
            integrations.append(integration)

    # Create monitoring service
    service = ProxmoxMonitoringService(
        api_credentials=api_credentials, monitoring_integrations=integrations
    )

    return service


# Example usage and testing


async def main():
    """Example usage of Proxmox monitoring service."""
    # Example configuration
    config = {
        "hosts": [
            {
                "host": "pve.example.com",
                "username": "root@pam",
                "api_token": "your-api-token",
                "token_name": "tailopsmcp",
            }
        ],
        "monitoring_integrations": [
            {
                "type": "prometheus",
                "enabled": True,
                "pushgateway_url": "http://prometheus-pushgateway:9091",
                "job_name": "proxmox-monitoring",
            }
        ],
    }

    # Create monitoring service
    service = create_proxmox_monitoring_service(config)

    try:
        # Start monitoring
        await service.start_monitoring()

        # Wait for some monitoring cycles
        await asyncio.sleep(300)  # 5 minutes

        # Get status
        status = await service.get_monitoring_status()
        print(f"Monitoring status: {status}")

        # Perform manual health check
        health = await service.manual_health_check()
        print(f"Health check: {health}")

        # Perform manual metrics collection
        metrics = await service.manual_metrics_collection()
        print(f"Metrics collected: {metrics['metrics_count']} metrics")

    finally:
        # Stop monitoring
        await service.stop_monitoring()


if __name__ == "__main__":
    asyncio.run(main())
