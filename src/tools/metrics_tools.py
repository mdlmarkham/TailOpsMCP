"""Prometheus metrics export tools.

Provides Prometheus-compatible metrics endpoints for homelab monitoring
integration.
"""

from __future__ import annotations

import asyncio
import json
import os
import logging
import psutil
from typing import Dict, Any, Optional, List
from datetime import datetime
import subprocess
from asyncio import to_thread

from fastmcp import FastMCP
from src.utils.audit import AuditLogger
from src.auth.middleware import secure_tool
from src.server.utils import format_error


audit = AuditLogger()
logger = logging.getLogger(__name__)


class PrometheusMetric:
    """Helper class to format Prometheus metrics."""

    @staticmethod
    def gauge(name: str, value: float, labels: Optional[Dict[str, str]] = None, help_text: Optional[str] = None) -> str:
        """Format a gauge metric."""
        lines = []
        if help_text:
            lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} gauge")

        if labels:
            label_str = ",".join([f'{k}="{v}"' for k, v in labels.items()])
            lines.append(f"{name}{{{label_str}}} {value}")
        else:
            lines.append(f"{name} {value}")

        return "\n".join(lines)

    @staticmethod
    def counter(name: str, value: float, labels: Optional[Dict[str, str]] = None, help_text: Optional[str] = None) -> str:
        """Format a counter metric."""
        lines = []
        if help_text:
            lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} counter")

        if labels:
            label_str = ",".join([f'{k}="{v}"' for k, v in labels.items()])
            lines.append(f"{name}{{{label_str}}} {value}")
        else:
            lines.append(f"{name} {value}")

        return "\n".join(lines)

    @staticmethod
    def histogram(name: str, buckets: Dict[float, int], sum_value: float, count: int, labels: Optional[Dict[str, str]] = None, help_text: Optional[str] = None) -> str:
        """Format a histogram metric."""
        lines = []
        if help_text:
            lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} histogram")

        label_base = ""
        if labels:
            label_base = ",".join([f'{k}="{v}"' for k, v in labels.items()])

        for le, count_val in sorted(buckets.items()):
            bucket_labels = f"{label_base},le=\"{le}\"" if label_base else f"le=\"{le}\""
            lines.append(f"{name}_bucket{{{bucket_labels}}} {count_val}")

        # Add +Inf bucket
        inf_labels = f"{label_base},le=\"+Inf\"" if label_base else "le=\"+Inf\""
        lines.append(f"{name}_bucket{{{inf_labels}}} {count}")

        # Add sum and count
        if label_base:
            lines.append(f"{name}_sum{{{label_base}}} {sum_value}")
            lines.append(f"{name}_count{{{label_base}}} {count}")
        else:
            lines.append(f"{name}_sum {sum_value}")
            lines.append(f"{name}_count {count}")

        return "\n".join(lines)


async def get_system_metrics() -> str:
    """Export system metrics in Prometheus format.

    Returns:
        Prometheus-formatted metrics text
    """
    metrics = []

    try:
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq()

        metrics.append(PrometheusMetric.gauge(
            "node_cpu_usage_percent",
            cpu_percent,
            help_text="CPU usage percentage"
        ))
        metrics.append(PrometheusMetric.gauge(
            "node_cpu_count",
            cpu_count,
            help_text="Number of CPU cores"
        ))
        if cpu_freq:
            metrics.append(PrometheusMetric.gauge(
                "node_cpu_frequency_mhz",
                cpu_freq.current,
                help_text="Current CPU frequency in MHz"
            ))

        # Per-CPU metrics
        cpu_percents = psutil.cpu_percent(interval=1, percpu=True)
        for i, percent in enumerate(cpu_percents):
            metrics.append(PrometheusMetric.gauge(
                "node_cpu_usage_percent",
                percent,
                labels={"cpu": str(i)},
                help_text="Per-CPU usage percentage"
            ))

        # Memory metrics
        mem = psutil.virtual_memory()
        metrics.append(PrometheusMetric.gauge(
            "node_memory_total_bytes",
            mem.total,
            help_text="Total physical memory"
        ))
        metrics.append(PrometheusMetric.gauge(
            "node_memory_available_bytes",
            mem.available,
            help_text="Available memory"
        ))
        metrics.append(PrometheusMetric.gauge(
            "node_memory_used_bytes",
            mem.used,
            help_text="Used memory"
        ))
        metrics.append(PrometheusMetric.gauge(
            "node_memory_usage_percent",
            mem.percent,
            help_text="Memory usage percentage"
        ))

        # Swap metrics
        swap = psutil.swap_memory()
        metrics.append(PrometheusMetric.gauge(
            "node_swap_total_bytes",
            swap.total,
            help_text="Total swap memory"
        ))
        metrics.append(PrometheusMetric.gauge(
            "node_swap_used_bytes",
            swap.used,
            help_text="Used swap memory"
        ))
        metrics.append(PrometheusMetric.gauge(
            "node_swap_usage_percent",
            swap.percent,
            help_text="Swap usage percentage"
        ))

        # Disk metrics
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                labels = {
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "fstype": partition.fstype
                }

                metrics.append(PrometheusMetric.gauge(
                    "node_disk_total_bytes",
                    usage.total,
                    labels=labels,
                    help_text="Total disk space"
                ))
                metrics.append(PrometheusMetric.gauge(
                    "node_disk_used_bytes",
                    usage.used,
                    labels=labels,
                    help_text="Used disk space"
                ))
                metrics.append(PrometheusMetric.gauge(
                    "node_disk_free_bytes",
                    usage.free,
                    labels=labels,
                    help_text="Free disk space"
                ))
                metrics.append(PrometheusMetric.gauge(
                    "node_disk_usage_percent",
                    usage.percent,
                    labels=labels,
                    help_text="Disk usage percentage"
                ))
            except:
                continue

        # Disk I/O metrics
        disk_io = psutil.disk_io_counters()
        if disk_io:
            metrics.append(PrometheusMetric.counter(
                "node_disk_read_bytes_total",
                disk_io.read_bytes,
                help_text="Total bytes read from disk"
            ))
            metrics.append(PrometheusMetric.counter(
                "node_disk_write_bytes_total",
                disk_io.write_bytes,
                help_text="Total bytes written to disk"
            ))
            metrics.append(PrometheusMetric.counter(
                "node_disk_reads_total",
                disk_io.read_count,
                help_text="Total read operations"
            ))
            metrics.append(PrometheusMetric.counter(
                "node_disk_writes_total",
                disk_io.write_count,
                help_text="Total write operations"
            ))

        # Network metrics
        net_io = psutil.net_io_counters(pernic=True)
        for interface, stats in net_io.items():
            labels = {"interface": interface}

            metrics.append(PrometheusMetric.counter(
                "node_network_receive_bytes_total",
                stats.bytes_recv,
                labels=labels,
                help_text="Total bytes received"
            ))
            metrics.append(PrometheusMetric.counter(
                "node_network_transmit_bytes_total",
                stats.bytes_sent,
                labels=labels,
                help_text="Total bytes transmitted"
            ))
            metrics.append(PrometheusMetric.counter(
                "node_network_receive_packets_total",
                stats.packets_recv,
                labels=labels,
                help_text="Total packets received"
            ))
            metrics.append(PrometheusMetric.counter(
                "node_network_transmit_packets_total",
                stats.packets_sent,
                labels=labels,
                help_text="Total packets transmitted"
            ))
            metrics.append(PrometheusMetric.counter(
                "node_network_receive_errors_total",
                stats.errin,
                labels=labels,
                help_text="Total receive errors"
            ))
            metrics.append(PrometheusMetric.counter(
                "node_network_transmit_errors_total",
                stats.errout,
                labels=labels,
                help_text="Total transmit errors"
            ))

        # Load average
        load_avg = os.getloadavg()
        metrics.append(PrometheusMetric.gauge(
            "node_load1",
            load_avg[0],
            help_text="1-minute load average"
        ))
        metrics.append(PrometheusMetric.gauge(
            "node_load5",
            load_avg[1],
            help_text="5-minute load average"
        ))
        metrics.append(PrometheusMetric.gauge(
            "node_load15",
            load_avg[2],
            help_text="15-minute load average"
        ))

        # Boot time
        boot_time = psutil.boot_time()
        metrics.append(PrometheusMetric.gauge(
            "node_boot_time_seconds",
            boot_time,
            help_text="System boot time in Unix time"
        ))

        # Uptime
        uptime_seconds = datetime.now().timestamp() - boot_time
        metrics.append(PrometheusMetric.gauge(
            "node_uptime_seconds",
            uptime_seconds,
            help_text="System uptime in seconds"
        ))

        audit.log("get_system_metrics", {}, {"success": True})

        return "\n".join(metrics) + "\n"

    except Exception as e:
        audit.log("get_system_metrics", {}, {
            "success": False,
            "error": str(e)
        })
        return f"# Error collecting metrics: {str(e)}\n"


async def get_docker_metrics() -> str:
    """Export Docker container metrics in Prometheus format.

    Returns:
        Prometheus-formatted metrics text
    """
    metrics = []

    try:
        # Try using docker SDK first
        try:
            import docker
            client = docker.from_env()
            containers = client.containers.list(all=True)

            for container in containers:
                try:
                    labels = {
                        "name": container.name,
                        "id": container.id[:12],
                        "image": container.image.tags[0] if container.image.tags else "unknown"
                    }

                    # Container state
                    state_value = 1 if container.status == "running" else 0
                    metrics.append(PrometheusMetric.gauge(
                        "docker_container_running",
                        state_value,
                        labels=labels,
                        help_text="Container running status (1=running, 0=stopped)"
                    ))

                    # Get stats if running
                    if container.status == "running":
                        stats = container.stats(stream=False)

                        # CPU usage
                        cpu_delta = stats["cpu_stats"]["cpu_usage"]["total_usage"] - stats["precpu_stats"]["cpu_usage"]["total_usage"]
                        system_delta = stats["cpu_stats"]["system_cpu_usage"] - stats["precpu_stats"]["system_cpu_usage"]
                        cpu_percent = (cpu_delta / system_delta) * len(stats["cpu_stats"]["cpu_usage"]["percpu_usage"]) * 100.0 if system_delta > 0 else 0

                        metrics.append(PrometheusMetric.gauge(
                            "docker_container_cpu_usage_percent",
                            cpu_percent,
                            labels=labels,
                            help_text="Container CPU usage percentage"
                        ))

                        # Memory usage
                        mem_usage = stats["memory_stats"].get("usage", 0)
                        mem_limit = stats["memory_stats"].get("limit", 0)
                        mem_percent = (mem_usage / mem_limit) * 100.0 if mem_limit > 0 else 0

                        metrics.append(PrometheusMetric.gauge(
                            "docker_container_memory_usage_bytes",
                            mem_usage,
                            labels=labels,
                            help_text="Container memory usage in bytes"
                        ))
                        metrics.append(PrometheusMetric.gauge(
                            "docker_container_memory_limit_bytes",
                            mem_limit,
                            labels=labels,
                            help_text="Container memory limit in bytes"
                        ))
                        metrics.append(PrometheusMetric.gauge(
                            "docker_container_memory_usage_percent",
                            mem_percent,
                            labels=labels,
                            help_text="Container memory usage percentage"
                        ))

                        # Network I/O
                        networks = stats.get("networks", {})
                        for net_name, net_stats in networks.items():
                            net_labels = {**labels, "network": net_name}

                            metrics.append(PrometheusMetric.counter(
                                "docker_container_network_receive_bytes_total",
                                net_stats.get("rx_bytes", 0),
                                labels=net_labels,
                                help_text="Container network bytes received"
                            ))
                            metrics.append(PrometheusMetric.counter(
                                "docker_container_network_transmit_bytes_total",
                                net_stats.get("tx_bytes", 0),
                                labels=net_labels,
                                help_text="Container network bytes transmitted"
                            ))

                except Exception as e:
                    continue

        except ImportError:
            # Fall back to docker CLI
            result = await to_thread(
                subprocess.run,
                ["docker", "ps", "-a", "--format", "{{json .}}"],
                capture_output=True,
                text=True,
                check=True
            )

            for line in result.stdout.splitlines():
                if not line.strip():
                    continue

                container_info = json.loads(line)
                name = container_info.get("Names", "unknown")
                container_id = container_info.get("ID", "unknown")
                image = container_info.get("Image", "unknown")
                status = container_info.get("State", "unknown")

                labels = {
                    "name": name,
                    "id": container_id,
                    "image": image
                }

                state_value = 1 if status == "running" else 0
                metrics.append(PrometheusMetric.gauge(
                    "docker_container_running",
                    state_value,
                    labels=labels,
                    help_text="Container running status (1=running, 0=stopped)"
                ))

        audit.log("get_docker_metrics", {}, {"success": True})

        return "\n".join(metrics) + "\n" if metrics else "# No Docker containers found\n"

    except Exception as e:
        audit.log("get_docker_metrics", {}, {
            "success": False,
            "error": str(e)
        })
        return f"# Error collecting Docker metrics: {str(e)}\n"


async def get_all_metrics() -> str:
    """Export all available metrics in Prometheus format.

    Returns:
        Prometheus-formatted metrics text
    """
    metrics = []

    # Add system metrics
    system_metrics = await get_system_metrics()
    metrics.append(system_metrics)

    # Add Docker metrics
    docker_metrics = await get_docker_metrics()
    metrics.append(docker_metrics)

    # Add custom metrics
    metrics.append(PrometheusMetric.gauge(
        "tailopsmcp_scrape_timestamp_seconds",
        datetime.now().timestamp(),
        help_text="Timestamp of metrics collection"
    ))

    audit.log("get_all_metrics", {}, {"success": True})

    return "\n".join(metrics)


async def start_metrics_server(
    port: int = 9100,
    bind_address: str = "0.0.0.0"
) -> Dict[str, Any]:
    """Start a simple HTTP server to expose Prometheus metrics.

    Args:
        port: Port to bind to (default: 9100)
        bind_address: Address to bind to (default: 0.0.0.0)

    Returns:
        Dict with server info
    """
    try:
        from aiohttp import web

        async def metrics_handler(request):
            """Handle /metrics requests."""
            metrics = await get_all_metrics()
            return web.Response(text=metrics, content_type="text/plain; version=0.0.4")

        async def health_handler(request):
            """Handle health check requests."""
            return web.Response(text="OK\n")

        app = web.Application()
        app.router.add_get("/metrics", metrics_handler)
        app.router.add_get("/health", health_handler)
        app.router.add_get("/", lambda r: web.Response(text="TailOpsMCP Metrics Exporter\n/metrics - Prometheus metrics\n/health - Health check\n"))

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, bind_address, port)
        await site.start()

        audit.log("start_metrics_server", {
            "port": port,
            "bind_address": bind_address
        }, {
            "success": True
        })

        return {
            "success": True,
            "message": f"Metrics server started on {bind_address}:{port}",
            "endpoint": f"http://{bind_address}:{port}/metrics"
        }

    except Exception as e:
        error_msg = f"Failed to start metrics server: {str(e)}"
        audit.log("start_metrics_server", {
            "port": port,
            "bind_address": bind_address
        }, {
            "success": False,
            "error": error_msg
        })
        return {
            "success": False,
            "error": error_msg
        }


async def save_metrics_to_file(
    output_path: str = "/var/lib/node_exporter/textfile_collector/tailopsmcp.prom"
) -> Dict[str, Any]:
    """Save metrics to a file for node_exporter textfile collector.

    Args:
        output_path: Path to write metrics file

    Returns:
        Dict with result status
    """
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        # Get all metrics
        metrics = await get_all_metrics()

        # Write to temp file first, then rename (atomic operation)
        temp_path = output_path + ".tmp"
        with open(temp_path, 'w') as f:
            f.write(metrics)

        os.rename(temp_path, output_path)

        audit.log("save_metrics_to_file", {
            "output_path": output_path
        }, {
            "success": True
        })

        return {
            "success": True,
            "message": f"Metrics written to {output_path}",
            "path": output_path
        }

    except Exception as e:
        error_msg = f"Failed to write metrics file: {str(e)}"
        audit.log("save_metrics_to_file", {
            "output_path": output_path
        }, {
            "success": False,
            "error": error_msg
        })
        return {
            "success": False,
            "error": error_msg
        }


def register_tools(mcp: FastMCP):
    """Register Prometheus metrics export tools with MCP instance."""

    @mcp.tool()
    @secure_tool("metrics:read")
    async def export_prometheus_metrics(
        include_docker: bool = True
    ) -> str:
        """Export system and Docker metrics in Prometheus format.

        Args:
            include_docker: Include Docker container metrics (default: True)

        Returns:
            Prometheus-formatted metrics text
        """
        try:
            if include_docker:
                result = await get_all_metrics()
            else:
                result = await get_system_metrics()
            return result
        except Exception as e:
            return format_error(e, "export_prometheus_metrics")

    @mcp.tool()
    @secure_tool("metrics:read")
    async def get_prometheus_system_metrics() -> str:
        """Export system metrics in Prometheus format.

        Returns:
            Prometheus-formatted system metrics text
        """
        try:
            result = await get_system_metrics()
            return result
        except Exception as e:
            return format_error(e, "get_prometheus_system_metrics")

    @mcp.tool()
    @secure_tool("metrics:read")
    async def get_prometheus_docker_metrics() -> str:
        """Export Docker container metrics in Prometheus format.

        Returns:
            Prometheus-formatted Docker metrics text
        """
        try:
            result = await get_docker_metrics()
            return result
        except Exception as e:
            return format_error(e, "get_prometheus_docker_metrics")

    @mcp.tool()
    @secure_tool("metrics:admin")
    async def write_metrics_textfile(
        output_path: str = "/var/lib/node_exporter/textfile_collector/tailopsmcp.prom"
    ) -> dict:
        """Save metrics to a file for node_exporter textfile collector.

        Args:
            output_path: Path to write metrics file (default: /var/lib/node_exporter/textfile_collector/tailopsmcp.prom)

        Returns:
            Dict with result status
        """
        try:
            result = await save_metrics_to_file(output_path=output_path)
            return result
        except Exception as e:
            return format_error(e, "write_metrics_textfile")

    logger.info("Registered 4 metrics tools")
