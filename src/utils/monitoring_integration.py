"""
Integration utilities for monitoring systems and observability platforms.
"""

import json
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.utils.audit import AuditLogger, LogLevel
from src.utils.logging_config import MetricsCollector, health_checker


class MonitoringIntegration:
    """Base class for monitoring system integrations."""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.enabled = config.get("enabled", True)
    
    def send_metrics(self, metrics: Dict[str, Any]) -> bool:
        """Send metrics to the monitoring system."""
        raise NotImplementedError
    
    def send_logs(self, logs: List[Dict[str, Any]]) -> bool:
        """Send logs to the monitoring system."""
        raise NotImplementedError
    
    def send_health_check(self, health_data: Dict[str, Any]) -> bool:
        """Send health check data to the monitoring system."""
        raise NotImplementedError
    
    def test_connection(self) -> bool:
        """Test connection to the monitoring system."""
        raise NotImplementedError


class PrometheusIntegration(MonitoringIntegration):
    """Prometheus integration for metrics collection."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("prometheus", config)
        self.pushgateway_url = config.get("pushgateway_url")
        self.job_name = config.get("job_name", "systemmanager")
    
    def send_metrics(self, metrics: Dict[str, Any]) -> bool:
        """Send metrics to Prometheus pushgateway."""
        if not self.enabled or not self.pushgateway_url:
            return False
        
        try:
            import requests
            
            # Format metrics for Prometheus
            prometheus_metrics = self._format_metrics_for_prometheus(metrics)
            
            response = requests.post(
                f"{self.pushgateway_url}/metrics/job/{self.job_name}",
                data=prometheus_metrics,
                timeout=10
            )
            
            return response.status_code == 200
        except Exception:
            return False
    
    def _format_metrics_for_prometheus(self, metrics: Dict[str, Any]) -> str:
        """Format metrics in Prometheus exposition format."""
        lines = []
        
        for metric_name, value in metrics.items():
            if isinstance(value, (int, float)):
                # Convert metric name to Prometheus format
                prom_name = metric_name.replace(".", "_").replace("-", "_")
                lines.append(f"{prom_name} {value}")
        
        return "\n".join(lines)
    
    def test_connection(self) -> bool:
        """Test connection to Prometheus pushgateway."""
        if not self.enabled or not self.pushgateway_url:
            return False
        
        try:
            import requests
            response = requests.get(f"{self.pushgateway_url}", timeout=5)
            return response.status_code == 200
        except Exception:
            return False


class ElasticsearchIntegration(MonitoringIntegration):
    """Elasticsearch integration for log aggregation."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("elasticsearch", config)
        self.host = config.get("host", "localhost")
        self.port = config.get("port", 9200)
        self.index_prefix = config.get("index_prefix", "systemmanager")
    
    def send_logs(self, logs: List[Dict[str, Any]]) -> bool:
        """Send logs to Elasticsearch."""
        if not self.enabled:
            return False
        
        try:
            from elasticsearch import Elasticsearch
            
            es = Elasticsearch([{"host": self.host, "port": self.port}])
            
            for log in logs:
                index_name = f"{self.index_prefix}-{datetime.utcnow().strftime('%Y.%m.%d')}"
                es.index(index=index_name, body=log)
            
            return True
        except Exception:
            return False
    
    def test_connection(self) -> bool:
        """Test connection to Elasticsearch."""
        if not self.enabled:
            return False
        
        try:
            from elasticsearch import Elasticsearch
            es = Elasticsearch([{"host": self.host, "port": self.port}])
            return es.ping()
        except Exception:
            return False


class DatadogIntegration(MonitoringIntegration):
    """Datadog integration for comprehensive monitoring."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("datadog", config)
        self.api_key = config.get("api_key")
        self.app_key = config.get("app_key")
        self.host = config.get("host", "https://api.datadoghq.com")
    
    def send_metrics(self, metrics: Dict[str, Any]) -> bool:
        """Send metrics to Datadog."""
        if not self.enabled or not self.api_key:
            return False
        
        try:
            import requests
            
            datadog_metrics = []
            timestamp = int(time.time())
            
            for metric_name, value in metrics.items():
                if isinstance(value, (int, float)):
                    datadog_metrics.append({
                        "metric": f"systemmanager.{metric_name}",
                        "points": [[timestamp, value]],
                        "type": "gauge",
                        "tags": ["environment:production"]
                    })
            
            response = requests.post(
                f"{self.host}/api/v1/series",
                headers={
                    "Content-Type": "application/json",
                    "DD-API-KEY": self.api_key
                },
                data=json.dumps({"series": datadog_metrics}),
                timeout=10
            )
            
            return response.status_code == 202
        except Exception:
            return False
    
    def test_connection(self) -> bool:
        """Test connection to Datadog."""
        if not self.enabled or not self.api_key:
            return False
        
        try:
            import requests
            response = requests.get(
                f"{self.host}/api/v1/validate",
                headers={"DD-API-KEY": self.api_key},
                timeout=5
            )
            return response.status_code == 200
        except Exception:
            return False


class MonitoringManager:
    """Manager for monitoring system integrations."""
    
    def __init__(self):
        self.integrations: Dict[str, MonitoringIntegration] = {}
        self._setup_integrations()
    
    def _setup_integrations(self) -> None:
        """Set up monitoring integrations based on configuration."""
        
        # Prometheus integration
        prometheus_config = {
            "enabled": os.getenv("PROMETHEUS_ENABLED", "false").lower() == "true",
            "pushgateway_url": os.getenv("PROMETHEUS_PUSHGATEWAY_URL"),
            "job_name": os.getenv("PROMETHEUS_JOB_NAME", "systemmanager")
        }
        
        if prometheus_config["enabled"] and prometheus_config["pushgateway_url"]:
            self.integrations["prometheus"] = PrometheusIntegration(prometheus_config)
        
        # Elasticsearch integration
        elasticsearch_config = {
            "enabled": os.getenv("ELASTICSEARCH_ENABLED", "false").lower() == "true",
            "host": os.getenv("ELASTICSEARCH_HOST", "localhost"),
            "port": int(os.getenv("ELASTICSEARCH_PORT", "9200")),
            "index_prefix": os.getenv("ELASTICSEARCH_INDEX_PREFIX", "systemmanager")
        }
        
        if elasticsearch_config["enabled"]:
            self.integrations["elasticsearch"] = ElasticsearchIntegration(elasticsearch_config)
        
        # Datadog integration
        datadog_config = {
            "enabled": os.getenv("DATADOG_ENABLED", "false").lower() == "true",
            "api_key": os.getenv("DATADOG_API_KEY"),
            "app_key": os.getenv("DATADOG_APP_KEY"),
            "host": os.getenv("DATADOG_HOST", "https://api.datadoghq.com")
        }
        
        if datadog_config["enabled"] and datadog_config["api_key"]:
            self.integrations["datadog"] = DatadogIntegration(datadog_config)
    
    def send_metrics(self, metrics: Dict[str, Any]) -> None:
        """Send metrics to all enabled monitoring integrations."""
        for integration in self.integrations.values():
            try:
                integration.send_metrics(metrics)
            except Exception:
                # Silently fail for monitoring integrations
                pass
    
    def send_health_check(self) -> None:
        """Send health check data to monitoring systems."""
        health_data = health_checker.get_status_report()
        
        for integration in self.integrations.values():
            try:
                integration.send_health_check(health_data)
            except Exception:
                # Silently fail for monitoring integrations
                pass
    
    def test_all_connections(self) -> Dict[str, bool]:
        """Test connections to all monitoring systems."""
        results = {}
        
        for name, integration in self.integrations.items():
            try:
                results[name] = integration.test_connection()
            except Exception:
                results[name] = False
        
        return results


class DashboardExporter:
    """Export data in dashboard-friendly formats."""
    
    @staticmethod
    def export_metrics_for_dashboard(metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Export metrics in a format suitable for dashboards."""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "metrics": metrics,
            "summary": {
                "total_metrics": len(metrics),
                "numeric_metrics": sum(1 for v in metrics.values() if isinstance(v, (int, float))),
                "string_metrics": sum(1 for v in metrics.values() if isinstance(v, str))
            }
        }
    
    @staticmethod
    def export_logs_for_dashboard(logs: List[Dict[str, Any]], limit: int = 100) -> Dict[str, Any]:
        """Export logs in a format suitable for dashboards."""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "logs": logs[:limit],
            "summary": {
                "total_logs": len(logs),
                "displayed_logs": min(len(logs), limit),
                "levels": {
                    level: sum(1 for log in logs if log.get("level") == level)
                    for level in ["debug", "info", "warning", "error", "critical"]
                }
            }
        }
    
    @staticmethod
    def export_health_for_dashboard(health_data: Dict[str, Any]) -> Dict[str, Any]:
        """Export health data in a format suitable for dashboards."""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "health": health_data,
            "status": health_data.get("overall_status", "unknown")
        }


# Global monitoring manager instance
monitoring_manager = MonitoringManager()


def setup_monitoring() -> None:
    """Set up monitoring system integrations."""
    # Test connections and log status
    connection_results = monitoring_manager.test_all_connections()
    
    for system, connected in connection_results.items():
        status = "connected" if connected else "disconnected"
        AuditLogger().log_structured(
            level=LogLevel.INFO,
            message=f"Monitoring system {system}: {status}",
            correlation_id="monitoring_setup"
        )


# Set up monitoring when module is imported
setup_monitoring()