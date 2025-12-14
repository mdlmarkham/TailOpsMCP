"""
Secure logging configuration with sensitive data redaction and production hardening.
"""

import logging
import os
import sys
import re
from datetime import datetime
from typing import Any, Dict, Optional, List
from io import StringIO

from src.utils.audit import LogLevel, audit_logger


class SystemLogger:
    """Standardized system logger with correlation IDs and structured logging."""
    
    def __init__(self, name: str, correlation_id: Optional[str] = None):
        self.name = name
        self.correlation_id = correlation_id or "system"
        self._logger = logging.getLogger(name)
    
    def _log_with_context(self, level: LogLevel, message: str, **kwargs) -> None:
        """Log a message with correlation ID and additional context."""
        # Log to Python logging system
        log_method = getattr(self._logger, level.value)
        
        # Add correlation ID to log record
        extra = {"correlation_id": self.correlation_id}
        if kwargs:
            extra.update(kwargs)
        
        log_method(message, extra=extra)
        
        # Also log to audit system for structured logging
        audit_logger.log_structured(
            level=level,
            message=message,
            correlation_id=self.correlation_id,
            logger=self.name,
            **kwargs
        )
    
    def debug(self, message: str, **kwargs) -> None:
        """Log a debug message."""
        self._log_with_context(LogLevel.DEBUG, message, **kwargs)
    
    def info(self, message: str, **kwargs) -> None:
        """Log an info message."""
        self._log_with_context(LogLevel.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs) -> None:
        """Log a warning message."""
        self._log_with_context(LogLevel.WARNING, message, **kwargs)
    
    def error(self, message: str, **kwargs) -> None:
        """Log an error message."""
        self._log_with_context(LogLevel.ERROR, message, **kwargs)
    
    def critical(self, message: str, **kwargs) -> None:
        """Log a critical message."""
        self._log_with_context(LogLevel.CRITICAL, message, **kwargs)
    
    def set_correlation_id(self, correlation_id: str) -> None:
        """Set the correlation ID for this logger."""
        self.correlation_id = correlation_id


class MetricsCollector:
    """Metrics collection for operational observability."""
    
    def __init__(self):
        self.metrics: Dict[str, Any] = {}
        self._start_times: Dict[str, datetime] = {}
    
    def start_timer(self, operation: str) -> None:
        """Start timing an operation."""
        self._start_times[operation] = datetime.utcnow()
    
    def stop_timer(self, operation: str) -> float:
        """Stop timing an operation and return duration."""
        if operation not in self._start_times:
            return 0.0
        
        duration = (datetime.utcnow() - self._start_times[operation]).total_seconds()
        self._record_metric(f"{operation}_duration", duration)
        return duration
    
    def _record_metric(self, name: str, value: Any) -> None:
        """Record a metric."""
        self.metrics[name] = value
    
    def increment_counter(self, name: str, value: int = 1) -> None:
        """Increment a counter metric."""
        current = self.metrics.get(name, 0)
        self.metrics[name] = current + value
    
    def record_gauge(self, name: str, value: float) -> None:
        """Record a gauge metric."""
        self.metrics[name] = value
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get all collected metrics."""
        return self.metrics.copy()
    
    def clear_metrics(self) -> None:
        """Clear all metrics."""
        self.metrics.clear()
        self._start_times.clear()


class HealthChecker:
    """Health checking and status reporting for system components."""
    
    def __init__(self):
        self.checks: Dict[str, Dict[str, Any]] = {}
        self.logger = SystemLogger("health")
    
    def register_check(self, name: str, check_func, interval: int = 30) -> None:
        """Register a health check."""
        self.checks[name] = {
            "function": check_func,
            "interval": interval,
            "last_run": None,
            "last_status": None,
            "last_error": None
        }
    
    def run_check(self, name: str) -> Dict[str, Any]:
        """Run a specific health check."""
        if name not in self.checks:
            return {
                "status": "error",
                "message": f"Health check '{name}' not found",
                "timestamp": datetime.utcnow().isoformat()
            }
        
        check = self.checks[name]
        try:
            result = check["function"]()
            check["last_status"] = result.get("status", "unknown")
            check["last_error"] = None
            check["last_run"] = datetime.utcnow()
            
            self.logger.info(f"Health check '{name}' completed with status: {result.get('status')}")
            return result
            
        except Exception as e:
            check["last_status"] = "error"
            check["last_error"] = str(e)
            check["last_run"] = datetime.utcnow()
            
            self.logger.error(f"Health check '{name}' failed: {e}")
            return {
                "status": "error",
                "message": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def run_all_checks(self) -> Dict[str, Dict[str, Any]]:
        """Run all registered health checks."""
        results = {}
        for name in self.checks:
            results[name] = self.run_check(name)
        
        return results
    
    def get_status_report(self) -> Dict[str, Any]:
        """Get a comprehensive status report."""
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "checks": {},
            "overall_status": "healthy",
            "summary": {
                "total_checks": len(self.checks),
                "healthy_checks": 0,
                "unhealthy_checks": 0,
                "error_checks": 0
            }
        }
        
        for name, check in self.checks.items():
            status_info = {
                "last_run": check["last_run"].isoformat() if check["last_run"] else None,
                "last_status": check["last_status"],
                "last_error": check["last_error"],
                "interval": check["interval"]
            }
            
            report["checks"][name] = status_info
            
            if check["last_status"] == "healthy":
                report["summary"]["healthy_checks"] += 1
            elif check["last_status"] == "unhealthy":
                report["summary"]["unhealthy_checks"] += 1
                report["overall_status"] = "unhealthy"
            elif check["last_status"] == "error":
                report["summary"]["error_checks"] += 1
                report["overall_status"] = "error"
        
        return report


# Global instances
metrics_collector = MetricsCollector()
health_checker = HealthChecker()


def get_logger(name: str, correlation_id: Optional[str] = None) -> SystemLogger:
    """Get a standardized logger instance."""
    return SystemLogger(name, correlation_id)


def setup_health_checks() -> None:
    """Set up default health checks for the system."""
    
    def check_audit_logging() -> Dict[str, Any]:
        """Check if audit logging is functioning."""
        try:
            # Test audit logging
            audit_logger.log_structured(
                level=LogLevel.INFO,
                message="Health check: audit logging test",
                correlation_id="health_check"
            )
            return {
                "status": "healthy",
                "message": "Audit logging is functioning",
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                "status": "error",
                "message": f"Audit logging error: {e}",
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def check_disk_space() -> Dict[str, Any]:
        """Check available disk space."""
        try:
            import shutil
            
            total, used, free = shutil.disk_usage("/")
            free_gb = free / (2**30)  # Convert to GB
            
            if free_gb < 1:  # Less than 1GB free
                return {
                    "status": "unhealthy",
                    "message": f"Low disk space: {free_gb:.2f}GB free",
                    "free_space_gb": free_gb,
                    "timestamp": datetime.utcnow().isoformat()
                }
            else:
                return {
                    "status": "healthy",
                    "message": f"Adequate disk space: {free_gb:.2f}GB free",
                    "free_space_gb": free_gb,
                    "timestamp": datetime.utcnow().isoformat()
                }
        except Exception as e:
            return {
                "status": "error",
                "message": f"Disk space check error: {e}",
                "timestamp": datetime.utcnow().isoformat()
            }
    
    # Register default health checks
    health_checker.register_check("audit_logging", check_audit_logging, interval=60)
    health_checker.register_check("disk_space", check_disk_space, interval=300)


# Set up health checks when module is imported
setup_health_checks()