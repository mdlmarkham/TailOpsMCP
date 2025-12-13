"""
Configuration for audit log sinks, retention policies, and observability settings.
"""

import os
from typing import Dict, List, Optional


class AuditLogConfig:
    """Configuration for audit logging system."""
    
    # Default configuration
    DEFAULT_CONFIG = {
        "sinks": [
            {
                "type": "file",
                "enabled": True,
                "path": os.getenv("SYSTEMMANAGER_AUDIT_LOG", "./logs/audit.log"),
                "max_size": 10 * 1024 * 1024,  # 10MB
                "backup_count": 5,
                "retention_days": 30
            },
            {
                "type": "console",
                "enabled": os.getenv("SYSTEMMANAGER_LOG_CONSOLE", "true").lower() == "true",
                "format": "human"
            }
        ],
        "retention": {
            "enabled": True,
            "max_age_days": 90,
            "max_size_mb": 100,
            "compression": False
        },
        "format": {
            "timestamp_format": "iso",
            "include_metadata": True,
            "redact_sensitive": True
        }
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from environment variables and defaults."""
        config = self.DEFAULT_CONFIG.copy()
        
        # Override with environment variables
        config["retention"]["max_age_days"] = int(os.getenv(
            "SYSTEMMANAGER_LOG_RETENTION_DAYS", 
            config["retention"]["max_age_days"]
        ))
        
        config["retention"]["max_size_mb"] = int(os.getenv(
            "SYSTEMMANAGER_LOG_MAX_SIZE_MB", 
            config["retention"]["max_size_mb"]
        ))
        
        return config
    
    def get_sink_config(self, sink_type: str) -> Optional[Dict[str, Any]]:
        """Get configuration for a specific sink type."""
        for sink in self.config["sinks"]:
            if sink["type"] == sink_type:
                return sink
        return None
    
    def get_enabled_sinks(self) -> List[Dict[str, Any]]:
        """Get list of enabled sinks."""
        return [sink for sink in self.config["sinks"] if sink.get("enabled", True)]


class LogRetentionPolicy:
    """Log retention policy management."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("enabled", True)
        self.max_age_days = config.get("max_age_days", 90)
        self.max_size_mb = config.get("max_size_mb", 100)
        self.compression = config.get("compression", False)
    
    def should_cleanup(self, log_file: str) -> bool:
        """Check if a log file should be cleaned up."""
        if not self.enabled:
            return False
        
        import os
        from datetime import datetime, timedelta
        
        try:
            file_stat = os.stat(log_file)
            file_age = datetime.fromtimestamp(file_stat.st_mtime)
            file_size_mb = file_stat.st_size / (1024 * 1024)
            
            # Check age
            if datetime.now() - file_age > timedelta(days=self.max_age_days):
                return True
            
            # Check size (for rotated files)
            if file_size_mb > self.max_size_mb:
                return True
            
            return False
        except OSError:
            return False
    
    def cleanup_old_logs(self, log_directory: str) -> List[str]:
        """Clean up old log files based on retention policy."""
        if not self.enabled:
            return []
        
        import os
        import glob
        
        cleaned_files = []
        
        # Find all log files in the directory
        log_patterns = [
            os.path.join(log_directory, "*.log"),
            os.path.join(log_directory, "*.log.*"),  # Rotated files
        ]
        
        for pattern in log_patterns:
            for log_file in glob.glob(pattern):
                if self.should_cleanup(log_file):
                    try:
                        os.remove(log_file)
                        cleaned_files.append(log_file)
                    except OSError:
                        # Skip files that can't be removed
                        pass
        
        return cleaned_files


class ObservabilityConfig:
    """Configuration for observability features."""
    
    def __init__(self):
        self.metrics_enabled = os.getenv("SYSTEMMANAGER_METRICS_ENABLED", "true").lower() == "true"
        self.health_checks_enabled = os.getenv("SYSTEMMANAGER_HEALTH_CHECKS_ENABLED", "true").lower() == "true"
        self.monitoring_enabled = os.getenv("SYSTEMMANAGER_MONITORING_ENABLED", "false").lower() == "true"
        
        # Metrics collection intervals (seconds)
        self.metrics_interval = int(os.getenv("SYSTEMMANAGER_METRICS_INTERVAL", "60"))
        self.health_check_interval = int(os.getenv("SYSTEMMANAGER_HEALTH_CHECK_INTERVAL", "300"))
        
        # Alert thresholds
        self.error_threshold = int(os.getenv("SYSTEMMANAGER_ERROR_THRESHOLD", "10"))
        self.latency_threshold = float(os.getenv("SYSTEMMANAGER_LATENCY_THRESHOLD", "5.0"))
    
    def get_metrics_config(self) -> Dict[str, Any]:
        """Get metrics collection configuration."""
        return {
            "enabled": self.metrics_enabled,
            "interval": self.metrics_interval,
            "latency_threshold": self.latency_threshold
        }
    
    def get_health_config(self) -> Dict[str, Any]:
        """Get health check configuration."""
        return {
            "enabled": self.health_checks_enabled,
            "interval": self.health_check_interval
        }
    
    def get_monitoring_config(self) -> Dict[str, Any]:
        """Get monitoring configuration."""
        return {
            "enabled": self.monitoring_enabled,
            "error_threshold": self.error_threshold
        }


class CorrelationIDManager:
    """Management of correlation IDs for distributed tracing."""
    
    def __init__(self):
        self.id_generator = self._id_generator()
    
    def _id_generator(self):
        """Generate unique correlation IDs."""
        import uuid
        while True:
            yield str(uuid.uuid4())
    
    def generate_id(self) -> str:
        """Generate a new correlation ID."""
        return next(self.id_generator)
    
    def validate_id(self, correlation_id: str) -> bool:
        """Validate a correlation ID format."""
        import re
        # UUID format validation
        uuid_pattern = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            re.IGNORECASE
        )
        return bool(uuid_pattern.match(correlation_id))


# Global configuration instances
audit_log_config = AuditLogConfig()
observability_config = ObservabilityConfig()
correlation_id_manager = CorrelationIDManager()


def get_audit_log_config() -> AuditLogConfig:
    """Get the global audit log configuration."""
    return audit_log_config


def get_observability_config() -> ObservabilityConfig:
    """Get the global observability configuration."""
    return observability_config


def generate_correlation_id() -> str:
    """Generate a new correlation ID."""
    return correlation_id_manager.generate_id()


def validate_correlation_id(correlation_id: str) -> bool:
    """Validate a correlation ID."""
    return correlation_id_manager.validate_id(correlation_id)


# Configuration validation
def validate_configuration() -> List[str]:
    """Validate the observability configuration."""
    errors = []
    
    # Validate audit log configuration
    audit_config = get_audit_log_config()
    sinks = audit_config.get_enabled_sinks()
    
    if not sinks:
        errors.append("No audit log sinks are enabled")
    
    for sink in sinks:
        if sink["type"] == "file":
            path = sink.get("path")
            if not path:
                errors.append("File sink missing path configuration")
    
    # Validate observability configuration
    obs_config = get_observability_config()
    
    if obs_config.metrics_interval <= 0:
        errors.append("Metrics interval must be positive")
    
    if obs_config.health_check_interval <= 0:
        errors.append("Health check interval must be positive")
    
    return errors