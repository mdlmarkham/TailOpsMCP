"""
Configuration management for TailOpsMCP observability system.

This module provides comprehensive configuration management including YAML configuration files,
environment variables, validation, and default settings for the observability platform.
"""

import os
import yaml
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field, asdict

from src.utils.logging_config import get_logger


@dataclass
class EventCollectionConfig:
    """Configuration for event collection."""

    enabled: bool = True
    interval: int = 60  # seconds
    batch_size: int = 100
    timeout: int = 30
    retry_attempts: int = 3
    retry_delay: int = 5  # seconds

    sources: List[str] = field(
        default_factory=lambda: [
            "fleet_inventory",
            "policy_engine",
            "security_audit",
            "remote_agent",
            "discovery_pipeline",
            "proxmox_api",
        ]
    )

    filters: Dict[str, Any] = field(default_factory=dict)

    # Source-specific configurations
    fleet_inventory_config: Dict[str, Any] = field(
        default_factory=lambda: {
            "health_check_interval": 300,
            "resource_check_interval": 60,
            "enabled": True,
        }
    )

    policy_engine_config: Dict[str, Any] = field(
        default_factory=lambda: {
            "violation_check_interval": 60,
            "audit_check_interval": 300,
            "enabled": True,
        }
    )

    security_audit_config: Dict[str, Any] = field(
        default_factory=lambda: {
            "audit_interval": 300,
            "log_level_filter": "INFO",
            "enabled": True,
        }
    )

    remote_agent_config: Dict[str, Any] = field(
        default_factory=lambda: {"service_status_interval": 60, "enabled": True}
    )

    discovery_pipeline_config: Dict[str, Any] = field(
        default_factory=lambda: {"discovery_interval": 600, "enabled": True}
    )

    proxmox_config: Dict[str, Any] = field(
        default_factory=lambda: {
            "container_check_interval": 120,
            "resource_check_interval": 300,
            "enabled": True,
        }
    )


@dataclass
class EventStorageConfig:
    """Configuration for event storage."""

    # Database settings
    database_path: str = "./data/events.db"
    backup_enabled: bool = True
    backup_interval: int = 86400  # 24 hours
    backup_retention_days: int = 30

    # Performance settings
    max_events: int = 1000000
    retention_days: int = 90
    compression: bool = True
    auto_cleanup: bool = True
    cleanup_interval: int = 3600  # 1 hour

    # Indexing
    enable_full_text_search: bool = True
    indexes: List[str] = field(
        default_factory=lambda: [
            "timestamp",
            "event_type",
            "severity",
            "source",
            "target",
            "category",
        ]
    )

    # Connection settings
    connection_pool_size: int = 10
    connection_timeout: int = 30


@dataclass
class EventAnalysisConfig:
    """Configuration for event analysis."""

    enabled: bool = True
    analysis_interval: int = 300  # 5 minutes

    # Analysis features
    trend_analysis: bool = True
    anomaly_detection: bool = True
    pattern_recognition: bool = True
    predictive_analytics: bool = True

    # Analysis parameters
    trend_window_hours: int = 24
    anomaly_threshold: float = 2.0  # Standard deviations
    pattern_min_frequency: int = 3
    prediction_horizon_hours: int = 24

    # Machine learning settings
    ml_enabled: bool = False
    model_retrain_interval: int = 86400  # 24 hours
    confidence_threshold: float = 0.7


@dataclass
class EventProcessingConfig:
    """Configuration for event processing."""

    enabled: bool = True
    buffer_size: int = 1000
    batch_size: int = 50
    batch_timeout: float = 5.0  # seconds
    processing_interval: float = 1.0  # seconds

    # WebSocket settings
    websocket_enabled: bool = True
    websocket_port: int = 8765
    websocket_host: str = "localhost"

    # Filter settings
    filters: List[Dict[str, Any]] = field(default_factory=list)

    # Performance settings
    max_concurrent_processors: int = 4
    memory_limit_mb: int = 512


@dataclass
class AlertingConfig:
    """Configuration for alerting system."""

    enabled: bool = True
    evaluation_interval: int = 60  # seconds

    # Notification channels
    email_enabled: bool = False
    slack_enabled: bool = False
    webhook_enabled: bool = False
    console_enabled: bool = True

    # Channel configurations
    email_config: Dict[str, Any] = field(
        default_factory=lambda: {
            "smtp_host": "",
            "smtp_port": 587,
            "username": "",
            "password": "",
            "use_tls": True,
            "recipients": [],
        }
    )

    slack_config: Dict[str, Any] = field(
        default_factory=lambda: {
            "webhook_url": "",
            "channel": "#alerts",
            "username": "TailOpsMCP",
        }
    )

    webhook_config: Dict[str, Any] = field(
        default_factory=lambda: {"urls": {}, "timeout": 10, "retry_attempts": 3}
    )

    # Alert rules
    default_rules: List[Dict[str, Any]] = field(default_factory=list)

    # Escalation settings
    escalation_enabled: bool = True
    max_escalation_levels: int = 3
    escalation_delays: List[int] = field(
        default_factory=lambda: [15, 30, 60]
    )  # minutes


@dataclass
class ReportingConfig:
    """Configuration for reporting system."""

    enabled: bool = True

    # Report generation
    auto_generate_reports: bool = True
    report_interval: int = 3600  # 1 hour

    # Report types
    health_reports: bool = True
    security_reports: bool = True
    operational_reports: bool = True
    compliance_reports: bool = True

    # Export settings
    export_formats: List[str] = field(default_factory=lambda: ["json", "html"])
    export_directory: str = "./reports"

    # Dashboard settings
    dashboard_enabled: bool = True
    dashboard_refresh_interval: int = 60  # seconds
    dashboard_port: int = 8080
    dashboard_host: str = "localhost"


@dataclass
class ObservabilityConfig:
    """Main configuration for the observability system."""

    # System settings
    system_name: str = "TailOpsMCP"
    version: str = "1.0.0"
    debug: bool = False
    log_level: str = "INFO"

    # Component configurations
    event_collection: EventCollectionConfig = field(
        default_factory=EventCollectionConfig
    )
    event_storage: EventStorageConfig = field(default_factory=EventStorageConfig)
    event_analysis: EventAnalysisConfig = field(default_factory=EventAnalysisConfig)
    event_processing: EventProcessingConfig = field(
        default_factory=EventProcessingConfig
    )
    alerting: AlertingConfig = field(default_factory=AlertingConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)

    # Security settings
    security: Dict[str, Any] = field(
        default_factory=lambda: {
            "encryption_enabled": True,
            "api_authentication": True,
            "rate_limiting": True,
            "audit_logging": True,
        }
    )

    # Performance settings
    performance: Dict[str, Any] = field(
        default_factory=lambda: {
            "max_workers": 4,
            "memory_limit_mb": 1024,
            "cpu_limit_percent": 80,
            "disk_usage_limit_percent": 85,
        }
    )

    # Integration settings
    integrations: Dict[str, Any] = field(
        default_factory=lambda: {
            "fleet_inventory": {"enabled": True, "priority": 1},
            "policy_engine": {"enabled": True, "priority": 2},
            "security_audit": {"enabled": True, "priority": 3},
            "remote_agent": {"enabled": True, "priority": 4},
            "discovery_pipeline": {"enabled": True, "priority": 5},
            "proxmox_api": {"enabled": True, "priority": 6},
        }
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        result = asdict(self)

        # Convert dataclass fields to dictionaries
        result["event_collection"] = asdict(self.event_collection)
        result["event_storage"] = asdict(self.event_storage)
        result["event_analysis"] = asdict(self.event_analysis)
        result["event_processing"] = asdict(self.event_processing)
        result["alerting"] = asdict(self.alerting)
        result["reporting"] = asdict(self.reporting)

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ObservabilityConfig":
        """Create configuration from dictionary."""
        # Extract dataclass fields
        collection_config = EventCollectionConfig(**data.get("event_collection", {}))
        storage_config = EventStorageConfig(**data.get("event_storage", {}))
        analysis_config = EventAnalysisConfig(**data.get("event_analysis", {}))
        processing_config = EventProcessingConfig(**data.get("event_processing", {}))
        alerting_config = AlertingConfig(**data.get("alerting", {}))
        reporting_config = ReportingConfig(**data.get("reporting", {}))

        return cls(
            system_name=data.get("system_name", "TailOpsMCP"),
            version=data.get("version", "1.0.0"),
            debug=data.get("debug", False),
            log_level=data.get("log_level", "INFO"),
            event_collection=collection_config,
            event_storage=storage_config,
            event_analysis=analysis_config,
            event_processing=processing_config,
            alerting=alerting_config,
            reporting=reporting_config,
            security=data.get("security", {}),
            performance=data.get("performance", {}),
            integrations=data.get("integrations", {}),
        )


class ConfigManager:
    """Configuration manager for the observability system."""

    def __init__(self, config_path: Optional[str] = None):
        self.logger = get_logger("config_manager")
        self.config_path = config_path or os.getenv(
            "OBSERVABILITY_CONFIG_PATH", "./config/observability.yaml"
        )
        self.config: Optional[ObservabilityConfig] = None
        self._config_cache = {}

    def load_config(self) -> ObservabilityConfig:
        """Load configuration from file and environment variables."""
        try:
            # Try to load from file
            if os.path.exists(self.config_path):
                self.logger.info(f"Loading configuration from {self.config_path}")
                with open(self.config_path, "r") as f:
                    config_data = yaml.safe_load(f)
            else:
                self.logger.info("Configuration file not found, using defaults")
                config_data = {}

            # Override with environment variables
            config_data = self._apply_environment_overrides(config_data)

            # Create configuration object
            self.config = ObservabilityConfig.from_dict(config_data)

            # Validate configuration
            self._validate_config(self.config)

            self.logger.info("Configuration loaded successfully")
            return self.config

        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            # Return default configuration as fallback
            self.config = ObservabilityConfig()
            return self.config

    def _apply_environment_overrides(
        self, config_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Apply environment variable overrides to configuration."""

        # System settings
        if os.getenv("OBSERVABILITY_DEBUG"):
            config_data["debug"] = os.getenv("OBSERVABILITY_DEBUG").lower() == "true"

        if os.getenv("OBSERVABILITY_LOG_LEVEL"):
            config_data["log_level"] = os.getenv("OBSERVABILITY_LOG_LEVEL")

        # Event collection settings
        if os.getenv("EVENT_COLLECTION_INTERVAL"):
            config_data.setdefault("event_collection", {})["interval"] = int(
                os.getenv("EVENT_COLLECTION_INTERVAL")
            )

        if os.getenv("EVENT_COLLECTION_ENABLED"):
            config_data.setdefault("event_collection", {})["enabled"] = (
                os.getenv("EVENT_COLLECTION_ENABLED").lower() == "true"
            )

        # Event storage settings
        if os.getenv("EVENT_DB_PATH"):
            config_data.setdefault("event_storage", {})["database_path"] = os.getenv(
                "EVENT_DB_PATH"
            )

        if os.getenv("EVENT_RETENTION_DAYS"):
            config_data.setdefault("event_storage", {})["retention_days"] = int(
                os.getenv("EVENT_RETENTION_DAYS")
            )

        # Event processing settings
        if os.getenv("WEBSOCKET_ENABLED"):
            config_data.setdefault("event_processing", {})["websocket_enabled"] = (
                os.getenv("WEBSOCKET_ENABLED").lower() == "true"
            )

        if os.getenv("WEBSOCKET_PORT"):
            config_data.setdefault("event_processing", {})["websocket_port"] = int(
                os.getenv("WEBSOCKET_PORT")
            )

        # Alerting settings
        if os.getenv("ALERTING_ENABLED"):
            config_data.setdefault("alerting", {})["enabled"] = (
                os.getenv("ALERTING_ENABLED").lower() == "true"
            )

        if os.getenv("EMAIL_ENABLED"):
            config_data.setdefault("alerting", {})["email_enabled"] = (
                os.getenv("EMAIL_ENABLED").lower() == "true"
            )

        if os.getenv("SMTP_HOST"):
            config_data.setdefault("alerting", {}).setdefault("email_config", {})[
                "smtp_host"
            ] = os.getenv("SMTP_HOST")

        if os.getenv("SMTP_USERNAME"):
            config_data.setdefault("alerting", {}).setdefault("email_config", {})[
                "username"
            ] = os.getenv("SMTP_USERNAME")

        if os.getenv("SMTP_PASSWORD"):
            config_data.setdefault("alerting", {}).setdefault("email_config", {})[
                "password"
            ] = os.getenv("SMTP_PASSWORD")

        if os.getenv("SLACK_ENABLED"):
            config_data.setdefault("alerting", {})["slack_enabled"] = (
                os.getenv("SLACK_ENABLED").lower() == "true"
            )

        if os.getenv("SLACK_WEBHOOK_URL"):
            config_data.setdefault("alerting", {}).setdefault("slack_config", {})[
                "webhook_url"
            ] = os.getenv("SLACK_WEBHOOK_URL")

        # Reporting settings
        if os.getenv("REPORTING_ENABLED"):
            config_data.setdefault("reporting", {})["enabled"] = (
                os.getenv("REPORTING_ENABLED").lower() == "true"
            )

        if os.getenv("AUTO_GENERATE_REPORTS"):
            config_data.setdefault("reporting", {})["auto_generate_reports"] = (
                os.getenv("AUTO_GENERATE_REPORTS").lower() == "true"
            )

        if os.getenv("EXPORT_DIRECTORY"):
            config_data.setdefault("reporting", {})["export_directory"] = os.getenv(
                "EXPORT_DIRECTORY"
            )

        return config_data

    def _validate_config(self, config: ObservabilityConfig) -> None:
        """Validate configuration settings."""
        errors = []

        # Validate event collection
        if config.event_collection.interval <= 0:
            errors.append("Event collection interval must be positive")

        if config.event_collection.batch_size <= 0:
            errors.append("Event collection batch size must be positive")

        # Validate event storage
        if not config.event_storage.database_path:
            errors.append("Database path cannot be empty")

        if config.event_storage.retention_days <= 0:
            errors.append("Retention days must be positive")

        # Validate event processing
        if (
            config.event_processing.websocket_port <= 0
            or config.event_processing.websocket_port > 65535
        ):
            errors.append("WebSocket port must be between 1 and 65535")

        # Validate alerting
        if config.alerting.evaluation_interval <= 0:
            errors.append("Alert evaluation interval must be positive")

        # Validate reporting
        if (
            config.reporting.dashboard_port <= 0
            or config.reporting.dashboard_port > 65535
        ):
            errors.append("Dashboard port must be between 1 and 65535")

        if errors:
            raise ValueError(f"Configuration validation failed: {', '.join(errors)}")

    def save_config(
        self, config: ObservabilityConfig, path: Optional[str] = None
    ) -> None:
        """Save configuration to file."""
        try:
            save_path = path or self.config_path

            # Ensure directory exists
            os.makedirs(os.path.dirname(save_path), exist_ok=True)

            # Convert to dictionary and save
            config_data = config.to_dict()

            with open(save_path, "w") as f:
                yaml.dump(config_data, f, default_flow_style=False, indent=2)

            self.logger.info(f"Configuration saved to {save_path}")

        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
            raise

    def get_config(self) -> ObservabilityConfig:
        """Get current configuration."""
        if self.config is None:
            self.config = self.load_config()
        return self.config

    def update_config(self, updates: Dict[str, Any]) -> ObservabilityConfig:
        """Update configuration with new values."""
        current_config = self.get_config()

        # Create updated configuration
        updated_data = current_config.to_dict()
        updated_data.update(updates)

        # Create new configuration object
        self.config = ObservabilityConfig.from_dict(updated_data)

        # Validate updated configuration
        self._validate_config(self.config)

        self.logger.info("Configuration updated successfully")
        return self.config

    def create_default_config(self, output_path: str) -> None:
        """Create a default configuration file."""
        default_config = ObservabilityConfig()
        self.save_config(default_config, output_path)
        self.logger.info(f"Default configuration created at {output_path}")

    def get_config_summary(self) -> Dict[str, Any]:
        """Get configuration summary for display."""
        config = self.get_config()

        return {
            "system": {
                "name": config.system_name,
                "version": config.version,
                "debug": config.debug,
                "log_level": config.log_level,
            },
            "components": {
                "event_collection": {
                    "enabled": config.event_collection.enabled,
                    "interval": config.event_collection.interval,
                    "sources": len(config.event_collection.sources),
                },
                "event_storage": {
                    "enabled": True,
                    "database_path": config.event_storage.database_path,
                    "retention_days": config.event_storage.retention_days,
                },
                "event_analysis": {
                    "enabled": config.event_analysis.enabled,
                    "trend_analysis": config.event_analysis.trend_analysis,
                    "anomaly_detection": config.event_analysis.anomaly_detection,
                },
                "event_processing": {
                    "enabled": config.event_processing.enabled,
                    "websocket_enabled": config.event_processing.websocket_enabled,
                    "websocket_port": config.event_processing.websocket_port,
                },
                "alerting": {
                    "enabled": config.alerting.enabled,
                    "email_enabled": config.alerting.email_enabled,
                    "slack_enabled": config.alerting.slack_enabled,
                },
                "reporting": {
                    "enabled": config.reporting.enabled,
                    "auto_generate": config.reporting.auto_generate_reports,
                    "export_formats": config.reporting.export_formats,
                },
            },
            "integrations": {
                name: details["enabled"]
                for name, details in config.integrations.items()
            },
        }


# Default configuration templates


def get_default_config_template() -> Dict[str, Any]:
    """Get default configuration template."""
    return {
        "system_name": "TailOpsMCP",
        "version": "1.0.0",
        "debug": False,
        "log_level": "INFO",
        "event_collection": {
            "enabled": True,
            "interval": 60,
            "batch_size": 100,
            "sources": [
                "fleet_inventory",
                "policy_engine",
                "security_audit",
                "remote_agent",
                "discovery_pipeline",
                "proxmox_api",
            ],
        },
        "event_storage": {
            "database_path": "./data/events.db",
            "max_events": 1000000,
            "retention_days": 90,
            "compression": True,
            "auto_cleanup": True,
        },
        "event_analysis": {
            "enabled": True,
            "trend_analysis": True,
            "anomaly_detection": True,
            "pattern_recognition": True,
            "predictive_analytics": True,
        },
        "event_processing": {
            "enabled": True,
            "websocket_enabled": True,
            "websocket_port": 8765,
            "buffer_size": 1000,
        },
        "alerting": {
            "enabled": True,
            "evaluation_interval": 60,
            "email_enabled": False,
            "slack_enabled": False,
            "console_enabled": True,
        },
        "reporting": {
            "enabled": True,
            "auto_generate_reports": True,
            "export_formats": ["json", "html"],
            "export_directory": "./reports",
        },
    }


def create_config_from_environment() -> ObservabilityConfig:
    """Create configuration from environment variables only."""
    config_data = {}

    # Apply environment variable overrides
    manager = ConfigManager()
    config_data = manager._apply_environment_overrides(config_data)

    return ObservabilityConfig.from_dict(config_data)


# Global configuration manager instance
_config_manager_instance = None


def get_config_manager() -> ConfigManager:
    """Get the global configuration manager instance."""
    global _config_manager_instance
    if _config_manager_instance is None:
        _config_manager_instance = ConfigManager()
    return _config_manager_instance


def get_observability_config() -> ObservabilityConfig:
    """Get the global observability configuration."""
    manager = get_config_manager()
    return manager.get_config()


# Configuration validation
def validate_observability_config(config: ObservabilityConfig) -> List[str]:
    """Validate observability configuration and return any errors."""
    errors = []

    try:
        manager = ConfigManager()
        manager._validate_config(config)
    except ValueError as e:
        errors.append(str(e))
    except Exception as e:
        errors.append(f"Configuration validation error: {e}")

    return errors


# Environment variable documentation
ENVIRONMENT_VARIABLES = {
    # System settings
    "OBSERVABILITY_CONFIG_PATH": "Path to configuration file",
    "OBSERVABILITY_DEBUG": "Enable debug mode (true/false)",
    "OBSERVABILITY_LOG_LEVEL": "Logging level (DEBUG, INFO, WARNING, ERROR)",
    # Event collection
    "EVENT_COLLECTION_ENABLED": "Enable event collection (true/false)",
    "EVENT_COLLECTION_INTERVAL": "Event collection interval in seconds",
    # Event storage
    "EVENT_DB_PATH": "Path to event database",
    "EVENT_RETENTION_DAYS": "Event retention period in days",
    # Event processing
    "WEBSOCKET_ENABLED": "Enable WebSocket server (true/false)",
    "WEBSOCKET_PORT": "WebSocket server port",
    # Alerting
    "ALERTING_ENABLED": "Enable alerting system (true/false)",
    "EMAIL_ENABLED": "Enable email notifications (true/false)",
    "SMTP_HOST": "SMTP server hostname",
    "SMTP_USERNAME": "SMTP username",
    "SMTP_PASSWORD": "SMTP password",
    "SLACK_ENABLED": "Enable Slack notifications (true/false)",
    "SLACK_WEBHOOK_URL": "Slack webhook URL",
    # Reporting
    "REPORTING_ENABLED": "Enable reporting system (true/false)",
    "AUTO_GENERATE_REPORTS": "Auto-generate reports (true/false)",
    "EXPORT_DIRECTORY": "Directory for exported reports",
}


def print_environment_variables_help():
    """Print help information about environment variables."""
    print("Environment Variables for TailOpsMCP Observability System")
    print("=" * 60)

    for var, description in ENVIRONMENT_VARIABLES.items():
        current_value = os.getenv(var, "(not set)")
        print(f"{var}:")
        print(f"  Description: {description}")
        print(f"  Current value: {current_value}")
        print()


def create_sample_config_file(output_path: str = "./config/observability.yaml"):
    """Create a sample configuration file."""
    sample_config = get_default_config_template()

    # Ensure directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w") as f:
        yaml.dump(sample_config, f, default_flow_style=False, indent=2)

    print(f"Sample configuration file created at: {output_path}")
    print("Please review and customize the configuration as needed.")
