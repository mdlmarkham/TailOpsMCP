"""
TOON Configuration Management Module

This module provides comprehensive configuration management for TOON serialization settings,
including environment-specific configurations, runtime adjustments, and persistent settings.

CONSOLIDATED: All configuration management in one place.
- Serialization behavior configuration
- Environment-specific settings
- Performance tuning parameters
- Template and formatting configurations
- Runtime configuration management
"""

from __future__ import annotations

import json
import os
import yaml
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
import logging

from .serializer import TOONVersion
from .formatter import LLMFormat, ContextType

logger = logging.getLogger(__name__)


# Configuration Data Classes
@dataclass
class TOONSerializationConfig:
    """Configuration for TOON serialization behavior."""

    default_token_budget: int = 4000
    compression_enabled: bool = True
    smart_prioritization: bool = True
    preserve_structure: bool = True
    enable_tabular_format: bool = True
    enable_diffs: bool = True

    # Token optimization
    min_token_efficiency: float = 0.6
    max_content_length: int = 50000
    aggressive_compression_threshold: float = 0.8

    # Serialization options
    compact_json: bool = True
    preserve_order: bool = False
    include_metadata: bool = True
    include_timestamps: bool = True

    # Performance settings
    cache_size: int = 100
    enable_caching: bool = True
    parallel_processing: bool = True
    max_workers: int = 4


@dataclass
class TOONLLMConfig:
    """Configuration for LLM formatting behavior."""

    default_format: LLMFormat = LLMFormat.CONVERSATIONAL
    default_context: ContextType = ContextType.INITIAL_QUERY
    max_tokens_per_response: int = 4000
    include_executive_summary: bool = True
    include_actionable_insights: bool = True
    prioritize_critical_content: bool = True

    # Formatting preferences
    user_expertise_level: str = "intermediate"
    business_focus: bool = True
    action_orientation: bool = False
    include_technical_details: bool = True

    # Content filtering
    exclude_debug_content: bool = True
    exclude_verbose_content: bool = False
    min_priority_level: int = 3  # ContentPriority.INFO = 3

    # Summary generation
    executive_summary_max_length: int = 300
    max_actionable_items: int = 5
    max_key_insights: int = 3


@dataclass
class TOONPerformanceConfig:
    """Configuration for TOON performance optimization."""

    # Memory management
    max_memory_usage_mb: int = 512
    cache_ttl_seconds: int = 3600
    enable_memory_monitoring: bool = True

    # Processing optimization
    batch_size: int = 50
    enable_parallel_serialization: bool = True
    enable_async_processing: bool = False

    # Quality assurance
    quality_threshold: float = 0.7
    enable_quality_checks: bool = True
    auto_optimization: bool = True

    # Monitoring and metrics
    enable_performance_metrics: bool = True
    log_slow_operations: bool = True
    slow_operation_threshold_ms: int = 1000


@dataclass
class TOONSystemConfig:
    """Complete TOON system configuration."""

    # Core settings
    version: str = "1.0.0"
    toon_version: TOONVersion = TOONVersion.V1_1
    backward_compatibility: bool = True

    # Feature flags
    enabled_features: List[str] = field(
        default_factory=lambda: [
            "serialization",
            "formatting",
            "caching",
            "quality_checks",
        ]
    )

    # Component configurations
    serialization: TOONSerializationConfig = field(
        default_factory=TOONSerializationConfig
    )
    llm_formatting: TOONLLMConfig = field(default_factory=TOONLLMConfig)
    performance: TOONPerformanceConfig = field(default_factory=TOONPerformanceConfig)

    # Environment settings
    environment: str = "development"  # development, staging, production
    debug_mode: bool = False
    log_level: str = "INFO"

    # Runtime settings
    config_id: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    def __post_init__(self):
        if not self.config_id:
            self.config_id = f"toon_config_{datetime.now().strftime('%Y%m%d_%H%M%S')}"


# Configuration Manager
class TOONConfigManager:
    """Manages TOON configuration loading, saving, and updates."""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.config: Optional[TOONSystemConfig] = None
        self._config_lock = threading.Lock() if "threading" in globals() else None

    def load_config(self) -> TOONSystemConfig:
        """Load configuration from file or environment."""
        # Try to load from file first
        if self.config_path and os.path.exists(self.config_path):
            try:
                return self._load_from_file(self.config_path)
            except Exception as e:
                logger.warning(f"Failed to load config from {self.config_path}: {e}")

        # Try environment variables
        if self._has_env_overrides():
            return self._load_from_environment()

        # Return default configuration
        return TOONSystemConfig()

    def save_config(
        self, config: TOONSystemConfig, config_path: Optional[str] = None
    ) -> None:
        """Save configuration to file."""
        save_path = config_path or self.config_path
        if not save_path:
            raise ValueError("No configuration path provided")

        # Update timestamp
        config.updated_at = datetime.now()

        try:
            os.makedirs(os.path.dirname(save_path), exist_ok=True)

            with open(save_path, "w") as f:
                if save_path.endswith(".yaml") or save_path.endswith(".yml"):
                    yaml.dump(asdict(config), f, default_flow_style=False, indent=2)
                else:
                    json.dump(asdict(config), f, indent=2, default=str)

            logger.info(f"Configuration saved to {save_path}")
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            raise

    def update_config(self, updates: Dict[str, Any]) -> TOONSystemConfig:
        """Update configuration with new values."""
        if not self.config:
            self.config = self.load_config()

        # Apply updates to configuration
        self._apply_updates(self.config, updates)
        self.config.updated_at = datetime.now()

        return self.config

    def reset_to_defaults(self) -> TOONSystemConfig:
        """Reset configuration to default values."""
        self.config = TOONSystemConfig()
        return self.config

    def get_config_path(self) -> str:
        """Get default configuration path."""
        # Try various common locations
        possible_paths = [
            "config/toon_config.yaml",
            "config/toon_config.yml",
            "toon_config.yaml",
            ".toon_config.yaml",
            os.path.expanduser("~/.toon_config.yaml"),
        ]

        for path in possible_paths:
            if os.path.exists(path):
                return path

        # Create default path
        config_dir = Path("config")
        config_dir.mkdir(exist_ok=True)
        return str(config_dir / "toon_config.yaml")

    def _load_from_file(self, config_path: str) -> TOONSystemConfig:
        """Load configuration from file."""
        with open(config_path, "r") as f:
            if config_path.endswith(".yaml") or config_path.endswith(".yml"):
                data = yaml.safe_load(f)
            else:
                data = json.load(f)

        config = TOONSystemConfig()

        # Apply loaded data
        if "version" in data:
            config.version = data["version"]
        if "toon_version" in data:
            config.toon_version = TOONVersion(data["toon_version"])
        if "backward_compatibility" in data:
            config.backward_compatibility = data["backward_compatibility"]
        if "enabled_features" in data:
            config.enabled_features = data["enabled_features"]

        # Load sub-configurations
        if "serialization" in data:
            config.serialization = TOONSerializationConfig(**data["serialization"])
        if "llm_formatting" in data:
            config.llm_formatting = TOONLLMConfig(**data["llm_formatting"])
        if "performance" in data:
            config.performance = TOONPerformanceConfig(**data["performance"])

        # Set timestamps
        config.created_at = datetime.now()
        config.updated_at = datetime.now()
        config.config_id = data.get(
            "config_id", f"toon_config_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )

        return config

    def _load_from_environment(self) -> TOONSystemConfig:
        """Load configuration from environment variables."""
        config = TOONSystemConfig()

        # Environment overrides
        if os.getenv("TOON_VERSION"):
            config.version = os.getenv("TOON_VERSION")
        if os.getenv("TOON_FORMAT"):
            config.llm_formatting.default_format = LLMFormat(os.getenv("TOON_FORMAT"))
        if os.getenv("TOON_TOKEN_BUDGET"):
            config.serialization.default_token_budget = int(
                os.getenv("TOON_TOKEN_BUDGET")
            )
        if os.getenv("TOON_CACHE_SIZE"):
            config.serialization.cache_size = int(os.getenv("TOON_CACHE_SIZE"))
        if os.getenv("TOON_ENVIRONMENT"):
            config.environment = os.getenv("TOON_ENVIRONMENT")

        return config

    def _has_env_overrides(self) -> bool:
        """Check if there are environment variable overrides."""
        env_vars = [
            "TOON_VERSION",
            "TOON_FORMAT",
            "TOON_TOKEN_BUDGET",
            "TOON_CACHE_SIZE",
            "TOON_ENVIRONMENT",
        ]
        return any(os.getenv(var) for var in env_vars)

    def _apply_updates(self, config: TOONSystemConfig, updates: Dict[str, Any]) -> None:
        """Apply updates to configuration object."""
        for key, value in updates.items():
            if hasattr(config, key):
                setattr(config, key, value)
            elif key == "serialization" and isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    if hasattr(config.serialization, sub_key):
                        setattr(config.serialization, sub_key, sub_value)
            elif key == "llm_formatting" and isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    if hasattr(config.llm_formatting, sub_key):
                        setattr(config.llm_formatting, sub_key, sub_value)
            elif key == "performance" and isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    if hasattr(config.performance, sub_key):
                        setattr(config.performance, sub_key, sub_value)


# Global Configuration Manager
_config_manager = TOONConfigManager()


# Convenience Functions
def get_toon_config() -> TOONSystemConfig:
    """Get current TOON configuration."""
    global _config_manager
    if _config_manager.config is None:
        _config_manager.config = _config_manager.load_config()
    return _config_manager.config


def update_toon_config(updates: Dict[str, Any]) -> None:
    """Update TOON configuration."""
    global _config_manager
    _config_manager.config = _config_manager.update_config(updates)


def reset_toon_config() -> None:
    """Reset TOON configuration to defaults."""
    global _config_manager
    _config_manager.config = _config_manager.reset_to_defaults()


def load_toon_config_from_env() -> None:
    """Load configuration overrides from environment variables."""
    global _config_manager
    env_config = _config_manager._load_from_environment()

    # Merge with existing config
    if _config_manager.config:
        _config_manager._apply_updates(_config_manager.config, asdict(env_config))
    else:
        _config_manager.config = env_config


def save_toon_config(config_path: Optional[str] = None) -> None:
    """Save current TOON configuration to file."""
    global _config_manager
    if _config_manager.config is None:
        _config_manager.config = _config_manager.load_config()

    save_path = config_path or _config_manager.get_config_path()
    _config_manager.save_config(_config_manager.config, save_path)


# Configuration presets for different environments
ENVIRONMENT_PRESETS = {
    "development": {
        "debug_mode": True,
        "log_level": "DEBUG",
        "serialization": {
            "cache_size": 50,
            "enable_caching": False,
            "compact_json": False,
        },
        "llm_formatting": {
            "include_technical_details": True,
            "exclude_debug_content": False,
        },
    },
    "staging": {
        "debug_mode": False,
        "log_level": "INFO",
        "serialization": {"cache_size": 100, "enable_caching": True},
        "performance": {
            "enable_performance_metrics": True,
            "log_slow_operations": True,
        },
    },
    "production": {
        "debug_mode": False,
        "log_level": "WARNING",
        "serialization": {
            "cache_size": 200,
            "enable_caching": True,
            "compression_enabled": True,
        },
        "llm_formatting": {
            "exclude_debug_content": True,
            "exclude_verbose_content": True,
        },
        "performance": {
            "enable_memory_monitoring": True,
            "enable_performance_metrics": True,
        },
    },
}


def apply_environment_preset(environment: str) -> None:
    """Apply configuration preset for specific environment."""
    if environment not in ENVIRONMENT_PRESETS:
        logger.warning(f"Unknown environment preset: {environment}")
        return

    preset = ENVIRONMENT_PRESETS[environment]
    update_toon_config(preset)

    logger.info(f"Applied {environment} environment preset")


# Initialize threading if available
try:
    import threading

    _config_manager._config_lock = threading.Lock()
except (ImportError, NameError, AttributeError):
    pass
