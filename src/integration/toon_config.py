"""
TOON Configuration Management

This module provides comprehensive configuration management for TOON serialization settings,
including environment-specific configurations, runtime adjustments, and persistent settings.
"""

from __future__ import annotations

import json
import os
import yaml
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
import logging

from src.integration.toon_enhanced import TOONVersion
from src.integration.toon_templates import TemplateType
from src.integration.toon_llm_formatter import LLMFormat


logger = logging.getLogger(__name__)


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


@dataclass
class TOONTemplatesConfig:
    """Configuration for TOON templates."""
    
    # Template settings
    default_template: Optional[TemplateType] = None
    auto_template_selection: bool = True
    template_validation_enabled: bool = True
    
    # Fleet overview template
    fleet_overview_enabled: bool = True
    fleet_overview_token_limit: int = 3000
    fleet_overview_sections: List[str] = field(default_factory=lambda: [
        "summary", "health", "issues", "operations"
    ])
    
    # Operation result template
    operation_result_enabled: bool = True
    operation_result_token_limit: int = 1000
    operation_result_sections: List[str] = field(default_factory=lambda: [
        "summary", "details", "results", "actions"
    ])
    
    # Events summary template
    events_summary_enabled: bool = True
    events_summary_token_limit: int = 1500
    events_summary_sections: List[str] = field(default_factory=lambda: [
        "statistics", "critical_events", "trends", "insights"
    ])
    
    # Health report template
    health_report_enabled: bool = True
    health_report_token_limit: int = 1300
    health_report_sections: List[str] = field(default_factory=lambda: [
        "overall_health", "component_health", "issues", "recommendations"
    ])


@dataclass
class TOONLLMConfig:
    """Configuration for LLM formatting and optimization."""
    
    # Default formatting
    default_format_style: LLMFormat = LLMFormat.CONVERSATIONAL
    default_user_expertise: str = "intermediate"
    include_recommendations: bool = True
    include_trends: bool = True
    
    # Context management
    context_window_size: int = 8000
    conversation_history_limit: int = 50
    context_compression_enabled: bool = True
    
    # Response optimization
    max_response_length: Optional[int] = None
    response_time_optimization: bool = True
    streaming_enabled: bool = False
    
    # Quality settings
    quality_threshold: float = 0.8
    auto_optimization: bool = True
    quality_validation_enabled: bool = True


@dataclass
class TOONPerformanceConfig:
    """Configuration for TOON performance optimization."""
    
    # Caching
    caching_enabled: bool = True
    cache_ttl_seconds: int = 300
    cache_max_size: int = 1000
    cache_compression: bool = True
    
    # Batching and parallelization
    batch_processing_enabled: bool = True
    batch_size: int = 100
    max_concurrent_operations: int = 4
    parallel_processing_enabled: bool = True
    
    # Memory management
    memory_limit_mb: int = 2048
    memory_threshold_percent: float = 85.0
    garbage_collection_enabled: bool = True
    memory_optimization_level: str = "moderate"  # "low", "moderate", "aggressive"
    
    # Performance monitoring
    performance_monitoring_enabled: bool = True
    metrics_retention_hours: int = 24
    alert_threshold_latency_ms: int = 1000


@dataclass
class TOONQualityConfig:
    """Configuration for TOON quality assurance."""
    
    # Quality validation
    validation_enabled: bool = True
    token_limit_enforcement: bool = True
    content_completeness_check: bool = True
    structure_validation_enabled: bool = True
    
    # Quality thresholds
    min_quality_score: float = 0.7
    auto_fix_enabled: bool = True
    quality_escalation_enabled: bool = True
    
    # Validation rules
    required_sections: List[str] = field(default_factory=lambda: [
        "summary", "status", "recommendations"
    ])
    critical_priorities: List[str] = field(default_factory=lambda: [
        "critical_issues", "errors", "health_summary"
    ])
    
    # Optimization settings
    optimization_suggestions_enabled: bool = True
    automatic_optimization: bool = False
    optimization_aggressiveness: str = "moderate"  # "conservative", "moderate", "aggressive"


@dataclass
class TOONSystemConfig:
    """Main TOON system configuration."""
    
    # Version and compatibility
    version: str = "1.0.0"
    toon_version: TOONVersion = TOONVersion.V1_1
    backward_compatibility: bool = True
    
    # Environment settings
    environment: str = "production"  # development, staging, production
    debug_mode: bool = False
    logging_level: str = "INFO"
    
    # Feature flags
    features: Dict[str, bool] = field(default_factory=lambda: {
        "enhanced_serialization": True,
        "llm_optimization": True,
        "performance_optimization": True,
        "quality_assurance": True,
        "parallel_processing": True,
        "advanced_templates": True
    })
    
    # Sub-configurations
    serialization: TOONSerializationConfig = field(default_factory=TOONSerializationConfig)
    templates: TOONTemplatesConfig = field(default_factory=TOONTemplatesConfig)
    llm: TOONLLMConfig = field(default_factory=TOONLLMConfig)
    performance: TOONPerformanceConfig = field(default_factory=TOONPerformanceConfig)
    quality: TOONQualityConfig = field(default_factory=TOONQualityConfig)
    
    # Integration settings
    integrations: Dict[str, bool] = field(default_factory=lambda: {
        "fleet_inventory": True,
        "events_system": True,
        "operations_system": True,
        "policy_system": True,
        "health_monitoring": True,
        "security_analysis": True
    })
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    config_id: str = ""


class TOONConfigManager:
    """Configuration manager for TOON system settings."""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._get_default_config_path()
        self._config: Optional[TOONSystemConfig] = None
        self._watchers: List[Callable] = []
        self._load_config()
    
    def _get_default_config_path(self) -> str:
        """Get default configuration file path."""
        # Look for config in various locations
        possible_paths = [
            "config/toon_config.yaml",
            "config/toon_config.yml",
            "toon_config.yaml",
            ".toon_config.yaml",
            os.path.expanduser("~/.toon_config.yaml")
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        # Create default config directory
        config_dir = Path("config")
        config_dir.mkdir(exist_ok=True)
        return str(config_dir / "toon_config.yaml")
    
    def _load_config(self) -> None:
        """Load configuration from file or create default."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    if self.config_path.endswith(('.yaml', '.yml')):
                        config_data = yaml.safe_load(f)
                    else:
                        config_data = json.load(f)
                
                self._config = self._dict_to_config(config_data)
                logger.info(f"Loaded TOON configuration from {self.config_path}")
            else:
                self._config = self._create_default_config()
                self.save_config()
                logger.info(f"Created default TOON configuration at {self.config_path}")
        
        except Exception as e:
            logger.error(f"Error loading TOON configuration: {e}")
            self._config = self._create_default_config()
    
    def _create_default_config(self) -> TOONSystemConfig:
        """Create default configuration."""
        config = TOONSystemConfig()
        config.config_id = f"toon_config_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        return config
    
    def _dict_to_config(self, data: Dict[str, Any]) -> TOONSystemConfig:
        """Convert dictionary to TOONSystemConfig."""
        # Convert sub-configurations
        serialization_config = TOONSerializationConfig(**data.get('serialization', {}))
        templates_config = TOONTemplatesConfig(**data.get('templates', {}))
        llm_config = TOONLLMConfig(**data.get('llm', {}))
        performance_config = TOONPerformanceConfig(**data.get('performance', {}))
        quality_config = TOONQualityConfig(**data.get('quality', {}))
        
        # Create main config
        config = TOONSystemConfig(
            version=data.get('version', '1.0.0'),
            toon_version=TOONVersion(data.get('toon_version', '1.1')),
            backward_compatibility=data.get('backward_compatibility', True),
            environment=data.get('environment', 'production'),
            debug_mode=data.get('debug_mode', False),
            logging_level=data.get('logging_level', 'INFO'),
            features=data.get('features', {}),
            integrations=data.get('integrations', {}),
            serialization=serialization_config,
            templates=templates_config,
            llm=llm_config,
            performance=performance_config,
            quality=quality_config
        )
        
        # Set metadata
        config.created_at = datetime.fromisoformat(data.get('created_at', datetime.now().isoformat()))
        config.updated_at = datetime.now()
        config.config_id = data.get('config_id', f"toon_config_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        
        return config
    
    def _config_to_dict(self, config: TOONSystemConfig) -> Dict[str, Any]:
        """Convert TOONSystemConfig to dictionary."""
        return {
            'version': config.version,
            'toon_version': config.toon_version.value,
            'backward_compatibility': config.backward_compatibility,
            'environment': config.environment,
            'debug_mode': config.debug_mode,
            'logging_level': config.logging_level,
            'features': config.features,
            'integrations': config.integrations,
            'serialization': asdict(config.serialization),
            'templates': asdict(config.templates),
            'llm': asdict(config.llm),
            'performance': asdict(config.performance),
            'quality': asdict(config.quality),
            'created_at': config.created_at.isoformat(),
            'updated_at': config.updated_at.isoformat(),
            'config_id': config.config_id
        }
    
    def save_config(self) -> None:
        """Save current configuration to file."""
        if not self._config:
            return
        
        try:
            # Update timestamp
            self._config.updated_at = datetime.now()
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            
            # Save configuration
            config_dict = self._config_to_dict(self._config)
            
            with open(self.config_path, 'w') as f:
                if self.config_path.endswith(('.yaml', '.yml')):
                    yaml.dump(config_dict, f, default_flow_style=False, indent=2)
                else:
                    json.dump(config_dict, f, indent=2, default=str)
            
            logger.info(f"Saved TOON configuration to {self.config_path}")
            
            # Notify watchers
            self._notify_watchers()
        
        except Exception as e:
            logger.error(f"Error saving TOON configuration: {e}")
            raise
    
    def get_config(self) -> TOONSystemConfig:
        """Get current configuration."""
        return self._config
    
    def update_config(self, updates: Dict[str, Any]) -> None:
        """Update configuration with new values."""
        if not self._config:
            return
        
        # Update top-level fields
        for key, value in updates.items():
            if key in ['version', 'environment', 'debug_mode', 'logging_level']:
                setattr(self._config, key, value)
            elif key == 'features':
                self._config.features.update(value)
            elif key == 'integrations':
                self._config.integrations.update(value)
            elif key == 'serialization':
                self._update_sub_config('serialization', value, TOONSerializationConfig)
            elif key == 'templates':
                self._update_sub_config('templates', value, TOONTemplatesConfig)
            elif key == 'llm':
                self._update_sub_config('llm', value, TOONLLMConfig)
            elif key == 'performance':
                self._update_sub_config('performance', value, TOONPerformanceConfig)
            elif key == 'quality':
                self._update_sub_config('quality', value, TOONQualityConfig)
        
        self.save_config()
    
    def _update_sub_config(self, config_name: str, updates: Dict[str, Any], config_class: type) -> None:
        """Update a sub-configuration."""
        if hasattr(self._config, config_name):
            current_config = getattr(self._config, config_name)
            for key, value in updates.items():
                if hasattr(current_config, key):
                    setattr(current_config, key, value)
    
    def reset_to_defaults(self) -> None:
        """Reset configuration to defaults."""
        self._config = self._create_default_config()
        self.save_config()
        logger.info("Reset TOON configuration to defaults")
    
    def validate_config(self) -> List[str]:
        """Validate current configuration."""
        errors = []
        
        if not self._config:
            errors.append("No configuration loaded")
            return errors
        
        # Validate token budgets
        if self._config.serialization.default_token_budget <= 0:
            errors.append("Default token budget must be positive")
        
        # Validate quality thresholds
        if not 0.0 <= self._config.quality.min_quality_score <= 1.0:
            errors.append("Quality score must be between 0.0 and 1.0")
        
        # Validate memory limits
        if self._config.performance.memory_limit_mb <= 0:
            errors.append("Memory limit must be positive")
        
        # Validate batch sizes
        if self._config.performance.batch_size <= 0:
            errors.append("Batch size must be positive")
        
        # Validate feature flags
        for feature, enabled in self._config.features.items():
            if not isinstance(enabled, bool):
                errors.append(f"Feature flag '{feature}' must be boolean")
        
        return errors
    
    def add_watcher(self, callback: Callable) -> None:
        """Add configuration change watcher."""
        self._watchers.append(callback)
    
    def remove_watcher(self, callback: Callable) -> None:
        """Remove configuration change watcher."""
        if callback in self._watchers:
            self._watchers.remove(callback)
    
    def _notify_watchers(self) -> None:
        """Notify all watchers of configuration changes."""
        for watcher in self._watchers:
            try:
                watcher(self._config)
            except Exception as e:
                logger.error(f"Error notifying configuration watcher: {e}")
    
    def export_config(self, export_path: str, format_type: str = "yaml") -> None:
        """Export configuration to file."""
        if not self._config:
            return
        
        config_dict = self._config_to_dict(self._config)
        
        with open(export_path, 'w') as f:
            if format_type.lower() == "yaml":
                yaml.dump(config_dict, f, default_flow_style=False, indent=2)
            else:
                json.dump(config_dict, f, indent=2, default=str)
        
        logger.info(f"Exported TOON configuration to {export_path}")
    
    def import_config(self, import_path: str) -> None:
        """Import configuration from file."""
        try:
            with open(import_path, 'r') as f:
                if import_path.endswith(('.yaml', '.yml')):
                    config_data = yaml.safe_load(f)
                else:
                    config_data = json.load(f)
            
            self._config = self._dict_to_config(config_data)
            self.save_config()
            logger.info(f"Imported TOON configuration from {import_path}")
        
        except Exception as e:
            logger.error(f"Error importing TOON configuration: {e}")
            raise
    
    def get_effective_config(self) -> Dict[str, Any]:
        """Get effective configuration with environment overrides."""
        if not self._config:
            return {}
        
        config = self._config_to_dict(self._config)
        
        # Apply environment-specific overrides
        env = self._config.environment
        if env == "development":
            config["debug_mode"] = True
            config["logging_level"] = "DEBUG"
            config["performance"]["caching_enabled"] = False
            config["quality"]["validation_enabled"] = True
        elif env == "staging":
            config["debug_mode"] = False
            config["logging_level"] = "DEBUG"
            config["performance"]["caching_enabled"] = True
        elif env == "production":
            config["debug_mode"] = False
            config["logging_level"] = "INFO"
            config["performance"]["caching_enabled"] = True
        
        return config


class TOONConfigEnvironment:
    """Environment variable configuration loader for TOON."""
    
    @staticmethod
    def load_from_env() -> Dict[str, Any]:
        """Load TOON configuration from environment variables."""
        config = {}
        
        # Serialization settings
        if token_budget := os.getenv("TOON_DEFAULT_TOKEN_BUDGET"):
            config.setdefault("serialization", {})["default_token_budget"] = int(token_budget)
        
        if compression := os.getenv("TOON_COMPRESSION_ENABLED"):
            config.setdefault("serialization", {})["compression_enabled"] = compression.lower() == "true"
        
        # LLM settings
        if format_style := os.getenv("TOON_DEFAULT_FORMAT_STYLE"):
            config.setdefault("llm", {})["default_format_style"] = format_style
        
        if expertise := os.getenv("TOON_DEFAULT_USER_EXPERTISE"):
            config.setdefault("llm", {})["default_user_expertise"] = expertise
        
        # Performance settings
        if cache_enabled := os.getenv("TOON_CACHING_ENABLED"):
            config.setdefault("performance", {})["caching_enabled"] = cache_enabled.lower() == "true"
        
        if batch_size := os.getenv("TOON_BATCH_SIZE"):
            config.setdefault("performance", {})["batch_size"] = int(batch_size)
        
        # Quality settings
        if quality_threshold := os.getenv("TOON_QUALITY_THRESHOLD"):
            config.setdefault("quality", {})["min_quality_score"] = float(quality_threshold)
        
        # System settings
        if environment := os.getenv("TOON_ENVIRONMENT"):
            config["environment"] = environment
        
        if debug_mode := os.getenv("TOON_DEBUG_MODE"):
            config["debug_mode"] = debug_mode.lower() == "true"
        
        if logging_level := os.getenv("TOON_LOGGING_LEVEL"):
            config["logging_level"] = logging_level
        
        return config
    
    @staticmethod
    def get_env_vars_doc() -> str:
        """Get documentation for environment variables."""
        return """
TOON Environment Variables:

Serialization:
- TOON_DEFAULT_TOKEN_BUDGET: Default token limit for documents (default: 4000)
- TOON_COMPRESSION_ENABLED: Enable content compression (default: true)

LLM Formatting:
- TOON_DEFAULT_FORMAT_STYLE: Default LLM format (conversational, structured, executive, technical, actionable)
- TOON_DEFAULT_USER_EXPERTISE: Default user expertise level (beginner, intermediate, expert)

Performance:
- TOON_CACHING_ENABLED: Enable document caching (default: true)
- TOON_BATCH_SIZE: Default batch processing size (default: 100)

Quality:
- TOON_QUALITY_THRESHOLD: Minimum quality score (default: 0.7)

System:
- TOON_ENVIRONMENT: Environment (development, staging, production)
- TOON_DEBUG_MODE: Enable debug mode (default: false)
- TOON_LOGGING_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR)
"""


# Global configuration manager
_config_manager: Optional[TOONConfigManager] = None


def get_config_manager() -> TOONConfigManager:
    """Get the global configuration manager."""
    global _config_manager
    if _config_manager is None:
        _config_manager = TOONConfigManager()
    return _config_manager


def get_toon_config() -> TOONSystemConfig:
    """Get current TOON configuration."""
    return get_config_manager().get_config()


def update_toon_config(updates: Dict[str, Any]) -> None:
    """Update TOON configuration."""
    get_config_manager().update_config(updates)


def reset_toon_config() -> None:
    """Reset TOON configuration to defaults."""
    get_config_manager().reset_to_defaults()


def load_toon_config_from_env() -> None:
    """Load configuration overrides from environment variables."""
    env_config = TOONConfigEnvironment.load_from_env()
    if env_config:
        get_config_manager().update_config(env_config)


# Configuration presets for different use cases
def create_development_config() -> TOONSystemConfig:
    """Create configuration optimized for development."""
    config = TOONSystemConfig()
    config.environment = "development"
    config.debug_mode = True
    config.logging_level = "DEBUG"
    config.serialization.compression_enabled = False
    config.performance.caching_enabled = False
    config.quality.validation_enabled = True
    return config


def create_production_config() -> TOONSystemConfig:
    """Create configuration optimized for production."""
    config = TOONSystemConfig()
    config.environment = "production"
    config.debug_mode = False
    config.logging_level = "INFO"
    config.serialization.compression_enabled = True
    config.performance.caching_enabled = True
    config.performance.memory_limit_mb = 4096
    config.quality.validation_enabled = True
    config.quality.auto_fix_enabled = True
    return config


def create_high_throughput_config() -> TOONSystemConfig:
    """Create configuration optimized for high throughput."""
    config = TOONSystemConfig()
    config.performance.batch_size = 500
    config.performance.max_concurrent_operations = 8
    config.performance.parallel_processing_enabled = True
    config.performance.memory_limit_mb = 8192
    config.serialization.aggressive_compression_threshold = 0.9
    return config


def create_low_latency_config() -> TOONSystemConfig:
    """Create configuration optimized for low latency."""
    config = TOONSystemConfig()
    config.performance.caching_enabled = True
    config.performance.cache_ttl_seconds = 60
    config.llm.response_time_optimization = True
    config.serialization.compact_json = True
    config.quality.auto_optimization = True
    return config