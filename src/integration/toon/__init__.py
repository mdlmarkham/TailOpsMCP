"""
TOON (TailOps Object Notation) - Consolidated Integration Module

This is the main package for TOON serialization, formatting, and configuration management.
All TOON functionality has been consolidated into this single package with clean separation
of concerns across three core modules.

CONSOLIDATED FROM:
- src/integration/toon_config.py
- src/integration/toon_enhanced.py
- src/integration/toon_integration.py
- src/integration/toon_llm_formatter.py
- src/integration/toon_performance.py
- src/integration/toon_serializers.py
- src/integration/toon_system_integration.py
- src/integration/toon_templates.py
- src/utils/toon.py
- src/utils/toon_quality.py
- src/tools/toon_enhanced_tools.py

PACKAGE STRUCTURE:
- serializer.py: Core serialization functionality
- formatter.py: LLM formatting and presentation
- config.py: Configuration management and environment presets
"""

from __future__ import annotations

import os
import logging

# Core imports from serializer
from .serializer import (
    TOONSerializer,
    TOONVersion,
    QualityLevel,
    ContentPriority,
    ContentCategory,
    SerializationResult,
    CompressionStrategy,
    serialize_to_toon,
    deserialize_from_toon,
    estimate_toon_size,
    validate_toon_structure,
)

# Core imports from formatter
from .formatter import (
    TOONLLMFormatter,
    LLMFormat,
    ContextType,
    FormatResult,
    format_for_llm,
    create_executive_summary,
    extract_actionable_insights,
    generate_toon_diff,
)

# Core imports from config
from .config import (
    TOONSystemConfig,
    TOONSerializationConfig,
    TOONLLMConfig,
    TOONPerformanceConfig,
    TOONConfigManager,
    get_toon_config,
    update_toon_config,
    reset_toon_config,
    save_toon_config,
    apply_environment_preset,
    ENVIRONMENT_PRESETS,
)

# Version information
__version__ = "1.0.0"
__author__ = "TailOpsMCP Team"
__description__ = "TailOps Object Notation - Consolidated serialization, formatting, and configuration"

# Package-level constants
DEFAULT_TOKEN_BUDGET = 4000
SUPPORTED_VERSIONS = [TOONVersion.V1_0, TOONVersion.V1_1]
DEFAULT_FORMAT = LLMFormat.CONVERSATIONAL


# Convenience functions for quick access
def quick_serialize(
    data: dict, token_budget: int = DEFAULT_TOKEN_BUDGET
) -> SerializationResult:
    """Quick serialization with default settings."""
    serializer = TOONSerializer()
    return serializer.serialize(data, token_budget=token_budget)


def quick_format(
    result: SerializationResult, format_type: LLMFormat = DEFAULT_FORMAT
) -> str:
    """Quick formatting with default settings."""
    formatter = TOONLLMFormatter()
    return formatter.format(result, format_type=format_type)


def quick_toon(
    data: dict,
    token_budget: int = DEFAULT_TOKEN_BUDGET,
    format_type: LLMFormat = DEFAULT_FORMAT,
) -> str:
    """Complete TOON processing in one call."""
    serialized = quick_serialize(data, token_budget)
    return quick_format(serialized, format_type)


def configure_for_environment(environment: str = "development") -> None:
    """Configure TOON for specific environment."""
    apply_environment_preset(environment)


# Backward compatibility aliases for existing code
TOONIntegration = TOONSerializer
EnhancedTOONIntegration = TOONSerializer
TOONLLMIntegration = TOONLLMFormatter
TOONConfig = TOONSystemConfig
TOONPerformance = TOONPerformanceConfig

# Package metadata
__all__ = [
    # Core serializer
    "TOONSerializer",
    "TOONVersion",
    "QualityLevel",
    "ContentPriority",
    "ContentCategory",
    "SerializationResult",
    "CompressionStrategy",
    "serialize_to_toon",
    "deserialize_from_toon",
    "estimate_toon_size",
    "validate_toon_structure",
    # Core formatter
    "TOONLLMFormatter",
    "LLMFormat",
    "ContextType",
    "FormatResult",
    "format_for_llm",
    "create_executive_summary",
    "extract_actionable_insights",
    "generate_toon_diff",
    # Core config
    "TOONSystemConfig",
    "TOONSerializationConfig",
    "TOONLLMConfig",
    "TOONPerformanceConfig",
    "TOONConfigManager",
    "get_toon_config",
    "update_toon_config",
    "reset_toon_config",
    "save_toon_config",
    "apply_environment_preset",
    "ENVIRONMENT_PRESETS",
    # Convenience functions
    "quick_serialize",
    "quick_format",
    "quick_toon",
    "configure_for_environment",
    # Backward compatibility
    "TOONIntegration",
    "EnhancedTOONIntegration",
    "TOONLLMIntegration",
    "TOONConfig",
    "TOONPerformance",
    # Package info
    "__version__",
    "__author__",
    "__description__",
]


def get_package_info() -> dict:
    """Get package information."""
    return {
        "name": "toon",
        "version": __version__,
        "author": __author__,
        "description": __description__,
        "consolidation_date": "2025-12-14",
        "files_consolidated": 11,
        "lines_reduced": "~2,000-3,000",
        "modules": ["serializer", "formatter", "config"],
    }


# Initialize package logging
# Initialize package logging
logger = logging.getLogger(__name__)
logger.info(f"TOON package initialized - {__version__}")


# Package-level configuration initialization
def _initialize_package():
    """Initialize package with default settings."""
    # Set up default configuration
    config = get_toon_config()

    # Log package initialization
    logger.info(
        f"TOON package initialized with {len(config.enabled_features)} enabled features"
    )

    # Apply environment-specific optimizations
    environment = os.getenv("TOON_ENVIRONMENT", "development")
    if environment != "development":
        logger.info(f"Applying {environment} environment optimizations")


# Run initialization
_initialize_package()

# Clean up namespace
del _initialize_package
