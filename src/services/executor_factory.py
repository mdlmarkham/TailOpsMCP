"""
Executor Factory Module - Simplified Factory Pattern

This module provides factory methods for creating different types of executors.
This factory is deprecated in favor of the unified executor.py module,
but kept for backward compatibility.
"""

import logging
from typing import Any, Dict, Optional

from src.services.executor import (
    Executor,
    ExecutorConfig,
    ExecutorType,
    LocalExecutor,
    SSHExecutor,
    DockerExecutor,
)

logger = logging.getLogger(__name__)


class ExecutorFactory:
    """Factory for creating executors."""

    def __init__(self) -> None:
        """Initialize executor factory."""
        self.executors = {}

    def create_executor(self, executor_type: str, **kwargs) -> Optional[Executor]:
        """Create an executor of the specified type.

        Args:
            executor_type: Type of executor to create
            **kwargs: Configuration parameters

        Returns:
            Executor instance or None if creation fails
        """
        try:
            # Create executor configuration
            executor_enum = ExecutorType(executor_type.lower())
            config = ExecutorConfig(executor_type=executor_enum, **kwargs)

            # Create appropriate executor
            if executor_enum == ExecutorType.LOCAL:
                return LocalExecutor(config)
            elif executor_enum == ExecutorType.SSH:
                return SSHExecutor(config)
            elif executor_enum == ExecutorType.DOCKER:
                return DockerExecutor(config)
            else:
                logger.error(f"Unsupported executor type: {executor_type}")
                return None

        except ValueError as e:
            logger.error(f"Unknown executor type: {executor_type}")
            return None
        except Exception as e:
            logger.error(f"Failed to create {executor_type} executor: {e}")
            return None

    def register_executor(self, executor_type: str, executor_class: type) -> None:
        """Register a new executor type.

        Args:
            executor_type: Type identifier for the executor
            executor_class: Executor class to register
        """
        self.executors[executor_type] = executor_class
        logger.info(f"Registered custom executor type: {executor_type}")


# Default factory instance
default_factory = ExecutorFactory()
