"""
Consolidated Executor Module - Simplified Execution Framework

This module provides a unified executor interface and factory for all execution types.
All executor functionality has been consolidated into a single module with clean
separation of concerns between interface, factory, and implementation patterns.

CONSOLIDATED FROM:
- src/services/executor.py (base interface)
- src/services/executor_factory.py
- src/services/capability_executor.py (moved to security package)
- src/services/execution_factory.py (simplified)
- src/services/execution_service.py (simplified)

FEATURES:
- Unified executor interface
- Simple factory pattern
- Standardized result models
- Connection management
- Retry and timeout handling
"""

from __future__ import annotations

import abc
import hashlib
import logging
import time
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field
import json

# Configure logging
logger = logging.getLogger(__name__)


# Execution Enums
class ExecutionStatus(str, Enum):
    """Execution result status."""
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"
    AUTHENTICATION_ERROR = "authentication_error"
    PERMISSION_ERROR = "permission_error"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


class ExecutorType(str, Enum):
    """Types of executors available."""
    LOCAL = "local"
    SSH = "ssh"
    DOCKER = "docker"
    HTTP = "http"
    PROXMOX = "proxmox"
    REMOTE_OPERATION = "remote_operation"


class ConnectionState(str, Enum):
    """Connection states."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    ERROR = "error"


# Data Models
@dataclass
class ExecutionResult:
    """Standardized execution result model."""
    
    # Core status
    status: ExecutionStatus
    success: bool
    exit_code: Optional[int] = None
    output: Optional[str] = None
    error: Optional[str] = None
    duration: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Additional information
    command: Optional[str] = None
    working_directory: Optional[str] = None
    environment: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Connection info
    connection_info: Dict[str, Any] = field(default_factory=dict)
    retry_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "status": self.status.value,
            "success": self.success,
            "exit_code": self.exit_code,
            "output": self.output,
            "error": self.error,
            "duration": self.duration,
            "timestamp": self.timestamp.isoformat(),
            "command": self.command,
            "working_directory": self.working_directory,
            "environment": self.environment,
            "metadata": self.metadata,
            "connection_info": self.connection_info,
            "retry_count": self.retry_count
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ExecutionResult:
        """Create from dictionary."""
        data = data.copy()
        data["status"] = ExecutionStatus(data["status"])
        if data.get("timestamp"):
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        return cls(**data)


@dataclass
class ExecutorConfig:
    """Configuration for executor creation."""
    
    executor_type: ExecutorType
    timeout: int = 30
    retry_attempts: int = 3
    retry_delay: float = 1.0
    connect_timeout: int = 10
    max_connections: int = 5
    
    # Connection parameters
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    key_path: Optional[str] = None
    socket_path: Optional[str] = None
    
    # Additional parameters
    environment: Dict[str, str] = field(default_factory=dict)
    working_directory: Optional[str] = None
    additional_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConnectionInfo:
    """Connection information and state."""
    
    executor_type: ExecutorType
    connection_state: ConnectionState = ConnectionState.DISCONNECTED
    connected_at: Optional[datetime] = None
    last_activity: Optional[datetime] = None
    connection_id: str = field(default_factory=lambda: f"conn_{int(time.time() * 1000)}")
    
    # Connection details
    endpoint: Optional[str] = None
    credentials_used: bool = False
    connection_params: Dict[str, Any] = field(default_factory=dict)
    
    # Statistics
    total_connections: int = 0
    successful_connections: int = 0
    failed_connections: int = 0
    total_operations: int = 0
    successful_operations: int = 0
    failed_operations: int = 0


# Abstract Base Executor
class Executor(abc.ABC):
    """Abstract base class for all executors."""
    
    def __init__(self, config: ExecutorConfig):
        """Initialize executor with configuration."""
        self.config = config
        self._connection_info = ConnectionInfo(executor_type=config.executor_type)
        self._connected = False
        self._connection_lock = False  # Simple connection locking
        
        logger.debug(f"Initialized {config.executor_type.value} executor")
    
    @abc.abstractmethod
    def connect(self) -> bool:
        """Establish connection to target.
        
        Returns:
            True if connection successful, False otherwise
        """
        pass
    
    @abc.abstractmethod
    def disconnect(self) -> None:
        """Close connection to target."""
        pass
    
    @abc.abstractmethod
    def execute_command(self, command: str, **kwargs) -> ExecutionResult:
        """Execute a command on the target.
        
        Args:
            command: Command to execute
            **kwargs: Additional executor-specific parameters
            
        Returns:
            ExecutionResult with standardized output
        """
        pass
    
    @abc.abstractmethod
    def is_available(self) -> bool:
        """Check if executor is available for use.
        
        Returns:
            True if executor is ready, False otherwise
        """
        pass
    
    # Common functionality
    def is_connected(self) -> bool:
        """Check if executor is connected to target.
        
        Returns:
            True if connected, False otherwise
        """
        return self._connected
    
    def get_connection_info(self) -> ConnectionInfo:
        """Get current connection information.
        
        Returns:
            ConnectionInfo object with current state
        """
        return self._connection_info
    
    def execute_with_retry(self, command: str, **kwargs) -> ExecutionResult:
        """Execute command with retry logic.
        
        Args:
            command: Command to execute
            **kwargs: Additional parameters
            
        Returns:
            ExecutionResult with retry information
        """
        last_error = None
        
        for attempt in range(self.config.retry_attempts):
            try:
                start_time = time.time()
                result = self.execute_command(command, **kwargs)
                result.duration = time.time() - start_time
                result.retry_count = attempt
                
                if result.success:
                    logger.debug(f"Command executed successfully on attempt {attempt + 1}")
                    return result
                
                last_error = result
                
                # Don't retry on certain errors
                if result.status in [ExecutionStatus.AUTHENTICATION_ERROR, 
                                   ExecutionStatus.PERMISSION_ERROR]:
                    logger.warning(f"Not retrying on {result.status.value} error")
                    break
                
            except Exception as e:
                logger.warning(f"Execution attempt {attempt + 1} failed: {e}")
                last_error = ExecutionResult(
                    status=ExecutionStatus.CONNECTION_ERROR,
                    success=False,
                    error=str(e),
                    command=command,
                    retry_count=attempt
                )
            
            # Wait before retry (except on last attempt)
            if attempt < self.config.retry_attempts - 1:
                time.sleep(self.config.retry_delay * (attempt + 1))  # Exponential backoff
        
        # Return the last error result
        if last_error:
            return last_error
        else:
            return ExecutionResult(
                status=ExecutionStatus.FAILURE,
                success=False,
                error="Unknown execution failure",
                command=command,
                retry_count=self.config.retry_attempts
            )
    
    def context_execute(self, command: str, **kwargs) -> ExecutionResult:
        """Execute command with automatic connection management.
        
        Args:
            command: Command to execute
            **kwargs: Additional parameters
            
        Returns:
            ExecutionResult
        """
        if not self.is_connected():
            if not self.connect():
                return ExecutionResult(
                    status=ExecutionStatus.CONNECTION_ERROR,
                    success=False,
                    error="Failed to establish connection",
                    command=command
                )
        
        try:
            return self.execute_command(command, **kwargs)
        finally:
            # Optionally disconnect after execution for long-lived connections
            # This can be controlled by configuration
            pass
    
    # Context manager support
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
    
    # Utility methods
    def _create_result(self, status: ExecutionStatus, success: bool, 
                      command: Optional[str] = None,
                      exit_code: Optional[int] = None, 
                      output: Optional[str] = None,
                      error: Optional[str] = None, 
                      duration: float = 0.0,
                      metadata: Optional[Dict[str, Any]] = None) -> ExecutionResult:
        """Create standardized execution result.
        
        Args:
            status: Execution status
            success: Whether execution was successful
            command: Command that was executed
            exit_code: Process exit code
            output: Standard output
            error: Error output
            duration: Execution duration
            metadata: Additional metadata
            
        Returns:
            Standardized ExecutionResult
        """
        return ExecutionResult(
            status=status,
            success=success,
            command=command,
            exit_code=exit_code,
            output=output,
            error=error,
            duration=duration,
            metadata=metadata or {},
            connection_info=self._connection_info.__dict__
        )
    
    def _update_connection_state(self, state: ConnectionState) -> None:
        """Update connection state and statistics.
        
        Args:
            state: New connection state
        """
        self._connection_info.connection_state = state
        self._connection_info.last_activity = datetime.utcnow()
        
        if state == ConnectionState.CONNECTED:
            self._connection_info.connected_at = datetime.utcnow()
            self._connected = True
        elif state == ConnectionState.DISCONNECTED:
            self._connected = False
        
        logger.debug(f"Connection state updated to {state.value}")


# Executor Factory
class ExecutorFactory:
    """Unified factory for creating executors based on configuration."""
    
    def __init__(self):
        """Initialize executor factory."""
        self._executor_cache: Dict[str, Executor] = {}
        self._config_cache: Dict[str, ExecutorConfig] = {}
        self._registry: Dict[ExecutorType, type] = {}
        
        # Register default executor types
        self._register_default_executors()
    
    def _register_default_executors(self) -> None:
        """Register default executor implementations."""
        # Import executor implementations
        try:
            from .local_executor import LocalExecutor
            self._registry[ExecutorType.LOCAL] = LocalExecutor
        except ImportError:
            logger.warning("LocalExecutor not available")
        
        try:
            from .ssh_executor import SSHExecutor
            self._registry[ExecutorType.SSH] = SSHExecutor
        except ImportError:
            logger.warning("SSHExecutor not available")
        
        try:
            from .docker_executor import DockerExecutor
            self._registry[ExecutorType.DOCKER] = DockerExecutor
        except ImportError:
            logger.warning("DockerExecutor not available")
        
        try:
            from .http_executor import HTTPExecutor
            self._registry[ExecutorType.HTTP] = HTTPExecutor
        except ImportError:
            logger.warning("HTTPExecutor not available")
        
        try:
            from .proxmox_executor import ProxmoxExecutor
            self._registry[ExecutorType.PROXMOX] = ProxmoxExecutor
        except ImportError:
            logger.warning("ProxmoxExecutor not available")
    
    def create_executor(self, config: ExecutorConfig) -> Optional[Executor]:
        """Create executor based on configuration.
        
        Args:
            config: Executor configuration
            
        Returns:
            Executor instance or None if creation fails
        """
        # Validate configuration
        errors = self._validate_config(config)
        if errors:
            logger.error(f"Invalid executor configuration: {errors}")
            return None
        
        # Generate cache key
        cache_key = self._generate_cache_key(config)
        
        # Return cached executor if available and valid
        if cache_key in self._executor_cache:
            cached_executor = self._executor_cache[cache_key]
            if cached_executor.is_available():
                logger.debug(f"Returning cached executor for {config.executor_type.value}")
                return cached_executor
            else:
                # Remove invalid cached executor
                logger.warning(f"Removing invalid cached executor for {cache_key}")
                del self._executor_cache[cache_key]
        
        # Create new executor
        executor_class = self._registry.get(config.executor_type)
        if not executor_class:
            logger.error(f"No executor class registered for type: {config.executor_type.value}")
            return None
        
        try:
            executor = executor_class(config)
            
            # Cache the executor and config
            self._executor_cache[cache_key] = executor
            self._config_cache[cache_key] = config
            
            logger.info(f"Created new {config.executor_type.value} executor")
            return executor
            
        except Exception as e:
            logger.error(f"Failed to create {config.executor_type.value} executor: {e}")
            return None
    
    def get_or_create_executor(self, config: ExecutorConfig) -> Optional[Executor]:
        """Get cached executor or create new one.
        
        Args:
            config: Executor configuration
            
        Returns:
            Executor instance
        """
        return self.create_executor(config)
    
    def clear_cache(self) -> None:
        """Clear all cached executors and configurations."""
        self._executor_cache.clear()
        self._config_cache.clear()
        logger.info("Executor cache cleared")
    
    def remove_from_cache(self, config: ExecutorConfig) -> bool:
        """Remove specific executor from cache.
        
        Args:
            config: Executor configuration
            
        Returns:
            True if executor was removed, False if not found
        """
        cache_key = self._generate_cache_key(config)
        
        if cache_key in self._executor_cache:
            del self._executor_cache[cache_key]
        if cache_key in self._config_cache:
            del self._config_cache[cache_key]
        
        return cache_key in self._executor_cache or cache_key in self._config_cache
    
    def get_cached_executors(self) -> List[Executor]:
        """Get all cached executors.
        
        Returns:
            List of cached executor instances
        """
        return list(self._executor_cache.values())
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get factory cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        stats = {
            "total_cached": len(self._executor_cache),
            "by_executor_type": {},
            "available_executor_types": list(self._registry.keys())
        }
        
        # Count by executor type
        for executor in self._executor_cache.values():
            executor_type = executor.config.executor_type.value
            if executor_type not in stats["by_executor_type"]:
                stats["by_executor_type"][executor_type] = 0
            stats["by_executor_type"][executor_type] += 1
        
        return stats
    
    def register_executor_type(self, executor_type: ExecutorType, executor_class: type) -> None:
        """Register custom executor type.
        
        Args:
            executor_type: Type of executor
            executor_class: Executor class implementation
        """
        self._registry[executor_type] = executor_class
        logger.info(f"Registered custom executor type: {executor_type.value}")
    
    def _validate_config(self, config: ExecutorConfig) -> List[str]:
        """Validate executor configuration.
        
        Args:
            config: Configuration to validate
            
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        # Basic validation
        if not config.executor_type:
            errors.append("Executor type is required")
        
        if config.timeout <= 0:
            errors.append("Timeout must be positive")
        
        if config.retry_attempts < 0:
            errors.append("Retry attempts cannot be negative")
        
        # Type-specific validation
        if config.executor_type in [ExecutorType.SSH, ExecutorType.HTTP, ExecutorType.PROXMOX]:
            if not config.host:
                errors.append("Host is required for remote executors")
        
        if config.executor_type == ExecutorType.SSH:
            if not config.username:
                errors.append("Username is required for SSH executors")
        
        if config.executor_type == ExecutorType.DOCKER:
            if not config.socket_path and not config.host:
                errors.append("Socket path or host is required for Docker executors")
        
        return errors
    
    def _generate_cache_key(self, config: ExecutorConfig) -> str:
        """Generate cache key from configuration.
        
        Args:
            config: Configuration to generate key from
            
        Returns:
            Unique cache key string
        """
        # Create key components
        key_data = {
            "type": config.executor_type.value,
            "host": config.host,
            "port": config.port,
            "username": config.username,
            "socket_path": config.socket_path,
            "working_directory": config.working_directory
        }
        
        # Create hash
        key_string = json.dumps(key_data, sort_keys=True, default=str)
        return hashlib.md5(key_string.encode()).hexdigest()


# Global factory instance
_executor_factory = None


def get_executor_factory() -> ExecutorFactory:
    """Get global executor factory instance.
    
    Returns:
        ExecutorFactory instance
    """
    global _executor_factory
    if _executor_factory is None:
        _executor_factory = ExecutorFactory()
    return _executor_factory


# Convenience functions
def create_executor(executor_type: str, **kwargs) -> Optional[Executor]:
    """Create executor with simplified interface.
    
    Args:
        executor_type: Type of executor to create
        **kwargs: Configuration parameters
        
    Returns:
        Executor instance or None if creation fails
    """
    try:
        executor_enum = ExecutorType(executor_type.lower())
        config = ExecutorConfig(executor_type=executor_enum, **kwargs)
        return get_executor_factory().create_executor(config)
    except ValueError:
        logger.error(f"Unknown executor type: {executor_type}")
        return None


def execute_command(executor_type: str, command: str, **kwargs) -> ExecutionResult:
    """Execute command with simplified interface.
    
    Args:
        executor_type: Type of executor to use
        command: Command to execute
        **kwargs: Additional configuration parameters
        
    Returns:
        ExecutionResult
    """
    executor = create_executor(executor_type, **kwargs)
    if not executor:
        return ExecutionResult(
            status=ExecutionStatus.CONNECTION_ERROR,
            success=False,
            error=f"Failed to create {executor_type} executor",
            command=command
        )
    
    with executor:
        return executor.execute_command(command)


# Export main classes and functions
__all__ = [
    # Core classes
    'Executor',
    'ExecutorFactory', 
    'ExecutionResult',
    'ExecutorConfig',
    'ConnectionInfo',
    
    # Enums
    'ExecutionStatus',
    'ExecutorType',
    'ConnectionState',
    
    # Factory functions
    'get_executor_factory',
    'create_executor',
    'execute_command',
    
    # Version info
    '__version__'
]

# Version information
__version__ = "1.0.0"