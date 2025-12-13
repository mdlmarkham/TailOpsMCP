"""
Executor factory for creating appropriate executors based on target configuration.
"""

import logging
from typing import Dict, Optional

from src.models.target_registry import TargetConnection, ExecutorType
from src.services.executor import Executor
from src.services.local_executor import LocalExecutor
from src.services.ssh_executor import SSHExecutor
from src.services.docker_executor import DockerExecutor

logger = logging.getLogger(__name__)


class ExecutorFactory:
    """Factory for creating executors based on target configuration."""
    
    def __init__(self):
        """Initialize executor factory."""
        self._executor_cache: Dict[str, Executor] = {}
    
    def create_executor(self, connection: TargetConnection) -> Optional[Executor]:
        """Create executor based on target connection configuration.
        
        Args:
            connection: Target connection configuration
            
        Returns:
            Appropriate executor instance or None if configuration is invalid
        """
        # Create cache key from connection parameters
        cache_key = self._get_cache_key(connection)
        
        # Return cached executor if available
        if cache_key in self._executor_cache:
            return self._executor_cache[cache_key]
        
        # Validate connection configuration
        errors = connection.validate()
        if errors:
            logger.error(f"Invalid connection configuration: {errors}")
            return None
        
        # Create appropriate executor
        executor = None
        
        if connection.executor == ExecutorType.LOCAL:
            executor = LocalExecutor(
                timeout=connection.timeout
            )
        
        elif connection.executor == ExecutorType.SSH:
            executor = SSHExecutor(
                host=connection.host,
                port=connection.port or 22,
                username=connection.username,
                key_path=connection.key_path,
                timeout=connection.timeout
            )
        
        elif connection.executor == ExecutorType.DOCKER:
            executor = DockerExecutor(
                socket_path=connection.socket_path,
                host=connection.host,
                timeout=connection.timeout
            )
        
        else:
            logger.error(f"Unsupported executor type: {connection.executor}")
            return None
        
        # Cache the executor
        self._executor_cache[cache_key] = executor
        logger.info(f"Created {connection.executor.value} executor for {cache_key}")
        
        return executor
    
    def get_or_create_executor(self, connection: TargetConnection) -> Optional[Executor]:
        """Get cached executor or create new one.
        
        Args:
            connection: Target connection configuration
            
        Returns:
            Cached or newly created executor
        """
        cache_key = self._get_cache_key(connection)
        
        if cache_key in self._executor_cache:
            return self._executor_cache[cache_key]
        
        return self.create_executor(connection)
    
    def clear_cache(self) -> None:
        """Clear executor cache."""
        self._executor_cache.clear()
        logger.info("Executor cache cleared")
    
    def remove_from_cache(self, connection: TargetConnection) -> bool:
        """Remove specific executor from cache.
        
        Args:
            connection: Target connection configuration
            
        Returns:
            True if executor was removed, False if not found
        """
        cache_key = self._get_cache_key(connection)
        
        if cache_key in self._executor_cache:
            del self._executor_cache[cache_key]
            logger.info(f"Removed executor from cache: {cache_key}")
            return True
        
        return False
    
    def _get_cache_key(self, connection: TargetConnection) -> str:
        """Generate cache key from connection parameters.
        
        Args:
            connection: Target connection configuration
            
        Returns:
            Unique cache key string
        """
        if connection.executor == ExecutorType.LOCAL:
            return "local"
        
        elif connection.executor == ExecutorType.SSH:
            return f"ssh://{connection.username}@{connection.host}:{connection.port or 22}"
        
        elif connection.executor == ExecutorType.DOCKER:
            if connection.socket_path:
                return f"docker://socket:{connection.socket_path}"
            elif connection.host:
                return f"docker://{connection.host}"
            else:
                return "docker://default"
        
        return str(connection.executor.value)