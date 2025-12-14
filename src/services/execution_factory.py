"""
Execution Backend Factory - Pluggable Remote Execution System

Provides pluggable execution backends for different target types and connection methods,
supporting SSH/Tailscale, local execution, and other remote execution mechanisms.
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Type, Union
from datetime import datetime

from src.models.policy_models import OperationType, TargetRole
from src.models.fleet_inventory import TargetNode, ConnectionMethod, Runtime
from src.models.execution import ExecutionResult, ExecutionStatus, ExecutionSeverity
from src.services.local_execution_backend import LocalExecutionBackend
from src.services.ssh_tailscale_backend import SSHTailscaleBackend
from src.services.docker_backend import DockerBackend
from src.services.proxmox_backend import ProxmoxBackend
from src.utils.errors import SystemManagerError, ErrorCategory


logger = logging.getLogger(__name__)


class RemoteExecutionBackend(ABC):
    """Abstract base class for remote execution backends."""
    
    def __init__(self, target_config: Dict[str, Any]):
        """Initialize execution backend.
        
        Args:
            target_config: Target configuration including connection details
        """
        self.target_config = target_config
        self.connection_method = target_config.get("connection_method", ConnectionMethod.SSH)
        self.runtime = target_config.get("runtime", Runtime.SYSTEMD)
        self.backend_type = self._get_backend_type()
    
    def _get_backend_type(self) -> str:
        """Get backend type identifier."""
        return f"{self.connection_method.value}_{self.runtime.value}"
    
    @abstractmethod
    async def execute_capability(self, capability: OperationType, 
                               parameters: Dict[str, Any], 
                               target_info: Dict[str, Any]) -> ExecutionResult:
        """Execute a capability operation on the target.
        
        Args:
            capability: Type of capability to execute
            parameters: Operation parameters
            target_info: Target information and metadata
            
        Returns:
            Execution result
        """
        pass
    
    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection to target.
        
        Returns:
            True if connection successful, False otherwise
        """
        pass
    
    @abstractmethod
    async def disconnect(self):
        """Disconnect from target and cleanup resources."""
        pass
    
    @abstractmethod
    def is_connected(self) -> bool:
        """Check if backend is currently connected.
        
        Returns:
            True if connected, False otherwise
        """
        pass
    
    @abstractmethod
    async def test_connection(self) -> ExecutionResult:
        """Test connection to target without executing operations.
        
        Returns:
            Connection test result
        """
        pass
    
    def get_supported_capabilities(self) -> List[OperationType]:
        """Get list of capabilities supported by this backend.
        
        Returns:
            List of supported operation types
        """
        return []
    
    def get_capability_timeout(self, capability: OperationType) -> int:
        """Get default timeout for a capability type.
        
        Args:
            capability: Operation type
            
        Returns:
            Timeout in seconds
        """
        # Default timeouts by capability type
        timeouts = {
            OperationType.SERVICE_RESTART: 60,
            OperationType.SERVICE_START: 30,
            OperationType.SERVICE_STOP: 30,
            OperationType.SERVICE_STATUS: 10,
            OperationType.CONTAINER_CREATE: 180,
            OperationType.CONTAINER_DELETE: 60,
            OperationType.CONTAINER_START: 60,
            OperationType.CONTAINER_STOP: 60,
            OperationType.CONTAINER_RESTART: 90,
            OperationType.CONTAINER_INSPECT: 30,
            OperationType.STACK_DEPLOY: 300,
            OperationType.STACK_REMOVE: 180,
            OperationType.STACK_UPDATE: 240,
            OperationType.BACKUP_CREATE: 1800,
            OperationType.BACKUP_RESTORE: 3600,
            OperationType.SNAPSHOT_CREATE: 120,
            OperationType.SNAPSHOT_DELETE: 60,
            OperationType.SNAPSHOT_RESTORE: 180,
            OperationType.FILE_READ: 30,
            OperationType.FILE_WRITE: 60,
            OperationType.FILE_DELETE: 30,
            OperationType.NETWORK_SCAN: 120,
            OperationType.NETWORK_TEST: 30,
            OperationType.NETWORK_STATUS: 15
        }
        
        return timeouts.get(capability, 300)  # Default 5 minutes
    
    def validate_capability_support(self, capability: OperationType) -> bool:
        """Validate if capability is supported by this backend.
        
        Args:
            capability: Operation type to validate
            
        Returns:
            True if supported, False otherwise
        """
        return capability in self.get_supported_capabilities()


class ExecutionBackendFactory:
    """Factory for creating and managing execution backends."""
    
    def __init__(self):
        """Initialize execution backend factory."""
        self.backend_registry: Dict[str, Type[RemoteExecutionBackend]] = {}
        self.backend_instances: Dict[str, RemoteExecutionBackend] = {}
        
        # Register default backends
        self._register_default_backends()
        
        # Connection pool management
        self.connection_pool: Dict[str, Any] = {}
        self.max_connections_per_target = 5
        self.connection_timeout = 30
    
    def _register_default_backends(self):
        """Register default execution backends."""
        self.register_backend(ConnectionMethod.SSH, Runtime.BARE_METAL, SSHTailscaleBackend)
        self.register_backend(ConnectionMethod.SSH, Runtime.SYSTEMD, SSHTailscaleBackend)
        self.register_backend(ConnectionMethod.SSH, Runtime.DOCKER, SSHTailscaleBackend)
        
        self.register_backend(ConnectionMethod.TAILSCALE_SSH, Runtime.BARE_METAL, SSHTailscaleBackend)
        self.register_backend(ConnectionMethod.TAILSCALE_SSH, Runtime.SYSTEMD, SSHTailscaleBackend)
        self.register_backend(ConnectionMethod.TAILSCALE_SSH, Runtime.DOCKER, SSHTailscaleBackend)
        
        self.register_backend(ConnectionMethod.DOCKER_API, Runtime.DOCKER, DockerBackend)
        
        self.register_backend(ConnectionMethod.PROXMOX_API, Runtime.PROXMOX, ProxmoxBackend)
        self.register_backend(ConnectionMethod.PROXMOX_API, Runtime.CONTAINER, ProxmoxBackend)
        self.register_backend(ConnectionMethod.PROXMOX_API, Runtime.VM, ProxmoxBackend)
        
        # Local execution for gateway itself
        self.register_backend(ConnectionMethod.SSH, Runtime.BARE_METAL, LocalExecutionBackend)
    
    def register_backend(self, connection_method: ConnectionMethod, 
                        runtime: Runtime, backend_class: Type[RemoteExecutionBackend]):
        """Register a new execution backend.
        
        Args:
            connection_method: Connection method supported by backend
            runtime: Runtime environment supported by backend
            backend_class: Backend implementation class
        """
        key = f"{connection_method.value}_{runtime.value}"
        self.backend_registry[key] = backend_class
        logger.debug(f"Registered backend {backend_class.__name__} for {key}")
    
    def get_backend(self, target_config: Union[Dict[str, Any], TargetNode], 
                   capability: Optional[OperationType] = None) -> Optional[RemoteExecutionBackend]:
        """Get or create execution backend for target.
        
        Args:
            target_config: Target configuration
            capability: Optional capability to check support for
            
        Returns:
            Execution backend instance or None if not available
        """
        # Extract connection method and runtime from target config
        if isinstance(target_config, TargetNode):
            connection_method = target_config.connection.method
            runtime = target_config.runtime
            target_id = target_config.id
            backend_config = {
                "connection_method": connection_method,
                "runtime": runtime,
                "connection": target_config.connection.dict(),
                "target_id": target_id,
                "target_metadata": target_config.metadata
            }
        else:
            connection_method = ConnectionMethod(target_config.get("connection_method", "ssh"))
            runtime = Runtime(target_config.get("runtime", "bare_metal"))
            target_id = target_config.get("id", "unknown")
            backend_config = target_config
        
        # Generate backend key
        backend_key = f"{connection_method.value}_{runtime.value}_{target_id}"
        
        # Check if backend is already cached
        if backend_key in self.backend_instances:
            backend = self.backend_instances[backend_key]
            
            # Check if capability is supported
            if capability and not backend.validate_capability_support(capability):
                logger.warning(f"Backend {backend_key} does not support capability {capability}")
                return None
            
            return backend
        
        # Create new backend instance
        backend_class = self._get_backend_class(connection_method, runtime)
        if not backend_class:
            logger.error(f"No backend registered for {connection_method.value}_{runtime.value}")
            return None
        
        try:
            backend = backend_class(backend_config)
            
            # Check capability support if specified
            if capability and not backend.validate_capability_support(capability):
                logger.warning(f"Backend {backend_class.__name__} does not support capability {capability}")
                return None
            
            # Cache the backend instance
            self.backend_instances[backend_key] = backend
            logger.info(f"Created {backend_class.__name__} backend for target {target_id}")
            
            return backend
            
        except Exception as e:
            logger.error(f"Failed to create backend for {backend_key}: {e}")
            return None
    
    def _get_backend_class(self, connection_method: ConnectionMethod, 
                          runtime: Runtime) -> Optional[Type[RemoteExecutionBackend]]:
        """Get backend class for connection method and runtime.
        
        Args:
            connection_method: Connection method
            runtime: Runtime environment
            
        Returns:
            Backend class or None if not found
        """
        key = f"{connection_method.value}_{runtime.value}"
        return self.backend_registry.get(key)
    
    async def test_all_backends(self) -> Dict[str, ExecutionResult]:
        """Test all registered backends for availability.
        
        Returns:
            Dictionary of backend type to test result
        """
        results = {}
        
        for backend_key, backend_class in self.backend_registry.items():
            try:
                # Create test configuration
                test_config = {
                    "connection_method": backend_key.split("_")[0],
                    "runtime": "_".join(backend_key.split("_")[1:]),
                    "test_mode": True
                }
                
                # Create backend instance
                backend = backend_class(test_config)
                
                # Test connection
                test_result = await backend.test_connection()
                results[backend_key] = test_result
                
            except Exception as e:
                results[backend_key] = ExecutionResult(
                    status=ExecutionStatus.CONFIGURATION_ERROR,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error=f"Backend test failed: {str(e)}",
                    duration=0.0
                )
        
        return results
    
    def get_supported_capabilities_matrix(self) -> Dict[str, List[OperationType]]:
        """Get matrix of capabilities supported by each backend type.
        
        Returns:
            Dictionary of backend type to list of supported capabilities
        """
        matrix = {}
        
        for backend_key, backend_class in self.backend_registry.items():
            try:
                # Create minimal test config
                test_config = {
                    "connection_method": backend_key.split("_")[0],
                    "runtime": "_".join(backend_key.split("_")[1:]),
                    "test_mode": True
                }
                
                backend = backend_class(test_config)
                supported_capabilities = backend.get_supported_capabilities()
                matrix[backend_key] = supported_capabilities
                
            except Exception as e:
                logger.warning(f"Failed to get capabilities for {backend_key}: {e}")
                matrix[backend_key] = []
        
        return matrix
    
    def cleanup_backend(self, target_id: str):
        """Cleanup backend instance for target.
        
        Args:
            target_id: Target identifier
        """
        # Find and cleanup backend instances for this target
        keys_to_remove = []
        for key in self.backend_instances:
            if target_id in key:
                backend = self.backend_instances[key]
                try:
                    # Disconnect backend
                    if hasattr(backend, 'disconnect'):
                        import asyncio
                        asyncio.create_task(backend.disconnect())
                except Exception as e:
                    logger.warning(f"Error disconnecting backend {key}: {e}")
                
                keys_to_remove.append(key)
        
        # Remove from cache
        for key in keys_to_remove:
            del self.backend_instances[key]
            logger.debug(f"Cleaned up backend {key}")
    
    def cleanup_all_backends(self):
        """Cleanup all backend instances and connections."""
        for backend in self.backend_instances.values():
            try:
                if hasattr(backend, 'disconnect'):
                    import asyncio
                    asyncio.create_task(backend.disconnect())
            except Exception as e:
                logger.warning(f"Error cleaning up backend: {e}")
        
        self.backend_instances.clear()
        self.connection_pool.clear()
        logger.info("All backends cleaned up")
    
    def get_backend_statistics(self) -> Dict[str, Any]:
        """Get statistics about backend usage and health.
        
        Returns:
            Dictionary of backend statistics
        """
        stats = {
            "total_registered_backends": len(self.backend_registry),
            "active_backend_instances": len(self.backend_instances),
            "backend_types": list(self.backend_registry.keys()),
            "active_backend_types": list(set(key.rsplit("_", 1)[0] for key in self.backend_instances.keys())),
            "connection_pool_size": len(self.connection_pool),
            "max_connections_per_target": self.max_connections_per_target
        }
        
        # Backend-specific statistics
        backend_stats = {}
        for key, backend in self.backend_instances.items():
            backend_stats[key] = {
                "connected": backend.is_connected() if hasattr(backend, 'is_connected') else False,
                "backend_type": backend.backend_type,
                "supported_capabilities_count": len(backend.get_supported_capabilities())
            }
        
        stats["backend_instance_stats"] = backend_stats
        
        return stats


class CapabilityExecutionRouter:
    """Routes capability executions to appropriate backends based on target capabilities."""
    
    def __init__(self, backend_factory: ExecutionBackendFactory):
        """Initialize capability execution router.
        
        Args:
            backend_factory: Execution backend factory
        """
        self.backend_factory = backend_factory
    
    async def execute_capability(self, capability: OperationType, 
                               parameters: Dict[str, Any], 
                               target_config: Dict[str, Any]) -> ExecutionResult:
        """Execute capability with automatic backend selection.
        
        Args:
            capability: Operation type to execute
            parameters: Operation parameters
            target_config: Target configuration
            
        Returns:
            Execution result
        """
        start_time = datetime.now()
        
        try:
            # Get appropriate backend
            backend = self.backend_factory.get_backend(target_config, capability)
            if not backend:
                return ExecutionResult(
                    status=ExecutionStatus.CONFIGURATION_ERROR,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error=f"No suitable backend found for capability {capability} on target",
                    duration=(datetime.now() - start_time).total_seconds()
                )
            
            # Execute capability
            result = await backend.execute_capability(capability, parameters, target_config)
            
            # Add routing metadata
            result.metadata["routing_backend"] = backend.backend_type
            result.metadata["routing_capability"] = capability.value
            
            return result
            
        except Exception as e:
            return ExecutionResult(
                status=ExecutionStatus.EXECUTION_ERROR,
                success=False,
                severity=ExecutionSeverity.ERROR,
                error=f"Capability routing failed: {str(e)}",
                duration=(datetime.now() - start_time).total_seconds()
            )
    
    def get_recommended_backend(self, target_config: Dict[str, Any], 
                               capability: OperationType) -> Optional[str]:
        """Get recommended backend type for target and capability combination.
        
        Args:
            target_config: Target configuration
            capability: Operation type
            
        Returns:
            Recommended backend type or None
        """
        # Get all compatible backends
        compatible_backends = []
        
        for backend_key, backend_class in self.backend_factory.backend_registry.items():
            try:
                test_config = target_config.copy()
                test_config.update({
                    "connection_method": backend_key.split("_")[0],
                    "runtime": "_".join(backend_key.split("_")[1:])
                })
                
                backend = backend_class(test_config)
                
                if backend.validate_capability_support(capability):
                    compatible_backends.append((backend_key, backend))
                    
            except Exception:
                continue
        
        if not compatible_backends:
            return None
        
        # Simple ranking algorithm (can be enhanced)
        # Prefer SSH-based backends for system operations
        if capability in [OperationType.SERVICE_RESTART, OperationType.SERVICE_START, 
                         OperationType.SERVICE_STOP, OperationType.SERVICE_STATUS]:
            for backend_key, backend in compatible_backends:
                if "ssh" in backend_key:
                    return backend_key
        
        # Return first compatible backend
        return compatible_backends[0][0]


# Global factory instance
execution_backend_factory = ExecutionBackendFactory()
capability_router = CapabilityExecutionRouter(execution_backend_factory)