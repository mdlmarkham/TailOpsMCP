"""Capability-driven tool patterns with "Observe First" workflow implementation."""
import logging
from typing import Dict, Any, Optional, List
from enum import Enum
from dataclasses import dataclass
from src.services.policy_gate import PolicyGate, OperationTier, ValidationMode
from src.services.executor_factory import ExecutorFactory
from src.utils.audit import AuditLogger

logger = logging.getLogger(__name__)
audit = AuditLogger()


class CapabilityType(str, Enum):
    """Types of capabilities supported by the system."""
    SYSTEM = "system"
    CONTAINER = "container"
    STACK = "stack"
    NETWORK = "network"
    FILE = "file"


@dataclass
class Capability:
    """Represents a specific capability that can be executed on a target."""
    name: str
    type: CapabilityType
    description: str
    tier: OperationTier
    default_timeout: int
    parameters: Dict[str, Any]


class CapabilityManager:
    """Manages capability-driven operations with "Observe First" workflow patterns."""
    
    def __init__(self):
        self.from src.server.dependencies import deps
            policy_gate = deps.policy_gate
        self.executor_factory = ExecutorFactory()
        
        # Define available capabilities
        self.capabilities = {
            # System capabilities
            "get_system_status": Capability(
                name="get_system_status",
                type=CapabilityType.SYSTEM,
                description="Get comprehensive system status",
                tier=OperationTier.OBSERVE,
                default_timeout=30,
                parameters={}
            ),
            "restart_service": Capability(
                name="restart_service",
                type=CapabilityType.SYSTEM,
                description="Restart a system service",
                tier=OperationTier.CONTROL,
                default_timeout=60,
                parameters={"service": ""}
            ),
            
            # Container capabilities
            "start_container": Capability(
                name="start_container",
                type=CapabilityType.CONTAINER,
                description="Start a Docker container",
                tier=OperationTier.CONTROL,
                default_timeout=60,
                parameters={"container": ""}
            ),
            "stop_container": Capability(
                name="stop_container",
                type=CapabilityType.CONTAINER,
                description="Stop a Docker container",
                tier=OperationTier.CONTROL,
                default_timeout=60,
                parameters={"container": ""}
            ),
            "inspect_container": Capability(
                name="inspect_container",
                type=CapabilityType.CONTAINER,
                description="Inspect a Docker container",
                tier=OperationTier.OBSERVE,
                default_timeout=30,
                parameters={"container": ""}
            ),
            
            # Stack capabilities
            "deploy_stack": Capability(
                name="deploy_stack",
                type=CapabilityType.STACK,
                description="Deploy a Docker stack",
                tier=OperationTier.CONTROL,
                default_timeout=300,
                parameters={"stack": "", "force": False}
            ),
            "pull_stack": Capability(
                name="pull_stack",
                type=CapabilityType.STACK,
                description="Pull latest images for a stack",
                tier=OperationTier.CONTROL,
                default_timeout=600,
                parameters={"stack": ""}
            ),
            "restart_stack": Capability(
                name="restart_stack",
                type=CapabilityType.STACK,
                description="Restart a Docker stack",
                tier=OperationTier.CONTROL,
                default_timeout=180,
                parameters={"stack": ""}
            ),
            
            # Network capabilities
            "test_connectivity": Capability(
                name="test_connectivity",
                type=CapabilityType.NETWORK,
                description="Test connectivity to host and port",
                tier=OperationTier.OBSERVE,
                default_timeout=10,
                parameters={"host": "", "port": 0, "timeout": 5}
            ),
            "scan_ports": Capability(
                name="scan_ports",
                type=CapabilityType.NETWORK,
                description="Scan a range of ports",
                tier=OperationTier.OBSERVE,
                default_timeout=300,
                parameters={"range": "", "timeout": 1}
            ),
            
            # File capabilities
            "read_file": Capability(
                name="read_file",
                type=CapabilityType.FILE,
                description="Read a file",
                tier=OperationTier.OBSERVE,
                default_timeout=30,
                parameters={"path": "", "lines": 100, "offset": 0}
            ),
            "list_directory": Capability(
                name="list_directory",
                type=CapabilityType.FILE,
                description="List directory contents",
                tier=OperationTier.OBSERVE,
                default_timeout=30,
                parameters={"path": "/"}
            ),
        }
    
    async def execute_capability(
        self,
        capability_name: str,
        target: str,
        parameters: Dict[str, Any],
        dry_run: bool = False,
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """Execute a capability on a target with "Observe First" workflow.
        
        Args:
            capability_name: Name of the capability to execute
            target: Target system
            parameters: Capability parameters
            dry_run: If True, simulate without executing
            timeout: Custom timeout (uses default if None)
            
        Returns:
            Execution result dictionary
        """
        try:
            # Get capability definition
            capability = self.capabilities.get(capability_name)
            if not capability:
                return {
                    "success": False,
                    "error": f"Unknown capability: {capability_name}"
                }
            
            # Apply "Observe First" workflow pattern
            # For control/admin operations, first check if we can observe the current state
            if capability.tier in [OperationTier.CONTROL, OperationTier.ADMIN]:
                await self._observe_before_control(capability, target, parameters)
            
            # Use Policy Gate for authorization
            validation_mode = ValidationMode.DRY_RUN if dry_run else ValidationMode.STRICT
            
            await self.policy_gate.authorize(
                operation=capability_name,
                target=target,
                tier=capability.tier,
                parameters=parameters,
                mode=validation_mode
            )

            if dry_run:
                return {
                    "success": True,
                    "dry_run": True,
                    "capability": capability_name,
                    "target": target,
                    "parameters": parameters,
                    "message": "Operation would be executed in non-dry-run mode"
                }

            # Get executor for target
            executor = self.executor_factory.get_executor(target)
            
            # Execute capability
            exec_timeout = timeout or capability.default_timeout
            result = await executor.execute(
                command=capability_name,
                parameters=parameters,
                timeout=exec_timeout
            )

            # Log operation
            audit.log_operation(
                operation=capability_name,
                target=target,
                success=result.success,
                parameters=parameters,
                result=result.output if result.success else None,
                error=result.error if not result.success else None
            )

            if result.success:
                return {
                    "success": True,
                    "capability": capability_name,
                    "target": target,
                    "parameters": parameters,
                    "output": result.output,
                    "duration": result.duration
                }
            else:
                return {
                    "success": False,
                    "capability": capability_name,
                    "target": target,
                    "parameters": parameters,
                    "error": result.error,
                    "duration": result.duration
                }
                
        except Exception as e:
            audit.log_operation(
                operation=capability_name,
                target=target,
                success=False,
                error=str(e)
            )
            return {
                "success": False,
                "capability": capability_name,
                "target": target,
                "parameters": parameters,
                "error": str(e)
            }
    
    async def _observe_before_control(
        self,
        capability: Capability,
        target: str,
        parameters: Dict[str, Any]
    ):
        """Implement "Observe First" pattern by checking current state before control operations."""
        
        # For container operations, check current container state
        if capability.type == CapabilityType.CONTAINER:
            container = parameters.get("container")
            if container:
                try:
                    # Get current container state
                    executor = self.executor_factory.get_executor(target)
                    state_result = await executor.execute(
                        command="container_state",
                        parameters={"container": container},
                        timeout=10
                    )
                    
                    if state_result.success:
                        logger.info(f"Container {container} current state: {state_result.output}")
                    else:
                        logger.warning(f"Could not get state for container {container}: {state_result.error}")
                        
                except Exception as e:
                    logger.warning(f"Failed to observe container state: {e}")
        
        # For stack operations, check current stack state
        elif capability.type == CapabilityType.STACK:
            stack = parameters.get("stack")
            if stack:
                try:
                    # Get current stack state
                    executor = self.executor_factory.get_executor(target)
                    state_result = await executor.execute(
                        command="stack_state",
                        parameters={"stack": stack},
                        timeout=15
                    )
                    
                    if state_result.success:
                        logger.info(f"Stack {stack} current state: {state_result.output}")
                    else:
                        logger.warning(f"Could not get state for stack {stack}: {state_result.error}")
                        
                except Exception as e:
                    logger.warning(f"Failed to observe stack state: {e}")
        
        # For service operations, check current service state
        elif capability.type == CapabilityType.SYSTEM and "service" in parameters:
            service = parameters.get("service")
            if service:
                try:
                    # Get current service state
                    executor = self.executor_factory.get_executor(target)
                    state_result = await executor.execute(
                        command="service_state",
                        parameters={"service": service},
                        timeout=10
                    )
                    
                    if state_result.success:
                        logger.info(f"Service {service} current state: {state_result.output}")
                    else:
                        logger.warning(f"Could not get state for service {service}: {state_result.error}")
                        
                except Exception as e:
                    logger.warning(f"Failed to observe service state: {e}")
    
    def get_capabilities(self, capability_type: Optional[CapabilityType] = None) -> List[Capability]:
        """Get list of available capabilities, optionally filtered by type."""
        if capability_type:
            return [cap for cap in self.capabilities.values() if cap.type == capability_type]
        return list(self.capabilities.values())
    
    def get_capability(self, capability_name: str) -> Optional[Capability]:
        """Get a specific capability by name."""
        return self.capabilities.get(capability_name)


# Global capability manager instance
capability_manager = CapabilityManager()