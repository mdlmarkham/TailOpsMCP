"""Integration module for Policy Gate and execution layer in capability-driven tools."""
import logging
from typing import Dict, Any, Optional
from src.services.policy_gate import PolicyGate, OperationTier, ValidationMode
from src.services.executor_factory import ExecutorFactory
from src.services.target_registry import TargetRegistry
from src.utils.audit import AuditLogger

logger = logging.getLogger(__name__)
audit = AuditLogger()


class ToolIntegrationManager:
    """Manages integration between tools, Policy Gate, and execution layer."""
    
    def __init__(self):
        self.policy_gate = PolicyGate()
        self.executor_factory = ExecutorFactory()
        self.target_registry = TargetRegistry()
    
    async def authorize_and_execute(
        self,
        operation: str,
        target: str,
        tier: OperationTier,
        parameters: Dict[str, Any],
        command: str,
        timeout: int,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """Authorize and execute an operation with full integration.
        
        Args:
            operation: Operation name for authorization
            target: Target system
            tier: Operation tier (OBSERVE/CONTROL/ADMIN)
            parameters: Operation parameters
            command: Command to execute
            timeout: Execution timeout
            dry_run: If True, simulate without executing
            
        Returns:
            Execution result dictionary
        """
        try:
            # Validate target exists
            target_metadata = self.target_registry.get_target(target)
            if not target_metadata:
                return {
                    "success": False,
                    "error": f"Target not found: {target}"
                }
            
            # Use Policy Gate for authorization
            validation_mode = ValidationMode.DRY_RUN if dry_run else ValidationMode.STRICT
            
            await self.policy_gate.authorize(
                operation=operation,
                target=target,
                tier=tier,
                parameters=parameters,
                mode=validation_mode
            )

            if dry_run:
                return {
                    "success": True,
                    "dry_run": True,
                    "operation": operation,
                    "target": target,
                    "parameters": parameters,
                    "message": "Operation would be executed in non-dry-run mode"
                }

            # Get executor for target
            executor = self.executor_factory.get_executor(target)
            
            # Execute operation
            result = await executor.execute(
                command=command,
                parameters=parameters,
                timeout=timeout
            )

            # Log operation
            audit.log_operation(
                operation=operation,
                target=target,
                success=result.success,
                parameters=parameters,
                result=result.output if result.success else None,
                error=result.error if not result.success else None,
                duration=result.duration
            )

            if result.success:
                return {
                    "success": True,
                    "operation": operation,
                    "target": target,
                    "parameters": parameters,
                    "output": result.output,
                    "duration": result.duration
                }
            else:
                return {
                    "success": False,
                    "operation": operation,
                    "target": target,
                    "parameters": parameters,
                    "error": result.error,
                    "duration": result.duration
                }
                
        except Exception as e:
            audit.log_operation(
                operation=operation,
                target=target,
                success=False,
                error=str(e)
            )
            return {
                "success": False,
                "operation": operation,
                "target": target,
                "parameters": parameters,
                "error": str(e)
            }
    
    def get_target_capabilities(self, target: str) -> Dict[str, Any]:
        """Get capabilities available for a specific target."""
        target_metadata = self.target_registry.get_target(target)
        if not target_metadata:
            return {"error": f"Target not found: {target}"}
        
        # Return target capabilities based on executor type and configuration
        capabilities = {
            "target": target,
            "executor_type": target_metadata.executor_type,
            "capabilities": []
        }
        
        # Add capabilities based on executor type
        if target_metadata.executor_type == "local":
            capabilities["capabilities"] = [
                "get_system_status", "restart_service", "start_container",
                "stop_container", "inspect_container", "deploy_stack",
                "pull_stack", "restart_stack", "test_connectivity",
                "scan_ports", "read_file", "list_directory"
            ]
        elif target_metadata.executor_type == "ssh":
            capabilities["capabilities"] = [
                "get_system_status", "restart_service", "start_container",
                "stop_container", "inspect_container", "deploy_stack",
                "pull_stack", "restart_stack", "test_connectivity",
                "scan_ports", "read_file", "list_directory"
            ]
        elif target_metadata.executor_type == "docker":
            capabilities["capabilities"] = [
                "start_container", "stop_container", "inspect_container",
                "deploy_stack", "pull_stack", "restart_stack"
            ]
        elif target_metadata.executor_type == "proxmox":
            capabilities["capabilities"] = [
                "get_system_status", "restart_service"
            ]
        
        return capabilities
    
    async def validate_operation(
        self,
        operation: str,
        target: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Validate an operation without executing it."""
        try:
            # Validate target
            target_metadata = self.target_registry.get_target(target)
            if not target_metadata:
                return {
                    "valid": False,
                    "error": f"Target not found: {target}"
                }
            
            # Validate operation with Policy Gate
            validation_result = await self.policy_gate.validate_operation(
                operation=operation,
                target=target,
                parameters=parameters
            )
            
            return {
                "valid": validation_result.get("valid", False),
                "warnings": validation_result.get("warnings", []),
                "errors": validation_result.get("errors", []),
                "target": target,
                "operation": operation
            }
            
        except Exception as e:
            return {
                "valid": False,
                "error": str(e),
                "target": target,
                "operation": operation
            }


# Global integration manager instance
integration_manager = ToolIntegrationManager()