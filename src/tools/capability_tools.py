"""
Capability Tools - MCP Tools for Policy-Driven Operations

Provides MCP tools for executing capability-driven operations with comprehensive
policy enforcement, validation, and audit logging.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

from src.models.policy_models import (
    CapabilityOperation, OperationType, TargetRole, create_default_policy_config,
    PolicyContext, validate_policy_config
)
from src.services.capability_executor import CapabilityExecutor, create_service_restart_operation
from src.services.policy_engine import PolicyEngine
from src.services.execution_factory import execution_backend_factory
from src.models.execution import ExecutionResult
from src.utils.audit import AuditLogger


logger = logging.getLogger(__name__)


class CapabilityTools:
    """MCP tools for capability-driven operations."""
    
    def __init__(self, 
                 capability_executor: CapabilityExecutor,
                 policy_engine: PolicyEngine,
                 audit_logger: AuditLogger):
        """Initialize capability tools.
        
        Args:
            capability_executor: Capability executor for operations
            policy_engine: Policy engine for enforcement
            audit_logger: Audit logger for operations
        """
        self.capability_executor = capability_executor
        self.policy_engine = policy_engine
        self.audit_logger = audit_logger
    
    async def execute_service_restart(self, 
                                    service_name: str,
                                    target_id: str,
                                    requested_by: str,
                                    timeout: int = 60,
                                    dry_run: bool = False) -> Dict[str, Any]:
        """Execute service restart operation with policy enforcement.
        
        Args:
            service_name: Name of service to restart
            target_id: Target identifier
            requested_by: User requesting the operation
            timeout: Operation timeout in seconds
            dry_run: Whether to perform dry run
            
        Returns:
            Operation result with status and details
        """
        try:
            # Create capability operation
            operation = await create_service_restart_operation(
                service_name=service_name,
                target_id=target_id,
                requested_by=requested_by,
                timeout=timeout
            )
            
            # Execute operation
            result = await self.capability_executor.execute_operation(operation, dry_run)
            
            return {
                "status": "success" if result.success else "failed",
                "operation_id": operation.id,
                "correlation_id": operation.correlation_id,
                "result": {
                    "success": result.success,
                    "status": result.status.value,
                    "output": result.output,
                    "error": result.error,
                    "duration": result.duration,
                    "exit_code": result.exit_code
                },
                "metadata": result.metadata
            }
            
        except Exception as e:
            logger.error(f"Service restart operation failed: {e}")
            return {
                "status": "error",
                "error": str(e),
                "service_name": service_name,
                "target_id": target_id
            }
    
    async def execute_container_operation(self,
                                        operation_type: str,
                                        container_name: str,
                                        target_id: str,
                                        requested_by: str,
                                        **kwargs) -> Dict[str, Any]:
        """Execute container operation with policy enforcement.
        
        Args:
            operation_type: Type of container operation
            container_name: Name of container
            target_id: Target identifier
            requested_by: User requesting the operation
            **kwargs: Additional operation parameters
            
        Returns:
            Operation result with status and details
        """
        try:
            # Validate operation type
            try:
                op_type = OperationType(operation_type)
            except ValueError:
                return {
                    "status": "error",
                    "error": f"Invalid operation type: {operation_type}"
                }
            
            # Create capability operation
            from src.services.capability_executor import create_container_operation
            operation = await create_container_operation(
                operation_type=op_type,
                container_name=container_name,
                target_id=target_id,
                requested_by=requested_by,
                **kwargs
            )
            
            # Execute operation
            result = await self.capability_executor.execute_operation(operation)
            
            return {
                "status": "success" if result.success else "failed",
                "operation_id": operation.id,
                "correlation_id": operation.correlation_id,
                "result": {
                    "success": result.success,
                    "status": result.status.value,
                    "output": result.output,
                    "error": result.error,
                    "duration": result.duration
                },
                "metadata": result.metadata
            }
            
        except Exception as e:
            logger.error(f"Container operation failed: {e}")
            return {
                "status": "error",
                "error": str(e),
                "operation_type": operation_type,
                "container_name": container_name,
                "target_id": target_id
            }
    
    async def execute_stack_operation(self,
                                    operation_type: str,
                                    stack_name: str,
                                    target_id: str,
                                    requested_by: str,
                                    config: Optional[Dict[str, Any]] = None,
                                    **kwargs) -> Dict[str, Any]:
        """Execute stack operation with policy enforcement.
        
        Args:
            operation_type: Type of stack operation
            stack_name: Name of stack
            target_id: Target identifier
            requested_by: User requesting the operation
            config: Stack configuration
            **kwargs: Additional operation parameters
            
        Returns:
            Operation result with status and details
        """
        try:
            # Validate operation type
            try:
                op_type = OperationType(operation_type)
            except ValueError:
                return {
                    "status": "error",
                    "error": f"Invalid operation type: {operation_type}"
                }
            
            # Create capability operation
            from src.models.policy_models import CapabilityOperation
            parameters = {"stack_name": stack_name}
            if config:
                parameters["config"] = config
            parameters.update(kwargs)
            
            operation = CapabilityOperation(
                name=f"{operation_type}_{stack_name}",
                capability=op_type,
                description=f"{operation_type.replace('_', ' ').title()} stack {stack_name}",
                parameters=parameters,
                target_id=target_id,
                target_role=TargetRole.DEVELOPMENT,  # Would be determined from target lookup
                requested_by=requested_by,
                request_reason=f"{operation_type} operation for stack {stack_name}"
            )
            
            # Execute operation
            result = await self.capability_executor.execute_operation(operation)
            
            return {
                "status": "success" if result.success else "failed",
                "operation_id": operation.id,
                "correlation_id": operation.correlation_id,
                "result": {
                    "success": result.success,
                    "status": result.status.value,
                    "output": result.output,
                    "error": result.error,
                    "duration": result.duration
                },
                "metadata": result.metadata
            }
            
        except Exception as e:
            logger.error(f"Stack operation failed: {e}")
            return {
                "status": "error",
                "error": str(e),
                "operation_type": operation_type,
                "stack_name": stack_name,
                "target_id": target_id
            }
    
    async def execute_backup_operation(self,
                                     operation_type: str,
                                     backup_id: str,
                                     target_path: str,
                                     target_id: str,
                                     requested_by: str,
                                     **kwargs) -> Dict[str, Any]:
        """Execute backup operation with policy enforcement.
        
        Args:
            operation_type: Type of backup operation
            backup_id: Backup identifier
            target_path: Path to backup
            target_id: Target identifier
            requested_by: User requesting the operation
            **kwargs: Additional operation parameters
            
        Returns:
            Operation result with status and details
        """
        try:
            # Validate operation type
            try:
                op_type = OperationType(operation_type)
            except ValueError:
                return {
                    "status": "error",
                    "error": f"Invalid operation type: {operation_type}"
                }
            
            # Create capability operation
            from src.services.capability_executor import create_backup_operation
            operation = await create_backup_operation(
                operation_type=op_type,
                backup_id=backup_id,
                target_path=target_path,
                target_id=target_id,
                requested_by=requested_by,
                **kwargs
            )
            
            # Execute operation
            result = await self.capability_executor.execute_operation(operation)
            
            return {
                "status": "success" if result.success else "failed",
                "operation_id": operation.id,
                "correlation_id": operation.correlation_id,
                "result": {
                    "success": result.success,
                    "status": result.status.value,
                    "output": result.output,
                    "error": result.error,
                    "duration": result.duration
                },
                "metadata": result.metadata
            }
            
        except Exception as e:
            logger.error(f"Backup operation failed: {e}")
            return {
                "status": "error",
                "error": str(e),
                "operation_type": operation_type,
                "backup_id": backup_id,
                "target_id": target_id
            }
    
    async def simulate_operation(self,
                               operation_type: str,
                               target_id: str,
                               requested_by: str,
                               parameters: Dict[str, Any],
                               target_role: str = "development") -> Dict[str, Any]:
        """Simulate an operation with policy checks (dry run).
        
        Args:
            operation_type: Type of operation to simulate
            target_id: Target identifier
            requested_by: User requesting the simulation
            parameters: Operation parameters
            target_role: Target role for policy evaluation
            
        Returns:
            Simulation results with policy analysis
        """
        try:
            # Create simulated capability operation
            from src.models.policy_models import CapabilityOperation
            
            try:
                op_type = OperationType(operation_type)
            except ValueError:
                return {
                    "status": "error",
                    "error": f"Invalid operation type: {operation_type}"
                }
            
            operation = CapabilityOperation(
                name=f"simulate_{operation_type}",
                capability=op_type,
                description=f"Simulation of {operation_type} operation",
                parameters=parameters,
                target_id=target_id,
                target_role=TargetRole(target_role.lower()),
                dry_run=True,
                requested_by=requested_by,
                request_reason=f"Simulation of {operation_type} operation"
            )
            
            # Create policy context
            from src.models.policy_models import PolicyContext
            context = PolicyContext(
                operation=operation,
                target_role=TargetRole(target_role.lower()),
                user_id=requested_by,
                current_time=datetime.utcnow()
            )
            
            # Evaluate policy
            policy_result = await self.policy_engine.evaluate_operation(operation, context)
            
            # Simulate capability execution
            result = await self.capability_executor.execute_operation(operation, dry_run=True)
            
            return {
                "status": "completed",
                "simulation_id": operation.correlation_id,
                "operation": {
                    "type": operation_type,
                    "parameters": parameters,
                    "target_id": target_id,
                    "target_role": target_role
                },
                "policy_evaluation": {
                    "decision": policy_result.decision.value,
                    "reason": policy_result.reason,
                    "matched_rules": policy_result.matched_rules,
                    "required_approvals": policy_result.required_approvals
                },
                "simulation_result": {
                    "success": result.success,
                    "status": result.status.value,
                    "output": result.output,
                    "duration": result.duration,
                    "dry_run": True
                },
                "recommendations": self._generate_simulation_recommendations(policy_result, result)
            }
            
        except Exception as e:
            logger.error(f"Operation simulation failed: {e}")
            return {
                "status": "error",
                "error": str(e),
                "operation_type": operation_type,
                "target_id": target_id
            }
    
    def _generate_simulation_recommendations(self, policy_result, execution_result) -> List[str]:
        """Generate recommendations based on simulation results."""
        recommendations = []
        
        # Policy-based recommendations
        if policy_result.decision.value == "deny":
            recommendations.append("Operation is denied by current policies - review policy configuration")
        elif policy_result.decision.value == "require_approval":
            recommendations.append("Operation requires approval before execution")
        elif policy_result.decision.value == "dry_run_only":
            recommendations.append("Operation is restricted to dry-run only")
        
        # Execution-based recommendations
        if not execution_result.success:
            recommendations.append("Operation simulation failed - check parameters and target connectivity")
        
        # General recommendations
        if len(policy_result.matched_rules) == 0:
            recommendations.append("No specific policies matched - operation allowed by default")
        
        return recommendations
    
    async def validate_operation_parameters(self,
                                          operation_type: str,
                                          parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Validate operation parameters without execution.
        
        Args:
            operation_type: Type of operation
            parameters: Parameters to validate
            
        Returns:
            Validation results
        """
        try:
            # Get validator from capability executor
            validator = self.capability_executor.validator
            
            # Convert operation type
            try:
                op_type = OperationType(operation_type)
            except ValueError:
                return {
                    "valid": False,
                    "errors": [f"Invalid operation type: {operation_type}"]
                }
            
            # Validate parameters
            is_valid, errors = validator.validate_parameters(op_type, parameters)
            
            return {
                "valid": is_valid,
                "operation_type": operation_type,
                "parameters": parameters,
                "errors": errors,
                "validation_timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Parameter validation failed: {e}")
            return {
                "valid": False,
                "error": str(e),
                "operation_type": operation_type
            }
    
    async def get_operation_status(self, operation_id: str) -> Dict[str, Any]:
        """Get status of a capability operation.
        
        Args:
            operation_id: Operation identifier
            
        Returns:
            Operation status information
        """
        # This would typically query a persistent operation store
        # For now, return placeholder information
        return {
            "operation_id": operation_id,
            "status": "unknown",
            "message": "Operation status tracking not yet implemented",
            "timestamp": datetime.utcnow().isoformat()
        }


class PolicyManagementTools:
    """MCP tools for policy management and configuration."""
    
    def __init__(self, policy_engine: PolicyEngine, audit_logger: AuditLogger):
        """Initialize policy management tools.
        
        Args:
            policy_engine: Policy engine for management
            audit_logger: Audit logger for policy changes
        """
        self.policy_engine = policy_engine
        self.audit_logger = audit_logger
    
    async def get_policy_status(self) -> Dict[str, Any]:
        """Get current policy configuration status.
        
        Returns:
            Policy status information
        """
        try:
            status = self.policy_engine.get_policy_status()
            
            return {
                "status": "success",
                "policy_status": status,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get policy status: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def list_allowed_operations(self, 
                                    target_role: str,
                                    user_id: Optional[str] = None) -> Dict[str, Any]:
        """List operations allowed for a target role and user.
        
        Args:
            target_role: Target role to check
            user_id: Optional user ID for user-specific permissions
            
        Returns:
            List of allowed operations
        """
        try:
            # Validate target role
            try:
                role = TargetRole(target_role.lower())
            except ValueError:
                return {
                    "status": "error",
                    "error": f"Invalid target role: {target_role}"
                }
            
            # Get allowed operations
            allowed_ops = self.policy_engine.list_allowed_operations(role, user_id)
            
            return {
                "status": "success",
                "target_role": target_role,
                "user_id": user_id,
                "allowed_operations": [op.value for op in allowed_ops],
                "operation_count": len(allowed_ops),
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to list allowed operations: {e}")
            return {
                "status": "error",
                "error": str(e),
                "target_role": target_role
            }
    
    async def validate_policy_config(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a policy configuration.
        
        Args:
            config_data: Policy configuration data
            
        Returns:
            Validation results
        """
        try:
            # Import policy config class
            from src.models.policy_models import PolicyConfig
            
            # Create policy config object
            config = PolicyConfig(**config_data)
            
            # Validate configuration
            validation_result = validate_policy_config(config)
            
            return {
                "status": "success",
                "valid": validation_result.is_valid,
                "errors": validation_result.errors,
                "warnings": validation_result.warnings,
                "suggestions": validation_result.suggestions,
                "rule_validations": validation_result.rule_validations,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Policy configuration validation failed: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def update_policy_config(self,
                                 config_data: Dict[str, Any],
                                 changed_by: str,
                                 change_reason: Optional[str] = None) -> Dict[str, Any]:
        """Update policy configuration.
        
        Args:
            config_data: New policy configuration
            changed_by: User making the change
            change_reason: Reason for the change
            
        Returns:
            Update result
        """
        try:
            # Import policy config class
            from src.models.policy_models import PolicyConfig
            
            # Create policy config object
            config = PolicyConfig(**config_data)
            
            # Update configuration
            success = self.policy_engine.update_policy_config(config, changed_by, change_reason)
            
            if success:
                return {
                    "status": "success",
                    "config_id": config.id,
                    "changed_by": changed_by,
                    "change_reason": change_reason,
                    "timestamp": datetime.utcnow().isoformat()
                }
            else:
                return {
                    "status": "error",
                    "error": "Policy configuration update failed"
                }
                
        except Exception as e:
            logger.error(f"Policy configuration update failed: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def rollback_policy(self,
                            history_entry_id: str,
                            rolled_back_by: str) -> Dict[str, Any]:
        """Rollback policy configuration to a previous version.
        
        Args:
            history_entry_id: ID of history entry to rollback to
            rolled_back_by: User performing the rollback
            
        Returns:
            Rollback result
        """
        try:
            success = self.policy_engine.rollback_policy(history_entry_id, rolled_back_by)
            
            if success:
                return {
                    "status": "success",
                    "history_entry_id": history_entry_id,
                    "rolled_back_by": rolled_back_by,
                    "timestamp": datetime.utcnow().isoformat()
                }
            else:
                return {
                    "status": "error",
                    "error": "Policy rollback failed"
                }
                
        except Exception as e:
            logger.error(f"Policy rollback failed: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def simulate_policy_scenario(self,
                                     operation_type: str,
                                     target_role: str,
                                     user_id: str,
                                     parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate a policy evaluation scenario.
        
        Args:
            operation_type: Type of operation
            target_role: Target role for evaluation
            user_id: User ID for evaluation
            parameters: Operation parameters
            
        Returns:
            Simulation results
        """
        try:
            # Create simulated operation
            from src.models.policy_models import CapabilityOperation, PolicyContext
            
            try:
                op_type = OperationType(operation_type)
            except ValueError:
                return {
                    "status": "error",
                    "error": f"Invalid operation type: {operation_type}"
                }
            
            operation = CapabilityOperation(
                name=f"scenario_{operation_type}",
                capability=op_type,
                description=f"Scenario simulation of {operation_type}",
                parameters=parameters,
                target_id="scenario_target",
                target_role=TargetRole(target_role.lower()),
                requested_by=user_id,
                request_reason="Policy scenario simulation"
            )
            
            context = PolicyContext(
                operation=operation,
                target_role=TargetRole(target_role.lower()),
                user_id=user_id,
                current_time=datetime.utcnow()
            )
            
            # Simulate policy evaluation
            simulation_result = self.policy_engine.simulate_policy_scenario(operation, context)
            
            return {
                "status": "success",
                "simulation": simulation_result,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Policy scenario simulation failed: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    async def get_policy_history(self, limit: int = 10) -> Dict[str, Any]:
        """Get policy change history.
        
        Args:
            limit: Maximum number of history entries to return
            
        Returns:
            Policy history entries
        """
        try:
            history = self.policy_engine.policy_history[-limit:] if self.policy_engine.policy_history else []
            
            return {
                "status": "success",
                "history": [
                    {
                        "id": entry.id,
                        "policy_id": entry.policy_id,
                        "change_type": entry.change_type,
                        "changed_by": entry.changed_by,
                        "changed_at": entry.changed_at.isoformat(),
                        "change_reason": entry.change_reason
                    }
                    for entry in history
                ],
                "total_entries": len(self.policy_engine.policy_history),
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get policy history: {e}")
            return {
                "status": "error",
                "error": str(e)
            }


# Global tool instances (would be initialized by the MCP server)
capability_tools = None
policy_management_tools = None


def initialize_capability_tools(capability_executor: CapabilityExecutor,
                               policy_engine: PolicyEngine,
                               audit_logger: AuditLogger):
    """Initialize global capability tools."""
    global capability_tools, policy_management_tools
    capability_tools = CapabilityTools(capability_executor, policy_engine, audit_logger)
    policy_management_tools = PolicyManagementTools(policy_engine, audit_logger)