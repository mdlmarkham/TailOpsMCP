"""
Execution service for orchestrating command execution across different targets.
"""

import logging
import time
from typing import Dict, List, Optional

from src.models.execution import ExecutionRequest, ExecutionResult, ExecutionBatchResult
from src.models.target_registry import TargetMetadata, TargetConnection
from src.services.executor_factory import ExecutorFactory
from src.services.executor import Executor

logger = logging.getLogger(__name__)


class ExecutionService:
    """Service for orchestrating command execution across different targets."""
    
    def __init__(self, executor_factory: ExecutorFactory):
        """Initialize execution service.
        
        Args:
            executor_factory: Factory for creating executors
        """
        self.executor_factory = executor_factory
    
    def execute_on_target(self, target: TargetMetadata, command: str, 
                         **kwargs) -> ExecutionResult:
        """Execute command on specific target.
        
        Args:
            target: Target metadata
            command: Command to execute
            **kwargs: Additional execution parameters
            
        Returns:
            Execution result
        """
        # Create executor for target
        executor = self.executor_factory.create_executor(target.connection)
        if not executor:
            return ExecutionResult(
                status="connection_error",
                success=False,
                error=f"Failed to create executor for target {target.id}",
                duration=0.0
            )
        
        # Execute command
        try:
            with executor:
                result = executor.execute_command(command, **kwargs)
                return result
        except Exception as e:
            return ExecutionResult(
                status="failure",
                success=False,
                error=str(e),
                duration=0.0
            )
    
    def execute_batch(self, requests: List[ExecutionRequest]) -> ExecutionBatchResult:
        """Execute multiple commands in batch.
        
        Args:
            requests: List of execution requests
            
        Returns:
            Batch execution result
        """
        start_time = time.time()
        results: Dict[str, ExecutionResult] = {}
        
        for i, request in enumerate(requests):
            request_id = f"request_{i}"
            
            if request.dry_run:
                results[request_id] = ExecutionResult(
                    status="success",
                    success=True,
                    output=f"Dry run: {request.command}",
                    duration=0.0,
                    metadata={"dry_run": True}
                )
                continue
            
            # TODO: Implement actual execution based on executor_type and target_id
            # This would require integration with TargetRegistry
            results[request_id] = ExecutionResult(
                status="failure",
                success=False,
                error="Batch execution not yet implemented",
                duration=0.0
            )
        
        total_duration = time.time() - start_time
        success_count = sum(1 for r in results.values() if r.success)
        failure_count = len(results) - success_count
        
        return ExecutionBatchResult(
            results=results,
            total_duration=total_duration,
            success_count=success_count,
            failure_count=failure_count
        )
    
    def test_connection(self, connection: TargetConnection) -> ExecutionResult:
        """Test connection to target.
        
        Args:
            connection: Target connection configuration
            
        Returns:
            Connection test result
        """
        start_time = time.time()
        
        try:
            executor = self.executor_factory.create_executor(connection)
            if not executor:
                return ExecutionResult(
                    status="connection_error",
                    success=False,
                    error="Failed to create executor",
                    duration=time.time() - start_time
                )
            
            # Test connection
            connected = executor.connect()
            duration = time.time() - start_time
            
            if connected:
                executor.disconnect()
                return ExecutionResult(
                    status="success",
                    success=True,
                    output="Connection successful",
                    duration=duration
                )
            else:
                return ExecutionResult(
                    status="connection_error",
                    success=False,
                    error="Connection failed",
                    duration=duration
                )
                
        except Exception as e:
            duration = time.time() - start_time
            return ExecutionResult(
                status="failure",
                success=False,
                error=str(e),
                duration=duration
            )
    
    def get_executor_info(self, connection: TargetConnection) -> Dict[str, Any]:
        """Get information about executor for connection.
        
        Args:
            connection: Target connection configuration
            
        Returns:
            Executor information dictionary
        """
        executor = self.executor_factory.create_executor(connection)
        if not executor:
            return {"error": "Failed to create executor"}
        
        return {
            "executor_type": connection.executor.value,
            "connected": executor.is_connected(),
            "timeout": executor.timeout,
            "retry_attempts": executor.retry_attempts,
            "retry_delay": executor.retry_delay
        }