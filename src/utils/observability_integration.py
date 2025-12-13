"""
Integration layer to update existing components with new observability features.
"""

import uuid
from typing import Any, Dict, Optional

from src.models.execution import ExecutionResult, ExecutionRequest, ExecutionStatus, StructuredError
from src.utils.audit_enhanced import AuditLogger, LogLevel
from src.utils.logging_config import SystemLogger, get_logger, metrics_collector, health_checker
from src.utils.observability_config import generate_correlation_id


class ObservabilityIntegration:
    """Integration layer for adding observability to existing components."""
    
    @staticmethod
    def enhance_execution_result(
        original_result: Dict[str, Any],
        correlation_id: Optional[str] = None,
        target_id: Optional[str] = None,
        capability: Optional[str] = None,
        executor_type: Optional[str] = None,
        dry_run: bool = False
    ) -> ExecutionResult:
        """Convert a legacy execution result to the enhanced ExecutionResult model."""
        
        # Determine status and success
        success = original_result.get("success", False)
        status = ExecutionStatus.SUCCESS if success else ExecutionStatus.FAILURE
        
        # Create enhanced result
        result = ExecutionResult(
            status=status,
            success=success,
            exit_code=original_result.get("exit_code"),
            output=original_result.get("output"),
            error=original_result.get("error"),
            duration=original_result.get("duration", 0.0),
            correlation_id=correlation_id or generate_correlation_id(),
            target_id=target_id,
            capability=capability,
            executor_type=executor_type,
            dry_run=dry_run
        )
        
        # Add structured error if present
        if "error" in original_result and original_result["error"]:
            result.set_structured_error(
                code="execution_error",
                message=original_result["error"],
                details={"original_result": original_result}
            )
        
        return result
    
    @staticmethod
    def enhance_execution_request(
        command: str,
        executor_type: str,
        target_id: Optional[str] = None,
        capability: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        dry_run: bool = False
    ) -> ExecutionRequest:
        """Create an enhanced execution request with observability features."""
        
        return ExecutionRequest(
            command=command,
            executor_type=executor_type,
            target_id=target_id,
            capability=capability,
            parameters=parameters or {},
            dry_run=dry_run,
            correlation_id=generate_correlation_id()
        )
    
    @staticmethod
    def log_operation_with_metrics(
        operation: str,
        target: Optional[str] = None,
        capability: Optional[str] = None,
        executor_type: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        success: bool = True,
        duration: Optional[float] = None,
        error: Optional[str] = None
    ) -> str:
        """Log an operation with comprehensive metrics collection."""
        
        correlation_id = generate_correlation_id()
        
        # Start metrics collection
        metrics_collector.start_timer(operation)
        
        # Log the operation
        AuditLogger().log_operation(
            operation=operation,
            correlation_id=correlation_id,
            target=target,
            capability=capability,
            executor_type=executor_type,
            parameters=parameters or {},
            status=ExecutionStatus.SUCCESS if success else ExecutionStatus.FAILURE,
            success=success,
            duration=duration,
            error=error
        )
        
        # Record metrics
        if duration is not None:
            metrics_collector.record_gauge(f"{operation}_duration", duration)
        
        metrics_collector.increment_counter(f"{operation}_count")
        if success:
            metrics_collector.increment_counter(f"{operation}_success")
        else:
            metrics_collector.increment_counter(f"{operation}_failure")
        
        return correlation_id


class LegacyAuditLoggerAdapter:
    """Adapter to maintain backward compatibility with the original AuditLogger."""
    
    def __init__(self):
        self.enhanced_logger = AuditLogger()
        self.logger = get_logger("legacy_adapter")
    
    def log(
        self,
        tool: str,
        args: Dict[str, Any],
        result: Dict[str, Any],
        subject: Optional[str] = None,
        truncated: bool = False,
        dry_run: bool = False,
        scopes: Optional[list] = None,
        risk_level: Optional[str] = None,
        approved: Optional[bool] = None
    ) -> None:
        """Adapt the legacy log method to use the enhanced audit logger."""
        
        correlation_id = generate_correlation_id()
        
        # Convert legacy result to enhanced format
        success = result.get("success", False)
        status = ExecutionStatus.SUCCESS if success else ExecutionStatus.FAILURE
        
        # Log using enhanced system
        self.enhanced_logger.log_operation(
            operation=tool,
            correlation_id=correlation_id,
            target=None,  # Legacy doesn't have target concept
            capability=tool,  # Use tool as capability
            executor_type="legacy",
            parameters=args,
            status=status,
            success=success,
            duration=result.get("duration"),
            subject=subject,
            scopes=scopes or [],
            risk_level=risk_level,
            approved=approved,
            error=result.get("error"),
            dry_run=dry_run
        )
        
        # Also log to structured logging
        self.logger.info(
            f"Legacy audit log adapted: {tool}",
            correlation_id=correlation_id,
            tool=tool,
            success=success,
            dry_run=dry_run
        )


class ToolIntegration:
    """Integration for capability-driven tools with observability."""
    
    @staticmethod
    def wrap_tool_execution(
        tool_func,
        tool_name: str,
        capability: Optional[str] = None
    ):
        """Wrap a tool function with observability features."""
        
        def wrapped_tool(*args, **kwargs):
            correlation_id = generate_correlation_id()
            logger = get_logger(tool_name, correlation_id)
            
            # Extract common parameters
            target = kwargs.get("target", "local")
            dry_run = kwargs.get("dry_run", False)
            
            # Start timing
            metrics_collector.start_timer(tool_name)
            
            try:
                logger.info(f"Starting {tool_name} execution", target=target, dry_run=dry_run)
                
                # Execute the tool
                result = tool_func(*args, **kwargs)
                
                # Calculate duration
                duration = metrics_collector.stop_timer(tool_name)
                
                # Log success
                AuditLogger().log_operation(
                    operation=tool_name,
                    correlation_id=correlation_id,
                    target=target,
                    capability=capability or tool_name,
                    executor_type="tool",
                    parameters=kwargs,
                    status=ExecutionStatus.SUCCESS,
                    success=True,
                    duration=duration
                )
                
                logger.info(f"{tool_name} completed successfully", duration=duration)
                
                return result
                
            except Exception as e:
                # Calculate duration even on error
                duration = metrics_collector.stop_timer(tool_name)
                
                # Log error
                AuditLogger().log_operation(
                    operation=tool_name,
                    correlation_id=correlation_id,
                    target=target,
                    capability=capability or tool_name,
                    executor_type="tool",
                    parameters=kwargs,
                    status=ExecutionStatus.FAILURE,
                    success=False,
                    duration=duration,
                    error=str(e)
                )
                
                logger.error(f"{tool_name} failed: {e}", duration=duration)
                raise
        
        return wrapped_tool


# Global integration instances
observability_integration = ObservabilityIntegration()
legacy_adapter = LegacyAuditLoggerAdapter()


def integrate_with_existing_system() -> None:
    """Integrate observability features with the existing system."""
    
    logger = get_logger("integration")
    
    # Test integration
    try:
        # Generate a test correlation ID
        test_id = generate_correlation_id()
        
        # Log integration start
        AuditLogger().log_structured(
            level=LogLevel.INFO,
            message="Observability integration initialized",
            correlation_id=test_id
        )
        
        logger.info("Observability features integrated successfully")
        
    except Exception as e:
        logger.error(f"Observability integration failed: {e}")


# Initialize integration when module is imported
integrate_with_existing_system()