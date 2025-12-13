"""
Execution Abstraction Layer - Unified executor interface and result models.
"""

from __future__ import annotations

import abc
import time
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class ExecutionStatus(str, Enum):
    """Execution result status."""
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"
    AUTHENTICATION_ERROR = "authentication_error"
    PERMISSION_ERROR = "permission_error"


class ExecutionResult(BaseModel):
    """Standardized execution result model."""
    
    status: ExecutionStatus = Field(..., description="Execution status")
    success: bool = Field(..., description="Whether execution was successful")
    exit_code: Optional[int] = Field(None, description="Process exit code")
    output: Optional[str] = Field(None, description="Standard output")
    error: Optional[str] = Field(None, description="Error output")
    duration: float = Field(..., description="Execution duration in seconds")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Execution timestamp")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    
    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for backward compatibility."""
        return {
            "success": self.success,
            "exit_code": self.exit_code,
            "output": self.output,
            "error": self.error,
            "status": self.status.value,
            "duration": self.duration,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata
        }


class Executor(abc.ABC):
    """Abstract base class for all executors."""
    
    def __init__(self, timeout: int = 30, retry_attempts: int = 3, retry_delay: float = 1.0):
        """Initialize executor with common configuration.
        
        Args:
            timeout: Default timeout in seconds
            retry_attempts: Number of retry attempts for failed operations
            retry_delay: Delay between retries in seconds
        """
        self.timeout = timeout
        self.retry_attempts = retry_attempts
        self.retry_delay = retry_delay
        self._connected = False
    
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
    
    def is_connected(self) -> bool:
        """Check if executor is connected to target.
        
        Returns:
            True if connected, False otherwise
        """
        return self._connected
    
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
    
    def _create_result(self, status: ExecutionStatus, success: bool, 
                      exit_code: Optional[int] = None, output: Optional[str] = None,
                      error: Optional[str] = None, duration: float = 0.0,
                      metadata: Optional[Dict[str, Any]] = None) -> ExecutionResult:
        """Create standardized execution result.
        
        Args:
            status: Execution status
            success: Whether execution was successful
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
            exit_code=exit_code,
            output=output,
            error=error,
            duration=duration,
            metadata=metadata or {}
        )