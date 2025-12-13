"""
Local executor implementation for local command execution.
"""

import logging
import subprocess
import time
from typing import Any, Dict, Optional

from src.services.executor import Executor, ExecutionResult, ExecutionStatus

logger = logging.getLogger(__name__)


class LocalExecutor(Executor):
    """Local executor for local command execution."""
    
    def __init__(self, timeout: int = 30, retry_attempts: int = 3, retry_delay: float = 1.0):
        """Initialize local executor.
        
        Args:
            timeout: Command execution timeout in seconds
            retry_attempts: Number of retry attempts
            retry_delay: Delay between retries in seconds
        """
        super().__init__(timeout, retry_attempts, retry_delay)
    
    def connect(self) -> bool:
        """Establish local connection (always successful for local executor).
        
        Returns:
            Always True for local executor
        """
        self._connected = True
        logger.info("Local executor connected")
        return True
    
    def disconnect(self) -> None:
        """Disconnect local executor (no-op for local)."""
        self._connected = False
        logger.info("Local executor disconnected")
    
    def execute_command(self, command: str, **kwargs) -> ExecutionResult:
        """Execute command locally.
        
        Args:
            command: Command to execute
            **kwargs: Additional parameters (shell, cwd, env, etc.)
            
        Returns:
            ExecutionResult with standardized output
        """
        start_time = time.time()
        
        try:
            # Extract optional parameters
            shell = kwargs.get('shell', True)
            cwd = kwargs.get('cwd')
            env = kwargs.get('env')
            
            # Execute command
            process = subprocess.run(
                command,
                shell=shell,
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            duration = time.time() - start_time
            
            # Determine status based on exit code
            if process.returncode == 0:
                status = ExecutionStatus.SUCCESS
            else:
                status = ExecutionStatus.FAILURE
            
            return self._create_result(
                status=status,
                success=process.returncode == 0,
                exit_code=process.returncode,
                output=process.stdout,
                error=process.stderr,
                duration=duration,
                metadata={
                    "command": command,
                    "shell": shell,
                    "cwd": cwd
                }
            )
            
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return self._create_result(
                status=ExecutionStatus.TIMEOUT,
                success=False,
                duration=duration,
                error=f"Command timed out after {self.timeout} seconds",
                metadata={"command": command}
            )
            
        except Exception as e:
            duration = time.time() - start_time
            return self._create_result(
                status=ExecutionStatus.FAILURE,
                success=False,
                duration=duration,
                error=str(e),
                metadata={"command": command}
            )