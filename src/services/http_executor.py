"""
HTTP executor implementation for REST API operations.
"""

import logging
import time
from typing import Any, Dict, Optional

import httpx

from src.services.executor import Executor, ExecutionResult, ExecutionStatus

logger = logging.getLogger(__name__)


class HTTPExecutor(Executor):
    """HTTP executor for REST API operations."""
    
    def __init__(self, base_url: str, timeout: int = 30, retry_attempts: int = 3, 
                 retry_delay: float = 1.0, headers: Optional[Dict[str, str]] = None):
        """Initialize HTTP executor.
        
        Args:
            base_url: Base URL for API endpoints
            timeout: Request timeout in seconds
            retry_attempts: Number of retry attempts
            retry_delay: Delay between retries in seconds
            headers: Default headers for requests
        """
        super().__init__(timeout, retry_attempts, retry_delay)
        self.base_url = base_url.rstrip('/')
        self.headers = headers or {}
        self.client: Optional[httpx.Client] = None
    
    def connect(self) -> bool:
        """Establish HTTP connection (always successful for HTTP executor).
        
        Returns:
            Always True for HTTP executor
        """
        self.client = httpx.Client(
            base_url=self.base_url,
            timeout=self.timeout,
            headers=self.headers
        )
        self._connected = True
        logger.info(f"HTTP executor connected to {self.base_url}")
        return True
    
    def disconnect(self) -> None:
        """Close HTTP connection."""
        if self.client:
            self.client.close()
            self.client = None
        self._connected = False
        logger.info(f"HTTP executor disconnected from {self.base_url}")
    
    def execute_command(self, command: str, **kwargs) -> ExecutionResult:
        """Execute HTTP request.
        
        Args:
            command: HTTP method and endpoint (e.g., "GET /api/status")
            **kwargs: Additional parameters (method, endpoint, data, headers, etc.)
            
        Returns:
            ExecutionResult with standardized output
        """
        if not self._connected:
            return self._create_result(
                status=ExecutionStatus.CONNECTION_ERROR,
                success=False,
                error="HTTP connection not established"
            )
        
        start_time = time.time()
        
        try:
            # Parse command or use explicit parameters
            if ' ' in command:
                method, endpoint = command.split(' ', 1)
            else:
                method = kwargs.get('method', 'GET')
                endpoint = command
            
            # Extract optional parameters
            data = kwargs.get('data')
            headers = kwargs.get('headers', {})
            params = kwargs.get('params', {})
            timeout = kwargs.get('timeout', self.timeout)
            
            # Make HTTP request
            response = self.client.request(
                method=method.upper(),
                url=endpoint,
                json=data,
                headers={**self.headers, **headers},
                params=params,
                timeout=timeout
            )
            
            duration = time.time() - start_time
            
            # Determine status based on HTTP status code
            if 200 <= response.status_code < 300:
                status = ExecutionStatus.SUCCESS
            else:
                status = ExecutionStatus.FAILURE
            
            return self._create_result(
                status=status,
                success=200 <= response.status_code < 300,
                exit_code=response.status_code,
                output=response.text,
                error=None,
                duration=duration,
                metadata={
                    "method": method,
                    "endpoint": endpoint,
                    "status_code": response.status_code,
                    "headers": dict(response.headers)
                }
            )
            
        except httpx.TimeoutException:
            duration = time.time() - start_time
            return self._create_result(
                status=ExecutionStatus.TIMEOUT,
                success=False,
                duration=duration,
                error=f"HTTP request timed out after {timeout} seconds",
                metadata={"method": method, "endpoint": endpoint}
            )
            
        except httpx.RequestError as e:
            duration = time.time() - start_time
            return self._create_result(
                status=ExecutionStatus.CONNECTION_ERROR,
                success=False,
                duration=duration,
                error=str(e),
                metadata={"method": method, "endpoint": endpoint}
            )
            
        except Exception as e:
            duration = time.time() - start_time
            return self._create_result(
                status=ExecutionStatus.FAILURE,
                success=False,
                duration=duration,
                error=str(e),
                metadata={"method": method, "endpoint": endpoint}
            )