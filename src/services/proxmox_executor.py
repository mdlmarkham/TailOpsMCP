"""
Proxmox executor implementation for Proxmox API operations.
"""

import logging
import time
from typing import Any, Dict, Optional

import httpx

from src.services.executor import Executor, ExecutionResult, ExecutionStatus

logger = logging.getLogger(__name__)


class ProxmoxExecutor(Executor):
    """Proxmox executor for Proxmox API operations."""
    
    def __init__(self, host: str, username: str, password: str, port: int = 8006,
                 timeout: int = 30, retry_attempts: int = 3, retry_delay: float = 1.0,
                 verify_ssl: bool = True):
        """Initialize Proxmox executor.
        
        Args:
            host: Proxmox hostname or IP address
            username: Proxmox username
            password: Proxmox password or token
            port: Proxmox API port (default: 8006)
            timeout: Request timeout in seconds
            retry_attempts: Number of retry attempts
            retry_delay: Delay between retries in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        super().__init__(timeout, retry_attempts, retry_delay)
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.verify_ssl = verify_ssl
        self.base_url = f"https://{host}:{port}/api2/json"
        self.client: Optional[httpx.Client] = None
        self.ticket: Optional[str] = None
        self.csrf_token: Optional[str] = None
    
    def connect(self) -> bool:
        """Establish Proxmox API connection.
        
        Returns:
            True if connection successful, False otherwise
        """
        for attempt in range(self.retry_attempts):
            try:
                # Create HTTP client
                self.client = httpx.Client(
                    base_url=self.base_url,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                # Authenticate and get ticket
                auth_response = self.client.post(
                    "/access/ticket",
                    data={
                        "username": self.username,
                        "password": self.password
                    }
                )
                
                if auth_response.status_code != 200:
                    raise Exception(f"Authentication failed: {auth_response.text}")
                
                auth_data = auth_response.json()
                self.ticket = auth_data["data"]["ticket"]
                self.csrf_token = auth_data["data"]["CSRFPreventionToken"]
                
                self._connected = True
                logger.info(f"Proxmox connection established to {self.host}:{self.port}")
                return True
                
            except Exception as e:
                logger.warning(f"Proxmox connection attempt {attempt + 1} failed: {str(e)}")
                self.client = None
                
                if attempt < self.retry_attempts - 1:
                    time.sleep(self.retry_delay)
                else:
                    logger.error(f"Proxmox connection failed after {self.retry_attempts} attempts")
                    return False
        
        return False
    
    def disconnect(self) -> None:
        """Close Proxmox connection."""
        if self.client:
            self.client.close()
            self.client = None
        self.ticket = None
        self.csrf_token = None
        self._connected = False
        logger.info(f"Proxmox connection closed to {self.host}:{self.port}")
    
    def execute_command(self, command: str, **kwargs) -> ExecutionResult:
        """Execute Proxmox API command.
        
        Args:
            command: Proxmox API endpoint (e.g., "/nodes/{node}/qemu")
            **kwargs: Additional parameters (method, data, etc.)
            
        Returns:
            ExecutionResult with standardized output
        """
        if not self._connected:
            return self._create_result(
                status=ExecutionStatus.CONNECTION_ERROR,
                success=False,
                error="Proxmox connection not established"
            )
        
        start_time = time.time()
        
        try:
            # Extract optional parameters
            method = kwargs.get('method', 'GET')
            data = kwargs.get('data')
            
            # Prepare headers with authentication
            headers = {
                "Cookie": f"PVEAuthCookie={self.ticket}"
            }
            
            # Add CSRF token for write operations
            if method in ['POST', 'PUT', 'DELETE']:
                headers["CSRFPreventionToken"] = self.csrf_token
            
            # Make API request
            response = self.client.request(
                method=method.upper(),
                url=command,
                json=data,
                headers=headers
            )
            
            duration = time.time() - start_time
            
            # Determine status based on API response
            if response.status_code == 200:
                status = ExecutionStatus.SUCCESS
            else:
                status = ExecutionStatus.FAILURE
            
            return self._create_result(
                status=status,
                success=response.status_code == 200,
                exit_code=response.status_code,
                output=response.text,
                error=None,
                duration=duration,
                metadata={
                    "method": method,
                    "endpoint": command,
                    "status_code": response.status_code
                }
            )
            
        except httpx.TimeoutException:
            duration = time.time() - start_time
            return self._create_result(
                status=ExecutionStatus.TIMEOUT,
                success=False,
                duration=duration,
                error=f"Proxmox API request timed out after {self.timeout} seconds",
                metadata={"endpoint": command}
            )
            
        except httpx.RequestError as e:
            duration = time.time() - start_time
            return self._create_result(
                status=ExecutionStatus.CONNECTION_ERROR,
                success=False,
                duration=duration,
                error=str(e),
                metadata={"endpoint": command}
            )
            
        except Exception as e:
            duration = time.time() - start_time
            return self._create_result(
                status=ExecutionStatus.FAILURE,
                success=False,
                duration=duration,
                error=str(e),
                metadata={"endpoint": command}
            )