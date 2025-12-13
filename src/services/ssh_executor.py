"""
SSH executor implementation for remote target operations.
"""

import logging
import os
import paramiko
import socket
import time
from typing import Any, Dict, Optional

from src.services.executor import Executor, ExecutionResult, ExecutionStatus

logger = logging.getLogger(__name__)


class SSHExecutor(Executor):
    """SSH executor for remote target operations."""
    
    def __init__(self, host: str, port: int, username: str, key_path: str, timeout: int = 30,
                 retry_attempts: int = 3, retry_delay: float = 1.0):
        """Initialize SSH executor.
        
        Args:
            host: Target hostname or IP address.
            port: SSH port.
            username: SSH username.
            key_path: Path to SSH private key or environment variable name.
            timeout: Connection timeout in seconds.
            retry_attempts: Number of retry attempts for failed operations
            retry_delay: Delay between retries in seconds
        """
        super().__init__(timeout, retry_attempts, retry_delay)
        self.host = host
        self.port = port
        self.username = username
        self.key_path = key_path
        self.client: Optional[paramiko.SSHClient] = None
    
    def connect(self) -> bool:
        """Establish SSH connection to target.
        
        Returns:
            True if connection successful, False otherwise.
        """
        for attempt in range(self.retry_attempts):
            try:
                self.client = paramiko.SSHClient()
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                # Resolve key path from environment variable if needed
                actual_key_path = self.key_path
                if self.key_path.startswith("$"):
                    env_var = self.key_path[1:]
                    actual_key_path = os.getenv(env_var)
                    if not actual_key_path:
                        logger.error(f"Environment variable not found: {env_var}")
                        return False
                
                # Load private key
                key = paramiko.RSAKey.from_private_key_file(actual_key_path)
                
                self.client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    pkey=key,
                    timeout=self.timeout,
                    banner_timeout=self.timeout
                )
                
                self._connected = True
                logger.info(f"SSH connection established to {self.host}:{self.port}")
                return True
                
            except (paramiko.AuthenticationException, paramiko.SSHException,
                    socket.timeout, socket.error) as e:
                logger.warning(f"SSH connection attempt {attempt + 1} failed: {str(e)}")
                self.client = None
                
                if attempt < self.retry_attempts - 1:
                    time.sleep(self.retry_delay)
                else:
                    logger.error(f"SSH connection failed after {self.retry_attempts} attempts")
                    return False
        
        return False
    
    def disconnect(self) -> None:
        """Close SSH connection."""
        if self.client:
            self.client.close()
            self.client = None
        self._connected = False
        logger.info(f"SSH connection closed to {self.host}:{self.port}")
    
    def execute_command(self, command: str, **kwargs) -> ExecutionResult:
        """Execute command on remote target.
        
        Args:
            command: Command to execute
            **kwargs: Additional parameters (sudo, timeout, etc.)
            
        Returns:
            ExecutionResult with standardized output
        """
        if not self._connected:
            return self._create_result(
                status=ExecutionStatus.CONNECTION_ERROR,
                success=False,
                error="SSH connection not established"
            )
        
        start_time = time.time()
        
        try:
            # Extract optional parameters
            sudo = kwargs.get('sudo', False)
            timeout = kwargs.get('timeout', self.timeout)
            
            # Add sudo prefix if requested
            actual_command = f"sudo {command}" if sudo else command
            
            stdin, stdout, stderr = self.client.exec_command(actual_command, timeout=timeout)
            
            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode('utf-8').strip()
            error_output = stderr.read().decode('utf-8').strip()
            
            duration = time.time() - start_time
            
            # Determine status based on exit code
            if exit_code == 0:
                status = ExecutionStatus.SUCCESS
            else:
                status = ExecutionStatus.FAILURE
            
            return self._create_result(
                status=status,
                success=exit_code == 0,
                exit_code=exit_code,
                output=output,
                error=error_output,
                duration=duration,
                metadata={
                    "command": command,
                    "sudo": sudo,
                    "timeout": timeout
                }
            )
            
        except socket.timeout:
            duration = time.time() - start_time
            return self._create_result(
                status=ExecutionStatus.TIMEOUT,
                success=False,
                duration=duration,
                error=f"Command timed out after {timeout} seconds",
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
                "command": actual_command
            }
            
        except Exception as e:
            logger.error(f"Command execution failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def test_connection(self) -> bool:
        """Test SSH connection by executing a simple command.
        
        Returns:
            True if connection test successful, False otherwise.
        """
        result = self.execute_command("echo 'connection test'")
        return result["success"]
    
    def disconnect(self) -> None:
        """Close SSH connection."""
        if self.client:
            self.client.close()
            self.client = None
            logger.info(f"SSH connection closed to {self.host}:{self.port}")
    
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()