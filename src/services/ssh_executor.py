"""
SSH executor implementation for remote target operations with security hardening.
"""

import logging
import os
import socket
import time
import shlex
from typing import Optional
from pathlib import Path

from src.services.executor import (
    Executor,
    ExecutionResult,
    ExecutionStatus,
    ExecutorConfig,
)

logger = logging.getLogger(__name__)

# Try to import paramiko, but make it optional
try:
    import paramiko
except ImportError:
    paramiko = None


class SSHExecutor(Executor):
    """SSH executor for remote target operations."""

    def __init__(self, config: ExecutorConfig):
        """Initialize SSH executor with security hardening.

        Args:
            config: Executor configuration
        """
        super().__init__(config)
        self.host = config.host
        self.port = config.port or 22
        self.username = config.username
        self.key_path = config.key_path
        self.known_hosts_file = os.path.expanduser("~/.ssh/known_hosts")
        self.allowed_ciphers = [
            "chacha20-poly1305@openssh.com",
            "aes256-gcm@openssh.com",
            "aes128-gcm@openssh.com",
            "aes256-ctr",
            "aes192-ctr",
            "aes128-ctr",
        ]
        self.cert_path = None
        self.client: Optional[paramiko.SSHClient] = None
        self._host_key_verified = False

    def is_available(self) -> bool:
        """Check if SSH executor is available.

        Returns:
            True if paramiko is available and basic configuration is set
        """
        if paramiko is None:
            return False
        return True

    def connect(self) -> bool:
        """Establish secure SSH connection to target with strict host key verification.

        Returns:
            True if connection successful, False otherwise.
        """
        if paramiko is None:
            logger.error("paramiko not available")
            return False

        for attempt in range(self.config.retry_attempts):
            try:
                self.client = paramiko.SSHClient()

                # Load and verify against known hosts file
                if os.path.exists(self.known_hosts_file):
                    self.client.load_host_keys(self.known_hosts_file)
                else:
                    # Create empty known_hosts file if it doesn't exist
                    Path(self.known_hosts_file).touch(mode=0o600)
                    self.client.load_host_keys(self.known_hosts_file)

                # Set missing host key policy to reject unknown hosts (strict verification)
                self.client.set_missing_host_key_policy(paramiko.RejectPolicy())

                # Resolve key path from environment variable if needed
                actual_key_path = self.key_path
                if actual_key_path and actual_key_path.startswith("$"):
                    env_var = actual_key_path[1:]
                    actual_key_path = os.getenv(env_var)
                    if not actual_key_path:
                        logger.error(f"Environment variable not found: {env_var}")
                        return False

                # Validate key file exists and has proper permissions
                if actual_key_path and not os.path.exists(actual_key_path):
                    logger.error(f"SSH key file not found: {actual_key_path}")
                    return False

                if actual_key_path and not os.access(actual_key_path, os.R_OK):
                    logger.error(f"SSH key file not readable: {actual_key_path}")
                    return False

                # Load private key if key path provided
                key = None
                if actual_key_path:
                    # Handle public key file - load corresponding private key
                    if actual_key_path.endswith(".pub"):
                        private_key_path = actual_key_path[:-4]
                        if os.path.exists(private_key_path):
                            actual_key_path = private_key_path
                        else:
                            logger.error(
                                f"Private key not found for public key: {actual_key_path}"
                            )
                            return False

                    key = paramiko.RSAKey.from_private_key_file(actual_key_path)

                # Prepare connection parameters
                connect_params = {
                    "hostname": self.host,
                    "port": self.port,
                    "username": self.username,
                    "pkey": key,
                    "timeout": self.config.timeout,
                    "banner_timeout": self.config.timeout,
                    "auth_timeout": self.config.timeout,
                    "compress": False,  # Disable compression for security
                    "gss_auth": False,  # Disable GSS authentication
                }

                # Connect with security checks
                self.client.connect(**connect_params)

                self._connected = True
                self._host_key_verified = True
                logger.info(f"SSH connection established to {self.host}:{self.port}")
                return True

            except (
                paramiko.AuthenticationException,
                paramiko.SSHException,
                socket.timeout,
                socket.error,
            ) as e:
                logger.warning(f"SSH connection attempt {attempt + 1} failed: {str(e)}")
                self.client = None

                if attempt < self.config.retry_attempts - 1:
                    time.sleep(self.config.retry_delay)
                else:
                    logger.error(
                        f"SSH connection failed after {self.config.retry_attempts} attempts"
                    )
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
        if not self._connected or not self.client:
            return self._create_result(
                status=ExecutionStatus.CONNECTION_ERROR,
                success=False,
                error="SSH connection not established",
            )

        start_time = time.time()

        try:
            # Extract optional parameters
            sudo = kwargs.get("sudo", False)
            timeout = kwargs.get("timeout", self.config.timeout)

            # For security, validate sudo commands and use safe string format
            if sudo:
                # Command validation to prevent injection
                command_parts = command.split()
                if not command_parts:
                    return self._create_result(
                        status=ExecutionStatus.FAILURE,
                        success=False,
                        error="Empty command for sudo execution",
                    )

                # Use shlex.quote for proper shell escaping (fixes command injection vulnerability)
                escaped_parts = [shlex.quote(part) for part in command_parts]
                actual_command = f"sudo {' '.join(escaped_parts)}"

                logger.debug(f"Secure sudo command: {actual_command[:50]}...")
            else:
                # Also escape non-sudo commands for consistency
                actual_command = shlex.quote(command)

            stdin, stdout, stderr = self.client.exec_command(
                actual_command, timeout=timeout
            )

            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode("utf-8").strip()
            error_output = stderr.read().decode("utf-8").strip()

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
                metadata={"command": command, "sudo": sudo, "timeout": timeout},
            )

        except socket.timeout:
            duration = time.time() - start_time
            return self._create_result(
                status=ExecutionStatus.TIMEOUT,
                success=False,
                duration=duration,
                error=f"Command timed out after {timeout} seconds",
                metadata={"command": command},
            )

        except Exception as e:
            duration = time.time() - start_time
            return self._create_result(
                status=ExecutionStatus.FAILURE,
                success=False,
                duration=duration,
                error=str(e),
                metadata={"command": command},
            )

    def test_connection(self) -> bool:
        """Test SSH connection by executing a simple command.

        Returns:
            True if connection test successful, False otherwise.
        """
        result = self.execute_command("echo 'connection test'")
        return result.success
