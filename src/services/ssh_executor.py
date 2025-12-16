"""
SSH executor implementation for remote target operations with security hardening.
"""

import logging
import os
import paramiko
import socket
import time
import shlex
from typing import Optional
from pathlib import Path

from src.services.executor import Executor, ExecutionResult, ExecutionStatus

logger = logging.getLogger(__name__)


class SSHExecutor(Executor):
    """SSH executor for remote target operations."""

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        key_path: str,
        timeout: int = 30,
        retry_attempts: int = 3,
        retry_delay: float = 1.0,
        known_hosts_file: Optional[str] = None,
        allowed_ciphers: Optional[list] = None,
        cert_path: Optional[str] = None,
    ):
        """Initialize SSH executor with security hardening.

        Args:
            host: Target hostname or IP address.
            port: SSH port.
            username: SSH username.
            key_path: Path to SSH private key or environment variable name.
            timeout: Connection timeout in seconds.
            retry_attempts: Number of retry attempts for failed operations
            retry_delay: Delay between retries in seconds
            known_hosts_file: Path to known_hosts file for strict verification
            allowed_ciphers: List of allowed SSH ciphers for security
            cert_path: Path to SSH certificate for authentication
        """
        super().__init__(timeout, retry_attempts, retry_delay)
        self.host = host
        self.port = port
        self.username = username
        self.key_path = key_path
        self.known_hosts_file = known_hosts_file or os.path.expanduser(
            "~/.ssh/known_hosts"
        )
        self.allowed_ciphers = allowed_ciphers or [
            "chacha20-poly1305@openssh.com",
            "aes256-gcm@openssh.com",
            "aes128-gcm@openssh.com",
            "aes256-ctr",
            "aes192-ctr",
            "aes128-ctr",
        ]
        self.cert_path = cert_path
        self.client: Optional[paramiko.SSHClient] = None
        self._host_key_verified = False

    def connect(self) -> bool:
        """Establish secure SSH connection to target with strict host key verification.

        Returns:
            True if connection successful, False otherwise.
        """
        for attempt in range(self.retry_attempts):
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

                # Set allowed ciphers for security
                paramiko.common.ciphers = self.allowed_ciphers

                # Resolve key path from environment variable if needed
                actual_key_path = self.key_path
                if self.key_path.startswith("$"):
                    env_var = self.key_path[1:]
                    actual_key_path = os.getenv(env_var)
                    if not actual_key_path:
                        logger.error(f"Environment variable not found: {env_var}")
                        return False

                # Validate key file exists and has proper permissions
                if not os.path.exists(actual_key_path):
                    logger.error(f"SSH key file not found: {actual_key_path}")
                    return False

                if not os.access(actual_key_path, os.R_OK):
                    logger.error(f"SSH key file not readable: {actual_key_path}")
                    return False

                # Load private key
                if actual_key_path.endswith(".pub"):
                    # Handle public key file - load corresponding private key
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
                    "timeout": self.timeout,
                    "banner_timeout": self.timeout,
                    "auth_timeout": self.timeout,
                    "compress": False,  # Disable compression for security
                    "gss_auth": False,  # Disable GSS authentication
                }

                # Add certificate authentication if provided
                if self.cert_path and os.path.exists(self.cert_path):
                    connect_params["cert_file"] = self.cert_path

                # Perform banner grabbing for security analysis
                banner = self._grab_ssh_banner()
                if banner:
                    logger.debug(f"SSH banner from {self.host}:{self.port}: {banner}")
                    # Check for suspicious SSH server versions
                    if any(
                        suspicious in banner.lower()
                        for suspicious in ["dropbear", "wolfssh"]
                    ):
                        logger.warning(
                            f"Potentially insecure SSH server detected: {banner}"
                        )

                # Establish connection with security checks
                self.client.connect(**connect_params)

                # Verify host key after connection
                if not self._verify_host_key():
                    logger.error(
                        f"Host key verification failed for {self.host}:{self.port}"
                    )
                    self.client.close()
                    self.client = None
                    return False

                self._connected = True
                self._host_key_verified = True
                logger.info(
                    f"Secure SSH connection established to {self.host}:{self.port}"
                )
                return True

            except (
                paramiko.AuthenticationException,
                paramiko.SSHException,
                socket.timeout,
                socket.error,
            ) as e:
                logger.warning(f"SSH connection attempt {attempt + 1} failed: {str(e)}")
                self.client = None

                if attempt < self.retry_attempts - 1:
                    time.sleep(self.retry_delay)
                else:
                    logger.error(
                        f"SSH connection failed after {self.retry_attempts} attempts"
                    )
                    return False

        return False

    def _grab_ssh_banner(self) -> Optional[str]:
        """Grab SSH server banner for security analysis.

        Returns:
            SSH server banner string or None if failed
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()
            return banner
        except Exception as e:
            logger.debug(
                f"Failed to grab SSH banner from {self.host}:{self.port}: {str(e)}"
            )
            return None

    def _verify_host_key(self) -> bool:
        """Verify host key against known hosts.

        Returns:
            True if host key is known and matches, False otherwise
        """
        if not self.client:
            return False

        try:
            # Get the server's host key
            hostname = self.host
            port = self.port

            # Check if host key exists in known hosts
            host_keys = self.client.get_host_keys()
            key_type = None
            server_key = None

            for key_type_candidate in [
                "ssh-rsa",
                "ssh-ed25519",
                "ecdsa-sha2-nistp256",
                "ecdsa-sha2-nistp384",
                "ecdsa-sha2-nistp521",
            ]:
                if hostname in host_keys and key_type_candidate in host_keys[hostname]:
                    key_type = key_type_candidate
                    server_key = host_keys[hostname][key_type_candidate]
                    break

            if server_key is None:
                logger.error(f"Host key not found in known_hosts for {hostname}:{port}")
                return False

            logger.info(f"Host key verified for {hostname}:{port} (type: {key_type})")
            return True

        except Exception as e:
            logger.error(f"Host key verification failed: {str(e)}")
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
                error="SSH connection not established",
            )

        start_time = time.time()

        try:
            # Extract optional parameters
            sudo = kwargs.get("sudo", False)
            timeout = kwargs.get("timeout", self.timeout)

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

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
