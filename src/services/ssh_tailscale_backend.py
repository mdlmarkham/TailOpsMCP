"""
SSH/Tailscale Execution Backend

Implements remote execution via SSH with optional Tailscale integration
for secure remote operations across different network environments.
"""

import asyncio
import logging
import shlex
from typing import Dict, List, Any
from datetime import datetime

from src.models.policy_models import OperationType
from src.models.execution import ExecutionResult, ExecutionStatus, ExecutionSeverity
from src.services.execution_factory import RemoteExecutionBackend


logger = logging.getLogger(__name__)


class SSHTailscaleBackend(RemoteExecutionBackend):
    """SSH/Tailscale execution backend for remote target operations."""

    def __init__(self, target_config: Dict[str, Any]):
        """Initialize SSH/Tailscale backend.

        Args:
            target_config: Target configuration with connection details
        """
        super().__init__(target_config)

        # Connection settings
        self.host = target_config.get("host", "localhost")
        self.port = target_config.get("port", 22)
        self.username = target_config.get("username", "root")
        self.key_path = target_config.get("key_path")
        self.password = target_config.get("password")
        self.timeout = target_config.get("timeout", 30)

        # Tailscale settings
        self.use_tailscale = target_config.get("use_tailscale", False)
        self.tailscale_hostname = target_config.get("tailscale_hostname")
        self.tailscale_namespace = target_config.get("tailscale_namespace", "default")

        # SSH client state
        self.client = None
        self.sftp_client = None
        self.connected = False

        # Capability mappings
        self._setup_capability_mappings()

    def _setup_capability_mappings(self):
        """Setup capability to command mappings."""
        self.capability_commands = {
            # Service operations
            OperationType.SERVICE_RESTART: self._command_service_restart,
            OperationType.SERVICE_START: self._command_service_start,
            OperationType.SERVICE_STOP: self._command_service_stop,
            OperationType.SERVICE_STATUS: self._command_service_status,
            # Container operations
            OperationType.CONTAINER_CREATE: self._command_container_create,
            OperationType.CONTAINER_DELETE: self._command_container_delete,
            OperationType.CONTAINER_START: self._command_container_start,
            OperationType.CONTAINER_STOP: self._command_container_stop,
            OperationType.CONTAINER_RESTART: self._command_container_restart,
            OperationType.CONTAINER_INSPECT: self._command_container_inspect,
            # Stack operations
            OperationType.STACK_DEPLOY: self._command_stack_deploy,
            OperationType.STACK_REMOVE: self._command_stack_remove,
            OperationType.STACK_UPDATE: self._command_stack_update,
            # Backup operations
            OperationType.BACKUP_CREATE: self._command_backup_create,
            OperationType.BACKUP_RESTORE: self._command_backup_restore,
            OperationType.BACKUP_LIST: self._command_backup_list,
            OperationType.BACKUP_DELETE: self._command_backup_delete,
            # Snapshot operations
            OperationType.SNAPSHOT_CREATE: self._command_snapshot_create,
            OperationType.SNAPSHOT_DELETE: self._command_snapshot_delete,
            OperationType.SNAPSHOT_RESTORE: self._command_snapshot_restore,
            OperationType.SNAPSHOT_LIST: self._command_snapshot_list,
            # File operations
            OperationType.FILE_READ: self._command_file_read,
            OperationType.FILE_WRITE: self._command_file_write,
            OperationType.FILE_DELETE: self._command_file_delete,
            OperationType.FILE_COPY: self._command_file_copy,
            # Network operations
            OperationType.NETWORK_SCAN: self._command_network_scan,
            OperationType.NETWORK_TEST: self._command_network_test,
            OperationType.NETWORK_STATUS: self._command_network_status,
            # Package operations
            OperationType.PACKAGE_UPDATE: self._command_package_update,
            OperationType.PACKAGE_INSTALL: self._command_package_install,
            OperationType.PACKAGE_REMOVE: self._command_package_remove,
            OperationType.PACKAGE_LIST: self._command_package_list,
        }

    def get_supported_capabilities(self) -> List[OperationType]:
        """Get list of capabilities supported by SSH/Tailscale backend."""
        return list(self.capability_commands.keys())

    async def connect(self) -> bool:
        """Establish SSH connection to target."""
        try:
            # Import paramiko lazily to avoid dependency issues
            import paramiko

            self.client = paramiko.SSHClient()

            # SECURITY: Load system host keys for secure SSH connections
            self.client.load_system_host_keys()

            # For development/testing environments, allow strict checking
            import os

            if os.getenv("SSH_STRICT_HOST_KEY_CHECKING", "true").lower() == "true":
                # Reject unknown hosts for production security
                self.client.set_missing_host_key_policy(paramiko.RejectPolicy())
            else:
                # Allow known hosts for development (with warning log)
                import logging

                logging.warning(
                    "SSH host key verification disabled - use only in development"
                )
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Resolve target host
            target_host = self._resolve_target_host()

            # Establish connection
            connection_kwargs = {
                "hostname": target_host,
                "port": self.port,
                "username": self.username,
                "timeout": self.timeout,
                "allow_agent": False,
                "look_for_keys": False,
            }

            # Add authentication
            if self.key_path:
                connection_kwargs["key_filename"] = self.key_path
            elif self.password:
                connection_kwargs["password"] = self.password
            else:
                # Try SSH agent and default key locations
                connection_kwargs["allow_agent"] = True
                connection_kwargs["look_for_keys"] = True

            # Connect
            self.client.connect(**connection_kwargs)

            # Test connection with a simple command
            stdin, stdout, stderr = self.client.exec_command("echo 'connection_test'")
            test_output = stdout.read().decode().strip()

            if test_output == "connection_test":
                self.connected = True
                logger.info(f"Successfully connected to {target_host} via SSH")
                return True
            else:
                logger.error("SSH connection test failed")
                return False

        except Exception as e:
            logger.error(f"SSH connection failed: {e}")
            self.connected = False
            return False

    def _resolve_target_host(self) -> str:
        """Resolve target host based on connection method."""
        if self.use_tailscale and self.tailscale_hostname:
            # Use Tailscale hostname
            return f"{self.tailscale_hostname}.{self.tailscale_namespace}.ts.net"
        elif self.use_tailscale:
            # Use Tailscale magic DNS
            return f"{self.host}.ts.net"
        else:
            # Use direct host
            return self.host

    async def disconnect(self):
        """Disconnect SSH client and cleanup resources."""
        try:
            if self.sftp_client:
                self.sftp_client.close()
                self.sftp_client = None

            if self.client:
                self.client.close()
                self.client = None

            self.connected = False
            logger.info("SSH connection closed")

        except Exception as e:
            logger.error(f"Error closing SSH connection: {e}")

    def is_connected(self) -> bool:
        """Check if backend is currently connected."""
        return (
            self.connected and self.client and self.client.get_transport().is_active()
        )

    async def test_connection(self) -> ExecutionResult:
        """Test connection to target without executing operations."""
        start_time = datetime.now()

        try:
            if not self.connected:
                connected = await self.connect()
                if not connected:
                    return ExecutionResult(
                        status=ExecutionStatus.CONNECTION_ERROR,
                        success=False,
                        severity=ExecutionSeverity.ERROR,
                        error="Failed to establish SSH connection",
                        duration=(datetime.now() - start_time).total_seconds(),
                    )

            # Test with a simple command
            stdin, stdout, stderr = self.client.exec_command("whoami && hostname")
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()

            if error:
                return ExecutionResult(
                    status=ExecutionStatus.EXECUTION_ERROR,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error=f"Connection test command failed: {error}",
                    duration=(datetime.now() - start_time).total_seconds(),
                )

            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                success=True,
                severity=ExecutionSeverity.INFO,
                output=output,
                duration=(datetime.now() - start_time).total_seconds(),
                metadata={
                    "connection_method": "ssh",
                    "target_host": self._resolve_target_host(),
                    "test_type": "connection",
                },
            )

        except Exception as e:
            return ExecutionResult(
                status=ExecutionStatus.EXECUTION_ERROR,
                success=False,
                severity=ExecutionSeverity.ERROR,
                error=f"Connection test failed: {str(e)}",
                duration=(datetime.now() - start_time).total_seconds(),
            )

    async def execute_capability(
        self,
        capability: OperationType,
        parameters: Dict[str, Any],
        target_info: Dict[str, Any],
    ) -> ExecutionResult:
        """Execute a capability operation via SSH."""
        start_time = datetime.now()

        try:
            # Ensure connection
            if not self.connected:
                connected = await self.connect()
                if not connected:
                    return ExecutionResult(
                        status=ExecutionStatus.CONNECTION_ERROR,
                        success=False,
                        severity=ExecutionSeverity.ERROR,
                        error="Failed to establish connection",
                        duration=(datetime.now() - start_time).total_seconds(),
                    )

            # Get capability command
            if capability not in self.capability_commands:
                return ExecutionResult(
                    status=ExecutionStatus.CONFIGURATION_ERROR,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error=f"Capability {capability} not supported by SSH backend",
                    duration=(datetime.now() - start_time).total_seconds(),
                )

            # Generate command
            command_generator = self.capability_commands[capability]
            command = await command_generator(parameters, target_info)

            if not command:
                return ExecutionResult(
                    status=ExecutionStatus.VALIDATION_ERROR,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error="Failed to generate command for capability",
                    duration=(datetime.now() - start_time).total_seconds(),
                )

            # Execute command
            stdin, stdout, stderr = self.client.exec_command(
                command, timeout=parameters.get("timeout", 300)
            )

            # Read output
            output = stdout.read().decode("utf-8", errors="replace")
            error = stderr.read().decode("utf-8", errors="replace")
            exit_status = stdout.channel.recv_exit_status()

            duration = (datetime.now() - start_time).total_seconds()

            # Determine success
            success = exit_status == 0

            # Create result
            result = ExecutionResult(
                status=ExecutionStatus.SUCCESS
                if success
                else ExecutionStatus.EXECUTION_ERROR,
                success=success,
                severity=ExecutionSeverity.INFO if success else ExecutionSeverity.ERROR,
                exit_code=exit_status,
                output=output,
                error=error if not success else None,
                duration=duration,
                metadata={
                    "capability": capability.value,
                    "command": command,
                    "target_host": self._resolve_target_host(),
                    "execution_method": "ssh",
                },
            )

            return result

        except asyncio.TimeoutError:
            return ExecutionResult(
                status=ExecutionStatus.TIMEOUT,
                success=False,
                severity=ExecutionSeverity.ERROR,
                error=f"Command execution timed out after {parameters.get('timeout', 300)} seconds",
                duration=(datetime.now() - start_time).total_seconds(),
            )
        except Exception as e:
            return ExecutionResult(
                status=ExecutionStatus.EXECUTION_ERROR,
                success=False,
                severity=ExecutionSeverity.ERROR,
                error=f"Command execution failed: {str(e)}",
                duration=(datetime.now() - start_time).total_seconds(),
            )

    # Command generators for different capabilities

    async def _command_service_restart(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for service restart."""
        service_name = parameters.get("service_name")
        if not service_name:
            return None

        # Detect service manager and use appropriate command
        return f"sudo systemctl restart {shlex.quote(service_name)}"

    async def _command_service_start(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for service start."""
        service_name = parameters.get("service_name")
        if not service_name:
            return None

        return f"sudo systemctl start {shlex.quote(service_name)}"

    async def _command_service_stop(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for service stop."""
        service_name = parameters.get("service_name")
        if not service_name:
            return None

        return f"sudo systemctl stop {shlex.quote(service_name)}"

    async def _command_service_status(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for service status."""
        service_name = parameters.get("service_name")
        if not service_name:
            return None

        return f"sudo systemctl status {shlex.quote(service_name)} --no-pager"

    async def _command_container_create(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for container creation."""
        template = parameters.get("template")
        name = parameters.get("name")
        if not template or not name:
            return None

        return f"sudo pct create {shlex.quote(name)} {shlex.quote(template)}"

    async def _command_container_delete(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for container deletion."""
        container_name = parameters.get("container_name")
        force = parameters.get("force", False)
        if not container_name:
            return None

        if force:
            return f"sudo pct destroy {shlex.quote(container_name)} --purge"
        else:
            return f"sudo pct destroy {shlex.quote(container_name)}"

    async def _command_container_start(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for container start."""
        container_name = parameters.get("container_name")
        if not container_name:
            return None

        return f"sudo pct start {shlex.quote(container_name)}"

    async def _command_container_stop(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for container stop."""
        container_name = parameters.get("container_name")
        if not container_name:
            return None

        return f"sudo pct stop {shlex.quote(container_name)}"

    async def _command_container_restart(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for container restart."""
        container_name = parameters.get("container_name")
        if not container_name:
            return None

        return f"sudo pct reboot {shlex.quote(container_name)}"

    async def _command_container_inspect(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for container inspection."""
        container_name = parameters.get("container_name")
        if not container_name:
            return None

        return f"sudo pct config {shlex.quote(container_name)}"

    async def _command_stack_deploy(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for stack deployment."""
        stack_name = parameters.get("stack_name")
        parameters.get("config", {})
        if not stack_name:
            return None

        # This would be customized based on stack type (Docker Compose, etc.)
        return f"sudo docker stack deploy -c - {shlex.quote(stack_name)}"

    async def _command_stack_remove(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for stack removal."""
        stack_name = parameters.get("stack_name")
        if not stack_name:
            return None

        return f"sudo docker stack rm {shlex.quote(stack_name)}"

    async def _command_stack_update(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for stack update."""
        stack_name = parameters.get("stack_name")
        if not stack_name:
            return None

        return f"sudo docker stack deploy --update-delay 10s {shlex.quote(stack_name)}"

    async def _command_backup_create(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for backup creation."""
        backup_id = parameters.get("backup_id")
        target_path = parameters.get("target_path")
        backup_type = parameters.get("backup_type", "full")

        if not backup_id or not target_path:
            return None

        return f"sudo vzdump {shlex.quote(target_path)} --mode {backup_type} --storage local --compress gzip"

    async def _command_backup_restore(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for backup restoration."""
        backup_id = parameters.get("backup_id")
        if not backup_id:
            return None

        return f"sudo qmrestore /var/lib/vz/dump/{shlex.quote(backup_id)}.vma.lzo"

    async def _command_backup_list(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for backup listing."""
        return "sudo vzdump --list"

    async def _command_backup_delete(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for backup deletion."""
        backup_id = parameters.get("backup_id")
        if not backup_id:
            return None

        return f"sudo rm -f /var/lib/vz/dump/{shlex.quote(backup_id)}*"

    async def _command_snapshot_create(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for snapshot creation."""
        container_id = parameters.get("container_id")
        snapshot_name = parameters.get("snapshot_name")
        if not container_id or not snapshot_name:
            return None

        return f"sudo pct snapshot {shlex.quote(container_id)} {shlex.quote(snapshot_name)}"

    async def _command_snapshot_delete(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for snapshot deletion."""
        container_id = parameters.get("container_id")
        snapshot_name = parameters.get("snapshot_name")
        if not container_id or not snapshot_name:
            return None

        return f"sudo pct delsnapshot {shlex.quote(container_id)} {shlex.quote(snapshot_name)}"

    async def _command_snapshot_restore(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for snapshot restoration."""
        container_id = parameters.get("container_id")
        snapshot_name = parameters.get("snapshot_name")
        if not container_id or not snapshot_name:
            return None

        return f"sudo pct rollback {shlex.quote(container_id)} {shlex.quote(snapshot_name)}"

    async def _command_snapshot_list(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for snapshot listing."""
        container_id = parameters.get("container_id")
        if not container_id:
            return None

        return f"sudo pct listsnapshots {shlex.quote(container_id)}"

    async def _command_file_read(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for file reading."""
        file_path = parameters.get("file_path")
        parameters.get("encoding", "utf-8")
        if not file_path:
            return None

        return f"sudo cat {shlex.quote(file_path)}"

    async def _command_file_write(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for file writing."""
        file_path = parameters.get("file_path")
        content = parameters.get("content")
        if not file_path or content is None:
            return None

        # Use a temporary file approach to avoid issues with special characters
        return f"sudo tee {shlex.quote(file_path)} > /dev/null"

    async def _command_file_delete(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for file deletion."""
        file_path = parameters.get("file_path")
        if not file_path:
            return None

        return f"sudo rm -f {shlex.quote(file_path)}"

    async def _command_file_copy(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for file copying."""
        source_path = parameters.get("source_path")
        dest_path = parameters.get("dest_path")
        if not source_path or not dest_path:
            return None

        return f"sudo cp {shlex.quote(source_path)} {shlex.quote(dest_path)}"

    async def _command_network_scan(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for network scanning."""
        target_host = parameters.get("host", "192.168.1.0/24")
        port = parameters.get("port")

        if port:
            return f"nmap -p {port} {shlex.quote(target_host)}"
        else:
            return f"nmap {shlex.quote(target_host)}"

    async def _command_network_test(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for network testing."""
        host = parameters.get("host")
        port = parameters.get("port")

        if port:
            return f"nc -z -v {shlex.quote(host)} {port}"
        else:
            return f"ping -c 4 {shlex.quote(host)}"

    async def _command_network_status(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for network status."""
        return "ip addr show && ip route show"

    async def _command_package_update(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for package updates."""
        package_name = parameters.get("package_name")
        if package_name:
            return f"sudo apt update && sudo apt install --upgrade {shlex.quote(package_name)}"
        else:
            return "sudo apt update && sudo apt list --upgradable"

    async def _command_package_install(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for package installation."""
        package_name = parameters.get("package_name")
        if not package_name:
            return None

        return f"sudo apt install {shlex.quote(package_name)}"

    async def _command_package_remove(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for package removal."""
        package_name = parameters.get("package_name")
        if not package_name:
            return None

        return f"sudo apt remove {shlex.quote(package_name)}"

    async def _command_package_list(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> str:
        """Generate command for package listing."""
        return "dpkg -l | grep ^ii"
