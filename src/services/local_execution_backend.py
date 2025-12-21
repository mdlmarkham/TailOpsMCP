"""
Local Execution Backend

Implements local execution for operations on the gateway itself,
providing secure local operations without network overhead.
"""

import logging
import os
import subprocess
import json
import shutil
from typing import Dict, List, Any
from datetime import datetime
from datetime import timezone, timezone
from pathlib import Path

from src.models.policy_models import OperationType
from src.models.execution import ExecutionResult, ExecutionStatus, ExecutionSeverity
from src.services.execution_factory import RemoteExecutionBackend


logger = logging.getLogger(__name__)


class LocalExecutionBackend(RemoteExecutionBackend):
    """Local execution backend for gateway operations."""

    def __init__(self, target_config: Dict[str, Any]):
        """Initialize local execution backend.

        Args:
            target_config: Target configuration (local gateway)
        """
        super().__init__(target_config)

        # Local execution settings with secure temporary directory
        self.working_directory = self._get_secure_working_directory(
            target_config.get("working_directory")
        )
        self.sudo_enabled = target_config.get("sudo_enabled", True)
        self.user = target_config.get("user", os.getenv("USER", "root"))

        # Ensure working directory exists with proper permissions
        self._setup_working_directory()

        # Capability mappings
        self._setup_capability_mappings()

    def _get_secure_working_directory(self, config_dir: Optional[str]) -> str:
        """Get a secure working directory, preferring user-specific temp dirs."""
        import tempfile

        if config_dir:
            # If config provides a directory, validate it's secure
            path = Path(config_dir).resolve()
            if self._is_safe_working_directory(path):
                return str(path)
            else:
                logger.warning(
                    f"Configured working directory is not secure: {config_dir}"
                )

        # Default: use system temp directory with user-specific subdirectory
        base_temp = tempfile.gettempdir()
        secure_dir = Path(base_temp) / f"systemmanager_{os.getuid()}"
        return str(secure_dir)

    def _is_safe_working_directory(self, path: Path) -> bool:
        """Check if a directory is safe for working files."""
        try:
            # Must be within /tmp or /var/tmp
            temp_roots = [Path("/tmp"), Path("/var/tmp")]
            if not any(path.is_relative_to(root) for root in temp_roots):
                return False

            # Must not be world-writable by others
            stat = path.stat()
            if (stat.st_mode & 0o002) != 0:  # Others write permission
                return False

            return True
        except (OSError, ValueError):
            return False

    def _setup_working_directory(self):
        """Create working directory with secure permissions."""
        import stat

        path = Path(self.working_directory)
        path.mkdir(parents=True, exist_ok=True)

        # Set permissions: user rwx, group rx only (if exists), no others access
        try:
            current_uid = os.getuid()
            if os.path.exists(path):
                os.chown(path, current_uid, -1)  # Set owner to current user
                path.chmod(0o750)  # rwxr-x---
        except OSError as e:
            logger.warning(
                f"Could not set secure permissions on working directory: {e}"
            )

    def _setup_capability_mappings(self):
        """Setup capability to command mappings."""
        self.capability_handlers = {
            # Service operations
            OperationType.SERVICE_RESTART: self._handle_service_restart,
            OperationType.SERVICE_START: self._handle_service_start,
            OperationType.SERVICE_STOP: self._handle_service_stop,
            OperationType.SERVICE_STATUS: self._handle_service_status,
            # Container operations (Docker/Podman)
            OperationType.CONTAINER_CREATE: self._handle_container_create,
            OperationType.CONTAINER_DELETE: self._handle_container_delete,
            OperationType.CONTAINER_START: self._handle_container_start,
            OperationType.CONTAINER_STOP: self._handle_container_stop,
            OperationType.CONTAINER_RESTART: self._handle_container_restart,
            OperationType.CONTAINER_INSPECT: self._handle_container_inspect,
            # Stack operations (Docker Compose)
            OperationType.STACK_DEPLOY: self._handle_stack_deploy,
            OperationType.STACK_REMOVE: self._handle_stack_remove,
            OperationType.STACK_UPDATE: self._handle_stack_update,
            # File operations
            OperationType.FILE_READ: self._handle_file_read,
            OperationType.FILE_WRITE: self._handle_file_write,
            OperationType.FILE_DELETE: self._handle_file_delete,
            OperationType.FILE_COPY: self._handle_file_copy,
            # Network operations
            OperationType.NETWORK_SCAN: self._handle_network_scan,
            OperationType.NETWORK_TEST: self._handle_network_test,
            OperationType.NETWORK_STATUS: self._handle_network_status,
            # Package operations
            OperationType.PACKAGE_UPDATE: self._handle_package_update,
            OperationType.PACKAGE_INSTALL: self._handle_package_install,
            OperationType.PACKAGE_REMOVE: self._handle_package_remove,
            OperationType.PACKAGE_LIST: self._handle_package_list,
        }

    def get_supported_capabilities(self) -> List[OperationType]:
        """Get list of capabilities supported by local backend."""
        return list(self.capability_handlers.keys())

    async def connect(self) -> bool:
        """Local backend doesn't need connection establishment."""
        # Verify we can execute commands locally
        try:
            result = subprocess.run(
                ["whoami"], capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Local execution test failed: {e}")
            return False

    async def disconnect(self):
        """Local backend doesn't need explicit disconnection."""
        pass

    def is_connected(self) -> bool:
        """Local backend is always 'connected'."""
        return True

    async def test_connection(self) -> ExecutionResult:
        """Test local execution capabilities."""
        start_time = datetime.now()

        try:
            # Test basic command execution
            result = subprocess.run(
                ["echo", "local_connection_test"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if (
                result.returncode == 0
                and result.stdout.strip() == "local_connection_test"
            ):
                return ExecutionResult(
                    status=ExecutionStatus.SUCCESS,
                    success=True,
                    severity=ExecutionSeverity.INFO,
                    output="Local execution test successful",
                    duration=(datetime.now() - start_time).total_seconds(),
                    metadata={
                        "connection_method": "local",
                        "test_type": "connection",
                        "working_directory": self.working_directory,
                        "user": self.user,
                    },
                )
            else:
                return ExecutionResult(
                    status=ExecutionStatus.EXECUTION_ERROR,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error=f"Local execution test failed: {result.stderr}",
                    duration=(datetime.now() - start_time).total_seconds(),
                )

        except Exception as e:
            return ExecutionResult(
                status=ExecutionStatus.EXECUTION_ERROR,
                success=False,
                severity=ExecutionSeverity.ERROR,
                error=f"Local execution test failed: {str(e)}",
                duration=(datetime.now() - start_time).total_seconds(),
            )

    async def execute_capability(
        self,
        capability: OperationType,
        parameters: Dict[str, Any],
        target_info: Dict[str, Any],
    ) -> ExecutionResult:
        """Execute capability operation locally."""
        start_time = datetime.now()

        try:
            # Get capability handler
            if capability not in self.capability_handlers:
                return ExecutionResult(
                    status=ExecutionStatus.CONFIGURATION_ERROR,
                    success=False,
                    severity=ExecutionSeverity.ERROR,
                    error=f"Capability {capability} not supported by local backend",
                    duration=(datetime.now() - start_time).total_seconds(),
                )

            # Execute capability
            handler = self.capability_handlers[capability]
            result = await handler(parameters, target_info)

            return result

        except Exception as e:
            return ExecutionResult(
                status=ExecutionStatus.EXECUTION_ERROR,
                success=False,
                severity=ExecutionSeverity.ERROR,
                error=f"Local capability execution failed: {str(e)}",
                duration=(datetime.now() - start_time).total_seconds(),
            )

    # Service operation handlers

    async def _handle_service_restart(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> ExecutionResult:
        """Handle service restart operation."""
        service_name = parameters.get("service_name")
        if not service_name:
            return self._create_error_result("Service name is required")

        cmd = ["sudo", "systemctl", "restart", service_name]
        return await self._execute_command(cmd, parameters.get("timeout", 60))

    async def _handle_service_start(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> ExecutionResult:
        """Handle service start operation."""
        service_name = parameters.get("service_name")
        if not service_name:
            return self._create_error_result("Service name is required")

        cmd = ["sudo", "systemctl", "start", service_name]
        return await self._execute_command(cmd, parameters.get("timeout", 30))

    async def _handle_service_stop(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> ExecutionResult:
        """Handle service stop operation."""
        service_name = parameters.get("service_name")
        if not service_name:
            return self._create_error_result("Service name is required")

        cmd = ["sudo", "systemctl", "stop", service_name]
        return await self._execute_command(cmd, parameters.get("timeout", 30))

    async def _handle_service_status(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> ExecutionResult:
        """Handle service status operation."""
        service_name = parameters.get("service_name")
        if not service_name:
            return self._create_error_result("Service name is required")

        cmd = ["sudo", "systemctl", "status", service_name, "--no-pager"]
        return await self._execute_command(cmd, parameters.get("timeout", 10))

    # Container operation handlers

    async def _handle_container_create(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> ExecutionResult:
        """Handle container creation operation."""
        template = parameters.get("template")
        name = parameters.get("name")
        if not template or not name:
            return self._create_error_result("Template and name are required")

        # Check if Docker is available
        docker_check = await self._execute_command(["which", "docker"])
        if not docker_check.success:
            return self._create_error_result("Docker is not available")

        # Create container using Docker
        cmd = ["docker", "create", "--name", name, template]
        return await self._execute_command(cmd, parameters.get("timeout", 180))

    async def _handle_container_delete(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> ExecutionResult:
        """Handle container deletion operation."""
        container_name = parameters.get("container_name")
        force = parameters.get("force", False)
        if not container_name:
            return self._create_error_result("Container name is required")

        cmd = ["docker", "rm"]
        if force:
            cmd.append("-f")
        cmd.append(container_name)

        return await self._execute_command(cmd, parameters.get("timeout", 60))

    async def _handle_container_start(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> ExecutionResult:
        """Handle container start operation."""
        container_name = parameters.get("container_name")
        if not container_name:
            return self._create_error_result("Container name is required")

        cmd = ["docker", "start", container_name]
        return await self._execute_command(cmd, parameters.get("timeout", 60))

    async def _handle_container_stop(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> ExecutionResult:
        """Handle container stop operation."""
        container_name = parameters.get("container_name")
        if not container_name:
            return self._create_error_result("Container name is required")

        cmd = ["docker", "stop", container_name]
        return await self._execute_command(cmd, parameters.get("timeout", 60))

    async def _handle_container_restart(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> ExecutionResult:
        """Handle container restart operation."""
        container_name = parameters.get("container_name")
        if not container_name:
            return self._create_error_result("Container name is required")

        cmd = ["docker", "restart", container_name]
        return await self._execute_command(cmd, parameters.get("timeout", 90))

    async def _handle_container_inspect(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> ExecutionResult:
        """Handle container inspection operation."""
        container_name = parameters.get("container_name")
        if not container_name:
            return self._create_error_result("Container name is required")

        cmd = ["docker", "inspect", container_name]
        return await self._execute_command(cmd, parameters.get("timeout", 30))

    # Stack operation handlers

    async def _handle_stack_deploy(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> ExecutionResult:
        """Handle stack deployment operation."""
        stack_name = parameters.get("stack_name")
        config = parameters.get("config")
        if not stack_name:
            return self._create_error_result("Stack name is required")

        # Write config to temporary file with secure permissions
        import tempfile
        import stat

        with tempfile.NamedTemporaryFile(
            mode="w",
            prefix=f"{stack_name}_config_",
            suffix=".json",
            dir=self.working_directory,
            delete=False,
        ) as config_file:
            json.dump(config or {}, config_file)
            config_file_path = config_file.name

            # Set secure permissions (user read/write only)
            try:
                os.chmod(config_file_path, 0o600)
            except OSError as e:
                logger.warning(f"Could not set secure permissions on config file: {e}")

        cmd = ["docker", "stack", "deploy", "-c", config_file_path, stack_name]
        result = await self._execute_command(cmd, parameters.get("timeout", 300))

        # Cleanup config file securely
        try:
            os.remove(config_file_path)
        except Exception:
            pass

        return result

    async def _handle_stack_remove(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> ExecutionResult:
        """Handle stack removal operation."""
        stack_name = parameters.get("stack_name")
        if not stack_name:
            return self._create_error_result("Stack name is required")

        cmd = ["docker", "stack", "rm", stack_name]
        return await self._execute_command(cmd, parameters.get("timeout", 180))

    async def _handle_stack_update(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> ExecutionResult:
        """Handle stack update operation."""
        stack_name = parameters.get("stack_name")
        if not stack_name:
            return self._create_error_result("Stack name is required")

        cmd = ["docker", "stack", "deploy", "--update-delay", "10s", stack_name]
        return await self._execute_command(cmd, parameters.get("timeout", 240))

    # File operation handlers

    async def _handle_file_read(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> ExecutionResult:
        """Handle file read operation."""
        file_path = parameters.get("file_path")
        encoding = parameters.get("encoding", "utf-8")
        if not file_path:
            return self._create_error_result("File path is required")

        # Validate file path for security
        try:
            from pathlib import Path

            resolved_path = Path(file_path).resolve()

            # Check for path traversal attempts
            if ".." in str(resolved_path) and not str(resolved_path).startswith(
                self.working_directory
            ):
                return self._create_error_result(
                    "Access outside working directory not allowed"
                )

            # Only allow files within working directory or specific safe paths
            safe_paths = [
                Path(self.working_directory),
                Path("/var/log"),
                Path("/tmp"),
                Path("/var/tmp"),
            ]

            if not any(
                str(resolved_path).startswith(str(safe_path))
                for safe_path in safe_paths
            ):
                return self._create_error_result("File path not in allowed directories")

        except Exception as e:
            return self._create_error_result(f"Invalid file path: {str(e)}")

        try:
            with open(file_path, "r", encoding=encoding) as f:
                content = f.read()

            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                success=True,
                severity=ExecutionSeverity.INFO,
                output=content,
                duration=0.0,
                metadata={
                    "capability": OperationType.FILE_READ.value,
                    "file_path": file_path,
                    "encoding": encoding,
                    "file_size": len(content),
                },
            )
        except Exception as e:
            return self._create_error_result(f"Failed to read file: {str(e)}")

    async def _handle_file_write(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> ExecutionResult:
        """Handle file write operation."""
        file_path = parameters.get("file_path")
        content = parameters.get("content")
        if not file_path or content is None:
            return self._create_error_result("File path and content are required")

        try:
            # Ensure directory exists
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)

            with open(file_path, "w") as f:
                f.write(content)

            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                success=True,
                severity=ExecutionSeverity.INFO,
                output=f"Successfully wrote {len(content)} bytes to {file_path}",
                duration=0.0,
                metadata={
                    "capability": OperationType.FILE_WRITE.value,
                    "file_path": file_path,
                    "bytes_written": len(content),
                },
            )
        except Exception as e:
            return self._create_error_result(f"Failed to write file: {str(e)}")

    async def _handle_file_delete(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> ExecutionResult:
        """Handle file delete operation."""
        file_path = parameters.get("file_path")
        if not file_path:
            return self._create_error_result("File path is required")

        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                return ExecutionResult(
                    status=ExecutionStatus.SUCCESS,
                    success=True,
                    severity=ExecutionSeverity.INFO,
                    output=f"Successfully deleted {file_path}",
                    duration=0.0,
                )
            else:
                return ExecutionResult(
                    status=ExecutionStatus.SUCCESS,
                    success=True,
                    severity=ExecutionSeverity.WARNING,
                    output=f"File {file_path} does not exist",
                    duration=0.0,
                )
        except Exception as e:
            return self._create_error_result(f"Failed to delete file: {str(e)}")

    async def _handle_file_copy(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> ExecutionResult:
        """Handle file copy operation."""
        source_path = parameters.get("source_path")
        dest_path = parameters.get("dest_path")
        if not source_path or not dest_path:
            return self._create_error_result(
                "Source and destination paths are required"
            )

        try:
            shutil.copy2(source_path, dest_path)
            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                success=True,
                severity=ExecutionSeverity.INFO,
                output=f"Successfully copied {source_path} to {dest_path}",
                duration=0.0,
            )
        except Exception as e:
            return self._create_error_result(f"Failed to copy file: {str(e)}")

    # Network operation handlers

    async def _handle_network_scan(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> ExecutionResult:
        """Handle network scan operation."""
        target_host = parameters.get("host", "192.168.1.0/24")
        port = parameters.get("port")

        cmd = ["nmap"]
        if port:
            cmd.extend(["-p", str(port)])
        cmd.append(target_host)

        return await self._execute_command(cmd, parameters.get("timeout", 120))

    async def _handle_network_test(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> ExecutionResult:
        """Handle network test operation."""
        host = parameters.get("host")
        port = parameters.get("port")

        if port:
            cmd = ["nc", "-z", "-v", host, str(port)]
        else:
            cmd = ["ping", "-c", "4", host]

        return await self._execute_command(cmd, parameters.get("timeout", 30))

    async def _handle_network_status(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> ExecutionResult:
        """Handle network status operation."""
        cmd = ["ip", "addr", "show", "&&", "ip", "route", "show"]
        return await self._execute_command(cmd, parameters.get("timeout", 15))

    # Package operation handlers

    async def _handle_package_update(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> ExecutionResult:
        """Handle package update operation."""
        package_name = parameters.get("package_name")

        if package_name:
            cmd = [
                "sudo",
                "apt",
                "update",
                "&&",
                "sudo",
                "apt",
                "install",
                "--upgrade",
                package_name,
            ]
        else:
            cmd = ["sudo", "apt", "update", "&&", "apt", "list", "--upgradable"]

        return await self._execute_command(cmd, parameters.get("timeout", 300))

    async def _handle_package_install(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> ExecutionResult:
        """Handle package installation operation."""
        package_name = parameters.get("package_name")
        if not package_name:
            return self._create_error_result("Package name is required")

        cmd = ["sudo", "apt", "install", package_name]
        return await self._execute_command(cmd, parameters.get("timeout", 180))

    async def _handle_package_remove(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> ExecutionResult:
        """Handle package removal operation."""
        package_name = parameters.get("package_name")
        if not package_name:
            return self._create_error_result("Package name is required")

        cmd = ["sudo", "apt", "remove", package_name]
        return await self._execute_command(cmd, parameters.get("timeout", 120))

    async def _handle_package_list(
        self, parameters: Dict[str, Any], target_info: Dict[str, Any]
    ) -> ExecutionResult:
        """Handle package listing operation."""
        cmd = ["dpkg", "-l", "|", "grep", "^ii"]
        return await self._execute_command(cmd, parameters.get("timeout", 60))

    # Helper methods

    async def _execute_command(
        self, cmd: List[str], timeout: int = 300
    ) -> ExecutionResult:
        """Execute a command and return execution result."""
        start_time = datetime.now()

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=self.working_directory,
            )

            duration = (datetime.now() - start_time).total_seconds()

            return ExecutionResult(
                status=ExecutionStatus.SUCCESS
                if result.returncode == 0
                else ExecutionStatus.EXECUTION_ERROR,
                success=result.returncode == 0,
                severity=ExecutionSeverity.INFO
                if result.returncode == 0
                else ExecutionSeverity.ERROR,
                exit_code=result.returncode,
                output=result.stdout,
                error=result.stderr if result.stderr else None,
                duration=duration,
                metadata={
                    "command": " ".join(cmd),
                    "working_directory": self.working_directory,
                    "user": self.user,
                },
            )

        except subprocess.TimeoutExpired:
            duration = (datetime.now() - start_time).total_seconds()
            return ExecutionResult(
                status=ExecutionStatus.TIMEOUT,
                success=False,
                severity=ExecutionSeverity.ERROR,
                error=f"Command timed out after {timeout} seconds",
                duration=duration,
                metadata={"command": " ".join(cmd), "timeout": timeout},
            )
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            return ExecutionResult(
                status=ExecutionStatus.EXECUTION_ERROR,
                success=False,
                severity=ExecutionSeverity.ERROR,
                error=f"Command execution failed: {str(e)}",
                duration=duration,
                metadata={"command": " ".join(cmd), "error_type": type(e).__name__},
            )

    def _create_error_result(self, error_message: str) -> ExecutionResult:
        """Create an error execution result."""
        return ExecutionResult(
            status=ExecutionStatus.EXECUTION_ERROR,
            success=False,
            severity=ExecutionSeverity.ERROR,
            error=error_message,
            duration=0.0,
        )
