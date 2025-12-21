"""
Local executor implementation for local command execution.
"""

import logging
import subprocess
import time

from src.services.executor import (
    Executor,
    ExecutionResult,
    ExecutionStatus,
    ExecutorConfig,
)

logger = logging.getLogger(__name__)


class LocalExecutor(Executor):
    """Local executor for local command execution."""

    def __init__(self, config: ExecutorConfig):
        """Initialize local executor.

        Args:
            config: Executor configuration
        """
        super().__init__(config)

    def is_available(self) -> bool:
        """Check if local executor is available.

        Returns:
            Always True for local executor
        """
        return True

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
            cwd = kwargs.get("cwd")
            env = kwargs.get("env")

            # SECURITY: Never use shell=True with user input for security
            # For security, always use list form without shell
            if isinstance(command, str):
                import shlex
                try:
                    cmd_list = shlex.split(command)
                except ValueError:
                    # Fallback to simple split if shlex fails
                    cmd_list = command.split()
            else:
                cmd_list = command

            # Execute command without shell for security
            process = subprocess.run(
                cmd_list,
                cwd=cwd,
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                timeout=self.config.timeout,
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
                metadata={"command": command, "shell": shell, "cwd": cwd},
            )

        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return self._create_result(
                status=ExecutionStatus.TIMEOUT,
                success=False,
                duration=duration,
                error=f"Command timed out after {self.config.timeout} seconds",
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
