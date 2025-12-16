"""
Sandbox utilities for secure execution environment management.

Provides sandboxing capabilities for running untrusted code or operations
in isolated environments.
"""

from typing import Any, Dict, List, Optional, Callable
import os
import tempfile
import subprocess
from pathlib import Path
from contextlib import contextmanager


class SandboxEnvironment:
    """Manages sandboxed execution environments."""

    def __init__(
        self,
        working_dir: Optional[str] = None,
        max_memory: int = 128 * 1024 * 1024,  # 128MB
        max_cpu_time: int = 30,  # 30 seconds
        allow_network: bool = False,
    ):
        """Initialize sandbox environment.

        Args:
            working_dir: Working directory for sandbox operations
            max_memory: Maximum memory usage in bytes
            max_cpu_time: Maximum CPU time in seconds
            allow_network: Whether to allow network access
        """
        self.working_dir = working_dir or tempfile.mkdtemp(prefix="sandbox_")
        self.max_memory = max_memory
        self.max_cpu_time = max_cpu_time
        self.allow_network = allow_network
        self.environment_vars = {}

    def set_environment_variable(self, key: str, value: str):
        """Set environment variable in sandbox."""
        self.environment_vars[key] = value

    def execute_command(
        self, command: List[str], timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """Execute command in sandbox environment.

        Args:
            command: Command and arguments to execute
            timeout: Override default timeout

        Returns:
            Dictionary with execution results
        """
        timeout = timeout or self.max_cpu_time

        try:
            result = subprocess.run(
                command,
                cwd=self.working_dir,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={**os.environ, **self.environment_vars},
            )

            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "success": result.returncode == 0,
            }
        except subprocess.TimeoutExpired:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": "Command timed out",
                "success": False,
                "timeout": True,
            }
        except Exception as e:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
                "success": False,
                "error": True,
            }

    def execute_python_code(
        self, code: str, timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """Execute Python code in sandbox.

        Args:
            code: Python code to execute
            timeout: Override default timeout

        Returns:
            Dictionary with execution results
        """
        timeout = timeout or self.max_cpu_time

        # Write code to temporary file
        code_file = Path(self.working_dir) / "sandbox_code.py"
        with open(code_file, "w") as f:
            f.write(code)

        # Execute the code
        return self.execute_command(["python", str(code_file)], timeout=timeout)

    def cleanup(self):
        """Clean up sandbox environment."""
        try:
            import shutil

            if Path(self.working_dir).exists():
                shutil.rmtree(self.working_dir)
        except Exception:
            pass  # Ignore cleanup errors

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()


class SandboxedExecutor:
    """Executor that runs operations in sandbox environments."""

    def __init__(self, sandbox_config: Optional[Dict[str, Any]] = None):
        """Initialize sandboxed executor.

        Args:
            sandbox_config: Configuration for sandbox environments
        """
        self.config = sandbox_config or {}
        self.active_sandboxes: List[SandboxEnvironment] = []

    @contextmanager
    def create_sandbox(self, **kwargs):
        """Create a new sandbox environment.

        Args:
            **kwargs: Sandbox configuration parameters

        Yields:
            SandboxEnvironment instance
        """
        # Merge config with kwargs
        sandbox_config = {**self.config, **kwargs}

        sandbox = SandboxEnvironment(**sandbox_config)
        self.active_sandboxes.append(sandbox)

        try:
            yield sandbox
        finally:
            sandbox.cleanup()
            if sandbox in self.active_sandboxes:
                self.active_sandboxes.remove(sandbox)

    def execute_in_sandbox(
        self,
        operation: Callable,
        sandbox_config: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Any:
        """Execute operation in sandbox environment.

        Args:
            operation: Function to execute
            sandbox_config: Sandbox configuration
            **kwargs: Additional arguments for operation

        Returns:
            Result of the operation
        """
        with self.create_sandbox(**(sandbox_config or {})) as sandbox:
            # Pass sandbox to operation if it accepts it
            try:
                if (
                    hasattr(operation, "__code__")
                    and "sandbox" in operation.__code__.co_varnames
                ):
                    return operation(sandbox=sandbox, **kwargs)
                else:
                    return operation(**kwargs)
            except Exception as e:
                return {"success": False, "error": str(e), "sandbox": sandbox}


# Utility functions
def create_secure_sandbox(**kwargs) -> SandboxEnvironment:
    """Create a secure sandbox environment with safe defaults."""
    safe_defaults = {
        "max_memory": 64 * 1024 * 1024,  # 64MB
        "max_cpu_time": 10,  # 10 seconds
        "allow_network": False,
    }
    safe_defaults.update(kwargs)
    return SandboxEnvironment(**safe_defaults)


def execute_with_sandbox(operation: Callable, **kwargs) -> Any:
    """Execute operation with automatic sandbox creation."""
    executor = SandboxedExecutor()
    return executor.execute_in_sandbox(operation, **kwargs)


def is_path_allowed(path: str, allowed_paths: List[str] = None) -> bool:
    """Check if a path is allowed for sandbox operations.
    
    Args:
        path: Path to check
        allowed_paths: List of allowed paths (defaults to safe system paths)
        
    Returns:
        True if path is allowed, False otherwise
    """
    import os
    
    # Default safe paths
    if allowed_paths is None:
        allowed_paths = [
            "/tmp",
            "/var/tmp",
            os.path.expanduser("~"),
        ]
    
    try:
        # Normalize and resolve the path
        normalized_path = os.path.normpath(path)
        resolved_path = os.path.realpath(normalized_path)
        
        # Check if path is within any allowed directory
        for allowed_path in allowed_paths:
            allowed_resolved = os.path.realpath(allowed_path)
            if resolved_path.startswith(allowed_resolved + os.sep) or resolved_path == allowed_resolved:
                return True
        
        return False
    except (OSError, ValueError):
        return False
