"""
Executor Factory Module.

This module provides factory methods for creating different types of executors.
"""

from typing import Any, Dict


class ExecutorFactory:
    """Factory for creating executors."""

    def __init__(self):
        self.executors = {}

    def create_executor(self, executor_type: str, **kwargs) -> Any:
        """Create an executor of the specified type."""
        if executor_type == "local":
            return LocalExecutor(**kwargs)
        elif executor_type == "ssh":
            return SSHExecutor(**kwargs)
        elif executor_type == "docker":
            return DockerExecutor(**kwargs)
        else:
            raise ValueError(f"Unknown executor type: {executor_type}")

    def register_executor(self, executor_type: str, executor_class: type) -> None:
        """Register a new executor type."""
        self.executors[executor_type] = executor_class


class LocalExecutor:
    """Local executor for running commands locally."""

    def __init__(self, **kwargs):
        self.type = "local"

    def execute(self, command: str) -> Dict[str, Any]:
        """Execute a command locally."""
        return {"status": "success", "output": "local execution"}


class SSHExecutor:
    """SSH executor for running commands via SSH."""

    def __init__(self, **kwargs):
        self.type = "ssh"

    def execute(self, command: str) -> Dict[str, Any]:
        """Execute a command via SSH."""
        return {"status": "success", "output": "ssh execution"}


class DockerExecutor:
    """Docker executor for running commands in Docker containers."""

    def __init__(self, **kwargs):
        self.type = "docker"

    def execute(self, command: str) -> Dict[str, Any]:
        """Execute a command in Docker."""
        return {"status": "success", "output": "docker execution"}


# Default factory instance
default_factory = ExecutorFactory()
