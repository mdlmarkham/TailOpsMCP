"""Shared dependencies for MCP tools."""

import logging

logger = logging.getLogger(__name__)


class Dependencies:
    """Container for shared service dependencies."""

    def __init__(self):
        # Docker client (singleton)
        self._docker_client = None

        # Services (lazy initialization)
        self._log_analyzer = None
        self._package_manager = None
        self._app_scanner = None
        self._inventory = None
        self._executor_factory = None
        self._target_registry = None
        self._audit_logger = None
        self._policy_gate = None

        # System identity (loaded at startup)
        self.system_identity = None

    def get_docker_client(self):
        """Get or create Docker client singleton."""
        if self._docker_client is None:
            import docker

            self._docker_client = docker.from_env()
        return self._docker_client

    @property
    def log_analyzer(self):
        """Get LogAnalyzer instance."""
        if self._log_analyzer is None:
            from src.services.log_analyzer import LogAnalyzer

            self._log_analyzer = LogAnalyzer()
        return self._log_analyzer

    @property
    def package_manager(self):
        """Get PackageManager instance."""
        if self._package_manager is None:
            from src.services.package_manager import PackageManager

            self._package_manager = PackageManager()
        return self._package_manager

    @property
    def app_scanner(self):
        """Get ApplicationScanner instance."""
        if self._app_scanner is None:
            from src.services.app_scanner import ApplicationScanner

            self._app_scanner = ApplicationScanner()
        return self._app_scanner

    @property
    def executor_factory(self):
        """Get ExecutorFactory instance."""
        if self._executor_factory is None:
            from src.services.executor_factory import ExecutorFactory

            self._executor_factory = ExecutorFactory()
        return self._executor_factory

    @property
    def inventory(self):
        """Get Inventory instance."""
        if self._inventory is None:
            from src.inventory import Inventory

            self._inventory = Inventory()
        return self._inventory

    @property
    def target_registry(self):
        """Get TargetRegistry instance."""
        if self._target_registry is None:
            from src.services.target_registry import TargetRegistry

            self._target_registry = TargetRegistry()
        return self._target_registry

    @property
    def audit_logger(self):
        """Get AuditLogger instance."""
        if self._audit_logger is None:
            from src.utils.audit import AuditLogger

            self._audit_logger = AuditLogger()
        return self._audit_logger

    @property
    def policy_gate(self):
        """Get PolicyGate instance."""
        if self._policy_gate is None:
            from src.services.policy_gate import PolicyGate

            self._policy_gate = PolicyGate(self.target_registry, self.audit_logger)
        return self._policy_gate

    def initialize_system_identity(self):
        """Load or auto-detect system identity."""
        from src.inventory import SystemIdentity
        import socket
        import platform
        import re

        system_identity = self.inventory.get_system_identity()
        if not system_identity:
            # Auto-detect on first run
            hostname = socket.gethostname()

            # Try to detect if running in Proxmox LXC
            container_id = None
            container_type = None
            try:
                # Check for Proxmox container ID in /proc/self/cgroup
                with open("/proc/self/cgroup", "r") as f:
                    content = f.read()
                    if "lxc" in content:
                        container_type = "lxc"
                        # Try to extract VMID/CTID
                        match = re.search(r"/lxc/(\d+)/", content)
                        if match:
                            container_id = match.group(1)
            except (FileNotFoundError, PermissionError):
                # Running on bare metal or can't detect
                container_type = (
                    "bare-metal" if platform.system() != "Windows" else None
                )

            system_identity = SystemIdentity(
                hostname=hostname,
                container_id=container_id,
                container_type=container_type,
            )
            self.inventory.set_system_identity(system_identity)
            logger.info(
                f"Auto-detected system identity: {system_identity.get_display_name()}"
            )
        else:
            logger.info(f"Loaded system identity: {system_identity.get_display_name()}")

        self.system_identity = system_identity
        return system_identity


# Global instance
deps = Dependencies()
