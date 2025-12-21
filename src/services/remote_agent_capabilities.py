"""
Remote Agent Capabilities Integration

Integrates remote agent functionality with the existing policy system and capability registry.
Provides comprehensive agent-like operations via SSH/Tailscale without requiring agent installation.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from datetime import timezone, timezone

from src.models.policy_models import OperationType
from src.services.remote_operation_executor import ResilientRemoteOperation
from src.tools.remote_agent_tools import remote_agent_tools
from src.models.target_registry import TargetConnection
from src.connectors.remote_agent_connector import OperationResult
from src.utils.audit import AuditLogger


logger = logging.getLogger(__name__)


class RemoteAgentCapabilities:
    """Agent-like capabilities for policy system integration."""

    def __init__(self):
        """Initialize remote agent capabilities."""
        self.audit_logger = AuditLogger()
        self.executor = ResilientRemoteOperation()
        self._initialized = False

    async def initialize(self):
        """Initialize the remote agent capabilities."""
        if not self._initialized:
            await remote_agent_tools.initialize()
            self._initialized = True

    @staticmethod
    async def get_journald_logs(
        target: TargetConnection, params: dict
    ) -> OperationResult:
        """Get journald logs from target.

        Args:
            target: Target connection configuration
            params: Operation parameters

        Returns:
            Operation result
        """
        try:
            # Get parameters
            service = params.get("service")
            lines = params.get("lines", 100)
            since = params.get("since")
            until = params.get("until")
            priority = params.get("priority")
            grep = params.get("grep")

            # Create target identifier
            target_id = f"{target.host}:{target.port or 22}"

            # Execute operation
            await remote_agent_tools.initialize()
            result = await remote_agent_tools.get_journald_logs(
                target=target_id,
                service=service,
                lines=lines,
                since=since,
                until=until,
                priority=priority,
                grep=grep,
            )

            if result["success"]:
                return OperationResult(
                    operation="get_journald_logs",
                    target=target.host,
                    success=True,
                    result=result,
                    timestamp=datetime.now(timezone.utc),
                )
            else:
                return OperationResult(
                    operation="get_journald_logs",
                    target=target.host,
                    success=False,
                    error=result["error"],
                    timestamp=datetime.now(timezone.utc),
                )

        except Exception as e:
            logger.error(f"Failed to get journald logs: {str(e)}")
            return OperationResult(
                operation="get_journald_logs",
                target=target.host if target else "unknown",
                success=False,
                error=str(e),
                timestamp=datetime.now(timezone.utc),
            )

    @staticmethod
    async def manage_service(target: TargetConnection, params: dict) -> OperationResult:
        """Manage systemd service on target.

        Args:
            target: Target connection configuration
            params: Operation parameters

        Returns:
            Operation result
        """
        try:
            # Get parameters
            service = params.get("service")
            action = params.get("action", "restart")  # restart, start, stop, status
            timeout = params.get("timeout", 60)

            # Create target identifier
            target_id = f"{target.host}:{target.port or 22}"

            # Execute operation based on action
            await remote_agent_tools.initialize()

            if action == "restart":
                result = await remote_agent_tools.restart_remote_service(
                    target=target_id, service=service, timeout=timeout
                )
            elif action == "status":
                result = await remote_agent_tools.get_service_status(
                    target=target_id, service=service
                )
            elif action == "start":
                # Note: start_service method needs to be added to remote_agent_tools
                result = {"success": False, "error": "Start service not implemented"}
            elif action == "stop":
                # Note: stop_service method needs to be added to remote_agent_tools
                result = {"success": False, "error": "Stop service not implemented"}
            else:
                result = {"success": False, "error": f"Unknown action: {action}"}

            if result["success"]:
                return OperationResult(
                    operation=f"service_{action}",
                    target=target.host,
                    success=True,
                    result=result,
                    timestamp=datetime.now(timezone.utc),
                )
            else:
                return OperationResult(
                    operation=f"service_{action}",
                    target=target.host,
                    success=False,
                    error=result["error"],
                    timestamp=datetime.now(timezone.utc),
                )

        except Exception as e:
            logger.error(f"Failed to manage service: {str(e)}")
            return OperationResult(
                operation=f"service_{action if 'action' in locals() else 'unknown'}",
                target=target.host if target else "unknown",
                success=False,
                error=str(e),
                timestamp=datetime.now(timezone.utc),
            )

    @staticmethod
    async def docker_operations(
        target: TargetConnection, params: dict
    ) -> OperationResult:
        """Perform Docker operations on target.

        Args:
            target: Target connection configuration
            params: Operation parameters

        Returns:
            Operation result
        """
        try:
            # Get parameters
            operation = params.get("operation")  # list, logs, restart, start, stop
            container_id = params.get("container_id")
            lines = params.get("lines", 100)
            since = params.get("since")
            timeout = params.get("timeout", 30)

            # Create target identifier
            target_id = f"{target.host}:{target.port or 22}"

            # Execute operation
            await remote_agent_tools.initialize()

            if operation == "list":
                result = await remote_agent_tools.get_remote_docker_containers(
                    target=target_id, all_containers=False
                )
            elif operation == "logs":
                result = await remote_agent_tools.get_container_logs_remote(
                    target=target_id,
                    container_id=container_id,
                    lines=lines,
                    since=since,
                )
            elif operation == "restart":
                result = await remote_agent_tools.restart_remote_container(
                    target=target_id, container_id=container_id, timeout=timeout
                )
            elif operation == "start":
                # Note: start_container method needs to be added to remote_agent_tools
                result = {"success": False, "error": "Start container not implemented"}
            elif operation == "stop":
                # Note: stop_container method needs to be added to remote_agent_tools
                result = {"success": False, "error": "Stop container not implemented"}
            else:
                result = {
                    "success": False,
                    "error": f"Unknown Docker operation: {operation}",
                }

            if result["success"]:
                return OperationResult(
                    operation=f"docker_{operation}",
                    target=target.host,
                    success=True,
                    result=result,
                    timestamp=datetime.now(timezone.utc),
                )
            else:
                return OperationResult(
                    operation=f"docker_{operation}",
                    target=target.host,
                    success=False,
                    error=result["error"],
                    timestamp=datetime.now(timezone.utc),
                )

        except Exception as e:
            logger.error(f"Failed to perform Docker operation: {str(e)}")
            return OperationResult(
                operation=f"docker_{operation if 'operation' in locals() else 'unknown'}",
                target=target.host if target else "unknown",
                success=False,
                error=str(e),
                timestamp=datetime.now(timezone.utc),
            )

    @staticmethod
    async def file_operations(
        target: TargetConnection, params: dict
    ) -> OperationResult:
        """Perform file operations on target.

        Args:
            target: Target connection configuration
            params: Operation parameters

        Returns:
            Operation result
        """
        try:
            # Get parameters
            operation = params.get("operation")  # read, write, list, stat
            path = params.get("path")
            content = params.get("content")
            create_backup = params.get("create_backup", True)
            include_hidden = params.get("include_hidden", False)

            # Create target identifier
            target_id = f"{target.host}:{target.port or 22}"

            # Execute operation
            await remote_agent_tools.initialize()

            if operation == "read":
                result = await remote_agent_tools.read_remote_file(
                    target=target_id, path=path
                )
            elif operation == "write":
                result = await remote_agent_tools.write_remote_file(
                    target=target_id,
                    path=path,
                    content=content,
                    create_backup=create_backup,
                )
            elif operation == "list":
                result = await remote_agent_tools.list_remote_directory(
                    target=target_id, path=path, include_hidden=include_hidden
                )
            else:
                result = {
                    "success": False,
                    "error": f"Unknown file operation: {operation}",
                }

            if result["success"]:
                return OperationResult(
                    operation=f"file_{operation}",
                    target=target.host,
                    success=True,
                    result=result,
                    timestamp=datetime.now(timezone.utc),
                )
            else:
                return OperationResult(
                    operation=f"file_{operation}",
                    target=target.host,
                    success=False,
                    error=result["error"],
                    timestamp=datetime.now(timezone.utc),
                )

        except Exception as e:
            logger.error(f"Failed to perform file operation: {str(e)}")
            return OperationResult(
                operation=f"file_{operation if 'operation' in locals() else 'unknown'}",
                target=target.host if target else "unknown",
                success=False,
                error=str(e),
                timestamp=datetime.now(timezone.utc),
            )

    @staticmethod
    async def system_status(target: TargetConnection, params: dict) -> OperationResult:
        """Get system status from target.

        Args:
            target: Target connection configuration
            params: Operation parameters

        Returns:
            Operation result
        """
        try:
            # Create target identifier
            target_id = f"{target.host}:{target.port or 22}"

            # Execute operation
            await remote_agent_tools.initialize()
            result = await remote_agent_tools.get_remote_system_status(target=target_id)

            if result["success"]:
                return OperationResult(
                    operation="system_status",
                    target=target.host,
                    success=True,
                    result=result,
                    timestamp=datetime.now(timezone.utc),
                )
            else:
                return OperationResult(
                    operation="system_status",
                    target=target.host,
                    success=False,
                    error=result["error"],
                    timestamp=datetime.now(timezone.utc),
                )

        except Exception as e:
            logger.error(f"Failed to get system status: {str(e)}")
            return OperationResult(
                operation="system_status",
                target=target.host if target else "unknown",
                success=False,
                error=str(e),
                timestamp=datetime.now(timezone.utc),
            )

    @staticmethod
    async def fleet_operations(
        targets: List[TargetConnection], params: dict
    ) -> OperationResult:
        """Perform fleet-wide operations.

        Args:
            targets: List of target connection configurations
            params: Operation parameters

        Returns:
            Operation result
        """
        try:
            # Get parameters
            operation = params.get("operation")  # analyze_logs, check_health
            service = params.get("service")
            time_range = params.get("time_range", "1 hour")

            # Create target identifiers
            target_ids = [f"{target.host}:{target.port or 22}" for target in targets]

            # Execute operation
            await remote_agent_tools.initialize()

            if operation == "analyze_logs":
                result = await remote_agent_tools.analyze_service_logs_across_fleet(
                    targets=target_ids, service=service, time_range=time_range
                )
            elif operation == "check_health":
                result = await remote_agent_tools.check_fleet_service_health(
                    targets=target_ids, service=service
                )
            else:
                result = {
                    "success": False,
                    "error": f"Unknown fleet operation: {operation}",
                }

            if result["success"]:
                return OperationResult(
                    operation=f"fleet_{operation}",
                    target="multiple",
                    success=True,
                    result=result,
                    timestamp=datetime.now(timezone.utc),
                )
            else:
                return OperationResult(
                    operation=f"fleet_{operation}",
                    target="multiple",
                    success=False,
                    error=result["error"],
                    timestamp=datetime.now(timezone.utc),
                )

        except Exception as e:
            logger.error(f"Failed to perform fleet operation: {str(e)}")
            return OperationResult(
                operation=f"fleet_{operation if 'operation' in locals() else 'unknown'}",
                target="multiple",
                success=False,
                error=str(e),
                timestamp=datetime.now(timezone.utc),
            )


class RemoteAgentCapabilityRegistry:
    """Registry for remote agent capabilities."""

    def __init__(self):
        """Initialize capability registry."""
        self.capabilities = {}
        self._setup_capabilities()

    def _setup_capabilities(self):
        """Setup remote agent capabilities."""

        # Journald log capabilities
        self.capabilities.update(
            {
                "get_journald_logs": {
                    "operation_type": OperationType.FILE_READ,  # Reusing existing type
                    "description": "Get journald logs from remote target",
                    "parameters": {
                        "service": {"type": "string", "required": False},
                        "lines": {"type": "int", "required": False, "default": 100},
                        "since": {"type": "string", "required": False},
                        "until": {"type": "string", "required": False},
                        "priority": {"type": "string", "required": False},
                        "grep": {"type": "string", "required": False},
                    },
                    "executor": RemoteAgentCapabilities.get_journald_logs,
                    "tier": "observe",
                },
                "follow_journald_logs": {
                    "operation_type": OperationType.FILE_READ,
                    "description": "Follow journald logs in real-time",
                    "parameters": {
                        "service": {"type": "string", "required": True},
                        "timeout": {"type": "int", "required": False, "default": 30},
                    },
                    "executor": RemoteAgentCapabilities.get_journald_logs,
                    "tier": "observe",
                },
            }
        )

        # Service management capabilities
        self.capabilities.update(
            {
                "service_restart": {
                    "operation_type": OperationType.SERVICE_RESTART,
                    "description": "Restart systemd service on remote target",
                    "parameters": {
                        "service": {"type": "string", "required": True},
                        "timeout": {"type": "int", "required": False, "default": 60},
                    },
                    "executor": RemoteAgentCapabilities.manage_service,
                    "tier": "control",
                },
                "service_status": {
                    "operation_type": OperationType.SERVICE_STATUS,
                    "description": "Get service status from remote target",
                    "parameters": {"service": {"type": "string", "required": True}},
                    "executor": RemoteAgentCapabilities.manage_service,
                    "tier": "observe",
                },
                "service_list": {
                    "operation_type": OperationType.SERVICE_STATUS,
                    "description": "List services on remote target",
                    "parameters": {
                        "filter_state": {"type": "string", "required": False}
                    },
                    "executor": RemoteAgentCapabilities.manage_service,
                    "tier": "observe",
                },
            }
        )

        # Docker capabilities
        self.capabilities.update(
            {
                "docker_container_list": {
                    "operation_type": OperationType.CONTAINER_INSPECT,
                    "description": "List Docker containers on remote target",
                    "parameters": {
                        "all_containers": {
                            "type": "bool",
                            "required": False,
                            "default": False,
                        }
                    },
                    "executor": RemoteAgentCapabilities.docker_operations,
                    "tier": "observe",
                },
                "docker_container_logs": {
                    "operation_type": OperationType.CONTAINER_INSPECT,
                    "description": "Get Docker container logs from remote target",
                    "parameters": {
                        "container_id": {"type": "string", "required": True},
                        "lines": {"type": "int", "required": False, "default": 100},
                        "since": {"type": "string", "required": False},
                    },
                    "executor": RemoteAgentCapabilities.docker_operations,
                    "tier": "observe",
                },
                "docker_container_restart": {
                    "operation_type": OperationType.CONTAINER_RESTART,
                    "description": "Restart Docker container on remote target",
                    "parameters": {
                        "container_id": {"type": "string", "required": True},
                        "timeout": {"type": "int", "required": False, "default": 30},
                    },
                    "executor": RemoteAgentCapabilities.docker_operations,
                    "tier": "control",
                },
            }
        )

        # File operation capabilities
        self.capabilities.update(
            {
                "file_read": {
                    "operation_type": OperationType.FILE_READ,
                    "description": "Read file from remote target",
                    "parameters": {
                        "path": {"type": "string", "required": True},
                        "max_size": {"type": "int", "required": False},
                    },
                    "executor": RemoteAgentCapabilities.file_operations,
                    "tier": "observe",
                },
                "file_write": {
                    "operation_type": OperationType.FILE_WRITE,
                    "description": "Write file to remote target",
                    "parameters": {
                        "path": {"type": "string", "required": True},
                        "content": {"type": "string", "required": True},
                        "create_backup": {
                            "type": "bool",
                            "required": False,
                            "default": True,
                        },
                    },
                    "executor": RemoteAgentCapabilities.file_operations,
                    "tier": "control",
                },
                "file_list": {
                    "operation_type": OperationType.FILE_READ,
                    "description": "List directory contents on remote target",
                    "parameters": {
                        "path": {"type": "string", "required": True},
                        "include_hidden": {
                            "type": "bool",
                            "required": False,
                            "default": False,
                        },
                    },
                    "executor": RemoteAgentCapabilities.file_operations,
                    "tier": "observe",
                },
            }
        )

        # System status capabilities
        self.capabilities.update(
            {
                "system_status": {
                    "operation_type": OperationType.NETWORK_STATUS,  # Reusing existing type
                    "description": "Get comprehensive system status from remote target",
                    "parameters": {},
                    "executor": RemoteAgentCapabilities.system_status,
                    "tier": "observe",
                }
            }
        )

        # Fleet capabilities
        self.capabilities.update(
            {
                "fleet_analyze_logs": {
                    "operation_type": OperationType.FILE_READ,
                    "description": "Analyze service logs across multiple targets",
                    "parameters": {
                        "service": {"type": "string", "required": True},
                        "time_range": {
                            "type": "string",
                            "required": False,
                            "default": "1 hour",
                        },
                    },
                    "executor": RemoteAgentCapabilities.fleet_operations,
                    "tier": "observe",
                },
                "fleet_check_health": {
                    "operation_type": OperationType.SERVICE_STATUS,
                    "description": "Check service health across multiple targets",
                    "parameters": {"service": {"type": "string", "required": True}},
                    "executor": RemoteAgentCapabilities.fleet_operations,
                    "tier": "observe",
                },
            }
        )

    def get_capability(self, name: str) -> Optional[Dict[str, Any]]:
        """Get capability by name.

        Args:
            name: Capability name

        Returns:
            Capability definition or None
        """
        return self.capabilities.get(name)

    def list_capabilities(self) -> List[str]:
        """List all available capabilities.

        Returns:
            List of capability names
        """
        return list(self.capabilities.keys())

    def get_capabilities_by_tier(self, tier: str) -> List[str]:
        """Get capabilities by operation tier.

        Args:
            tier: Operation tier

        Returns:
            List of capability names for the tier
        """
        return [
            name for name, cap in self.capabilities.items() if cap.get("tier") == tier
        ]


# Global capability registry instance
remote_agent_capability_registry = RemoteAgentCapabilityRegistry()


def register_remote_agent_capabilities():
    """Register remote agent capabilities with the policy system."""
    try:
        # This would integrate with the existing CAPABILITY_REGISTRY
        # For now, we'll return the registry for manual integration

        logger.info(
            f"Registered {len(remote_agent_capability_registry.list_capabilities())} remote agent capabilities"
        )

        return remote_agent_capability_registry

    except Exception as e:
        logger.error(f"Failed to register remote agent capabilities: {str(e)}")
        raise


def get_remote_agent_capability_executor(capability_name: str):
    """Get executor function for remote agent capability.

    Args:
        capability_name: Name of the capability

    Returns:
        Executor function or None
    """
    capability = remote_agent_capability_registry.get_capability(capability_name)
    return capability.get("executor") if capability else None


def validate_remote_agent_capability_params(
    capability_name: str, params: dict
) -> Tuple[bool, Optional[str]]:
    """Validate parameters for remote agent capability.

    Args:
        capability_name: Name of the capability
        params: Parameters to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    capability = remote_agent_capability_registry.get_capability(capability_name)

    if not capability:
        return False, f"Unknown capability: {capability_name}"

    param_definitions = capability.get("parameters", {})

    # Check required parameters
    for param_name, param_def in param_definitions.items():
        if param_def.get("required", False) and param_name not in params:
            return False, f"Missing required parameter: {param_name}"

    # Validate parameter types and values
    for param_name, value in params.items():
        if param_name in param_definitions:
            param_def = param_definitions[param_name]
            param_type = param_def.get("type")

            # Type validation
            if param_type == "string" and not isinstance(value, str):
                return False, f"Parameter {param_name} must be a string"
            elif param_type == "int" and not isinstance(value, int):
                return False, f"Parameter {param_name} must be an integer"
            elif param_type == "bool" and not isinstance(value, bool):
                return False, f"Parameter {param_name} must be a boolean"

    return True, None
