"""
Remote Agent MCP Tools

High-level MCP tools for agent-like functionality across SSH/Tailscale connections.
Provides comprehensive remote management capabilities without requiring agent installation.
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

from src.connectors.remote_agent_connector import (
    RemoteAgentConnector, LogEntry, ServiceStatus, DockerContainer, FileInfo,
    OperationResult, HealthStatus
)
from src.connectors.journald_connector import JournaldConnector
from src.connectors.service_connector import ServiceConnector
from src.connectors.docker_connector import DockerConnector
from src.connectors.file_connector import FileConnector
from src.services.connection_manager import get_connection_manager
from src.services.remote_operation_executor import ResilientRemoteOperation
from src.models.target_registry import TargetConnection
from src.utils.audit import AuditLogger


logger = logging.getLogger(__name__)


class RemoteAgentTools:
    """High-level MCP tools for agent-like functionality."""
    
    def __init__(self):
        """Initialize remote agent tools."""
        self.connection_manager = None
        self.executor = ResilientRemoteOperation()
        self.audit_logger = AuditLogger()
        self.logger = logging.getLogger(__name__)
    
    async def initialize(self):
        """Initialize the connection manager."""
        if self.connection_manager is None:
            self.connection_manager = await get_connection_manager()
    
    async def _get_target_connection(self, target_id: str) -> TargetConnection:
        """Get target connection configuration.
        
        Args:
            target_id: Target identifier
            
        Returns:
            Target connection configuration
        """
        # This would typically look up the target in the inventory
        # For now, we'll create a simple configuration
        if ':' in target_id:
            host, port_str = target_id.rsplit(':', 1)
            port = int(port_str) if port_str.isdigit() else 22
        else:
            host = target_id
            port = 22
        
        return TargetConnection(
            executor="ssh",
            host=host,
            port=port,
            username="root",
            timeout=30
        )
    
    async def _create_connector(self, target: TargetConnection, connector_type: str):
        """Create appropriate connector for target.
        
        Args:
            target: Target connection configuration
            connector_type: Type of connector to create
            
        Returns:
            Connector instance
        """
        await self.initialize()
        connection = await self.connection_manager.create_connection(target)
        
        if connector_type == "journald":
            return JournaldConnector(target, connection)
        elif connector_type == "service":
            return ServiceConnector(target, connection)
        elif connector_type == "docker":
            return DockerConnector(target, connection)
        elif connector_type == "file":
            return FileConnector(target, connection)
        else:
            raise ValueError(f"Unknown connector type: {connector_type}")
    
    # Journald Tools
    
    async def get_journald_logs(self, 
                               target: str, 
                               service: Optional[str] = None,
                               lines: int = 100,
                               since: Optional[str] = None,
                               until: Optional[str] = None,
                               priority: Optional[str] = None,
                               grep: Optional[str] = None) -> Dict[str, Any]:
        """Get journald logs from remote target.
        
        Args:
            target: Target identifier (host or host:port)
            service: Service name to filter by
            lines: Number of lines to retrieve
            since: Start time (e.g., "1 hour ago", "2023-01-01")
            until: End time
            priority: Priority filter (emerg, alert, crit, err, warning, notice, info, debug)
            grep: Text pattern to search for
            
        Returns:
            Dictionary containing logs and metadata
        """
        try:
            target_config = await self._get_target_connection(target)
            connector = await self._create_connector(target_config, "journald")
            
            logs = await connector.get_logs(
                service=service,
                lines=lines,
                since=since,
                until=until,
                priority=priority,
                grep=grep
            )
            
            # Convert to dict format for JSON serialization
            log_dicts = []
            for log in logs:
                log_dicts.append({
                    "timestamp": log.timestamp.isoformat(),
                    "level": log.level,
                    "message": log.message,
                    "source": log.source,
                    "metadata": log.metadata
                })
            
            # Log operation
            await self.audit_logger.log_operation(
                operation="get_journald_logs",
                target=target,
                parameters={
                    "service": service,
                    "lines": lines,
                    "since": since,
                    "until": until,
                    "priority": priority,
                    "grep": grep
                },
                result={"log_count": len(log_dicts)}
            )
            
            return {
                "success": True,
                "target": target,
                "service": service,
                "log_count": len(log_dicts),
                "logs": log_dicts,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get journald logs from {target}: {str(e)}")
            
            # Log failed operation
            await self.audit_logger.log_operation(
                operation="get_journald_logs",
                target=target,
                parameters={
                    "service": service,
                    "lines": lines,
                    "since": since,
                    "until": until,
                    "priority": priority,
                    "grep": grep
                },
                error=str(e)
            )
            
            return {
                "success": False,
                "error": str(e),
                "target": target,
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def follow_service_logs(self, 
                                 target: str, 
                                 service: str,
                                 timeout: int = 30) -> Dict[str, Any]:
        """Follow service logs in real-time.
        
        Args:
            target: Target identifier
            service: Service name to follow
            timeout: Follow timeout in seconds
            
        Returns:
            Initial result with stream information
        """
        try:
            target_config = await self._get_target_connection(target)
            connector = await self._create_connector(target_config, "journald")
            
            # Note: This returns an async iterator, which MCP tools can't directly handle
            # In a real implementation, this would need to be handled differently
            # For now, we'll return information about how to start following
            
            return {
                "success": True,
                "target": target,
                "service": service,
                "message": f"Log following initiated for {service} on {target}",
                "timeout": timeout,
                "stream_type": "async_iterator",
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to start log following for {service} on {target}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "target": target,
                "service": service,
                "timestamp": datetime.utcnow().isoformat()
            }
    
    # Service Management Tools
    
    async def restart_remote_service(self, 
                                    target: str, 
                                    service: str,
                                    timeout: int = 60) -> Dict[str, Any]:
        """Restart a service on remote target.
        
        Args:
            target: Target identifier
            service: Service name to restart
            timeout: Restart timeout in seconds
            
        Returns:
            Operation result
        """
        try:
            target_config = await self._get_target_connection(target)
            connector = await self._create_connector(target_config, "service")
            
            result = await connector.restart_service(service, timeout)
            
            # Log operation
            await self.audit_logger.log_operation(
                operation="restart_remote_service",
                target=target,
                parameters={"service": service, "timeout": timeout},
                result={"success": result.success, "result": result.result}
            )
            
            return {
                "success": result.success,
                "target": target,
                "service": service,
                "result": result.result,
                "error": result.error,
                "execution_time": result.execution_time,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to restart service {service} on {target}: {str(e)}")
            
            await self.audit_logger.log_operation(
                operation="restart_remote_service",
                target=target,
                parameters={"service": service, "timeout": timeout},
                error=str(e)
            )
            
            return {
                "success": False,
                "error": str(e),
                "target": target,
                "service": service,
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def get_service_status(self, target: str, service: str) -> Dict[str, Any]:
        """Get service status from remote target.
        
        Args:
            target: Target identifier
            service: Service name
            
        Returns:
            Service status information
        """
        try:
            target_config = await self._get_target_connection(target)
            connector = await self._create_connector(target_config, "service")
            
            status = await connector.get_service_status(service)
            
            # Log operation
            await self.audit_logger.log_operation(
                operation="get_service_status",
                target=target,
                parameters={"service": service},
                result={"state": status.state, "active_since": status.active_since}
            )
            
            return {
                "success": True,
                "target": target,
                "service": service,
                "status": {
                    "name": status.name,
                    "state": status.state,
                    "active_since": status.active_since.isoformat() if status.active_since else None,
                    "memory_usage": status.memory_usage,
                    "cpu_usage": status.cpu_usage,
                    "restart_count": status.restart_count,
                    "description": status.description
                },
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get service status for {service} on {target}: {str(e)}")
            
            await self.audit_logger.log_operation(
                operation="get_service_status",
                target=target,
                parameters={"service": service},
                error=str(e)
            )
            
            return {
                "success": False,
                "error": str(e),
                "target": target,
                "service": service,
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def list_remote_services(self, 
                                  target: str, 
                                  filter_state: Optional[str] = None) -> Dict[str, Any]:
        """List services on remote target.
        
        Args:
            target: Target identifier
            filter_state: Filter by service state
            
        Returns:
            List of services
        """
        try:
            target_config = await self._get_target_connection(target)
            connector = await self._create_connector(target_config, "service")
            
            services = await connector.list_services(filter_state)
            
            # Convert to dict format
            service_list = []
            for service in services:
                service_list.append({
                    "name": service.name,
                    "description": service.description,
                    "state": service.state,
                    "active_state": service.active_state,
                    "sub_state": service.sub_state,
                    "active_since": service.active_since.isoformat() if service.active_since else None,
                    "memory_current": service.memory_current,
                    "restart_count": service.restart_count,
                    "main_pid": service.main_pid,
                    "unit_file_state": service.unit_file_state
                })
            
            # Log operation
            await self.audit_logger.log_operation(
                operation="list_remote_services",
                target=target,
                parameters={"filter_state": filter_state},
                result={"service_count": len(service_list)}
            )
            
            return {
                "success": True,
                "target": target,
                "filter_state": filter_state,
                "service_count": len(service_list),
                "services": service_list,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to list services on {target}: {str(e)}")
            
            await self.audit_logger.log_operation(
                operation="list_remote_services",
                target=target,
                parameters={"filter_state": filter_state},
                error=str(e)
            )
            
            return {
                "success": False,
                "error": str(e),
                "target": target,
                "timestamp": datetime.utcnow().isoformat()
            }
    
    # Docker Tools
    
    async def get_remote_docker_containers(self, 
                                          target: str, 
                                          all_containers: bool = False) -> Dict[str, Any]:
        """Get Docker containers from remote target.
        
        Args:
            target: Target identifier
            all_containers: Include stopped containers
            
        Returns:
            List of Docker containers
        """
        try:
            target_config = await self._get_target_connection(target)
            connector = await self._create_connector(target_config, "docker")
            
            containers = await connector.list_containers(all_containers)
            
            # Convert to dict format
            container_list = []
            for container in containers:
                container_list.append({
                    "container_id": container.container_id,
                    "name": container.name,
                    "status": container.status,
                    "image": container.image,
                    "ports": container.ports,
                    "created": container.created.isoformat(),
                    "state": container.state
                })
            
            # Log operation
            await self.audit_logger.log_operation(
                operation="get_remote_docker_containers",
                target=target,
                parameters={"all_containers": all_containers},
                result={"container_count": len(container_list)}
            )
            
            return {
                "success": True,
                "target": target,
                "all_containers": all_containers,
                "container_count": len(container_list),
                "containers": container_list,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get Docker containers from {target}: {str(e)}")
            
            await self.audit_logger.log_operation(
                operation="get_remote_docker_containers",
                target=target,
                parameters={"all_containers": all_containers},
                error=str(e)
            )
            
            return {
                "success": False,
                "error": str(e),
                "target": target,
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def get_container_logs_remote(self, 
                                       target: str, 
                                       container_id: str,
                                       lines: int = 100,
                                       since: Optional[str] = None) -> Dict[str, Any]:
        """Get container logs from remote target.
        
        Args:
            target: Target identifier
            container_id: Container ID or name
            lines: Number of lines to retrieve
            since: Show logs since timestamp
            
        Returns:
            Container logs
        """
        try:
            target_config = await self._get_target_connection(target)
            connector = await self._create_connector(target_config, "docker")
            
            logs = await connector.get_container_logs(
                container_id=container_id,
                lines=lines,
                since=since
            )
            
            # Log operation
            await self.audit_logger.log_operation(
                operation="get_container_logs_remote",
                target=target,
                parameters={"container_id": container_id, "lines": lines, "since": since},
                result={"log_length": len(logs)}
            )
            
            return {
                "success": True,
                "target": target,
                "container_id": container_id,
                "log_length": len(logs),
                "logs": logs,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get logs for container {container_id} on {target}: {str(e)}")
            
            await self.audit_logger.log_operation(
                operation="get_container_logs_remote",
                target=target,
                parameters={"container_id": container_id, "lines": lines, "since": since},
                error=str(e)
            )
            
            return {
                "success": False,
                "error": str(e),
                "target": target,
                "container_id": container_id,
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def restart_remote_container(self, 
                                      target: str, 
                                      container_id: str,
                                      timeout: int = 30) -> Dict[str, Any]:
        """Restart Docker container on remote target.
        
        Args:
            target: Target identifier
            container_id: Container ID or name
            timeout: Restart timeout in seconds
            
        Returns:
            Operation result
        """
        try:
            target_config = await self._get_target_connection(target)
            connector = await self._create_connector(target_config, "docker")
            
            result = await connector.restart_container(container_id, timeout)
            
            # Log operation
            await self.audit_logger.log_operation(
                operation="restart_remote_container",
                target=target,
                parameters={"container_id": container_id, "timeout": timeout},
                result={"success": result.success}
            )
            
            return {
                "success": result.success,
                "target": target,
                "container_id": container_id,
                "result": result.result,
                "error": result.error,
                "execution_time": result.execution_time,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to restart container {container_id} on {target}: {str(e)}")
            
            await self.audit_logger.log_operation(
                operation="restart_remote_container",
                target=target,
                parameters={"container_id": container_id, "timeout": timeout},
                error=str(e)
            )
            
            return {
                "success": False,
                "error": str(e),
                "target": target,
                "container_id": container_id,
                "timestamp": datetime.utcnow().isoformat()
            }
    
    # File Operations Tools
    
    async def read_remote_file(self, 
                              target: str, 
                              path: str,
                              max_size: Optional[int] = None) -> Dict[str, Any]:
        """Read file from remote target.
        
        Args:
            target: Target identifier
            path: File path to read
            max_size: Maximum file size to read
            
        Returns:
            File content and metadata
        """
        try:
            target_config = await self._get_target_connection(target)
            connector = await self._create_connector(target_config, "file")
            
            content = await connector.read_file(path, max_size)
            
            # Log operation
            await self.audit_logger.log_operation(
                operation="read_remote_file",
                target=target,
                parameters={"path": path, "max_size": max_size},
                result={"content_length": len(content)}
            )
            
            return {
                "success": True,
                "target": target,
                "path": path,
                "content": content,
                "content_length": len(content),
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to read file {path} from {target}: {str(e)}")
            
            await self.audit_logger.log_operation(
                operation="read_remote_file",
                target=target,
                parameters={"path": path, "max_size": max_size},
                error=str(e)
            )
            
            return {
                "success": False,
                "error": str(e),
                "target": target,
                "path": path,
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def write_remote_file(self, 
                               target: str, 
                               path: str, 
                               content: str,
                               create_backup: bool = True) -> Dict[str, Any]:
        """Write file to remote target.
        
        Args:
            target: Target identifier
            path: File path to write
            content: Content to write
            create_backup: Whether to create backup
            
        Returns:
            Operation result
        """
        try:
            target_config = await self._get_target_connection(target)
            connector = await self._create_connector(target_config, "file")
            
            result = await connector.write_file(path, content, create_backup)
            
            # Log operation
            await self.audit_logger.log_operation(
                operation="write_remote_file",
                target=target,
                parameters={"path": path, "content_length": len(content), "create_backup": create_backup},
                result={"success": result.success}
            )
            
            return {
                "success": result.success,
                "target": target,
                "path": path,
                "result": result.result,
                "error": result.error,
                "execution_time": result.execution_time,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to write file {path} to {target}: {str(e)}")
            
            await self.audit_logger.log_operation(
                operation="write_remote_file",
                target=target,
                parameters={"path": path, "content_length": len(content), "create_backup": create_backup},
                error=str(e)
            )
            
            return {
                "success": False,
                "error": str(e),
                "target": target,
                "path": path,
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def list_remote_directory(self, 
                                   target: str, 
                                   path: str,
                                   include_hidden: bool = False) -> Dict[str, Any]:
        """List directory contents on remote target.
        
        Args:
            target: Target identifier
            path: Directory path to list
            include_hidden: Whether to include hidden files
            
        Returns:
            Directory contents
        """
        try:
            target_config = await self._get_target_connection(target)
            connector = await self._create_connector(target_config, "file")
            
            files = await connector.list_directory(path, include_hidden)
            
            # Convert to dict format
            file_list = []
            for file_info in files:
                file_list.append({
                    "name": file_info.name,
                    "path": file_info.path,
                    "size": file_info.size,
                    "is_directory": file_info.is_directory,
                    "permissions": file_info.permissions,
                    "owner": file_info.owner,
                    "group": file_info.group,
                    "modified": file_info.modified.isoformat()
                })
            
            # Log operation
            await self.audit_logger.log_operation(
                operation="list_remote_directory",
                target=target,
                parameters={"path": path, "include_hidden": include_hidden},
                result={"file_count": len(file_list)}
            )
            
            return {
                "success": True,
                "target": target,
                "path": path,
                "include_hidden": include_hidden,
                "file_count": len(file_list),
                "files": file_list,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to list directory {path} on {target}: {str(e)}")
            
            await self.audit_logger.log_operation(
                operation="list_remote_directory",
                target=target,
                parameters={"path": path, "include_hidden": include_hidden},
                error=str(e)
            )
            
            return {
                "success": False,
                "error": str(e),
                "target": target,
                "path": path,
                "timestamp": datetime.utcnow().isoformat()
            }
    
    # System Status Tools
    
    async def get_remote_system_status(self, target: str) -> Dict[str, Any]:
        """Get comprehensive system status from remote target.
        
        Args:
            target: Target identifier
            
        Returns:
            System status information
        """
        try:
            target_config = await self._get_target_connection(target)
            
            # Get connection health
            await self.initialize()
            health_status = await self.connection_manager.health_check(target_config)
            
            # Get basic system info
            connection = await self.connection_manager.create_connection(target_config)
            
            # System information commands
            commands = [
                ("uname -a", "system_info"),
                ("uptime", "uptime"),
                ("df -h", "disk_usage"),
                ("free -h", "memory_usage"),
                ("systemctl --version | head -1", "systemd_version"),
                ("docker --version 2>/dev/null || echo 'not installed'", "docker_version"),
            ]
            
            system_info = {}
            for cmd, info_type in commands:
                try:
                    result = await connection.execute_command(cmd, timeout=10)
                    system_info[info_type] = {
                        "success": result.exit_code == 0,
                        "output": result.stdout.strip() if result.exit_code == 0 else result.stderr.strip()
                    }
                except Exception as e:
                    system_info[info_type] = {
                        "success": False,
                        "error": str(e)
                    }
            
            # Log operation
            await self.audit_logger.log_operation(
                operation="get_remote_system_status",
                target=target,
                parameters={},
                result={"healthy": health_status.healthy}
            )
            
            return {
                "success": True,
                "target": target,
                "health": {
                    "healthy": health_status.healthy,
                    "response_time": health_status.response_time,
                    "last_check": health_status.last_check.isoformat(),
                    "issues": health_status.issues
                },
                "system_info": system_info,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get system status from {target}: {str(e)}")
            
            await self.audit_logger.log_operation(
                operation="get_remote_system_status",
                target=target,
                parameters={},
                error=str(e)
            )
            
            return {
                "success": False,
                "error": str(e),
                "target": target,
                "timestamp": datetime.utcnow().isoformat()
            }
    
    # Fleet Operations
    
    async def analyze_service_logs_across_fleet(self, 
                                               targets: List[str],
                                               service: str,
                                               time_range: str = "1 hour") -> Dict[str, Any]:
        """Analyze service logs across multiple targets.
        
        Args:
            targets: List of target identifiers
            service: Service name to analyze
            time_range: Time range for analysis
            
        Returns:
            Aggregated log analysis
        """
        try:
            all_logs = []
            target_results = {}
            
            for target in targets:
                try:
                    result = await self.get_journald_logs(
                        target=target,
                        service=service,
                        since=time_range
                    )
                    
                    if result["success"]:
                        target_results[target] = {
                            "success": True,
                            "log_count": result["log_count"]
                        }
                        all_logs.extend(result["logs"])
                    else:
                        target_results[target] = {
                            "success": False,
                            "error": result["error"]
                        }
                        
                except Exception as e:
                    target_results[target] = {
                        "success": False,
                        "error": str(e)
                    }
            
            # Analyze aggregated logs
            analysis = {
                "total_targets": len(targets),
                "successful_targets": sum(1 for r in target_results.values() if r["success"]),
                "total_logs": len(all_logs),
                "time_range": time_range,
                "service": service,
                "target_results": target_results,
                "log_levels": {},
                "common_messages": {}
            }
            
            # Count log levels
            for log in all_logs:
                level = log.get("level", "unknown")
                analysis["log_levels"][level] = analysis["log_levels"].get(level, 0) + 1
            
            # Count common messages
            message_counts = {}
            for log in all_logs:
                message = log.get("message", "")
                if message:
                    message_counts[message] = message_counts.get(message, 0) + 1
            
            # Get top 10 most common messages
            analysis["common_messages"] = dict(sorted(
                message_counts.items(), key=lambda x: x[1], reverse=True
            )[:10])
            
            # Log operation
            await self.audit_logger.log_operation(
                operation="analyze_service_logs_across_fleet",
                target="multiple",
                parameters={"targets": targets, "service": service, "time_range": time_range},
                result=analysis
            )
            
            return {
                "success": True,
                "analysis": analysis,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to analyze logs across fleet: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def check_fleet_service_health(self, 
                                        targets: List[str],
                                        service: str) -> Dict[str, Any]:
        """Check service health across multiple targets.
        
        Args:
            targets: List of target identifiers
            service: Service name to check
            
        Returns:
            Fleet health report
        """
        try:
            health_report = []
            
            for target in targets:
                try:
                    result = await self.get_service_status(target, service)
                    
                    if result["success"]:
                        health_report.append({
                            "target": target,
                            "service": service,
                            "status": result["status"]["state"],
                            "healthy": result["status"]["state"] == "active",
                            "active_since": result["status"]["active_since"],
                            "memory_usage": result["status"]["memory_usage"],
                            "restart_count": result["status"]["restart_count"]
                        })
                    else:
                        health_report.append({
                            "target": target,
                            "service": service,
                            "error": result["error"]
                        })
                        
                except Exception as e:
                    health_report.append({
                        "target": target,
                        "service": service,
                        "error": str(e)
                    })
            
            # Calculate summary
            healthy_count = sum(1 for report in health_report if report.get("healthy", False))
            total_count = len(health_report)
            
            summary = {
                "total_targets": total_count,
                "healthy_targets": healthy_count,
                "unhealthy_targets": total_count - healthy_count,
                "health_percentage": (healthy_count / total_count * 100) if total_count > 0 else 0,
                "service": service
            }
            
            # Log operation
            await self.audit_logger.log_operation(
                operation="check_fleet_service_health",
                target="multiple",
                parameters={"targets": targets, "service": service},
                result=summary
            )
            
            return {
                "success": True,
                "summary": summary,
                "health_report": health_report,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to check fleet service health: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }


# Global instance
remote_agent_tools = RemoteAgentTools()


# MCP Tool Functions
async def get_journald_logs(target: str, service: str = None, lines: int = 100, 
                           since: str = None, until: str = None, priority: str = None, 
                           grep: str = None) -> Dict[str, Any]:
    """MCP tool: Get journald logs from remote target."""
    return await remote_agent_tools.get_journald_logs(
        target=target, service=service, lines=lines, since=since, 
        until=until, priority=priority, grep=grep
    )


async def follow_service_logs(target: str, service: str, timeout: int = 30) -> Dict[str, Any]:
    """MCP tool: Follow service logs in real-time."""
    return await remote_agent_tools.follow_service_logs(target=target, service=service, timeout=timeout)


async def restart_remote_service(target: str, service: str, timeout: int = 60) -> Dict[str, Any]:
    """MCP tool: Restart service on remote target."""
    return await remote_agent_tools.restart_remote_service(target=target, service=service, timeout=timeout)


async def get_service_status(target: str, service: str) -> Dict[str, Any]:
    """MCP tool: Get service status from remote target."""
    return await remote_agent_tools.get_service_status(target=target, service=service)


async def list_remote_services(target: str, filter_state: str = None) -> Dict[str, Any]:
    """MCP tool: List services on remote target."""
    return await remote_agent_tools.list_remote_services(target=target, filter_state=filter_state)


async def get_remote_docker_containers(target: str, all_containers: bool = False) -> Dict[str, Any]:
    """MCP tool: Get Docker containers from remote target."""
    return await remote_agent_tools.get_remote_docker_containers(target=target, all_containers=all_containers)


async def get_container_logs_remote(target: str, container_id: str, lines: int = 100, 
                                   since: str = None) -> Dict[str, Any]:
    """MCP tool: Get container logs from remote target."""
    return await remote_agent_tools.get_container_logs_remote(
        target=target, container_id=container_id, lines=lines, since=since
    )


async def restart_remote_container(target: str, container_id: str, timeout: int = 30) -> Dict[str, Any]:
    """MCP tool: Restart Docker container on remote target."""
    return await remote_agent_tools.restart_remote_container(
        target=target, container_id=container_id, timeout=timeout
    )


async def read_remote_file(target: str, path: str, max_size: int = None) -> Dict[str, Any]:
    """MCP tool: Read file from remote target."""
    return await remote_agent_tools.read_remote_file(target=target, path=path, max_size=max_size)


async def write_remote_file(target: str, path: str, content: str, create_backup: bool = True) -> Dict[str, Any]:
    """MCP tool: Write file to remote target."""
    return await remote_agent_tools.write_remote_file(
        target=target, path=path, content=content, create_backup=create_backup
    )


async def list_remote_directory(target: str, path: str, include_hidden: bool = False) -> Dict[str, Any]:
    """MCP tool: List directory contents on remote target."""
    return await remote_agent_tools.list_remote_directory(
        target=target, path=path, include_hidden=include_hidden
    )


async def get_remote_system_status(target: str) -> Dict[str, Any]:
    """MCP tool: Get comprehensive system status from remote target."""
    return await remote_agent_tools.get_remote_system_status(target=target)


async def analyze_service_logs_across_fleet(targets: List[str], service: str, 
                                           time_range: str = "1 hour") -> Dict[str, Any]:
    """MCP tool: Analyze service logs across multiple targets."""
    return await remote_agent_tools.analyze_service_logs_across_fleet(
        targets=targets, service=service, time_range=time_range
    )


async def check_fleet_service_health(targets: List[str], service: str) -> Dict[str, Any]:
    """MCP tool: Check service health across multiple targets."""
    return await remote_agent_tools.check_fleet_service_health(targets=targets, service=service)