"""
Service Connector for Systemd Service Management

Provides comprehensive systemd service management via SSH without requiring agent installation.
Supports service status checks, restarts, and log access.
"""

import asyncio
import json
import re
import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass

from src.connectors.remote_agent_connector import (
    RemoteAgentConnector, ServiceStatus, LogEntry, OperationResult
)
from src.services.remote_operation_executor import (
    ResilientRemoteOperation, resilient_service_operation, OperationType
)
from src.utils.errors import SystemManagerError


logger = logging.getLogger(__name__)


@dataclass
class ServiceInfo:
    """Information about a systemd service."""
    name: str
    description: str
    state: str
    active_state: str
    sub_state: str
    active_since: Optional[datetime]
    memory_current: Optional[int]
    cpu_usage: Optional[float]
    restart_count: int
    last_restart: Optional[datetime]
    main_pid: Optional[int]
    control_group: Optional[str]
    drop_in_files: List[str]
    unit_file_state: str
    unit_file_preset: str


@dataclass
class ServiceDependency:
    """Service dependency information."""
    service: str
    depends_on: List[str]
    required_by: List[str]
    wanted_by: List[str]


class ServiceConnector(RemoteAgentConnector):
    """Systemd service management via SSH.
    
    Provides agent-like systemd service functionality without requiring agent installation.
    Supports service status checks, restarts, and log access.
    """
    
    def __init__(self, target, connection):
        """Initialize service connector.
        
        Args:
            target: Target connection configuration
            connection: SSH connection instance
        """
        super().__init__(target, connection)
        self.executor = ResilientRemoteOperation()
        self._systemctl_timeout = 30
    
    async def get_capabilities(self) -> Dict[str, Any]:
        """Get service connector capabilities.
        
        Returns:
            Dictionary of available capabilities
        """
        try:
            # Check if systemctl is available
            result = await self.execute_command("which systemctl")
            if result.exit_code != 0:
                return {"available": False, "reason": "systemctl not found"}
            
            # Check systemctl permissions
            result = await self.execute_command("systemctl --version", timeout=10)
            if result.exit_code != 0:
                return {
                    "available": True,
                    "permissions": "limited",
                    "reason": "Limited systemctl access"
                }
            
            return {
                "available": True,
                "permissions": "full",
                "supports_service_management": True,
                "supports_dependency_analysis": True,
                "supports_unit_files": True,
                "version": self._get_systemctl_version(result.stdout)
            }
            
        except Exception as e:
            return {
                "available": False,
                "error": str(e)
            }
    
    async def validate_target(self) -> bool:
        """Validate that target supports systemd operations.
        
        Returns:
            True if target is valid for systemd operations
        """
        try:
            capabilities = await self.get_capabilities()
            return capabilities.get("available", False)
        except Exception:
            return False
    
    @resilient_service_operation(operation_name="get_service_status")
    async def get_service_status(self, service: str) -> ServiceStatus:
        """Get detailed service status.
        
        Args:
            service: Service name
            
        Returns:
            Service status information
        """
        cmd = f"systemctl show {service} -p ActiveState,SubState,ActiveEnterTimestamp,MemoryCurrent,CPUUsageNSec,Restart,RestartUSec,MainPID,ControlGroup,UnitFileState,Description --no-pager --json=short"
        
        try:
            result = await self.execute_command(cmd, timeout=self._systemctl_timeout)
            
            if result.exit_code != 0:
                if "not-found" in result.stderr.lower():
                    raise SystemManagerError(f"Service {service} not found")
                else:
                    raise SystemManagerError(f"Failed to get service status: {result.stderr}")
            
            # Parse systemctl show output
            properties = self._parse_systemctl_show(result.stdout)
            
            # Parse timestamp
            active_since = None
            active_since_str = properties.get('ActiveEnterTimestampMonotonic')
            if active_since_str:
                try:
                    # Convert from monotonic time to real time
                    boot_time_result = await self.execute_command("date -d @$(($(date +%s%6N) - $(cat /proc/stat/btime))) +%s%N", timeout=5)
                    if boot_time_result.exit_code == 0:
                        boot_time_ns = int(boot_time_result.stdout.strip())
                        active_since = datetime.fromtimestamp(
                            (boot_time_ns + int(active_since_str)) / 1_000_000_000
                        )
                except Exception:
                    active_since = None
            
            # Parse memory usage
            memory_usage = None
            memory_str = properties.get('MemoryCurrent')
            if memory_str and memory_str != '0':
                try:
                    memory_usage = int(memory_str)
                except ValueError:
                    pass
            
            # Parse CPU usage
            cpu_usage = None
            cpu_str = properties.get('CPUUsageNSec')
            if cpu_str and cpu_str != '0':
                try:
                    cpu_usage = float(cpu_str) / 1_000_000_000  # Convert to seconds
                except ValueError:
                    pass
            
            # Parse restart count
            restart_count = 0
            restart_str = properties.get('RestartUSec')
            if restart_str and restart_str != '0':
                try:
                    # This is approximate - systemd doesn't expose restart count directly
                    restart_count = 0
                except ValueError:
                    pass
            
            return ServiceStatus(
                name=service,
                state=properties.get('ActiveState', 'unknown'),
                active_since=active_since,
                memory_usage=memory_usage,
                cpu_usage=cpu_usage,
                restart_count=restart_count,
                description=properties.get('Description', '')
            )
            
        except Exception as e:
            logger.error(f"Failed to get service status for {service}: {str(e)}")
            raise
    
    @resilient_service_operation(operation_name="restart_service")
    async def restart_service(self, service: str, timeout: int = 60) -> OperationResult:
        """Restart a systemd service.
        
        Args:
            service: Service name
            timeout: Operation timeout in seconds
            
        Returns:
            Operation result
        """
        cmd = f"systemctl restart {service} --no-block --no-pager"
        
        try:
            result = await self.execute_command(cmd, timeout=timeout)
            
            if result.exit_code == 0:
                return OperationResult(
                    operation=f"restart_service",
                    target=service,
                    success=True,
                    result="Service restarted successfully",
                    timestamp=datetime.utcnow()
                )
            else:
                return OperationResult(
                    operation=f"restart_service",
                    target=service,
                    success=False,
                    error=result.stderr,
                    timestamp=datetime.utcnow()
                )
                
        except Exception as e:
            return OperationResult(
                operation=f"restart_service",
                target=service,
                success=False,
                error=str(e),
                timestamp=datetime.utcnow()
            )
    
    @resilient_service_operation(operation_name="start_service")
    async def start_service(self, service: str, timeout: int = 30) -> OperationResult:
        """Start a systemd service.
        
        Args:
            service: Service name
            timeout: Operation timeout in seconds
            
        Returns:
            Operation result
        """
        cmd = f"systemctl start {service} --no-block --no-pager"
        
        try:
            result = await self.execute_command(cmd, timeout=timeout)
            
            if result.exit_code == 0:
                return OperationResult(
                    operation=f"start_service",
                    target=service,
                    success=True,
                    result="Service started successfully",
                    timestamp=datetime.utcnow()
                )
            else:
                return OperationResult(
                    operation=f"start_service",
                    target=service,
                    success=False,
                    error=result.stderr,
                    timestamp=datetime.utcnow()
                )
                
        except Exception as e:
            return OperationResult(
                operation=f"start_service",
                target=service,
                success=False,
                error=str(e),
                timestamp=datetime.utcnow()
            )
    
    @resilient_service_operation(operation_name="stop_service")
    async def stop_service(self, service: str, timeout: int = 30) -> OperationResult:
        """Stop a systemd service.
        
        Args:
            service: Service name
            timeout: Operation timeout in seconds
            
        Returns:
            Operation result
        """
        cmd = f"systemctl stop {service} --no-block --no-pager"
        
        try:
            result = await self.execute_command(cmd, timeout=timeout)
            
            if result.exit_code == 0:
                return OperationResult(
                    operation=f"stop_service",
                    target=service,
                    success=True,
                    result="Service stopped successfully",
                    timestamp=datetime.utcnow()
                )
            else:
                return OperationResult(
                    operation=f"stop_service",
                    target=service,
                    success=False,
                    error=result.stderr,
                    timestamp=datetime.utcnow()
                )
                
        except Exception as e:
            return OperationResult(
                operation=f"stop_service",
                target=service,
                success=False,
                error=str(e),
                timestamp=datetime.utcnow()
            )
    
    async def get_service_logs(self, service: str, lines: int = 100) -> List[LogEntry]:
        """Get service logs via journald.
        
        Args:
            service: Service name
            lines: Number of log lines to retrieve
            
        Returns:
            List of log entries
        """
        cmd = f"journalctl -u {service} -n {lines} --no-pager -o json"
        
        try:
            result = await self.execute_command(cmd, timeout=60)
            
            if result.exit_code != 0:
                raise SystemManagerError(f"Failed to get service logs: {result.stderr}")
            
            # Parse JSON logs
            logs = []
            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                
                try:
                    log_data = json.loads(line)
                    
                    # Extract timestamp
                    timestamp_str = log_data.get('SYSLOG_TIMESTAMP')
                    if timestamp_str:
                        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    else:
                        timestamp = datetime.utcnow()
                    
                    logs.append(LogEntry(
                        timestamp=timestamp,
                        level="info",  # Default level
                        message=log_data.get('MESSAGE', ''),
                        source=service,
                        metadata=log_data
                    ))
                    
                except Exception as e:
                    logger.warning(f"Failed to parse log line: {str(e)}")
                    continue
            
            return logs
            
        except Exception as e:
            logger.error(f"Failed to get service logs for {service}: {str(e)}")
            raise
    
    @resilient_service_operation(operation_name="list_services")
    async def list_services(self, filter_state: Optional[str] = None) -> List[ServiceInfo]:
        """List all systemd services.
        
        Args:
            filter_state: Filter by service state (active, inactive, failed, etc.)
            
        Returns:
            List of service information
        """
        cmd = "systemctl list-units --all --type=service --no-pager --json=short"
        
        try:
            result = await self.execute_command(cmd, timeout=60)
            
            if result.exit_code != 0:
                raise SystemManagerError(f"Failed to list services: {result.stderr}")
            
            services = []
            
            # Parse JSON output
            try:
                service_data = json.loads(result.stdout)
                
                for unit in service_data:
                    service_name = unit.get('unit', '').replace('.service', '')
                    
                    # Filter by state if requested
                    if filter_state and unit.get('activeState') != filter_state:
                        continue
                    
                    # Parse timestamps
                    active_since = None
                    if unit.get('activeEnterTimestampMonotonic'):
                        try:
                            # This is simplified - real implementation would need boot time
                            active_since = datetime.utcnow()
                        except Exception:
                            pass
                    
                    # Parse memory usage
                    memory_current = unit.get('memoryCurrent')
                    if memory_current and memory_current != '0':
                        try:
                            memory_current = int(memory_current)
                        except ValueError:
                            memory_current = None
                    
                    services.append(ServiceInfo(
                        name=service_name,
                        description=unit.get('description', ''),
                        state=unit.get('unit', ''),
                        active_state=unit.get('activeState', 'unknown'),
                        sub_state=unit.get('subState', 'unknown'),
                        active_since=active_since,
                        memory_current=memory_current,
                        cpu_usage=None,  # Not available in list output
                        restart_count=0,  # Not available in list output
                        last_restart=None,
                        main_pid=unit.get('mainPID'),
                        control_group=unit.get('controlGroup'),
                        drop_in_files=[],
                        unit_file_state=unit.get('unitFileState', 'unknown'),
                        unit_file_preset=unit.get('unitFilePreset', 'unknown')
                    ))
                    
            except json.JSONDecodeError:
                # Fallback to parsing plain text output
                services = await self._parse_service_list_plain(result.stdout, filter_state)
            
            return services
            
        except Exception as e:
            logger.error(f"Failed to list services: {str(e)}")
            raise
    
    async def get_service_dependencies(self, service: str) -> ServiceDependency:
        """Get service dependencies.
        
        Args:
            service: Service name
            
        Returns:
            Service dependency information
        """
        cmd = f"systemctl list-dependencies {service} --reverse --no-pager --json=short"
        
        try:
            result = await self.execute_command(cmd, timeout=30)
            
            if result.exit_code != 0:
                raise SystemManagerError(f"Failed to get service dependencies: {result.stderr}")
            
            # Parse dependency information
            depends_on = []
            required_by = []
            wanted_by = []
            
            try:
                dep_data = json.loads(result.stdout)
                
                for dep in dep_data:
                    dep_name = dep.get('name', '')
                    
                    if dep.get('kind') == 'requires':
                        required_by.append(dep_name)
                    elif dep.get('kind') == 'wants':
                        wanted_by.append(dep_name)
                    else:
                        depends_on.append(dep_name)
                        
            except json.JSONDecodeError:
                # Fallback to text parsing
                lines = result.stdout.strip().split('\n')
                for line in lines[1:]:  # Skip header
                    if line.strip():
                        dep_name = line.strip().replace('●', '').strip()
                        if dep_name:
                            depends_on.append(dep_name)
            
            return ServiceDependency(
                service=service,
                depends_on=depends_on,
                required_by=required_by,
                wanted_by=wanted_by
            )
            
        except Exception as e:
            logger.error(f"Failed to get service dependencies for {service}: {str(e)}")
            raise
    
    async def check_service_health(self, service: str) -> Dict[str, Any]:
        """Comprehensive service health check.
        
        Args:
            service: Service name
            
        Returns:
            Health check results
        """
        try:
            # Get service status
            status = await self.get_service_status(service)
            
            # Get recent logs
            recent_logs = await self.get_service_logs(service, lines=20)
            
            # Analyze health
            health = {
                "service": service,
                "status": status.state,
                "healthy": status.state in ["active"],
                "last_check": datetime.utcnow(),
                "active_since": status.active_since,
                "memory_usage_mb": status.memory_usage / (1024 * 1024) if status.memory_usage else None,
                "cpu_usage": status.cpu_usage,
                "restart_count": status.restart_count,
                "recent_errors": 0,
                "recent_warnings": 0,
                "last_error_time": None
            }
            
            # Analyze recent logs for issues
            for log in recent_logs:
                if log.level in ["err", "crit", "alert", "emerg"]:
                    health["recent_errors"] += 1
                    if not health["last_error_time"]:
                        health["last_error_time"] = log.timestamp
                elif log.level == "warning":
                    health["recent_warnings"] += 1
            
            return health
            
        except Exception as e:
            return {
                "service": service,
                "status": "unknown",
                "healthy": False,
                "last_check": datetime.utcnow(),
                "error": str(e)
            }
    
    def _get_systemctl_version(self, version_output: str) -> str:
        """Extract systemctl version from output.
        
        Args:
            version_output: Version command output
            
        Returns:
            Version string
        """
        try:
            # Extract version from "systemd 245 (245.4-4ubuntu3.13)" format
            match = re.search(r'systemd\s+(\d+)', version_output)
            if match:
                return match.group(1)
            return "unknown"
        except Exception:
            return "unknown"
    
    def _parse_systemctl_show(self, output: str) -> Dict[str, str]:
        """Parse systemctl show output.
        
        Args:
            output: systemctl show output
            
        Returns:
            Dictionary of property names to values
        """
        properties = {}
        
        for line in output.strip().split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                properties[key] = value
        
        return properties
    
    async def _parse_service_list_plain(self, output: str, filter_state: Optional[str]) -> List[ServiceInfo]:
        """Parse plain text systemctl list-units output.
        
        Args:
            output: systemctl list-units output
            filter_state: State filter
            
        Returns:
            List of service information
        """
        services = []
        lines = output.strip().split('\n')
        
        # Skip header lines
        data_lines = []
        for line in lines:
            if line.strip() and not line.startswith('●') and not line.startswith('UNIT'):
                data_lines.append(line)
        
        for line in data_lines:
            try:
                # Parse format: "UNIT                          LOAD   ACTIVE SUB     DESCRIPTION"
                parts = line.split(None, 4)
                if len(parts) >= 4:
                    unit_name = parts[0]
                    load_state = parts[1]
                    active_state = parts[2]
                    sub_state = parts[3]
                    description = parts[4] if len(parts) > 4 else ""
                    
                    service_name = unit_name.replace('.service', '')
                    
                    # Filter by state if requested
                    if filter_state and active_state != filter_state:
                        continue
                    
                    services.append(ServiceInfo(
                        name=service_name,
                        description=description,
                        state=unit_name,
                        active_state=active_state,
                        sub_state=sub_state,
                        active_since=None,
                        memory_current=None,
                        cpu_usage=None,
                        restart_count=0,
                        last_restart=None,
                        main_pid=None,
                        control_group=None,
                        drop_in_files=[],
                        unit_file_state="unknown",
                        unit_file_preset="unknown"
                    ))
                    
            except Exception as e:
                logger.warning(f"Failed to parse service line: {line} - {str(e)}")
                continue
        
        return services