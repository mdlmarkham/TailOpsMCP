"""
Node Probing Service for Gateway Fleet Orchestrator.

Provides connection testing and health checking for discovered nodes,
with support for Tailscale SSH and regular SSH connections.
"""

import logging
import subprocess
import socket
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime

from src.models.fleet_inventory import Node, Service, ServiceStatus, Event, EventType, EventSeverity
from src.utils.retry import retry_with_backoff

logger = logging.getLogger(__name__)


class NodeProbing:
    """Node probing service with connection testing and health checking."""
    
    def __init__(self, tailscale_config: Dict[str, Any] = None):
        """Initialize node probing service.
        
        Args:
            tailscale_config: Tailscale configuration for SSH connections
        """
        self.tailscale_config = tailscale_config or {}
    
    def probe_node(self, node: Node) -> Dict[str, Any]:
        """Probe a node to collect system information and test connections.
        
        Args:
            node: Node to probe
            
        Returns:
            Dictionary with probe results including connection status and system info
        """
        probe_result = {
            "node_id": node.id,
            "node_name": node.name,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "connection_tests": {},
            "system_info": {},
            "services": [],
            "errors": []
        }
        
        # Test connections based on priority
        connection_results = self._test_connections(node)
        probe_result["connection_tests"] = connection_results
        
        # If any connection is successful, collect system information
        successful_connection = next((conn for conn, result in connection_results.items() 
                                    if result.get("success")), None)
        
        if successful_connection:
            try:
                system_info = self._collect_system_info(node, successful_connection)
                probe_result["system_info"] = system_info
                
                # Discover services
                services = self._discover_services(node, successful_connection)
                probe_result["services"] = services
                
            except Exception as e:
                probe_result["errors"].append(f"Failed to collect system info: {e}")
                logger.error(f"Failed to probe node {node.name}: {e}")
        
        return probe_result
    
    def _test_connections(self, node: Node) -> Dict[str, Dict[str, Any]]:
        """Test connections to a node with priority order."""
        connection_results = {}
        
        # Priority 1: Tailscale SSH (if configured)
        if self.tailscale_config and node.ip_address:
            tailscale_result = self._test_tailscale_ssh(node)
            connection_results["tailscale_ssh"] = tailscale_result
            
            if tailscale_result.get("success"):
                return connection_results  # Stop if Tailscale SSH works
        
        # Priority 2: Regular SSH
        if node.ip_address:
            ssh_result = self._test_regular_ssh(node)
            connection_results["ssh"] = ssh_result
        
        return connection_results
    
    @retry_with_backoff(max_retries=2, base_delay=2)
    def _test_tailscale_ssh(self, node: Node) -> Dict[str, Any]:
        """Test Tailscale SSH connection."""
        try:
            # Use tailscale ssh command
            command = ["tailscale", "ssh", node.ip_address, "echo", "test"]
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            
            return {
                "success": result.returncode == 0,
                "output": result.stdout.strip() if result.returncode == 0 else result.stderr,
                "method": "tailscale_ssh"
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Connection timeout",
                "method": "tailscale_ssh"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "method": "tailscale_ssh"
            }
    
    @retry_with_backoff(max_retries=2, base_delay=2)
    def _test_regular_ssh(self, node: Node) -> Dict[str, Any]:
        """Test regular SSH connection."""
        try:
            # Use standard SSH command
            # This is a simplified test - in production, would use paramiko or similar
            command = ["ssh", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes", 
                      f"root@{node.ip_address}", "echo", "test"]
            
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            
            return {
                "success": result.returncode == 0,
                "output": result.stdout.strip() if result.returncode == 0 else result.stderr,
                "method": "ssh"
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Connection timeout",
                "method": "ssh"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "method": "ssh"
            }
    
    def _collect_system_info(self, node: Node, connection_method: str) -> Dict[str, Any]:
        """Collect system information from a node."""
        system_info = {}
        
        # Basic system commands to collect information
        commands = {
            "hostname": "hostname",
            "os_info": "cat /etc/os-release",
            "uptime": "uptime",
            "memory": "free -m",
            "disk": "df -h",
            "docker_status": "docker --version 2>/dev/null || echo 'Docker not installed'",
            "docker_ps": "docker ps --format 'table {{.Names}}\t{{.Status}}' 2>/dev/null || echo ''"
        }
        
        for key, command in commands.items():
            try:
                result = self._execute_remote_command(node, connection_method, command)
                system_info[key] = result.get("output", "").strip()
            except Exception as e:
                system_info[key] = f"Error: {e}"
        
        # Parse structured information
        system_info["parsed"] = self._parse_system_info(system_info)
        
        return system_info
    
    def _execute_remote_command(self, node: Node, connection_method: str, command: str) -> Dict[str, Any]:
        """Execute a command on a remote node."""
        try:
            if connection_method == "tailscale_ssh":
                full_command = ["tailscale", "ssh", node.ip_address, command]
            else:  # regular SSH
                full_command = ["ssh", "-o", "ConnectTimeout=5", f"root@{node.ip_address}", command]
            
            result = subprocess.run(full_command, capture_output=True, text=True, timeout=30)
            
            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr if result.returncode != 0 else ""
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Command timeout"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _parse_system_info(self, system_info: Dict[str, str]) -> Dict[str, Any]:
        """Parse system information into structured format."""
        parsed = {}
        
        # Parse hostname
        parsed["hostname"] = system_info.get("hostname", "unknown").strip()
        
        # Parse OS information
        os_info = system_info.get("os_info", "")
        parsed["os"] = self._parse_os_info(os_info)
        
        # Parse uptime
        uptime = system_info.get("uptime", "")
        parsed["uptime"] = self._parse_uptime(uptime)
        
        # Parse memory
        memory = system_info.get("memory", "")
        parsed["memory"] = self._parse_memory(memory)
        
        # Parse disk
        disk = system_info.get("disk", "")
        parsed["disk"] = self._parse_disk(disk)
        
        # Parse Docker status
        docker_status = system_info.get("docker_status", "")
        parsed["docker"] = self._parse_docker_status(docker_status)
        
        # Parse Docker containers
        docker_ps = system_info.get("docker_ps", "")
        parsed["docker_containers"] = self._parse_docker_ps(docker_ps)
        
        return parsed
    
    def _parse_os_info(self, os_info: str) -> Dict[str, str]:
        """Parse /etc/os-release information."""
        os_data = {}
        for line in os_info.split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                os_data[key.strip()] = value.strip().strip('"')
        return os_data
    
    def _parse_uptime(self, uptime: str) -> Dict[str, Any]:
        """Parse uptime information."""
        try:
            # Extract uptime from typical uptime output
            parts = uptime.split()
            if len(parts) >= 4:
                # Format: "up X days, Y:Z, load average: ..."
                uptime_str = parts[2] + " " + parts[3]  # "X days,"
                load_average = parts[-3:]  # Last three parts are load averages
                
                return {
                    "uptime": uptime_str.rstrip(','),
                    "load_average": load_average
                }
        except Exception:
            pass
        return {"uptime": "unknown", "load_average": []}
    
    def _parse_memory(self, memory: str) -> Dict[str, int]:
        """Parse memory information from 'free -m'."""
        try:
            lines = memory.split('\n')
            if len(lines) > 1:
                # Second line contains memory info
                parts = lines[1].split()
                if len(parts) >= 6:
                    return {
                        "total": int(parts[1]),
                        "used": int(parts[2]),
                        "free": int(parts[3]),
                        "available": int(parts[6])
                    }
        except Exception:
            pass
        return {"total": 0, "used": 0, "free": 0, "available": 0}
    
    def _parse_disk(self, disk: str) -> List[Dict[str, Any]]:
        """Parse disk information from 'df -h'."""
        disks = []
        try:
            lines = disk.split('\n')[1:]  # Skip header
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 6:
                        disks.append({
                            "filesystem": parts[0],
                            "size": parts[1],
                            "used": parts[2],
                            "available": parts[3],
                            "use_percent": parts[4],
                            "mounted_on": parts[5]
                        })
        except Exception:
            pass
        return disks
    
    def _parse_docker_status(self, docker_status: str) -> Dict[str, Any]:
        """Parse Docker installation status."""
        if "Docker not installed" in docker_status:
            return {"installed": False}
        elif "Docker version" in docker_status:
            # Extract version
            version = docker_status.split("Docker version")[1].split(",")[0].strip()
            return {"installed": True, "version": version}
        return {"installed": False}
    
    def _parse_docker_ps(self, docker_ps: str) -> List[Dict[str, str]]:
        """Parse 'docker ps' output."""
        containers = []
        try:
            lines = docker_ps.split('\n')[1:]  # Skip header
            for line in lines:
                if line.strip() and not line.startswith('NAMES'):
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        containers.append({
                            "name": parts[0].strip(),
                            "status": parts[1].strip()
                        })
        except Exception:
            pass
        return containers
    
    def _discover_services(self, node: Node, connection_method: str) -> List[Service]:
        """Discover services running on a node."""
        services = []
        
        # Discover systemd services
        systemd_services = self._discover_systemd_services(node, connection_method)
        services.extend(systemd_services)
        
        # Discover Docker services
        docker_services = self._discover_docker_services(node, connection_method)
        services.extend(docker_services)
        
        # Discover Docker Compose stacks
        compose_stacks = self._discover_compose_stacks(node, connection_method)
        services.extend(compose_stacks)
        
        return services
    
    def _discover_systemd_services(self, node: Node, connection_method: str) -> List[Service]:
        """Discover systemd services."""
        services = []
        
        try:
            # Get list of active services
            command = "systemctl list-units --type=service --state=running --no-legend"
            result = self._execute_remote_command(node, connection_method, command)
            
            if result.get("success"):
                for line in result["output"].split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 1:
                            service_name = parts[0]
                            
                            service = Service(
                                name=service_name,
                                node_id=node.id,
                                service_type="systemd",
                                status=ServiceStatus.RUNNING,
                                tags=["systemd"]
                            )
                            services.append(service)
        except Exception as e:
            logger.error(f"Failed to discover systemd services on {node.name}: {e}")
        
        return services
    
    def _discover_docker_services(self, node: Node, connection_method: str) -> List[Service]:
        """Discover Docker container services."""
        services = []
        
        try:
            # Get detailed Docker container information
            command = "docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}'"
            result = self._execute_remote_command(node, connection_method, command)
            
            if result.get("success"):
                for line in result["output"].split('\n'):
                    if line.strip():
                        parts = line.split('|')
                        if len(parts) >= 3:
                            container_name = parts[0]
                            image = parts[1]
                            status = parts[2]
                            ports = parts[3] if len(parts) > 3 else ""
                            
                            # Determine service status from container status
                            service_status = ServiceStatus.UNKNOWN
                            if "Up" in status:
                                service_status = ServiceStatus.RUNNING
                            elif "Exited" in status:
                                service_status = ServiceStatus.STOPPED
                            
                            service = Service(
                                name=container_name,
                                node_id=node.id,
                                service_type="docker",
                                status=service_status,
                                version=image.split(':')[-1] if ':' in image else "latest",
                                tags=["docker", image.split('/')[0] if '/' in image else ""]
                            )
                            services.append(service)
        except Exception as e:
            logger.error(f"Failed to discover Docker services on {node.name}: {e}")
        
        return services
    
    def _discover_compose_stacks(self, node: Node, connection_method: str) -> List[Service]:
        """Discover Docker Compose stacks."""
        services = []
        
        try:
            # Look for docker-compose.yml files and check if stacks are running
            command = "find /opt /home /var/lib -name 'docker-compose.yml' -o -name 'compose.yml' 2>/dev/null | head -10"
            result = self._execute_remote_command(node, connection_method, command)
            
            if result.get("success"):
                for compose_file in result["output"].split('\n'):
                    if compose_file.strip():
                        # Get directory name as stack name
                        import os
                        stack_dir = os.path.dirname(compose_file.strip())
                        stack_name = os.path.basename(stack_dir)
                        
                        # Check if stack is running
                        check_command = f"cd {stack_dir} && docker-compose ps --services 2>/dev/null | wc -l"
                        check_result = self._execute_remote_command(node, connection_method, check_command)
                        
                        if check_result.get("success") and check_result["output"].strip().isdigit():
                            service_count = int(check_result["output"].strip())
                            
                            service = Service(
                                name=stack_name,
                                node_id=node.id,
                                service_type="compose_stack",
                                status=ServiceStatus.RUNNING if service_count > 0 else ServiceStatus.STOPPED,
                                tags=["compose", "stack"]
                            )
                            services.append(service)
        except Exception as e:
            logger.error(f"Failed to discover Compose stacks on {node.name}: {e}")
        
        return services
    
    def create_probe_event(self, node: Node, probe_result: Dict[str, Any], 
                         severity: EventSeverity = EventSeverity.INFO) -> Event:
        """Create a probe event."""
        successful_connections = [conn for conn, result in probe_result["connection_tests"].items() 
                                if result.get("success")]
        
        message = f"Probed node {node.name}: {len(successful_connections)} successful connections"
        
        if not successful_connections:
            message = f"Failed to probe node {node.name}: No successful connections"
            severity = EventSeverity.WARNING
        
        return Event(
            event_type=EventType.HEALTH_CHECK,
            severity=severity,
            source="node_probing",
            target_id=node.id,
            target_type="node",
            message=message,
            details={
                "timestamp": probe_result["timestamp"],
                "connection_results": probe_result["connection_tests"],
                "services_discovered": len(probe_result["services"])
            }
        )