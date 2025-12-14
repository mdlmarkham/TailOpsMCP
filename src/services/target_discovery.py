"""
Dynamic discovery mechanisms for SSH and Docker targets.
"""

import logging
import socket
import subprocess
from typing import List, Dict, Any
from ipaddress import ip_network, IPv4Address

from src.models.target_registry import TargetMetadata, TargetConnection, TargetConstraints, ExecutorType, SudoPolicy

logger = logging.getLogger(__name__)


class TargetDiscovery:
    """Dynamic discovery of SSH and Docker targets."""
    
    def __init__(self, network_ranges: List[str] = None, ssh_ports: List[int] = None):
        """Initialize target discovery.
        
        Args:
            network_ranges: List of CIDR ranges to scan (e.g., ["192.168.1.0/24"])
            ssh_ports: List of SSH ports to check (default: [22, 2222])
        """
        self.network_ranges = network_ranges or ["192.168.1.0/24", "10.0.0.0/8"]
        self.ssh_ports = ssh_ports or [22, 2222]
    
    def discover_ssh_targets(self, username: str = "root", key_path: str = None) -> List[TargetMetadata]:
        """Discover SSH targets by scanning network ranges.
        
        Args:
            username: SSH username to test
            key_path: SSH key path for testing connections
            
        Returns:
            List of discovered SSH targets
        """
        discovered = []
        
        for network_range in self.network_ranges:
            try:
                network = ip_network(network_range, strict=False)
                
                # Scan hosts in the network range
                for host in network.hosts():
                    host_ip = str(host)
                    
                    # Check if SSH port is open
                    for port in self.ssh_ports:
                        if self._check_port_open(host_ip, port):
                            logger.info(f"Found SSH service at {host_ip}:{port}")
                            
                            # Create target metadata
                            connection = TargetConnection(
                                executor=ExecutorType.SSH,
                                host=host_ip,
                                port=port,
                                username=username,
                                key_path=key_path or "${SSH_DISCOVERY_KEY}",
                                timeout=30
                            )
                            
                            constraints = TargetConstraints(
                                timeout=60,
                                concurrency=2,
                                sudo_policy=SudoPolicy.LIMITED
                            )
                            
                            target = TargetMetadata(
                                id=f"ssh-{host_ip.replace('.', '-')}-{port}",
                                type="remote",
                                executor=ExecutorType.SSH,
                                connection=connection,
                                capabilities=["system:read", "network:read", "container:read"],
                                constraints=constraints,
                                metadata={
                                    "hostname": f"discovered-{host_ip}",
                                    "platform": "unknown",
                                    "tags": ["discovered", "ssh"],
                                    "discovery_method": "network_scan"
                                }
                            )
                            
                            discovered.append(target)
                            break  # Found SSH, move to next host
                            
            except Exception as e:
                logger.error(f"Failed to scan network range {network_range}: {str(e)}")
        
        return discovered
    
    def discover_docker_targets(self) -> List[TargetMetadata]:
        """Discover Docker targets by checking common Docker endpoints.
        
        Returns:
            List of discovered Docker targets
        """
        discovered = []
        
        # Common Docker endpoints to check
        docker_endpoints = [
            ("localhost", 2375),  # Docker TCP (unencrypted)
            ("localhost", 2376),  # Docker TCP (TLS)
            # Add more endpoints as needed
        ]
        
        for host, port in docker_endpoints:
            if self._check_port_open(host, port):
                logger.info(f"Found Docker service at {host}:{port}")
                
                connection = TargetConnection(
                    executor=ExecutorType.DOCKER,
                    host=f"tcp://{host}:{port}",
                    timeout=30
                )
                
                constraints = TargetConstraints(
                    timeout=120,
                    concurrency=3,
                    sudo_policy=SudoPolicy.NONE
                )
                
                target = TargetMetadata(
                    id=f"docker-{host.replace('.', '-')}-{port}",
                    type="remote",
                    executor=ExecutorType.DOCKER,
                    connection=connection,
                    capabilities=["container:read", "container:write"],
                    constraints=constraints,
                    metadata={
                        "hostname": f"docker-{host}",
                        "platform": "docker-host",
                        "tags": ["discovered", "docker"],
                        "discovery_method": "port_scan"
                    }
                )
                
                discovered.append(target)
        
        return discovered
    
    def _check_port_open(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """Check if a TCP port is open.
        
        Args:
            host: Hostname or IP address
            port: Port number
            timeout: Connection timeout in seconds
            
        Returns:
            True if port is open, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def discover_all_targets(self, ssh_username: str = "root", ssh_key_path: str = None) -> List[TargetMetadata]:
        """Discover all types of targets.
        
        Args:
            ssh_username: SSH username for discovery
            ssh_key_path: SSH key path for discovery
            
        Returns:
            List of all discovered targets
        """
        discovered = []
        
        # Discover SSH targets
        ssh_targets = self.discover_ssh_targets(ssh_username, ssh_key_path)
        discovered.extend(ssh_targets)
        
        # Discover Docker targets
        docker_targets = self.discover_docker_targets()
        discovered.extend(docker_targets)
        
        logger.info(f"Discovered {len(discovered)} targets total")
        return discovered
    
    def test_ssh_connection(self, target: TargetMetadata) -> bool:
        """Test SSH connection to a discovered target.
        
        Args:
            target: Target to test
            
        Returns:
            True if connection successful, False otherwise
        """
        if target.executor != ExecutorType.SSH:
            return False
        
        try:
            # Use a simple SSH command to test connection
            import paramiko
            
            client = paramiko.SSHClient()
            
            # Load system host keys for verification
            client.load_system_host_keys()
            
            # Set missing host key policy to reject unknown hosts
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            
            # Resolve key path from environment variable if needed
            key_path = target.connection.key_path
            if key_path.startswith("$"):
                env_var = key_path[1:]
                key_path = os.getenv(env_var)
                if not key_path:
                    logger.error(f"Environment variable not found: {env_var}")
                    return False
            
            key = paramiko.RSAKey.from_private_key_file(key_path)
            
            client.connect(
                hostname=target.connection.host,
                port=target.connection.port,
                username=target.connection.username,
                pkey=key,
                timeout=target.connection.timeout
            )
            
            client.close()
            return True
            
        except Exception as e:
            logger.debug(f"SSH connection test failed for {target.id}: {str(e)}")
            return False
    
    def test_docker_connection(self, target: TargetMetadata) -> bool:
        """Test Docker connection to a discovered target.
        
        Args:
            target: Target to test
            
        Returns:
            True if connection successful, False otherwise
        """
        if target.executor != ExecutorType.DOCKER:
            return False
        
        try:
            import docker
            
            if target.connection.socket_path:
                client = docker.DockerClient(base_url=f"unix://{target.connection.socket_path}")
            else:
                client = docker.DockerClient(base_url=target.connection.host)
            
            client.ping()
            client.close()
            return True
            
        except Exception as e:
            logger.debug(f"Docker connection test failed for {target.id}: {str(e)}")
            return False