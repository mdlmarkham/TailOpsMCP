"""
Docker management service for SystemManager MCP Server
"""

import docker
from typing import Dict, List, Optional


class DockerManager:
    """Service for managing Docker containers."""
    
    def __init__(self):
        self.client = None
        try:
            self.client = docker.from_env()
        except Exception as e:
            # Docker might not be available
            pass
    
    async def list_containers(self, show_all: bool = False) -> Dict:
        """List Docker containers."""
        if not self.client:
            return {"success": False, "error": "Docker client not available"}
        
        try:
            containers = self.client.containers.list(all=show_all)
            container_list = []
            
            for container in containers:
                container_info = {
                    "id": container.id[:12],
                    "name": container.name,
                    "status": container.status,
                    "image": container.image.tags[0] if container.image.tags else "",
                    "created": container.attrs["Created"],
                    "ports": container.attrs["HostConfig"].get("PortBindings", {}),
                }
                container_list.append(container_info)
            
            return {"success": True, "data": container_list}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def get_container_info(self, container_id: str) -> Dict:
        """Get detailed information about a container."""
        if not self.client:
            return {"success": False, "error": "Docker client not available"}
        
        try:
            container = self.client.containers.get(container_id)
            
            info = {
                "id": container.id,
                "name": container.name,
                "status": container.status,
                "image": container.image.tags[0] if container.image.tags else "",
                "created": container.attrs["Created"],
                "started": container.attrs["State"]["StartedAt"],
                "finished": container.attrs["State"]["FinishedAt"],
                "ports": container.attrs["HostConfig"].get("PortBindings", {}),
                "environment": container.attrs["Config"].get("Env", []),
                "labels": container.attrs["Config"].get("Labels", {}),
                "volumes": container.attrs["HostConfig"].get("Binds", []),
                "network": container.attrs["NetworkSettings"]["Networks"],
            }
            
            return {"success": True, "data": info}
            
        except docker.errors.NotFound:
            return {"success": False, "error": f"Container not found: {container_id}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def start_container(self, container_id: str) -> Dict:
        """Start a Docker container."""
        if not self.client:
            return {"success": False, "error": "Docker client not available"}
        
        try:
            container = self.client.containers.get(container_id)
            container.start()
            return {"success": True, "message": f"Container {container_id} started"}
            
        except docker.errors.NotFound:
            return {"success": False, "error": f"Container not found: {container_id}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def stop_container(self, container_id: str) -> Dict:
        """Stop a Docker container."""
        if not self.client:
            return {"success": False, "error": "Docker client not available"}
        
        try:
            container = self.client.containers.get(container_id)
            container.stop()
            return {"success": True, "message": f"Container {container_id} stopped"}
            
        except docker.errors.NotFound:
            return {"success": False, "error": f"Container not found: {container_id}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def restart_container(self, container_id: str) -> Dict:
        """Restart a Docker container."""
        if not self.client:
            return {"success": False, "error": "Docker client not available"}
        
        try:
            container = self.client.containers.get(container_id)
            container.restart()
            return {"success": True, "message": f"Container {container_id} restarted"}
            
        except docker.errors.NotFound:
            return {"success": False, "error": f"Container not found: {container_id}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def get_container_logs(self, container_id: str, tail: int = 100) -> Dict:
        """Get container logs."""
        if not self.client:
            return {"success": False, "error": "Docker client not available"}
        
        try:
            container = self.client.containers.get(container_id)
            logs = container.logs(tail=tail).decode('utf-8')
            return {"success": True, "data": logs}
            
        except docker.errors.NotFound:
            return {"success": False, "error": f"Container not found: {container_id}"}
        except Exception as e:
            return {"success": False, "error": str(e)}