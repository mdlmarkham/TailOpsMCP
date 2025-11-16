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
    
    async def pull_image(self, image_name: str, tag: str = "latest") -> Dict:
        """Pull a Docker image from registry.
        
        Args:
            image_name: Name of the image (e.g., 'nginx', 'mysql')
            tag: Image tag (default: 'latest')
        """
        if not self.client:
            return {"success": False, "error": "Docker client not available"}
        
        try:
            full_image = f"{image_name}:{tag}"
            image = self.client.images.pull(image_name, tag=tag)
            
            return {
                "success": True,
                "image": full_image,
                "image_id": image.id[:12],
                "tags": image.tags,
                "size": image.attrs.get('Size', 0)
            }
            
        except docker.errors.APIError as e:
            return {"success": False, "error": f"Docker API error: {str(e)}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def update_container(self, container_id: str, pull_latest: bool = True) -> Dict:
        """Update a container by pulling latest image and recreating.
        
        Args:
            container_id: Container name or ID
            pull_latest: Whether to pull latest image before recreating (default: True)
        """
        if not self.client:
            return {"success": False, "error": "Docker client not available"}
        
        try:
            # Get container
            container = self.client.containers.get(container_id)
            
            # Save container configuration
            config = container.attrs
            image_name = config['Config']['Image']
            
            # Extract image name and tag
            if ':' in image_name:
                image, tag = image_name.rsplit(':', 1)
            else:
                image = image_name
                tag = 'latest'
            
            old_image_id = container.image.id[:12]
            
            # Pull latest image if requested
            if pull_latest:
                pull_result = await self.pull_image(image, tag)
                if not pull_result.get('success'):
                    return pull_result
                new_image_id = pull_result['image_id']
            else:
                new_image_id = old_image_id
            
            # Check if image actually changed
            if old_image_id == new_image_id:
                return {
                    "success": True,
                    "message": "Container already using latest image",
                    "container": container_id,
                    "image": image_name,
                    "image_id": old_image_id,
                    "updated": False
                }
            
            # Save important config details
            container_name = container.name
            env_vars = config['Config'].get('Env', [])
            volumes = config['HostConfig'].get('Binds', [])
            port_bindings = config['HostConfig'].get('PortBindings', {})
            network_mode = config['HostConfig'].get('NetworkMode', 'default')
            restart_policy = config['HostConfig'].get('RestartPolicy', {})
            
            # Stop and remove old container
            container.stop(timeout=10)
            container.remove()
            
            # Create new container with same config
            # Note: host network mode is incompatible with port bindings
            run_kwargs = {
                "image": f"{image}:{tag}",
                "name": container_name,
                "environment": env_vars,
                "volumes": volumes,
                "network_mode": network_mode,
                "restart_policy": restart_policy,
                "detach": True
            }
            
            # Only add ports if not using host network
            if network_mode != 'host':
                run_kwargs['ports'] = port_bindings
            
            new_container = self.client.containers.run(**run_kwargs)
            
            return {
                "success": True,
                "message": "Container updated successfully",
                "container": container_id,
                "new_container_id": new_container.id[:12],
                "image": image_name,
                "old_image_id": old_image_id,
                "new_image_id": new_image_id,
                "updated": True
            }
            
        except docker.errors.NotFound:
            return {"success": False, "error": f"Container not found: {container_id}"}
        except docker.errors.APIError as e:
            return {"success": False, "error": f"Docker API error: {str(e)}"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def list_images(self) -> Dict:
        """List all Docker images."""
        if not self.client:
            return {"success": False, "error": "Docker client not available"}
        
        try:
            images = self.client.images.list()
            image_list = []
            
            for image in images:
                image_list.append({
                    "id": image.id[:12],
                    "tags": image.tags,
                    "size": image.attrs.get('Size', 0),
                    "created": image.attrs.get('Created', '')
                })
            
            return {"success": True, "data": image_list, "count": len(image_list)}
            
        except Exception as e:
            return {"success": False, "error": str(e)}