"""
Discovery Configuration and Integration for Gateway Fleet Orchestrator.

Provides configuration management and integration with existing systems.
"""

import os
import logging
from typing import Dict, Any, Optional

from src.services.discovery_pipeline import DiscoveryPipeline
from src.services.proxmox_discovery import ProxmoxDiscovery
from src.services.node_probing import NodeProbing
from src.models.fleet_inventory_persistence import FleetInventoryPersistence

logger = logging.getLogger(__name__)


class DiscoveryManager:
    """Manages discovery configuration and integration with existing systems."""
    
    def __init__(self):
        """Initialize discovery manager with configuration from environment."""
        self.config = self._load_config_from_env()
        self.pipeline = DiscoveryPipeline(self.config)
        
    def _load_config_from_env(self) -> Dict[str, Any]:
        """Load discovery configuration from environment variables."""
        config = {
            "discovery_interval": int(os.getenv("SYSTEMMANAGER_DISCOVERY_INTERVAL", "300")),
            "health_check_interval": int(os.getenv("SYSTEMMANAGER_HEALTH_CHECK_INTERVAL", "60")),
            "max_concurrent_probes": int(os.getenv("SYSTEMMANAGER_MAX_CONCURRENT_PROBES", "5")),
            "auto_register": os.getenv("SYSTEMMANAGER_AUTO_REGISTER", "false").lower() == "true",
            "max_fleet_size": int(os.getenv("SYSTEMMANAGER_MAX_FLEET_SIZE", "50")),
        }
        
        # Proxmox API configuration
        proxmox_api_config = {}
        if os.getenv("PROXMOX_HOST"):
            proxmox_api_config = {
                "host": os.getenv("PROXMOX_HOST"),
                "username": os.getenv("PROXMOX_USERNAME", "root@pam"),
                "password": os.getenv("PROXMOX_PASSWORD"),
                "token_name": os.getenv("PROXMOX_TOKEN_NAME"),
                "token_value": os.getenv("PROXMOX_TOKEN_VALUE"),
                "verify_ssl": os.getenv("PROXMOX_VERIFY_SSL", "true").lower() == "true"
            }
        config["proxmox_api"] = proxmox_api_config
        
        # Tailscale configuration
        tailscale_config = {}
        if os.getenv("TAILSCALE_ENABLED", "false").lower() == "true":
            tailscale_config = {
                "enabled": True,
                "tailnet": os.getenv("TAILSCALE_TAILNET"),
                "auth_key": os.getenv("TAILSCALE_AUTH_KEY"),
                "ssh_user": os.getenv("TAILSCALE_SSH_USER", "root")
            }
        config["tailscale"] = tailscale_config
        
        return config
    
    async def run_discovery_if_needed(self) -> bool:
        """Run discovery if it's time to do so."""
        if self.pipeline.should_run_discovery():
            await self.pipeline.run_discovery_cycle()
            return True
        return False
    
    async def force_discovery(self) -> Dict[str, Any]:
        """Force a discovery cycle to run immediately."""
        inventory = await self.pipeline.run_discovery_cycle()
        return {
            "success": True,
            "inventory": inventory.to_dict(),
            "status": self.pipeline.get_discovery_status()
        }
    
    def get_discovery_status(self) -> Dict[str, Any]:
        """Get current discovery status."""
        return self.pipeline.get_discovery_status()
    
    def get_configuration(self) -> Dict[str, Any]:
        """Get current discovery configuration."""
        return {
            "intervals": {
                "discovery": self.config["discovery_interval"],
                "health_check": self.config["health_check_interval"]
            },
            "limits": {
                "max_concurrent_probes": self.config["max_concurrent_probes"],
                "max_fleet_size": self.config["max_fleet_size"]
            },
            "features": {
                "auto_register": self.config["auto_register"],
                "proxmox_api": bool(self.config["proxmox_api"].get("host")),
                "tailscale": self.config["tailscale"].get("enabled", False)
            }
        }
    
    def update_configuration(self, new_config: Dict[str, Any]) -> Dict[str, Any]:
        """Update discovery configuration."""
        # Update intervals
        if "discovery_interval" in new_config:
            self.config["discovery_interval"] = new_config["discovery_interval"]
            self.pipeline.discovery_interval = new_config["discovery_interval"]
        
        if "health_check_interval" in new_config:
            self.config["health_check_interval"] = new_config["health_check_interval"]
            self.pipeline.health_check_interval = new_config["health_check_interval"]
        
        # Update limits
        if "max_concurrent_probes" in new_config:
            self.config["max_concurrent_probes"] = new_config["max_concurrent_probes"]
        
        if "max_fleet_size" in new_config:
            self.config["max_fleet_size"] = new_config["max_fleet_size"]
        
        # Update features
        if "auto_register" in new_config:
            self.config["auto_register"] = new_config["auto_register"]
        
        # Update Proxmox API config
        if "proxmox_api" in new_config:
            self.config["proxmox_api"].update(new_config["proxmox_api"])
            self.pipeline.proxmox_discovery.api_config = self.config["proxmox_api"]
        
        # Update Tailscale config
        if "tailscale" in new_config:
            self.config["tailscale"].update(new_config["tailscale"])
            self.pipeline.node_probing.tailscale_config = self.config["tailscale"]
        
        return self.get_configuration()


def create_default_discovery_config() -> Dict[str, Any]:
    """Create a default discovery configuration template."""
    return {
        "discovery_interval": 300,
        "health_check_interval": 60,
        "max_concurrent_probes": 5,
        "auto_register": False,
        "max_fleet_size": 50,
        "proxmox_api": {
            "host": "",
            "username": "root@pam",
            "password": "",
            "token_name": "",
            "token_value": "",
            "verify_ssl": True
        },
        "tailscale": {
            "enabled": False,
            "tailnet": "",
            "auth_key": "",
            "ssh_user": "root"
        }
    }


def integrate_with_target_registry(discovery_manager: DiscoveryManager, 
                                 target_registry) -> None:
    """Integrate discovery with existing TargetRegistry."""
    # This function would create targets from discovered nodes
    # and register them with the TargetRegistry
    
    def create_targets_from_inventory():
        """Create TargetRegistry targets from discovered inventory."""
        inventory = discovery_manager.pipeline.inventory
        
        for node in inventory.nodes.values():
            # Create target metadata for the node
            target_metadata = _create_target_metadata_from_node(node)
            
            # Register with target registry
            if target_metadata:
                target_registry.add_target(target_metadata)
    
    def _create_target_metadata_from_node(node):
        """Create TargetMetadata from a Node."""
        from src.models.target_registry import TargetMetadata, TargetConnection, ExecutorType
        
        # Determine executor type based on connection method
        if node.connection_method == "tailscale_ssh":
            executor = ExecutorType.SSH
            connection = TargetConnection(
                executor=executor,
                host=node.ip_address,
                username="root",  # Default SSH user
                timeout=30
            )
        elif node.connection_method == "ssh":
            executor = ExecutorType.SSH
            connection = TargetConnection(
                executor=executor,
                host=node.ip_address,
                username="root",
                timeout=30
            )
        else:
            # Skip nodes without SSH connectivity
            return None
        
        return TargetMetadata(
            id=f"discovered-{node.id}",
            type="remote",
            executor=executor,
            connection=connection,
            capabilities=["system:read", "network:read", "container:read"],
            metadata={
                "hostname": node.name,
                "node_type": node.node_type.value,
                "runtime": node.runtime.value,
                "discovery_source": "fleet_inventory",
                "tags": node.tags + ["discovered"]
            }
        )
    
    # Register the integration function
    target_registry.register_discovery_hook(create_targets_from_inventory)


def get_discovery_tools() -> Dict[str, Any]:
    """Get discovery tools for integration with MCP server."""
    discovery_manager = DiscoveryManager()
    
    async def run_discovery() -> Dict[str, Any]:
        """Run discovery and return results."""
        result = await discovery_manager.force_discovery()
        return result
    
    async def get_status() -> Dict[str, Any]:
        """Get discovery status."""
        return discovery_manager.get_discovery_status()
    
    async def get_config() -> Dict[str, Any]:
        """Get discovery configuration."""
        return discovery_manager.get_configuration()
    
    async def update_config(new_config: Dict[str, Any]) -> Dict[str, Any]:
        """Update discovery configuration."""
        return discovery_manager.update_configuration(new_config)
    
    return {
        "run_discovery": run_discovery,
        "get_discovery_status": get_status,
        "get_discovery_config": get_config,
        "update_discovery_config": update_config
    }