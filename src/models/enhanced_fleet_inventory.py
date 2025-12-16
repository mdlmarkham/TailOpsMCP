"""
Enhanced Fleet Inventory Models.

This module extends the base fleet inventory with enhanced capabilities.
"""

from typing import Dict, List, Any
from dataclasses import dataclass, field

from src.models.fleet_inventory import FleetInventory, ProxmoxHost, Node, Service


@dataclass
class EnhancedProxmoxHost(ProxmoxHost):
    """Enhanced Proxmox host with additional features."""

    enhanced_monitoring: bool = True
    custom_tags: List[str] = field(default_factory=list)
    performance_metrics: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EnhancedNode(Node):
    """Enhanced node with additional capabilities."""

    enhanced_features: bool = True
    custom_attributes: Dict[str, Any] = field(default_factory=dict)
    monitoring_enabled: bool = True


@dataclass
class EnhancedService(Service):
    """Enhanced service with additional features."""

    enhanced_monitoring: bool = True
    custom_metrics: Dict[str, Any] = field(default_factory=dict)
    health_checks_enabled: bool = True


@dataclass
class EnhancedFleetInventory(FleetInventory):
    """Enhanced fleet inventory with additional capabilities."""

    enhanced_features: bool = True
    custom_configuration: Dict[str, Any] = field(default_factory=dict)
    monitoring_integration: bool = True

    def add_enhanced_host(self, host: EnhancedProxmoxHost) -> None:
        """Add an enhanced host to the inventory."""
        # Convert to base type and add
        super().add_host(host)

    def get_enhanced_hosts(self) -> List[EnhancedProxmoxHost]:
        """Get all enhanced hosts."""
        hosts = self.get_hosts()
        return [EnhancedProxmoxHost(**host.__dict__) for host in hosts]


# Convenience function
def create_enhanced_fleet_inventory() -> EnhancedFleetInventory:
    """Create an enhanced fleet inventory instance."""
    return EnhancedFleetInventory()
