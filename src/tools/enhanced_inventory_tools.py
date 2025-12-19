"""
Enhanced inventory tools for TailOpsMCP.

This module provides enhanced inventory management tools that wrap the core
inventory service functionality for easier integration with other system components.
"""

import logging
from typing import Any, Dict
from datetime import datetime

from src.server.dependencies import deps
from src.models.enhanced_fleet_inventory import EnhancedFleetInventory
from src.utils.errors import SystemManagerError, ErrorCategory

logger = logging.getLogger(__name__)


class EnhancedInventoryTools:
    """Enhanced inventory tools for fleet management and monitoring."""

    def __init__(self) -> None:
        """Initialize enhanced inventory tools."""
        self.inventory_service = deps.inventory_service

    async def get_fleet_status(self) -> Dict[str, Any]:
        """Get current fleet status and health information.

        Returns:
            Dictionary containing fleet status, health metrics, and inventory summary
        """
        try:
            if not self.inventory_service:
                raise SystemManagerError(
                    "Inventory service not available",
                    ErrorCategory.SYSTEM,
                    details={"service": "inventory_service"},
                )

            # Get current inventory
            inventory = self.inventory_service.current_inventory

            if not inventory:
                return {
                    "status": "no_data",
                    "timestamp": datetime.now().isoformat(),
                    "total_targets": 0,
                    "total_services": 0,
                    "healthy_targets": 0,
                    "unhealthy_targets": 0,
                }

            # Calculate health metrics
            healthy_targets = sum(
                1
                for target in inventory.targets.values()
                if target.health_status == "healthy"
            )
            unhealthy_targets = sum(
                1
                for target in inventory.targets.values()
                if target.health_status != "healthy"
            )

            return {
                "status": "ok",
                "timestamp": datetime.now().isoformat(),
                "total_targets": len(inventory.targets),
                "total_services": len(inventory.services),
                "healthy_targets": healthy_targets,
                "unhealthy_targets": unhealthy_targets,
                "inventory_type": "enhanced"
                if isinstance(inventory, EnhancedFleetInventory)
                else "basic",
                "last_updated": getattr(inventory, "last_updated", None),
            }

        except Exception as e:
            logger.error(f"Error getting fleet status: {e}")
            raise SystemManagerError(
                f"Failed to get fleet status: {e}",
                ErrorCategory.SYSTEM,
                details={"error": str(e)},
            )

    async def get_inventory_summary(self) -> Dict[str, Any]:
        """Get summary of the current inventory.

        Returns:
            Dictionary containing inventory summary information
        """
        try:
            inventory = self.inventory_service.current_inventory

            if not inventory:
                return {
                    "status": "no_inventory",
                    "timestamp": datetime.now().isoformat(),
                }

            return {
                "status": "ok",
                "timestamp": datetime.now().isoformat(),
                "total_targets": len(inventory.targets),
                "total_services": len(inventory.services),
                "total_containers": len(inventory.containers)
                if hasattr(inventory, "containers")
                else 0,
                "total_vms": len(inventory.vms) if hasattr(inventory, "vms") else 0,
                "total_hosts": len(inventory.hosts)
                if hasattr(inventory, "hosts")
                else 0,
                "inventory_type": "enhanced"
                if isinstance(inventory, EnhancedFleetInventory)
                else "basic",
                "last_discovery": getattr(inventory, "last_discovery", None),
                "last_updated": getattr(inventory, "last_updated", None),
            }

        except Exception as e:
            logger.error(f"Error getting inventory summary: {e}")
            raise SystemManagerError(
                f"Failed to get inventory summary: {e}",
                ErrorCategory.SYSTEM,
                details={"error": str(e)},
            )

    async def get_target_health(self, target_id: str) -> Dict[str, Any]:
        """Get health status for a specific target.

        Args:
            target_id: ID of the target to check

        Returns:
            Dictionary containing target health information
        """
        try:
            inventory = self.inventory_service.current_inventory

            if not inventory or target_id not in inventory.targets:
                return {
                    "status": "not_found",
                    "target_id": target_id,
                    "timestamp": datetime.now().isoformat(),
                }

            target = inventory.targets[target_id]

            return {
                "status": "ok",
                "target_id": target_id,
                "health_status": target.health_status,
                "health_details": getattr(target, "health_details", {}),
                "last_checked": getattr(target, "last_health_check", None),
                "resource_usage": getattr(target, "resource_usage", {}),
                "security_posture": getattr(target, "security_posture", {}),
                "timestamp": datetime.now().isoformat(),
            }

        except Exception as e:
            logger.error(f"Error getting target health for {target_id}: {e}")
            raise SystemManagerError(
                f"Failed to get target health for {target_id}: {e}",
                ErrorCategory.SYSTEM,
                details={"target_id": target_id, "error": str(e)},
            )

    async def trigger_inventory_update(self) -> Dict[str, Any]:
        """Trigger a manual inventory update.

        Returns:
            Dictionary containing update status and results
        """
        try:
            if not self.inventory_service:
                raise SystemManagerError(
                    "Inventory service not available",
                    ErrorCategory.SYSTEM,
                    details={"service": "inventory_service"},
                )

            # Trigger discovery
            result = await self.inventory_service.discover_inventory()

            return {
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "discovered_targets": len(result.targets),
                "discovered_services": len(result.services),
                "inventory_type": "enhanced"
                if isinstance(result, EnhancedFleetInventory)
                else "basic",
            }

        except Exception as e:
            logger.error(f"Error triggering inventory update: {e}")
            raise SystemManagerError(
                f"Failed to trigger inventory update: {e}",
                ErrorCategory.SYSTEM,
                details={"error": str(e)},
            )
