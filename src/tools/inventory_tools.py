"""Application inventory and system identity tools for TailOpsMCP."""
import logging
from typing import Literal, Optional
from datetime import datetime
from fastmcp import FastMCP
from src.auth.middleware import secure_tool
from src.server.dependencies import deps
from src.server.utils import format_error
from src.inventory import ApplicationMetadata, SystemIdentity

logger = logging.getLogger(__name__)

def register_tools(mcp: FastMCP):
    """Register inventory management tools with MCP instance."""

    @mcp.tool()
    @secure_tool("scan_installed_applications")
    async def scan_installed_applications(save_to_inventory: bool = True) -> dict:
        """Scan the system for installed applications (Jellyfin, Pi-hole, Ollama, PostgreSQL, etc.).

        This auto-detects common home lab applications running directly on the LXC container,
        not just Docker containers. Useful for initial system discovery.

        Args:
            save_to_inventory: If True, automatically save detected apps to inventory

        Returns:
            Dictionary with detected applications and their metadata
        """
        try:
            detected = deps.app_scanner.scan()

            result = {
                "scanned_at": datetime.now().isoformat(),
                "system": deps.system_identity.get_display_name() if deps.system_identity else "unknown",
                "detected_count": len(detected),
                "applications": []
            }

            for app in detected:
                app_data = {
                    "name": app.name,
                    "type": app.type,
                    "version": app.version,
                    "port": app.port,
                    "service_name": app.service_name,
                    "config_path": app.config_path,
                    "data_path": app.data_path,
                    "confidence": app.confidence
                }
                result["applications"].append(app_data)

                # Save to inventory if requested
                if save_to_inventory:
                    app_meta = ApplicationMetadata(
                        name=app.name,
                        type=app.type,
                        version=app.version,
                        port=app.port,
                        service_name=app.service_name,
                        config_path=app.config_path,
                        data_path=app.data_path,
                        auto_detected=True
                    )
                    deps.inventory.add_application(app.name, app_meta)

            if save_to_inventory and detected:
                result["saved_to_inventory"] = True
                logger.info(f"Saved {len(detected)} detected applications to inventory")

            return result
        except Exception as e:
            return format_error(e, "scan_installed_applications")

    @mcp.tool()
    @secure_tool("get_inventory")
    async def get_inventory() -> dict:
        """Get the complete system inventory including identity, applications, and stacks.

        Returns:
            Complete inventory with system identity, applications, and Docker stacks
        """
        try:
            system = deps.inventory.get_system_identity()
            apps = deps.inventory.list_applications()
            stacks = deps.inventory.list_stacks()

            return {
                "system": {
                    "hostname": system.hostname if system else "unknown",
                    "container_id": system.container_id if system else None,
                    "container_type": system.container_type if system else None,
                    "display_name": system.get_display_name() if system else "unknown",
                    "mcp_server_name": system.mcp_server_name if system else None
                } if system else None,
                "applications": apps,
                "stacks": stacks,
                "inventory_path": deps.inventory.path,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return format_error(e, "get_inventory")

    @mcp.tool()
    @secure_tool("add_application_to_inventory")
    async def manage_inventory(
        action: Literal["add", "remove"],
        name: str,
        app_type: str = None,
        version: Optional[str] = None,
        port: Optional[int] = None,
        service_name: Optional[str] = None,
        config_path: Optional[str] = None,
        data_path: Optional[str] = None,
        notes: Optional[str] = None
    ) -> dict:
        """Add or remove applications from the inventory.

        Args:
            action: Operation to perform (add|remove)
            name: Application name (e.g., "jellyfin", "pihole")
            app_type: Type/category (required for add: "media-server", "dns", "database")
            version: Application version (optional, for add)
            port: Primary port number (optional, for add)
            service_name: systemd service name (optional, for add)
            config_path: Configuration directory (optional, for add)
            data_path: Data directory (optional, for add)
            notes: Custom notes (optional, for add)
        """
        try:
            if action == "add":
                if not app_type:
                    return {"error": "app_type required for add action"}

                app_meta = ApplicationMetadata(
                    name=name,
                    type=app_type,
                    version=version,
                    port=port,
                    service_name=service_name,
                    config_path=config_path,
                    data_path=data_path,
                    auto_detected=False,
                    notes=notes
                )

                deps.inventory.add_application(name, app_meta)

                return {
                    "success": True,
                    "action": "added",
                    "application": name,
                    "details": {
                        "name": name,
                        "type": app_type,
                        "version": version,
                        "port": port,
                        "service_name": service_name,
                        "config_path": config_path,
                        "data_path": data_path,
                        "notes": notes
                    },
                    "timestamp": datetime.now().isoformat()
                }

            elif action == "remove":
                app = deps.inventory.get_application(name)
                if not app:
                    return {
                        "success": False,
                        "error": f"Application '{name}' not found in inventory"
                    }

                deps.inventory.remove_application(name)

                return {
                    "success": True,
                    "action": "removed",
                    "application": name,
                    "timestamp": datetime.now().isoformat()
                }

            else:
                return {"error": f"Invalid action: {action}"}

        except Exception as e:
            return format_error(e, "manage_inventory")

    @mcp.tool()
    @secure_tool("set_system_identity")
    async def set_system_identity(
        hostname: Optional[str] = None,
        container_id: Optional[str] = None,
        container_type: Optional[str] = None,
        mcp_server_name: Optional[str] = None
    ) -> dict:
        """Set or update the system identity for this MCP server instance.

        This is useful when managing multiple systems with a single LLM, as each
        system can have a unique identifier (hostname + container ID).

        Args:
            hostname: System hostname (auto-detected if not provided)
            container_id: Proxmox VMID/CTID (e.g., "103")
            container_type: "lxc", "vm", or "bare-metal"
            mcp_server_name: Custom name for this MCP server instance

        Returns:
            Updated system identity
        """
        try:
            import socket

            # Use current identity as base if it exists
            current = deps.inventory.get_system_identity()

            new_identity = SystemIdentity(
                hostname=hostname or (current.hostname if current else socket.gethostname()),
                container_id=container_id or (current.container_id if current else None),
                container_type=container_type or (current.container_type if current else None),
                mcp_server_name=mcp_server_name or (current.mcp_server_name if current else None)
            )

            deps.inventory.set_system_identity(new_identity)

            # Update global reference
            deps.system_identity = new_identity

            logger.info(f"Updated system identity: {new_identity.get_display_name()}")

            return {
                "success": True,
                "action": "updated",
                "system_identity": {
                    "hostname": new_identity.hostname,
                    "container_id": new_identity.container_id,
                    "container_type": new_identity.container_type,
                    "display_name": new_identity.get_display_name(),
                    "mcp_server_name": new_identity.mcp_server_name
                },
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return format_error(e, "set_system_identity")

    logger.info("Registered 4 inventory management tools")
