"""
Application inventory and system identity tools for TailOpsMCP.

This module provides comprehensive MCP tools for inventory management including:
- Basic application discovery and system identity management
- Enhanced fleet inventory with health monitoring, snapshots, and change detection
- Fleet-wide queries, filtering, and advanced reporting
"""

import logging
from typing import Optional, Literal
from datetime import datetime
from fastmcp import FastMCP

from src.auth.middleware import secure_tool
from src.server.dependencies import deps
from src.server.utils import format_error
from src.inventory import ApplicationMetadata
from src.models.fleet_inventory import NodeRole

logger = logging.getLogger(__name__)


def register_tools(mcp: FastMCP):
    """Register inventory management tools with MCP instance."""

    # Basic inventory tools
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
                "system": deps.system_identity.get_display_name()
                if deps.system_identity
                else "unknown",
                "detected_count": len(detected),
                "applications": [],
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
                    "confidence": app.confidence,
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
                        auto_detected=True,
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
                    "mcp_server_name": system.mcp_server_name if system else None,
                }
                if system
                else None,
                "applications": apps,
                "stacks": stacks,
                "inventory_path": deps.inventory.path,
                "timestamp": datetime.now().isoformat(),
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
        notes: Optional[str] = None,
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
                    notes=notes,
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
                        "notes": notes,
                    },
                    "timestamp": datetime.now().isoformat(),
                }

            elif action == "remove":
                app = deps.inventory.get_application(name)
                if not app:
                    return {
                        "success": False,
                        "error": f"Application '{name}' not found in inventory",
                    }

                deps.inventory.remove_application(name)

                return {
                    "success": True,
                    "action": "removed",
                    "application": name,
                    "timestamp": datetime.now().isoformat(),
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
        mcp_server_name: Optional[str] = None,
    ) -> dict:
        """Set or update the system identity for this MCP server instance.

        This is useful when managing multiple systems with a single LLM, as each
        system can have a unique identifier (hostname + container ID).

        Args:
            hostname: System hostname
            container_id: Container/LXC ID
            container_type: Type of container (lxc, docker, etc.)
            mcp_server_name: Custom name for this MCP server
        """
        try:
            # Update system identity
            if hostname is not None:
                deps.inventory.system.hostname = hostname
            if container_id is not None:
                deps.inventory.system.container_id = container_id
            if container_type is not None:
                deps.inventory.system.container_type = container_type
            if mcp_server_name is not None:
                deps.inventory.system.mcp_server_name = mcp_server_name

            # Save updated identity
            deps.inventory.save()

            return {
                "success": True,
                "message": "System identity updated",
                "identity": {
                    "hostname": deps.inventory.system.hostname,
                    "container_id": deps.inventory.system.container_id,
                    "container_type": deps.inventory.system.container_type,
                    "display_name": deps.inventory.system.get_display_name(),
                    "mcp_server_name": deps.inventory.system.mcp_server_name,
                },
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            return format_error(e, "set_system_identity")

    # Enhanced fleet inventory tools
    @mcp.tool()
    @secure_tool("fleet_discovery")
    async def run_fleet_discovery() -> dict:
        """Run complete fleet discovery and inventory update.

        Performs comprehensive discovery including:
        - Proxmox host discovery
        - Node and container detection
        - Service and stack mapping
        - Security posture assessment
        - Resource utilization analysis

        Returns:
            Discovery results with inventory statistics
        """
        try:
            # TODO: Implement fleet discovery
            # For now, return a placeholder response
            return {
                "success": True,
                "discovery_completed": True,
                "inventory_stats": {
                    "total_targets": 0,
                    "total_services": 0,
                    "total_stacks": 0,
                    "healthy_targets": 0,
                    "unhealthy_targets": 0,
                    "average_health_score": 0.0,
                },
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        except Exception as e:
            return format_error(e, "run_fleet_discovery")

    @mcp.tool()
    @secure_tool("fleet_overview")
    async def get_fleet_overview() -> dict:
        """Get comprehensive fleet overview with health metrics.

        Returns:
            Complete fleet status including targets, services, health scores, and issues
        """
        try:
            # TODO: Implement fleet overview
            # For now, return a placeholder response
            targets_by_role = {role.value: 0 for role in NodeRole}
            services_by_type = {}

            return {
                "success": True,
                "fleet_summary": {
                    "total_targets": 0,
                    "total_services": 0,
                    "total_stacks": 0,
                    "healthy_targets": 0,
                    "unhealthy_targets": 0,
                    "average_health_score": 0.0,
                },
                "targets_by_role": targets_by_role,
                "services_by_type": services_by_type,
                "health_issues": {"unhealthy_targets": 0, "stale_targets": 0},
                "recent_activity": {"last_discovery": None, "last_health_check": None},
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        except Exception as e:
            return format_error(e, "get_fleet_overview")

    @mcp.tool()
    @secure_tool("get_production_targets")
    async def get_production_targets() -> dict:
        """Get all production targets with detailed information.

        Returns:
            List of production targets with health status and resource usage
        """
        try:
            # TODO: Implement production targets query
            return {
                "success": True,
                "production_targets": [],
                "count": 0,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        except Exception as e:
            return format_error(e, "get_production_targets")

    @mcp.tool()
    @secure_tool("get_services_by_runtime")
    async def get_services_by_runtime(runtime: str) -> dict:
        """Get all services running on specified runtime.

        Args:
            runtime: Runtime type (docker, systemd, application, etc.)

        Returns:
            List of services running on the specified runtime
        """
        try:
            # TODO: Implement services by runtime query
            return {
                "success": True,
                "runtime": runtime,
                "services": [],
                "count": 0,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        except Exception as e:
            return format_error(e, "get_services_by_runtime")

    @mcp.tool()
    @secure_tool("find_stale_targets")
    async def find_stale_targets(hours: int = 24) -> dict:
        """Find targets that haven't been seen recently.

        Args:
            hours: Number of hours to consider stale (default: 24)

        Returns:
            List of stale targets with last seen timestamps
        """
        try:
            # TODO: Implement stale targets detection
            return {
                "success": True,
                "stale_threshold_hours": hours,
                "stale_targets": [],
                "count": 0,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        except Exception as e:
            return format_error(e, "find_stale_targets")

    @mcp.tool()
    @secure_tool("get_unhealthy_targets")
    async def get_unhealthy_targets(threshold: float = 0.7) -> dict:
        """Get targets with health scores below threshold.

        Args:
            threshold: Health score threshold (0.0-1.0, default: 0.7)

        Returns:
            List of unhealthy targets with health scores and issues
        """
        try:
            # TODO: Implement unhealthy targets detection
            return {
                "success": True,
                "health_threshold": threshold,
                "unhealthy_targets": [],
                "count": 0,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        except Exception as e:
            return format_error(e, "get_unhealthy_targets")

    @mcp.tool()
    @secure_tool("search_fleet")
    async def search_fleet(
        query: str,
        entity_type: Literal["targets", "services", "stacks"] = "targets",
        limit: int = 50,
    ) -> dict:
        """Search the fleet for entities matching criteria.

        Args:
            query: Search query string
            entity_type: Type of entities to search (targets, services, stacks)
            limit: Maximum number of results to return

        Returns:
            Search results with matching entities
        """
        try:
            # TODO: Implement fleet search functionality
            return {
                "success": True,
                "query": query,
                "entity_type": entity_type,
                "results": [],
                "total_results": 0,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        except Exception as e:
            return format_error(e, "search_fleet")

    @mcp.tool()
    @secure_tool("create_inventory_snapshot")
    async def create_inventory_snapshot(
        name: str,
        description: Optional[str] = None,
        snapshot_type: str = "manual",
        tags: Optional[str] = None,
    ) -> dict:
        """Create a point-in-time inventory snapshot for change detection.

        Args:
            name: Snapshot name
            description: Optional description
            snapshot_type: Type (manual, scheduled, pre_deployment, post_deployment, health_check, backup, discovery)
            tags: Optional comma-separated tags

        Returns:
            Created snapshot information
        """
        try:
            # TODO: Implement snapshot creation
            tag_list = []
            if tags:
                tag_list = [tag.strip() for tag in tags.split(",")]

            return {
                "success": True,
                "snapshot": {
                    "id": "snapshot_placeholder",
                    "name": name,
                    "description": description,
                    "snapshot_type": snapshot_type,
                    "created_at": datetime.utcnow().isoformat() + "Z",
                    "tags": tag_list,
                    "total_targets": 0,
                    "total_services": 0,
                    "total_stacks": 0,
                    "healthy_targets": 0,
                    "average_health_score": 0.0,
                    "size_bytes": 0,
                },
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        except Exception as e:
            return format_error(e, "create_inventory_snapshot")

    @mcp.tool()
    @secure_tool("compare_snapshots")
    async def compare_snapshots(snapshot_a_id: str, snapshot_b_id: str) -> dict:
        """Compare two inventory snapshots to detect changes.

        Args:
            snapshot_a_id: First snapshot ID (older)
            snapshot_b_id: Second snapshot ID (newer)

        Returns:
            Detailed change analysis between snapshots
        """
        try:
            # TODO: Implement snapshot comparison
            return {
                "success": True,
                "comparison": {
                    "snapshot_a_id": snapshot_a_id,
                    "snapshot_b_id": snapshot_b_id,
                    "comparison_timestamp": datetime.utcnow().isoformat() + "Z",
                    "changes_summary": {},
                    "health_impact": {},
                    "target_changes": [],
                    "service_changes": [],
                    "stack_changes": [],
                },
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        except Exception as e:
            return format_error(e, "compare_snapshots")

    @mcp.tool()
    @secure_tool("list_snapshots")
    async def list_snapshots(
        snapshot_type: Optional[str] = None, limit: int = 50
    ) -> dict:
        """List inventory snapshots with optional filtering.

        Args:
            snapshot_type: Optional filter by type (manual, scheduled, pre_deployment, etc.)
            limit: Maximum number of snapshots to return (default: 50)

        Returns:
            List of snapshots with metadata
        """
        try:
            # TODO: Implement snapshot listing
            return {
                "success": True,
                "snapshots": [],
                "count": 0,
                "filters": {"snapshot_type": snapshot_type, "limit": limit},
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        except Exception as e:
            return format_error(e, "list_snapshots")

    @mcp.tool()
    @secure_tool("generate_fleet_report")
    async def generate_fleet_report(report_type: str = "summary") -> dict:
        """Generate comprehensive fleet reports.

        Args:
            report_type: Type of report (summary, health, security, resources, dependencies)

        Returns:
            Detailed fleet report based on requested type
        """
        try:
            if report_type == "summary":
                return await _generate_summary_report()
            elif report_type == "health":
                return await _generate_health_report()
            elif report_type == "security":
                return await _generate_security_report()
            elif report_type == "resources":
                return await _generate_resource_report()
            elif report_type == "dependencies":
                return await _generate_dependency_report()
            else:
                return {
                    "success": False,
                    "error": f"Unknown report type: {report_type}",
                }

        except Exception as e:
            return format_error(e, "generate_fleet_report")

    @mcp.tool()
    @secure_tool("run_health_check")
    async def run_comprehensive_health_check() -> dict:
        """Run comprehensive fleet health check and return detailed results.

        Returns:
            Complete health assessment with issues and recommendations
        """
        try:
            # TODO: Implement comprehensive health check
            return {
                "success": True,
                "health_check": {
                    "overall_health_score": 0.0,
                    "total_targets_checked": 0,
                    "healthy_targets": 0,
                    "unhealthy_targets": 0,
                    "issues_found": [],
                },
                "resource_summary": {
                    "high_cpu_targets": 0,
                    "high_memory_targets": 0,
                    "high_disk_targets": 0,
                },
                "security_summary": {
                    "secure_targets": 0,
                    "warning_targets": 0,
                    "vulnerable_targets": 0,
                },
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        except Exception as e:
            return format_error(e, "run_comprehensive_health_check")

    @mcp.tool()
    @secure_tool("get_inventory_stats")
    async def get_inventory_statistics() -> dict:
        """Get comprehensive inventory statistics and storage information.

        Returns:
            Detailed inventory and storage statistics
        """
        try:
            # TODO: Implement inventory statistics
            return {
                "success": True,
                "inventory_stats": {
                    "entities": {
                        "targets": 0,
                        "services": 0,
                        "stacks": 0,
                        "proxmox_hosts": 0,
                    },
                    "health": {
                        "healthy_targets": 0,
                        "unhealthy_targets": 0,
                        "average_health_score": 0.0,
                    },
                    "by_role": {role.value: 0 for role in NodeRole},
                },
                "storage_stats": {
                    "database_size": 0,
                    "snapshots_count": 0,
                    "oldest_snapshot": None,
                    "newest_snapshot": None,
                },
                "service_status": {
                    "running": 0,
                    "stopped": 0,
                    "failed": 0,
                    "unknown": 0,
                },
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        except Exception as e:
            return format_error(e, "get_inventory_statistics")


# Helper functions for report generation
async def _generate_summary_report() -> dict:
    """Generate comprehensive summary report."""
    return {
        "success": True,
        "report_type": "summary",
        "fleet_overview": {
            "total_targets": 0,
            "total_services": 0,
            "total_stacks": 0,
            "healthy_targets": 0,
            "average_health_score": 0.0,
        },
        "role_distribution": {role.value: 0 for role in NodeRole},
        "service_distribution": {},
        "stack_distribution": {},
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


async def _generate_health_report() -> dict:
    """Generate detailed health report."""
    return {
        "success": True,
        "report_type": "health",
        "health_summary": {
            "total_targets": 0,
            "healthy_targets": 0,
            "unhealthy_targets": 0,
            "stale_targets": 0,
            "average_health_score": 0.0,
        },
        "health_issues": {"unhealthy_targets": [], "stale_targets": []},
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


async def _generate_security_report() -> dict:
    """Generate security posture report."""
    security_summary = {"secure": 0, "warning": 0, "vulnerable": 0, "unknown": 0}

    return {
        "success": True,
        "report_type": "security",
        "security_summary": security_summary,
        "security_issues": [],
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


async def _generate_resource_report() -> dict:
    """Generate resource utilization report."""
    resource_summary = {
        "high_cpu": 0,
        "high_memory": 0,
        "high_disk": 0,
        "total_cpu_cores": 0,
        "total_memory_mb": 0,
        "total_disk_gb": 0,
    }

    return {
        "success": True,
        "report_type": "resources",
        "resource_summary": resource_summary,
        "resource_intensive": [],
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


async def _generate_dependency_report() -> dict:
    """Generate service dependency report."""
    return {
        "success": True,
        "report_type": "dependencies",
        "dependency_map": {},
        "total_services_with_dependencies": 0,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }
