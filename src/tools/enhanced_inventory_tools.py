"""
Enhanced Fleet Inventory Management Tools

Provides comprehensive MCP tools for the enhanced fleet inventory system including:
- Fleet-wide queries and filtering
- Change detection and drift monitoring
- Health monitoring and alerting
- Advanced reporting and analytics
- Snapshot management
"""

import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
from fastmcp import FastMCP

from src.services.inventory_service import InventoryService
from src.models.enhanced_fleet_inventory import (
    EnhancedFleetInventory, EnhancedTarget, EnhancedService, EnhancedStack, NodeRole
)
from src.models.inventory_snapshot import SnapshotType, SnapshotDiff
from src.auth.middleware import secure_tool
from src.server.dependencies import deps
from src.server.utils import format_error

logger = logging.getLogger(__name__)


def register_enhanced_inventory_tools(mcp: FastMCP):
    """Register enhanced inventory management tools with MCP instance."""

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
            inventory_service = InventoryService()
            inventory = await inventory_service.run_full_discovery()
            
            return {
                "success": True,
                "discovery_completed": True,
                "inventory_stats": {
                    "total_targets": inventory.total_targets,
                    "total_services": inventory.total_services,
                    "total_stacks": inventory.total_stacks,
                    "healthy_targets": inventory.healthy_targets,
                    "unhealthy_targets": inventory.unhealthy_targets,
                    "average_health_score": round(inventory.average_health_score, 2)
                },
                "timestamp": datetime.utcnow().isoformat() + "Z"
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
            inventory_service = InventoryService()
            inventory = inventory_service.current_inventory
            
            # Get health issues
            unhealthy_targets = inventory_service.get_unhealthy_targets()
            stale_targets = inventory_service.get_stale_targets()
            
            # Group targets by role
            targets_by_role = {}
            for role in NodeRole:
                targets_by_role[role.value] = len(inventory_service.get_targets_by_role(role))
            
            # Group services by type
            services_by_type = {}
            for service in inventory.services.values():
                service_type = service.service_type
                services_by_type[service_type] = services_by_type.get(service_type, 0) + 1
            
            return {
                "success": True,
                "fleet_summary": {
                    "total_targets": inventory.total_targets,
                    "total_services": inventory.total_services,
                    "total_stacks": inventory.total_stacks,
                    "healthy_targets": inventory.healthy_targets,
                    "unhealthy_targets": inventory.unhealthy_targets,
                    "average_health_score": round(inventory.average_health_score, 2)
                },
                "targets_by_role": targets_by_role,
                "services_by_type": services_by_type,
                "health_issues": {
                    "unhealthy_targets": len(unhealthy_targets),
                    "stale_targets": len(stale_targets)
                },
                "recent_activity": {
                    "last_discovery": inventory_service.discovery_pipeline.last_discovery.isoformat() if inventory_service.discovery_pipeline.last_discovery else None,
                    "last_health_check": inventory_service.last_health_check.isoformat() if inventory_service.last_health_check else None
                },
                "timestamp": datetime.utcnow().isoformat() + "Z"
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
            inventory_service = InventoryService()
            production_targets = inventory_service.get_targets_by_role(NodeRole.PRODUCTION)
            
            target_list = []
            for target in production_targets:
                target_data = {
                    "id": target.id,
                    "name": target.name,
                    "status": target.status,
                    "ip_address": target.ip_address,
                    "health_score": target.health_score,
                    "resource_usage": {
                        "cpu_percent": target.resource_usage.cpu_percent,
                        "memory_percent": target.resource_usage.memory_percent,
                        "disk_percent": target.resource_usage.disk_percent,
                        "status": target.resource_usage.status.value
                    },
                    "security_status": target.security_posture.security_status.value,
                    "last_seen": target.last_seen,
                    "services": len([s for s in inventory_service.current_inventory.services.values() if s.target_id == target.id]),
                    "tags": target.tags
                }
                target_list.append(target_data)
            
            return {
                "success": True,
                "production_targets": target_list,
                "count": len(target_list),
                "timestamp": datetime.utcnow().isoformat() + "Z"
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
            inventory_service = InventoryService()
            inventory = inventory_service.current_inventory
            
            services = []
            for service in inventory.services.values():
                if service.service_type.lower() == runtime.lower():
                    # Get target information
                    target = inventory.targets.get(service.target_id)
                    target_name = target.name if target else "unknown"
                    
                    service_data = {
                        "id": service.id,
                        "name": service.name,
                        "service_type": service.service_type,
                        "status": service.status.value,
                        "target_id": service.target_id,
                        "target_name": target_name,
                        "port": service.port,
                        "version": service.version,
                        "health_status": service.health_status,
                        "stack_name": service.stack_name,
                        "last_checked": service.last_checked,
                        "tags": service.tags
                    }
                    services.append(service_data)
            
            return {
                "success": True,
                "runtime": runtime,
                "services": services,
                "count": len(services),
                "timestamp": datetime.utcnow().isoformat() + "Z"
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
            inventory_service = InventoryService()
            stale_targets = inventory_service.get_stale_targets(hours)
            
            target_list = []
            for target in stale_targets:
                # Calculate hours since last seen
                if target.last_seen:
                    last_seen = datetime.fromisoformat(target.last_seen.replace('Z', '+00:00'))
                    hours_since_seen = (datetime.utcnow() - last_seen).total_seconds() / 3600
                else:
                    hours_since_seen = float('inf')
                
                target_data = {
                    "id": target.id,
                    "name": target.name,
                    "status": target.status,
                    "role": target.role.value,
                    "last_seen": target.last_seen,
                    "hours_since_seen": round(hours_since_seen, 1),
                    "ip_address": target.ip_address,
                    "health_score": target.health_score,
                    "services": len([s for s in inventory_service.current_inventory.services.values() if s.target_id == target.id])
                }
                target_list.append(target_data)
            
            # Sort by hours since seen (most stale first)
            target_list.sort(key=lambda x: x["hours_since_seen"], reverse=True)
            
            return {
                "success": True,
                "stale_threshold_hours": hours,
                "stale_targets": target_list,
                "count": len(target_list),
                "timestamp": datetime.utcnow().isoformat() + "Z"
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
            inventory_service = InventoryService()
            unhealthy_targets = inventory_service.get_unhealthy_targets(threshold)
            
            target_list = []
            for target in unhealthy_targets:
                # Identify health issues
                issues = []
                
                if target.health_score < threshold:
                    if target.resource_usage.status.value in ["warning", "critical"]:
                        issues.append("resource_usage")
                    if target.security_posture.security_status.value in ["warning", "vulnerable"]:
                        issues.append("security_posture")
                    if target.last_seen:
                        last_seen = datetime.fromisoformat(target.last_seen.replace('Z', '+00:00'))
                        hours_since_seen = (datetime.utcnow() - last_seen).total_seconds() / 3600
                        if hours_since_seen > 12:
                            issues.append("stale")
                
                target_data = {
                    "id": target.id,
                    "name": target.name,
                    "status": target.status,
                    "role": target.role.value,
                    "health_score": target.health_score,
                    "issues": issues,
                    "resource_usage": {
                        "cpu_percent": target.resource_usage.cpu_percent,
                        "memory_percent": target.resource_usage.memory_percent,
                        "disk_percent": target.resource_usage.disk_percent,
                        "status": target.resource_usage.status.value
                    },
                    "security_status": target.security_posture.security_status.value,
                    "last_seen": target.last_seen,
                    "last_health_check": target.last_health_check,
                    "services": len([s for s in inventory_service.current_inventory.services.values() if s.target_id == target.id])
                }
                target_list.append(target_data)
            
            # Sort by health score (worst first)
            target_list.sort(key=lambda x: x["health_score"])
            
            return {
                "success": True,
                "health_threshold": threshold,
                "unhealthy_targets": target_list,
                "count": len(target_list),
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        except Exception as e:
            return format_error(e, "get_unhealthy_targets")

    @mcp.tool()
    @secure_tool("search_fleet")
    async def search_fleet(query: str, entity_type: str = "all") -> dict:
        """Search fleet inventory by name, description, or tags.
        
        Args:
            query: Search query string
            entity_type: Type to search (all, target, service, stack)
            
        Returns:
            Search results with matching entities
        """
        try:
            inventory_service = InventoryService()
            inventory = inventory_service.current_inventory
            
            results = {
                "targets": [],
                "services": [],
                "stacks": []
            }
            
            # Search targets
            if entity_type in ["all", "target"]:
                targets = inventory_service.search_targets(query)
                for target in targets:
                    results["targets"].append({
                        "id": target.id,
                        "name": target.name,
                        "type": "target",
                        "description": target.description,
                        "status": target.status,
                        "role": target.role.value,
                        "health_score": target.health_score,
                        "tags": target.tags
                    })
            
            # Search services
            if entity_type in ["all", "service"]:
                for service in inventory.services.values():
                    if (query.lower() in service.name.lower() or
                        query.lower() in service.service_type.lower() or
                        any(query.lower() in tag.lower() for tag in service.tags)):
                        
                        target = inventory.targets.get(service.target_id)
                        target_name = target.name if target else "unknown"
                        
                        results["services"].append({
                            "id": service.id,
                            "name": service.name,
                            "type": "service",
                            "service_type": service.service_type,
                            "status": service.status.value,
                            "target_name": target_name,
                            "stack_name": service.stack_name,
                            "tags": service.tags
                        })
            
            # Search stacks
            if entity_type in ["all", "stack"]:
                for stack in inventory.stacks.values():
                    if (query.lower() in stack.name.lower() or
                        query.lower() in stack.description.lower() or
                        any(query.lower() in tag.lower() for tag in stack.tags)):
                        
                        results["stacks"].append({
                            "id": stack.id,
                            "name": stack.name,
                            "type": "stack",
                            "description": stack.description,
                            "stack_status": stack.stack_status,
                            "services_count": len(stack.services),
                            "targets_count": len(stack.targets),
                            "tags": stack.tags
                        })
            
            total_results = len(results["targets"]) + len(results["services"]) + len(results["stacks"])
            
            return {
                "success": True,
                "query": query,
                "entity_type": entity_type,
                "results": results,
                "total_results": total_results,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        except Exception as e:
            return format_error(e, "search_fleet")

    @mcp.tool()
    @secure_tool("create_inventory_snapshot")
    async def create_inventory_snapshot(
        name: str,
        description: Optional[str] = None,
        snapshot_type: str = "manual",
        tags: Optional[str] = None
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
            inventory_service = InventoryService()
            
            # Parse tags
            tag_list = []
            if tags:
                tag_list = [tag.strip() for tag in tags.split(",")]
            
            snapshot = await inventory_service.create_snapshot(
                name=name,
                description=description,
                snapshot_type=SnapshotType(snapshot_type),
                tags=tag_list
            )
            
            return {
                "success": True,
                "snapshot": {
                    "id": snapshot.id,
                    "name": snapshot.name,
                    "description": snapshot.description,
                    "snapshot_type": snapshot.snapshot_type.value,
                    "created_at": snapshot.created_at,
                    "tags": snapshot.tags,
                    "total_targets": snapshot.total_targets,
                    "total_services": snapshot.total_services,
                    "total_stacks": snapshot.total_stacks,
                    "healthy_targets": snapshot.healthy_targets,
                    "average_health_score": snapshot.average_health_score,
                    "size_bytes": snapshot.size_bytes
                },
                "timestamp": datetime.utcnow().isoformat() + "Z"
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
            inventory_service = InventoryService()
            diff = inventory_service.compare_snapshots(snapshot_a_id, snapshot_b_id)
            
            if not diff:
                return {
                    "success": False,
                    "error": "One or both snapshots not found"
                }
            
            # Get change summary
            change_summary = diff.get_change_summary()
            
            return {
                "success": True,
                "comparison": {
                    "snapshot_a_id": snapshot_a_id,
                    "snapshot_b_id": snapshot_b_id,
                    "comparison_timestamp": diff.created_at,
                    "changes_summary": change_summary,
                    "health_impact": diff.health_impact,
                    "target_changes": [
                        {
                            "entity_id": change.entity_id,
                            "change_type": change.change_type.value,
                            "field_changes": change.field_changes
                        }
                        for change in diff.target_changes
                    ],
                    "service_changes": [
                        {
                            "entity_id": change.entity_id,
                            "change_type": change.change_type.value,
                            "field_changes": change.field_changes
                        }
                        for change in diff.service_changes
                    ],
                    "stack_changes": [
                        {
                            "entity_id": change.entity_id,
                            "change_type": change.change_type.value,
                            "field_changes": change.field_changes
                        }
                        for change in diff.stack_changes
                    ]
                },
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        except Exception as e:
            return format_error(e, "compare_snapshots")

    @mcp.tool()
    @secure_tool("list_snapshots")
    async def list_snapshots(snapshot_type: Optional[str] = None, limit: int = 50) -> dict:
        """List inventory snapshots with optional filtering.
        
        Args:
            snapshot_type: Optional filter by type (manual, scheduled, pre_deployment, etc.)
            limit: Maximum number of snapshots to return (default: 50)
            
        Returns:
            List of snapshots with metadata
        """
        try:
            inventory_service = InventoryService()
            
            # Parse snapshot type
            snapshot_type_enum = None
            if snapshot_type:
                snapshot_type_enum = SnapshotType(snapshot_type)
            
            snapshots = inventory_service.list_snapshots(snapshot_type_enum, limit)
            
            snapshot_list = []
            for snapshot in snapshots:
                snapshot_data = {
                    "id": snapshot.id,
                    "name": snapshot.name,
                    "description": snapshot.description,
                    "snapshot_type": snapshot.snapshot_type.value,
                    "created_at": snapshot.created_at,
                    "created_by": snapshot.created_by,
                    "tags": snapshot.tags,
                    "total_targets": snapshot.total_targets,
                    "total_services": snapshot.total_services,
                    "total_stacks": snapshot.total_stacks,
                    "healthy_targets": snapshot.healthy_targets,
                    "average_health_score": snapshot.average_health_score,
                    "size_bytes": snapshot.size_bytes,
                    "expires_at": snapshot.expires_at,
                    "is_archived": snapshot.is_archived
                }
                snapshot_list.append(snapshot_data)
            
            return {
                "success": True,
                "snapshots": snapshot_list,
                "count": len(snapshot_list),
                "filters": {
                    "snapshot_type": snapshot_type,
                    "limit": limit
                },
                "timestamp": datetime.utcnow().isoformat() + "Z"
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
            inventory_service = InventoryService()
            inventory = inventory_service.current_inventory
            
            if report_type == "summary":
                # Generate summary report
                return await _generate_summary_report(inventory_service, inventory)
            elif report_type == "health":
                # Generate health report
                return await _generate_health_report(inventory_service, inventory)
            elif report_type == "security":
                # Generate security report
                return await _generate_security_report(inventory_service, inventory)
            elif report_type == "resources":
                # Generate resource utilization report
                return await _generate_resource_report(inventory_service, inventory)
            elif report_type == "dependencies":
                # Generate service dependency report
                return await _generate_dependency_report(inventory_service, inventory)
            else:
                return {
                    "success": False,
                    "error": f"Unknown report type: {report_type}"
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
            inventory_service = InventoryService()
            health_results = await inventory_service.run_health_check()
            
            # Add additional health metrics
            inventory = inventory_service.current_inventory
            
            # Resource utilization summary
            resource_summary = {
                "high_cpu_targets": 0,
                "high_memory_targets": 0,
                "high_disk_targets": 0
            }
            
            for target in inventory.targets.values():
                if target.resource_usage.cpu_percent > 80:
                    resource_summary["high_cpu_targets"] += 1
                if target.resource_usage.memory_percent > 80:
                    resource_summary["high_memory_targets"] += 1
                if target.resource_usage.disk_percent > 80:
                    resource_summary["high_disk_targets"] += 1
            
            health_results["resource_summary"] = resource_summary
            
            # Security summary
            security_summary = {
                "secure_targets": 0,
                "warning_targets": 0,
                "vulnerable_targets": 0
            }
            
            for target in inventory.targets.values():
                if target.security_posture.security_status.value == "secure":
                    security_summary["secure_targets"] += 1
                elif target.security_posture.security_status.value == "warning":
                    security_summary["warning_targets"] += 1
                else:
                    security_summary["vulnerable_targets"] += 1
            
            health_results["security_summary"] = security_summary
            
            return {
                "success": True,
                "health_check": health_results,
                "timestamp": datetime.utcnow().isoformat() + "Z"
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
            inventory_service = InventoryService()
            inventory = inventory_service.current_inventory
            storage_stats = inventory_service.get_storage_stats()
            service_status = inventory_service.get_service_status()
            
            return {
                "success": True,
                "inventory_stats": {
                    "entities": {
                        "targets": inventory.total_targets,
                        "services": inventory.total_services,
                        "stacks": inventory.total_stacks,
                        "proxmox_hosts": inventory.total_hosts
                    },
                    "health": {
                        "healthy_targets": inventory.healthy_targets,
                        "unhealthy_targets": inventory.unhealthy_targets,
                        "average_health_score": round(inventory.average_health_score, 2)
                    },
                    "by_role": {
                        role.value: len(inventory_service.get_targets_by_role(role))
                        for role in NodeRole
                    }
                },
                "storage_stats": storage_stats,
                "service_status": service_status,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        except Exception as e:
            return format_error(e, "get_inventory_statistics")


# Helper functions for report generation
async def _generate_summary_report(inventory_service, inventory) -> dict:
    """Generate comprehensive summary report."""
    return {
        "success": True,
        "report_type": "summary",
        "fleet_overview": {
            "total_targets": inventory.total_targets,
            "total_services": inventory.total_services,
            "total_stacks": inventory.total_stacks,
            "healthy_targets": inventory.healthy_targets,
            "average_health_score": round(inventory.average_health_score, 2)
        },
        "role_distribution": {
            role.value: len(inventory_service.get_targets_by_role(role))
            for role in NodeRole
        },
        "service_distribution": {},
        "stack_distribution": {},
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


async def _generate_health_report(inventory_service, inventory) -> dict:
    """Generate detailed health report."""
    unhealthy_targets = inventory_service.get_unhealthy_targets()
    stale_targets = inventory_service.get_stale_targets()
    
    return {
        "success": True,
        "report_type": "health",
        "health_summary": {
            "total_targets": inventory.total_targets,
            "healthy_targets": inventory.healthy_targets,
            "unhealthy_targets": len(unhealthy_targets),
            "stale_targets": len(stale_targets),
            "average_health_score": round(inventory.average_health_score, 2)
        },
        "health_issues": {
            "unhealthy_targets": [
                {
                    "id": target.id,
                    "name": target.name,
                    "health_score": target.health_score,
                    "issues": ["low_health_score"]
                }
                for target in unhealthy_targets[:10]  # Limit to top 10
            ],
            "stale_targets": [
                {
                    "id": target.id,
                    "name": target.name,
                    "last_seen": target.last_seen
                }
                for target in stale_targets[:10]  # Limit to top 10
            ]
        },
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


async def _generate_security_report(inventory_service, inventory) -> dict:
    """Generate security posture report."""
    from src.models.enhanced_fleet_inventory import SecurityStatus
    
    security_summary = {
        "secure": 0,
        "warning": 0,
        "vulnerable": 0,
        "unknown": 0
    }
    
    security_issues = []
    
    for target in inventory.targets.values():
        status = target.security_posture.security_status.value
        security_summary[status] = security_summary.get(status, 0) + 1
        
        if status in ["warning", "vulnerable"]:
            security_issues.append({
                "target_id": target.id,
                "target_name": target.name,
                "security_status": status,
                "issues": target.security_posture.dict()
            })
    
    return {
        "success": True,
        "report_type": "security",
        "security_summary": security_summary,
        "security_issues": security_issues,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


async def _generate_resource_report(inventory_service, inventory) -> dict:
    """Generate resource utilization report."""
    resource_summary = {
        "high_cpu": 0,
        "high_memory": 0,
        "high_disk": 0,
        "total_cpu_cores": 0,
        "total_memory_mb": 0,
        "total_disk_gb": 0
    }
    
    resource_intensive = []
    
    for target in inventory.targets.values():
        # Aggregate resource totals
        resource_summary["total_cpu_cores"] += target.cpu_cores
        resource_summary["total_memory_mb"] += target.memory_mb
        resource_summary["total_disk_gb"] += target.disk_gb
        
        # Check for high utilization
        if target.resource_usage.cpu_percent > 80:
            resource_summary["high_cpu"] += 1
            resource_intensive.append({
                "target_id": target.id,
                "target_name": target.name,
                "cpu_percent": target.resource_usage.cpu_percent,
                "issue": "high_cpu"
            })
        
        if target.resource_usage.memory_percent > 80:
            resource_summary["high_memory"] += 1
            resource_intensive.append({
                "target_id": target.id,
                "target_name": target.name,
                "memory_percent": target.resource_usage.memory_percent,
                "issue": "high_memory"
            })
        
        if target.resource_usage.disk_percent > 80:
            resource_summary["high_disk"] += 1
            resource_intensive.append({
                "target_id": target.id,
                "target_name": target.name,
                "disk_percent": target.resource_usage.disk_percent,
                "issue": "high_disk"
            })
    
    return {
        "success": True,
        "report_type": "resources",
        "resource_summary": resource_summary,
        "resource_intensive": resource_intensive,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


async def _generate_dependency_report(inventory_service, inventory) -> dict:
    """Generate service dependency report."""
    dependency_map = {}
    
    for service in inventory.services.values():
        if service.depends_on:
            dependency_map[service.name] = {
                "depends_on": service.depends_on,
                "target": inventory.targets.get(service.target_id).name if inventory.targets.get(service.target_id) else "unknown"
            }
    
    return {
        "success": True,
        "report_type": "dependencies",
        "dependency_map": dependency_map,
        "total_services_with_dependencies": len(dependency_map),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


    logger.info("Registered enhanced inventory management tools")