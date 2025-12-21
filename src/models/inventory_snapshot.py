"""
Inventory Snapshot Management for Change Detection

Provides point-in-time inventory snapshots with delta comparison capabilities.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from datetime import timezone, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
from uuid import uuid4

from pydantic import BaseModel, Field

from src.models.enhanced_fleet_inventory import EnhancedFleetInventory


class SnapshotType(str, Enum):
    """Types of inventory snapshots."""

    MANUAL = "manual"
    SCHEDULED = "scheduled"
    PRE_DEPLOYMENT = "pre_deployment"
    POST_DEPLOYMENT = "post_deployment"
    HEALTH_CHECK = "health_check"
    BACKUP = "backup"
    DISCOVERY = "discovery"


class ChangeType(str, Enum):
    """Types of changes detected between snapshots."""

    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    NO_CHANGE = "no_change"


class EntityChange(BaseModel):
    """Represents a change in a single entity."""

    entity_id: str
    entity_type: str  # "target", "service", "stack"
    change_type: ChangeType
    field_changes: Dict[str, Any] = Field(default_factory=dict)
    old_value: Optional[Any] = None
    new_value: Optional[Any] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z")


class SnapshotDiff(BaseModel):
    """Represents the difference between two inventory snapshots."""

    snapshot_a_id: str
    snapshot_b_id: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z")

    # Change summaries
    target_changes: List[EntityChange] = Field(default_factory=list)
    service_changes: List[EntityChange] = Field(default_factory=list)
    stack_changes: List[EntityChange] = Field(default_factory=list)

    # Change metrics
    total_changes: int = 0
    entities_created: int = 0
    entities_modified: int = 0
    entities_deleted: int = 0

    # Health impact
    health_impact: Dict[str, Any] = Field(default_factory=dict)

    def calculate_metrics(self) -> None:
        """Calculate change metrics."""
        self.total_changes = (
            len(self.target_changes)
            + len(self.service_changes)
            + len(self.stack_changes)
        )

        for change_list in [
            self.target_changes,
            self.service_changes,
            self.stack_changes,
        ]:
            for change in change_list:
                if change.change_type == ChangeType.CREATED:
                    self.entities_created += 1
                elif change.change_type == ChangeType.MODIFIED:
                    self.entities_modified += 1
                elif change.change_type == ChangeType.DELETED:
                    self.entities_deleted += 1

    def get_change_summary(self) -> Dict[str, Any]:
        """Get human-readable change summary."""
        summary = {
            "total_changes": self.total_changes,
            "entities_created": self.entities_created,
            "entities_modified": self.entities_modified,
            "entities_deleted": self.entities_deleted,
            "changes_by_type": {"targets": {}, "services": {}, "stacks": {}},
            "health_impact": self.health_impact,
        }

        # Group changes by type for targets
        for change in self.target_changes:
            change_type = change.change_type.value
            if change_type not in summary["changes_by_type"]["targets"]:
                summary["changes_by_type"]["targets"][change_type] = []
            summary["changes_by_type"]["targets"][change_type].append(
                {"id": change.entity_id, "changes": change.field_changes}
            )

        # Group changes by type for services
        for change in self.service_changes:
            change_type = change.change_type.value
            if change_type not in summary["changes_by_type"]["services"]:
                summary["changes_by_type"]["services"][change_type] = []
            summary["changes_by_type"]["services"][change_type].append(
                {"id": change.entity_id, "changes": change.field_changes}
            )

        # Group changes by type for stacks
        for change in self.stack_changes:
            change_type = change.change_type.value
            if change_type not in summary["changes_by_type"]["stacks"]:
                summary["changes_by_type"]["stacks"][change_type] = []
            summary["changes_by_type"]["stacks"][change_type].append(
                {"id": change.entity_id, "changes": change.field_changes}
            )

        return summary


@dataclass
class InventorySnapshot:
    """Point-in-time inventory snapshot."""

    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: Optional[str] = None
    snapshot_type: SnapshotType = SnapshotType.MANUAL

    # Snapshot metadata
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z")
    created_by: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    # Inventory data
    inventory_data: Dict[str, Any] = field(default_factory=dict)

    # Snapshot metrics
    total_targets: int = 0
    total_services: int = 0
    total_stacks: int = 0
    healthy_targets: int = 0
    average_health_score: float = 0.0

    # Storage information
    size_bytes: int = 0
    compression_ratio: float = 1.0

    # Retention policy
    expires_at: Optional[str] = None
    is_archived: bool = False

    def validate(self) -> List[str]:
        """Validate snapshot configuration."""
        errors = []

        if not self.name:
            errors.append("Snapshot name is required")

        return errors

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "snapshot_type": self.snapshot_type.value,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "tags": self.tags,
            "inventory_data": self.inventory_data,
            "total_targets": self.total_targets,
            "total_services": self.total_services,
            "total_stacks": self.total_stacks,
            "healthy_targets": self.healthy_targets,
            "average_health_score": self.average_health_score,
            "size_bytes": self.size_bytes,
            "compression_ratio": self.compression_ratio,
            "expires_at": self.expires_at,
            "is_archived": self.is_archived,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> InventorySnapshot:
        """Create InventorySnapshot from dictionary."""
        return cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description"),
            snapshot_type=SnapshotType(data.get("snapshot_type", "manual")),
            created_at=data.get("created_at"),
            created_by=data.get("created_by"),
            tags=data.get("tags", []),
            inventory_data=data.get("inventory_data", {}),
            total_targets=data.get("total_targets", 0),
            total_services=data.get("total_services", 0),
            total_stacks=data.get("total_stacks", 0),
            healthy_targets=data.get("healthy_targets", 0),
            average_health_score=data.get("average_health_score", 0.0),
            size_bytes=data.get("size_bytes", 0),
            compression_ratio=data.get("compression_ratio", 1.0),
            expires_at=data.get("expires_at"),
            is_archived=data.get("is_archived", False),
        )

    def get_inventory(self) -> EnhancedFleetInventory:
        """Get the inventory data as EnhancedFleetInventory object."""
        return EnhancedFleetInventory.from_dict(self.inventory_data)

    def set_inventory(self, inventory: EnhancedFleetInventory) -> None:
        """Set the inventory data from EnhancedFleetInventory object."""
        self.inventory_data = inventory.to_dict()
        self.total_targets = inventory.total_targets
        self.total_services = inventory.total_services
        self.total_stacks = inventory.total_stacks
        self.healthy_targets = inventory.healthy_targets
        self.average_health_score = inventory.average_health_score

        # Calculate size
        self.size_bytes = len(json.dumps(self.inventory_data))


class SnapshotManager:
    """Manages inventory snapshots and change detection."""

    def __init__(self, persistence_manager=None):
        """Initialize snapshot manager.

        Args:
            persistence_manager: Optional persistence manager for storing snapshots
        """
        self.persistence_manager = persistence_manager
        self.snapshots: Dict[str, InventorySnapshot] = {}

    def create_snapshot(
        self,
        inventory: EnhancedFleetInventory,
        name: str,
        snapshot_type: SnapshotType = SnapshotType.MANUAL,
        description: Optional[str] = None,
        created_by: Optional[str] = None,
        tags: Optional[List[str]] = None,
        expires_at: Optional[str] = None,
    ) -> InventorySnapshot:
        """Create a new inventory snapshot.

        Args:
            inventory: Current inventory to snapshot
            name: Snapshot name
            snapshot_type: Type of snapshot
            description: Optional description
            created_by: User who created the snapshot
            tags: Optional tags
            expires_at: Optional expiration date

        Returns:
            Created snapshot
        """
        snapshot = InventorySnapshot(
            name=name,
            description=description,
            snapshot_type=snapshot_type,
            created_by=created_by,
            tags=tags or [],
            expires_at=expires_at,
        )

        snapshot.set_inventory(inventory)

        # Store snapshot
        self.snapshots[snapshot.id] = snapshot

        # Persist if manager available
        if self.persistence_manager:
            self.persistence_manager.save_snapshot(snapshot)

        return snapshot

    def compare_snapshots(
        self, snapshot_a: InventorySnapshot, snapshot_b: InventorySnapshot
    ) -> SnapshotDiff:
        """Compare two snapshots and return differences.

        Args:
            snapshot_a: First snapshot (older)
            snapshot_b: Second snapshot (newer)

        Returns:
            SnapshotDiff with detected changes
        """
        diff = SnapshotDiff(snapshot_a_id=snapshot_a.id, snapshot_b_id=snapshot_b.id)

        # Get inventory objects
        inventory_a = snapshot_a.get_inventory()
        inventory_b = snapshot_b.get_inventory()

        # Compare targets
        diff.target_changes = self._compare_entities(
            inventory_a.targets, inventory_b.targets, "target"
        )

        # Compare services
        diff.service_changes = self._compare_entities(
            inventory_a.services, inventory_b.services, "service"
        )

        # Compare stacks
        diff.stack_changes = self._compare_entities(
            inventory_a.stacks, inventory_b.stacks, "stack"
        )

        # Calculate metrics
        diff.calculate_metrics()

        # Analyze health impact
        diff.health_impact = self._analyze_health_impact(inventory_a, inventory_b, diff)

        return diff

    def _compare_entities(
        self, entities_a: Dict[str, Any], entities_b: Dict[str, Any], entity_type: str
    ) -> List[EntityChange]:
        """Compare two entity dictionaries and return changes.

        Args:
            entities_a: First entity dictionary (older)
            entities_b: Second entity dictionary (newer)
            entity_type: Type of entity ("target", "service", "stack")

        Returns:
            List of entity changes
        """
        changes = []

        # Find entities that were created or modified
        for entity_id, entity_b in entities_b.items():
            if entity_id not in entities_a:
                # Entity was created
                changes.append(
                    EntityChange(
                        entity_id=entity_id,
                        entity_type=entity_type,
                        change_type=ChangeType.CREATED,
                        new_value=entity_b.to_dict()
                        if hasattr(entity_b, "to_dict")
                        else entity_b,
                    )
                )
            else:
                # Entity might have been modified
                entity_a = entities_a[entity_id]
                entity_a_dict = (
                    entity_a.to_dict() if hasattr(entity_a, "to_dict") else entity_a
                )
                entity_b_dict = (
                    entity_b.to_dict() if hasattr(entity_b, "to_dict") else entity_b
                )

                field_changes = self._find_field_changes(entity_a_dict, entity_b_dict)

                if field_changes:
                    changes.append(
                        EntityChange(
                            entity_id=entity_id,
                            entity_type=entity_type,
                            change_type=ChangeType.MODIFIED,
                            field_changes=field_changes,
                            old_value=entity_a_dict,
                            new_value=entity_b_dict,
                        )
                    )
                else:
                    # No changes
                    changes.append(
                        EntityChange(
                            entity_id=entity_id,
                            entity_type=entity_type,
                            change_type=ChangeType.NO_CHANGE,
                        )
                    )

        # Find entities that were deleted
        for entity_id, entity_a in entities_a.items():
            if entity_id not in entities_b:
                changes.append(
                    EntityChange(
                        entity_id=entity_id,
                        entity_type=entity_type,
                        change_type=ChangeType.DELETED,
                        old_value=entity_a.to_dict()
                        if hasattr(entity_a, "to_dict")
                        else entity_a,
                    )
                )

        return changes

    def _find_field_changes(
        self, old_dict: Dict[str, Any], new_dict: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Find changes between two dictionaries.

        Args:
            old_dict: Old dictionary
            new_dict: New dictionary

        Returns:
            Dictionary of field changes
        """
        changes = {}

        all_keys = set(old_dict.keys()) | set(new_dict.keys())

        for key in all_keys:
            old_value = old_dict.get(key)
            new_value = new_dict.get(key)

            if old_value != new_value:
                changes[key] = {"old": old_value, "new": new_value}

        return changes

    def _analyze_health_impact(
        self,
        inventory_a: EnhancedFleetInventory,
        inventory_b: EnhancedFleetInventory,
        diff: SnapshotDiff,
    ) -> Dict[str, Any]:
        """Analyze the health impact of changes.

        Args:
            inventory_a: Previous inventory
            inventory_b: Current inventory
            diff: Detected changes

        Returns:
            Health impact analysis
        """
        impact = {
            "health_score_change": inventory_b.average_health_score
            - inventory_a.average_health_score,
            "healthy_targets_change": inventory_b.healthy_targets
            - inventory_a.healthy_targets,
            "unhealthy_targets_change": inventory_b.unhealthy_targets
            - inventory_a.unhealthy_targets,
            "critical_changes": [],
            "potential_issues": [],
        }

        # Check for critical changes
        for change in diff.target_changes + diff.service_changes + diff.stack_changes:
            if change.change_type == ChangeType.DELETED:
                impact["critical_changes"].append(
                    {
                        "type": "deletion",
                        "entity_type": change.entity_type,
                        "entity_id": change.entity_id,
                        "description": f"{change.entity_type.capitalize()} {change.entity_id} was removed",
                    }
                )
            elif change.change_type == ChangeType.MODIFIED:
                # Check for status changes that could impact health
                if "status" in change.field_changes:
                    old_status = change.field_changes["status"]["old"]
                    new_status = change.field_changes["status"]["new"]

                    if old_status in ["running", "healthy"] and new_status in [
                        "stopped",
                        "failed",
                    ]:
                        impact["potential_issues"].append(
                            {
                                "type": "status_degradation",
                                "entity_type": change.entity_type,
                                "entity_id": change.entity_id,
                                "description": f"{change.entity_type.capitalize()} {change.entity_id} status degraded from {old_status} to {new_status}",
                            }
                        )

                # Check for health score changes
                if "health_score" in change.field_changes:
                    old_score = change.field_changes["health_score"]["old"]
                    new_score = change.field_changes["health_score"]["new"]

                    if (
                        old_score - new_score > 0.2
                    ):  # Health score dropped by more than 20%
                        impact["potential_issues"].append(
                            {
                                "type": "health_score_drop",
                                "entity_type": change.entity_type,
                                "entity_id": change.entity_id,
                                "description": f"{change.entity_type.capitalize()} {change.entity_id} health score dropped from {old_score} to {new_score}",
                            }
                        )

        return impact

    def get_snapshot(self, snapshot_id: str) -> Optional[InventorySnapshot]:
        """Get a snapshot by ID."""
        return self.snapshots.get(snapshot_id)

    def list_snapshots(
        self, snapshot_type: Optional[SnapshotType] = None, limit: Optional[int] = None
    ) -> List[InventorySnapshot]:
        """List snapshots with optional filtering.

        Args:
            snapshot_type: Optional filter by snapshot type
            limit: Optional limit on number of results

        Returns:
            List of snapshots
        """
        snapshots = list(self.snapshots.values())

        # Filter by type if specified
        if snapshot_type:
            snapshots = [s for s in snapshots if s.snapshot_type == snapshot_type]

        # Sort by creation time (newest first)
        snapshots.sort(key=lambda x: x.created_at, reverse=True)

        # Apply limit if specified
        if limit:
            snapshots = snapshots[:limit]

        return snapshots

    def delete_snapshot(self, snapshot_id: str) -> bool:
        """Delete a snapshot.

        Args:
            snapshot_id: ID of snapshot to delete

        Returns:
            True if deleted, False if not found
        """
        if snapshot_id in self.snapshots:
            del self.snapshots[snapshot_id]

            # Remove from persistence if available
            if self.persistence_manager:
                self.persistence_manager.delete_snapshot(snapshot_id)

            return True
        return False

    def cleanup_expired_snapshots(self) -> int:
        """Remove expired snapshots.

        Returns:
            Number of snapshots cleaned up
        """
        from datetime import datetime
from datetime import timezone, timezone

        now = datetime.now(timezone.utc)
        expired_ids = []

        for snapshot_id, snapshot in self.snapshots.items():
            if snapshot.expires_at:
                expires_at = datetime.fromisoformat(
                    snapshot.expires_at.replace("Z", "+00:00")
                )
                if now > expires_at:
                    expired_ids.append(snapshot_id)

        # Remove expired snapshots
        for snapshot_id in expired_ids:
            self.delete_snapshot(snapshot_id)

        return len(expired_ids)
