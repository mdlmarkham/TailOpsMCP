"""
TOON (Typed Object-Oriented Notation) serialization for Fleet Inventory models.

Provides serialization and deserialization between TOON format and JSON format
for the fleet inventory data model.
"""

from __future__ import annotations

import json
from typing import Dict, List, Optional, Any, Union

from src.models.fleet_inventory import (
    FleetInventory, ProxmoxHost, Node, Service, Snapshot, Event,
    ConnectionMethod, Runtime, NodeType, ServiceStatus, SnapshotType, EventType, EventSeverity
)


class TOONSerializer:
    """TOON serialization utilities for Fleet Inventory models."""
    
    @staticmethod
    def to_toon(inventory: FleetInventory, compact: bool = True) -> str:
        """Convert FleetInventory to TOON format.
        
        Args:
            inventory: Fleet inventory to serialize
            compact: Whether to use compact TOON format (default: True)
        
        Returns:
            TOON-formatted string, either compact or pretty JSON
        """
        toon_data = {
            "version": "1.0.0",
            "type": "FleetInventory",
            "metadata": {
                "created_at": inventory.created_at,
                "last_updated": inventory.last_updated,
                "total_hosts": inventory.total_hosts,
                "total_nodes": inventory.total_nodes,
                "total_services": inventory.total_services,
                "total_snapshots": inventory.total_snapshots
            },
            "proxmox_hosts": [TOONSerializer._host_to_toon(host) for host in inventory.proxmox_hosts.values()],
            "nodes": [TOONSerializer._node_to_toon(node) for node in inventory.nodes.values()],
            "services": [TOONSerializer._service_to_toon(service) for service in inventory.services.values()],
            "snapshots": [TOONSerializer._snapshot_to_toon(snapshot) for snapshot in inventory.snapshots.values()],
            "events": [TOONSerializer._event_to_toon(event) for event in inventory.events.values()]
        }
        
        if compact:
            # Use compact TOON format for LLM consumption
            from src.utils.toon import _compact_json
            return _compact_json(toon_data)
        else:
            # Fallback to pretty JSON
            return json.dumps(toon_data, indent=2, ensure_ascii=False)
    
    @staticmethod
    def from_toon(toon_str: str) -> FleetInventory:
        """Create FleetInventory from TOON format."""
        # Handle both compact TOON and regular JSON
        try:
            toon_data = json.loads(toon_str)
        except json.JSONDecodeError:
            # Try to parse as compact TOON format
            from src.utils.toon import _from_toon_tabular
            toon_data = _from_toon_tabular(toon_str)
        
        inventory = FleetInventory()
        
        # Load Proxmox hosts
        for host_data in toon_data.get("proxmox_hosts", []):
            host = TOONSerializer._host_from_toon(host_data)
            inventory.add_proxmox_host(host)
        
        # Load nodes
        for node_data in toon_data.get("nodes", []):
            node = TOONSerializer._node_from_toon(node_data)
            inventory.add_node(node)
        
        # Load services
        for service_data in toon_data.get("services", []):
            service = TOONSerializer._service_from_toon(service_data)
            inventory.add_service(service)
        
        # Load snapshots
        for snapshot_data in toon_data.get("snapshots", []):
            snapshot = TOONSerializer._snapshot_from_toon(snapshot_data)
            inventory.add_snapshot(snapshot)
        
        # Load events
        for event_data in toon_data.get("events", []):
            event = TOONSerializer._event_from_toon(event_data)
            inventory.add_event(event)
        
        # Set metadata
        metadata = toon_data.get("metadata", {})
        inventory.created_at = metadata.get("created_at", inventory.created_at)
        inventory.last_updated = metadata.get("last_updated", inventory.last_updated)
        
        return inventory
    
    @staticmethod
    def compute_diff(prev_inventory: FleetInventory, new_inventory: FleetInventory) -> str:
        """Compute a compact diff between two inventory states.
        
        Args:
            prev_inventory: Previous inventory state
            new_inventory: New inventory state
            
        Returns:
            Compact TOON diff string
        """
        from src.utils.toon import compute_delta
        
        prev_toon = TOONSerializer.to_toon(prev_inventory, compact=True)
        new_toon = TOONSerializer.to_toon(new_inventory, compact=True)
        
        return compute_delta(prev_toon, new_toon)
    
    @staticmethod
    def to_tabular(inventory: FleetInventory, entity_type: str) -> str:
        """Convert specific entity type to TOON tabular format.
        
        Args:
            inventory: Fleet inventory
            entity_type: Type of entities to tabularize ("hosts", "nodes", "services", "snapshots", "events")
            
        Returns:
            TOON tabular string or empty string if no entities
        """
        from src.utils.toon import _to_toon_tabular
        
        entities = []
        if entity_type == "hosts":
            entities = [TOONSerializer._host_to_toon(host) for host in inventory.proxmox_hosts.values()]
        elif entity_type == "nodes":
            entities = [TOONSerializer._node_to_toon(node) for node in inventory.nodes.values()]
        elif entity_type == "services":
            entities = [TOONSerializer._service_to_toon(service) for service in inventory.services.values()]
        elif entity_type == "snapshots":
            entities = [TOONSerializer._snapshot_to_toon(snapshot) for snapshot in inventory.snapshots.values()]
        elif entity_type == "events":
            entities = [TOONSerializer._event_to_toon(event) for event in inventory.events.values()]
        
        if entities:
            tabular = _to_toon_tabular(entities)
            return tabular if tabular else json.dumps(entities, separators=(",",":"), ensure_ascii=False)
        
        return ""
    
    @staticmethod
    def _host_to_toon(host: ProxmoxHost) -> Dict[str, Any]:
        """Convert ProxmoxHost to TOON format."""
        return {
            "type": "ProxmoxHost",
            "id": host.id,
            "hostname": host.hostname,
            "address": host.address,
            "port": host.port,
            "username": host.username,
            "realm": host.realm,
            "node_name": host.node_name,
            "cluster_name": host.cluster_name,
            "resources": {
                "cpu_cores": host.cpu_cores,
                "memory_mb": host.memory_mb,
                "storage_gb": host.storage_gb
            },
            "version": host.version,
            "tags": host.tags,
            "timestamps": {
                "discovered_at": host.discovered_at,
                "last_seen": host.last_seen
            },
            "is_active": host.is_active
        }
    
    @staticmethod
    def _host_from_toon(data: Dict[str, Any]) -> ProxmoxHost:
        """Create ProxmoxHost from TOON format."""
        resources = data.get("resources", {})
        timestamps = data.get("timestamps", {})
        
        return ProxmoxHost(
            id=data["id"],
            hostname=data["hostname"],
            address=data["address"],
            port=data.get("port", 8006),
            username=data["username"],
            realm=data.get("realm", "pam"),
            node_name=data["node_name"],
            cluster_name=data.get("cluster_name"),
            cpu_cores=resources.get("cpu_cores", 0),
            memory_mb=resources.get("memory_mb", 0),
            storage_gb=resources.get("storage_gb", 0),
            version=data.get("version"),
            tags=data.get("tags", []),
            discovered_at=timestamps.get("discovered_at"),
            last_seen=timestamps.get("last_seen"),
            is_active=data.get("is_active", True)
        )
    
    @staticmethod
    def _node_to_toon(node: Node) -> Dict[str, Any]:
        """Convert Node to TOON format."""
        return {
            "type": "Node",
            "id": node.id,
            "name": node.name,
            "node_type": node.node_type.value,
            "host_id": node.host_id,
            "vmid": node.vmid,
            "status": node.status,
            "resources": {
                "cpu_cores": node.cpu_cores,
                "memory_mb": node.memory_mb,
                "disk_gb": node.disk_gb
            },
            "network": {
                "ip_address": node.ip_address,
                "mac_address": node.mac_address
            },
            "runtime": node.runtime.value,
            "connection_method": node.connection_method.value,
            "tags": node.tags,
            "timestamps": {
                "created_at": node.created_at,
                "last_updated": node.last_updated
            },
            "is_managed": node.is_managed
        }
    
    @staticmethod
    def _node_from_toon(data: Dict[str, Any]) -> Node:
        """Create Node from TOON format."""
        resources = data.get("resources", {})
        network = data.get("network", {})
        timestamps = data.get("timestamps", {})
        
        return Node(
            id=data["id"],
            name=data["name"],
            node_type=NodeType(data["node_type"]),
            host_id=data["host_id"],
            vmid=data.get("vmid"),
            status=data.get("status", "stopped"),
            cpu_cores=resources.get("cpu_cores", 1),
            memory_mb=resources.get("memory_mb", 512),
            disk_gb=resources.get("disk_gb", 10),
            ip_address=network.get("ip_address"),
            mac_address=network.get("mac_address"),
            runtime=Runtime(data["runtime"]),
            connection_method=ConnectionMethod(data["connection_method"]),
            tags=data.get("tags", []),
            created_at=timestamps.get("created_at"),
            last_updated=timestamps.get("last_updated"),
            is_managed=data.get("is_managed", False)
        )
    
    @staticmethod
    def _service_to_toon(service: Service) -> Dict[str, Any]:
        """Convert Service to TOON format."""
        return {
            "type": "Service",
            "id": service.id,
            "name": service.name,
            "node_id": service.node_id,
            "service_type": service.service_type,
            "status": service.status.value,
            "version": service.version,
            "port": service.port,
            "paths": {
                "config": service.config_path,
                "data": service.data_path
            },
            "health_endpoint": service.health_endpoint,
            "tags": service.tags,
            "timestamps": {
                "created_at": service.created_at,
                "last_checked": service.last_checked
            },
            "is_monitored": service.is_monitored
        }
    
    @staticmethod
    def _service_from_toon(data: Dict[str, Any]) -> Service:
        """Create Service from TOON format."""
        paths = data.get("paths", {})
        timestamps = data.get("timestamps", {})
        
        return Service(
            id=data["id"],
            name=data["name"],
            node_id=data["node_id"],
            service_type=data["service_type"],
            status=ServiceStatus(data.get("status", "unknown")),
            version=data.get("version"),
            port=data.get("port"),
            config_path=paths.get("config"),
            data_path=paths.get("data"),
            health_endpoint=data.get("health_endpoint"),
            tags=data.get("tags", []),
            created_at=timestamps.get("created_at"),
            last_checked=timestamps.get("last_checked"),
            is_monitored=data.get("is_monitored", True)
        )
    
    @staticmethod
    def _snapshot_to_toon(snapshot: Snapshot) -> Dict[str, Any]:
        """Convert Snapshot to TOON format."""
        return {
            "type": "Snapshot",
            "id": snapshot.id,
            "name": snapshot.name,
            "snapshot_type": snapshot.snapshot_type.value,
            "target": {
                "id": snapshot.target_id,
                "type": snapshot.target_type
            },
            "size_mb": snapshot.size_mb,
            "storage_path": snapshot.storage_path,
            "created_at": snapshot.created_at,
            "expires_at": snapshot.expires_at,
            "tags": snapshot.tags,
            "metadata": snapshot.metadata
        }
    
    @staticmethod
    def _snapshot_from_toon(data: Dict[str, Any]) -> Snapshot:
        """Create Snapshot from TOON format."""
        target = data.get("target", {})
        
        return Snapshot(
            id=data["id"],
            name=data["name"],
            snapshot_type=SnapshotType(data["snapshot_type"]),
            target_id=target["id"],
            target_type=target["type"],
            size_mb=data.get("size_mb"),
            storage_path=data.get("storage_path"),
            created_at=data["created_at"],
            expires_at=data.get("expires_at"),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {})
        )
    
    @staticmethod
    def _event_to_toon(event: Event) -> Dict[str, Any]:
        """Convert Event to TOON format."""
        return {
            "type": "Event",
            "id": event.id,
            "event_type": event.event_type.value,
            "severity": event.severity.value,
            "source": event.source,
            "target": {
                "id": event.target_id,
                "type": event.target_type
            } if event.target_id else None,
            "message": event.message,
            "details": event.details,
            "timestamp": event.timestamp,
            "user": event.user,
            "correlation_id": event.correlation_id
        }
    
    @staticmethod
    def _event_from_toon(data: Dict[str, Any]) -> Event:
        """Create Event from TOON format."""
        target = data.get("target", {})
        
        return Event(
            id=data["id"],
            event_type=EventType(data["event_type"]),
            severity=EventSeverity(data.get("severity", "info")),
            source=data["source"],
            target_id=target.get("id"),
            target_type=target.get("type"),
            message=data["message"],
            details=data.get("details", {}),
            timestamp=data["timestamp"],
            user=data.get("user"),
            correlation_id=data.get("correlation_id")
        )


class FleetInventoryAdapter:
    """Adapter for integrating Fleet Inventory with existing TargetRegistry system."""
    
    @staticmethod
    def target_metadata_to_node(target: TargetMetadata) -> Node:
        """Convert TargetMetadata to Node model."""
        # Map executor type to runtime
        runtime_map = {
            ExecutorType.LOCAL: Runtime.BARE_METAL,
            ExecutorType.SSH: Runtime.SYSTEMD,
            ExecutorType.DOCKER: Runtime.DOCKER
        }
        
        # Map executor type to connection method
        connection_map = {
            ExecutorType.LOCAL: ConnectionMethod.SSH,
            ExecutorType.SSH: ConnectionMethod.SSH,
            ExecutorType.DOCKER: ConnectionMethod.DOCKER_API
        }
        
        return Node(
            id=target.id,
            name=target.id,  # Use target ID as node name
            node_type=NodeType.BARE_METAL if target.type == "local" else NodeType.CONTAINER,
            host_id="local" if target.type == "local" else target.connection.host or "unknown",
            runtime=runtime_map.get(target.executor, Runtime.BARE_METAL),
            connection_method=connection_map.get(target.executor, ConnectionMethod.SSH),
            tags=["target-registry"],
            is_managed=True
        )
    
    @staticmethod
    def node_to_target_metadata(node: Node) -> TargetMetadata:
        """Convert Node to TargetMetadata model."""
        # Map runtime to executor type
        executor_map = {
            Runtime.DOCKER: ExecutorType.DOCKER,
            Runtime.SYSTEMD: ExecutorType.SSH,
            Runtime.PROXMOX: ExecutorType.SSH,
            Runtime.BARE_METAL: ExecutorType.LOCAL
        }
        
        # Create connection based on node properties
        connection = TargetConnection(
            executor=executor_map.get(node.runtime, ExecutorType.SSH),
            host=node.ip_address if node.ip_address else node.host_id if node.host_id != "local" else None,
            port=22 if node.connection_method == ConnectionMethod.SSH else None
        )
        
        return TargetMetadata(
            id=node.id,
            type="local" if node.host_id == "local" else "remote",
            executor=executor_map.get(node.runtime, ExecutorType.SSH),
            connection=connection,
            capabilities=[],  # Would need mapping from node capabilities
            constraints=TargetConstraints(),
            metadata={
                "node_type": node.node_type.value,
                "runtime": node.runtime.value,
                "connection_method": node.connection_method.value
            }
        )
    
    @staticmethod
    def merge_inventory_with_targets(inventory: FleetInventory, targets: Dict[str, TargetMetadata]) -> FleetInventory:
        """Merge TargetRegistry targets into Fleet Inventory."""
        merged_inventory = FleetInventory.from_dict(inventory.to_dict())
        
        for target_id, target in targets.items():
            # Check if this target already exists as a node
            existing_node = None
            for node in merged_inventory.nodes.values():
                if node.id == target_id:
                    existing_node = node
                    break
            
            if not existing_node:
                # Convert target to node and add to inventory
                node = FleetInventoryAdapter.target_metadata_to_node(target)
                merged_inventory.add_node(node)
            
            # TODO: Update existing node with target metadata if needed
        
        return merged_inventory