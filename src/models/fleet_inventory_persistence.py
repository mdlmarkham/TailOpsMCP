"""
Persistence layer for Fleet Inventory using SQLite with JSON fallback.

Provides efficient storage and querying capabilities for the fleet inventory model.
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Iterator

from src.models.fleet_inventory import (
    FleetInventory, ProxmoxHost, Node, Service, Snapshot, Event
)


class FleetInventoryPersistence:
    """Persistence layer for Fleet Inventory with SQLite and JSON support."""
    
    def __init__(self, db_path: Optional[str] = None, use_sqlite: bool = True):
        """Initialize persistence layer.
        
        Args:
            db_path: Path to SQLite database or JSON file
            use_sqlite: Whether to use SQLite (True) or JSON (False)
        """
        if db_path is None:
            # Default to /var/lib/systemmanager for production, local dir for development
            if os.path.exists('/var/lib/systemmanager'):
                default_path = '/var/lib/systemmanager/fleet_inventory.db'
            else:
                default_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fleet_inventory.db")
            db_path = default_path
        
        self.db_path = db_path
        self.use_sqlite = use_sqlite
        
        if self.use_sqlite:
            self._init_sqlite()
    
    def _init_sqlite(self) -> None:
        """Initialize SQLite database schema."""
        with self._get_connection() as conn:
            # Create tables
            conn.execute("""
                CREATE TABLE IF NOT EXISTS proxmox_hosts (
                    id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    address TEXT NOT NULL,
                    port INTEGER DEFAULT 8006,
                    username TEXT NOT NULL,
                    realm TEXT DEFAULT 'pam',
                    node_name TEXT NOT NULL,
                    cluster_name TEXT,
                    cpu_cores INTEGER NOT NULL,
                    memory_mb INTEGER NOT NULL,
                    storage_gb INTEGER NOT NULL,
                    version TEXT,
                    tags TEXT,  -- JSON array
                    discovered_at TEXT NOT NULL,
                    last_seen TEXT,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS nodes (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    node_type TEXT NOT NULL,
                    host_id TEXT NOT NULL,
                    vmid INTEGER,
                    status TEXT DEFAULT 'stopped',
                    cpu_cores INTEGER DEFAULT 1,
                    memory_mb INTEGER DEFAULT 512,
                    disk_gb INTEGER DEFAULT 10,
                    ip_address TEXT,
                    mac_address TEXT,
                    runtime TEXT NOT NULL,
                    connection_method TEXT NOT NULL,
                    tags TEXT,  -- JSON array
                    created_at TEXT NOT NULL,
                    last_updated TEXT,
                    is_managed BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (host_id) REFERENCES proxmox_hosts (id)
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS services (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    service_type TEXT NOT NULL,
                    status TEXT DEFAULT 'unknown',
                    version TEXT,
                    port INTEGER,
                    config_path TEXT,
                    data_path TEXT,
                    health_endpoint TEXT,
                    tags TEXT,  -- JSON array
                    created_at TEXT NOT NULL,
                    last_checked TEXT,
                    is_monitored BOOLEAN DEFAULT TRUE,
                    FOREIGN KEY (node_id) REFERENCES nodes (id)
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS snapshots (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    snapshot_type TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    size_mb INTEGER,
                    storage_path TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    tags TEXT,  -- JSON array
                    metadata TEXT,  -- JSON object
                    created_at TEXT NOT NULL
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    severity TEXT DEFAULT 'info',
                    source TEXT NOT NULL,
                    target_id TEXT,
                    target_type TEXT,
                    message TEXT NOT NULL,
                    details TEXT,  -- JSON object
                    timestamp TEXT NOT NULL,
                    user TEXT,
                    correlation_id TEXT
                )
            """)
            
            # Create indexes for efficient querying
            conn.execute("CREATE INDEX IF NOT EXISTS idx_nodes_host_id ON nodes(host_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_services_node_id ON services(node_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_snapshots_target_id ON snapshots(target_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)")
    
    @contextmanager
    def _get_connection(self) -> Iterator[sqlite3.Connection]:
        """Get SQLite connection with context management."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def save_inventory(self, inventory: FleetInventory) -> None:
        """Save entire fleet inventory."""
        if self.use_sqlite:
            self._save_inventory_sqlite(inventory)
        else:
            self._save_inventory_json(inventory)
    
    def load_inventory(self) -> FleetInventory:
        """Load entire fleet inventory."""
        if self.use_sqlite:
            return self._load_inventory_sqlite()
        else:
            return self._load_inventory_json()
    
    def _save_inventory_sqlite(self, inventory: FleetInventory) -> None:
        """Save inventory to SQLite database."""
        with self._get_connection() as conn:
            # Clear existing data
            conn.execute("DELETE FROM events")
            conn.execute("DELETE FROM snapshots")
            conn.execute("DELETE FROM services")
            conn.execute("DELETE FROM nodes")
            conn.execute("DELETE FROM proxmox_hosts")
            
            # Save Proxmox hosts
            for host in inventory.proxmox_hosts.values():
                conn.execute("""
                    INSERT INTO proxmox_hosts (
                        id, hostname, address, port, username, realm, node_name,
                        cluster_name, cpu_cores, memory_mb, storage_gb, version,
                        tags, discovered_at, last_seen, is_active
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    host.id, host.hostname, host.address, host.port, host.username,
                    host.realm, host.node_name, host.cluster_name, host.cpu_cores,
                    host.memory_mb, host.storage_gb, host.version,
                    json.dumps(host.tags), host.discovered_at, host.last_seen, host.is_active
                ))
            
            # Save nodes
            for node in inventory.nodes.values():
                conn.execute("""
                    INSERT INTO nodes (
                        id, name, node_type, host_id, vmid, status, cpu_cores,
                        memory_mb, disk_gb, ip_address, mac_address, runtime,
                        connection_method, tags, created_at, last_updated, is_managed
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    node.id, node.name, node.node_type.value, node.host_id, node.vmid,
                    node.status, node.cpu_cores, node.memory_mb, node.disk_gb,
                    node.ip_address, node.mac_address, node.runtime.value,
                    node.connection_method.value, json.dumps(node.tags),
                    node.created_at, node.last_updated, node.is_managed
                ))
            
            # Save services
            for service in inventory.services.values():
                conn.execute("""
                    INSERT INTO services (
                        id, name, node_id, service_type, status, version, port,
                        config_path, data_path, health_endpoint, tags, created_at,
                        last_checked, is_monitored
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    service.id, service.name, service.node_id, service.service_type,
                    service.status.value, service.version, service.port,
                    service.config_path, service.data_path, service.health_endpoint,
                    json.dumps(service.tags), service.created_at, service.last_checked,
                    service.is_monitored
                ))
            
            # Save snapshots
            for snapshot in inventory.snapshots.values():
                conn.execute("""
                    INSERT INTO snapshots (
                        id, name, snapshot_type, target_id, target_type, size_mb,
                        storage_path, created_at, expires_at, tags, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    snapshot.id, snapshot.name, snapshot.snapshot_type.value,
                    snapshot.target_id, snapshot.target_type, snapshot.size_mb,
                    snapshot.storage_path, snapshot.created_at, snapshot.expires_at,
                    json.dumps(snapshot.tags), json.dumps(snapshot.metadata)
                ))
            
            # Save events
            for event in inventory.events.values():
                conn.execute("""
                    INSERT INTO events (
                        id, event_type, severity, source, target_id, target_type,
                        message, details, timestamp, user, correlation_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.id, event.event_type.value, event.severity.value,
                    event.source, event.target_id, event.target_type, event.message,
                    json.dumps(event.details), event.timestamp, event.user,
                    event.correlation_id
                ))
    
    def _load_inventory_sqlite(self) -> FleetInventory:
        """Load inventory from SQLite database."""
        inventory = FleetInventory()
        
        with self._get_connection() as conn:
            # Load Proxmox hosts
            cursor = conn.execute("SELECT * FROM proxmox_hosts")
            for row in cursor:
                host = ProxmoxHost(
                    id=row['id'],
                    hostname=row['hostname'],
                    address=row['address'],
                    port=row['port'],
                    username=row['username'],
                    realm=row['realm'],
                    node_name=row['node_name'],
                    cluster_name=row['cluster_name'],
                    cpu_cores=row['cpu_cores'],
                    memory_mb=row['memory_mb'],
                    storage_gb=row['storage_gb'],
                    version=row['version'],
                    tags=json.loads(row['tags'] or '[]'),
                    discovered_at=row['discovered_at'],
                    last_seen=row['last_seen'],
                    is_active=bool(row['is_active'])
                )
                inventory.add_proxmox_host(host)
            
            # Load nodes
            cursor = conn.execute("SELECT * FROM nodes")
            for row in cursor:
                from src.models.fleet_inventory import NodeType, Runtime, ConnectionMethod
                node = Node(
                    id=row['id'],
                    name=row['name'],
                    node_type=NodeType(row['node_type']),
                    host_id=row['host_id'],
                    vmid=row['vmid'],
                    status=row['status'],
                    cpu_cores=row['cpu_cores'],
                    memory_mb=row['memory_mb'],
                    disk_gb=row['disk_gb'],
                    ip_address=row['ip_address'],
                    mac_address=row['mac_address'],
                    runtime=Runtime(row['runtime']),
                    connection_method=ConnectionMethod(row['connection_method']),
                    tags=json.loads(row['tags'] or '[]'),
                    created_at=row['created_at'],
                    last_updated=row['last_updated'],
                    is_managed=bool(row['is_managed'])
                )
                inventory.add_node(node)
            
            # Load services
            cursor = conn.execute("SELECT * FROM services")
            for row in cursor:
                from src.models.fleet_inventory import ServiceStatus
                service = Service(
                    id=row['id'],
                    name=row['name'],
                    node_id=row['node_id'],
                    service_type=row['service_type'],
                    status=ServiceStatus(row['status']),
                    version=row['version'],
                    port=row['port'],
                    config_path=row['config_path'],
                    data_path=row['data_path'],
                    health_endpoint=row['health_endpoint'],
                    tags=json.loads(row['tags'] or '[]'),
                    created_at=row['created_at'],
                    last_checked=row['last_checked'],
                    is_monitored=bool(row['is_monitored'])
                )
                inventory.add_service(service)
            
            # Load snapshots
            cursor = conn.execute("SELECT * FROM snapshots")
            for row in cursor:
                from src.models.fleet_inventory import SnapshotType
                snapshot = Snapshot(
                    id=row['id'],
                    name=row['name'],
                    snapshot_type=SnapshotType(row['snapshot_type']),
                    target_id=row['target_id'],
                    target_type=row['target_type'],
                    size_mb=row['size_mb'],
                    storage_path=row['storage_path'],
                    created_at=row['created_at'],
                    expires_at=row['expires_at'],
                    tags=json.loads(row['tags'] or '[]'),
                    metadata=json.loads(row['metadata'] or '{}')
                )
                inventory.add_snapshot(snapshot)
            
            # Load events
            cursor = conn.execute("SELECT * FROM events")
            for row in cursor:
                from src.models.fleet_inventory import EventType, EventSeverity
                event = Event(
                    id=row['id'],
                    event_type=EventType(row['event_type']),
                    severity=EventSeverity(row['severity']),
                    source=row['source'],
                    target_id=row['target_id'],
                    target_type=row['target_type'],
                    message=row['message'],
                    details=json.loads(row['details'] or '{}'),
                    timestamp=row['timestamp'],
                    user=row['user'],
                    correlation_id=row['correlation_id']
                )
                inventory.add_event(event)
        
        return inventory
    
    def _save_inventory_json(self, inventory: FleetInventory) -> None:
        """Save inventory to JSON file."""
        data = inventory.to_dict()
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        with open(self.db_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def _load_inventory_json(self) -> FleetInventory:
        """Load inventory from JSON file."""
        if not os.path.exists(self.db_path):
            return FleetInventory()
        
        with open(self.db_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        return FleetInventory.from_dict(data)
    
    # Query methods for efficient data access
    def get_nodes_by_host(self, host_id: str) -> List[Node]:
        """Get all nodes for a specific host."""
        if self.use_sqlite:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT * FROM nodes WHERE host_id = ?", (host_id,))
                nodes = []
                for row in cursor:
                    from src.models.fleet_inventory import NodeType, Runtime, ConnectionMethod
                    nodes.append(Node(
                        id=row['id'],
                        name=row['name'],
                        node_type=NodeType(row['node_type']),
                        host_id=row['host_id'],
                        vmid=row['vmid'],
                        status=row['status'],
                        cpu_cores=row['cpu_cores'],
                        memory_mb=row['memory_mb'],
                        disk_gb=row['disk_gb'],
                        ip_address=row['ip_address'],
                        mac_address=row['mac_address'],
                        runtime=Runtime(row['runtime']),
                        connection_method=ConnectionMethod(row['connection_method']),
                        tags=json.loads(row['tags'] or '[]'),
                        created_at=row['created_at'],
                        last_updated=row['last_updated'],
                        is_managed=bool(row['is_managed'])
                    ))
                return nodes
        else:
            inventory = self.load_inventory()
            return [node for node in inventory.nodes.values() if node.host_id == host_id]
    
    def get_services_by_node(self, node_id: str) -> List[Service]:
        """Get all services for a specific node."""
        if self.use_sqlite:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT * FROM services WHERE node_id = ?", (node_id,))
                services = []
                for row in cursor:
                    from src.models.fleet_inventory import ServiceStatus
                    services.append(Service(
                        id=row['id'],
                        name=row['name'],
                        node_id=row['node_id'],
                        service_type=row['service_type'],
                        status=ServiceStatus(row['status']),
                        version=row['version'],
                        port=row['port'],
                        config_path=row['config_path'],
                        data_path=row['data_path'],
                        health_endpoint=row['health_endpoint'],
                        tags=json.loads(row['tags'] or '[]'),
                        created_at=row['created_at'],
                        last_checked=row['last_checked'],
                        is_monitored=bool(row['is_monitored'])
                    ))
                return services
        else:
            inventory = self.load_inventory()
            return [service for service in inventory.services.values() if service.node_id == node_id]
    
    def get_events_by_type(self, event_type: str, limit: int = 100) -> List[Event]:
        """Get events by type with limit."""
        if self.use_sqlite:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT * FROM events WHERE event_type = ? ORDER BY timestamp DESC LIMIT ?",
                    (event_type, limit)
                )
                events = []
                for row in cursor:
                    from src.models.fleet_inventory import EventType, EventSeverity
                    events.append(Event(
                        id=row['id'],
                        event_type=EventType(row['event_type']),
                        severity=EventSeverity(row['severity']),
                        source=row['source'],
                        target_id=row['target_id'],
                        target_type=row['target_type'],
                        message=row['message'],
                        details=json.loads(row['details'] or '{}'),
                        timestamp=row['timestamp'],
                        user=row['user'],
                        correlation_id=row['correlation_id']
                    ))
                return events
        else:
            inventory = self.load_inventory()
            events = [event for event in inventory.events.values() if event.event_type.value == event_type]
            events.sort(key=lambda x: x.timestamp, reverse=True)
            return events[:limit]