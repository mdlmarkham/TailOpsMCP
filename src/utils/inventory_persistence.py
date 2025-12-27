"""
Enhanced Inventory Persistence Layer

Provides advanced persistence capabilities for the enhanced fleet inventory with:
- Enhanced metadata support
- Snapshot management
- Change tracking
- Query optimization
- Archive management
"""

from __future__ import annotations

import json
import os
import aiosqlite
import gzip
from contextlib import asynccontextmanager
from datetime import datetime
from datetime import timezone, timezone, timezone, timedelta
from typing import Dict, List, Optional, Any, AsyncIterator

from src.models.enhanced_fleet_inventory import (
    EnhancedFleetInventory,
    EnhancedTarget,
    EnhancedService,
    EnhancedStack,
    NodeRole,
)
from src.models.inventory_snapshot import InventorySnapshot, SnapshotType


class EnhancedInventoryPersistence:
    """Enhanced persistence layer with advanced features."""

    def __init__(self, db_path: Optional[str] = None, use_sqlite: bool = True):
        """Initialize enhanced persistence layer.

        Args:
            db_path: Path to SQLite database or JSON file
            use_sqlite: Whether to use SQLite (True) or JSON (False)
        """
        if db_path is None:
            # Default to /var/lib/systemmanager for production, local dir for development
            if os.path.exists("/var/lib/systemmanager"):
                default_path = "/var/lib/systemmanager/enhanced_inventory.db"
            else:
                default_path = os.path.join(
                    os.path.dirname(os.path.dirname(__file__)), "enhanced_inventory.db"
                )
            db_path = default_path

        self.db_path = db_path
        self.use_sqlite = use_sqlite

        # Snapshot storage
        self.snapshot_dir = os.path.join(os.path.dirname(db_path), "snapshots")
        os.makedirs(self.snapshot_dir, exist_ok=True)

        # Archive storage
        self.archive_dir = os.path.join(os.path.dirname(db_path), "archive")
        os.makedirs(self.archive_dir, exist_ok=True)

        # Note: Schema initialization must be done explicitly via async_init()
        # This is because __init__ cannot be async
        self._schema_initialized = False
        self._init_lock = None  # Will be set to asyncio.Lock in _get_lock

    def _get_lock(self) -> Any:
        """Lazy load asyncio lock."""
        if self._init_lock is None:
            import asyncio

            self._init_lock = asyncio.Lock()
        return self._init_lock

    async def _ensure_initialized(self) -> None:
        """Ensure schema is initialized."""
        if self.use_sqlite and not self._schema_initialized:
            async with self._get_lock():
                if not self._schema_initialized:
                    await self._init_enhanced_schema()
                    self._schema_initialized = True

    async def _init_enhanced_schema(self) -> None:
        """Initialize enhanced SQLite database schema."""
        async with self._get_connection() as conn:
            # Enhanced targets table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS enhanced_targets (
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
                    role TEXT DEFAULT 'development',
                    description TEXT,
                    environment TEXT,  -- JSON object
                    resource_usage TEXT,  -- JSON object
                    security_posture TEXT,  -- JSON object
                    container_info TEXT,  -- JSON object
                    services TEXT,  -- JSON array
                    stacks TEXT,  -- JSON array
                    last_seen TEXT,
                    last_health_check TEXT,
                    health_score REAL DEFAULT 0.0,
                    created_at TEXT NOT NULL,
                    last_updated TEXT,
                    is_managed BOOLEAN DEFAULT FALSE,
                    is_active BOOLEAN DEFAULT TRUE,
                    tags TEXT,  -- JSON array
                    custom_attributes TEXT,  -- JSON object
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Enhanced services table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS enhanced_services (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    service_type TEXT NOT NULL,
                    status TEXT DEFAULT 'unknown',
                    version TEXT,
                    port INTEGER,
                    protocol TEXT DEFAULT 'tcp',
                    config_path TEXT,
                    data_path TEXT,
                    health_endpoint TEXT,
                    stack_name TEXT,
                    depends_on TEXT,  -- JSON array
                    environment TEXT,  -- JSON object
                    cpu_limit REAL,
                    memory_limit INTEGER,
                    restart_policy TEXT DEFAULT 'unless-stopped',
                    health_check_enabled BOOLEAN DEFAULT TRUE,
                    health_check_interval INTEGER DEFAULT 30,
                    health_check_timeout INTEGER DEFAULT 5,
                    health_check_retries INTEGER DEFAULT 3,
                    last_health_check TEXT,
                    health_status TEXT DEFAULT 'unknown',
                    tls_enabled BOOLEAN DEFAULT FALSE,
                    tls_port INTEGER,
                    exposed_ports TEXT,  -- JSON array
                    security_context TEXT,  -- JSON object
                    created_at TEXT NOT NULL,
                    last_checked TEXT,
                    last_updated TEXT,
                    is_monitored BOOLEAN DEFAULT TRUE,
                    is_managed BOOLEAN DEFAULT FALSE,
                    tags TEXT,  -- JSON array
                    custom_attributes TEXT,  -- JSON object
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Enhanced stacks table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS enhanced_stacks (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    compose_file_path TEXT NOT NULL,
                    stack_file_content TEXT,
                    variables TEXT,  -- JSON object
                    services TEXT,  -- JSON array
                    targets TEXT,  -- JSON array
                    stack_status TEXT DEFAULT 'unknown',
                    last_deployed TEXT,
                    deployment_method TEXT DEFAULT 'docker-compose',
                    namespace TEXT,
                    health_score REAL DEFAULT 0.0,
                    last_health_check TEXT,
                    security_scan_results TEXT,  -- JSON object
                    compliance_status TEXT DEFAULT 'unknown',
                    total_cpu_cores REAL DEFAULT 0.0,
                    total_memory_mb INTEGER DEFAULT 0,
                    total_disk_gb INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    last_updated TEXT,
                    is_active BOOLEAN DEFAULT TRUE,
                    tags TEXT,  -- JSON array
                    custom_attributes TEXT,  -- JSON object
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Enhanced snapshots table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS enhanced_snapshots (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    snapshot_type TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    created_by TEXT,
                    tags TEXT,  -- JSON array
                    inventory_data TEXT NOT NULL,  -- JSON object
                    total_targets INTEGER DEFAULT 0,
                    total_services INTEGER DEFAULT 0,
                    total_stacks INTEGER DEFAULT 0,
                    healthy_targets INTEGER DEFAULT 0,
                    average_health_score REAL DEFAULT 0.0,
                    size_bytes INTEGER DEFAULT 0,
                    compression_ratio REAL DEFAULT 1.0,
                    expires_at TEXT,
                    is_archived BOOLEAN DEFAULT FALSE,
                    file_path TEXT
                )
            """)

            # Create indexes for efficient querying
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_enhanced_targets_host_id ON enhanced_targets(host_id)"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_enhanced_targets_role ON enhanced_targets(role)"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_enhanced_targets_status ON enhanced_targets(status)"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_enhanced_targets_last_seen ON enhanced_targets(last_seen)"
            )

            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_enhanced_services_target_id ON enhanced_services(target_id)"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_enhanced_services_stack_name ON enhanced_services(stack_name)"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_enhanced_services_status ON enhanced_services(status)"
            )

            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_enhanced_stacks_status ON enhanced_stacks(stack_status)"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_enhanced_stacks_last_deployed ON enhanced_stacks(last_deployed)"
            )

            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_enhanced_snapshots_type ON enhanced_snapshots(snapshot_type)"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_enhanced_snapshots_created_at ON enhanced_snapshots(created_at)"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_enhanced_snapshots_expires_at ON enhanced_snapshots(expires_at)"
            )

    @asynccontextmanager
    async def _get_connection(self) -> AsyncIterator[aiosqlite.Connection]:
        """Get SQLite connection with async context management."""
        conn = await aiosqlite.connect(self.db_path)
        conn.row_factory = aiosqlite.Row
        try:
            yield conn
            await conn.commit()
        except Exception:
            await conn.rollback()
            raise
        finally:
            await conn.close()

    async def save_inventory(self, inventory: EnhancedFleetInventory) -> None:
        """Save enhanced fleet inventory."""
        await self._ensure_initialized()
        if self.use_sqlite:
            await self._save_inventory_sqlite(inventory)
        else:
            self._save_inventory_json(inventory)

    async def load_inventory(self) -> EnhancedFleetInventory:
        """Load enhanced fleet inventory."""
        await self._ensure_initialized()
        if self.use_sqlite:
            return await self._load_inventory_sqlite()
        else:
            return self._load_inventory_json()

    async def _save_inventory_sqlite(self, inventory: EnhancedFleetInventory) -> None:
        """Save inventory to SQLite database."""
        async with self._get_connection() as conn:
            # Clear existing data
            await conn.execute("DELETE FROM enhanced_services")
            await conn.execute("DELETE FROM enhanced_targets")
            await conn.execute("DELETE FROM enhanced_stacks")

            # Save targets
            for target in inventory.targets.values():
                await conn.execute(
                    """
                    INSERT OR REPLACE INTO enhanced_targets (
                        id, name, node_type, host_id, vmid, status, cpu_cores,
                        memory_mb, disk_gb, ip_address, mac_address, runtime,
                        connection_method, role, description, environment,
                        resource_usage, security_posture, container_info,
                        services, stacks, last_seen, last_health_check,
                        health_score, created_at, last_updated, is_managed,
                        is_active, tags, custom_attributes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        target.id,
                        target.name,
                        target.node_type.value,
                        target.host_id,
                        target.vmid,
                        target.status,
                        target.cpu_cores,
                        target.memory_mb,
                        target.disk_gb,
                        target.ip_address,
                        target.mac_address,
                        target.runtime.value,
                        target.connection_method.value,
                        target.role.value,
                        target.description,
                        json.dumps(target.environment),
                        target.resource_usage.dict(),
                        target.security_posture.dict(),
                        target.container_info.dict() if target.container_info else None,
                        json.dumps(target.services),
                        json.dumps(target.stacks),
                        target.last_seen,
                        target.last_health_check,
                        target.health_score,
                        target.created_at,
                        target.last_updated,
                        target.is_managed,
                        target.is_active,
                        json.dumps(target.tags),
                        json.dumps(target.custom_attributes),
                    ),
                )

            # Save services
            for service in inventory.services.values():
                await conn.execute(
                    """
                    INSERT OR REPLACE INTO enhanced_services (
                        id, name, target_id, service_type, status, version, port,
                        protocol, config_path, data_path, health_endpoint,
                        stack_name, depends_on, environment, cpu_limit,
                        memory_limit, restart_policy, health_check_enabled,
                        health_check_interval, health_check_timeout,
                        health_check_retries, last_health_check, health_status,
                        tls_enabled, tls_port, exposed_ports, security_context,
                        created_at, last_checked, last_updated, is_monitored,
                        is_managed, tags, custom_attributes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        service.id,
                        service.name,
                        service.target_id,
                        service.service_type,
                        service.status.value,
                        service.version,
                        service.port,
                        service.protocol,
                        service.config_path,
                        service.data_path,
                        service.health_endpoint,
                        service.stack_name,
                        json.dumps(service.depends_on),
                        json.dumps(service.environment),
                        service.cpu_limit,
                        service.memory_limit,
                        service.restart_policy,
                        service.health_check_enabled,
                        service.health_check_interval,
                        service.health_check_timeout,
                        service.health_check_retries,
                        service.last_health_check,
                        service.health_status,
                        service.tls_enabled,
                        service.tls_port,
                        json.dumps(service.exposed_ports),
                        json.dumps(service.security_context),
                        service.created_at,
                        service.last_checked,
                        service.last_updated,
                        service.is_monitored,
                        service.is_managed,
                        json.dumps(service.tags),
                        json.dumps(service.custom_attributes),
                    ),
                )

            # Save stacks
            for stack in inventory.stacks.values():
                await conn.execute(
                    """
                    INSERT OR REPLACE INTO enhanced_services (
                        id, name, target_id, service_type, status, version, port,
                        protocol, config_path, data_path, health_endpoint,
                        stack_name, depends_on, environment, cpu_limit,
                        memory_limit, restart_policy, health_check_enabled,
                        health_check_interval, health_check_timeout,
                        health_check_retries, last_health_check, health_status,
                        tls_enabled, tls_port, exposed_ports, security_context,
                        created_at, last_checked, last_updated, is_monitored,
                        is_managed, tags, custom_attributes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        service.id,
                        service.name,
                        service.target_id,
                        service.service_type,
                        service.status.value,
                        service.version,
                        service.port,
                        service.protocol,
                        service.config_path,
                        service.data_path,
                        service.health_endpoint,
                        service.stack_name,
                        json.dumps(service.depends_on),
                        json.dumps(service.environment),
                        service.cpu_limit,
                        service.memory_limit,
                        service.restart_policy,
                        service.health_check_enabled,
                        service.health_check_interval,
                        service.health_check_timeout,
                        service.health_check_retries,
                        service.last_health_check,
                        service.health_status,
                        service.tls_enabled,
                        service.tls_port,
                        json.dumps(service.exposed_ports),
                        json.dumps(service.security_context),
                        service.created_at,
                        service.last_checked,
                        service.last_updated,
                        service.is_monitored,
                        service.is_managed,
                        json.dumps(service.tags),
                        json.dumps(service.custom_attributes),
                    ),
                )

            # Save stacks
            for stack in inventory.stacks.values():
                conn.execute(
                    """
                    INSERT OR REPLACE INTO enhanced_stacks (
                        id, name, description, compose_file_path, stack_file_content,
                        variables, services, targets, stack_status, last_deployed,
                        deployment_method, namespace, health_score, last_health_check,
                        security_scan_results, compliance_status, total_cpu_cores,
                        total_memory_mb, total_disk_gb, created_at, last_updated,
                        is_active, tags, custom_attributes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        stack.id,
                        stack.name,
                        stack.description,
                        stack.compose_file_path,
                        stack.stack_file_content,
                        json.dumps(stack.variables),
                        json.dumps(stack.services),
                        json.dumps(stack.targets),
                        stack.stack_status,
                        stack.last_deployed,
                        stack.deployment_method,
                        stack.namespace,
                        stack.health_score,
                        stack.last_health_check,
                        json.dumps(stack.security_scan_results),
                        stack.compliance_status,
                        stack.total_cpu_cores,
                        stack.total_memory_mb,
                        stack.total_disk_gb,
                        stack.created_at,
                        stack.last_updated,
                        stack.is_active,
                        json.dumps(stack.tags),
                        json.dumps(stack.custom_attributes),
                    ),
                )

    async def _load_inventory_sqlite(self) -> EnhancedFleetInventory:
        """Load inventory from SQLite database."""
        inventory = EnhancedFleetInventory()

        async with self._get_connection() as conn:
            # Load targets
            cursor = await conn.execute("SELECT * FROM enhanced_targets")
            for row in cursor:
                from src.models.fleet_inventory import (
                    NodeType,
                    Runtime,
                    ConnectionMethod,
                )

                target = EnhancedTarget(
                    id=row["id"],
                    name=row["name"],
                    node_type=NodeType(row["node_type"]),
                    host_id=row["host_id"],
                    vmid=row["vmid"],
                    status=row["status"],
                    cpu_cores=row["cpu_cores"],
                    memory_mb=row["memory_mb"],
                    disk_gb=row["disk_gb"],
                    ip_address=row["ip_address"],
                    mac_address=row["mac_address"],
                    runtime=Runtime(row["runtime"]),
                    connection_method=ConnectionMethod(row["connection_method"]),
                    role=NodeRole(row["role"]),
                    description=row["description"],
                    environment=json.loads(row["environment"] or "{}"),
                    resource_usage=EnhancedTarget(**{}).resource_usage.__class__(
                        **json.loads(row["resource_usage"] or "{}")
                    ),
                    security_posture=EnhancedTarget(**{}).security_posture.__class__(
                        **json.loads(row["security_posture"] or "{}")
                    ),
                    services=json.loads(row["services"] or "[]"),
                    stacks=json.loads(row["stacks"] or "[]"),
                    last_seen=row["last_seen"],
                    last_health_check=row["last_health_check"],
                    health_score=row["health_score"],
                    created_at=row["created_at"],
                    last_updated=row["last_updated"],
                    is_managed=bool(row["is_managed"]),
                    is_active=bool(row["is_active"]),
                    tags=json.loads(row["tags"] or "[]"),
                    custom_attributes=json.loads(row["custom_attributes"] or "{}"),
                )

                # Handle container_info if present
                if row["container_info"]:
                    from src.models.enhanced_fleet_inventory import ContainerInfo

                    target.container_info = ContainerInfo(
                        **json.loads(row["container_info"])
                    )

                inventory.add_target(target)

            # Load services
            cursor = await conn.execute("SELECT * FROM enhanced_services")
            for row in cursor:
                from src.models.fleet_inventory import ServiceStatus

                service = EnhancedService(
                    id=row["id"],
                    name=row["name"],
                    target_id=row["target_id"],
                    service_type=row["service_type"],
                    status=ServiceStatus(row["status"]),
                    version=row["version"],
                    port=row["port"],
                    protocol=row["protocol"],
                    config_path=row["config_path"],
                    data_path=row["data_path"],
                    health_endpoint=row["health_endpoint"],
                    stack_name=row["stack_name"],
                    depends_on=json.loads(row["depends_on"] or "[]"),
                    environment=json.loads(row["environment"] or "{}"),
                    cpu_limit=row["cpu_limit"],
                    memory_limit=row["memory_limit"],
                    restart_policy=row["restart_policy"],
                    health_check_enabled=bool(row["health_check_enabled"]),
                    health_check_interval=row["health_check_interval"],
                    health_check_timeout=row["health_check_timeout"],
                    health_check_retries=row["health_check_retries"],
                    last_health_check=row["last_health_check"],
                    health_status=row["health_status"],
                    tls_enabled=bool(row["tls_enabled"]),
                    tls_port=row["tls_port"],
                    exposed_ports=json.loads(row["exposed_ports"] or "[]"),
                    security_context=json.loads(row["security_context"] or "{}"),
                    created_at=row["created_at"],
                    last_checked=row["last_checked"],
                    last_updated=row["last_updated"],
                    is_monitored=bool(row["is_monitored"]),
                    is_managed=bool(row["is_managed"]),
                    tags=json.loads(row["tags"] or "[]"),
                    custom_attributes=json.loads(row["custom_attributes"] or "{}"),
                )

                inventory.add_service(service)

            # Load stacks
            cursor = await conn.execute("SELECT * FROM enhanced_stacks")
            for row in cursor:
                stack = EnhancedStack(
                    id=row["id"],
                    name=row["name"],
                    description=row["description"],
                    compose_file_path=row["compose_file_path"],
                    stack_file_content=row["stack_file_content"],
                    variables=json.loads(row["variables"] or "{}"),
                    services=json.loads(row["services"] or "[]"),
                    targets=json.loads(row["targets"] or "[]"),
                    stack_status=row["stack_status"],
                    last_deployed=row["last_deployed"],
                    deployment_method=row["deployment_method"],
                    namespace=row["namespace"],
                    health_score=row["health_score"],
                    last_health_check=row["last_health_check"],
                    security_scan_results=json.loads(
                        row["security_scan_results"] or "{}"
                    ),
                    compliance_status=row["compliance_status"],
                    total_cpu_cores=row["total_cpu_cores"],
                    total_memory_mb=row["total_memory_mb"],
                    total_disk_gb=row["total_disk_gb"],
                    created_at=row["created_at"],
                    last_updated=row["last_updated"],
                    is_active=bool(row["is_active"]),
                    tags=json.loads(row["tags"] or "[]"),
                    custom_attributes=json.loads(row["custom_attributes"] or "{}"),
                )

                inventory.add_stack(stack)

        return inventory

    def _save_inventory_json(self, inventory: EnhancedFleetInventory) -> None:
        """Save inventory to JSON file."""
        data = inventory.to_dict()
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        with open(self.db_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _load_inventory_json(self) -> EnhancedFleetInventory:
        """Load inventory from JSON file."""
        if not os.path.exists(self.db_path):
            return EnhancedFleetInventory()

        with open(self.db_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        return EnhancedFleetInventory.from_dict(data)

    # Snapshot management methods
    async def save_snapshot(self, snapshot: InventorySnapshot) -> None:
        """Save a snapshot."""
        if self.use_sqlite:
            await self._save_snapshot_sqlite(snapshot)
        else:
            self._save_snapshot_json(snapshot)

    async def load_snapshot(self, snapshot_id: str) -> Optional[InventorySnapshot]:
        """Load a snapshot by ID."""
        if self.use_sqlite:
            return await self._load_snapshot_sqlite(snapshot_id)
        else:
            return self._load_snapshot_json(snapshot_id)

    async def delete_snapshot(self, snapshot_id: str) -> bool:
        """Delete a snapshot."""
        if self.use_sqlite:
            return await self._delete_snapshot_sqlite(snapshot_id)
        else:
            return self._delete_snapshot_json(snapshot_id)

    async def _save_snapshot_sqlite(self, snapshot: InventorySnapshot) -> None:
        """Save snapshot to SQLite."""
        async with self._get_connection() as conn:
            await conn.execute(
                """
                INSERT OR REPLACE INTO enhanced_snapshots (
                    id, name, description, snapshot_type, created_at, created_by,
                    tags, inventory_data, total_targets, total_services,
                    total_stacks, healthy_targets, average_health_score,
                    size_bytes, compression_ratio, expires_at, is_archived
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    snapshot.id,
                    snapshot.name,
                    snapshot.description,
                    snapshot.snapshot_type.value,
                    snapshot.created_at,
                    snapshot.created_by,
                    json.dumps(snapshot.tags),
                    json.dumps(snapshot.inventory_data),
                    snapshot.total_targets,
                    snapshot.total_services,
                    snapshot.total_stacks,
                    snapshot.healthy_targets,
                    snapshot.average_health_score,
                    snapshot.size_bytes,
                    snapshot.compression_ratio,
                    snapshot.expires_at,
                    snapshot.is_archived,
                ),
            )

    async def _load_snapshot_sqlite(
        self, snapshot_id: str
    ) -> Optional[InventorySnapshot]:
        """Load snapshot from SQLite."""
        async with self._get_connection() as conn:
            cursor = await conn.execute(
                "SELECT * FROM enhanced_snapshots WHERE id = ?", (snapshot_id,)
            )
            row = await cursor.fetchone()

            if row:
                return InventorySnapshot(
                    id=row["id"],
                    name=row["name"],
                    description=row["description"],
                    snapshot_type=SnapshotType(row["snapshot_type"]),
                    created_at=row["created_at"],
                    created_by=row["created_by"],
                    tags=json.loads(row["tags"] or "[]"),
                    inventory_data=json.loads(row["inventory_data"]),
                    total_targets=row["total_targets"],
                    total_services=row["total_services"],
                    total_stacks=row["total_stacks"],
                    healthy_targets=row["healthy_targets"],
                    average_health_score=row["average_health_score"],
                    size_bytes=row["size_bytes"],
                    compression_ratio=row["compression_ratio"],
                    expires_at=row["expires_at"],
                    is_archived=bool(row["is_archived"]),
                )

        return None

    async def _delete_snapshot_sqlite(self, snapshot_id: str) -> bool:
        """Delete snapshot from SQLite."""
        async with self._get_connection() as conn:
            cursor = await conn.execute(
                "DELETE FROM enhanced_snapshots WHERE id = ?", (snapshot_id,)
            )
            return cursor.rowcount > 0

    def _save_snapshot_json(self, snapshot: InventorySnapshot) -> None:
        """Save snapshot to JSON file."""
        snapshot_file = os.path.join(self.snapshot_dir, f"{snapshot.id}.json")
        with open(snapshot_file, "w", encoding="utf-8") as f:
            json.dump(snapshot.to_dict(), f, indent=2, ensure_ascii=False)

    def _load_snapshot_json(self, snapshot_id: str) -> Optional[InventorySnapshot]:
        """Load snapshot from JSON file."""
        snapshot_file = os.path.join(self.snapshot_dir, f"{snapshot_id}.json")
        if os.path.exists(snapshot_file):
            with open(snapshot_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return InventorySnapshot.from_dict(data)
        return None

    def _delete_snapshot_json(self, snapshot_id: str) -> bool:
        """Delete snapshot from JSON file."""
        snapshot_file = os.path.join(self.snapshot_dir, f"{snapshot_id}.json")
        if os.path.exists(snapshot_file):
            os.remove(snapshot_file)
            return True
        return False

    # Advanced query methods
    async def get_targets_by_role(self, role: NodeRole) -> List[EnhancedTarget]:
        """Get targets by role."""
        if self.use_sqlite:
            async with self._get_connection() as conn:
                cursor = await conn.execute(
                    "SELECT * FROM enhanced_targets WHERE role = ?", (role.value,)
                )
                return [self._row_to_target(row) for row in cursor]
        else:
            inventory = await self.load_inventory()
            return [
                target for target in inventory.targets.values() if target.role == role
            ]

    async def get_targets_by_status(self, status: str) -> List[EnhancedTarget]:
        """Get targets by status."""
        if self.use_sqlite:
            async with self._get_connection() as conn:
                cursor = await conn.execute(
                    "SELECT * FROM enhanced_targets WHERE status = ?", (status,)
                )
                return [self._row_to_target(row) for row in cursor]
        else:
            inventory = await self.load_inventory()
            return [
                target
                for target in inventory.targets.values()
                if target.status == status
            ]

    async def get_unhealthy_targets(
        self, threshold: float = 0.7
    ) -> List[EnhancedTarget]:
        """Get targets with health score below threshold."""
        if self.use_sqlite:
            async with self._get_connection() as conn:
                cursor = await conn.execute(
                    "SELECT * FROM enhanced_targets WHERE health_score < ?",
                    (threshold,),
                )
                return [self._row_to_target(row) for row in cursor]
        else:
            inventory = await self.load_inventory()
            return [
                target
                for target in inventory.targets.values()
                if target.health_score < threshold
            ]

    async def get_stale_targets(self, hours: int = 24) -> List[EnhancedTarget]:
        """Get targets not seen within specified hours."""

        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        if self.use_sqlite:
            async with self._get_connection() as conn:
                cursor = await conn.execute(
                    "SELECT * FROM enhanced_targets WHERE last_seen < ?",
                    (cutoff.isoformat(),),
                )
                return [self._row_to_target(row) for row in cursor]
        else:
            inventory = await self.load_inventory()
            return inventory.get_stale_targets(hours)

    async def get_services_by_stack(self, stack_name: str) -> List[EnhancedService]:
        """Get services by stack name."""
        if self.use_sqlite:
            async with self._get_connection() as conn:
                cursor = await conn.execute(
                    "SELECT * FROM enhanced_services WHERE stack_name = ?",
                    (stack_name,),
                )
                return [self._row_to_service(row) for row in cursor]
        else:
            inventory = await self.load_inventory()
            return [
                service
                for service in inventory.services.values()
                if service.stack_name == stack_name
            ]

    async def search_targets(self, query: str) -> List[EnhancedTarget]:
        """Search targets by name or tags."""
        if self.use_sqlite:
            async with self._get_connection() as conn:
                cursor = await conn.execute(
                    """
                    SELECT * FROM enhanced_targets
                    WHERE name LIKE ? OR
                          description LIKE ? OR
                          EXISTS (
                              SELECT 1 FROM json_each(tags)
                              WHERE json_extract(value, '$') LIKE ?
                          )
                """,
                    (f"%{query}%", f"%{query}%", f"%{query}%"),
                )
                return [self._row_to_target(row) for row in cursor]
        else:
            inventory = await self.load_inventory()
            results = []
            for target in inventory.targets.values():
                if (
                    query.lower() in target.name.lower()
                    or (
                        target.description
                        and query.lower() in target.description.lower()
                    )
                    or any(query.lower() in tag.lower() for tag in target.tags)
                ):
                    results.append(target)
            return results

    def _row_to_target(self, row) -> EnhancedTarget:
        """Convert database row to EnhancedTarget."""
        from src.models.fleet_inventory import NodeType, Runtime, ConnectionMethod
        from src.models.enhanced_fleet_inventory import ContainerInfo

        target = EnhancedTarget(
            id=row["id"],
            name=row["name"],
            node_type=NodeType(row["node_type"]),
            host_id=row["host_id"],
            vmid=row["vmid"],
            status=row["status"],
            cpu_cores=row["cpu_cores"],
            memory_mb=row["memory_mb"],
            disk_gb=row["disk_gb"],
            ip_address=row["ip_address"],
            mac_address=row["mac_address"],
            runtime=Runtime(row["runtime"]),
            connection_method=ConnectionMethod(row["connection_method"]),
            role=NodeRole(row["role"]),
            description=row["description"],
            environment=json.loads(row["environment"] or "{}"),
            services=json.loads(row["services"] or "[]"),
            stacks=json.loads(row["stacks"] or "[]"),
            last_seen=row["last_seen"],
            last_health_check=row["last_health_check"],
            health_score=row["health_score"],
            created_at=row["created_at"],
            last_updated=row["last_updated"],
            is_managed=bool(row["is_managed"]),
            is_active=bool(row["is_active"]),
            tags=json.loads(row["tags"] or "[]"),
            custom_attributes=json.loads(row["custom_attributes"] or "{}"),
        )

        # Handle nested objects
        if row["resource_usage"]:
            from src.models.enhanced_fleet_inventory import ResourceUsage

            target.resource_usage = ResourceUsage(**json.loads(row["resource_usage"]))

        if row["security_posture"]:
            from src.models.enhanced_fleet_inventory import SecurityPosture

            target.security_posture = SecurityPosture(
                **json.loads(row["security_posture"])
            )

        if row["container_info"]:
            target.container_info = ContainerInfo(**json.loads(row["container_info"]))

        return target

    def _row_to_service(self, row) -> EnhancedService:
        """Convert database row to EnhancedService."""
        from src.models.fleet_inventory import ServiceStatus

        return EnhancedService(
            id=row["id"],
            name=row["name"],
            target_id=row["target_id"],
            service_type=row["service_type"],
            status=ServiceStatus(row["status"]),
            version=row["version"],
            port=row["port"],
            protocol=row["protocol"],
            config_path=row["config_path"],
            data_path=row["data_path"],
            health_endpoint=row["health_endpoint"],
            stack_name=row["stack_name"],
            depends_on=json.loads(row["depends_on"] or "[]"),
            environment=json.loads(row["environment"] or "{}"),
            cpu_limit=row["cpu_limit"],
            memory_limit=row["memory_limit"],
            restart_policy=row["restart_policy"],
            health_check_enabled=bool(row["health_check_enabled"]),
            health_check_interval=row["health_check_interval"],
            health_check_timeout=row["health_check_timeout"],
            health_check_retries=row["health_check_retries"],
            last_health_check=row["last_health_check"],
            health_status=row["health_status"],
            tls_enabled=bool(row["tls_enabled"]),
            tls_port=row["tls_port"],
            exposed_ports=json.loads(row["exposed_ports"] or "[]"),
            security_context=json.loads(row["security_context"] or "{}"),
            created_at=row["created_at"],
            last_checked=row["last_checked"],
            last_updated=row["last_updated"],
            is_monitored=bool(row["is_monitored"]),
            is_managed=bool(row["is_managed"]),
            tags=json.loads(row["tags"] or "[]"),
            custom_attributes=json.loads(row["custom_attributes"] or "{}"),
        )

    # Archive and maintenance methods
    async def archive_old_snapshots(self, days: int = 30) -> int:
        """Archive snapshots older than specified days."""

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        archived_count = 0

        async with self._get_connection() as conn:
            cursor = await conn.execute(
                "SELECT id FROM enhanced_snapshots WHERE created_at < ? AND is_archived = FALSE",
                (cutoff.isoformat(),),
            )

            for row in cursor:
                snapshot_id = row["id"]
                snapshot = await self.load_snapshot(snapshot_id)
                if snapshot:
                    # Archive to compressed file
                    archive_file = os.path.join(
                        self.archive_dir, f"{snapshot_id}.json.gz"
                    )
                    with gzip.open(archive_file, "wt", encoding="utf-8") as f:
                        json.dump(snapshot.to_dict(), f, indent=2)

                    # Mark as archived in database
                    await conn.execute(
                        "UPDATE enhanced_snapshots SET is_archived = TRUE WHERE id = ?",
                        (snapshot_id,),
                    )
                    archived_count += 1

        return archived_count

    async def cleanup_expired_snapshots(self) -> int:
        """Remove expired snapshots."""

        now = datetime.now(timezone.utc)
        cleaned_count = 0

        async with self._get_connection() as conn:
            cursor = await conn.execute(
                "SELECT id FROM enhanced_snapshots WHERE expires_at IS NOT NULL AND expires_at < ?",
                (now.isoformat(),),
            )

            for row in cursor:
                snapshot_id = row["id"]
                if await self.delete_snapshot(snapshot_id):
                    cleaned_count += 1

        return cleaned_count

    async def get_storage_stats(self) -> Dict[str, Any]:
        """Get storage statistics."""
        stats = {
            "database_size_bytes": 0,
            "snapshot_count": 0,
            "archived_snapshot_count": 0,
            "total_targets": 0,
            "total_services": 0,
            "total_stacks": 0,
        }

        # Database size
        if os.path.exists(self.db_path):
            stats["database_size_bytes"] = os.path.getsize(self.db_path)

        # Snapshot counts
        if self.use_sqlite:
            async with self._get_connection() as conn:
                # Total snapshots
                cursor = await conn.execute(
                    "SELECT COUNT(*) as count FROM enhanced_snapshots"
                )
                stats["snapshot_count"] = (await cursor.fetchone())["count"]

                # Archived snapshots
                cursor = await conn.execute(
                    "SELECT COUNT(*) as count FROM enhanced_snapshots WHERE is_archived = TRUE"
                )
                stats["archived_snapshot_count"] = (await cursor.fetchone())["count"]

                # Entity counts
                cursor = await conn.execute(
                    "SELECT COUNT(*) as count FROM enhanced_targets"
                )
                stats["total_targets"] = (await cursor.fetchone())["count"]

                cursor = await conn.execute(
                    "SELECT COUNT(*) as count FROM enhanced_services"
                )
                stats["total_services"] = (await cursor.fetchone())["count"]

                cursor = await conn.execute(
                    "SELECT COUNT(*) as count FROM enhanced_stacks"
                )
                stats["total_stacks"] = (await cursor.fetchone())["count"]

        return stats
