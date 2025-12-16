"""
Event persistence and storage system for TailOpsMCP observability.

This module provides persistent event storage with indexing, efficient querying,
and data management capabilities for the observability platform.
"""

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from src.models.event_models import (
    SystemEvent,
    EventType,
    EventSeverity,
    EventSource,
    EventCategory,
    EventStatus,
    EventFilters,
    EventStatistics,
    ResourceUsage,
)
from src.utils.logging_config import get_logger


class EventStore:
    """Persistent event storage with indexing."""

    def __init__(self, database_path: Optional[str] = None):
        self.database_path = database_path or os.getenv(
            "SYSTEMMANAGER_EVENT_DB", "./data/events.db"
        )
        self.logger = get_logger("event_store")
        self._lock = threading.Lock()

        # Ensure directory exists
        os.makedirs(os.path.dirname(self.database_path), exist_ok=True)

        # Initialize database
        self._init_database()

    def _init_database(self) -> None:
        """Initialize the event database with schema and indexes."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Create events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    timestamp DATETIME NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source TEXT NOT NULL,
                    target TEXT,
                    category TEXT NOT NULL,
                    status TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    details TEXT, -- JSON
                    correlation_id TEXT,
                    user_id TEXT,
                    session_id TEXT,
                    tags TEXT, -- JSON array
                    health_score REAL,
                    resource_usage TEXT, -- JSON
                    location TEXT,
                    component TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create indexes for performance
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)",
                "CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)",
                "CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)",
                "CREATE INDEX IF NOT EXISTS idx_events_target ON events(target)",
                "CREATE INDEX IF NOT EXISTS idx_events_category ON events(category)",
                "CREATE INDEX IF NOT EXISTS idx_events_status ON events(status)",
                "CREATE INDEX IF NOT EXISTS idx_events_correlation_id ON events(correlation_id)",
                "CREATE INDEX IF NOT EXISTS idx_events_user_id ON events(user_id)",
                "CREATE INDEX IF NOT EXISTS idx_events_health_score ON events(health_score)",
                "CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at)",
                "CREATE INDEX IF NOT EXISTS idx_events_title_search ON events(title)",
            ]

            for index_sql in indexes:
                cursor.execute(index_sql)

            # Create full-text search index for title and description
            cursor.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
                    title, description, details, tags, content=events, content_rowid=rowid
                )
            """)

            conn.commit()
            self.logger.info(f"Event database initialized at {self.database_path}")

    @contextmanager
    def get_connection(self):
        """Get a database connection with proper error handling."""
        conn = None
        try:
            conn = sqlite3.connect(self.database_path, timeout=30.0)
            conn.row_factory = sqlite3.Row
            yield conn
        except sqlite3.Error as e:
            self.logger.error(f"Database error: {e}")
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()

    async def store_event(self, event: SystemEvent) -> str:
        """Store a single event."""
        with self._lock:
            try:
                with self.get_connection() as conn:
                    cursor = conn.cursor()

                    # Prepare event data for storage
                    event_data = self._prepare_event_data(event)

                    # Insert event
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO events (
                            id, timestamp, event_type, severity, source, target, category, status,
                            title, description, details, correlation_id, user_id, session_id,
                            tags, health_score, resource_usage, location, component, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    """,
                        event_data,
                    )

                    # Update full-text search index
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO events_fts (rowid, title, description, details, tags)
                        VALUES (?, ?, ?, ?, ?)
                    """,
                        (
                            event.event_id,
                            event.title,
                            event.description,
                            json.dumps(event.details),
                            json.dumps(event.metadata.tags),
                        ),
                    )

                    conn.commit()
                    self.logger.debug(f"Stored event {event.event_id}")
                    return event.event_id

            except Exception as e:
                self.logger.error(f"Failed to store event {event.event_id}: {e}")
                raise

    async def store_events(self, events: List[SystemEvent]) -> List[str]:
        """Store multiple events in a single transaction."""
        with self._lock:
            if not events:
                return []

            try:
                with self.get_connection() as conn:
                    cursor = conn.cursor()

                    event_ids = []

                    for event in events:
                        # Prepare event data
                        event_data = self._prepare_event_data(event)

                        # Insert event
                        cursor.execute(
                            """
                            INSERT OR REPLACE INTO events (
                                id, timestamp, event_type, severity, source, target, category, status,
                                title, description, details, correlation_id, user_id, session_id,
                                tags, health_score, resource_usage, location, component, updated_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                        """,
                            event_data,
                        )

                        # Update full-text search index
                        cursor.execute(
                            """
                            INSERT OR REPLACE INTO events_fts (rowid, title, description, details, tags)
                            VALUES (?, ?, ?, ?, ?)
                        """,
                            (
                                event.event_id,
                                event.title,
                                event.description,
                                json.dumps(event.details),
                                json.dumps(event.metadata.tags),
                            ),
                        )

                        event_ids.append(event.event_id)

                    conn.commit()
                    self.logger.info(f"Stored {len(events)} events")
                    return event_ids

            except Exception as e:
                self.logger.error(f"Failed to store {len(events)} events: {e}")
                raise

    def _prepare_event_data(self, event: SystemEvent) -> Tuple:
        """Prepare event data for database storage."""
        return (
            event.event_id,
            event.timestamp,
            event.event_type.value,
            event.severity.value,
            event.source.value,
            event.target,
            event.category.value,
            event.status.value,
            event.title,
            event.description,
            json.dumps(event.details),
            event.metadata.correlation_id,
            event.metadata.user_id,
            event.metadata.session_id,
            json.dumps(event.metadata.tags),
            event.health_score,
            json.dumps(event.resource_usage.__dict__) if event.resource_usage else None,
            event.location,
            event.component,
        )

    async def get_events(
        self, filters: Optional[EventFilters] = None, limit: Optional[int] = None
    ) -> List[SystemEvent]:
        """Get events based on filters."""
        filters = filters or EventFilters()
        limit = limit or filters.limit

        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Build query
                query, params = self._build_query(filters, limit)

                # Execute query
                cursor.execute(query, params)
                rows = cursor.fetchall()

                # Convert to events
                events = []
                for row in rows:
                    event = self._row_to_event(row)
                    if event:
                        events.append(event)

                self.logger.debug(f"Retrieved {len(events)} events with filters")
                return events

        except Exception as e:
            self.logger.error(f"Failed to retrieve events: {e}")
            raise

    def _build_query(
        self, filters: EventFilters, limit: Optional[int]
    ) -> Tuple[str, List]:
        """Build SQL query with filters."""
        base_query = "SELECT * FROM events WHERE 1=1"
        params = []

        # Add filters
        if filters.event_types:
            placeholders = ",".join(["?"] * len(filters.event_types))
            base_query += f" AND event_type IN ({placeholders})"
            params.extend([et.value for et in filters.event_types])

        if filters.severities:
            placeholders = ",".join(["?"] * len(filters.severities))
            base_query += f" AND severity IN ({placeholders})"
            params.extend([es.value for es in filters.severities])

        if filters.sources:
            placeholders = ",".join(["?"] * len(filters.sources))
            base_query += f" AND source IN ({placeholders})"
            params.extend([es.value for es in filters.sources])

        if filters.categories:
            placeholders = ",".join(["?"] * len(filters.categories))
            base_query += f" AND category IN ({placeholders})"
            params.extend([ec.value for ec in filters.categories])

        if filters.targets:
            placeholders = ",".join(["?"] * len(filters.targets))
            base_query += f" AND target IN ({placeholders})"
            params.extend(filters.targets)

        if filters.status:
            placeholders = ",".join(["?"] * len(filters.status))
            base_query += f" AND status IN ({placeholders})"
            params.extend([es.value for es in filters.status])

        if filters.start_time:
            base_query += " AND timestamp >= ?"
            params.append(filters.start_time.isoformat())

        if filters.end_time:
            base_query += " AND timestamp <= ?"
            params.append(filters.end_time.isoformat())

        if filters.min_health_score is not None:
            base_query += " AND health_score >= ?"
            params.append(filters.min_health_score)

        if filters.max_health_score is not None:
            base_query += " AND health_score <= ?"
            params.append(filters.max_health_score)

        if filters.search_text:
            base_query += (
                " AND id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)"
            )
            params.append(filters.search_text)

        # Add ordering and limit
        base_query += " ORDER BY timestamp DESC"

        if limit:
            base_query += " LIMIT ?"
            params.append(limit)

        if filters.offset:
            base_query += " OFFSET ?"
            params.append(filters.offset)

        return base_query, params

    def _row_to_event(self, row: sqlite3.Row) -> Optional[SystemEvent]:
        """Convert database row to SystemEvent."""
        try:
            # Parse JSON fields
            details = json.loads(row["details"]) if row["details"] else {}
            tags = json.loads(row["tags"]) if row["tags"] else []
            resource_usage_data = (
                json.loads(row["resource_usage"]) if row["resource_usage"] else None
            )

            # Create resource usage
            resource_usage = None
            if resource_usage_data:
                resource_usage = ResourceUsage(**resource_usage_data)

            # Create metadata
            from src.models.event_models import EventMetadata

            metadata = EventMetadata(
                correlation_id=row["correlation_id"],
                user_id=row["user_id"],
                session_id=row["session_id"],
                tags=tags,
            )

            # Create event
            event = SystemEvent(
                event_id=row["id"],
                timestamp=datetime.fromisoformat(
                    row["timestamp"].replace("Z", "+00:00")
                ),
                event_type=EventType(row["event_type"]),
                severity=EventSeverity(row["severity"]),
                source=EventSource(row["source"]),
                target=row["target"],
                category=EventCategory(row["category"]),
                status=EventStatus(row["status"]),
                title=row["title"],
                description=row["description"],
                details=details,
                health_score=row["health_score"],
                resource_usage=resource_usage,
                metadata=metadata,
                location=row["location"],
                component=row["component"],
            )

            return event

        except Exception as e:
            self.logger.error(f"Failed to convert row to event: {e}")
            return None

    async def get_events_by_time_range(
        self, start: datetime, end: datetime, limit: Optional[int] = None
    ) -> List[SystemEvent]:
        """Get events within a time range."""
        filters = EventFilters(start_time=start, end_time=end, limit=limit)
        return await self.get_events(filters)

    async def get_events_by_source(
        self, source: str, hours: int = 24, limit: Optional[int] = None
    ) -> List[SystemEvent]:
        """Get events from a specific source within time range."""
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)

        filters = EventFilters(
            sources=[EventSource(source)],
            start_time=start_time,
            end_time=end_time,
            limit=limit,
        )
        return await self.get_events(filters)

    async def get_events_by_target(
        self, target: str, hours: int = 24, limit: Optional[int] = None
    ) -> List[SystemEvent]:
        """Get events for a specific target within time range."""
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)

        filters = EventFilters(
            targets=[target], start_time=start_time, end_time=end_time, limit=limit
        )
        return await self.get_events(filters)

    async def search_events(
        self, query: str, hours: int = 24, limit: Optional[int] = None
    ) -> List[SystemEvent]:
        """Search events using full-text search."""
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)

        filters = EventFilters(
            search_text=query, start_time=start_time, end_time=end_time, limit=limit
        )
        return await self.get_events(filters)

    async def delete_old_events(self, before_date: datetime) -> int:
        """Delete events older than specified date."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Delete from events table
                cursor.execute(
                    "DELETE FROM events WHERE timestamp < ?", (before_date.isoformat(),)
                )
                deleted_count = cursor.rowcount

                # Delete from FTS index (SQLite handles this automatically for content table)
                conn.commit()

                self.logger.info(
                    f"Deleted {deleted_count} events older than {before_date}"
                )
                return deleted_count

        except Exception as e:
            self.logger.error(f"Failed to delete old events: {e}")
            raise

    async def get_statistics(self, hours: int = 24) -> EventStatistics:
        """Get event statistics for the specified time range."""
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)

        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Basic counts
                cursor.execute(
                    """
                    SELECT COUNT(*) as total_events,
                           COUNT(DISTINCT source) as unique_sources,
                           COUNT(DISTINCT target) as unique_targets,
                           COUNT(DISTINCT user_id) as unique_users
                    FROM events
                    WHERE timestamp >= ? AND timestamp <= ?
                """,
                    (start_time.isoformat(), end_time.isoformat()),
                )

                row = cursor.fetchone()
                stats = EventStatistics(
                    total_events=row["total_events"],
                    unique_sources=row["unique_sources"],
                    unique_targets=row["unique_targets"],
                    unique_users=row["unique_users"],
                )

                # Events by type
                cursor.execute(
                    """
                    SELECT event_type, COUNT(*) as count
                    FROM events
                    WHERE timestamp >= ? AND timestamp <= ?
                    GROUP BY event_type
                """,
                    (start_time.isoformat(), end_time.isoformat()),
                )

                for row in cursor.fetchall():
                    try:
                        event_type = EventType(row["event_type"])
                        stats.events_by_type[event_type] = row["count"]
                    except ValueError:
                        pass  # Skip unknown event types

                # Events by severity
                cursor.execute(
                    """
                    SELECT severity, COUNT(*) as count
                    FROM events
                    WHERE timestamp >= ? AND timestamp <= ?
                    GROUP BY severity
                """,
                    (start_time.isoformat(), end_time.isoformat()),
                )

                for row in cursor.fetchall():
                    try:
                        severity = EventSeverity(row["severity"])
                        stats.events_by_severity[severity] = row["count"]

                        # Update severity-specific counts
                        if severity == EventSeverity.CRITICAL:
                            stats.critical_events = row["count"]
                        elif severity == EventSeverity.ERROR:
                            stats.error_events = row["count"]
                        elif severity == EventSeverity.WARNING:
                            stats.warning_events = row["count"]
                        elif severity == EventSeverity.INFO:
                            stats.info_events = row["count"]
                        elif severity == EventSeverity.DEBUG:
                            stats.debug_events = row["count"]
                    except ValueError:
                        pass

                # Events by source
                cursor.execute(
                    """
                    SELECT source, COUNT(*) as count
                    FROM events
                    WHERE timestamp >= ? AND timestamp <= ?
                    GROUP BY source
                """,
                    (start_time.isoformat(), end_time.isoformat()),
                )

                for row in cursor.fetchall():
                    try:
                        source = EventSource(row["source"])
                        stats.events_by_source[source] = row["count"]
                    except ValueError:
                        pass

                # Events by category
                cursor.execute(
                    """
                    SELECT category, COUNT(*) as count
                    FROM events
                    WHERE timestamp >= ? AND timestamp <= ?
                    GROUP BY category
                """,
                    (start_time.isoformat(), end_time.isoformat()),
                )

                for row in cursor.fetchall():
                    try:
                        category = EventCategory(row["category"])
                        stats.events_by_category[category] = row["count"]
                    except ValueError:
                        pass

                # Health score statistics
                cursor.execute(
                    """
                    SELECT AVG(health_score) as avg_score,
                           MIN(health_score) as min_score,
                           MAX(health_score) as max_score
                    FROM events
                    WHERE timestamp >= ? AND timestamp <= ?
                    AND health_score IS NOT NULL
                """,
                    (start_time.isoformat(), end_time.isoformat()),
                )

                health_row = cursor.fetchone()
                if health_row and health_row["avg_score"]:
                    stats.avg_health_score = health_row["avg_score"]
                    stats.min_health_score = health_row["min_score"]
                    stats.max_health_score = health_row["max_score"]

                return stats

        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            raise

    async def cleanup_and_maintain(self, retention_days: int = 90) -> Dict[str, int]:
        """Perform database maintenance and cleanup."""
        results = {
            "deleted_old_events": 0,
            "vacuum_completed": False,
            "analyze_completed": False,
        }

        try:
            # Delete old events
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
            results["deleted_old_events"] = await self.delete_old_events(cutoff_date)

            # Vacuum database
            with self.get_connection() as conn:
                conn.execute("VACUUM")
                results["vacuum_completed"] = True

                # Analyze for query optimization
                conn.execute("ANALYZE")
                results["analyze_completed"] = True

            self.logger.info(f"Database maintenance completed: {results}")
            return results

        except Exception as e:
            self.logger.error(f"Database maintenance failed: {e}")
            raise

    async def backup_database(self, backup_path: str) -> bool:
        """Create a backup of the event database."""
        try:
            import shutil

            # Ensure backup directory exists
            os.makedirs(os.path.dirname(backup_path), exist_ok=True)

            # Create backup
            shutil.copy2(self.database_path, backup_path)

            self.logger.info(f"Database backup created at {backup_path}")
            return True

        except Exception as e:
            self.logger.error(f"Database backup failed: {e}")
            return False


class EventIndex:
    """Event indexing for fast queries."""

    def __init__(self, event_store: EventStore):
        self.event_store = event_store
        self.logger = get_logger("event_index")

    async def create_index(self, field: str) -> None:
        """Create an index on a specific field."""
        if field not in [
            "timestamp",
            "event_type",
            "severity",
            "source",
            "target",
            "category",
            "status",
        ]:
            raise ValueError(f"Cannot index field: {field}")

        try:
            with self.event_store.get_connection() as conn:
                cursor = conn.cursor()
                index_name = f"idx_events_{field}"
                cursor.execute(
                    f"CREATE INDEX IF NOT EXISTS {index_name} ON events({field})"
                )
                conn.commit()

                self.logger.info(f"Created index on {field}")

        except Exception as e:
            self.logger.error(f"Failed to create index on {field}: {e}")
            raise

    async def query_events(self, filters: EventFilters) -> List[SystemEvent]:
        """Query events using indexes."""
        return await self.event_store.get_events(filters)

    async def get_event_statistics(self, time_range_hours: int = 24) -> Dict[str, Any]:
        """Get event statistics with indexing."""
        stats = await self.event_store.get_statistics(time_range_hours)
        return stats.to_dict()


# Global instances
_event_store_instance = None


def get_event_store() -> EventStore:
    """Get the global event store instance."""
    global _event_store_instance
    if _event_store_instance is None:
        _event_store_instance = EventStore()
    return _event_store_instance


def get_event_index() -> EventIndex:
    """Get the global event index instance."""
    return EventIndex(get_event_store())


async def initialize_event_storage() -> None:
    """Initialize the event storage system."""
    try:
        store = get_event_store()
        await store.cleanup_and_maintain()
        get_logger("event_storage").info("Event storage system initialized")
    except Exception as e:
        get_logger("event_storage").error(f"Failed to initialize event storage: {e}")
        raise
