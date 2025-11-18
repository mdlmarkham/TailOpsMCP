"""Database backup and restore tools for PostgreSQL and MySQL.

Provides automated backup, restore, and scheduling functionality for
homelab database instances.
"""

from __future__ import annotations

import asyncio
import json
import os
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path
import subprocess
from asyncio import to_thread

from fastmcp import FastMCP
from src.utils.audit import AuditLogger
from src.auth.middleware import secure_tool
from src.server.utils import format_error
from pydantic import BaseModel


audit = AuditLogger()
logger = logging.getLogger(__name__)


class BackupConfig(BaseModel):
    """Configuration for database backups."""
    database_type: str  # postgresql, mysql
    host: str = "localhost"
    port: Optional[int] = None
    database: Optional[str] = None  # None means all databases
    username: str
    password: Optional[str] = None
    backup_path: str = "/var/backups/databases"
    retention_days: int = 7
    compress: bool = True


class BackupResult(BaseModel):
    """Result of a backup operation."""
    success: bool
    backup_file: Optional[str] = None
    size_bytes: Optional[int] = None
    duration_seconds: Optional[float] = None
    error: Optional[str] = None
    timestamp: datetime = None


class RestoreResult(BaseModel):
    """Result of a restore operation."""
    success: bool
    restored_database: Optional[str] = None
    error: Optional[str] = None
    duration_seconds: Optional[float] = None


async def backup_postgresql(
    host: str = "localhost",
    port: int = 5432,
    database: Optional[str] = None,
    username: str = "postgres",
    password: Optional[str] = None,
    backup_path: str = "/var/backups/databases",
    compress: bool = True
) -> Dict[str, Any]:
    """Backup PostgreSQL database(s).

    Args:
        host: Database host
        port: Database port
        database: Specific database to backup (None for all)
        username: Database username
        password: Database password (uses PGPASSWORD env var)
        backup_path: Path to store backups
        compress: Whether to compress the backup

    Returns:
        BackupResult with backup file path and metadata
    """
    start_time = datetime.now()
    timestamp = start_time.strftime("%Y%m%d_%H%M%S")

    # Ensure backup directory exists
    Path(backup_path).mkdir(parents=True, exist_ok=True)

    # Build backup filename
    db_name = database or "all_databases"
    backup_file = f"{backup_path}/postgresql_{db_name}_{timestamp}.sql"
    if compress:
        backup_file += ".gz"

    try:
        # Set up environment
        env = os.environ.copy()
        if password:
            env["PGPASSWORD"] = password

        # Build command
        if database:
            # Backup single database
            cmd = [
                "pg_dump",
                "-h", host,
                "-p", str(port),
                "-U", username,
                "-F", "c" if not compress else "c",  # custom format
                "-f", backup_file,
                database
            ]
        else:
            # Backup all databases
            cmd = [
                "pg_dumpall",
                "-h", host,
                "-p", str(port),
                "-U", username,
                "-f", backup_file
            ]

        # Add compression if needed
        if compress and not database:  # pg_dumpall doesn't support -F c
            cmd_str = " ".join(cmd) + f" | gzip > {backup_file}"
            result = await to_thread(
                subprocess.run,
                cmd_str,
                shell=True,
                env=env,
                capture_output=True,
                text=True,
                check=True
            )
        else:
            result = await to_thread(
                subprocess.run,
                cmd,
                env=env,
                capture_output=True,
                text=True,
                check=True
            )

        # Get backup file size
        size_bytes = os.path.getsize(backup_file)
        duration = (datetime.now() - start_time).total_seconds()

        backup_result = BackupResult(
            success=True,
            backup_file=backup_file,
            size_bytes=size_bytes,
            duration_seconds=duration,
            timestamp=start_time
        )

        audit.log("backup_postgresql", {
            "host": host,
            "database": database,
            "backup_file": backup_file
        }, {
            "success": True,
            "size_bytes": size_bytes,
            "duration_seconds": duration
        })

        return backup_result.dict()

    except subprocess.CalledProcessError as e:
        error_msg = f"Backup failed: {e.stderr}"
        backup_result = BackupResult(
            success=False,
            error=error_msg,
            timestamp=start_time
        )
        audit.log("backup_postgresql", {
            "host": host,
            "database": database
        }, {
            "success": False,
            "error": error_msg
        })
        return backup_result.dict()

    except Exception as e:
        error_msg = f"Backup failed: {str(e)}"
        backup_result = BackupResult(
            success=False,
            error=error_msg,
            timestamp=start_time
        )
        audit.log("backup_postgresql", {
            "host": host,
            "database": database
        }, {
            "success": False,
            "error": error_msg
        })
        return backup_result.dict()


async def backup_mysql(
    host: str = "localhost",
    port: int = 3306,
    database: Optional[str] = None,
    username: str = "root",
    password: Optional[str] = None,
    backup_path: str = "/var/backups/databases",
    compress: bool = True
) -> Dict[str, Any]:
    """Backup MySQL/MariaDB database(s).

    Args:
        host: Database host
        port: Database port
        database: Specific database to backup (None for all)
        username: Database username
        password: Database password
        backup_path: Path to store backups
        compress: Whether to compress the backup

    Returns:
        BackupResult with backup file path and metadata
    """
    start_time = datetime.now()
    timestamp = start_time.strftime("%Y%m%d_%H%M%S")

    # Ensure backup directory exists
    Path(backup_path).mkdir(parents=True, exist_ok=True)

    # Build backup filename
    db_name = database or "all_databases"
    backup_file = f"{backup_path}/mysql_{db_name}_{timestamp}.sql"
    if compress:
        backup_file += ".gz"

    try:
        # Build command
        cmd = [
            "mysqldump",
            "-h", host,
            "-P", str(port),
            "-u", username,
        ]

        if password:
            cmd.extend([f"-p{password}"])

        # Add options
        cmd.extend([
            "--single-transaction",
            "--quick",
            "--lock-tables=false",
        ])

        if database:
            cmd.append(database)
        else:
            cmd.append("--all-databases")

        # Execute backup with optional compression
        if compress:
            cmd_str = " ".join(cmd) + f" | gzip > {backup_file}"
            result = await to_thread(
                subprocess.run,
                cmd_str,
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
        else:
            cmd.extend(["-r", backup_file])
            result = await to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                check=True
            )

        # Get backup file size
        size_bytes = os.path.getsize(backup_file)
        duration = (datetime.now() - start_time).total_seconds()

        backup_result = BackupResult(
            success=True,
            backup_file=backup_file,
            size_bytes=size_bytes,
            duration_seconds=duration,
            timestamp=start_time
        )

        audit.log("backup_mysql", {
            "host": host,
            "database": database,
            "backup_file": backup_file
        }, {
            "success": True,
            "size_bytes": size_bytes,
            "duration_seconds": duration
        })

        return backup_result.dict()

    except subprocess.CalledProcessError as e:
        error_msg = f"Backup failed: {e.stderr}"
        backup_result = BackupResult(
            success=False,
            error=error_msg,
            timestamp=start_time
        )
        audit.log("backup_mysql", {
            "host": host,
            "database": database
        }, {
            "success": False,
            "error": error_msg
        })
        return backup_result.dict()

    except Exception as e:
        error_msg = f"Backup failed: {str(e)}"
        backup_result = BackupResult(
            success=False,
            error=error_msg,
            timestamp=start_time
        )
        audit.log("backup_mysql", {
            "host": host,
            "database": database
        }, {
            "success": False,
            "error": error_msg
        })
        return backup_result.dict()


async def restore_postgresql(
    backup_file: str,
    host: str = "localhost",
    port: int = 5432,
    database: Optional[str] = None,
    username: str = "postgres",
    password: Optional[str] = None,
    drop_existing: bool = False
) -> Dict[str, Any]:
    """Restore PostgreSQL database from backup.

    Args:
        backup_file: Path to backup file
        host: Database host
        port: Database port
        database: Target database name (for single DB restores)
        username: Database username
        password: Database password
        drop_existing: Whether to drop existing database before restore

    Returns:
        RestoreResult with success status and metadata
    """
    start_time = datetime.now()

    if not os.path.exists(backup_file):
        return RestoreResult(
            success=False,
            error=f"Backup file not found: {backup_file}"
        ).dict()

    try:
        env = os.environ.copy()
        if password:
            env["PGPASSWORD"] = password

        # Determine if it's a custom format or SQL dump
        is_custom_format = backup_file.endswith(".dump") or not backup_file.endswith((".sql", ".sql.gz"))

        if is_custom_format and database:
            # Restore custom format to specific database
            cmd = [
                "pg_restore",
                "-h", host,
                "-p", str(port),
                "-U", username,
                "-d", database,
            ]
            if drop_existing:
                cmd.append("-c")  # Clean (drop) database objects before recreating
            cmd.append(backup_file)

        elif backup_file.endswith(".gz"):
            # Restore gzipped SQL dump
            if database:
                cmd_str = f"gunzip -c {backup_file} | psql -h {host} -p {port} -U {username} -d {database}"
            else:
                cmd_str = f"gunzip -c {backup_file} | psql -h {host} -p {port} -U {username}"

            result = await to_thread(
                subprocess.run,
                cmd_str,
                shell=True,
                env=env,
                capture_output=True,
                text=True,
                check=True
            )
            duration = (datetime.now() - start_time).total_seconds()
            restore_result = RestoreResult(
                success=True,
                restored_database=database or "all",
                duration_seconds=duration
            )
            audit.log("restore_postgresql", {
                "backup_file": backup_file,
                "database": database
            }, {
                "success": True,
                "duration_seconds": duration
            })
            return restore_result.dict()
        else:
            # Restore plain SQL dump
            cmd = [
                "psql",
                "-h", host,
                "-p", str(port),
                "-U", username,
            ]
            if database:
                cmd.extend(["-d", database])
            cmd.extend(["-f", backup_file])

        result = await to_thread(
            subprocess.run,
            cmd,
            env=env,
            capture_output=True,
            text=True,
            check=True
        )

        duration = (datetime.now() - start_time).total_seconds()

        restore_result = RestoreResult(
            success=True,
            restored_database=database or "all",
            duration_seconds=duration
        )

        audit.log("restore_postgresql", {
            "backup_file": backup_file,
            "database": database
        }, {
            "success": True,
            "duration_seconds": duration
        })

        return restore_result.dict()

    except subprocess.CalledProcessError as e:
        error_msg = f"Restore failed: {e.stderr}"
        restore_result = RestoreResult(
            success=False,
            error=error_msg
        )
        audit.log("restore_postgresql", {
            "backup_file": backup_file,
            "database": database
        }, {
            "success": False,
            "error": error_msg
        })
        return restore_result.dict()

    except Exception as e:
        error_msg = f"Restore failed: {str(e)}"
        restore_result = RestoreResult(
            success=False,
            error=error_msg
        )
        audit.log("restore_postgresql", {
            "backup_file": backup_file,
            "database": database
        }, {
            "success": False,
            "error": error_msg
        })
        return restore_result.dict()


async def restore_mysql(
    backup_file: str,
    host: str = "localhost",
    port: int = 3306,
    database: Optional[str] = None,
    username: str = "root",
    password: Optional[str] = None
) -> Dict[str, Any]:
    """Restore MySQL/MariaDB database from backup.

    Args:
        backup_file: Path to backup file
        host: Database host
        port: Database port
        database: Target database name
        username: Database username
        password: Database password

    Returns:
        RestoreResult with success status and metadata
    """
    start_time = datetime.now()

    if not os.path.exists(backup_file):
        return RestoreResult(
            success=False,
            error=f"Backup file not found: {backup_file}"
        ).dict()

    try:
        cmd = [
            "mysql",
            "-h", host,
            "-P", str(port),
            "-u", username,
        ]

        if password:
            cmd.append(f"-p{password}")

        if database:
            cmd.append(database)

        # Handle compressed backups
        if backup_file.endswith(".gz"):
            cmd_str = " ".join(cmd) + f" < <(gunzip -c {backup_file})"
            result = await to_thread(
                subprocess.run,
                cmd_str,
                shell=True,
                executable="/bin/bash",
                capture_output=True,
                text=True,
                check=True
            )
        else:
            cmd_str = " ".join(cmd) + f" < {backup_file}"
            result = await to_thread(
                subprocess.run,
                cmd_str,
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )

        duration = (datetime.now() - start_time).total_seconds()

        restore_result = RestoreResult(
            success=True,
            restored_database=database or "all",
            duration_seconds=duration
        )

        audit.log("restore_mysql", {
            "backup_file": backup_file,
            "database": database
        }, {
            "success": True,
            "duration_seconds": duration
        })

        return restore_result.dict()

    except subprocess.CalledProcessError as e:
        error_msg = f"Restore failed: {e.stderr}"
        restore_result = RestoreResult(
            success=False,
            error=error_msg
        )
        audit.log("restore_mysql", {
            "backup_file": backup_file,
            "database": database
        }, {
            "success": False,
            "error": error_msg
        })
        return restore_result.dict()

    except Exception as e:
        error_msg = f"Restore failed: {str(e)}"
        restore_result = RestoreResult(
            success=False,
            error=error_msg
        )
        audit.log("restore_mysql", {
            "backup_file": backup_file,
            "database": database
        }, {
            "success": False,
            "error": error_msg
        })
        return restore_result.dict()


async def list_backups(
    backup_path: str = "/var/backups/databases",
    database_type: Optional[str] = None
) -> List[Dict[str, Any]]:
    """List available database backups.

    Args:
        backup_path: Path to backup directory
        database_type: Filter by database type (postgresql, mysql)

    Returns:
        List of backup files with metadata
    """
    backups = []

    try:
        if not os.path.exists(backup_path):
            return backups

        for file in os.listdir(backup_path):
            file_path = os.path.join(backup_path, file)

            # Filter by database type if specified
            if database_type:
                if database_type == "postgresql" and not file.startswith("postgresql_"):
                    continue
                if database_type == "mysql" and not file.startswith("mysql_"):
                    continue

            # Get file metadata
            stat = os.stat(file_path)
            backups.append({
                "filename": file,
                "path": file_path,
                "size_bytes": stat.st_size,
                "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat()
            })

        # Sort by creation time (newest first)
        backups.sort(key=lambda x: x["created_at"], reverse=True)

        audit.log("list_backups", {
            "backup_path": backup_path,
            "database_type": database_type
        }, {
            "success": True,
            "count": len(backups)
        })

        return backups

    except Exception as e:
        audit.log("list_backups", {
            "backup_path": backup_path,
            "database_type": database_type
        }, {
            "success": False,
            "error": str(e)
        })
        return backups


async def cleanup_old_backups(
    backup_path: str = "/var/backups/databases",
    retention_days: int = 7,
    database_type: Optional[str] = None,
    dry_run: bool = True
) -> Dict[str, Any]:
    """Clean up old database backups based on retention policy.

    Args:
        backup_path: Path to backup directory
        retention_days: Number of days to retain backups
        database_type: Filter by database type (postgresql, mysql)
        dry_run: If True, only list files that would be deleted

    Returns:
        Dict with cleanup results
    """
    from datetime import timedelta

    deleted_files = []
    errors = []
    total_space_freed = 0

    try:
        if not os.path.exists(backup_path):
            return {
                "success": True,
                "dry_run": dry_run,
                "deleted_count": 0,
                "space_freed_bytes": 0,
                "deleted_files": []
            }

        cutoff_time = datetime.now() - timedelta(days=retention_days)

        for file in os.listdir(backup_path):
            file_path = os.path.join(backup_path, file)

            # Filter by database type if specified
            if database_type:
                if database_type == "postgresql" and not file.startswith("postgresql_"):
                    continue
                if database_type == "mysql" and not file.startswith("mysql_"):
                    continue

            # Check file age
            stat = os.stat(file_path)
            file_time = datetime.fromtimestamp(stat.st_mtime)

            if file_time < cutoff_time:
                if not dry_run:
                    try:
                        os.remove(file_path)
                        total_space_freed += stat.st_size
                        deleted_files.append(file)
                    except Exception as e:
                        errors.append(f"Failed to delete {file}: {str(e)}")
                else:
                    total_space_freed += stat.st_size
                    deleted_files.append(file)

        result = {
            "success": len(errors) == 0,
            "dry_run": dry_run,
            "deleted_count": len(deleted_files),
            "space_freed_bytes": total_space_freed,
            "deleted_files": deleted_files,
            "errors": errors
        }

        audit.log("cleanup_old_backups", {
            "backup_path": backup_path,
            "retention_days": retention_days,
            "database_type": database_type,
            "dry_run": dry_run
        }, result)

        return result

    except Exception as e:
        audit.log("cleanup_old_backups", {
            "backup_path": backup_path,
            "retention_days": retention_days
        }, {
            "success": False,
            "error": str(e)
        })
        return {
            "success": False,
            "error": str(e),
            "deleted_files": deleted_files,
            "errors": errors
        }


def register_tools(mcp: FastMCP):
    """Register database backup and restore tools with MCP instance."""

    @mcp.tool()
    @secure_tool("database:backup")
    async def backup_database(
        database_type: str,
        host: str = "localhost",
        port: int = None,
        database: str = None,
        username: str = None,
        password: str = None,
        backup_path: str = "/var/backups/databases",
        compress: bool = True
    ) -> dict:
        """Backup PostgreSQL or MySQL database.

        Args:
            database_type: Database type (postgresql or mysql)
            host: Database host (default: localhost)
            port: Database port (default: 5432 for PostgreSQL, 3306 for MySQL)
            database: Specific database to backup (None for all databases)
            username: Database username (default: postgres/root)
            password: Database password (optional, will use environment variable if not provided)
            backup_path: Path to store backups (default: /var/backups/databases)
            compress: Whether to compress the backup (default: True)

        Returns:
            BackupResult with backup file path and metadata
        """
        try:
            if database_type == "postgresql":
                result = await backup_postgresql(
                    host=host,
                    port=port or 5432,
                    database=database,
                    username=username or "postgres",
                    password=password,
                    backup_path=backup_path,
                    compress=compress
                )
            elif database_type == "mysql":
                result = await backup_mysql(
                    host=host,
                    port=port or 3306,
                    database=database,
                    username=username or "root",
                    password=password,
                    backup_path=backup_path,
                    compress=compress
                )
            else:
                return {"error": f"Invalid database_type: {database_type}. Must be 'postgresql' or 'mysql'"}

            return result
        except Exception as e:
            return format_error(e, "backup_database")

    @mcp.tool()
    @secure_tool("database:restore")
    async def restore_database(
        database_type: str,
        backup_file: str,
        host: str = "localhost",
        port: int = None,
        database: str = None,
        username: str = None,
        password: str = None,
        drop_existing: bool = False
    ) -> dict:
        """Restore PostgreSQL or MySQL database from backup.

        Args:
            database_type: Database type (postgresql or mysql)
            backup_file: Path to backup file
            host: Database host (default: localhost)
            port: Database port (default: 5432 for PostgreSQL, 3306 for MySQL)
            database: Target database name (required for single database restores)
            username: Database username (default: postgres/root)
            password: Database password (optional)
            drop_existing: Whether to drop existing database before restore (PostgreSQL only)

        Returns:
            RestoreResult with success status and metadata
        """
        try:
            if database_type == "postgresql":
                result = await restore_postgresql(
                    backup_file=backup_file,
                    host=host,
                    port=port or 5432,
                    database=database,
                    username=username or "postgres",
                    password=password,
                    drop_existing=drop_existing
                )
            elif database_type == "mysql":
                result = await restore_mysql(
                    backup_file=backup_file,
                    host=host,
                    port=port or 3306,
                    database=database,
                    username=username or "root",
                    password=password
                )
            else:
                return {"error": f"Invalid database_type: {database_type}. Must be 'postgresql' or 'mysql'"}

            return result
        except Exception as e:
            return format_error(e, "restore_database")

    @mcp.tool()
    @secure_tool("database:read")
    async def list_database_backups(
        backup_path: str = "/var/backups/databases",
        database_type: str = None
    ) -> list:
        """List available database backups.

        Args:
            backup_path: Path to backup directory (default: /var/backups/databases)
            database_type: Filter by database type (postgresql or mysql, optional)

        Returns:
            List of backup files with metadata
        """
        try:
            result = await list_backups(
                backup_path=backup_path,
                database_type=database_type
            )
            return result
        except Exception as e:
            return format_error(e, "list_database_backups")

    @mcp.tool()
    @secure_tool("database:admin")
    async def cleanup_database_backups(
        backup_path: str = "/var/backups/databases",
        retention_days: int = 7,
        database_type: str = None,
        dry_run: bool = True
    ) -> dict:
        """Clean up old database backups based on retention policy.

        Args:
            backup_path: Path to backup directory (default: /var/backups/databases)
            retention_days: Number of days to retain backups (default: 7)
            database_type: Filter by database type (postgresql or mysql, optional)
            dry_run: If True, only list files that would be deleted (default: True)

        Returns:
            Dict with cleanup results including deleted files and space freed
        """
        try:
            result = await cleanup_old_backups(
                backup_path=backup_path,
                retention_days=retention_days,
                database_type=database_type,
                dry_run=dry_run
            )
            return result
        except Exception as e:
            return format_error(e, "cleanup_database_backups")

    logger.info("Registered 4 database tools")
