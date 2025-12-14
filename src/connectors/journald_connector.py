"""
Journald Connector for Remote Log Access

Provides comprehensive journald log access via SSH without requiring agent installation.
Supports log retrieval, filtering, and real-time log following.
"""

import asyncio
import json
import re
import logging
from typing import Dict, List, Optional, Any, AsyncIterator
from datetime import datetime, timedelta
from dataclasses import dataclass

from src.connectors.remote_agent_connector import (
    RemoteAgentConnector, LogEntry, OperationResult
)
from src.services.remote_operation_executor import (
    ResilientRemoteOperation, resilient_operation, OperationType
)
from src.utils.errors import SystemManagerError


logger = logging.getLogger(__name__)


@dataclass
class JournalEntry:
    """Enhanced journald entry with structured fields."""
    timestamp: datetime
    priority: int
    level: str
    message: str
    unit: Optional[str] = None
    hostname: Optional[str] = None
    syslog_identifier: Optional[str] = None
    process_id: Optional[int] = None
    user_id: Optional[int] = None
    group_id: Optional[int] = None
    session_id: Optional[str] = None
    journal_cursor: Optional[str] = None
    fields: Dict[str, Any] = None

    def __post_init__(self):
        if self.fields is None:
            self.fields = {}


class JournaldConnector(RemoteAgentConnector):
    """Journald log access via SSH.
    
    Provides agent-like journald functionality without requiring agent installation.
    Supports log retrieval, filtering, and real-time following.
    """
    
    def __init__(self, target, connection):
        """Initialize journald connector.
        
        Args:
            target: Target connection configuration
            connection: SSH connection instance
        """
        super().__init__(target, connection)
        self.executor = ResilientRemoteOperation()
        self._journal_fields = [
            'MESSAGE', 'PRIORITY', 'SYSLOG_TIMESTAMP', 'SYSLOG_IDENTIFIER',
            'UNIT', 'HOSTNAME', '_PID', '_UID', '_GID', '_SESSION_ID',
            '_COMM', '_EXE', '_CMDLINE', '_SYSTEMD_CGROUP', '_SYSTEMD_UNIT'
        ]
    
    async def get_capabilities(self) -> Dict[str, Any]:
        """Get journald connector capabilities.
        
        Returns:
            Dictionary of available capabilities
        """
        try:
            # Check if journald is available
            result = await self.execute_command("which journalctl")
            if result.exit_code != 0:
                return {"available": False, "reason": "journalctl not found"}
            
            # Check journald permissions
            result = await self.execute_command("journalctl --list-catalog", timeout=10)
            if result.exit_code != 0:
                return {
                    "available": True,
                    "permissions": "limited",
                    "reason": "Limited journald access"
                }
            
            return {
                "available": True,
                "permissions": "full",
                "supports_real_time": True,
                "max_lines": 10000,
                "supported_fields": self._journal_fields
            }
            
        except Exception as e:
            return {
                "available": False,
                "error": str(e)
            }
    
    async def validate_target(self) -> bool:
        """Validate that target supports journald operations.
        
        Returns:
            True if target is valid for journald operations
        """
        try:
            capabilities = await self.get_capabilities()
            return capabilities.get("available", False)
        except Exception:
            return False
    
    @resilient_operation(
        operation_type=OperationType.LOG_RETRIEVAL,
        operation_name="get_journald_logs"
    )
    async def get_logs(self, 
                      service: Optional[str] = None,
                      lines: int = 100,
                      since: Optional[str] = None,
                      until: Optional[str] = None,
                      priority: Optional[str] = None,
                      grep: Optional[str] = None,
                      format_json: bool = True) -> List[LogEntry]:
        """Get journald logs with filtering options.
        
        Args:
            service: Service name to filter by
            lines: Number of lines to retrieve
            since: Start time (e.g., "1 hour ago", "2023-01-01")
            until: End time
            priority: Priority filter (emerg, alert, crit, err, warning, notice, info, debug)
            grep: Text pattern to search for
            format_json: Whether to output in JSON format
            
        Returns:
            List of log entries
        """
        cmd_parts = ["journalctl"]
        
        # Add filters
        if service:
            cmd_parts.extend(["-u", service])
        
        if since:
            cmd_parts.extend(["--since", since])
        
        if until:
            cmd_parts.extend(["--until", until])
        
        if priority:
            cmd_parts.extend(["-p", priority])
        
        if grep:
            cmd_parts.extend(["-g", grep])
        
        # Set line limit
        cmd_parts.extend(["-n", str(lines)])
        
        # Output format
        if format_json:
            cmd_parts.extend(["-o", "json"])
        else:
            cmd_parts.extend(["-o", "short"])
        
        command = " ".join(cmd_parts)
        
        try:
            result = await self.execute_command(command, timeout=60)
            
            if result.exit_code != 0:
                raise SystemManagerError(f"journalctl command failed: {result.stderr}")
            
            if format_json:
                return await self._parse_json_logs(result.stdout)
            else:
                return await self._parse_plain_logs(result.stdout)
                
        except Exception as e:
            logger.error(f"Failed to get logs: {str(e)}")
            raise
    
    async def follow_logs(self, 
                         service: Optional[str] = None,
                         since: Optional[str] = None,
                         timeout: int = 30) -> AsyncIterator[LogEntry]:
        """Follow journald logs in real-time.
        
        Args:
            service: Service name to follow
            since: Start time for log follow
            timeout: Follow timeout in seconds
            
        Yields:
            Log entries as they are generated
        """
        cmd_parts = ["journalctl", "-f"]
        
        if service:
            cmd_parts.extend(["-u", service])
        
        if since:
            cmd_parts.extend(["--since", since])
        
        cmd_parts.extend(["-o", "json"])
        command = " ".join(cmd_parts)
        
        try:
            # Execute command and get process
            process = await asyncio.create_subprocess_exec(
                *cmd_parts.split(),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            start_time = datetime.utcnow()
            
            while True:
                # Check timeout
                if (datetime.utcnow() - start_time).total_seconds() > timeout:
                    break
                
                # Read line with timeout
                try:
                    line = await asyncio.wait_for(
                        process.stdout.readline(), 
                        timeout=1.0
                    )
                    
                    if not line:
                        break
                    
                    # Parse log entry
                    log_entry = await self._parse_json_log_line(line.decode().strip())
                    if log_entry:
                        yield log_entry
                        
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    logger.error(f"Error reading log line: {str(e)}")
                    break
            
        except Exception as e:
            logger.error(f"Failed to follow logs: {str(e)}")
            raise
        
        finally:
            if 'process' in locals() and process:
                try:
                    process.terminate()
                    await process.wait()
                except:
                    pass
    
    async def get_journal_entries(self, 
                                 filters: Dict[str, Any],
                                 limit: int = 1000,
                                 cursor: Optional[str] = None) -> List[JournalEntry]:
        """Get journald entries with advanced filtering.
        
        Args:
            filters: Dictionary of journald field filters
            limit: Maximum number of entries to return
            cursor: Journal cursor for pagination
            
        Returns:
            List of journal entries
        """
        cmd_parts = ["journalctl", "-o", "json"]
        
        # Add field filters
        for field, value in filters.items():
            if field == "since":
                cmd_parts.extend(["--since", value])
            elif field == "until":
                cmd_parts.extend(["--until", value])
            elif field == "priority":
                cmd_parts.extend(["-p", value])
            elif field == "unit":
                cmd_parts.extend(["-u", value])
            elif field == "grep":
                cmd_parts.extend(["-g", value])
            elif field == "hostname":
                cmd_parts.extend(["--host", value])
        
        # Add cursor if provided
        if cursor:
            cmd_parts.extend(["--cursor", cursor])
        
        # Set limit
        cmd_parts.extend(["-n", str(limit)])
        
        command = " ".join(cmd_parts)
        
        try:
            result = await self.execute_command(command, timeout=60)
            
            if result.exit_code != 0:
                raise SystemManagerError(f"journalctl command failed: {result.stderr}")
            
            entries = await self._parse_json_journal_entries(result.stdout)
            
            # Add cursor information if available
            if cursor:
                for entry in entries:
                    entry.journal_cursor = cursor
            
            return entries
            
        except Exception as e:
            logger.error(f"Failed to get journal entries: {str(e)}")
            raise
    
    async def search_logs(self, 
                         query: str,
                         service: Optional[str] = None,
                         time_range: Optional[str] = None,
                         max_results: int = 100) -> List[LogEntry]:
        """Search logs using advanced query patterns.
        
        Args:
            query: Search query (supports regex)
            service: Service to search in
            time_range: Time range to search (e.g., "1 hour ago")
            max_results: Maximum number of results
            
        Returns:
            List of matching log entries
        """
        filters = {"grep": query}
        
        if service:
            filters["unit"] = service
        
        if time_range:
            filters["since"] = time_range
        
        entries = await self.get_journal_entries(filters, limit=max_results)
        
        # Additional client-side filtering if needed
        if query and not filters.get("grep"):
            # Client-side regex matching
            pattern = re.compile(query, re.IGNORECASE)
            entries = [
                entry for entry in entries 
                if pattern.search(entry.message)
            ]
        
        return entries
    
    async def get_log_statistics(self, 
                                service: Optional[str] = None,
                                time_range: str = "1 hour") -> Dict[str, Any]:
        """Get log statistics for analysis.
        
        Args:
            service: Service to analyze
            time_range: Time range for analysis
            
        Returns:
            Dictionary of log statistics
        """
        cmd_parts = ["journalctl"]
        
        if service:
            cmd_parts.extend(["-u", service])
        
        cmd_parts.extend([
            "--since", time_range,
            "-o", "json"
        ])
        
        command = " ".join(cmd_parts)
        
        try:
            result = await self.execute_command(command, timeout=120)
            
            if result.exit_code != 0:
                raise SystemManagerError(f"journalctl command failed: {result.stderr}")
            
            entries = await self._parse_json_journal_entries(result.stdout)
            
            # Calculate statistics
            stats = {
                "total_entries": len(entries),
                "time_range": time_range,
                "service": service,
                "priority_distribution": {},
                "hourly_distribution": {},
                "error_count": 0,
                "warning_count": 0,
                "unique_messages": 0
            }
            
            seen_messages = set()
            
            for entry in entries:
                # Priority distribution
                priority_name = self._priority_to_name(entry.priority)
                stats["priority_distribution"][priority_name] = \
                    stats["priority_distribution"].get(priority_name, 0) + 1
                
                # Error and warning counts
                if entry.priority <= 4:  # err, crit, alert, emerg
                    stats["error_count"] += 1
                elif entry.priority == 4:  # warning
                    stats["warning_count"] += 1
                
                # Hourly distribution
                hour = entry.timestamp.hour
                stats["hourly_distribution"][hour] = \
                    stats["hourly_distribution"].get(hour, 0) + 1
                
                # Unique messages
                seen_messages.add(entry.message)
            
            stats["unique_messages"] = len(seen_messages)
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get log statistics: {str(e)}")
            raise
    
    async def _parse_json_logs(self, stdout: str) -> List[LogEntry]:
        """Parse JSON formatted journald output.
        
        Args:
            stdout: JSON output from journalctl
            
        Returns:
            List of log entries
        """
        entries = []
        
        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                entry = await self._parse_json_log_line(line)
                if entry:
                    entries.append(entry)
            except Exception as e:
                logger.warning(f"Failed to parse log line: {str(e)}")
        
        return entries
    
    async def _parse_json_journal_entries(self, stdout: str) -> List[JournalEntry]:
        """Parse JSON formatted journald entries.
        
        Args:
            stdout: JSON output from journalctl
            
        Returns:
            List of journal entries
        """
        entries = []
        
        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                entry = await self._parse_json_journal_line(line)
                if entry:
                    entries.append(entry)
            except Exception as e:
                logger.warning(f"Failed to parse journal line: {str(e)}")
        
        return entries
    
    async def _parse_json_log_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single JSON log line.
        
        Args:
            line: JSON log line
            
        Returns:
            Log entry or None if parsing fails
        """
        try:
            data = json.loads(line)
            
            # Extract timestamp
            timestamp_str = data.get('SYSLOG_TIMESTAMP') or data.get('_SOURCE_REALTIME_TIMESTAMP')
            if timestamp_str:
                # Handle nanosecond timestamps
                if timestamp_str.isdigit() and len(timestamp_str) > 10:
                    timestamp = datetime.fromtimestamp(int(timestamp_str[:10]))
                else:
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                timestamp = datetime.utcnow()
            
            # Extract priority and level
            priority = int(data.get('PRIORITY', 6))  # Default to info
            level = self._priority_to_name(priority)
            
            # Extract message
            message = data.get('MESSAGE', '')
            
            # Extract source
            source = data.get('SYSLOG_IDENTIFIER') or data.get('_COMM') or 'unknown'
            
            return LogEntry(
                timestamp=timestamp,
                level=level,
                message=message,
                source=source,
                metadata=data
            )
            
        except Exception as e:
            logger.warning(f"Failed to parse JSON log line: {str(e)}")
            return None
    
    async def _parse_json_journal_line(self, line: str) -> Optional[JournalEntry]:
        """Parse a single JSON journal line.
        
        Args:
            line: JSON journal line
            
        Returns:
            Journal entry or None if parsing fails
        """
        try:
            data = json.loads(line)
            
            # Extract timestamp
            timestamp_str = data.get('SYSLOG_TIMESTAMP') or data.get('_SOURCE_REALTIME_TIMESTAMP')
            if timestamp_str:
                if timestamp_str.isdigit() and len(timestamp_str) > 10:
                    timestamp = datetime.fromtimestamp(int(timestamp_str[:10]))
                else:
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                timestamp = datetime.utcnow()
            
            # Extract priority
            priority = int(data.get('PRIORITY', 6))
            level = self._priority_to_name(priority)
            
            # Extract message
            message = data.get('MESSAGE', '')
            
            # Extract additional fields
            unit = data.get('UNIT')
            hostname = data.get('HOSTNAME')
            syslog_identifier = data.get('SYSLOG_IDENTIFIER')
            
            # Extract process info
            try:
                process_id = int(data.get('_PID', 0)) if data.get('_PID') else None
            except (ValueError, TypeError):
                process_id = None
            
            try:
                user_id = int(data.get('_UID', 0)) if data.get('_UID') else None
            except (ValueError, TypeError):
                user_id = None
            
            try:
                group_id = int(data.get('_GID', 0)) if data.get('_GID') else None
            except (ValueError, TypeError):
                group_id = None
            
            session_id = data.get('_SESSION_ID')
            
            return JournalEntry(
                timestamp=timestamp,
                priority=priority,
                level=level,
                message=message,
                unit=unit,
                hostname=hostname,
                syslog_identifier=syslog_identifier,
                process_id=process_id,
                user_id=user_id,
                group_id=group_id,
                session_id=session_id,
                fields=data
            )
            
        except Exception as e:
            logger.warning(f"Failed to parse JSON journal line: {str(e)}")
            return None
    
    async def _parse_plain_logs(self, stdout: str) -> List[LogEntry]:
        """Parse plain text journald output.
        
        Args:
            stdout: Plain text output from journalctl
            
        Returns:
            List of log entries
        """
        entries = []
        
        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                # Simple parsing for plain format
                # Format: "MMM DD HH:MM:SS hostname service[pid]: message"
                pattern = r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\s\[]+)(?:\[(\d+)\])?:\s+(.+)$'
                match = re.match(pattern, line)
                
                if match:
                    timestamp_str, hostname, service, pid, message = match.groups()
                    
                    # Convert timestamp
                    current_year = datetime.utcnow().year
                    timestamp_str = f"{current_year} {timestamp_str}"
                    timestamp = datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")
                    
                    level = "info"  # Default level for plain format
                    
                    entries.append(LogEntry(
                        timestamp=timestamp,
                        level=level,
                        message=message,
                        source=service,
                        metadata={
                            "hostname": hostname,
                            "pid": pid
                        }
                    ))
            except Exception as e:
                logger.warning(f"Failed to parse plain log line: {str(e)}")
        
        return entries
    
    def _priority_to_name(self, priority: int) -> str:
        """Convert journald priority number to name.
        
        Args:
            priority: Journald priority number (0-7)
            
        Returns:
            Priority name
        """
        priority_names = {
            0: "emerg",
            1: "alert", 
            2: "crit",
            3: "err",
            4: "warning",
            5: "notice",
            6: "info",
            7: "debug"
        }
        
        return priority_names.get(priority, "unknown")