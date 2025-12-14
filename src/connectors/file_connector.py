"""
File Connector for Secure File Operations

Provides secure file operations via SSH with comprehensive path validation,
access control, and audit logging. Supports reading, writing, listing, and
stat operations with security-first approach.
"""

import asyncio
import json
import hashlib
import logging
import os
import pwd
import grp
import stat
from typing import Dict, List, Optional, Any, Tuple, Set
from datetime import datetime, timedelta
from dataclasses import dataclass
from pathlib import Path

from src.connectors.remote_agent_connector import (
    RemoteAgentConnector, FileInfo, FileStats, OperationResult
)
from src.services.remote_operation_executor import (
    ResilientRemoteOperation, resilient_file_operation, OperationType
)
from src.utils.errors import SystemManagerError, SecurityError


logger = logging.getLogger(__name__)


@dataclass
class FileSearchResult:
    """File search result with context."""
    path: str
    name: str
    size: int
    is_directory: bool
    permissions: str
    modified: datetime
    matches: List[str]  # What matched in the search


@dataclass
class DirectoryTreeNode:
    """Directory tree structure node."""
    path: str
    name: str
    is_directory: bool
    size: int
    children: Optional[List['DirectoryTreeNode']] = None
    permissions: str
    modified: datetime


class SecureFilePaths:
    """Secure path handling with whitelist validation."""
    
    # Allowed base paths for file operations
    ALLOWED_BASE_PATHS = {
        '/etc/systemd/system/',
        '/etc/nginx/',
        '/etc/ssl/',
        '/etc/cron.d/',
        '/etc/logrotate.d/',
        '/var/log/',
        '/var/log/journal/',
        '/tmp/',
        '/var/tmp/',
        '/opt/',
        '/usr/local/bin/',
        '/home/',
    }
    
    # Forbidden paths that should never be accessible
    FORBIDDEN_PATHS = {
        '/etc/shadow',
        '/etc/passwd',
        '/etc/group',
        '/etc/sudoers',
        '/etc/ssh/ssh_host_',
        '/root/',
        '/.ssh/',
        '/.aws/',
        '/.docker/',
        '/.kube/',
        '/var/lib/dpkg/',
        '/var/lib/apt/',
        '/proc/',
        '/sys/',
        '/dev/',
        '/run/systemd/',
    }
    
    # Allowed file extensions
    ALLOWED_EXTENSIONS = {
        '.conf', '.cfg', '.ini', '.yaml', '.yml', '.json', '.txt', '.log',
        '.service', '.socket', '.target', '.timer', '.path', '.mount',
        '.env', '.sh', '.py', '.pl', '.rb', '.js', '.ts', '.md'
    }
    
    @classmethod
    def validate_path(cls, path: str, operation: str = "read") -> str:
        """Validate file path for security.
        
        Args:
            path: File path to validate
            operation: Type of operation being performed
            
        Returns:
            Sanitized path
            
        Raises:
            SecurityError: If path is not safe
        """
        if not path or not isinstance(path, str):
            raise SecurityError("Invalid path provided")
        
        # Normalize path
        normalized = os.path.normpath(path)
        
        # Check for absolute path attempts
        if os.path.isabs(normalized) and not cls._is_allowed_absolute_path(normalized):
            raise SecurityError(f"Access to absolute path not allowed: {normalized}")
        
        # Check for directory traversal
        if '..' in normalized or normalized.startswith('..'):
            raise SecurityError("Directory traversal detected in path")
        
        # Check for null bytes and control characters
        if any(ord(c) < 32 and c not in '\t\n' for c in normalized):
            raise SecurityError("Path contains invalid characters")
        
        # Check forbidden paths
        for forbidden in cls.FORBIDDEN_PATHS:
            if normalized.startswith(forbidden):
                raise SecurityError(f"Access to forbidden path: {forbidden}")
        
        # For file operations, check file extension
        if operation in ["read", "write"] and not cls._is_allowed_file_type(normalized):
            raise SecurityError(f"File type not allowed: {normalized}")
        
        return normalized
    
    @classmethod
    def _is_allowed_absolute_path(cls, path: str) -> bool:
        """Check if absolute path is allowed.
        
        Args:
            path: Absolute path to check
            
        Returns:
            True if path is allowed
        """
        for allowed_base in cls.ALLOWED_BASE_PATHS:
            if path.startswith(allowed_base):
                return True
        
        # Allow paths under home directories (but not root)
        if path.startswith('/home/') and not path.startswith('/home/root'):
            return True
        
        return False
    
    @classmethod
    def _is_allowed_file_type(cls, path: str) -> bool:
        """Check if file type is allowed.
        
        Args:
            path: File path to check
            
        Returns:
            True if file type is allowed
        """
        # Allow configuration files
        for allowed_base in cls.ALLOWED_BASE_PATHS:
            if path.startswith(allowed_base):
                return True
        
        # Check file extension
        if '.' in os.path.basename(path):
            extension = os.path.splitext(path)[1].lower()
            return extension in cls.ALLOWED_EXTENSIONS
        
        return True  # No extension is allowed


class FileConnector(RemoteAgentConnector):
    """Secure file operations via SSH.
    
    Provides agent-like file functionality with comprehensive security controls.
    Supports reading, writing, listing, and stat operations.
    """
    
    def __init__(self, target, connection):
        """Initialize file connector.
        
        Args:
            target: Target connection configuration
            connection: SSH connection instance
        """
        super().__init__(target, connection)
        self.executor = ResilientRemoteOperation()
        self._file_paths = SecureFilePaths()
        self._max_file_size = 10 * 1024 * 1024  # 10MB limit
        self._operation_log: List[Dict[str, Any]] = []
    
    async def get_capabilities(self) -> Dict[str, Any]:
        """Get file connector capabilities.
        
        Returns:
            Dictionary of available capabilities
        """
        try:
            # Check basic file system access
            result = await self.execute_command("ls /tmp", timeout=5)
            if result.exit_code != 0:
                return {"available": False, "reason": "Limited file system access"}
            
            # Check permissions for common operations
            checks = {
                "read_files": await self._check_file_permission("read"),
                "write_files": await self._check_file_permission("write"),
                "list_directories": await self._check_file_permission("list"),
                "get_file_stats": await self._check_file_permission("stat")
            }
            
            available_permissions = sum(1 for check in checks.values() if check)
            
            return {
                "available": True,
                "permissions": "full" if available_permissions == 4 else "limited",
                "permission_checks": checks,
                "max_file_size": self._max_file_size,
                "allowed_paths": list(self._file_paths.ALLOWED_BASE_PATHS),
                "forbidden_paths": list(self._file_paths.FORBIDDEN_PATHS),
                "allowed_extensions": list(self._file_paths.ALLOWED_EXTENSIONS)
            }
            
        except Exception as e:
            return {
                "available": False,
                "error": str(e)
            }
    
    async def validate_target(self) -> bool:
        """Validate that target supports file operations.
        
        Returns:
            True if target is valid for file operations
        """
        try:
            capabilities = await self.get_capabilities()
            return capabilities.get("available", False)
        except Exception:
            return False
    
    @resilient_file_operation(operation_name="read_file")
    async def read_file(self, path: str, max_size: Optional[int] = None) -> str:
        """Read file content with security validation.
        
        Args:
            path: File path to read
            max_size: Maximum file size to read (overrides default)
            
        Returns:
            File content as string
            
        Raises:
            SecurityError: If path is not secure
            SystemManagerError: If file read fails
        """
        max_size = max_size or self._max_file_size
        
        # Validate path
        validated_path = self._file_paths.validate_path(path, "read")
        
        # Check file size
        size_result = await self.get_file_stats(validated_path)
        if size_result.size > max_size:
            raise SystemManagerError(f"File too large: {size_result.size} bytes (limit: {max_size})")
        
        # Read file content
        cmd = f"cat {validated_path}"
        
        try:
            result = await self.execute_command(cmd, timeout=60)
            
            if result.exit_code != 0:
                if "Permission denied" in result.stderr:
                    raise SecurityError(f"Permission denied reading file: {validated_path}")
                elif "No such file" in result.stderr:
                    raise SystemManagerError(f"File not found: {validated_path}")
                else:
                    raise SystemManagerError(f"Failed to read file: {result.stderr}")
            
            # Log operation
            self._log_file_operation("read", validated_path, True)
            
            return result.stdout
            
        except Exception as e:
            self._log_file_operation("read", validated_path, False, str(e))
            raise
    
    @resilient_file_operation(operation_name="write_file")
    async def write_file(self, path: str, content: str, create_backup: bool = True) -> OperationResult:
        """Write file content with security validation.
        
        Args:
            path: File path to write
            content: Content to write
            create_backup: Whether to create backup before writing
            
        Returns:
            Operation result
        """
        # Validate path
        validated_path = self._file_paths.validate_path(path, "write")
        
        try:
            # Create backup if file exists
            backup_path = None
            if create_backup:
                backup_path = f"{validated_path}.backup.{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
                await self._create_backup(validated_path, backup_path)
            
            # Write content via temporary file and move
            temp_path = f"{validated_path}.tmp.{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            
            # Create temporary file
            write_cmd = f"cat > {temp_path} << 'EOF'\n{content}\nEOF"
            result = await self.execute_command(write_cmd, timeout=60)
            
            if result.exit_code != 0:
                raise SystemManagerError(f"Failed to write temporary file: {result.stderr}")
            
            # Move to final location
            move_cmd = f"mv {temp_path} {validated_path}"
            result = await self.execute_command(move_cmd, timeout=30)
            
            if result.exit_code != 0:
                raise SystemManagerError(f"Failed to move file to final location: {result.stderr}")
            
            # Set proper permissions if possible
            await self._set_file_permissions(validated_path)
            
            # Log operation
            self._log_file_operation("write", validated_path, True, backup_path=backup_path)
            
            return OperationResult(
                operation="write_file",
                target=validated_path,
                success=True,
                result=f"File written successfully{' (backup created)' if backup_path else ''}",
                timestamp=datetime.utcnow()
            )
            
        except Exception as e:
            self._log_file_operation("write", validated_path, False, str(e))
            return OperationResult(
                operation="write_file",
                target=validated_path,
                success=False,
                error=str(e),
                timestamp=datetime.utcnow()
            )
    
    async def list_directory(self, path: str, include_hidden: bool = False) -> List[FileInfo]:
        """List directory contents with security validation.
        
        Args:
            path: Directory path to list
            include_hidden: Whether to include hidden files
            
        Returns:
            List of file information
        """
        # Validate path
        validated_path = self._file_paths.validate_path(path, "list")
        
        cmd = f"find {validated_path} -maxdepth 1"
        
        if not include_hidden:
            cmd += " -not -name '.*'"
        
        cmd += " -exec ls -ld {} \\; | awk '{print $1, $3, $4, $5, $6, $7, $8, $9}'"
        
        try:
            result = await self.execute_command(cmd, timeout=60)
            
            if result.exit_code != 0:
                if "Permission denied" in result.stderr:
                    raise SecurityError(f"Permission denied listing directory: {validated_path}")
                elif "No such file" in result.stderr:
                    raise SystemManagerError(f"Directory not found: {validated_path}")
                else:
                    raise SystemManagerError(f"Failed to list directory: {result.stderr}")
            
            files = await self._parse_ls_output(result.stdout, validated_path)
            
            # Log operation
            self._log_file_operation("list", validated_path, True, file_count=len(files))
            
            return files
            
        except Exception as e:
            self._log_file_operation("list", validated_path, False, str(e))
            raise
    
    async def get_file_stats(self, path: str) -> FileStats:
        """Get file statistics with security validation.
        
        Args:
            path: File path to get stats for
            
        Returns:
            File statistics
        """
        # Validate path
        validated_path = self._file_paths.validate_path(path, "stat")
        
        cmd = f"stat -c '%s %U %G %a %Y %X %Z' {validated_path}"
        
        try:
            result = await self.execute_command(cmd, timeout=30)
            
            if result.exit_code != 0:
                if "Permission denied" in result.stderr:
                    raise SecurityError(f"Permission denied getting stats for: {validated_path}")
                elif "No such file" in result.stderr:
                    raise SystemManagerError(f"File not found: {validated_path}")
                else:
                    raise SystemManagerError(f"Failed to get file stats: {result.stderr}")
            
            stats_data = result.stdout.strip().split()
            
            if len(stats_data) < 7:
                raise SystemManagerError("Invalid stat output format")
            
            size = int(stats_data[0])
            owner = stats_data[1]
            group = stats_data[2]
            permissions = stats_data[3]
            modified_time = int(stats_data[4])
            accessed_time = int(stats_data[5])
            created_time = int(stats_data[6])
            
            # Log operation
            self._log_file_operation("stat", validated_path, True)
            
            return FileStats(
                path=validated_path,
                size=size,
                permissions=permissions,
                owner=owner,
                group=group,
                created=datetime.fromtimestamp(created_time),
                modified=datetime.fromtimestamp(modified_time),
                accessed=datetime.fromtimestamp(accessed_time)
            )
            
        except Exception as e:
            self._log_file_operation("stat", validated_path, False, str(e))
            raise
    
    async def search_files(self, 
                          directory: str, 
                          pattern: str, 
                          file_type: Optional[str] = None,
                          max_results: int = 100) -> List[FileSearchResult]:
        """Search for files matching pattern.
        
        Args:
            directory: Directory to search in
            pattern: Search pattern (supports glob and regex)
            file_type: Filter by file type ('file', 'directory')
            max_results: Maximum number of results
            
        Returns:
            List of search results
        """
        # Validate directory path
        validated_dir = self._file_paths.validate_path(directory, "list")
        
        cmd = f"find {validated_dir} -type {file_type or 'f'} -name '{pattern}' -exec ls -ld {{}} \\;"
        
        try:
            result = await self.execute_command(cmd, timeout=120)
            
            if result.exit_code != 0:
                raise SystemManagerError(f"File search failed: {result.stderr}")
            
            search_results = await self._parse_search_output(result.stdout, validated_dir, pattern)
            
            # Limit results
            return search_results[:max_results]
            
        except Exception as e:
            logger.error(f"File search failed in {validated_dir}: {str(e)}")
            raise
    
    async def get_directory_tree(self, 
                                directory: str, 
                                max_depth: int = 3,
                                include_files: bool = True) -> DirectoryTreeNode:
        """Get directory tree structure.
        
        Args:
            directory: Directory path
            max_depth: Maximum depth to traverse
            include_files: Whether to include files
            
        Returns:
            Directory tree root node
        """
        # Validate directory path
        validated_dir = self._file_paths.validate_path(directory, "list")
        
        cmd = f"find {validated_dir} -maxdepth {max_depth} -exec ls -ld {{}} \\; | head -50"
        
        try:
            result = await self.execute_command(cmd, timeout=60)
            
            if result.exit_code != 0:
                raise SystemManagerError(f"Directory tree failed: {result.stderr}")
            
            return await self._build_directory_tree(result.stdout, validated_dir)
            
        except Exception as e:
            logger.error(f"Directory tree failed for {validated_dir}: {str(e)}")
            raise
    
    async def compare_files(self, path1: str, path2: str) -> Dict[str, Any]:
        """Compare two files.
        
        Args:
            path1: First file path
            path2: Second file path
            
        Returns:
            Comparison results
        """
        # Validate both paths
        validated_path1 = self._file_paths.validate_path(path1, "read")
        validated_path2 = self._file_paths.validate_path(path2, "read")
        
        try:
            # Get file stats for both files
            stats1 = await self.get_file_stats(validated_path1)
            stats2 = await self.get_file_stats(validated_path2)
            
            # Read file contents
            content1 = await self.read_file(validated_path1)
            content2 = await self.read_file(validated_path2)
            
            # Calculate checksums
            checksum1 = hashlib.sha256(content1.encode()).hexdigest()
            checksum2 = hashlib.sha256(content2.encode()).hexdigest()
            
            # Compare
            comparison = {
                "path1": validated_path1,
                "path2": validated_path2,
                "size1": stats1.size,
                "size2": stats2.size,
                "size_equal": stats1.size == stats2.size,
                "checksum1": checksum1,
                "checksum2": checksum2,
                "content_equal": content1 == content2,
                "modified1": stats1.modified,
                "modified2": stats2.modified,
                "permissions1": stats1.permissions,
                "permissions2": stats2.permissions,
                "owner1": stats1.owner,
                "owner2": stats2.owner
            }
            
            return comparison
            
        except Exception as e:
            logger.error(f"File comparison failed: {validated_path1} vs {validated_path2}: {str(e)}")
            raise
    
    def get_operation_log(self) -> List[Dict[str, Any]]:
        """Get audit log of file operations.
        
        Returns:
            List of operation log entries
        """
        return self._operation_log.copy()
    
    async def _check_file_permission(self, operation: str) -> bool:
        """Check if file operation permission is available.
        
        Args:
            operation: Operation type to check
            
        Returns:
            True if permission is available
        """
        try:
            test_path = "/tmp/systemmanager_test"
            
            if operation == "read":
                cmd = f"test -r {test_path} && echo 'yes' || echo 'no'"
            elif operation == "write":
                cmd = f"test -w /tmp && echo 'yes' || echo 'no'"
            elif operation == "list":
                cmd = f"test -x /tmp && echo 'yes' || echo 'no'"
            elif operation == "stat":
                cmd = f"test -e {test_path} && echo 'yes' || echo 'no'"
            else:
                return False
            
            result = await self.execute_command(cmd, timeout=5)
            return result.stdout.strip() == "yes"
            
        except Exception:
            return False
    
    async def _create_backup(self, original_path: str, backup_path: str):
        """Create backup of file.
        
        Args:
            original_path: Original file path
            backup_path: Backup file path
        """
        cmd = f"cp {original_path} {backup_path}"
        result = await self.execute_command(cmd, timeout=30)
        
        if result.exit_code != 0:
            logger.warning(f"Failed to create backup {backup_path}: {result.stderr}")
    
    async def _set_file_permissions(self, path: str):
        """Set appropriate file permissions.
        
        Args:
            path: File path to set permissions for
        """
        # For configuration files, set 644 (rw-r--r--)
        if any(path.startswith(base) for base in ['/etc/', '/opt/']):
            cmd = f"chmod 644 {path}"
        else:
            # For other files, set 600 (rw-------)
            cmd = f"chmod 600 {path}"
        
        try:
            await self.execute_command(cmd, timeout=10)
        except Exception as e:
            logger.warning(f"Failed to set file permissions for {path}: {str(e)}")
    
    async def _parse_ls_output(self, output: str, directory: str) -> List[FileInfo]:
        """Parse ls output to FileInfo objects.
        
        Args:
            output: ls command output
            directory: Directory path for context
            
        Returns:
            List of FileInfo objects
        """
        files = []
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                parts = line.split()
                if len(parts) >= 9:
                    permissions = parts[0]
                    owner = parts[2]
                    group = parts[3]
                    size = int(parts[4])
                    date_str = f"{parts[5]} {parts[6]} {parts[7]}"
                    name = ' '.join(parts[8:])
                    
                    # Parse date (format: MMM DD HH:MM or MMM DD YYYY)
                    if ':' in parts[7]:
                        # Recent file with time
                        modified = datetime.strptime(f"{datetime.utcnow().year} {date_str}", "%Y %b %d %H:%M")
                    else:
                        # Older file with year
                        modified = datetime.strptime(date_str, "%b %d %Y")
                    
                    # Construct full path
                    full_path = os.path.join(directory, name)
                    
                    files.append(FileInfo(
                        name=name,
                        path=full_path,
                        size=size,
                        is_directory=permissions.startswith('d'),
                        permissions=permissions,
                        owner=owner,
                        group=group,
                        modified=modified
                    ))
                    
            except Exception as e:
                logger.warning(f"Failed to parse ls line: {line} - {str(e)}")
                continue
        
        return files
    
    async def _parse_search_output(self, output: str, directory: str, pattern: str) -> List[FileSearchResult]:
        """Parse find output to search results.
        
        Args:
            output: find command output
            directory: Directory path for context
            pattern: Search pattern
            
        Returns:
            List of search results
        """
        results = []
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                parts = line.split()
                if len(parts) >= 9:
                    permissions = parts[0]
                    owner = parts[2]
                    group = parts[3]
                    size = int(parts[4])
                    date_str = f"{parts[5]} {parts[6]} {parts[7]}"
                    name = ' '.join(parts[8:])
                    
                    # Parse date
                    if ':' in parts[7]:
                        modified = datetime.strptime(f"{datetime.utcnow().year} {date_str}", "%Y %b %d %H:%M")
                    else:
                        modified = datetime.strptime(date_str, "%b %d %Y")
                    
                    # Construct full path
                    full_path = os.path.join(directory, name)
                    
                    results.append(FileSearchResult(
                        path=full_path,
                        name=name,
                        size=size,
                        is_directory=permissions.startswith('d'),
                        permissions=permissions,
                        modified=modified,
                        matches=[pattern]
                    ))
                    
            except Exception as e:
                logger.warning(f"Failed to parse search line: {line} - {str(e)}")
                continue
        
        return results
    
    async def _build_directory_tree(self, output: str, root_path: str) -> DirectoryTreeNode:
        """Build directory tree from find output.
        
        Args:
            output: find command output
            root_path: Root directory path
            
        Returns:
            Directory tree root node
        """
        # This is a simplified implementation
        # A full directory tree would require recursive parsing
        
        files = await self._parse_ls_output(output, root_path)
        
        root_node = DirectoryTreeNode(
            path=root_path,
            name=os.path.basename(root_path) or '/',
            is_directory=True,
            size=0,
            children=[],
            permissions="drwxr-xr-x",
            modified=datetime.utcnow()
        )
        
        for file_info in files:
            node = DirectoryTreeNode(
                path=file_info.path,
                name=file_info.name,
                is_directory=file_info.is_directory,
                size=file_info.size,
                permissions=file_info.permissions,
                modified=file_info.modified
            )
            
            root_node.children.append(node)
        
        return root_node
    
    def _log_file_operation(self, operation: str, path: str, success: bool, 
                           error: Optional[str] = None, **kwargs):
        """Log file operation for audit.
        
        Args:
            operation: Operation type
            path: File path
            success: Whether operation was successful
            error: Error message if any
            **kwargs: Additional context
        """
        log_entry = {
            "timestamp": datetime.utcnow(),
            "operation": operation,
            "path": path,
            "success": success,
            "error": error,
            "target": self.target.host,
            **kwargs
        }
        
        self._operation_log.append(log_entry)
        
        # Keep only last 1000 entries
        if len(self._operation_log) > 1000:
            self._operation_log = self._operation_log[-1000:]
        
        # Log to system logger
        if success:
            logger.info(f"File operation {operation} on {path} completed successfully")
        else:
            logger.error(f"File operation {operation} on {path} failed: {error}")