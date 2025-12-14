"""
Secure file system sandbox utilities for preventing path traversal attacks.

Provides secure path resolution, directory restrictions, and symlink protection
for safe file system operations.
"""

import os
import logging
from pathlib import Path, PurePath
from typing import Optional, List, Set, Tuple
from urllib.parse import unquote

logger = logging.getLogger(__name__)


class SecurePathResolver:
    """Secure path resolution with traversal attack prevention."""
    
    def __init__(self, allowed_base_paths: Optional[List[str]] = None, 
                 blocked_paths: Optional[List[str]] = None):
        """Initialize secure path resolver.
        
        Args:
            allowed_base_paths: List of allowed base directories (chroot-style)
            blocked_paths: List of paths to block access to
        """
        self.allowed_base_paths = allowed_base_paths or []
        self.blocked_paths = blocked_paths or []
        
        # Convert to absolute paths and normalize
        self.allowed_base_paths = [
            os.path.abspath(os.path.expanduser(path)) 
            for path in self.allowed_base_paths
        ]
        self.blocked_paths = [
            os.path.abspath(os.path.expanduser(path))
            for path in self.blocked_paths
        ]
        
        logger.info(f"SecurePathResolver initialized with {len(self.allowed_base_paths)} allowed paths")
    
    def resolve_secure_path(self, user_path: str, ensure_within_allowed: bool = True) -> Tuple[Optional[str], Optional[str]]:
        """Securely resolve a user-provided path.
        
        Args:
            user_path: Path provided by user
            ensure_within_allowed: If True, ensure path is within allowed directories
            
        Returns:
            (resolved_path: str or None, error_message: str or None)
        """
        try:
            # Decode URL-encoded characters
            decoded_path = unquote(user_path)
            
            # Expand user paths and normalize
            resolved_path = os.path.abspath(os.path.expanduser(decoded_path))
            
            # Check for path traversal attempts
            if self._contains_path_traversal(decoded_path):
                return None, "Path traversal attack detected"
            
            # Normalize path to resolve symlinks and remove redundant separators
            try:
                normalized_path = os.path.normpath(resolved_path)
            except (OSError, ValueError) as e:
                return None, f"Invalid path: {str(e)}"
            
            # Check if path is within allowed directories
            if ensure_within_allowed and self.allowed_base_paths:
                if not any(normalized_path.startswith(base_path + os.sep) or normalized_path == base_path 
                          for base_path in self.allowed_base_paths):
                    return None, f"Path outside allowed directories: {normalized_path}"
            
            # Check against blocked paths
            if self._is_blocked_path(normalized_path):
                return None, f"Access to path is blocked: {normalized_path}"
            
            # Additional security checks
            if not self._is_safe_path(normalized_path):
                return None, "Path contains unsafe components"
            
            return normalized_path, None
            
        except Exception as e:
            logger.error(f"Error resolving path {user_path}: {str(e)}")
            return None, f"Path resolution error: {str(e)}"
    
    def _contains_path_traversal(self, path: str) -> bool:
        """Check if path contains traversal attempts."""
        # Common traversal patterns
        traversal_patterns = ['..', '~', '${', '$(', '`', '${IFS}']
        
        # Normalize path separators for consistent checking
        normalized_path = path.replace('\\', '/')
        
        for pattern in traversal_patterns:
            if pattern in normalized_path:
                return True
        
        return False
    
    def _is_blocked_path(self, path: str) -> bool:
        """Check if path is in blocked list."""
        for blocked_path in self.blocked_paths:
            if path.startswith(blocked_path + os.sep) or path == blocked_path:
                return True
        return False
    
    def _is_safe_path(self, path: str) -> bool:
        """Additional safety checks for the path."""
        try:
            # Check for dangerous filenames
            dangerous_names = {
                '.', '..', '', None, 
                'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
                'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
            }
            
            path_parts = path.split(os.sep)
            
            for part in path_parts:
                if part in dangerous_names:
                    return False
                
                # Check for control characters
                if any(ord(c) < 32 and c not in '\t\n\r' for c in part):
                    return False
            
            return True
            
        except Exception:
            return False


class SecureFileSandbox:
    """Secure file operations within a sandbox environment."""
    
    def __init__(self, allowed_base_paths: Optional[List[str]] = None,
                 blocked_paths: Optional[List[str]] = None):
        """Initialize secure file sandbox.
        
        Args:
            allowed_base_paths: Directories where file operations are allowed
            blocked_paths: Paths that should never be accessible
        """
        self.path_resolver = SecurePathResolver(allowed_base_paths, blocked_paths)
        self._visited_symlinks: Set[str] = set()
    
    def safe_list_directory(self, user_path: str) -> Tuple[Optional[List], Optional[str]]:
        """Safely list directory contents with traversal protection.
        
        Args:
            user_path: User-provided directory path
            
        Returns:
            (directory_entries: List or None, error_message: str or None)
        """
        try:
            # Resolve path securely
            resolved_path, error = self.path_resolver.resolve_secure_path(user_path)
            if error:
                return None, error
            
            # Check if path is a directory
            if not os.path.isdir(resolved_path):
                return None, f"Path is not a directory: {resolved_path}"
            
            # List directory contents
            entries = []
            try:
                for entry_name in os.listdir(resolved_path):
                    entry_path = os.path.join(resolved_path, entry_name)
                    
                    # Check for symlink loops and resolve safely
                    if os.path.islink(entry_path):
                        if self._is_safe_symlink(entry_path):
                            entry_info = self._get_safe_entry_info(entry_path, entry_name)
                            if entry_info:
                                entries.append(entry_info)
                        else:
                            logger.warning(f"Skipping unsafe symlink: {entry_path}")
                    else:
                        entry_info = self._get_safe_entry_info(entry_path, entry_name)
                        if entry_info:
                            entries.append(entry_info)
                            
            except PermissionError:
                return None, f"Permission denied accessing directory: {resolved_path}"
            
            return entries, None
            
        except Exception as e:
            logger.error(f"Error listing directory {user_path}: {str(e)}")
            return None, f"Directory listing error: {str(e)}"
    
    def safe_read_file(self, user_path: str, max_size: int = 1024 * 1024) -> Tuple[Optional[str], Optional[str]]:
        """Safely read file contents with size and path restrictions.
        
        Args:
            user_path: User-provided file path
            max_size: Maximum file size to read (default 1MB)
            
        Returns:
            (file_content: str or None, error_message: str or None)
        """
        try:
            # Resolve path securely
            resolved_path, error = self.path_resolver.resolve_secure_path(user_path)
            if error:
                return None, error
            
            # Check if path is a file
            if not os.path.isfile(resolved_path):
                return None, f"Path is not a file: {resolved_path}"
            
            # Check file size
            file_size = os.path.getsize(resolved_path)
            if file_size > max_size:
                return None, f"File too large (max {max_size} bytes)"
            
            # Check for symlinks (only allow regular files)
            if os.path.islink(resolved_path):
                return None, "Symlinks are not allowed for file reading"
            
            # Read file contents safely
            try:
                with open(resolved_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                return content, None
            except UnicodeDecodeError:
                return None, "File contains invalid UTF-8 encoding"
                
        except Exception as e:
            logger.error(f"Error reading file {user_path}: {str(e)}")
            return None, f"File read error: {str(e)}"
    
    def safe_get_file_info(self, user_path: str) -> Tuple[Optional[dict], Optional[str]]:
        """Safely get file information with path restrictions.
        
        Args:
            user_path: User-provided file path
            
        Returns:
            (file_info: dict or None, error_message: str or None)
        """
        try:
            # Resolve path securely
            resolved_path, error = self.path_resolver.resolve_secure_path(user_path)
            if error:
                return None, error
            
            # Check if path exists
            if not os.path.exists(resolved_path):
                return None, f"Path does not exist: {resolved_path}"
            
            # Get file statistics safely
            try:
                stat = os.stat(resolved_path)
            except (OSError, PermissionError):
                return None, f"Cannot access file information: {resolved_path}"
            
            # Build safe file info
            file_info = {
                "path": resolved_path,
                "name": os.path.basename(resolved_path),
                "size": stat.st_size,
                "permissions": oct(stat.st_mode)[-3:],
                "owner": stat.st_uid,
                "group": stat.st_gid,
                "type": "directory" if os.path.isdir(resolved_path) else "file",
                "symlink": os.path.islink(resolved_path),
                "created": str(stat.st_ctime),
                "modified": str(stat.st_mtime),
                "accessed": str(stat.st_atime)
            }
            
            return file_info, None
            
        except Exception as e:
            logger.error(f"Error getting file info for {user_path}: {str(e)}")
            return None, f"File info error: {str(e)}"
    
    def _is_safe_symlink(self, symlink_path: str) -> bool:
        """Check if symlink is safe to follow."""
        try:
            # Prevent symlink loops
            real_path = os.path.realpath(symlink_path)
            if real_path in self._visited_symlinks:
                logger.warning(f"Symlink loop detected: {symlink_path}")
                return False
            
            self._visited_symlinks.add(real_path)
            
            # Check if symlink points outside allowed directories
            resolved_path, error = self.path_resolver.resolve_secure_path(real_path, ensure_within_allowed=True)
            if error:
                logger.warning(f"Symlink points outside allowed area: {symlink_path}")
                return False
            
            return True
            
        except Exception:
            return False
    
    def _get_safe_entry_info(self, entry_path: str, entry_name: str) -> Optional[dict]:
        """Get safe entry information."""
        try:
            # Check if we can access the entry
            if not os.access(entry_path, os.R_OK):
                return None
            
            stat = os.stat(entry_path)
            entry_info = {
                "name": entry_name,
                "path": entry_path,
                "type": "directory" if os.path.isdir(entry_path) else "file",
                "size": stat.st_size if os.path.isfile(entry_path) else 0,
                "permissions": oct(stat.st_mode)[-3:],
                "symlink": os.path.islink(entry_path),
                "modified": str(stat.st_mtime),
                "accessed": str(stat.st_atime)
            }
            
            return entry_info
            
        except (OSError, PermissionError):
            return None


# Default sandbox instance for general use
default_sandbox = SecureFileSandbox(
    allowed_base_paths=["/"],  # Allow access to entire filesystem (restrict as needed)
    blocked_paths=[
        "/proc", "/sys", "/dev", "/run", "/var/run",
        "/etc/shadow", "/etc/passwd", "/etc/sudoers",
        "/root", "/home/*/.ssh"
    ]
)


def create_restricted_sandbox(base_paths: List[str]) -> SecureFileSandbox:
    """Create a sandbox restricted to specific base paths.
    
    Args:
        base_paths: List of allowed base directories
        
    Returns:
        SecureFileSandbox instance
    """
    return SecureFileSandbox(allowed_base_paths=base_paths)