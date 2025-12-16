"""
File system explorer service for SystemManager MCP Server with secure path traversal protection.
"""

import os
import fnmatch
import logging
from typing import Dict, Optional

from src.utils.sandbox import SecureFileSandbox, default_sandbox

logger = logging.getLogger(__name__)


class FileExplorer:
    """Secure service for file system exploration and search with path traversal protection."""

    def __init__(self, sandbox: Optional[SecureFileSandbox] = None):
        """Initialize FileExplorer with secure sandbox.

        Args:
            sandbox: SecureFileSandbox instance for path protection (uses default if None)
        """
        self.sandbox = sandbox or default_sandbox
        logger.info("FileExplorer initialized with secure sandbox protection")

    async def list_directory(self, path: str = "/", recursive: bool = False) -> Dict:
        """List contents of a directory with secure path traversal protection.

        Args:
            path: Directory path to list
            recursive: Whether to list recursively

        Returns:
            Dictionary with success status and data or error message
        """
        try:
            # Use secure sandbox for path validation and traversal
            entries, error = self.sandbox.safe_list_directory(path)

            if error:
                return {"success": False, "error": error}

            if not entries:
                return {"success": True, "data": []}

            # Apply recursive listing if requested
            if recursive:
                all_entries = entries.copy()
                directory_entries = [e for e in entries if e["type"] == "directory"]

                for directory_entry in directory_entries:
                    try:
                        subdir_path = directory_entry["path"]
                        subdir_entries, subdir_error = self.sandbox.safe_list_directory(
                            subdir_path
                        )

                        if not subdir_error and subdir_entries:
                            # Add entries with relative paths
                            for sub_entry in subdir_entries:
                                sub_entry["path"] = sub_entry["path"]
                                sub_entry["name"] = os.path.relpath(
                                    sub_entry["path"], subdir_path
                                )
                                all_entries.append(sub_entry)
                    except Exception as e:
                        logger.warning(
                            f"Error listing subdirectory {directory_entry['path']}: {str(e)}"
                        )
                        continue

                return {"success": True, "data": all_entries}

            return {"success": True, "data": entries}

        except Exception as e:
            logger.error(f"Error listing directory {path}: {str(e)}")
            return {"success": False, "error": f"Directory listing error: {str(e)}"}

    async def search_files(
        self, pattern: str, path: str = "/", max_results: int = 100
    ) -> Dict:
        """Search for files by name pattern with secure path handling.

        Args:
            pattern: File name pattern to search for
            path: Base directory to search in
            max_results: Maximum number of results to return

        Returns:
            Dictionary with success status and results or error message
        """
        try:
            # Validate base path using sandbox
            resolved_path, error = self.sandbox.path_resolver.resolve_secure_path(path)
            if error:
                return {"success": False, "error": error}

            results = []

            # Walk directory tree safely
            for root, dirs, files in os.walk(resolved_path):
                # Skip directories we can't access or that are blocked
                try:
                    # Filter out inaccessible directories
                    dirs[:] = [
                        d
                        for d in dirs
                        if self._is_safe_directory_access(os.path.join(root, d))
                    ]
                except PermissionError:
                    continue

                # Search for matching files
                for file in files:
                    if fnmatch.fnmatch(file, pattern):
                        file_path = os.path.join(root, file)

                        # Validate each file path using sandbox
                        validated_path, validation_error = (
                            self.sandbox.path_resolver.resolve_secure_path(file_path)
                        )
                        if validation_error:
                            continue

                        try:
                            # Get file info using sandbox
                            file_info, info_error = self.sandbox.safe_get_file_info(
                                validated_path
                            )
                            if not info_error and file_info:
                                results.append(
                                    {
                                        "path": file_info["path"],
                                        "name": file_info["name"],
                                        "size": file_info["size"],
                                        "modified": file_info["modified"],
                                    }
                                )

                                if len(results) >= max_results:
                                    break
                        except Exception as e:
                            logger.debug(f"Error accessing file {file_path}: {str(e)}")
                            continue

                if len(results) >= max_results:
                    break

            return {"success": True, "data": results}

        except Exception as e:
            logger.error(f"Error searching files in {path}: {str(e)}")
            return {"success": False, "error": f"File search error: {str(e)}"}

    async def get_file_info(self, file_path: str) -> Dict:
        """Get detailed information about a file with secure path handling.

        Args:
            file_path: Path to the file

        Returns:
            Dictionary with success status and file info or error message
        """
        try:
            # Use secure sandbox to get file info
            file_info, error = self.sandbox.safe_get_file_info(file_path)

            if error:
                return {"success": False, "error": error}

            return {"success": True, "data": file_info}

        except Exception as e:
            logger.error(f"Error getting file info for {file_path}: {str(e)}")
            return {"success": False, "error": f"File info error: {str(e)}"}

    async def read_file(self, file_path: str, encoding: str = "utf-8") -> Dict:
        """Read the contents of a file with secure path handling.

        Args:
            file_path: Path to the file to read
            encoding: File encoding (default utf-8)

        Returns:
            Dictionary with success status and file content or error message
        """
        try:
            # Use secure sandbox to read file
            content, error = self.sandbox.safe_read_file(
                file_path, max_size=1024 * 1024
            )  # 1MB limit

            if error:
                return {"success": False, "error": error}

            return {"success": True, "data": content}

        except Exception as e:
            logger.error(f"Error reading file {file_path}: {str(e)}")
            return {"success": False, "error": f"File read error: {str(e)}"}

    def _is_safe_directory_access(self, directory_path: str) -> bool:
        """Check if directory access is safe.

        Args:
            directory_path: Path to check

        Returns:
            True if directory access is safe, False otherwise
        """
        try:
            # Check if we can read the directory
            if not os.access(directory_path, os.R_OK):
                return False

            # Use sandbox to validate path
            resolved_path, error = self.sandbox.path_resolver.resolve_secure_path(
                directory_path, ensure_within_allowed=True
            )
            return error is None

        except Exception:
            return False
