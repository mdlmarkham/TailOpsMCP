"""
File system explorer service for SystemManager MCP Server
"""

import os
import fnmatch
from typing import Dict, List
from datetime import datetime


class FileExplorer:
    """Service for file system exploration and search."""
    
    async def list_directory(self, path: str = "/", recursive: bool = False) -> Dict:
        """List contents of a directory."""
        try:
            if not os.path.exists(path):
                return {"success": False, "error": f"Path does not exist: {path}"}
            
            if not os.path.isdir(path):
                return {"success": False, "error": f"Path is not a directory: {path}"}
            
            entries = []
            
            for entry in os.listdir(path):
                entry_path = os.path.join(path, entry)
                try:
                    stat = os.stat(entry_path)
                    entry_info = {
                        "name": entry,
                        "path": entry_path,
                        "type": "directory" if os.path.isdir(entry_path) else "file",
                        "size": stat.st_size if os.path.isfile(entry_path) else 0,
                        "permissions": oct(stat.st_mode)[-3:],
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "accessed": datetime.fromtimestamp(stat.st_atime).isoformat()
                    }
                    entries.append(entry_info)
                except PermissionError:
                    # Skip entries we don't have permission to access
                    continue
            
            return {"success": True, "data": entries}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def search_files(self, pattern: str, path: str = "/", max_results: int = 100) -> Dict:
        """Search for files by name pattern."""
        try:
            if not os.path.exists(path):
                return {"success": False, "error": f"Path does not exist: {path}"}
            
            results = []
            
            for root, dirs, files in os.walk(path):
                # Skip directories we can't access
                try:
                    dirs[:] = [d for d in dirs if os.access(os.path.join(root, d), os.R_OK)]
                except PermissionError:
                    continue
                
                for file in files:
                    if fnmatch.fnmatch(file, pattern):
                        file_path = os.path.join(root, file)
                        try:
                            stat = os.stat(file_path)
                            results.append({
                                "path": file_path,
                                "name": file,
                                "size": stat.st_size,
                                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                            })
                            
                            if len(results) >= max_results:
                                break
                        except (PermissionError, OSError):
                            continue
                
                if len(results) >= max_results:
                    break
            
            return {"success": True, "data": results}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def get_file_info(self, file_path: str) -> Dict:
        """Get detailed information about a file."""
        try:
            if not os.path.exists(file_path):
                return {"success": False, "error": f"File does not exist: {file_path}"}
            
            if not os.path.isfile(file_path):
                return {"success": False, "error": f"Path is not a file: {file_path}"}
            
            stat = os.stat(file_path)
            
            file_info = {
                "path": file_path,
                "name": os.path.basename(file_path),
                "size": stat.st_size,
                "permissions": oct(stat.st_mode)[-3:],
                "owner": stat.st_uid,
                "group": stat.st_gid,
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "accessed": datetime.fromtimestamp(stat.st_atime).isoformat()
            }
            
            return {"success": True, "data": file_info}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def read_file(self, file_path: str, encoding: str = "utf-8") -> Dict:
        """Read the contents of a file."""
        try:
            if not os.path.exists(file_path):
                return {"success": False, "error": f"File does not exist: {file_path}"}
            
            if not os.path.isfile(file_path):
                return {"success": False, "error": f"Path is not a file: {file_path}"}
            
            # Check file size (limit to 1MB for safety)
            file_size = os.path.getsize(file_path)
            if file_size > 1024 * 1024:  # 1MB
                return {"success": False, "error": "File too large (max 1MB)"}
            
            with open(file_path, 'r', encoding=encoding) as f:
                content = f.read()
            
            return {"success": True, "data": content}
            
        except Exception as e:
            return {"success": False, "error": str(e)}