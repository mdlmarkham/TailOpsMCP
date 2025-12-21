"""Centralized path configuration using environment variables with hybrid approach

This module provides a unified way to manage paths throughout TailOpsMCP using
environment variables with sensible defaults, supporting both base directory
scanning and service-specific path overrides.
"""

import os
from pathlib import Path
from typing import List, Optional, Tuple
import re


class PathConfig:
    """Centralized path management with flexible configuration options

    Supports hybrid approach:
    1. Base configurable directories for scanning
    2. Service-specific path overrides
    3. Security-sensitive paths remain protected
    """

    # Core System Paths (with environment variable support)
    @staticmethod
    def get_docker_socket_path() -> Path:
        """Get Docker socket path for container operations"""
        return Path(
            os.getenv("SYSTEMMANAGER_DOCKER_SOCKET_PATH", "/var/run/docker.sock")
        )

    @staticmethod
    def get_stacks_dir() -> Path:
        """Get Docker Compose stacks directory"""
        return Path(os.getenv("SYSTEMMANAGER_STACKS_DIR", "/opt/stacks"))

    @staticmethod
    def get_base_url() -> str:
        """Get server base URL for external connections"""
        return os.getenv("SYSTEMMANAGER_BASE_URL", "http://localhost:8080")

    # Installation & Data Directories
    @staticmethod
    def get_install_dir() -> Path:
        """Get installation directory"""
        return Path(os.getenv("SYSTEMMANAGER_INSTALL_DIR", "/opt/systemmanager"))

    @staticmethod
    def get_data_dir() -> Path:
        """Get data storage directory"""
        return Path(os.getenv("SYSTEMMANAGER_DATA_DIR", "/var/lib/systemmanager"))

    @staticmethod
    def get_config_dir() -> Path:
        """Get configuration directory"""
        return Path(os.getenv("SYSTEMMANAGER_CONFIG_DIR", "/etc/systemmanager"))

    @staticmethod
    def get_log_dir() -> Path:
        """Get log directory"""
        return Path(os.getenv("SYSTEMMANAGER_LOG_DIR", "/var/log/systemmanager"))

    @staticmethod
    def get_credential_dir() -> Path:
        """Get credential storage directory"""
        return Path(
            os.getenv("SYSTEMMANAGER_CREDENTIAL_DIR", "/etc/systemmanager/credentials")
        )

    # Proxmox Integration
    @staticmethod
    def get_proxmox_dump_dir() -> Path:
        """Get Proxmox backup directory path"""
        return Path(os.getenv("SYSTEMMANAGER_PROXMOX_DUMP_DIR", "/var/lib/vz/dump"))

    # Application Scanning - Hybrid Approach
    @staticmethod
    def get_app_scan_config_dirs() -> List[Path]:
        """Get base configuration directories for application scanning"""
        config_env = os.getenv(
            "SYSTEMMANAGER_APP_SCAN_CONFIG_DIRS", "/etc,/usr/local/etc,/opt,/etc/config"
        )
        return [Path(p.strip()) for p in config_env.split(",") if p.strip()]

    @staticmethod
    def get_app_scan_data_dirs() -> List[Path]:
        """Get base data directories for application scanning"""
        data_env = os.getenv(
            "SYSTEMMANAGER_APP_SCAN_DATA_DIRS",
            "/var/lib,/var/local/lib,/opt/data,/storage",
        )
        return [Path(p.strip()) for p in data_env.split(",") if p.strip()]

    @staticmethod
    def get_service_specific_dir(service_name: str, path_type: str) -> Optional[Path]:
        """Get service-specific directory override

        Args:
            service_name: Name of the service (e.g., 'jellyfin', 'pihole')
            path_type: Type of path ('config' or 'data')

        Returns:
            Service-specific path if set, None otherwise
        """
        env_var = f"SYSTEMMANAGER_{service_name.upper()}_{path_type.upper()}_DIR"
        env_value = os.getenv(env_var)
        return Path(env_value) if env_value else None

    @staticmethod
    def get_service_paths(service_name: str) -> Tuple[List[Path], List[Path]]:
        """Get both config and data paths for a service with fallback logic

        Returns:
            Tuple of (config_paths, data_paths) with service-specific overrides
            prioritized over base scanning directories
        """
        # Check for service-specific overrides
        config_override = PathConfig.get_service_specific_dir(service_name, "config")
        data_override = PathConfig.get_service_specific_dir(service_name, "data")

        config_paths = []
        data_paths = []

        # Priority 1: Service-specific overrides
        if config_override:
            config_paths.append(config_override)
        if data_override:
            data_paths.append(data_override)

        # Priority 2: Base scanning directories (if no service-specific override)
        if not config_override:
            config_paths.extend(PathConfig.get_app_scan_config_dirs())
        if not data_override:
            data_paths.extend(PathConfig.get_app_scan_data_dirs())

        return config_paths, data_paths

    # Temporary directories for operations
    @staticmethod
    def get_temp_dirs() -> List[Path]:
        """Get temporary directories for operations"""
        temp_env = os.getenv("SYSTEMMANAGER_TEMP_DIRS", "/tmp,/var/tmp")
        return [Path(p.strip()) for p in temp_env.split(",") if p.strip()]

    # Security and Access Control
    @staticmethod
    def get_allowed_base_dirs() -> List[Path]:
        """Get allowed base directories for file operations (security boundary)"""
        allowed_env = os.getenv(
            "SYSTEMMANAGER_ALLOWED_BASE_DIRS", "/tmp,/var/tmp,/var/log,/opt,/home"
        )
        return [Path(p.strip()) for p in allowed_env.split(",") if p.strip()]

    # Category-based organization for applications
    @staticmethod
    def get_media_app_dirs() -> List[Path]:
        """Get directories for media applications (jellyfin, plex, emby)"""
        media_env = os.getenv(
            "SYSTEMMANAGER_MEDIA_CONFIG_DIRS", "/etc/jellyfin,/etc/plex,/etc/emby"
        )
        return [Path(p.strip()) for p in media_env.split(",") if p.strip()]

    @staticmethod
    def get_network_app_dirs() -> List[Path]:
        """Get directories for network applications (pihole, adguard)"""
        network_env = os.getenv(
            "SYSTEMMANAGER_NETWORK_CONFIG_DIRS", "/etc/pihole,/etc/adguard"
        )
        return [Path(p.strip()) for p in network_env.split(",") if p.strip()]

    @staticmethod
    def get_database_app_dirs() -> List[Path]:
        """Get directories for database applications"""
        db_env = os.getenv(
            "SYSTEMMANAGER_DATABASE_DATA_DIRS",
            "/var/lib/postgresql,/var/lib/mysql,/var/lib/redis,/var/lib/mongodb",
        )
        return [Path(p.strip()) for p in db_env.split(",") if p.strip()]

    # Path validation and security
    @staticmethod
    def validate_path_safety(path: Path, purpose: str = "general") -> bool:
        """Validate that a path is safe for the intended purpose

        Args:
            path: Path to validate
            purpose: Purpose ("general", "config", "data", "security")

        Returns:
            True if path is safe, False otherwise
        """
        # Basic path safety checks
        if not path or ".." in str(path) or str(path).startswith("//"):
            return False

        # Resolve canonical path to check traversal
        try:
            resolved = path.resolve()
            if not str(resolved).startswith("/"):  # Should be absolute
                return False
        except (OSError, ValueError):
            return False

        # Check against allowed base directories for general operations
        if purpose != "security":
            allowed_bases = PathConfig.get_allowed_base_dirs()
            return any(resolved.is_relative_to(base) for base in allowed_bases)

        # Security purpose has stricter validation (should remain hardcoded for now)
        SECURITY_SENSITIVE_PATHS = {
            "/etc/shadow",
            "/etc/passwd",
            "/etc/sudoers",
            "/etc/group",
            "/root/",
            "/proc/",
            "/sys/",
            "/dev/",
            "/etc/ssh/",
            "/.ssh/",
        }

        path_str = str(resolved)
        for sensitive_path in SECURITY_SENSITIVE_PATHS:
            if path_str.startswith(sensitive_path):
                return False

        return True

    @staticmethod
    def get_all_paths() -> dict:
        """Get all configured paths for debugging/diagnostics"""
        return {
            "docker_socket": str(PathConfig.get_docker_socket_path()),
            "stacks_dir": str(PathConfig.get_stacks_dir()),
            "base_url": PathConfig.get_base_url(),
            "install_dir": str(PathConfig.get_install_dir()),
            "data_dir": str(PathConfig.get_data_dir()),
            "config_dir": str(PathConfig.get_config_dir()),
            "log_dir": str(PathConfig.get_log_dir()),
            "credential_dir": str(PathConfig.get_credential_dir()),
            "proxmox_dump_dir": str(PathConfig.get_proxmox_dump_dir()),
            "app_scan_config_dirs": [
                str(p) for p in PathConfig.get_app_scan_config_dirs()
            ],
            "app_scan_data_dirs": [str(p) for p in PathConfig.get_app_scan_data_dirs()],
            "temp_dirs": [str(p) for p in PathConfig.get_temp_dirs()],
            "allowed_base_dirs": [str(p) for p in PathConfig.get_allowed_base_dirs()],
        }
