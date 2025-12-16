"""
Application Scanner - Auto-detect applications running on LXC
Detects common home lab applications like Jellyfin, Pi-hole, Ollama, PostgreSQL, etc.
"""

import re
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)


@dataclass
class DetectedApp:
    """Result from application detection."""

    name: str
    type: str
    version: Optional[str] = None
    port: Optional[int] = None
    service_name: Optional[str] = None
    config_path: Optional[str] = None
    data_path: Optional[str] = None
    confidence: float = 1.0  # 0.0 to 1.0


class ApplicationScanner:
    """Scan system for installed applications."""

    # Application detection patterns
    DETECTION_RULES = {
        "jellyfin": {
            "service": "jellyfin",
            "process": "jellyfin",
            "port": 8096,
            "config": "/etc/jellyfin",
            "data": "/var/lib/jellyfin",
            "version_cmd": "jellyfin --version",
        },
        "pihole": {
            "service": "pihole-FTL",
            "process": "pihole-FTL",
            "port": 80,
            "config": "/etc/pihole",
            "data": "/etc/pihole",
            "check_file": "/usr/local/bin/pihole",
        },
        "ollama": {
            "service": "ollama",
            "process": "ollama",
            "port": 11434,
            "config": "/etc/ollama",
            "data": "/usr/share/ollama",
            "version_cmd": "ollama --version",
        },
        "postgresql": {
            "service": "postgresql",
            "process": "postgres",
            "port": 5432,
            "config": "/etc/postgresql",
            "data": "/var/lib/postgresql",
            "version_cmd": "psql --version",
        },
        "mysql": {
            "service": "mysql",
            "process": "mysqld",
            "port": 3306,
            "config": "/etc/mysql",
            "data": "/var/lib/mysql",
            "version_cmd": "mysql --version",
        },
        "mariadb": {
            "service": "mariadb",
            "process": "mariadbd",
            "port": 3306,
            "config": "/etc/mysql",
            "data": "/var/lib/mysql",
            "version_cmd": "mariadb --version",
        },
        "nginx": {
            "service": "nginx",
            "process": "nginx",
            "port": 80,
            "config": "/etc/nginx",
            "data": "/var/www",
            "version_cmd": "nginx -v",
        },
        "apache": {
            "service": "apache2",
            "process": "apache2",
            "port": 80,
            "config": "/etc/apache2",
            "data": "/var/www",
            "version_cmd": "apache2 -v",
        },
        "redis": {
            "service": "redis-server",
            "process": "redis-server",
            "port": 6379,
            "config": "/etc/redis",
            "data": "/var/lib/redis",
            "version_cmd": "redis-server --version",
        },
        "mongodb": {
            "service": "mongod",
            "process": "mongod",
            "port": 27017,
            "config": "/etc/mongod.conf",
            "data": "/var/lib/mongodb",
            "version_cmd": "mongod --version",
        },
        "home-assistant": {
            "service": "home-assistant",
            "process": "hass",
            "port": 8123,
            "config": "/home/homeassistant/.homeassistant",
            "data": "/home/homeassistant/.homeassistant",
        },
        "plex": {
            "service": "plexmediaserver",
            "process": "Plex Media Server",
            "port": 32400,
            "config": "/var/lib/plexmediaserver/Library/Application Support/Plex Media Server",
            "data": "/var/lib/plexmediaserver",
        },
        "portainer": {
            "service": "portainer",
            "process": "portainer",
            "port": 9000,
            "data": "/var/lib/portainer",
        },
        "nextcloud": {
            "service": "apache2",  # Usually runs under Apache/Nginx
            "port": 80,
            "check_file": "/var/www/nextcloud/occ",
            "config": "/var/www/nextcloud/config",
            "data": "/var/www/nextcloud/data",
        },
        "wireguard": {
            "service": "wg-quick@wg0",
            "check_file": "/etc/wireguard/wg0.conf",
            "config": "/etc/wireguard",
        },
        "adguard": {
            "service": "AdGuardHome",
            "process": "AdGuardHome",
            "port": 3000,
            "config": "/opt/AdGuardHome",
            "data": "/opt/AdGuardHome/data",
        },
        "prometheus": {
            "service": "prometheus",
            "process": "prometheus",
            "port": 9090,
            "config": "/etc/prometheus",
            "data": "/var/lib/prometheus",
        },
        "grafana": {
            "service": "grafana-server",
            "process": "grafana-server",
            "port": 3000,
            "config": "/etc/grafana",
            "data": "/var/lib/grafana",
        },
    }

    def __init__(self):
        self.detected_apps: List[DetectedApp] = []

    def scan(self) -> List[DetectedApp]:
        """Run full system scan for applications."""
        self.detected_apps = []

        # Get running services
        services = self._get_systemd_services()

        # Get running processes
        processes = self._get_running_processes()

        # Get listening ports
        ports = self._get_listening_ports()

        # Check each detection rule
        for app_type, rules in self.DETECTION_RULES.items():
            detected = self._check_application(
                app_type, rules, services, processes, ports
            )
            if detected:
                self.detected_apps.append(detected)

        logger.info(
            f"System scan complete. Detected {len(self.detected_apps)} applications."
        )
        return self.detected_apps

    def _check_application(
        self,
        app_type: str,
        rules: Dict[str, Any],
        services: List[str],
        processes: List[str],
        ports: List[int],
    ) -> Optional[DetectedApp]:
        """Check if application is installed/running."""
        confidence = 0.0
        reasons = []

        # Check systemd service
        if "service" in rules and rules["service"] in services:
            confidence += 0.4
            reasons.append(f"service:{rules['service']}")

        # Check process
        if "process" in rules:
            for proc in processes:
                if rules["process"].lower() in proc.lower():
                    confidence += 0.3
                    reasons.append(f"process:{rules['process']}")
                    break

        # Check port
        if "port" in rules and rules["port"] in ports:
            confidence += 0.2
            reasons.append(f"port:{rules['port']}")

        # Check file existence
        if "check_file" in rules and self._file_exists(rules["check_file"]):
            confidence += 0.3
            reasons.append(f"file:{rules['check_file']}")

        # Require at least moderate confidence
        if confidence < 0.3:
            return None

        # Get version if possible
        version = None
        if "version_cmd" in rules:
            version = self._get_version(rules["version_cmd"])

        # Determine service name
        service_name = None
        if "service" in rules and rules["service"] in services:
            service_name = rules["service"]

        logger.info(
            f"Detected {app_type}: confidence={confidence:.2f}, reasons={reasons}"
        )

        return DetectedApp(
            name=app_type,
            type=app_type,
            version=version,
            port=rules.get("port"),
            service_name=service_name,
            config_path=rules.get("config"),
            data_path=rules.get("data"),
            confidence=confidence,
        )

    def _get_systemd_services(self) -> List[str]:
        """Get list of active systemd services."""
        try:
            result = subprocess.run(
                [
                    "systemctl",
                    "list-units",
                    "--type=service",
                    "--state=running",
                    "--no-pager",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                # Parse service names from output
                services = []
                for line in result.stdout.splitlines():
                    match = re.match(r"\s*(\S+\.service)", line)
                    if match:
                        # Remove .service suffix
                        service = match.group(1).replace(".service", "")
                        services.append(service)
                return services
        except Exception as e:
            logger.warning(f"Failed to get systemd services: {e}")
        return []

    def _get_running_processes(self) -> List[str]:
        """Get list of running process names."""
        try:
            result = subprocess.run(
                ["ps", "aux"], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return result.stdout.splitlines()
        except Exception as e:
            logger.warning(f"Failed to get running processes: {e}")
        return []

    def _get_listening_ports(self) -> List[int]:
        """Get list of listening TCP ports."""
        ports = []
        try:
            result = subprocess.run(
                ["ss", "-tlnH"],  # TCP listening, numeric, no header
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    # Parse port from "LISTEN 0 128 *:8080 *:*" format
                    match = re.search(r":(\d+)\s", line)
                    if match:
                        ports.append(int(match.group(1)))
        except Exception as e:
            logger.warning(f"Failed to get listening ports: {e}")
        return ports

    def _file_exists(self, path: str) -> bool:
        """Check if file or directory exists."""
        try:
            result = subprocess.run(["test", "-e", path], timeout=5)
            return result.returncode == 0
        except Exception:
            return False

    def _get_version(self, cmd: str) -> Optional[str]:
        """Try to get application version."""
        try:
            result = subprocess.run(
                cmd.split(), capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                # Try to extract version number
                output = result.stdout + result.stderr
                match = re.search(r"(\d+\.\d+(?:\.\d+)?)", output)
                if match:
                    return match.group(1)
                return output.strip()[:50]  # First 50 chars
        except Exception as e:
            logger.debug(f"Failed to get version with '{cmd}': {e}")
        return None
