"""
Package management service for SystemManager MCP Server
"""

import subprocess
import re
from typing import Dict


class PackageManager:
    """Service for managing system packages (apt-based systems)."""

    def __init__(self):
        self.package_manager = self._detect_package_manager()

    def _detect_package_manager(self) -> str:
        """Detect which package manager is available."""
        try:
            subprocess.run(["which", "apt-get"], check=True, capture_output=True)
            return "apt"
        except (subprocess.CalledProcessError, FileNotFoundError):
            try:
                subprocess.run(["which", "yum"], check=True, capture_output=True)
                return "yum"
            except (subprocess.CalledProcessError, FileNotFoundError):
                return "unknown"

    async def check_updates(self) -> Dict:
        """Check for available package updates without installing."""
        if self.package_manager == "apt":
            return await self._apt_check_updates()
        elif self.package_manager == "yum":
            return await self._yum_check_updates()
        else:
            return {"success": False, "error": "No supported package manager found"}

    async def _apt_check_updates(self) -> Dict:
        """Check for apt updates."""
        try:
            # Update package list
            update_result = subprocess.run(
                ["sudo", "apt-get", "update"],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if update_result.returncode != 0:
                return {"success": False, "error": update_result.stderr}

            # Check for upgradable packages
            check_result = subprocess.run(
                ["apt", "list", "--upgradable"],
                capture_output=True,
                text=True,
                timeout=30,
            )

            upgradable = []
            for line in check_result.stdout.split("\n"):
                if "/" in line and "upgradable" in line:
                    # Parse: package/repo version [upgradable from: old_version]
                    match = re.match(
                        r"([^/]+)/\S+\s+(\S+)\s+.*upgradable from:\s+(\S+)", line
                    )
                    if match:
                        upgradable.append(
                            {
                                "package": match.group(1),
                                "new_version": match.group(2),
                                "current_version": match.group(3),
                            }
                        )

            return {
                "success": True,
                "package_manager": "apt",
                "updates_available": len(upgradable),
                "packages": upgradable,
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _yum_check_updates(self) -> Dict:
        """Check for yum updates."""
        try:
            result = subprocess.run(
                ["sudo", "yum", "check-update"],
                capture_output=True,
                text=True,
                timeout=60,
            )

            # yum returns 100 if updates are available
            updates_available = result.returncode == 100

            upgradable = []
            if updates_available:
                for line in result.stdout.split("\n"):
                    match = re.match(r"(\S+)\s+(\S+)\s+(\S+)", line)
                    if match:
                        upgradable.append(
                            {
                                "package": match.group(1),
                                "new_version": match.group(2),
                                "repo": match.group(3),
                            }
                        )

            return {
                "success": True,
                "package_manager": "yum",
                "updates_available": len(upgradable),
                "packages": upgradable,
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def update_system(self, auto_approve: bool = False) -> Dict:
        """Update all system packages.

        Args:
            auto_approve: If True, automatically approve updates (apt -y)
        """
        if self.package_manager == "apt":
            return await self._apt_update_system(auto_approve)
        elif self.package_manager == "yum":
            return await self._yum_update_system(auto_approve)
        else:
            return {"success": False, "error": "No supported package manager found"}

    async def _apt_update_system(self, auto_approve: bool) -> Dict:
        """Perform apt upgrade."""
        try:
            # Update package list first
            update_result = subprocess.run(
                ["sudo", "apt-get", "update"],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if update_result.returncode != 0:
                return {
                    "success": False,
                    "error": f"apt-get update failed: {update_result.stderr}",
                }

            # Upgrade packages
            cmd = ["sudo", "apt-get", "upgrade"]
            if auto_approve:
                cmd.append("-y")

            upgrade_result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes for upgrades
            )

            if upgrade_result.returncode != 0:
                return {
                    "success": False,
                    "error": f"apt-get upgrade failed: {upgrade_result.stderr}",
                }

            # Parse output for upgraded packages
            upgraded_count = 0
            for line in upgrade_result.stdout.split("\n"):
                if "upgraded," in line:
                    match = re.search(r"(\d+)\s+upgraded", line)
                    if match:
                        upgraded_count = int(match.group(1))

            return {
                "success": True,
                "package_manager": "apt",
                "packages_upgraded": upgraded_count,
                "output": upgrade_result.stdout[-500:]
                if len(upgrade_result.stdout) > 500
                else upgrade_result.stdout,
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timed out (>5 minutes)"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _yum_update_system(self, auto_approve: bool) -> Dict:
        """Perform yum update."""
        try:
            cmd = ["sudo", "yum", "update"]
            if auto_approve:
                cmd.append("-y")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode != 0:
                return {"success": False, "error": result.stderr}

            return {
                "success": True,
                "package_manager": "yum",
                "output": result.stdout[-500:]
                if len(result.stdout) > 500
                else result.stdout,
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timed out (>5 minutes)"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def install_package(
        self, package_name: str, auto_approve: bool = False
    ) -> Dict:
        """Install a specific package.

        Args:
            package_name: Name of the package to install
            auto_approve: If True, automatically approve installation
        """
        if self.package_manager == "apt":
            return await self._apt_install(package_name, auto_approve)
        elif self.package_manager == "yum":
            return await self._yum_install(package_name, auto_approve)
        else:
            return {"success": False, "error": "No supported package manager found"}

    async def _apt_install(self, package_name: str, auto_approve: bool) -> Dict:
        """Install package with apt."""
        try:
            cmd = ["sudo", "apt-get", "install", package_name]
            if auto_approve:
                cmd.append("-y")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

            if result.returncode != 0:
                return {"success": False, "error": result.stderr}

            return {
                "success": True,
                "package": package_name,
                "package_manager": "apt",
                "output": result.stdout[-300:]
                if len(result.stdout) > 300
                else result.stdout,
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timed out (>3 minutes)"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _yum_install(self, package_name: str, auto_approve: bool) -> Dict:
        """Install package with yum."""
        try:
            cmd = ["sudo", "yum", "install", package_name]
            if auto_approve:
                cmd.append("-y")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

            if result.returncode != 0:
                return {"success": False, "error": result.stderr}

            return {
                "success": True,
                "package": package_name,
                "package_manager": "yum",
                "output": result.stdout[-300:]
                if len(result.stdout) > 300
                else result.stdout,
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timed out (>3 minutes)"}
        except Exception as e:
            return {"success": False, "error": str(e)}
