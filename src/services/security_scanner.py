"""
Security scanning service for container vulnerability detection.

Supports:
- Trivy scanner (preferred, more comprehensive)
- Grype scanner (fallback alternative)
"""

import asyncio
import json
import shutil
from typing import Dict, List, Optional
from pathlib import Path


class SecurityScanner:
    """Service for scanning container images for vulnerabilities."""

    def __init__(self):
        # Check which scanners are available
        self.trivy_available = shutil.which("trivy") is not None
        self.grype_available = shutil.which("grype") is not None

    async def scan_image(
        self,
        image: str,
        scanner: Optional[str] = None,
        severity: str = "MEDIUM,HIGH,CRITICAL"
    ) -> Dict:
        """
        Scan a Docker image for vulnerabilities.

        Args:
            image: Docker image name (e.g., "nginx:latest")
            scanner: Scanner to use ("trivy" or "grype"). Auto-detect if None.
            severity: Comma-separated severity levels to report

        Returns:
            Dict with scan results including vulnerabilities found
        """
        # Auto-detect scanner
        if scanner is None:
            if self.trivy_available:
                scanner = "trivy"
            elif self.grype_available:
                scanner = "grype"
            else:
                return {
                    "success": False,
                    "error": "No vulnerability scanner found. Install trivy or grype.",
                    "install_hints": {
                        "trivy": "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin",
                        "grype": "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin"
                    }
                }

        if scanner == "trivy":
            return await self._scan_with_trivy(image, severity)
        elif scanner == "grype":
            return await self._scan_with_grype(image, severity)
        else:
            return {"success": False, "error": f"Unknown scanner: {scanner}"}

    async def _scan_with_trivy(self, image: str, severity: str) -> Dict:
        """Scan image with Trivy."""
        if not self.trivy_available:
            return {"success": False, "error": "Trivy not installed"}

        try:
            # Run trivy scan with JSON output
            cmd = [
                "trivy", "image",
                "--severity", severity,
                "--format", "json",
                "--quiet",
                image
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                return {
                    "success": False,
                    "error": f"Trivy scan failed: {stderr.decode()}"
                }

            # Parse JSON results
            results = json.loads(stdout.decode())

            # Extract vulnerability summary
            vulnerabilities = []
            total_vulns = 0

            for result in results.get("Results", []):
                for vuln in result.get("Vulnerabilities", []):
                    vulnerabilities.append({
                        "id": vuln.get("VulnerabilityID"),
                        "package": vuln.get("PkgName"),
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion", "Not available"),
                        "severity": vuln.get("Severity"),
                        "title": vuln.get("Title", ""),
                        "description": vuln.get("Description", "")[:200]  # Truncate
                    })
                    total_vulns += 1

            # Count by severity
            severity_counts = {}
            for vuln in vulnerabilities:
                sev = vuln["severity"]
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            return {
                "success": True,
                "scanner": "trivy",
                "image": image,
                "total_vulnerabilities": total_vulns,
                "severity_counts": severity_counts,
                "vulnerabilities": vulnerabilities[:50],  # Limit to first 50
                "truncated": total_vulns > 50,
                "summary": f"Found {total_vulns} vulnerabilities in {image}"
            }

        except Exception as e:
            return {"success": False, "error": f"Trivy scan error: {str(e)}"}

    async def _scan_with_grype(self, image: str, severity: str) -> Dict:
        """Scan image with Grype."""
        if not self.grype_available:
            return {"success": False, "error": "Grype not installed"}

        try:
            # Run grype scan with JSON output
            cmd = [
                "grype",
                image,
                "--output", "json",
                "--quiet"
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode not in [0, 1]:  # Grype returns 1 when vulns found
                return {
                    "success": False,
                    "error": f"Grype scan failed: {stderr.decode()}"
                }

            # Parse JSON results
            results = json.loads(stdout.decode())

            # Filter by severity
            severity_filter = set(severity.split(","))
            vulnerabilities = []

            for match in results.get("matches", []):
                vuln = match.get("vulnerability", {})
                vuln_severity = vuln.get("severity", "UNKNOWN")

                if vuln_severity in severity_filter:
                    vulnerabilities.append({
                        "id": vuln.get("id"),
                        "package": match.get("artifact", {}).get("name"),
                        "installed_version": match.get("artifact", {}).get("version"),
                        "fixed_version": vuln.get("fix", {}).get("versions", ["Not available"])[0],
                        "severity": vuln_severity,
                        "description": vuln.get("description", "")[:200]
                    })

            # Count by severity
            severity_counts = {}
            for vuln in vulnerabilities:
                sev = vuln["severity"]
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            total_vulns = len(vulnerabilities)

            return {
                "success": True,
                "scanner": "grype",
                "image": image,
                "total_vulnerabilities": total_vulns,
                "severity_counts": severity_counts,
                "vulnerabilities": vulnerabilities[:50],
                "truncated": total_vulns > 50,
                "summary": f"Found {total_vulns} vulnerabilities in {image}"
            }

        except Exception as e:
            return {"success": False, "error": f"Grype scan error: {str(e)}"}

    async def scan_filesystem(self, path: str, severity: str = "MEDIUM,HIGH,CRITICAL") -> Dict:
        """
        Scan a filesystem path for vulnerabilities (useful for LXC containers).

        Args:
            path: Path to scan
            severity: Comma-separated severity levels

        Returns:
            Scan results
        """
        if not self.trivy_available:
            return {
                "success": False,
                "error": "Filesystem scanning requires Trivy"
            }

        try:
            cmd = [
                "trivy", "fs",
                "--severity", severity,
                "--format", "json",
                "--quiet",
                path
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                return {
                    "success": False,
                    "error": f"Filesystem scan failed: {stderr.decode()}"
                }

            results = json.loads(stdout.decode())

            # Extract vulnerabilities
            vulnerabilities = []
            for result in results.get("Results", []):
                for vuln in result.get("Vulnerabilities", []):
                    vulnerabilities.append({
                        "id": vuln.get("VulnerabilityID"),
                        "package": vuln.get("PkgName"),
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion", "Not available"),
                        "severity": vuln.get("Severity"),
                        "title": vuln.get("Title", "")
                    })

            severity_counts = {}
            for vuln in vulnerabilities:
                sev = vuln["severity"]
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            return {
                "success": True,
                "scanner": "trivy",
                "path": path,
                "total_vulnerabilities": len(vulnerabilities),
                "severity_counts": severity_counts,
                "vulnerabilities": vulnerabilities[:50],
                "truncated": len(vulnerabilities) > 50
            }

        except Exception as e:
            return {"success": False, "error": f"Filesystem scan error: {str(e)}"}

    def get_scanner_info(self) -> Dict:
        """Get information about available scanners."""
        return {
            "trivy_available": self.trivy_available,
            "grype_available": self.grype_available,
            "preferred_scanner": "trivy" if self.trivy_available else "grype" if self.grype_available else None
        }
