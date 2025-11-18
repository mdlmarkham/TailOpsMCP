"""
Secrets scanning service for detecting exposed credentials in configuration files.

Detects common secret patterns:
- API keys
- Private keys
- Passwords in configs
- Cloud credentials
- Database connection strings
"""

import re
import os
from typing import Dict, List, Optional
from pathlib import Path


class SecretsScanner:
    """Service for detecting secrets in files and configurations."""

    # Common secret patterns (regex)
    SECRET_PATTERNS = {
        "aws_access_key": {
            "pattern": r"AKIA[0-9A-Z]{16}",
            "description": "AWS Access Key ID"
        },
        "aws_secret_key": {
            "pattern": r"aws_secret_access_key\s*=\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
            "description": "AWS Secret Access Key"
        },
        "github_token": {
            "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
            "description": "GitHub Personal Access Token"
        },
        "generic_api_key": {
            "pattern": r"api[_-]?key\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?",
            "description": "Generic API Key",
            "case_insensitive": True
        },
        "private_key": {
            "pattern": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
            "description": "Private Key"
        },
        "password_in_url": {
            "pattern": r"[a-z]+://[^:]+:([^@]+)@",
            "description": "Password in connection string"
        },
        "slack_token": {
            "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,32}",
            "description": "Slack Token"
        },
        "slack_webhook": {
            "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
            "description": "Slack Webhook URL"
        },
        "stripe_key": {
            "pattern": r"sk_live_[0-9a-zA-Z]{24,}",
            "description": "Stripe Live Secret Key"
        },
        "mailgun_key": {
            "pattern": r"key-[0-9a-zA-Z]{32}",
            "description": "Mailgun API Key"
        },
        "twilio_key": {
            "pattern": r"SK[0-9a-f]{32}",
            "description": "Twilio API Key"
        },
        "jwt_token": {
            "pattern": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "description": "JWT Token"
        },
        "generic_secret": {
            "pattern": r"secret\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?",
            "description": "Generic Secret",
            "case_insensitive": True
        },
        "database_url": {
            "pattern": r"(postgres|mysql|mongodb)://[^:]+:[^@]+@[^/]+",
            "description": "Database Connection String with Credentials"
        },
        "docker_auth": {
            "pattern": r'"auth":\s*"[A-Za-z0-9+/=]{20,}"',
            "description": "Docker Registry Authentication"
        },
        "npm_token": {
            "pattern": r"//registry\.npmjs\.org/:_authToken=[A-Za-z0-9-]+",
            "description": "NPM Auth Token"
        }
    }

    # File extensions to scan
    SCANNABLE_EXTENSIONS = {
        ".env", ".conf", ".config", ".ini", ".yml", ".yaml",
        ".json", ".xml", ".properties", ".toml", ".sh", ".bash",
        ".py", ".js", ".ts", ".rb", ".go", ".java", ".php"
    }

    # Directories to skip
    SKIP_DIRS = {
        ".git", "node_modules", "__pycache__", ".venv", "venv",
        "vendor", "dist", "build", ".pytest_cache"
    }

    def __init__(self):
        # Compile regex patterns for performance
        self.compiled_patterns = {}
        for name, config in self.SECRET_PATTERNS.items():
            flags = re.IGNORECASE if config.get("case_insensitive", False) else 0
            self.compiled_patterns[name] = {
                "regex": re.compile(config["pattern"], flags),
                "description": config["description"]
            }

    async def scan_file(self, file_path: str) -> Dict:
        """
        Scan a single file for secrets.

        Args:
            file_path: Path to file to scan

        Returns:
            Dict with findings
        """
        try:
            path = Path(file_path)

            if not path.exists():
                return {"success": False, "error": f"File not found: {file_path}"}

            if not path.is_file():
                return {"success": False, "error": f"Not a file: {file_path}"}

            # Read file content
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                return {"success": False, "error": f"Failed to read file: {str(e)}"}

            # Scan for secrets
            findings = []
            for secret_type, pattern_info in self.compiled_patterns.items():
                matches = pattern_info["regex"].finditer(content)

                for match in matches:
                    # Get line number
                    line_num = content[:match.start()].count("\n") + 1

                    # Get the matched text (redacted)
                    matched_text = match.group(0)
                    redacted = self._redact_secret(matched_text)

                    findings.append({
                        "type": secret_type,
                        "description": pattern_info["description"],
                        "line": line_num,
                        "matched_text": redacted,
                        "severity": self._get_severity(secret_type)
                    })

            return {
                "success": True,
                "file": str(path),
                "findings_count": len(findings),
                "findings": findings
            }

        except Exception as e:
            return {"success": False, "error": f"Scan error: {str(e)}"}

    async def scan_directory(
        self,
        directory: str,
        recursive: bool = True,
        max_files: int = 1000
    ) -> Dict:
        """
        Scan a directory for secrets.

        Args:
            directory: Path to directory to scan
            recursive: Scan subdirectories
            max_files: Maximum number of files to scan

        Returns:
            Dict with all findings
        """
        try:
            dir_path = Path(directory)

            if not dir_path.exists():
                return {"success": False, "error": f"Directory not found: {directory}"}

            if not dir_path.is_dir():
                return {"success": False, "error": f"Not a directory: {directory}"}

            # Collect files to scan
            files_to_scan = []

            if recursive:
                for root, dirs, files in os.walk(dir_path):
                    # Skip excluded directories
                    dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]

                    for file in files:
                        file_path = Path(root) / file
                        if file_path.suffix in self.SCANNABLE_EXTENSIONS:
                            files_to_scan.append(file_path)

                            if len(files_to_scan) >= max_files:
                                break

                    if len(files_to_scan) >= max_files:
                        break
            else:
                for file_path in dir_path.iterdir():
                    if file_path.is_file() and file_path.suffix in self.SCANNABLE_EXTENSIONS:
                        files_to_scan.append(file_path)

                        if len(files_to_scan) >= max_files:
                            break

            # Scan all files
            all_findings = []
            files_with_secrets = []

            for file_path in files_to_scan:
                result = await self.scan_file(str(file_path))

                if result.get("success") and result.get("findings_count", 0) > 0:
                    files_with_secrets.append(str(file_path))
                    all_findings.extend(result["findings"])

            # Summarize by severity
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for finding in all_findings:
                severity = finding.get("severity", "MEDIUM")
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            return {
                "success": True,
                "directory": str(dir_path),
                "files_scanned": len(files_to_scan),
                "files_with_secrets": len(files_with_secrets),
                "total_findings": len(all_findings),
                "severity_counts": severity_counts,
                "files": files_with_secrets,
                "findings": all_findings[:100],  # Limit output
                "truncated": len(all_findings) > 100
            }

        except Exception as e:
            return {"success": False, "error": f"Directory scan error: {str(e)}"}

    async def scan_docker_config(self) -> Dict:
        """Scan Docker config for exposed credentials."""
        docker_config_path = Path.home() / ".docker" / "config.json"

        if not docker_config_path.exists():
            return {
                "success": True,
                "message": "No Docker config found",
                "findings_count": 0,
                "findings": []
            }

        return await self.scan_file(str(docker_config_path))

    async def scan_env_files(self, directory: str = "/opt/systemmanager") -> Dict:
        """Scan for .env files that might contain secrets."""
        env_files = []
        dir_path = Path(directory)

        if dir_path.exists():
            # Find all .env files
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    if file.startswith(".env") or file.endswith(".env"):
                        env_files.append(Path(root) / file)

        findings = []
        for env_file in env_files:
            result = await self.scan_file(str(env_file))
            if result.get("success") and result.get("findings_count", 0) > 0:
                findings.append({
                    "file": str(env_file),
                    "findings": result["findings"]
                })

        return {
            "success": True,
            "env_files_scanned": len(env_files),
            "files_with_secrets": len(findings),
            "findings": findings
        }

    def _redact_secret(self, text: str) -> str:
        """Redact secret but show first/last few characters."""
        if len(text) <= 8:
            return "***REDACTED***"
        return f"{text[:4]}...{text[-4:]}"

    def _get_severity(self, secret_type: str) -> str:
        """Determine severity level for secret type."""
        critical_types = {
            "aws_secret_key", "private_key", "stripe_key",
            "github_token", "database_url"
        }
        high_types = {
            "aws_access_key", "slack_token", "mailgun_key",
            "twilio_key", "docker_auth"
        }
        medium_types = {
            "generic_api_key", "jwt_token", "npm_token"
        }

        if secret_type in critical_types:
            return "CRITICAL"
        elif secret_type in high_types:
            return "HIGH"
        elif secret_type in medium_types:
            return "MEDIUM"
        else:
            return "LOW"
