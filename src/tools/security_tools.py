"""Security scanning and hardening tools for TailOpsMCP."""
import logging
from typing import Literal, Optional
from fastmcp import FastMCP, Context
from src.auth.middleware import secure_tool
from src.server.utils import format_response, format_error
from src.services.security_scanner import SecurityScanner
from src.services.secrets_scanner import SecretsScanner
from src.services.firewall_manager import FirewallManager
from src.services.cis_checker import CISChecker

logger = logging.getLogger(__name__)


def register_tools(mcp: FastMCP):
    """Register security tools with MCP instance."""

    # Initialize services
    security_scanner = SecurityScanner()
    secrets_scanner = SecretsScanner()
    firewall_manager = FirewallManager()
    cis_checker = CISChecker()

    # ========================================================================
    # VULNERABILITY SCANNING TOOLS
    # ========================================================================

    @mcp.tool()
    @secure_tool("scan_container_vulnerabilities")
    async def scan_container_vulnerabilities(
        image: str,
        scanner: Optional[Literal["trivy", "grype"]] = None,
        severity: str = "MEDIUM,HIGH,CRITICAL",
        format: Literal["json", "toon"] = "json"
    ) -> dict:
        """
        Scan a Docker container image for security vulnerabilities.

        Uses Trivy (preferred) or Grype to detect known CVEs in container images.
        Scans base images, installed packages, and application dependencies.

        Args:
            image: Docker image to scan (e.g., "nginx:latest", "postgres:14")
            scanner: Scanner to use ("trivy" or "grype"). Auto-detects if not specified.
            severity: Comma-separated severity levels to report (CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN)
            format: Response format - 'json' (detailed) or 'toon' (compact)

        Returns:
            Vulnerability scan results with counts by severity and detailed findings

        Examples:
            - scan_container_vulnerabilities(image="nginx:latest")
            - scan_container_vulnerabilities(image="postgres:14", severity="CRITICAL,HIGH")
            - scan_container_vulnerabilities(image="myapp:1.0", scanner="trivy")

        Note:
            Requires trivy or grype to be installed on the system.
            Install with: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
        """
        try:
            result = await security_scanner.scan_image(image, scanner, severity)

            if not result.get("success"):
                return result

            return format_response(result, format)

        except Exception as e:
            logger.error(f"Container vulnerability scan error: {str(e)}")
            return format_error(e, "scan_container_vulnerabilities")

    @mcp.tool()
    @secure_tool("scan_filesystem_vulnerabilities")
    async def scan_filesystem_vulnerabilities(
        path: str = "/",
        severity: str = "MEDIUM,HIGH,CRITICAL",
        format: Literal["json", "toon"] = "json"
    ) -> dict:
        """
        Scan filesystem for vulnerabilities (useful for LXC containers).

        Scans the filesystem for vulnerable packages and dependencies.
        Useful for scanning the host system or LXC container filesystems.

        Args:
            path: Filesystem path to scan (default: "/")
            severity: Comma-separated severity levels
            format: Response format

        Returns:
            Vulnerability scan results for the filesystem

        Examples:
            - scan_filesystem_vulnerabilities(path="/")
            - scan_filesystem_vulnerabilities(path="/var/lib/lxc/container/rootfs")
        """
        try:
            result = await security_scanner.scan_filesystem(path, severity)

            if not result.get("success"):
                return result

            return format_response(result, format)

        except Exception as e:
            logger.error(f"Filesystem vulnerability scan error: {str(e)}")
            return format_error(e, "scan_filesystem_vulnerabilities")

    # ========================================================================
    # SECRETS SCANNING TOOLS
    # ========================================================================

    @mcp.tool()
    @secure_tool("scan_secrets_in_file")
    async def scan_secrets_in_file(
        file_path: str,
        format: Literal["json", "toon"] = "json"
    ) -> dict:
        """
        Scan a file for exposed secrets and credentials.

        Detects common secret patterns:
        - API keys (AWS, GitHub, Slack, Stripe, etc.)
        - Private keys (RSA, DSA, EC, OpenSSH)
        - Passwords in connection strings
        - Database credentials
        - JWT tokens
        - Docker registry authentication

        Args:
            file_path: Path to file to scan (e.g., ".env", "config.yml", "docker-compose.yml")
            format: Response format

        Returns:
            List of detected secrets with type, line number, and severity

        Examples:
            - scan_secrets_in_file(file_path=".env")
            - scan_secrets_in_file(file_path="/opt/systemmanager/.env")
            - scan_secrets_in_file(file_path="docker-compose.yml")

        Security:
            Secrets are redacted in results (only first/last 4 chars shown)
        """
        try:
            result = await secrets_scanner.scan_file(file_path)
            return format_response(result, format)

        except Exception as e:
            logger.error(f"Secrets scan error: {str(e)}")
            return format_error(e, "scan_secrets_in_file")

    @mcp.tool()
    @secure_tool("scan_secrets_in_directory")
    async def scan_secrets_in_directory(
        directory: str,
        recursive: bool = True,
        max_files: int = 1000,
        format: Literal["json", "toon"] = "json"
    ) -> dict:
        """
        Scan a directory for exposed secrets in configuration files.

        Recursively scans common config file types for exposed credentials.
        Automatically skips .git, node_modules, and other excluded directories.

        Args:
            directory: Directory path to scan
            recursive: Scan subdirectories (default: True)
            max_files: Maximum number of files to scan (default: 1000)
            format: Response format

        Returns:
            Summary of findings across all files with severity counts

        Examples:
            - scan_secrets_in_directory(directory="/opt/systemmanager")
            - scan_secrets_in_directory(directory="/home/user/project", recursive=True)
            - scan_secrets_in_directory(directory="/etc", max_files=500)

        Scanned Extensions:
            .env, .conf, .config, .ini, .yml, .yaml, .json, .xml, .properties, .toml, .sh
        """
        try:
            result = await secrets_scanner.scan_directory(directory, recursive, max_files)
            return format_response(result, format)

        except Exception as e:
            logger.error(f"Directory secrets scan error: {str(e)}")
            return format_error(e, "scan_secrets_in_directory")

    @mcp.tool()
    @secure_tool("scan_docker_config_secrets")
    async def scan_docker_config_secrets(
        format: Literal["json", "toon"] = "json"
    ) -> dict:
        """
        Scan Docker configuration for exposed credentials.

        Checks ~/.docker/config.json for exposed registry credentials.

        Returns:
            Detected secrets in Docker config

        Example:
            - scan_docker_config_secrets()
        """
        try:
            result = await secrets_scanner.scan_docker_config()
            return format_response(result, format)

        except Exception as e:
            logger.error(f"Docker config scan error: {str(e)}")
            return format_error(e, "scan_docker_config_secrets")

    # ========================================================================
    # FIREWALL MANAGEMENT TOOLS
    # ========================================================================

    @mcp.tool()
    @secure_tool("get_firewall_status")
    async def get_firewall_status(
        format: Literal["json", "toon"] = "json"
    ) -> dict:
        """
        Get firewall status and configuration.

        Works with UFW (Ubuntu/Debian) or iptables (other Linux).

        Returns:
            Firewall status, active state, and default policies

        Example:
            - get_firewall_status()
        """
        try:
            result = await firewall_manager.get_status()
            return format_response(result, format)

        except Exception as e:
            logger.error(f"Firewall status error: {str(e)}")
            return format_error(e, "get_firewall_status")

    @mcp.tool()
    @secure_tool("list_firewall_rules")
    async def list_firewall_rules(
        format: Literal["json", "toon"] = "json"
    ) -> dict:
        """
        List all firewall rules.

        Returns numbered list of all firewall rules with actions and targets.

        Returns:
            List of firewall rules with rule numbers

        Example:
            - list_firewall_rules()
        """
        try:
            result = await firewall_manager.list_rules()
            return format_response(result, format)

        except Exception as e:
            logger.error(f"Firewall list error: {str(e)}")
            return format_error(e, "list_firewall_rules")

    @mcp.tool()
    @secure_tool("add_firewall_rule")
    async def add_firewall_rule(
        action: Literal["allow", "deny"],
        port: Optional[int] = None,
        protocol: Literal["tcp", "udp", "any"] = "tcp",
        from_ip: Optional[str] = None,
        comment: Optional[str] = None,
        format: Literal["json", "toon"] = "json"
    ) -> dict:
        """
        Add a firewall rule.

        Args:
            action: "allow" or "deny"
            port: Port number (optional, for port-specific rules)
            protocol: "tcp", "udp", or "any"
            from_ip: Source IP address to restrict (optional)
            comment: Description of the rule (UFW only)
            format: Response format

        Returns:
            Result of adding the rule

        Examples:
            - add_firewall_rule(action="allow", port=22, protocol="tcp")
            - add_firewall_rule(action="allow", port=443, protocol="tcp", comment="HTTPS")
            - add_firewall_rule(action="allow", from_ip="192.168.1.100", port=22)
            - add_firewall_rule(action="deny", port=23, protocol="tcp", comment="Block Telnet")

        Warning:
            This is a HIGH RISK operation. Test rules carefully to avoid locking yourself out.
        """
        try:
            result = await firewall_manager.add_rule(action, port, protocol, from_ip, comment)
            return format_response(result, format)

        except Exception as e:
            logger.error(f"Firewall add rule error: {str(e)}")
            return format_error(e, "add_firewall_rule")

    @mcp.tool()
    @secure_tool("delete_firewall_rule")
    async def delete_firewall_rule(
        rule_number: int,
        format: Literal["json", "toon"] = "json"
    ) -> dict:
        """
        Delete a firewall rule by number.

        Args:
            rule_number: Rule number to delete (from list_firewall_rules)
            format: Response format

        Returns:
            Result of deleting the rule

        Example:
            - delete_firewall_rule(rule_number=5)

        Warning:
            This is a HIGH RISK operation. Verify rule number before deletion.
        """
        try:
            result = await firewall_manager.delete_rule(rule_number)
            return format_response(result, format)

        except Exception as e:
            logger.error(f"Firewall delete rule error: {str(e)}")
            return format_error(e, "delete_firewall_rule")

    # ========================================================================
    # CIS BENCHMARK / SECURITY POSTURE TOOLS
    # ========================================================================

    @mcp.tool()
    @secure_tool("run_cis_benchmark")
    async def run_cis_benchmark(
        profile: Literal["basic", "intermediate", "comprehensive"] = "basic",
        format: Literal["json", "toon"] = "json"
    ) -> dict:
        """
        Run CIS Linux benchmark security assessment.

        Performs automated security posture checks based on CIS benchmarks:
        - Filesystem permissions (passwd, shadow, SSH config)
        - SSH configuration (root login, password auth, empty passwords)
        - Network security (IP forwarding, ICMP redirects)
        - System auditing (auditd)
        - User account security (UID 0, password complexity)
        - Firewall configuration
        - Kernel security parameters

        Args:
            profile: Assessment level
                - "basic": Essential security checks (10-15 checks)
                - "intermediate": Basic + additional checks (15-20 checks)
                - "comprehensive": All available checks (20+ checks)
            format: Response format

        Returns:
            Assessment results with:
            - Total checks performed
            - Pass/fail/warning counts
            - Security score (percentage)
            - Detailed findings with remediation steps

        Examples:
            - run_cis_benchmark(profile="basic")
            - run_cis_benchmark(profile="comprehensive")

        Check Categories:
            1.x - Filesystem & Permissions
            2.x - SSH Configuration
            3.x - Network Security
            4.x - System Auditing
            5.x - User Accounts & Authentication
        """
        try:
            result = await cis_checker.run_assessment(profile)
            return format_response(result, format)

        except Exception as e:
            logger.error(f"CIS benchmark error: {str(e)}")
            return format_error(e, "run_cis_benchmark")

    # ========================================================================
    # UTILITY / INFO TOOLS
    # ========================================================================

    @mcp.tool()
    @secure_tool("get_security_scanner_info")
    async def get_security_scanner_info(
        format: Literal["json", "toon"] = "json"
    ) -> dict:
        """
        Get information about available security scanners.

        Returns:
            Availability status of security tools (trivy, grype, ufw, iptables)

        Example:
            - get_security_scanner_info()
        """
        try:
            scanner_info = security_scanner.get_scanner_info()
            firewall_info = firewall_manager.get_firewall_info()

            result = {
                "success": True,
                "scanners": scanner_info,
                "firewall": firewall_info
            }

            return format_response(result, format)

        except Exception as e:
            logger.error(f"Scanner info error: {str(e)}")
            return format_error(e, "get_security_scanner_info")
