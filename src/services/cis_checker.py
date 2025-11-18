"""
CIS Benchmark security posture assessment service.

Implements basic CIS Linux benchmark checks for:
- Filesystem permissions
- SSH configuration
- User/password policies
- Network security
- System auditing
"""

import asyncio
import os
from pathlib import Path
from typing import Dict, List, Optional


class CISChecker:
    """Service for CIS benchmark security assessment."""

    def __init__(self):
        pass

    async def run_assessment(self, profile: str = "basic") -> Dict:
        """
        Run CIS benchmark assessment.

        Args:
            profile: Assessment profile ("basic", "intermediate", "comprehensive")

        Returns:
            Assessment results with pass/fail for each check
        """
        if profile == "basic":
            checks = await self._run_basic_checks()
        elif profile == "intermediate":
            checks = await self._run_intermediate_checks()
        elif profile == "comprehensive":
            checks = await self._run_comprehensive_checks()
        else:
            return {"success": False, "error": f"Unknown profile: {profile}"}

        # Summarize results
        passed = sum(1 for c in checks if c["status"] == "PASS")
        failed = sum(1 for c in checks if c["status"] == "FAIL")
        warnings = sum(1 for c in checks if c["status"] == "WARN")
        skipped = sum(1 for c in checks if c["status"] == "SKIP")

        # Calculate score
        total_scored = passed + failed
        score = (passed / total_scored * 100) if total_scored > 0 else 0

        return {
            "success": True,
            "profile": profile,
            "total_checks": len(checks),
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "skipped": skipped,
            "score": round(score, 1),
            "checks": checks
        }

    async def _run_basic_checks(self) -> List[Dict]:
        """Run basic CIS checks."""
        checks = []

        # Check 1.1: Filesystem Permissions
        checks.append(await self._check_file_permissions("/etc/passwd", "644", "1.1.1"))
        checks.append(await self._check_file_permissions("/etc/shadow", "000", "1.1.2"))
        checks.append(await self._check_file_permissions("/etc/group", "644", "1.1.3"))

        # Check 2.1: SSH Configuration
        checks.append(await self._check_ssh_root_login("2.1.1"))
        checks.append(await self._check_ssh_password_auth("2.1.2"))
        checks.append(await self._check_ssh_permit_empty_passwords("2.1.3"))

        # Check 3.1: Network Security
        checks.append(await self._check_ip_forwarding("3.1.1"))
        checks.append(await self._check_icmp_redirects("3.1.2"))

        # Check 4.1: System Auditing
        checks.append(await self._check_auditd_installed("4.1.1"))

        # Check 5.1: User Accounts
        checks.append(await self._check_root_uid("5.1.1"))
        checks.append(await self._check_password_complexity("5.1.2"))

        return checks

    async def _run_intermediate_checks(self) -> List[Dict]:
        """Run intermediate CIS checks (includes basic + more)."""
        checks = await self._run_basic_checks()

        # Additional filesystem checks
        checks.append(await self._check_file_permissions("/etc/ssh/sshd_config", "600", "1.2.1"))
        checks.append(await self._check_file_permissions("/etc/crontab", "600", "1.2.2"))

        # Additional network checks
        checks.append(await self._check_firewall_enabled("3.2.1"))

        # Additional service checks
        checks.append(await self._check_unnecessary_services("4.2.1"))

        return checks

    async def _run_comprehensive_checks(self) -> List[Dict]:
        """Run comprehensive CIS checks (all checks)."""
        checks = await self._run_intermediate_checks()

        # Additional comprehensive checks
        checks.append(await self._check_kernel_parameters("3.3.1"))
        checks.append(await self._check_sudo_configuration("5.2.1"))
        checks.append(await self._check_file_integrity_monitoring("4.3.1"))

        return checks

    # Individual Check Methods

    async def _check_file_permissions(self, file_path: str, expected_perms: str, check_id: str) -> Dict:
        """Check file permissions."""
        try:
            path = Path(file_path)

            if not path.exists():
                return {
                    "id": check_id,
                    "name": f"File Permissions: {file_path}",
                    "status": "SKIP",
                    "message": f"File not found: {file_path}",
                    "remediation": None
                }

            # Get actual permissions
            stat_info = path.stat()
            actual_perms = oct(stat_info.st_mode)[-3:]

            # Check if more restrictive than expected
            passed = actual_perms <= expected_perms

            return {
                "id": check_id,
                "name": f"File Permissions: {file_path}",
                "status": "PASS" if passed else "FAIL",
                "expected": expected_perms,
                "actual": actual_perms,
                "message": f"Permissions: {actual_perms} (expected: {expected_perms} or more restrictive)",
                "remediation": f"chmod {expected_perms} {file_path}" if not passed else None
            }

        except Exception as e:
            return {
                "id": check_id,
                "name": f"File Permissions: {file_path}",
                "status": "WARN",
                "message": f"Error checking permissions: {str(e)}",
                "remediation": None
            }

    async def _check_ssh_root_login(self, check_id: str) -> Dict:
        """Check if SSH root login is disabled."""
        try:
            ssh_config = Path("/etc/ssh/sshd_config")

            if not ssh_config.exists():
                return {
                    "id": check_id,
                    "name": "SSH Root Login Disabled",
                    "status": "SKIP",
                    "message": "sshd_config not found",
                    "remediation": None
                }

            content = ssh_config.read_text()

            # Check for PermitRootLogin no
            passed = "PermitRootLogin no" in content or "PermitRootLogin without-password" in content

            return {
                "id": check_id,
                "name": "SSH Root Login Disabled",
                "status": "PASS" if passed else "FAIL",
                "message": "Root login is disabled" if passed else "Root login is enabled",
                "remediation": "Add 'PermitRootLogin no' to /etc/ssh/sshd_config" if not passed else None
            }

        except Exception as e:
            return {
                "id": check_id,
                "name": "SSH Root Login Disabled",
                "status": "WARN",
                "message": f"Error checking SSH config: {str(e)}",
                "remediation": None
            }

    async def _check_ssh_password_auth(self, check_id: str) -> Dict:
        """Check if SSH password authentication is recommended."""
        try:
            ssh_config = Path("/etc/ssh/sshd_config")

            if not ssh_config.exists():
                return {
                    "id": check_id,
                    "name": "SSH Password Authentication",
                    "status": "SKIP",
                    "message": "sshd_config not found",
                    "remediation": None
                }

            content = ssh_config.read_text()

            # Password auth disabled is more secure (key-only)
            key_only = "PasswordAuthentication no" in content

            return {
                "id": check_id,
                "name": "SSH Password Authentication",
                "status": "PASS" if key_only else "WARN",
                "message": "Key-only authentication" if key_only else "Password authentication enabled (consider key-only)",
                "remediation": "Add 'PasswordAuthentication no' to /etc/ssh/sshd_config for maximum security" if not key_only else None
            }

        except Exception as e:
            return {
                "id": check_id,
                "name": "SSH Password Authentication",
                "status": "WARN",
                "message": f"Error checking SSH config: {str(e)}",
                "remediation": None
            }

    async def _check_ssh_permit_empty_passwords(self, check_id: str) -> Dict:
        """Check if empty passwords are disallowed."""
        try:
            ssh_config = Path("/etc/ssh/sshd_config")

            if not ssh_config.exists():
                return {
                    "id": check_id,
                    "name": "SSH Empty Passwords Disallowed",
                    "status": "SKIP",
                    "message": "sshd_config not found",
                    "remediation": None
                }

            content = ssh_config.read_text()

            passed = "PermitEmptyPasswords no" in content

            return {
                "id": check_id,
                "name": "SSH Empty Passwords Disallowed",
                "status": "PASS" if passed else "FAIL",
                "message": "Empty passwords disallowed" if passed else "Empty passwords may be allowed",
                "remediation": "Add 'PermitEmptyPasswords no' to /etc/ssh/sshd_config" if not passed else None
            }

        except Exception as e:
            return {
                "id": check_id,
                "name": "SSH Empty Passwords Disallowed",
                "status": "WARN",
                "message": f"Error checking SSH config: {str(e)}",
                "remediation": None
            }

    async def _check_ip_forwarding(self, check_id: str) -> Dict:
        """Check if IP forwarding is disabled."""
        try:
            # Check IPv4 forwarding
            ipv4_forward_file = Path("/proc/sys/net/ipv4/ip_forward")

            if ipv4_forward_file.exists():
                value = ipv4_forward_file.read_text().strip()
                passed = value == "0"

                return {
                    "id": check_id,
                    "name": "IP Forwarding Disabled",
                    "status": "PASS" if passed else "WARN",
                    "message": f"IP forwarding is {'disabled' if passed else 'enabled'}",
                    "remediation": "Set net.ipv4.ip_forward=0 in /etc/sysctl.conf" if not passed else None
                }
            else:
                return {
                    "id": check_id,
                    "name": "IP Forwarding Disabled",
                    "status": "SKIP",
                    "message": "Cannot check IP forwarding",
                    "remediation": None
                }

        except Exception as e:
            return {
                "id": check_id,
                "name": "IP Forwarding Disabled",
                "status": "WARN",
                "message": f"Error checking IP forwarding: {str(e)}",
                "remediation": None
            }

    async def _check_icmp_redirects(self, check_id: str) -> Dict:
        """Check if ICMP redirects are disabled."""
        try:
            icmp_file = Path("/proc/sys/net/ipv4/conf/all/accept_redirects")

            if icmp_file.exists():
                value = icmp_file.read_text().strip()
                passed = value == "0"

                return {
                    "id": check_id,
                    "name": "ICMP Redirects Disabled",
                    "status": "PASS" if passed else "WARN",
                    "message": f"ICMP redirects are {'disabled' if passed else 'enabled'}",
                    "remediation": "Set net.ipv4.conf.all.accept_redirects=0 in /etc/sysctl.conf" if not passed else None
                }
            else:
                return {
                    "id": check_id,
                    "name": "ICMP Redirects Disabled",
                    "status": "SKIP",
                    "message": "Cannot check ICMP redirects",
                    "remediation": None
                }

        except Exception as e:
            return {
                "id": check_id,
                "name": "ICMP Redirects Disabled",
                "status": "WARN",
                "message": f"Error: {str(e)}",
                "remediation": None
            }

    async def _check_auditd_installed(self, check_id: str) -> Dict:
        """Check if auditd is installed."""
        try:
            process = await asyncio.create_subprocess_exec(
                "which", "auditd",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()
            passed = process.returncode == 0

            return {
                "id": check_id,
                "name": "Auditd Installed",
                "status": "PASS" if passed else "WARN",
                "message": "auditd is installed" if passed else "auditd is not installed",
                "remediation": "Install auditd: apt-get install auditd (Debian/Ubuntu) or yum install audit (RHEL/CentOS)" if not passed else None
            }

        except Exception as e:
            return {
                "id": check_id,
                "name": "Auditd Installed",
                "status": "WARN",
                "message": f"Error: {str(e)}",
                "remediation": None
            }

    async def _check_root_uid(self, check_id: str) -> Dict:
        """Check if only root has UID 0."""
        try:
            passwd_file = Path("/etc/passwd")
            uid_0_users = []

            for line in passwd_file.read_text().split("\n"):
                if line and ":" in line:
                    parts = line.split(":")
                    if len(parts) > 2 and parts[2] == "0":
                        uid_0_users.append(parts[0])

            passed = uid_0_users == ["root"]

            return {
                "id": check_id,
                "name": "Only Root Has UID 0",
                "status": "PASS" if passed else "FAIL",
                "message": f"Users with UID 0: {', '.join(uid_0_users)}",
                "remediation": f"Remove UID 0 from non-root users: {', '.join([u for u in uid_0_users if u != 'root'])}" if not passed else None
            }

        except Exception as e:
            return {
                "id": check_id,
                "name": "Only Root Has UID 0",
                "status": "WARN",
                "message": f"Error: {str(e)}",
                "remediation": None
            }

    async def _check_password_complexity(self, check_id: str) -> Dict:
        """Check password complexity requirements."""
        try:
            # Check if pam_pwquality or pam_cracklib is configured
            pam_file = Path("/etc/pam.d/common-password")

            if not pam_file.exists():
                return {
                    "id": check_id,
                    "name": "Password Complexity Configured",
                    "status": "SKIP",
                    "message": "PAM config not found",
                    "remediation": None
                }

            content = pam_file.read_text()
            passed = "pam_pwquality" in content or "pam_cracklib" in content

            return {
                "id": check_id,
                "name": "Password Complexity Configured",
                "status": "PASS" if passed else "WARN",
                "message": "Password complexity is enforced" if passed else "Password complexity may not be enforced",
                "remediation": "Configure pam_pwquality in /etc/pam.d/common-password" if not passed else None
            }

        except Exception as e:
            return {
                "id": check_id,
                "name": "Password Complexity Configured",
                "status": "WARN",
                "message": f"Error: {str(e)}",
                "remediation": None
            }

    async def _check_firewall_enabled(self, check_id: str) -> Dict:
        """Check if firewall is enabled."""
        try:
            # Check UFW
            process = await asyncio.create_subprocess_exec(
                "ufw", "status",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                output = stdout.decode()
                passed = "Status: active" in output

                return {
                    "id": check_id,
                    "name": "Firewall Enabled",
                    "status": "PASS" if passed else "FAIL",
                    "message": "Firewall is active" if passed else "Firewall is inactive",
                    "remediation": "Enable firewall: ufw enable" if not passed else None
                }
            else:
                return {
                    "id": check_id,
                    "name": "Firewall Enabled",
                    "status": "WARN",
                    "message": "Cannot determine firewall status",
                    "remediation": "Install and configure a firewall (ufw recommended)"
                }

        except Exception as e:
            return {
                "id": check_id,
                "name": "Firewall Enabled",
                "status": "WARN",
                "message": f"Error: {str(e)}",
                "remediation": None
            }

    async def _check_unnecessary_services(self, check_id: str) -> Dict:
        """Check for unnecessary services."""
        # This is a placeholder - would need more context about what's "necessary"
        return {
            "id": check_id,
            "name": "Unnecessary Services Check",
            "status": "SKIP",
            "message": "Manual review required",
            "remediation": "Review running services with 'systemctl list-units --type=service'"
        }

    async def _check_kernel_parameters(self, check_id: str) -> Dict:
        """Check kernel security parameters."""
        return {
            "id": check_id,
            "name": "Kernel Security Parameters",
            "status": "SKIP",
            "message": "Manual review required",
            "remediation": "Review /etc/sysctl.conf for security parameters"
        }

    async def _check_sudo_configuration(self, check_id: str) -> Dict:
        """Check sudo configuration."""
        try:
            sudoers_file = Path("/etc/sudoers")

            if not sudoers_file.exists():
                return {
                    "id": check_id,
                    "name": "Sudo Configuration",
                    "status": "SKIP",
                    "message": "sudoers file not found",
                    "remediation": None
                }

            # Check permissions
            stat_info = sudoers_file.stat()
            perms = oct(stat_info.st_mode)[-3:]
            passed = perms == "440" or perms == "400"

            return {
                "id": check_id,
                "name": "Sudo Configuration",
                "status": "PASS" if passed else "WARN",
                "message": f"/etc/sudoers permissions: {perms}",
                "remediation": "chmod 440 /etc/sudoers" if not passed else None
            }

        except Exception as e:
            return {
                "id": check_id,
                "name": "Sudo Configuration",
                "status": "WARN",
                "message": f"Error: {str(e)}",
                "remediation": None
            }

    async def _check_file_integrity_monitoring(self, check_id: str) -> Dict:
        """Check if file integrity monitoring is configured."""
        try:
            # Check if AIDE is installed
            process = await asyncio.create_subprocess_exec(
                "which", "aide",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()
            passed = process.returncode == 0

            return {
                "id": check_id,
                "name": "File Integrity Monitoring",
                "status": "PASS" if passed else "WARN",
                "message": "AIDE is installed" if passed else "File integrity monitoring not configured",
                "remediation": "Install AIDE: apt-get install aide (Debian/Ubuntu)" if not passed else None
            }

        except Exception as e:
            return {
                "id": check_id,
                "name": "File Integrity Monitoring",
                "status": "WARN",
                "message": f"Error: {str(e)}",
                "remediation": None
            }
