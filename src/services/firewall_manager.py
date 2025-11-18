"""
Firewall management service for UFW and iptables.

Supports:
- UFW (Uncomplicated Firewall) - preferred for Ubuntu/Debian
- iptables - fallback for other Linux distributions
"""

import asyncio
import shutil
import re
from typing import Dict, List, Optional


class FirewallManager:
    """Service for managing firewall rules."""

    def __init__(self):
        # Check which firewall is available
        self.ufw_available = shutil.which("ufw") is not None
        self.iptables_available = shutil.which("iptables") is not None

    async def get_status(self) -> Dict:
        """Get firewall status."""
        if self.ufw_available:
            return await self._get_ufw_status()
        elif self.iptables_available:
            return await self._get_iptables_status()
        else:
            return {
                "success": False,
                "error": "No firewall found (ufw or iptables)"
            }

    async def list_rules(self) -> Dict:
        """List all firewall rules."""
        if self.ufw_available:
            return await self._list_ufw_rules()
        elif self.iptables_available:
            return await self._list_iptables_rules()
        else:
            return {
                "success": False,
                "error": "No firewall found"
            }

    async def add_rule(
        self,
        action: str,
        port: Optional[int] = None,
        protocol: str = "tcp",
        from_ip: Optional[str] = None,
        comment: Optional[str] = None
    ) -> Dict:
        """
        Add a firewall rule.

        Args:
            action: "allow" or "deny"
            port: Port number (optional)
            protocol: "tcp" or "udp"
            from_ip: Source IP address (optional)
            comment: Description of the rule

        Returns:
            Result of adding the rule
        """
        if action not in ["allow", "deny"]:
            return {"success": False, "error": "Action must be 'allow' or 'deny'"}

        if protocol not in ["tcp", "udp", "any"]:
            return {"success": False, "error": "Protocol must be 'tcp', 'udp', or 'any'"}

        if self.ufw_available:
            return await self._add_ufw_rule(action, port, protocol, from_ip, comment)
        elif self.iptables_available:
            return await self._add_iptables_rule(action, port, protocol, from_ip)
        else:
            return {"success": False, "error": "No firewall found"}

    async def delete_rule(self, rule_number: int) -> Dict:
        """
        Delete a firewall rule by number.

        Args:
            rule_number: Rule number to delete

        Returns:
            Result of deleting the rule
        """
        if self.ufw_available:
            return await self._delete_ufw_rule(rule_number)
        elif self.iptables_available:
            return await self._delete_iptables_rule(rule_number)
        else:
            return {"success": False, "error": "No firewall found"}

    # UFW Methods

    async def _get_ufw_status(self) -> Dict:
        """Get UFW status."""
        try:
            process = await asyncio.create_subprocess_exec(
                "ufw", "status", "verbose",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                return {"success": False, "error": stderr.decode()}

            output = stdout.decode()

            # Parse status
            status_active = "Status: active" in output
            default_incoming = "deny (incoming)" if "deny (incoming)" in output else "allow (incoming)"
            default_outgoing = "deny (outgoing)" if "deny (outgoing)" in output else "allow (outgoing)"

            return {
                "success": True,
                "firewall": "ufw",
                "active": status_active,
                "default_incoming": default_incoming,
                "default_outgoing": default_outgoing,
                "raw_output": output
            }

        except Exception as e:
            return {"success": False, "error": f"UFW status error: {str(e)}"}

    async def _list_ufw_rules(self) -> Dict:
        """List UFW rules."""
        try:
            process = await asyncio.create_subprocess_exec(
                "ufw", "status", "numbered",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                return {"success": False, "error": stderr.decode()}

            output = stdout.decode()

            # Parse rules
            rules = []
            for line in output.split("\n"):
                # Match lines like: [ 1] 22/tcp ALLOW IN Anywhere
                match = re.match(r"\[\s*(\d+)\]\s+(.+)", line)
                if match:
                    rule_num = int(match.group(1))
                    rule_text = match.group(2).strip()
                    rules.append({
                        "number": rule_num,
                        "rule": rule_text
                    })

            return {
                "success": True,
                "firewall": "ufw",
                "rule_count": len(rules),
                "rules": rules
            }

        except Exception as e:
            return {"success": False, "error": f"UFW list error: {str(e)}"}

    async def _add_ufw_rule(
        self,
        action: str,
        port: Optional[int],
        protocol: str,
        from_ip: Optional[str],
        comment: Optional[str]
    ) -> Dict:
        """Add UFW rule."""
        try:
            cmd = ["ufw"]

            # Build command
            if from_ip:
                cmd.extend(["allow", "from", from_ip])
                if port:
                    cmd.extend(["to", "any", "port", str(port)])
                    if protocol != "any":
                        cmd.append(f"proto {protocol}")
            else:
                cmd.append(action)
                if port:
                    cmd.append(f"{port}/{protocol}" if protocol != "any" else str(port))

            if comment:
                cmd.extend(["comment", comment])

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                return {"success": False, "error": stderr.decode()}

            return {
                "success": True,
                "message": f"UFW rule added: {' '.join(cmd[1:])}",
                "output": stdout.decode()
            }

        except Exception as e:
            return {"success": False, "error": f"UFW add rule error: {str(e)}"}

    async def _delete_ufw_rule(self, rule_number: int) -> Dict:
        """Delete UFW rule."""
        try:
            # UFW delete requires confirmation, use --force
            process = await asyncio.create_subprocess_exec(
                "ufw", "--force", "delete", str(rule_number),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                return {"success": False, "error": stderr.decode()}

            return {
                "success": True,
                "message": f"UFW rule {rule_number} deleted",
                "output": stdout.decode()
            }

        except Exception as e:
            return {"success": False, "error": f"UFW delete rule error: {str(e)}"}

    # iptables Methods

    async def _get_iptables_status(self) -> Dict:
        """Get iptables status."""
        try:
            # Count rules
            process = await asyncio.create_subprocess_exec(
                "iptables", "-L", "-n", "--line-numbers",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                return {"success": False, "error": stderr.decode()}

            output = stdout.decode()
            rule_count = len([l for l in output.split("\n") if l and not l.startswith("Chain") and not l.startswith("num")])

            return {
                "success": True,
                "firewall": "iptables",
                "active": True,
                "rule_count": rule_count,
                "raw_output": output[:500]  # Truncate
            }

        except Exception as e:
            return {"success": False, "error": f"iptables status error: {str(e)}"}

    async def _list_iptables_rules(self) -> Dict:
        """List iptables rules."""
        try:
            process = await asyncio.create_subprocess_exec(
                "iptables", "-L", "-n", "--line-numbers", "-v",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                return {"success": False, "error": stderr.decode()}

            output = stdout.decode()

            # Parse rules by chain
            chains = {}
            current_chain = None

            for line in output.split("\n"):
                if line.startswith("Chain"):
                    current_chain = line.split()[1]
                    chains[current_chain] = []
                elif current_chain and line.strip() and not line.startswith("num"):
                    chains[current_chain].append(line.strip())

            return {
                "success": True,
                "firewall": "iptables",
                "chains": chains,
                "raw_output": output[:1000]  # Truncate
            }

        except Exception as e:
            return {"success": False, "error": f"iptables list error: {str(e)}"}

    async def _add_iptables_rule(
        self,
        action: str,
        port: Optional[int],
        protocol: str,
        from_ip: Optional[str]
    ) -> Dict:
        """Add iptables rule."""
        try:
            # Convert action to iptables target
            target = "ACCEPT" if action == "allow" else "DROP"

            cmd = ["iptables", "-A", "INPUT"]

            if from_ip:
                cmd.extend(["-s", from_ip])

            if protocol != "any":
                cmd.extend(["-p", protocol])

            if port:
                cmd.extend(["--dport", str(port)])

            cmd.extend(["-j", target])

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                return {"success": False, "error": stderr.decode()}

            return {
                "success": True,
                "message": f"iptables rule added: {' '.join(cmd)}",
                "warning": "iptables rules are not persistent. Use iptables-save to persist."
            }

        except Exception as e:
            return {"success": False, "error": f"iptables add rule error: {str(e)}"}

    async def _delete_iptables_rule(self, rule_number: int) -> Dict:
        """Delete iptables rule."""
        try:
            process = await asyncio.create_subprocess_exec(
                "iptables", "-D", "INPUT", str(rule_number),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                return {"success": False, "error": stderr.decode()}

            return {
                "success": True,
                "message": f"iptables rule {rule_number} deleted"
            }

        except Exception as e:
            return {"success": False, "error": f"iptables delete rule error: {str(e)}"}

    def get_firewall_info(self) -> Dict:
        """Get information about available firewalls."""
        return {
            "ufw_available": self.ufw_available,
            "iptables_available": self.iptables_available,
            "preferred_firewall": "ufw" if self.ufw_available else "iptables" if self.iptables_available else None
        }
