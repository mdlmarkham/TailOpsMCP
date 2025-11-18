"""Let's Encrypt certificate automation tools.

Provides automated SSL certificate management using certbot/acme.sh
for homelab services.
"""

from __future__ import annotations

import asyncio
import json
import os
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from pathlib import Path
import subprocess
from asyncio import to_thread

from fastmcp import FastMCP
from src.utils.audit import AuditLogger
from src.auth.middleware import secure_tool
from src.server.utils import format_error
from pydantic import BaseModel


audit = AuditLogger()
logger = logging.getLogger(__name__)


class CertificateInfo(BaseModel):
    """Information about an SSL certificate."""
    domain: str
    issuer: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    days_remaining: Optional[int] = None
    status: str = "unknown"  # valid, expiring_soon, expired, not_found
    cert_path: Optional[str] = None
    key_path: Optional[str] = None


class CertificateRequest(BaseModel):
    """Request to obtain a new certificate."""
    domain: str
    additional_domains: Optional[List[str]] = []
    email: str
    challenge_type: str = "http-01"  # http-01, dns-01
    webroot_path: Optional[str] = None
    dns_provider: Optional[str] = None
    staging: bool = False  # Use Let's Encrypt staging for testing


class CertificateResult(BaseModel):
    """Result of certificate operation."""
    success: bool
    domain: str
    cert_path: Optional[str] = None
    key_path: Optional[str] = None
    fullchain_path: Optional[str] = None
    error: Optional[str] = None
    renewed: bool = False


async def check_certificate(
    domain: str,
    cert_path: Optional[str] = None
) -> Dict[str, Any]:
    """Check certificate status and expiration.

    Args:
        domain: Domain name to check
        cert_path: Optional path to certificate file (auto-detect if not provided)

    Returns:
        CertificateInfo with certificate status and metadata
    """
    try:
        # Auto-detect certbot path if not provided
        if not cert_path:
            # Try common certbot paths
            cert_paths = [
                f"/etc/letsencrypt/live/{domain}/cert.pem",
                f"/etc/letsencrypt/live/{domain}/fullchain.pem",
            ]
            for path in cert_paths:
                if os.path.exists(path):
                    cert_path = path
                    break

        if not cert_path or not os.path.exists(cert_path):
            # Try to get info from remote server
            cmd = [
                "openssl", "s_client",
                "-connect", f"{domain}:443",
                "-servername", domain,
                "-showcerts"
            ]

            result = await to_thread(
                subprocess.run,
                cmd,
                input="",
                capture_output=True,
                text=True,
                timeout=10
            )

            # Extract certificate from output
            cert_text = result.stdout
            if "BEGIN CERTIFICATE" not in cert_text:
                return CertificateInfo(
                    domain=domain,
                    status="not_found"
                ).dict()

            # Write to temp file for parsing
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as f:
                # Extract first certificate
                start = cert_text.find("-----BEGIN CERTIFICATE-----")
                end = cert_text.find("-----END CERTIFICATE-----") + len("-----END CERTIFICATE-----")
                f.write(cert_text[start:end])
                temp_cert_path = f.name

            cert_path = temp_cert_path

        # Parse certificate details
        cmd = [
            "openssl", "x509",
            "-in", cert_path,
            "-noout",
            "-dates",
            "-issuer",
            "-subject"
        ]

        result = await to_thread(
            subprocess.run,
            cmd,
            capture_output=True,
            text=True,
            check=True
        )

        # Parse output
        output = result.stdout
        issuer = None
        valid_from = None
        valid_until = None

        for line in output.splitlines():
            if line.startswith("notBefore="):
                date_str = line.replace("notBefore=", "").strip()
                valid_from = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
            elif line.startswith("notAfter="):
                date_str = line.replace("notAfter=", "").strip()
                valid_until = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
            elif line.startswith("issuer="):
                issuer = line.replace("issuer=", "").strip()

        # Calculate days remaining
        days_remaining = None
        status = "unknown"
        if valid_until:
            days_remaining = (valid_until - datetime.now()).days
            if days_remaining < 0:
                status = "expired"
            elif days_remaining < 30:
                status = "expiring_soon"
            else:
                status = "valid"

        # Determine cert and key paths
        key_path = None
        if cert_path.endswith("/cert.pem"):
            key_path = cert_path.replace("/cert.pem", "/privkey.pem")
        elif cert_path.endswith("/fullchain.pem"):
            key_path = cert_path.replace("/fullchain.pem", "/privkey.pem")

        cert_info = CertificateInfo(
            domain=domain,
            issuer=issuer,
            valid_from=valid_from,
            valid_until=valid_until,
            days_remaining=days_remaining,
            status=status,
            cert_path=cert_path if os.path.exists(cert_path) else None,
            key_path=key_path if key_path and os.path.exists(key_path) else None
        )

        audit.log("check_certificate", {
            "domain": domain
        }, {
            "success": True,
            "status": status,
            "days_remaining": days_remaining
        })

        return cert_info.dict()

    except Exception as e:
        audit.log("check_certificate", {
            "domain": domain
        }, {
            "success": False,
            "error": str(e)
        })
        return CertificateInfo(
            domain=domain,
            status="error"
        ).dict()


async def obtain_certificate(
    domain: str,
    email: str,
    additional_domains: Optional[List[str]] = None,
    challenge_type: str = "http-01",
    webroot_path: Optional[str] = None,
    dns_provider: Optional[str] = None,
    staging: bool = False,
    dry_run: bool = False
) -> Dict[str, Any]:
    """Obtain a new Let's Encrypt certificate.

    Args:
        domain: Primary domain name
        email: Email for certificate notifications
        additional_domains: Additional domains for SAN certificate
        challenge_type: Challenge type (http-01 or dns-01)
        webroot_path: Path for HTTP challenge (required for http-01)
        dns_provider: DNS provider for DNS challenge (required for dns-01)
        staging: Use Let's Encrypt staging environment
        dry_run: Test without actually obtaining certificate

    Returns:
        CertificateResult with certificate paths and status
    """
    try:
        # Check if certbot is installed
        which_result = await to_thread(
            subprocess.run,
            ["which", "certbot"],
            capture_output=True,
            text=True
        )

        if which_result.returncode != 0:
            return CertificateResult(
                success=False,
                domain=domain,
                error="certbot not installed. Install with: apt-get install certbot"
            ).dict()

        # Build certbot command
        cmd = ["certbot", "certonly"]

        # Add domains
        cmd.extend(["-d", domain])
        if additional_domains:
            for d in additional_domains:
                cmd.extend(["-d", d])

        # Add email
        cmd.extend(["--email", email])
        cmd.append("--agree-tos")
        cmd.append("--non-interactive")

        # Add challenge type
        if challenge_type == "http-01":
            if not webroot_path:
                return CertificateResult(
                    success=False,
                    domain=domain,
                    error="webroot_path required for http-01 challenge"
                ).dict()
            cmd.extend(["--webroot", "-w", webroot_path])
        elif challenge_type == "dns-01":
            if not dns_provider:
                return CertificateResult(
                    success=False,
                    domain=domain,
                    error="dns_provider required for dns-01 challenge"
                ).dict()
            cmd.extend([f"--dns-{dns_provider}"])
        else:
            return CertificateResult(
                success=False,
                domain=domain,
                error=f"Invalid challenge_type: {challenge_type}"
            ).dict()

        # Add staging if requested
        if staging:
            cmd.append("--staging")

        # Add dry-run if requested
        if dry_run:
            cmd.append("--dry-run")

        # Execute certbot
        result = await to_thread(
            subprocess.run,
            cmd,
            capture_output=True,
            text=True,
            check=True
        )

        # Determine certificate paths
        cert_path = f"/etc/letsencrypt/live/{domain}/cert.pem"
        key_path = f"/etc/letsencrypt/live/{domain}/privkey.pem"
        fullchain_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"

        cert_result = CertificateResult(
            success=True,
            domain=domain,
            cert_path=cert_path if not dry_run else None,
            key_path=key_path if not dry_run else None,
            fullchain_path=fullchain_path if not dry_run else None,
            renewed=False
        )

        audit.log("obtain_certificate", {
            "domain": domain,
            "challenge_type": challenge_type,
            "staging": staging,
            "dry_run": dry_run
        }, {
            "success": True,
            "cert_path": cert_path if not dry_run else None
        })

        return cert_result.dict()

    except subprocess.CalledProcessError as e:
        error_msg = f"Certificate request failed: {e.stderr}"
        audit.log("obtain_certificate", {
            "domain": domain
        }, {
            "success": False,
            "error": error_msg
        })
        return CertificateResult(
            success=False,
            domain=domain,
            error=error_msg
        ).dict()

    except Exception as e:
        error_msg = f"Certificate request failed: {str(e)}"
        audit.log("obtain_certificate", {
            "domain": domain
        }, {
            "success": False,
            "error": error_msg
        })
        return CertificateResult(
            success=False,
            domain=domain,
            error=error_msg
        ).dict()


async def renew_certificate(
    domain: Optional[str] = None,
    force: bool = False,
    dry_run: bool = False
) -> Dict[str, Any]:
    """Renew Let's Encrypt certificate(s).

    Args:
        domain: Specific domain to renew (None for all)
        force: Force renewal even if not expiring soon
        dry_run: Test renewal without actually renewing

    Returns:
        CertificateResult with renewal status
    """
    try:
        # Build certbot command
        cmd = ["certbot", "renew"]

        if domain:
            cmd.extend(["--cert-name", domain])

        if force:
            cmd.append("--force-renewal")

        if dry_run:
            cmd.append("--dry-run")

        # Execute certbot
        result = await to_thread(
            subprocess.run,
            cmd,
            capture_output=True,
            text=True,
            check=True
        )

        # Parse output to determine if renewal occurred
        renewed = "Renewing" in result.stdout or "renewed" in result.stdout

        cert_result = CertificateResult(
            success=True,
            domain=domain or "all",
            renewed=renewed
        )

        audit.log("renew_certificate", {
            "domain": domain,
            "force": force,
            "dry_run": dry_run
        }, {
            "success": True,
            "renewed": renewed
        })

        return cert_result.dict()

    except subprocess.CalledProcessError as e:
        error_msg = f"Certificate renewal failed: {e.stderr}"
        audit.log("renew_certificate", {
            "domain": domain
        }, {
            "success": False,
            "error": error_msg
        })
        return CertificateResult(
            success=False,
            domain=domain or "all",
            error=error_msg
        ).dict()

    except Exception as e:
        error_msg = f"Certificate renewal failed: {str(e)}"
        audit.log("renew_certificate", {
            "domain": domain
        }, {
            "success": False,
            "error": error_msg
        })
        return CertificateResult(
            success=False,
            domain=domain or "all",
            error=error_msg
        ).dict()


async def list_certificates() -> List[Dict[str, Any]]:
    """List all Let's Encrypt certificates managed by certbot.

    Returns:
        List of certificates with their status
    """
    certificates = []

    try:
        # Run certbot certificates command
        result = await to_thread(
            subprocess.run,
            ["certbot", "certificates"],
            capture_output=True,
            text=True,
            check=True
        )

        # Parse output
        # Format is typically:
        # Certificate Name: example.com
        #   Domains: example.com www.example.com
        #   Expiry Date: 2024-06-01 12:00:00+00:00
        #   Certificate Path: /etc/letsencrypt/live/example.com/fullchain.pem
        #   Private Key Path: /etc/letsencrypt/live/example.com/privkey.pem

        current_cert = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Certificate Name:"):
                if current_cert:
                    certificates.append(current_cert)
                current_cert = {
                    "name": line.split(":", 1)[1].strip()
                }
            elif line.startswith("Domains:"):
                current_cert["domains"] = [d.strip() for d in line.split(":", 1)[1].split()]
            elif line.startswith("Expiry Date:"):
                expiry_str = line.split(":", 1)[1].strip()
                try:
                    # Parse date
                    expiry = datetime.strptime(expiry_str.split("+")[0].strip(), "%Y-%m-%d %H:%M:%S")
                    days_remaining = (expiry - datetime.now()).days
                    current_cert["expiry_date"] = expiry.isoformat()
                    current_cert["days_remaining"] = days_remaining
                    current_cert["status"] = "valid" if days_remaining > 30 else "expiring_soon"
                except:
                    pass
            elif line.startswith("Certificate Path:"):
                current_cert["cert_path"] = line.split(":", 1)[1].strip()
            elif line.startswith("Private Key Path:"):
                current_cert["key_path"] = line.split(":", 1)[1].strip()

        # Add last certificate
        if current_cert:
            certificates.append(current_cert)

        audit.log("list_certificates", {}, {
            "success": True,
            "count": len(certificates)
        })

        return certificates

    except subprocess.CalledProcessError as e:
        audit.log("list_certificates", {}, {
            "success": False,
            "error": str(e)
        })
        return []

    except Exception as e:
        audit.log("list_certificates", {}, {
            "success": False,
            "error": str(e)
        })
        return []


async def delete_certificate(
    domain: str
) -> Dict[str, Any]:
    """Delete a Let's Encrypt certificate.

    Args:
        domain: Domain name of certificate to delete

    Returns:
        Result with success status
    """
    try:
        # Run certbot delete command
        result = await to_thread(
            subprocess.run,
            ["certbot", "delete", "--cert-name", domain],
            capture_output=True,
            text=True,
            input="y\n",  # Confirm deletion
            check=True
        )

        audit.log("delete_certificate", {
            "domain": domain
        }, {
            "success": True
        })

        return {
            "success": True,
            "domain": domain,
            "message": f"Certificate for {domain} deleted successfully"
        }

    except subprocess.CalledProcessError as e:
        error_msg = f"Certificate deletion failed: {e.stderr}"
        audit.log("delete_certificate", {
            "domain": domain
        }, {
            "success": False,
            "error": error_msg
        })
        return {
            "success": False,
            "domain": domain,
            "error": error_msg
        }

    except Exception as e:
        error_msg = f"Certificate deletion failed: {str(e)}"
        audit.log("delete_certificate", {
            "domain": domain
        }, {
            "success": False,
            "error": error_msg
        })
        return {
            "success": False,
            "domain": domain,
            "error": error_msg
        }


async def setup_auto_renewal() -> Dict[str, Any]:
    """Setup automatic certificate renewal via cron/systemd timer.

    Returns:
        Result with setup status
    """
    try:
        # Check if systemd timer exists (preferred method)
        timer_check = await to_thread(
            subprocess.run,
            ["systemctl", "list-timers", "certbot.timer"],
            capture_output=True,
            text=True
        )

        if "certbot.timer" in timer_check.stdout:
            # Timer already exists, ensure it's enabled
            await to_thread(
                subprocess.run,
                ["systemctl", "enable", "certbot.timer"],
                capture_output=True,
                text=True,
                check=True
            )
            await to_thread(
                subprocess.run,
                ["systemctl", "start", "certbot.timer"],
                capture_output=True,
                text=True,
                check=True
            )

            audit.log("setup_auto_renewal", {}, {
                "success": True,
                "method": "systemd-timer"
            })

            return {
                "success": True,
                "method": "systemd-timer",
                "message": "Automatic renewal enabled via systemd timer"
            }

        # Fall back to cron
        cron_entry = "0 0,12 * * * root certbot renew --quiet"
        cron_file = "/etc/cron.d/certbot"

        # Check if cron file exists
        if os.path.exists(cron_file):
            audit.log("setup_auto_renewal", {}, {
                "success": True,
                "method": "cron",
                "already_exists": True
            })

            return {
                "success": True,
                "method": "cron",
                "message": "Automatic renewal already configured via cron"
            }

        # Create cron file
        with open(cron_file, 'w') as f:
            f.write(cron_entry + "\n")

        audit.log("setup_auto_renewal", {}, {
            "success": True,
            "method": "cron"
        })

        return {
            "success": True,
            "method": "cron",
            "message": "Automatic renewal configured via cron"
        }

    except Exception as e:
        error_msg = f"Auto-renewal setup failed: {str(e)}"
        audit.log("setup_auto_renewal", {}, {
            "success": False,
            "error": error_msg
        })
        return {
            "success": False,
            "error": error_msg
        }


def register_tools(mcp: FastMCP):
    """Register Let's Encrypt certificate tools with MCP instance."""

    @mcp.tool()
    @secure_tool("certificate:read")
    async def check_ssl_certificate_status(
        domain: str,
        cert_path: str = None
    ) -> dict:
        """Check SSL certificate status and expiration.

        Args:
            domain: Domain name to check
            cert_path: Optional path to certificate file (auto-detect if not provided)

        Returns:
            CertificateInfo with certificate status and metadata
        """
        try:
            result = await check_certificate(domain=domain, cert_path=cert_path)
            return result
        except Exception as e:
            return format_error(e, "check_ssl_certificate_status")

    @mcp.tool()
    @secure_tool("certificate:admin")
    async def request_letsencrypt_certificate(
        domain: str,
        email: str,
        additional_domains: list = None,
        challenge_type: str = "http-01",
        webroot_path: str = None,
        dns_provider: str = None,
        staging: bool = False,
        dry_run: bool = False
    ) -> dict:
        """Obtain a new Let's Encrypt certificate.

        Args:
            domain: Primary domain name
            email: Email for certificate notifications
            additional_domains: Additional domains for SAN certificate
            challenge_type: Challenge type (http-01 or dns-01, default: http-01)
            webroot_path: Path for HTTP challenge (required for http-01)
            dns_provider: DNS provider for DNS challenge (required for dns-01)
            staging: Use Let's Encrypt staging environment (default: False)
            dry_run: Test without actually obtaining certificate (default: False)

        Returns:
            CertificateResult with certificate paths and status
        """
        try:
            result = await obtain_certificate(
                domain=domain,
                email=email,
                additional_domains=additional_domains,
                challenge_type=challenge_type,
                webroot_path=webroot_path,
                dns_provider=dns_provider,
                staging=staging,
                dry_run=dry_run
            )
            return result
        except Exception as e:
            return format_error(e, "request_letsencrypt_certificate")

    @mcp.tool()
    @secure_tool("certificate:admin")
    async def renew_letsencrypt_certificate(
        domain: str = None,
        force: bool = False,
        dry_run: bool = False
    ) -> dict:
        """Renew Let's Encrypt certificate(s).

        Args:
            domain: Specific domain to renew (None for all)
            force: Force renewal even if not expiring soon (default: False)
            dry_run: Test renewal without actually renewing (default: False)

        Returns:
            CertificateResult with renewal status
        """
        try:
            result = await renew_certificate(domain=domain, force=force, dry_run=dry_run)
            return result
        except Exception as e:
            return format_error(e, "renew_letsencrypt_certificate")

    @mcp.tool()
    @secure_tool("certificate:read")
    async def list_letsencrypt_certificates() -> list:
        """List all Let's Encrypt certificates managed by certbot.

        Returns:
            List of certificates with their status
        """
        try:
            result = await list_certificates()
            return result
        except Exception as e:
            return format_error(e, "list_letsencrypt_certificates")

    @mcp.tool()
    @secure_tool("certificate:admin")
    async def delete_letsencrypt_certificate(domain: str) -> dict:
        """Delete a Let's Encrypt certificate.

        Args:
            domain: Domain name of certificate to delete

        Returns:
            Result with success status
        """
        try:
            result = await delete_certificate(domain=domain)
            return result
        except Exception as e:
            return format_error(e, "delete_letsencrypt_certificate")

    @mcp.tool()
    @secure_tool("certificate:admin")
    async def setup_certificate_auto_renewal() -> dict:
        """Setup automatic certificate renewal via cron/systemd timer.

        Returns:
            Result with setup status
        """
        try:
            result = await setup_auto_renewal()
            return result
        except Exception as e:
            return format_error(e, "setup_certificate_auto_renewal")

    logger.info("Registered 6 certificate tools")
