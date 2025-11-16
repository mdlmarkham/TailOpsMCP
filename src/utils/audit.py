from __future__ import annotations

import datetime
import json
import os
import subprocess
from typing import Any, Dict, Optional, List


class AuditLogger:
    """Simple append-only JSONL audit logger for tool invocations.

    Writes one JSON object per line to the path defined by `SYSTEMMANAGER_AUDIT_LOG`
    (defaults to `./logs/audit.log`). This is intentionally simple and local; in
    production you may replace with structured remote logging.
    """

    def __init__(self, path: Optional[str] = None):
        self.path = path or os.getenv("SYSTEMMANAGER_AUDIT_LOG", "./logs/audit.log")
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._tailscale_enabled = self._check_tailscale()

    def _sanitize_args(self, args: Dict[str, Any]) -> Dict[str, Any]:
        # Avoid writing large blobs or tokens to the audit log
        sanitized = {}
        for k, v in args.items():
            if k and "token" in k.lower():
                sanitized[k] = "<REDACTED>"
            else:
                try:
                    # shallow serialization guard
                    json.dumps(v)
                    sanitized[k] = v
                except Exception:
                    sanitized[k] = str(type(v))
        return sanitized

    def _check_tailscale(self) -> bool:
        """Check if Tailscale is available on this system."""
        try:
            subprocess.run(
                ["tailscale", "version"],
                capture_output=True,
                timeout=2,
                check=False
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _get_tailscale_context(self) -> Dict[str, Any]:
        """Get Tailscale identity context for audit trail.
        
        Returns:
            Dict with Tailscale user, device, and network context
        """
        if not self._tailscale_enabled:
            return {}
        
        try:
            # Get Tailscale status
            result = subprocess.run(
                ["tailscale", "status", "--json"],
                capture_output=True,
                timeout=3,
                text=True,
                check=False
            )
            
            if result.returncode != 0:
                return {}
            
            status = json.loads(result.stdout)
            self_info = status.get("Self", {})
            
            return {
                "tailscale_node": self_info.get("HostName", "unknown"),
                "tailscale_user": self_info.get("UserID", "unknown"),
                "tailscale_tags": self_info.get("Tags", []),
                "tailnet": status.get("MagicDNSSuffix", "unknown"),
            }
        except Exception:
            # Fail open - don't block auditing if Tailscale check fails
            return {}

    def log(
        self,
        tool: str,
        args: Dict[str, Any],
        result: Dict[str, Any],
        subject: Optional[str] = None,
        truncated: bool = False,
        dry_run: bool = False,
        scopes: Optional[List[str]] = None,
        risk_level: Optional[str] = None,
        approved: Optional[bool] = None,
    ):
        """Write an audit record.

        Adds `dry_run` flag and stores a compact record. The logger intentionally
        avoids embedding large blobs and redacts token-like keys.
        
        Enhanced for tailnet deployments:
        - Captures Tailscale identity context (user, device, tags)
        - Records authorization scopes used
        - Tracks risk level of operation
        - Logs approval status for high-risk operations
        """
        rec: Dict[str, Any] = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "tool": tool,
            "subject": subject,
            "args": self._sanitize_args(args),
            "result_status": "success" if result.get("success") else "error",
            "error": result.get("error") if not result.get("success") else None,
            "truncated": bool(truncated),
            "dry_run": bool(dry_run),
        }
        
        # Add security context
        if scopes is not None:
            rec["scopes"] = scopes
        if risk_level is not None:
            rec["risk_level"] = risk_level
        if approved is not None:
            rec["approved"] = approved
        
        # Add Tailscale context for lateral movement detection
        tailscale_ctx = self._get_tailscale_context()
        if tailscale_ctx:
            rec["tailscale"] = tailscale_ctx

        # Write atomically by writing a single line. Keep file handle short-lived.
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, separators=(",",":"), ensure_ascii=False) + "\n")
