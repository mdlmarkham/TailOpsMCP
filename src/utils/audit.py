from __future__ import annotations

import datetime
import json
import os
from typing import Any, Dict, Optional


class AuditLogger:
    """Simple append-only JSONL audit logger for tool invocations.

    Writes one JSON object per line to the path defined by `SYSTEMMANAGER_AUDIT_LOG`
    (defaults to `./logs/audit.log`). This is intentionally simple and local; in
    production you may replace with structured remote logging.
    """

    def __init__(self, path: Optional[str] = None):
        self.path = path or os.getenv("SYSTEMMANAGER_AUDIT_LOG", "./logs/audit.log")
        os.makedirs(os.path.dirname(self.path), exist_ok=True)

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

    def log(
        self,
        tool: str,
        args: Dict[str, Any],
        result: Dict[str, Any],
        subject: Optional[str] = None,
        truncated: bool = False,
        dry_run: bool = False,
    ):
        """Write an audit record.

        Adds `dry_run` flag and stores a compact record. The logger intentionally
        avoids embedding large blobs and redacts token-like keys.
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

        # Write atomically by writing a single line. Keep file handle short-lived.
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, separators=(",",":"), ensure_ascii=False) + "\n")
