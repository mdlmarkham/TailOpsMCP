"""Minimal TOON-like serializer helpers for SystemManager.

This module provides a small, conservative implementation to convert our
Pydantic models (SystemStatus, MemoryUsage, DiskUsage, etc.) into a compact
representation inspired by the TOON format to reduce token size when sending
structured data to LLMs.

Note: This is an investigative PoC — it intentionally implements a small,
deterministic compacting scheme rather than a full third-party TOON dependency.
If you prefer the upstream `toon-format` library, we can swap to it later.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict

from src.models.system import SystemStatus, MemoryUsage, DiskUsage


# Short key maps to reduce size. Keep stable for deterministic encoding.
_SYS_KEYS = {
    "cpu": "c",
    "mem": "m",
    "disk": "d",
    "uptime": "u",
    "ts": "t",
}

_MEM_KEYS = {"total": "t", "available": "a", "used": "u", "percent": "p"}
_DISK_KEYS = {"total": "t", "used": "u", "free": "f", "percent": "p"}


def _ts_to_iso(ts: datetime) -> str:
    return ts.isoformat()


def system_status_to_toon(status: SystemStatus) -> str:
    """Serialize `SystemStatus` into a compact JSON string using short keys.

    Output is a compact JSON object with short keys (not binary TOON). This
    significantly reduces token usage compared to verbose keys and nested
    Pydantic dicts.
    """
    out: Dict[str, Any] = {}
    out[_SYS_KEYS["cpu"]] = round(status.cpu_percent, 2)

    mem = {}
    mem[_MEM_KEYS["total"]] = status.memory_usage.total
    mem[_MEM_KEYS["available"]] = status.memory_usage.available
    mem[_MEM_KEYS["used"]] = status.memory_usage.used
    mem[_MEM_KEYS["percent"]] = round(status.memory_usage.percent, 2)
    out[_SYS_KEYS["mem"]] = mem

    disk = {}
    disk[_DISK_KEYS["total"]] = status.disk_usage.total
    disk[_DISK_KEYS["used"]] = status.disk_usage.used
    disk[_DISK_KEYS["free"]] = status.disk_usage.free
    disk[_DISK_KEYS["percent"]] = round(status.disk_usage.percent, 2)
    out[_SYS_KEYS["disk"]] = disk

    out[_SYS_KEYS["uptime"]] = int(status.uptime)
    out[_SYS_KEYS["ts"]] = _ts_to_iso(status.timestamp)

    # Use separators to minimize size
    return json.dumps(out, separators=(",",":"), ensure_ascii=False)


def toon_to_system_status(s: str) -> SystemStatus:
    """Parse a compact TOON-like JSON string back into `SystemStatus`.

    This is a best-effort reverse mapper matching `system_status_to_toon`.
    """
    obj = json.loads(s)

    cpu = float(obj.get(_SYS_KEYS["cpu"], 0.0))

    mem_obj = obj.get(_SYS_KEYS["mem"], {})
    mem = MemoryUsage(
        total=int(mem_obj.get(_MEM_KEYS["total"], 0)),
        available=int(mem_obj.get(_MEM_KEYS["available"], 0)),
        used=int(mem_obj.get(_MEM_KEYS["used"], 0)),
        percent=float(mem_obj.get(_MEM_KEYS["percent"], 0.0)),
    )

    disk_obj = obj.get(_SYS_KEYS["disk"], {})
    disk = DiskUsage(
        total=int(disk_obj.get(_DISK_KEYS["total"], 0)),
        used=int(disk_obj.get(_DISK_KEYS["used"], 0)),
        free=int(disk_obj.get(_DISK_KEYS["free"], 0)),
        percent=float(disk_obj.get(_DISK_KEYS["percent"], 0.0)),
    )

    uptime = int(obj.get(_SYS_KEYS["uptime"], 0))
    ts_iso = obj.get(_SYS_KEYS["ts"])
    ts = datetime.fromisoformat(ts_iso) if ts_iso else datetime.now()

    return SystemStatus(
        cpu_percent=cpu,
        memory_usage=mem,
        disk_usage=disk,
        uptime=uptime,
        timestamp=ts,
    )


def model_to_toon(obj: Any) -> str:
    """Generic helper: dispatch to specific converters for known model types."""
    if isinstance(obj, SystemStatus):
        return system_status_to_toon(obj)
    # Add more dispatches when we implement other models
    raise TypeError(f"No TOON converter for {type(obj)}")
