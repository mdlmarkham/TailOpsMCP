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
from typing import Any, Dict, List

from src.models.system import SystemStatus, MemoryUsage, DiskUsage
from src.models.containers import ContainerInfo
from src.models.files import DirectoryListing, FileInfo
from src.models.network import NetworkStatus, InterfaceStats
import json


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
    if isinstance(obj, ContainerInfo):
        return container_to_toon(obj)
    if isinstance(obj, DirectoryListing):
        return directory_to_toon(obj)
    if isinstance(obj, NetworkStatus):
        return network_to_toon(obj)
    
    # Handle dicts (most common MCP response type)
    if isinstance(obj, dict):
        return dict_to_toon(obj)

    # If it's a list of models, try element-wise conversion to compact JSON
    if isinstance(obj, list):
        # Attempt to convert list of models to list of compact dicts then JSON
        try:
            compact = [json.loads(model_to_toon(x)) for x in obj]
            return json.dumps(compact, separators=(",",":"), ensure_ascii=False)
        except Exception:
            pass

    # Fallback to compact JSON
    return json.dumps(obj, separators=(",",":"), ensure_ascii=False, default=str)


def container_to_toon(ci: ContainerInfo) -> str:
    # short keys: id=i, name=n, status=s
    out = {"i": ci.id, "n": ci.name or "", "s": ci.status or ""}
    return json.dumps(out, separators=(",",":"), ensure_ascii=False)


def directory_to_toon(dl: DirectoryListing) -> str:
    # short keys: path=p, files=f, dirs=d
    files: List[Dict[str, Any]] = []
    for fi in dl.files:
        files.append({"n": fi.name, "p": fi.path, "s": fi.size or 0, "d": bool(fi.is_dir)})
    out = {"p": dl.path, "f": files, "d": dl.directories}
    return json.dumps(out, separators=(",",":"), ensure_ascii=False)


def network_to_toon(ns: NetworkStatus) -> str:
    # short keys: interfaces=i, each interface: n=name,a=addresses,u=up,bs=bytes_sent,br=bytes_recv
    ifaces: List[Dict[str, Any]] = []
    for iface in ns.interfaces:
        ifaces.append({
            "n": iface.name,
            "a": iface.addresses or [],
            "u": bool(iface.is_up) if iface.is_up is not None else None,
            "bs": iface.bytes_sent or 0,
            "br": iface.bytes_recv or 0,
        })
    out = {"i": ifaces, "t": ns.timestamp.isoformat()}
    return json.dumps(out, separators=(",",":"), ensure_ascii=False)


def dict_to_toon(data: Dict[str, Any]) -> str:
    """Convert a dictionary to compact TOON-like JSON.
    
    This is the generic converter for dict responses from MCP tools.
    Uses tabular format for uniform arrays of dicts.
    """
    return _compact_json(data)


def _compact_json(obj: Any) -> str:
    """Recursively compact a JSON-serializable object using TOON principles.
    
    - Arrays of uniform dicts become TOON tabular format: [k1,k2,...][v1,v2,...][...]
    - Nested dicts are compacted recursively
    - Everything else uses minimal JSON
    """
    if isinstance(obj, dict):
        # Check if this dict contains arrays that can be tabularized
        compact = {}
        for k, v in obj.items():
            if isinstance(v, list) and len(v) > 0 and all(isinstance(x, dict) for x in v):
                # Try TOON tabular format
                tabular = _to_toon_tabular(v)
                if tabular is not None:
                    # Use TOON tabular string representation
                    compact[k] = tabular
                else:
                    compact[k] = v
            elif isinstance(v, (dict, list)):
                # Recurse
                result = _compact_json(v)
                compact[k] = json.loads(result) if isinstance(result, str) else result
            else:
                compact[k] = v
        return json.dumps(compact, separators=(",",":"), ensure_ascii=False)
    elif isinstance(obj, list):
        if len(obj) > 0 and all(isinstance(x, dict) for x in obj):
            # Try TOON tabular format
            tabular = _to_toon_tabular(obj)
            if tabular is not None:
                return tabular
        # Mixed or primitive array
        return json.dumps(obj, separators=(",",":"), ensure_ascii=False)
    else:
        return json.dumps(obj, separators=(",",":"), ensure_ascii=False)


def _to_toon_tabular(arr: List[Dict[str, Any]]) -> Optional[str]:
    """Convert array of uniform dicts to TOON tabular format.
    
    Format: [key1,key2,key3][val1,val2,val3][val1,val2,val3]...
    Only works if all dicts have same keys and all values are primitives.
    
    Returns None if not suitable for tabular format.
    """
    if not arr:
        return None
    
    # Check if all dicts have same keys
    first_keys = list(arr[0].keys())
    if not all(list(d.keys()) == first_keys for d in arr):
        return None
    
    # Check if all values are primitives (not nested)
    for d in arr:
        for v in d.values():
            if isinstance(v, (dict, list)):
                return None
    
    # Build TOON tabular format
    # Header: [key1,key2,key3]
    header = "[" + ",".join(first_keys) + "]"
    
    # Rows: [val1,val2,val3]
    rows = []
    for d in arr:
        values = []
        for k in first_keys:
            v = d[k]
            if v is None:
                values.append("null")
            elif isinstance(v, bool):
                values.append("true" if v else "false")
            elif isinstance(v, str):
                # Escape and quote strings
                values.append(json.dumps(v))
            else:
                values.append(str(v))
        rows.append("[" + ",".join(values) + "]")
    
    return header + "".join(rows)


def _to_obj(s_or_obj):
    """Ensure we have a dict/list object from either a JSON string or an object."""
    if isinstance(s_or_obj, str):
        try:
            return json.loads(s_or_obj)
        except Exception:
            # not JSON; return as-is
            return s_or_obj
    return s_or_obj


def compute_delta(old, new):
    """Compute a minimal delta from `old` -> `new` for JSON-serializable dicts.

    - If a key is added or changed, include the new value.
    - If a key is removed, include `{ "__deleted": true }` marker.
    - For nested dicts, compute recursively.
    - For lists and primitives, replace when different.

    This is intentionally simple and deterministic.
    """
    o = _to_obj(old) or {}
    n = _to_obj(new) or {}

    if not isinstance(o, dict) or not isinstance(n, dict):
        # Non-dict types: if equal -> empty delta, else delta is new value
        return {} if o == n else n

    delta = {}
    # keys present in either
    keys = set(o.keys()) | set(n.keys())
    for k in keys:
        if k in o and k not in n:
            delta[k] = {"__deleted": True}
        elif k not in o and k in n:
            delta[k] = n[k]
        else:
            # both present
            if isinstance(o[k], dict) and isinstance(n[k], dict):
                sub = compute_delta(o[k], n[k])
                if sub:
                    delta[k] = sub
            else:
                if o[k] != n[k]:
                    delta[k] = n[k]
    return delta


def apply_delta(base, delta):
    """Apply a delta produced by `compute_delta` onto `base` and return new object."""
    b = _to_obj(base) or {}
    d = _to_obj(delta) or {}
    if not isinstance(b, dict) or not isinstance(d, dict):
        # Non-dict replacement
        return d if d != {} else b

    out = dict(b)
    for k, v in d.items():
        if isinstance(v, dict) and v.get("__deleted"):
            out.pop(k, None)
        elif isinstance(v, dict) and k in out and isinstance(out[k], dict):
            out[k] = apply_delta(out.get(k, {}), v)
        else:
            out[k] = v
    return out


def toon_delta(prev_toon: str, new_toon: str) -> str:
    """Return a compact JSON string representing the delta between two TOON payloads."""
    prev = _to_obj(prev_toon)
    new = _to_obj(new_toon)
    delta = compute_delta(prev, new)
    return json.dumps(delta, separators=(",",":"), ensure_ascii=False)


def apply_toon_delta(prev_toon: str, delta_toon: str) -> str:
    """Apply a TOON delta (JSON string) to a previous TOON payload and return the reconstructed TOON string."""
    prev = _to_obj(prev_toon)
    delta = _to_obj(delta_toon)
    new = apply_delta(prev, delta)
    return json.dumps(new, separators=(",",":"), ensure_ascii=False)


def _from_toon_tabular(tabular_str: str) -> List[Dict[str, Any]]:
    """Parse TOON tabular format back to list of dicts.
    
    Format: [key1,key2,key3][val1,val2,val3][val1,val2,val3]...
    
    Returns:
        List of dictionaries reconstructed from tabular format
    """
    if not tabular_str.startswith('[') or ']' not in tabular_str:
        # Not tabular format, try to parse as regular JSON
        try:
            return json.loads(tabular_str)
        except json.JSONDecodeError:
            return []
    
    # Extract header
    header_end = tabular_str.find(']') + 1
    header_str = tabular_str[:header_end]
    
    try:
        keys = json.loads(header_str)
    except json.JSONDecodeError:
        return []
    
    # Extract rows
    rows_str = tabular_str[header_end:]
    rows = []
    
    # Parse each row
    i = 0
    while i < len(rows_str):
        if rows_str[i] == '[':
            # Find matching closing bracket
            j = i + 1
            bracket_count = 1
            while j < len(rows_str) and bracket_count > 0:
                if rows_str[j] == '[':
                    bracket_count += 1
                elif rows_str[j] == ']':
                    bracket_count -= 1
                j += 1
            
            row_str = rows_str[i:j]
            try:
                values = json.loads(row_str)
                if len(values) == len(keys):
                    row_dict = dict(zip(keys, values))
                    rows.append(row_dict)
            except json.JSONDecodeError:
                pass
            
            i = j
        else:
            i += 1
    
    return rows
