from __future__ import annotations

import json
import os
import socket
from typing import Dict, List


def local_listening_ports() -> List[Dict[str, str]]:
    """Return a list of (port, pid, proto) for local listening sockets.

    This is a lightweight implementation using `socket` and `/proc` when
    available. On systems without `/proc` this will return an empty list.
    """
    results: List[Dict[str, str]] = []
    # Best-effort: parse /proc/net/tcp and /proc/net/tcp6 for Linux
    proc_net = "/proc/net/tcp"
    if os.path.exists(proc_net):
        try:
            with open(proc_net, "r", encoding="utf-8") as f:
                lines = f.readlines()[1:]
            for l in lines:
                parts = l.split()
                local_address = parts[1]
                state = parts[3]
                if state != "0A":
                    continue
                ip_hex, port_hex = local_address.split(":")
                port = int(port_hex, 16)
                results.append({"port": str(port), "proto": "tcp", "info": "listening"})
        except Exception:
            pass
    return results


def port_exposure_summary() -> Dict[str, object]:
    """Return a small summary useful for alerts and inventory.

    - total_listening: int
    - top_ports: list
    """
    ports = local_listening_ports()
    by_port = {}
    for p in ports:
        by_port[p["port"]] = by_port.get(p["port"], 0) + 1
    top_ports = sorted(by_port.items(), key=lambda x: x[1], reverse=True)[:10]
    return {"total_listening": len(ports), "top_ports": top_ports}
