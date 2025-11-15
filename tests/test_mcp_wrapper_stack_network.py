import json
import os
import subprocess
import asyncio
from types import SimpleNamespace

import pytest

from src.mcp_server import mcp


def _make_completed(stdout: str, returncode: int = 0):
    cp = SimpleNamespace()
    cp.stdout = stdout
    cp.returncode = returncode
    cp.stderr = ""
    return cp


def write_inventory(stack_name: str):
    inv = {"hosts": {}, "stacks": {stack_name: {"stack_name": stack_name, "host": "node-1", "path": "/srv/webapp", "services": ["web"]}}}
    with open("inventory.json", "w", encoding="utf-8") as f:
        json.dump(inv, f)


def remove_inventory():
    try:
        os.remove("inventory.json")
    except Exception:
        pass


def test_mcp_wrapper_get_stack_network_info_cli(monkeypatch):
    stack_name = "webapp"
    write_inventory(stack_name)

    ps_line = json.dumps({"Names": f"{stack_name}_web_1", "ID": "abcd1234"}) + "\n"
    inspect_obj = [{
        "Id": "abcd1234",
        "Name": f"/{stack_name}_web_1",
        "Config": {"Image": "web:1.2.3", "Labels": {"com.docker.compose.service": "web"}},
        "HostConfig": {"NetworkMode": "bridge"},
        "NetworkSettings": {"Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}},
        "Mounts": []
    }]

    def fake_run(args, capture_output=True, text=True, check=True):
        if args[:3] == ["docker", "ps", "-a"] or args[:4] == ["docker", "ps", "-a", "--format"]:
            return _make_completed(ps_line)
        if args[0] == "docker" and args[1] == "inspect":
            return _make_completed(json.dumps(inspect_obj))
        raise RuntimeError("Unexpected docker command")

    monkeypatch.setattr(subprocess, "run", fake_run)

    # find mcp tool wrapper
    tool = next((t for t in mcp.tools if t.name == "get_stack_network_info"), None)
    assert tool is not None

    res = asyncio.get_event_loop().run_until_complete(tool.function(host="node-1", stack_name=stack_name))
    assert res["success"] is True
    data = res["data"]
    assert data["stack_name"] == stack_name
    assert len(data["containers"]) == 1

    remove_inventory()
