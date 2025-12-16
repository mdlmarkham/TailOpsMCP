import json
import os
import subprocess
from types import SimpleNamespace


from src.tools.stack_tools import get_stack_network_info


def _make_completed(stdout: str, returncode: int = 0):
    cp = SimpleNamespace()
    cp.stdout = stdout
    cp.returncode = returncode
    cp.stderr = ""
    return cp


def write_inventory(stack_name: str):
    inv = {
        "hosts": {},
        "stacks": {
            stack_name: {
                "stack_name": stack_name,
                "host": "node-1",
                "path": "/srv/webapp",
                "services": ["web"],
            }
        },
    }
    with open("inventory.json", "w", encoding="utf-8") as f:
        json.dump(inv, f)


def remove_inventory():
    try:
        os.remove("inventory.json")
    except Exception:
        pass


def test_get_stack_network_info_cli_single_container(monkeypatch):
    """CLI fallback: one container with a published host port should be parsed."""
    stack_name = "webapp"
    write_inventory(stack_name)

    # docker ps output: one container
    ps_line = json.dumps({"Names": f"{stack_name}_web_1", "ID": "abcd1234"}) + "\n"

    # docker inspect output for the container
    inspect_obj = [
        {
            "Id": "abcd1234",
            "Name": f"/{stack_name}_web_1",
            "Config": {
                "Image": "web:1.2.3",
                "Labels": {"com.docker.compose.service": "web"},
            },
            "HostConfig": {"NetworkMode": "bridge"},
            "NetworkSettings": {
                "Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}
            },
            "Mounts": [],
        }
    ]

    def fake_run(args, capture_output=True, text=True, check=True):
        cmd = args[0:3]
        if args[:3] == ["docker", "ps", "-a"] or args[:4] == [
            "docker",
            "ps",
            "-a",
            "--format",
        ]:
            return _make_completed(ps_line)
        if args[0] == "docker" and args[1] == "inspect":
            return _make_completed(json.dumps(inspect_obj))
        raise RuntimeError("Unexpected docker command")

    monkeypatch.setattr(subprocess, "run", fake_run)

    # Call the coroutine
    import asyncio

    info = asyncio.get_event_loop().run_until_complete(
        get_stack_network_info("node-1", stack_name)
    )

    assert info["stack_name"] == stack_name
    assert len(info["containers"]) == 1
    cont = info["containers"][0]
    assert cont["image"] == "web:1.2.3"
    assert cont["network_mode"] == "bridge"
    assert cont["ports"][0]["host_port"] == "8080"
    assert info["port_conflicts"] == []

    remove_inventory()


def test_get_stack_network_info_cli_conflict(monkeypatch):
    """Two containers mapping the same host port should produce a conflict entry."""
    stack_name = "webapp"
    write_inventory(stack_name)

    # docker ps output: two containers
    line1 = json.dumps({"Names": f"{stack_name}_web_1", "ID": "cid1"})
    line2 = json.dumps({"Names": f"{stack_name}_web_2", "ID": "cid2"})
    ps_out = line1 + "\n" + line2 + "\n"

    inspect_obj1 = [
        {
            "Id": "cid1",
            "Name": f"/{stack_name}_web_1",
            "Config": {
                "Image": "web:1.2.3",
                "Labels": {"com.docker.compose.service": "web"},
            },
            "HostConfig": {"NetworkMode": "bridge"},
            "NetworkSettings": {
                "Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}
            },
            "Mounts": [],
        }
    ]

    inspect_obj2 = [
        {
            "Id": "cid2",
            "Name": f"/{stack_name}_web_2",
            "Config": {
                "Image": "web:1.2.3",
                "Labels": {"com.docker.compose.service": "web"},
            },
            "HostConfig": {"NetworkMode": "bridge"},
            "NetworkSettings": {
                "Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}
            },
            "Mounts": [],
        }
    ]

    def fake_run(args, capture_output=True, text=True, check=True):
        if args[:4] == ["docker", "ps", "-a", "--format"] or args[:3] == [
            "docker",
            "ps",
            "-a",
        ]:
            return _make_completed(ps_out)
        if args[0] == "docker" and args[1] == "inspect":
            cid = args[2]
            if cid == "cid1":
                return _make_completed(json.dumps(inspect_obj1))
            if cid == "cid2":
                return _make_completed(json.dumps(inspect_obj2))
        raise RuntimeError("Unexpected docker command")

    monkeypatch.setattr(subprocess, "run", fake_run)

    import asyncio

    info = asyncio.get_event_loop().run_until_complete(
        get_stack_network_info("node-1", stack_name)
    )

    assert info["stack_name"] == stack_name
    assert len(info["containers"]) == 2
    assert len(info["port_conflicts"]) == 1
    conflict = info["port_conflicts"][0]
    assert conflict["host_port"] == "8080"

    remove_inventory()
