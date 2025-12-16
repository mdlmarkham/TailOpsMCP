import json
import os
import sys
import asyncio
from types import ModuleType


from src.tools.stack_tools import get_stack_network_info


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


class MockContainer:
    def __init__(self, id, name, attrs):
        self.id = id
        self.name = name
        self.attrs = attrs


class MockClient:
    def __init__(self, containers):
        self._containers = containers
        # expose .containers attribute like docker SDK client
        self.containers = self

    def list(self, all=True, filters=None):
        # simplistic filters: label matching or name prefix not implemented in mock
        return self._containers


def make_inspect_obj(cid, name, image, host_port):
    return {
        "Id": cid,
        "Name": name,
        "Config": {"Image": image, "Labels": {"com.docker.compose.service": "web"}},
        "HostConfig": {"NetworkMode": "bridge"},
        "NetworkSettings": {
            "Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": str(host_port)}]}
        },
        "Mounts": [],
    }


def test_get_stack_network_info_docker_sdk_single(monkeypatch):
    stack_name = "webapp"
    write_inventory(stack_name)

    inspect_obj = make_inspect_obj(
        "abcd1234", f"/{stack_name}_web_1", "web:1.2.3", 8080
    )
    mock_container = MockContainer("abcd1234", f"{stack_name}_web_1", inspect_obj)

    # Create fake docker module with from_env returning a client
    docker_mod = ModuleType("docker")
    client = MockClient([mock_container])
    docker_mod.from_env = lambda: client

    monkeypatch.setitem(sys.modules, "docker", docker_mod)

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


def test_get_stack_network_info_docker_sdk_conflict(monkeypatch):
    stack_name = "webapp"
    write_inventory(stack_name)

    inspect_obj1 = make_inspect_obj("cid1", f"/{stack_name}_web_1", "web:1.2.3", 8080)
    inspect_obj2 = make_inspect_obj("cid2", f"/{stack_name}_web_2", "web:1.2.3", 8080)
    mock_container1 = MockContainer("cid1", f"{stack_name}_web_1", inspect_obj1)
    mock_container2 = MockContainer("cid2", f"{stack_name}_web_2", inspect_obj2)

    docker_mod = ModuleType("docker")
    client = MockClient([mock_container1, mock_container2])
    docker_mod.from_env = lambda: client

    monkeypatch.setitem(sys.modules, "docker", docker_mod)

    info = asyncio.get_event_loop().run_until_complete(
        get_stack_network_info("node-1", stack_name)
    )

    assert info["stack_name"] == stack_name
    assert len(info["containers"]) == 2
    assert len(info["port_conflicts"]) == 1
    conflict = info["port_conflicts"][0]
    assert conflict["host_port"] == "8080"

    remove_inventory()
