from datetime import datetime

from src.models.containers import ContainerInfo
from src.models.files import FileInfo, DirectoryListing
from src.models.network import InterfaceStats, NetworkStatus
from src.utils.toon import container_to_toon, directory_to_toon, network_to_toon
import json


def test_container_toon_roundtrip():
    ci = ContainerInfo(id="abcdef123456", name="web", status="running")
    s = container_to_toon(ci)
    obj = json.loads(s)
    assert obj["i"] == ci.id
    assert obj["n"] == ci.name


def test_directory_toon_roundtrip():
    f1 = FileInfo(name="a.txt", path="/tmp/a.txt", size=123, is_dir=False)
    f2 = FileInfo(name="d", path="/tmp/d", size=0, is_dir=True)
    dl = DirectoryListing(path="/tmp", files=[f1, f2], directories=["old"])
    s = directory_to_toon(dl)
    obj = json.loads(s)
    assert obj["p"] == "/tmp"
    assert isinstance(obj["f"], list) and len(obj["f"]) == 2


def test_network_toon_roundtrip():
    iface = InterfaceStats(
        name="eth0",
        addresses=["10.0.0.1"],
        is_up=True,
        bytes_sent=1000,
        bytes_recv=2000,
    )
    ns = NetworkStatus(interfaces=[iface], timestamp=datetime.utcnow())
    s = network_to_toon(ns)
    obj = json.loads(s)
    assert "i" in obj and isinstance(obj["i"], list)
