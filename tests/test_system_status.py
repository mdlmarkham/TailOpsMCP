import pytest
from src.models.system import SystemStatus, MemoryUsage, DiskUsage
from datetime import datetime


def test_system_status_model():
    mem = MemoryUsage(total=8_589_934_592, available=4_294_967_296, used=4_294_967_296, percent=50.0)
    disk = DiskUsage(total=500_000_000_000, used=250_000_000_000, free=250_000_000_000, percent=50.0)
    status = SystemStatus(cpu_percent=10.0, memory_usage=mem, disk_usage=disk, uptime=3600, timestamp=datetime.utcnow())

    assert status.cpu_percent >= 0
    assert 0 <= status.memory_usage.percent <= 100
    assert 0 <= status.disk_usage.percent <= 100
