from datetime import datetime

from src.models.system import SystemStatus, MemoryUsage, DiskUsage
from src.utils.toon import system_status_to_toon, toon_to_system_status


def test_system_status_toon_roundtrip():
    mem = MemoryUsage(total=8000, available=4000, used=4000, percent=50.0)
    disk = DiskUsage(total=100000, used=50000, free=50000, percent=50.0)
    st = SystemStatus(cpu_percent=12.3456, memory_usage=mem, disk_usage=disk, uptime=3600, timestamp=datetime.utcnow())

    toon = system_status_to_toon(st)
    parsed = toon_to_system_status(toon)

    assert abs(parsed.cpu_percent - round(st.cpu_percent, 2)) < 0.01
    assert parsed.memory_usage.total == st.memory_usage.total
    assert parsed.disk_usage.total == st.disk_usage.total
    assert parsed.uptime == st.uptime
