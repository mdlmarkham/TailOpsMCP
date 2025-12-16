from pydantic import BaseModel, Field
from datetime import datetime


class MemoryUsage(BaseModel):
    """Memory usage statistics."""

    total: int = Field(..., description="Total memory in bytes")
    available: int = Field(..., description="Available memory in bytes")
    used: int = Field(..., description="Used memory in bytes")
    percent: float = Field(..., ge=0, le=100, description="Memory usage percentage")


class DiskUsage(BaseModel):
    """Disk usage statistics."""

    total: int = Field(..., description="Total disk space in bytes")
    used: int = Field(..., description="Used disk space in bytes")
    free: int = Field(..., description="Free disk space in bytes")
    percent: float = Field(..., ge=0, le=100, description="Disk usage percentage")


class SystemStatus(BaseModel):
    """Comprehensive system status."""

    cpu_percent: float = Field(..., ge=0, le=100, description="CPU usage percentage")
    memory_usage: MemoryUsage = Field(..., description="Memory usage statistics")
    disk_usage: DiskUsage = Field(..., description="Disk usage statistics")
    uptime: int = Field(..., ge=0, description="System uptime in seconds")
    timestamp: datetime = Field(..., description="Timestamp of status collection")

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}
