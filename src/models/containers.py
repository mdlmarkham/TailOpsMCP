from pydantic import BaseModel, Field
from typing import Dict, Optional


class ContainerInfo(BaseModel):
    id: str = Field(..., description="Container ID")
    name: Optional[str] = Field(None, description="Container name")
    status: Optional[str] = Field(None, description="Container status")


class ContainerStats(BaseModel):
    container_id: str = Field(..., description="Container ID")
    cpu_percent: Optional[float] = Field(None, ge=0, le=100)
    memory_stats: Optional[Dict] = Field(None)
    network_stats: Optional[Dict] = Field(None)
