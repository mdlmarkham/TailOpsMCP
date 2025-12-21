from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
from datetime import timezone, timezone


class InterfaceStats(BaseModel):
    name: str = Field(..., description="Interface name")
    addresses: Optional[List[str]] = Field(None)
    is_up: Optional[bool] = Field(None)
    bytes_sent: Optional[int] = Field(None)
    bytes_recv: Optional[int] = Field(None)


class NetworkStatus(BaseModel):
    interfaces: List[InterfaceStats] = Field(default_factory=list)
    timestamp: datetime = Field(...)

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}
