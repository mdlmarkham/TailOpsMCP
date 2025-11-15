from __future__ import annotations

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel


class ServiceSummary(BaseModel):
    name: str
    image: Optional[str] = None
    replicas: Optional[int] = None
    running_count: Optional[int] = None
    status: Optional[str] = None  # running|exited|paused
    uptime_seconds: Optional[int] = None
    restart_count: Optional[int] = None
    cpu_percent: Optional[float] = None
    memory_bytes: Optional[int] = None
    issues: Optional[List[str]] = []


class StackMeta(BaseModel):
    stack_name: str
    host: str
    path: Optional[str] = None
    repo_url: Optional[str] = None
    branch: Optional[str] = None
    deployed_commit: Optional[str] = None
    image_tags: Optional[List[str]] = []
    services: Optional[List[str]] = []
    deployed_at: Optional[datetime] = None
    environment: Optional[str] = None  # dev/stage/prod/homelab
    criticality: Optional[str] = None
    tags: Optional[List[str]] = []


class StackStatus(BaseModel):
    meta: StackMeta
    services: List[ServiceSummary]
    issues: Optional[List[str]] = []


class RepoStatus(BaseModel):
    repo_url: Optional[str] = None
    branch: Optional[str] = None
    latest_commit: Optional[str] = None
    deployed_commit: Optional[str] = None
    ahead_by: Optional[int] = None
    behind_by: Optional[int] = None
    tags: Optional[List[str]] = []
    has_uncommitted_changes: Optional[bool] = False


class ConfigDiff(BaseModel):
    stack_name: str
    diff_text: Optional[str] = None
    compact_delta: Optional[Dict[str, Any]] = None


class DeployRequest(BaseModel):
    host: str
    stack_name: str
    target_commit: Optional[str] = None
    pull_images: bool = True
    force: bool = False
    dry_run: bool = True


class DeployResult(BaseModel):
    success: bool
    dry_run: bool = True
    planned_changes: Optional[List[str]] = []
    errors: Optional[List[str]] = []
    deployed_commit: Optional[str] = None


class SimulateActionResult(BaseModel):
    impacted_stacks: Optional[List[str]] = []
    risk_level: Optional[str] = "low"  # low|medium|high
    details: Optional[Dict[str, Any]] = {}


class StackHistoryEntry(BaseModel):
    timestamp: datetime
    actor: Optional[str] = None
    action: str
    commit: Optional[str] = None
    image_tags: Optional[List[str]] = []
    result: Optional[str] = None
