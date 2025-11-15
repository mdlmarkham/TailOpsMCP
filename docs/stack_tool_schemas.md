# Stack Tool Input / Output Schemas

This file drafts Pydantic-style schemas and TOON-friendly minimal outputs for stack-related tools.

## Models (Pydantic)

- `ServiceSummary`:
  - `name: str`
  - `image: Optional[str]`
  - `replicas: Optional[int]`
  - `running_count: Optional[int]`
  - `status: Optional[str]` (running|exited|paused)
  - `uptime_seconds: Optional[int]`
  - `restart_count: Optional[int]`
  - `cpu_percent: Optional[float]`
  - `memory_bytes: Optional[int]`
  - `issues: Optional[List[str]]`

- `StackMeta`:
  - `stack_name`, `host`, `path`, `repo_url`, `branch`, `deployed_commit`, `image_tags`, `services`, `deployed_at`, `environment`, `criticality`, `tags`

- `StackStatus`:
  - `meta: StackMeta`
  - `services: List[ServiceSummary]`
  - `issues: List[str]`

- `RepoStatus`, `ConfigDiff`, `DeployRequest`, `DeployResult`, `SimulateActionResult`, `StackHistoryEntry` — see `src/models/stack_models.py` for full Pydantic definitions.

## Tool I/O (examples)

- `inventory_stacks(host=None)` -> list of `StackMeta` (minimal fields):
  ```json
  [
    {"stack_name":"webapp","host":"node-1","path":"/srv/webapp","repo_url":"git@...","branch":"main","deployed_commit":"abc123","services":["web","db"]}
  ]
  ```

- `get_stack_status(host, stack_name)` -> `StackStatus` (summary only):
  ```json
  {
    "meta": {"stack_name":"webapp","host":"node-1","deployed_commit":"abc123"},
    "services": [{"name":"web","status":"running","running_count":2,"image":"web:1.2.3","restart_count":0}],
    "issues": []
  }
  ```

- `get_config_diff(stack)` -> `ConfigDiff`:
  ```json
  {"stack_name":"webapp","diff_text":"--- a/docker-compose.yml\n+++ b/docker-compose.yml\n..."}
  ```

- `deploy_stack(DeployRequest)` -> `DeployResult` (dry_run default true):
  ```json
  {"success":true,"dry_run":true,"planned_changes":["pull web:1.2.4","restart web service"]}
  ```

## TOON compact examples

- A minimal TOON for `get_stack_status` might include only short keys:
  ```json
  {"n":"webapp","h":"node-1","s":[{"n":"web","st":"r","r":2,"i":"web:1.2.3"}],"t":"2025-11-15T12:00:00Z"}
  ```

Use delta helpers (`toon_delta`) to communicate changes between snapshots efficiently.
