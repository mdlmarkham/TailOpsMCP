# Tool Registry

This document catalogs available tools for the MCP server. Each entry includes: name, description, input schema, output schema, required permission scopes, implementation status, and notes.

---

## get_system_status
- Description: Snapshot of host system health (uptime, CPU, memory, disks, services).
- Input schema:
  ```json
  { "format": "string (optional: 'toon'|'json')", "include_processes": "bool (optional)" }
  ```
- Output schema (SystemStatus):
  ```json
  {
    "timestamp": "ISO8601",
    "uptime_seconds": 12345,
    "cpu_usage_percent": 12.3,
    "memory": { "total_bytes": 0, "used_bytes": 0, "free_bytes": 0 },
    "disks": [{ "mount_point": "/", "total_bytes": 0, "used_bytes": 0, "free_bytes": 0 }],
    "services": [{ "name": "nginx", "status": "running", "pid": 123 }]
  }
  ```
- Required scopes: `system:info`
- Implemented: Yes (Pydantic `SystemStatus` model). Supports `format="toon"`.

---

## list_containers
- Description: List containers on the host (Docker / Podman).
- Input schema:
  ```json
  { "all": "bool (optional)", "filters": { } }
  ```
- Output schema: array of ContainerInfo objects:
  ```json
  [{ "id": "", "name": "", "image": "", "status": "", "created_at": "", "ports": [], "labels": {} }]
  ```
- Required scopes: `container:inspect`
- Implemented: Partial (models and PoC converters present).

---

## container_info
- Description: Detailed status for a single container; can include a small log tail.
- Input schema:
  ```json
  { "container_id": "string", "include_logs": "bool (optional)", "log_tail": "int (optional)" }
  ```
- Output schema: extended ContainerInfo with resource usage and optional `logs` string.
- Required scopes: `container:inspect`
- Implemented: Planned/partial.

---

## start_container / stop_container
- Description: Start/stop/create container actions.
- Input schema (start_container example):
  ```json
  { "image": "string", "name": "string (optional)", "ports": [{"host": 80, "container": 80}], "env": {"K": "V"} }
  ```
- Output schema: `{ "container_id": "string", "status": "started" }`
- Required scopes: `container:manage` (high-risk)
- Implemented: Planned. Must require explicit operator approval and strong auditing.

---

## list_directory
- Description: Safe, sandboxed directory listing using allowed-paths policy.
- Input schema:
  ```json
  { "path": "string", "recursive": "bool (optional)", "max_entries": "int (optional)" }
  ```
- Output schema:
  ```json
  { "path": "string", "entries": [{"name": "", "type": "file|dir", "size": 0}], "truncated": false }
  ```
- Required scopes: `file:read`
- Implemented: Yes — uses `sandbox.safe_list_directory` and enforces `SYSTEMMANAGER_ALLOWED_PATHS`.

---

## read_file
- Description: Safe bounded file read with size/line caps.
- Input schema:
  ```json
  { "path": "string", "max_bytes": "int (optional)", "max_lines": "int (optional)", "encoding": "string (optional)" }
  ```
- Output schema:
  ```json
  { "path": "string", "size": 0, "content": "string", "truncated": false }
  ```
- Required scopes: `file:read`
- Implemented: Yes — `sandbox.safe_read_file` with truncation and audit.

---

## write_file
- Description: Write or append to a file (sensitive).
- Input schema:
  ```json
  { "path": "string", "content": "string", "mode": "write|append" }
  ```
- Output schema: `{ "path": "string", "bytes_written": 0, "status": "ok" }`
- Required scopes: `file:write` (high-risk)
- Implemented: Planned — must be gated by ACL, approval, and audit.

---

## network_status
- Description: Interface and routing status inspection.
- Input schema:
  ```json
  { "include_routes": "bool (optional)", "interfaces": ["string"] }
  ```
- Output schema: `NetworkStatus` with interface stats and routes.
- Required scopes: `network:inspect`
- Implemented: Partial (models exist).

---

## run_command
- Description: Execute commands in a sandbox/runner (container recommended).
- Input schema:
  ```json
  { "cmd": "string or [string]", "cwd": "string (optional)", "timeout": "int", "sandbox": "string (container|host-limited)" }
  ```
- Output schema:
  ```json
  { "exit_code": 0, "stdout": "...", "stderr": "...", "timed_out": false, "truncated": false }
  ```
- Required scopes: `system:exec` (very high risk)
- Implemented: Planned — must always use a containerized runner and require approval for destructive actions.

---

## mint_token (script)
- Description: Local CLI helper to mint HMAC fallback tokens with expiry and scopes.
- Input/CLI args: `--subject`, `--scopes`, `--expires-in`
- Output: token string
- Implemented: Yes (`scripts/mint_token.py`). Use secure distribution for tokens.

---

## audit_log_query
- Description: Read-only query interface for audit logs (local JSONL).
- Input schema:
  ```json
  { "since": "ISO8601 (optional)", "limit": "int (optional)", "filter_subject": "string (optional)" }
  ```
- Output schema: array of sanitized audit entries.
- Required scopes: `audit:read`
- Implemented: Planned (current audit sink is local JSONL `SYSTEMMANAGER_AUDIT_LOG`).

---

### Permission Scopes (recommended)
- `system:info`, `system:exec`, `file:read`, `file:write`, `container:inspect`, `container:manage`, `network:inspect`, `audit:read`, `admin`

### Safety Notes
- Monitoring tools should be preferred before action tools.
- Destructive or high-risk tools require explicit operator approval and must be audited.
- Path-based tools enforce `SYSTEMMANAGER_ALLOWED_PATHS`.
- Outputs are truncated to `SYSTEMMANAGER_MAX_OUTPUT_BYTES` and optionally `SYSTEMMANAGER_MAX_OUTPUT_LINES`.
