# LLM Prompt Templates and Tooling Guidelines

This document provides ready-to-use prompt templates and decision rules so an LLM agent can choose monitoring vs action tools safely.

## Principles
- Prefer read-only / monitoring tools first to gather evidence.
- Require one corroborating monitoring call before any high-risk action.
- Use scoped, short-lived tokens for automation; require human approval for high-risk changes.
- Include `subject` and `format` metadata on tool calls. Use `format="toon"` for compact payloads.

## Prompt Templates

### Monitoring / Triage (single-shot)
Prompt:
```
Here is a snapshot of the host: {system_snapshot}
Task: List top 5 actionable items (priority + one-line reason). For each item include:
- evidence (field + value),
- which monitoring tool to call next,
- which action tool (if any) should be used after confirmation,
- suggested confirmation checks.
Return result as JSON.
```
Recommended tools: `get_system_status`, `list_containers`, `network_status`.

### Investigate High CPU
Step 1 (monitor):
```
Call: get_system_status { "include_processes": true, "format": "toon" }
```
Step 2 (interpret):
```
If a single process > 80% CPU, recommend action and list exact tool call(s) with required approvals.
```

### Example: Action Request Template (requires approval)
```
Action: Stop container {container_id} because {reason}.
Evidence: {evidence_snippet}
Required: human approval token.
Proposed tool call JSON:
{ "tool": "stop_container", "args": { "container_id": "{container_id}", "timeout_seconds": 10 }, "meta": { "subject": "agent@domain" } }
```

### Run Command Safety Prompt
```
I want to run: {cmd}
Return: risk assessment, at least 2 monitoring checks to run first, a safe `run_command` wrapper using `sandbox='container'`, with `timeout` and recommended `cwd`.
```

## Decision Rules (When to Call Which Tool)
- Use monitoring tools (`get_system_status`, `list_containers`, `read_file`, `list_directory`, `network_status`) for diagnosis.
- Use action tools only when:
  - monitoring evidence shows a clear remediation,
  - the action is low-risk OR explicit operator approval is present,
  - token scopes authorize the action.
- If uncertain, call more monitoring tools rather than an action tool.

## Tool-Call Envelope (required fields)
- `tool`: string — tool name
- `args`: object — tool arguments
- `meta`: object — metadata (include `subject`, `format`, `dry_run` optional)

Example tool-call JSON:
```json
{
  "tool": "stop_container",
  "args": { "container_id": "abcd123", "timeout_seconds": 10 },
  "meta": { "subject": "agent@domain", "approval_token": "..." }
}
```

## Compact Serialization
- When token costs matter, prefer `format: "toon"` on monitoring tools to reduce size.
- If a client cannot parse TOON, request `format: "json"` (compact JSON fallback).
