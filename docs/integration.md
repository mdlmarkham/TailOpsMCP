# SystemManager Control Plane Gateway Integration & Deployment Guide

This guide explains how to deploy SystemManager control plane gateways across multiple hosts with a Tailscale-first access model, token fallback, and recommended security configuration.

## Overview
- Primary access: Tailscale Services (recommended).
- Fallback: HMAC or JWT tokens for automation (short-lived, scoped).
- Security: enforce `SYSTEMMANAGER_ALLOWED_PATHS`, non-root execution, and audit logging.

## Environment Variables (per host)
- `SYSTEMMANAGER_SHARED_SECRET` — HMAC fallback secret (required for token fallback).
- `SYSTEMMANAGER_JWT_SECRET` — optional JWT secret.
- `SYSTEMMANAGER_ALLOWED_PATHS` — comma-separated allowed roots (e.g., `/etc,/var/log,/home/svcuser/data`).
- `SYSTEMMANAGER_ENFORCE_NON_ROOT` — `true` to block host-root operations.
- `SYSTEMMANAGER_AUDIT_LOG` — path to JSONL audit log (default `./logs/audit.log`).
- `SYSTEMMANAGER_MAX_OUTPUT_BYTES` — integer (default 65536).
- `SYSTEMMANAGER_MAX_OUTPUT_LINES` — optional integer.

## Quick Setup (Linux example)

1. Clone and install
```bash
git clone https://github.com/mdlmarkham/SystemManager.git /opt/systemmanager
cd /opt/systemmanager
python -m venv .venv
. .venv/bin/activate
pip install -U pip
pip install -e .
```

2. Create environment file `/etc/systemmanager/env`
```
SYSTEMMANAGER_SHARED_SECRET=replace_with_secure_random
SYSTEMMANAGER_ALLOWED_PATHS=/etc,/var/log,/home/svcuser/data
SYSTEMMANAGER_ENFORCE_NON_ROOT=true
SYSTEMMANAGER_AUDIT_LOG=/var/log/systemmanager/audit.log
SYSTEMMANAGER_MAX_OUTPUT_BYTES=65536
```

3. Systemd service (example)
```
[Unit]
Description=SystemManager Control Plane Gateway
After=network.target

[Service]
Type=simple
User=svcuser
EnvironmentFile=/etc/systemmanager/env
WorkingDirectory=/opt/systemmanager
ExecStart=/opt/systemmanager/.venv/bin/python -m src.mcp_server
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

4. Tailscale setup
- Install Tailscale and authenticate device into your tailnet.
- Use a Tailscale Service Auth Key for unattended machines and tag them appropriately.
- In the Tailscale admin console, create a Service that points to the MCP server port (e.g., `:8000`).

5. Mint tokens for automation
```bash
. .venv/bin/activate
python scripts/mint_token.py --subject "ci-bot" --scopes "system:info,container:inspect" --expires-in 3600
```

6. Audit & log forwarding
- Configure logrotate for `SYSTEMMANAGER_AUDIT_LOG` and forward to central logging (SIEM) for immutable storage.

## Windows deployment notes
- Use a dedicated service user. Create a Windows Service (NSSM or `sc.exe`) that runs the venv Python and `src.mcp_server`.
- Adjust `SYSTEMMANAGER_ALLOWED_PATHS` to Windows paths (e.g., `C:\ProgramData\logs;C:\Users\svcuser\data`).

## Multi-host orchestration
- Use a configuration manager (Ansible, Salt, cloud-init) to distribute `SYSTEMMANAGER_SHARED_SECRET` and `ALLOWED_PATHS` consistently.
- Use Tailscale tags to group hosts and ACLs to restrict which identities can connect to which services.

## Security Hardening Recommendations
- Run the MCP server as a non-root, dedicated user.
- Enforce `SYSTEMMANAGER_ENFORCE_NON_ROOT=true` to prevent host-root operations.
- Use a containerized runner for `run_command` with seccomp/cgroup limits and short-lived containers.
- Require operator approval for `file:write`, `system:exec`, and `container:manage` actions.
- Forward audit logs to an immutable remote store and enable rotation/retention.

## Client Example (Python)
```python
import requests
token = "sha256:..."
headers = {"Authorization": f"Bearer {token}"}
resp = requests.post("http://<tailscale-host>:8000/tools/get_system_status", json={"format":"toon"}, headers=headers, timeout=30)
print(resp.text)
```

## Operational Checklist
- Verify `SYSTEMMANAGER_ALLOWED_PATHS` is minimal.
- Confirm audit log forwarding is configured.
- Ensure tokens are short-lived and rotated.
- Test `format="toon"` and JSON fallback parsing.
