from __future__ import annotations

import asyncio
import json
import os
from typing import List, Optional, Dict, Any
from datetime import datetime

from src.inventory import Inventory, HostMetadata, StackMetadata
from src.models.stack_models import (
    StackMeta,
    StackStatus,
    ServiceSummary,
    RepoStatus,
    ConfigDiff,
    DeployRequest,
    DeployResult,
    SimulateActionResult,
    StackHistoryEntry,
)
from src.utils.audit import AuditLogger
import subprocess
from asyncio import to_thread


audit = AuditLogger()


async def inventory_stacks(host: Optional[str] = None, format: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return list of stacks from inventory. If `host` provided, filter by host.

    Default output is structured JSON (or compact TOON if higher-level wrapper
    asks for `format='toon'`). This function is intentionally read-only.
    """
    inv = Inventory()
    stacks = inv.list_stacks()
    res = []
    for sid, s in stacks.items():
        if host and s.get("host") != host:
            continue
        res.append(s)

    # Audit the read
    audit.log("inventory_stacks", {"host": host}, {"success": True, "count": len(res)})
    return res


async def get_stack_status(host: str, stack_name: str, format: Optional[str] = None) -> Dict[str, Any]:
    """Return a structured StackStatus summary. Currently a conservative
    summary built from inventory plus light runtime inspection (placeholders).
    """
    inv = Inventory()
    stacks = inv.list_stacks()
    key = stack_name
    stack = stacks.get(key) if key in stacks else None
    meta = StackMeta(
        stack_name=stack_name,
        host=host,
        path=stack.get("path") if stack else None,
        repo_url=stack.get("repo_url") if stack else None,
        branch=stack.get("branch") if stack else None,
        deployed_commit=stack.get("deployed_commit") if stack else None,
        services=stack.get("services") if stack else [],
    )

    # Placeholder: no real container inspection here. Provide empty service summaries.
    services: List[ServiceSummary] = []
    for sname in meta.services or []:
        services.append(ServiceSummary(name=sname, status="unknown"))

    status = StackStatus(meta=meta, services=services, issues=[])

    audit.log("get_stack_status", {"host": host, "stack_name": stack_name}, {"success": True})
    return status.dict()


async def get_repo_status(stack_name: str) -> Dict[str, Any]:
    """Return repo status for a stack with actual git information."""
    inv = Inventory()
    stacks = inv.list_stacks()
    stack = stacks.get(stack_name)

    if not stack:
        audit.log("get_repo_status", {"stack_name": stack_name}, {"success": False, "error": "stack_not_found"})
        return RepoStatus(repo_url=None).dict()

    repo_url = stack.get("repo_url")
    stack_path = stack.get("path")
    deployed_commit = stack.get("deployed_commit")
    branch = stack.get("branch", "main")

    # If no path or git repo doesn't exist, return basic info
    if not stack_path or not os.path.exists(os.path.join(stack_path, ".git")):
        res = RepoStatus(
            repo_url=repo_url,
            branch=branch,
            latest_commit=None,
            deployed_commit=deployed_commit
        )
        audit.log("get_repo_status", {"stack_name": stack_name}, {"success": True, "no_git": True})
        return res.dict()

    try:
        # Get latest commit from remote
        await to_thread(
            subprocess.run,
            ["git", "fetch", "origin", branch],
            cwd=stack_path,
            capture_output=True,
            text=True,
            check=True
        )

        # Get remote HEAD commit
        remote_rev = await to_thread(
            subprocess.run,
            ["git", "rev-parse", f"origin/{branch}"],
            cwd=stack_path,
            capture_output=True,
            text=True,
            check=True
        )
        latest_commit = remote_rev.stdout.strip()

        # Get current HEAD commit
        local_rev = await to_thread(
            subprocess.run,
            ["git", "rev-parse", "HEAD"],
            cwd=stack_path,
            capture_output=True,
            text=True,
            check=True
        )
        current_commit = local_rev.stdout.strip()

        # Check if there are uncommitted changes
        status_result = await to_thread(
            subprocess.run,
            ["git", "status", "--porcelain"],
            cwd=stack_path,
            capture_output=True,
            text=True,
            check=True
        )
        has_uncommitted_changes = bool(status_result.stdout.strip())

        # Calculate ahead/behind
        revlist = await to_thread(
            subprocess.run,
            ["git", "rev-list", "--left-right", "--count", f"HEAD...origin/{branch}"],
            cwd=stack_path,
            capture_output=True,
            text=True,
            check=True
        )
        ahead, behind = map(int, revlist.stdout.strip().split())

        res = RepoStatus(
            repo_url=repo_url,
            branch=branch,
            latest_commit=latest_commit,
            deployed_commit=current_commit,
            ahead_by=ahead,
            behind_by=behind,
            has_uncommitted_changes=has_uncommitted_changes
        )

        audit.log("get_repo_status", {"stack_name": stack_name}, {"success": True})
        return res.dict()

    except Exception as e:
        # Fall back to basic info if git commands fail
        res = RepoStatus(
            repo_url=repo_url,
            branch=branch,
            latest_commit=None,
            deployed_commit=deployed_commit
        )
        audit.log("get_repo_status", {"stack_name": stack_name}, {"success": False, "error": str(e)})
        return res.dict()


async def get_config_diff(stack_name: str) -> Dict[str, Any]:
    """Compute config diff between deployed and source. Placeholder returns empty diff."""
    cd = ConfigDiff(stack_name=stack_name, diff_text="", compact_delta={})
    audit.log("get_config_diff", {"stack_name": stack_name}, {"success": True})
    return cd.dict()


async def deploy_stack(req: DeployRequest) -> Dict[str, Any]:
    """Perform a git-based stack deployment with docker-compose.

    This function:
    - Clones or updates a git repository
    - Checks out the specified commit/branch
    - Runs docker-compose up (with optional image pull)
    - Updates inventory with deployed commit info
    """
    errors = []
    planned = []

    # Get stack info from inventory
    inv = Inventory()
    stacks = inv.list_stacks()
    stack = stacks.get(req.stack_name, {})

    # Determine deployment path
    deploy_base = os.getenv("STACK_DEPLOY_PATH", "/opt/stacks")
    stack_path = stack.get("path") or os.path.join(deploy_base, req.stack_name)
    repo_url = stack.get("repo_url")

    if not repo_url:
        errors.append(f"No repo_url configured for stack {req.stack_name}")
        result = DeployResult(success=False, dry_run=req.dry_run, planned_changes=planned, errors=errors, deployed_commit=None)
        audit.log("deploy_stack", req.dict(), {"success": False, "error": "no_repo_url"})
        return result.dict()

    # Plan the deployment
    repo_exists = os.path.exists(os.path.join(stack_path, ".git"))
    if repo_exists:
        planned.append(f"Update repository in {stack_path}")
        planned.append(f"Fetch latest changes from {repo_url}")
    else:
        planned.append(f"Clone repository {repo_url} to {stack_path}")

    if req.target_commit:
        planned.append(f"Checkout commit/branch: {req.target_commit}")

    if req.pull_images:
        planned.append(f"Pull Docker images for {req.stack_name}")

    planned.append(f"Run docker-compose up -d for {req.stack_name}")

    if req.dry_run:
        result = DeployResult(success=True, dry_run=True, planned_changes=planned, errors=[], deployed_commit=req.target_commit)
        audit.log("deploy_stack", req.dict(), {"success": True, "dry_run": True})
        return result.dict()

    # Execute deployment
    try:
        # Ensure base directory exists
        os.makedirs(deploy_base, exist_ok=True)

        # Clone or update repository
        if repo_exists:
            # Update existing repo
            git_fetch = await to_thread(
                subprocess.run,
                ["git", "fetch", "--all"],
                cwd=stack_path,
                capture_output=True,
                text=True,
                check=True
            )
            git_reset = await to_thread(
                subprocess.run,
                ["git", "reset", "--hard", f"origin/{req.target_commit or stack.get('branch', 'main')}"],
                cwd=stack_path,
                capture_output=True,
                text=True,
                check=True
            )
        else:
            # Clone new repo
            git_clone = await to_thread(
                subprocess.run,
                ["git", "clone", repo_url, stack_path],
                capture_output=True,
                text=True,
                check=True
            )

            if req.target_commit:
                git_checkout = await to_thread(
                    subprocess.run,
                    ["git", "checkout", req.target_commit],
                    cwd=stack_path,
                    capture_output=True,
                    text=True,
                    check=True
                )

        # Get current commit hash
        git_rev = await to_thread(
            subprocess.run,
            ["git", "rev-parse", "HEAD"],
            cwd=stack_path,
            capture_output=True,
            text=True,
            check=True
        )
        deployed_commit = git_rev.stdout.strip()

        # Pull images if requested
        if req.pull_images:
            compose_pull = await to_thread(
                subprocess.run,
                ["docker", "compose", "pull"],
                cwd=stack_path,
                capture_output=True,
                text=True,
                check=True
            )

        # Deploy with docker-compose
        compose_up = await to_thread(
            subprocess.run,
            ["docker", "compose", "up", "-d", "--remove-orphans"],
            cwd=stack_path,
            capture_output=True,
            text=True,
            check=True
        )

        # Update inventory
        stack["deployed_commit"] = deployed_commit
        stack["path"] = stack_path
        stack["deployed_at"] = datetime.now().isoformat()
        inv._data["stacks"][req.stack_name] = stack
        inv._save()

        result = DeployResult(
            success=True,
            dry_run=False,
            planned_changes=planned,
            errors=[],
            deployed_commit=deployed_commit
        )

        audit.log("deploy_stack", req.dict(), {
            "success": True,
            "deployed_commit": deployed_commit,
            "stack_path": stack_path
        })

    except subprocess.CalledProcessError as e:
        errors.append(f"Command failed: {e.cmd}")
        errors.append(f"Error: {e.stderr}")
        result = DeployResult(
            success=False,
            dry_run=False,
            planned_changes=planned,
            errors=errors,
            deployed_commit=None
        )
        audit.log("deploy_stack", req.dict(), {
            "success": False,
            "error": str(e)
        })
    except Exception as e:
        errors.append(f"Deployment failed: {str(e)}")
        result = DeployResult(
            success=False,
            dry_run=False,
            planned_changes=planned,
            errors=errors,
            deployed_commit=None
        )
        audit.log("deploy_stack", req.dict(), {
            "success": False,
            "error": str(e)
        })

    return result.dict()


async def rollback_stack(host: str, stack_name: str, to_commit: str, dry_run: bool = True) -> Dict[str, Any]:
    """Rollback a stack to a previous commit."""
    errors = []
    planned = [
        f"Checkout commit {to_commit} for {stack_name}",
        f"Redeploy {stack_name} with docker-compose"
    ]

    if dry_run:
        res = DeployResult(success=True, dry_run=True, planned_changes=planned, errors=[], deployed_commit=to_commit)
        audit.log("rollback_stack", {"host": host, "stack_name": stack_name, "to_commit": to_commit}, {"success": True, "dry_run": True})
        return res.dict()

    # Execute rollback via deploy_stack
    deploy_req = DeployRequest(
        host=host,
        stack_name=stack_name,
        target_commit=to_commit,
        pull_images=False,
        force=True,
        dry_run=False
    )

    result = await deploy_stack(deploy_req)
    audit.log("rollback_stack", {"host": host, "stack_name": stack_name, "to_commit": to_commit}, {"success": result.get("success"), "dry_run": False})
    return result


async def get_stack_history(stack_name: str, limit: int = 20) -> List[Dict[str, Any]]:
    # Placeholder: in-memory or inventory-backed history not implemented; return empty
    audit.log("get_stack_history", {"stack_name": stack_name, "limit": limit}, {"success": True})
    return []


async def simulate_action(stack_name: str, action: str) -> Dict[str, Any]:
    # Minimal impact simulation: looks up inventory dependencies (not implemented)
    sim = SimulateActionResult(impacted_stacks=[], risk_level="low", details={"note": "No dependency graph configured"})
    audit.log("simulate_action", {"stack_name": stack_name, "action": action}, {"success": True})
    return sim.dict()


async def get_stack_network_info(host: str, stack_name: str) -> Dict[str, Any]:
    """Return port bindings, published ports, network mode, and detect host-port conflicts.

    Strategy:
    - Attempt to use docker-py if available to list containers for the compose project
      (label `com.docker.compose.project==<stack_name>`), otherwise fall back to
      `docker ps` + `docker inspect` via the CLI.
    - Collect for each container: container_id, name, service (best-effort), image,
      network_mode, port_bindings (host_port -> container_port/proto), mounts.
    - Detect conflicts where multiple containers bind the same host port.
    """
    inv = Inventory()
    stacks = inv.list_stacks()
    stack = stacks.get(stack_name, {})

    results: Dict[str, Any] = {"stack_name": stack_name, "host": host, "containers": [], "port_conflicts": []}

    # Helper: inspect container via docker inspect CLI
    def _inspect_container_cli(container_id: str) -> Optional[Dict[str, Any]]:
        try:
            p = subprocess.run(["docker", "inspect", container_id], capture_output=True, text=True, check=True)
            data = json.loads(p.stdout)
            if data and isinstance(data, list):
                return data[0]
        except Exception:
            return None

    containers_info: List[Dict[str, Any]] = []

    # Try docker SDK first
    try:
        import docker

        client = docker.from_env()
        # Try to find containers by compose project label
        filters = {"label": f"com.docker.compose.project={stack_name}"}
        found = client.containers.list(all=True, filters=filters)
        if not found:
            # fallback: match containers whose name begins with stack_name
            found = [c for c in client.containers.list(all=True) if c.name.startswith(stack_name + "_")]

        for c in found:
            try:
                ci = c.attrs
            except Exception:
                ci = _inspect_container_cli(c.id)
            if not ci:
                continue
            containers_info.append(ci)
    except Exception:
        # Docker SDK not available; fall back to CLI
        try:
            # List containers with names and ids
            p = subprocess.run(["docker", "ps", "-a", "--format", "{{json .}}"], capture_output=True, text=True, check=True)
            lines = [l for l in p.stdout.splitlines() if l.strip()]
            for ln in lines:
                try:
                    item = json.loads(ln)
                    name = item.get("Names") or item.get("Name") or ""
                    cid = item.get("ID") or item.get("Id") or item.get("ContainerID") or ""
                    if not cid:
                        continue
                    # Filter by stack_name match
                    if name.startswith(stack_name + "_") or name == stack_name:
                        ci = _inspect_container_cli(cid)
                        if ci:
                            containers_info.append(ci)
                except Exception:
                    continue
        except Exception:
            # No docker access
            audit.log("get_stack_network_info", {"host": host, "stack_name": stack_name}, {"success": False, "error": "docker unavailable"})
            return {"error": "docker unavailable or permission denied"}

    # Parse container infos
    host_port_map: Dict[str, List[Dict[str, Any]]] = {}
    for ci in containers_info:
        cid = ci.get("Id")
        name = ci.get("Name") or (ci.get("Name") if ci.get("Name") else None)
        # Try to determine service name from labels (compose overrides)
        labels = ci.get("Config", {}).get("Labels", {}) if isinstance(ci.get("Config"), dict) else {}
        service = labels.get("com.docker.compose.service") or labels.get("com.docker.compose.project")
        image = ci.get("Config", {}).get("Image") if isinstance(ci.get("Config"), dict) else ci.get("Image")
        network_mode = ci.get("HostConfig", {}).get("NetworkMode") if isinstance(ci.get("HostConfig"), dict) else None

        ports = []
        ns = ci.get("NetworkSettings", {}) or {}
        port_bindings = ns.get("Ports") if isinstance(ns.get("Ports"), dict) else {}
        for container_port_proto, host_bind in (port_bindings or {}).items():
            # container_port_proto example: "80/tcp"
            if host_bind is None:
                # not published
                continue
            for hb in host_bind:
                host_ip = hb.get("HostIp")
                host_port = hb.get("HostPort")
                cp = container_port_proto
                ports.append({"host_ip": host_ip, "host_port": host_port, "container_port": cp})
                host_port_map.setdefault(str(host_port), []).append({"container_id": cid, "name": name, "service": service, "stack": stack_name})

        mounts = ci.get("Mounts") or []

        containers_entry = {
            "container_id": cid,
            "name": name,
            "service": service,
            "image": image,
            "network_mode": network_mode,
            "ports": ports,
            "mounts": mounts,
        }
        results["containers"].append(containers_entry)

    # Detect conflicts: host ports mapped by multiple containers
    conflicts = []
    for host_p, bindings in host_port_map.items():
        if len(bindings) > 1:
            conflicts.append({"host_port": host_p, "bindings": bindings})

    results["port_conflicts"] = conflicts

    audit.log("get_stack_network_info", {"host": host, "stack_name": stack_name}, {"success": True, "count": len(results["containers"])})
    return results
