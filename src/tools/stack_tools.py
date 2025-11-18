from __future__ import annotations

import asyncio
import json
import os
import shutil
from typing import List, Optional, Dict, Any
from datetime import datetime
from pathlib import Path

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
from src.services.compose_manager import ComposeStackManager
import subprocess
from asyncio import to_thread

try:
    import docker
    import git
    DOCKER_AVAILABLE = True
    GIT_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False
    GIT_AVAILABLE = False


audit = AuditLogger()

# Stack deployment history storage
STACKS_DIR = os.getenv("TAILOPS_STACKS_DIR", "/opt/stacks")
HISTORY_DIR = os.getenv("TAILOPS_HISTORY_DIR", "/var/lib/systemmanager/stack_history")


# Helper functions for deployment history
def _get_history_file(stack_name: str) -> Path:
    """Get the history file path for a stack."""
    os.makedirs(HISTORY_DIR, exist_ok=True)
    return Path(HISTORY_DIR) / f"{stack_name}.json"


def _save_history_entry(stack_name: str, entry: StackHistoryEntry) -> None:
    """Save a deployment history entry."""
    history_file = _get_history_file(stack_name)
    history = []

    if history_file.exists():
        try:
            with open(history_file, 'r') as f:
                history = json.load(f)
        except Exception:
            history = []

    history.insert(0, entry.dict())

    # Keep last 100 entries
    history = history[:100]

    with open(history_file, 'w') as f:
        json.dump(history, f, indent=2, default=str)


def _load_history(stack_name: str, limit: int = 20) -> List[Dict[str, Any]]:
    """Load deployment history for a stack."""
    history_file = _get_history_file(stack_name)

    if not history_file.exists():
        return []

    try:
        with open(history_file, 'r') as f:
            history = json.load(f)
        return history[:limit]
    except Exception:
        return []


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
    """Return a structured StackStatus summary with real-time health monitoring.

    Inspects running containers to determine actual service health, uptime,
    resource usage, and issues.
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
        environment=stack.get("environment") if stack else None,
    )

    # Real container health monitoring
    services: List[ServiceSummary] = []
    issues: List[str] = []

    if DOCKER_AVAILABLE:
        try:
            client = docker.from_env()

            # Find containers for this stack
            filters = {"label": f"com.docker.compose.project={stack_name}"}
            containers = client.containers.list(all=True, filters=filters)

            # Group containers by service
            service_containers: Dict[str, List] = {}
            for container in containers:
                service = container.labels.get("com.docker.compose.service", "unknown")
                if service not in service_containers:
                    service_containers[service] = []
                service_containers[service].append(container)

            # Build service summaries with health data
            for service_name, ctrs in service_containers.items():
                running_count = sum(1 for c in ctrs if c.status == "running")
                total_count = len(ctrs)

                # Get stats from first running container
                stats_ctr = next((c for c in ctrs if c.status == "running"), None)
                cpu_percent = None
                memory_bytes = None
                uptime_seconds = None
                restart_count = None

                if stats_ctr:
                    try:
                        # Get container details
                        stats_ctr.reload()
                        started_at = stats_ctr.attrs["State"]["StartedAt"]
                        if started_at:
                            started_dt = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
                            uptime_seconds = int((datetime.now(started_dt.tzinfo) - started_dt).total_seconds())

                        restart_count = stats_ctr.attrs["RestartCount"]

                        # Get memory usage
                        stats = stats_ctr.stats(stream=False)
                        memory_bytes = stats.get("memory_stats", {}).get("usage", 0)

                        # Calculate CPU percentage
                        cpu_delta = stats.get("cpu_stats", {}).get("cpu_usage", {}).get("total_usage", 0) - \
                                   stats.get("precpu_stats", {}).get("cpu_usage", {}).get("total_usage", 0)
                        system_delta = stats.get("cpu_stats", {}).get("system_cpu_usage", 0) - \
                                      stats.get("precpu_stats", {}).get("system_cpu_usage", 0)
                        if system_delta > 0:
                            cpu_percent = (cpu_delta / system_delta) * 100.0
                    except Exception as e:
                        issues.append(f"Failed to get stats for {service_name}: {str(e)}")

                # Determine overall service status
                if running_count == 0:
                    status = "stopped"
                    issues.append(f"Service {service_name} has no running containers")
                elif running_count < total_count:
                    status = "degraded"
                    issues.append(f"Service {service_name} has {running_count}/{total_count} containers running")
                else:
                    status = "running"

                # Check for unhealthy containers
                service_issues = []
                for ctr in ctrs:
                    if ctr.status in ["exited", "dead"]:
                        service_issues.append(f"Container {ctr.name} is {ctr.status}")
                    health = ctr.attrs.get("State", {}).get("Health", {}).get("Status")
                    if health == "unhealthy":
                        service_issues.append(f"Container {ctr.name} is unhealthy")
                        status = "unhealthy"

                services.append(ServiceSummary(
                    name=service_name,
                    image=ctrs[0].image.tags[0] if ctrs and ctrs[0].image.tags else None,
                    replicas=total_count,
                    running_count=running_count,
                    status=status,
                    uptime_seconds=uptime_seconds,
                    restart_count=restart_count,
                    cpu_percent=cpu_percent,
                    memory_bytes=memory_bytes,
                    issues=service_issues,
                ))

            # Check if expected services are missing
            if meta.services:
                found_services = set(service_containers.keys())
                expected_services = set(meta.services)
                missing = expected_services - found_services
                if missing:
                    issues.append(f"Missing services: {', '.join(missing)}")

        except Exception as e:
            issues.append(f"Docker inspection failed: {str(e)}")
            # Fallback to basic service list
            for sname in meta.services or []:
                services.append(ServiceSummary(name=sname, status="unknown"))
    else:
        # Docker not available
        for sname in meta.services or []:
            services.append(ServiceSummary(name=sname, status="unknown"))
        issues.append("Docker SDK not available - cannot inspect containers")

    status_obj = StackStatus(meta=meta, services=services, issues=issues)

    audit.log("get_stack_status", {"host": host, "stack_name": stack_name}, {"success": True, "issues": len(issues)})
    return status_obj.dict()


async def get_repo_status(stack_name: str) -> Dict[str, Any]:
    """Return repo status for a stack with real git information.

    Checks the local repository for:
    - Current branch
    - Latest commit
    - How many commits ahead/behind from deployed
    - Uncommitted changes
    - Available tags
    """
    inv = Inventory()
    stacks = inv.list_stacks()
    stack = stacks.get(stack_name)

    if not stack:
        return {"error": f"Stack {stack_name} not found in inventory"}

    repo_url = stack.get("repo_url")
    branch = stack.get("branch", "main")
    deployed_commit = stack.get("deployed_commit")
    stack_path = Path(STACKS_DIR) / stack_name

    latest_commit = None
    ahead_by = None
    behind_by = None
    tags = []
    has_uncommitted = False

    if GIT_AVAILABLE and stack_path.exists():
        try:
            repo = git.Repo(stack_path)

            # Get current branch
            try:
                current_branch = repo.active_branch.name
                branch = current_branch
            except Exception:
                # Detached head state
                pass

            # Get latest commit
            latest_commit = repo.head.commit.hexsha

            # Get tags
            tags = [tag.name for tag in repo.tags]

            # Check for uncommitted changes
            has_uncommitted = repo.is_dirty() or len(repo.untracked_files) > 0

            # Calculate ahead/behind if deployed_commit is known
            if deployed_commit:
                try:
                    deployed_obj = repo.commit(deployed_commit)
                    current_obj = repo.head.commit

                    # Get commits between deployed and current
                    ahead = list(repo.iter_commits(f'{deployed_commit}..HEAD'))
                    behind = list(repo.iter_commits(f'HEAD..{deployed_commit}'))

                    ahead_by = len(ahead)
                    behind_by = len(behind)
                except Exception:
                    # Invalid commit reference
                    pass

        except Exception as e:
            audit.log("get_repo_status", {"stack_name": stack_name}, {"success": False, "error": str(e)})

    res = RepoStatus(
        repo_url=repo_url,
        branch=branch,
        latest_commit=latest_commit,
        deployed_commit=deployed_commit,
        ahead_by=ahead_by,
        behind_by=behind_by,
        tags=tags,
        has_uncommitted_changes=has_uncommitted,
    )

    audit.log("get_repo_status", {"stack_name": stack_name}, {"success": True})
    return res.dict()


async def get_config_diff(stack_name: str) -> Dict[str, Any]:
    """Compute config diff between deployed and latest repository version.

    Shows changes in docker-compose.yml and .env files.
    """
    inv = Inventory()
    stacks = inv.list_stacks()
    stack = stacks.get(stack_name)

    if not stack:
        return {"error": f"Stack {stack_name} not found in inventory"}

    deployed_commit = stack.get("deployed_commit")
    stack_path = Path(STACKS_DIR) / stack_name
    diff_text = ""
    compact_delta = {}

    if GIT_AVAILABLE and stack_path.exists() and deployed_commit:
        try:
            repo = git.Repo(stack_path)

            # Get diff between deployed commit and current HEAD
            try:
                diff = repo.git.diff(deployed_commit, "HEAD", "--", "docker-compose.yml", ".env")
                diff_text = diff
            except Exception:
                # Maybe the files don't exist or commit is invalid
                pass

            # Parse changed files
            changed_files = []
            try:
                diff_index = repo.commit(deployed_commit).diff(repo.head.commit)
                for diff_item in diff_index:
                    if diff_item.a_path in ["docker-compose.yml", ".env", "docker-compose.yaml"]:
                        changed_files.append({
                            "file": diff_item.a_path,
                            "change_type": diff_item.change_type,
                        })
            except Exception:
                pass

            compact_delta = {
                "changed_files": changed_files,
                "commits_ahead": len(list(repo.iter_commits(f'{deployed_commit}..HEAD'))) if deployed_commit else 0,
            }

        except Exception as e:
            audit.log("get_config_diff", {"stack_name": stack_name}, {"success": False, "error": str(e)})

    cd = ConfigDiff(stack_name=stack_name, diff_text=diff_text, compact_delta=compact_delta)
    audit.log("get_config_diff", {"stack_name": stack_name}, {"success": True})
    return cd.dict()


async def deploy_stack(req: DeployRequest) -> Dict[str, Any]:
    """GitOps stack deployment - Pull from GitHub and deploy compose stacks.

    Features:
    - Clone/pull from git repository
    - Checkout specific commit/branch
    - Support for multiple environments (dev/staging/prod)
    - Pull latest images
    - Deploy with docker-compose
    - Track deployment history
    - Dry-run mode for safety

    Args:
        req: DeployRequest with stack_name, target_commit, pull_images, force, dry_run

    Returns:
        DeployResult with success status, planned changes, errors, and deployed commit
    """
    inv = Inventory()
    stacks = inv.list_stacks()
    stack = stacks.get(req.stack_name)

    planned_changes = []
    errors = []
    deployed_commit = None

    # Verify stack exists in inventory
    if not stack and not req.force:
        errors.append(f"Stack {req.stack_name} not found in inventory. Use force=True to create new stack.")
        result = DeployResult(success=False, dry_run=req.dry_run, planned_changes=planned_changes, errors=errors)
        audit.log("deploy_stack", req.dict(), {"success": False, "error": "stack_not_found"})
        return result.dict()

    # Get stack metadata
    repo_url = stack.get("repo_url") if stack else None
    branch = stack.get("branch", "main") if stack else "main"
    environment = stack.get("environment", "prod") if stack else "prod"
    stack_path = Path(STACKS_DIR) / req.stack_name

    if not repo_url:
        errors.append(f"Stack {req.stack_name} has no repo_url configured")
        result = DeployResult(success=False, dry_run=req.dry_run, planned_changes=planned_changes, errors=errors)
        audit.log("deploy_stack", req.dict(), {"success": False, "error": "no_repo_url"})
        return result.dict()

    # Plan: Clone or pull repository
    if not stack_path.exists():
        planned_changes.append(f"Clone repository {repo_url} to {stack_path}")
    else:
        planned_changes.append(f"Pull latest changes from {repo_url}")

    # Plan: Checkout target commit
    if req.target_commit:
        planned_changes.append(f"Checkout commit/branch/tag: {req.target_commit}")
    else:
        planned_changes.append(f"Checkout branch: {branch}")

    # Plan: Environment-specific config
    compose_file = "docker-compose.yml"
    env_compose_file = f"docker-compose.{environment}.yml"
    planned_changes.append(f"Use environment: {environment}")

    # Plan: Pull images
    if req.pull_images:
        planned_changes.append("Pull latest Docker images")

    # Plan: Deploy services
    planned_changes.append("Deploy stack with docker-compose up -d")

    # Execute if not dry-run
    if not req.dry_run:
        try:
            # Step 1: Clone or pull repository
            if not GIT_AVAILABLE:
                errors.append("Git is not available")
                result = DeployResult(success=False, dry_run=False, planned_changes=planned_changes, errors=errors)
                audit.log("deploy_stack", req.dict(), {"success": False, "error": "git_unavailable"})
                return result.dict()

            if stack_path.exists():
                # Pull latest changes
                try:
                    repo = git.Repo(stack_path)
                    origin = repo.remotes.origin
                    origin.fetch()
                except Exception as e:
                    errors.append(f"Failed to fetch from origin: {str(e)}")
                    result = DeployResult(success=False, dry_run=False, planned_changes=planned_changes, errors=errors)
                    audit.log("deploy_stack", req.dict(), {"success": False, "error": str(e)})
                    return result.dict()
            else:
                # Clone repository
                try:
                    os.makedirs(STACKS_DIR, exist_ok=True)
                    repo = git.Repo.clone_from(repo_url, stack_path, branch=branch)
                except Exception as e:
                    errors.append(f"Failed to clone repository: {str(e)}")
                    result = DeployResult(success=False, dry_run=False, planned_changes=planned_changes, errors=errors)
                    audit.log("deploy_stack", req.dict(), {"success": False, "error": str(e)})
                    return result.dict()

            # Step 2: Checkout target commit/branch/tag
            try:
                target = req.target_commit or branch
                repo.git.checkout(target)
                deployed_commit = repo.head.commit.hexsha
            except Exception as e:
                errors.append(f"Failed to checkout {target}: {str(e)}")
                result = DeployResult(success=False, dry_run=False, planned_changes=planned_changes, errors=errors)
                audit.log("deploy_stack", req.dict(), {"success": False, "error": str(e)})
                return result.dict()

            # Step 3: Determine compose file(s)
            compose_files = []
            base_compose = stack_path / compose_file
            env_compose = stack_path / env_compose_file

            if not base_compose.exists():
                errors.append(f"docker-compose.yml not found in {stack_path}")
                result = DeployResult(success=False, dry_run=False, planned_changes=planned_changes, errors=errors)
                audit.log("deploy_stack", req.dict(), {"success": False, "error": "compose_file_missing"})
                return result.dict()

            compose_files.append(str(base_compose))

            # Use environment-specific override if it exists
            if env_compose.exists():
                compose_files.append(str(env_compose))
                planned_changes.append(f"Using environment override: {env_compose_file}")

            # Step 4: Pull images if requested
            if req.pull_images:
                try:
                    pull_cmd = ["docker-compose"] + [f for f_item in compose_files for f in ["-f", f_item]] + ["pull"]
                    result_pull = subprocess.run(
                        pull_cmd,
                        cwd=stack_path,
                        capture_output=True,
                        text=True,
                        timeout=300
                    )
                    if result_pull.returncode != 0:
                        errors.append(f"Image pull warnings: {result_pull.stderr}")
                        # Continue anyway - pull might fail for some images but others might succeed
                except Exception as e:
                    errors.append(f"Failed to pull images: {str(e)}")
                    # Continue anyway

            # Step 5: Deploy with docker-compose
            try:
                up_cmd = ["docker-compose"] + [f for f_item in compose_files for f in ["-f", f_item]] + ["up", "-d"]
                result_up = subprocess.run(
                    up_cmd,
                    cwd=stack_path,
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                if result_up.returncode != 0:
                    errors.append(f"Docker-compose up failed: {result_up.stderr}")
                    result = DeployResult(success=False, dry_run=False, planned_changes=planned_changes, errors=errors, deployed_commit=deployed_commit)
                    audit.log("deploy_stack", req.dict(), {"success": False, "error": "compose_up_failed"})
                    return result.dict()
            except Exception as e:
                errors.append(f"Failed to run docker-compose up: {str(e)}")
                result = DeployResult(success=False, dry_run=False, planned_changes=planned_changes, errors=errors, deployed_commit=deployed_commit)
                audit.log("deploy_stack", req.dict(), {"success": False, "error": str(e)})
                return result.dict()

            # Step 6: Update inventory
            stack_data = stack or {}
            stack_data.update({
                "name": req.stack_name,
                "path": str(stack_path),
                "repo_url": repo_url,
                "branch": branch,
                "deployed_commit": deployed_commit,
                "last_deployed": datetime.utcnow().isoformat() + "Z",
                "environment": environment,
                "host": req.host,
            })

            # Get services from compose file
            try:
                import yaml
                with open(base_compose, 'r') as f:
                    compose_data = yaml.safe_load(f)
                    services = list(compose_data.get("services", {}).keys())
                    stack_data["services"] = services
            except Exception:
                # Services list will remain as-is or empty
                pass

            inv._data.setdefault("stacks", {})[req.stack_name] = stack_data
            inv.save()

            # Step 7: Record deployment history
            history_entry = StackHistoryEntry(
                timestamp=datetime.utcnow(),
                actor="mcp-server",
                action="deploy",
                commit=deployed_commit,
                result="success",
            )
            _save_history_entry(req.stack_name, history_entry)

        except Exception as e:
            errors.append(f"Deployment failed with unexpected error: {str(e)}")
            result = DeployResult(success=False, dry_run=False, planned_changes=planned_changes, errors=errors, deployed_commit=deployed_commit)
            audit.log("deploy_stack", req.dict(), {"success": False, "error": str(e)})
            return result.dict()

    # Success
    success = len(errors) == 0
    result = DeployResult(
        success=success,
        dry_run=req.dry_run,
        planned_changes=planned_changes,
        errors=errors,
        deployed_commit=deployed_commit
    )

    audit.log("deploy_stack", req.dict(), {"success": success, "dry_run": req.dry_run, "commit": deployed_commit})
    return result.dict()


async def rollback_stack(host: str, stack_name: str, to_commit: str, dry_run: bool = True) -> Dict[str, Any]:
    """Rollback automation - Revert to previous stack version.

    Features:
    - Git-based rollback to specific commit
    - Automatic redeployment after rollback
    - Safety checks and validation
    - Deployment history tracking
    - Dry-run mode

    Args:
        host: Target host
        stack_name: Name of stack to rollback
        to_commit: Commit hash/tag/branch to rollback to
        dry_run: If True, only show planned changes

    Returns:
        DeployResult with rollback status
    """
    inv = Inventory()
    stacks = inv.list_stacks()
    stack = stacks.get(stack_name)

    planned_changes = []
    errors = []
    deployed_commit = None

    if not stack:
        errors.append(f"Stack {stack_name} not found in inventory")
        result = DeployResult(success=False, dry_run=dry_run, planned_changes=planned_changes, errors=errors)
        audit.log("rollback_stack", {"host": host, "stack_name": stack_name, "to_commit": to_commit}, {"success": False, "error": "stack_not_found"})
        return result.dict()

    stack_path = Path(STACKS_DIR) / stack_name
    current_commit = stack.get("deployed_commit")

    planned_changes.append(f"Current commit: {current_commit}")
    planned_changes.append(f"Rollback to commit: {to_commit}")

    # Verify stack path exists
    if not stack_path.exists():
        errors.append(f"Stack directory not found: {stack_path}")
        result = DeployResult(success=False, dry_run=dry_run, planned_changes=planned_changes, errors=errors)
        audit.log("rollback_stack", {"host": host, "stack_name": stack_name, "to_commit": to_commit}, {"success": False, "error": "path_not_found"})
        return result.dict()

    # Plan changes
    planned_changes.append(f"Checkout {to_commit} in {stack_path}")
    planned_changes.append("Stop running containers")
    planned_changes.append("Deploy services from rollback commit")
    planned_changes.append("Update inventory with rollback commit")

    # Execute rollback if not dry-run
    if not dry_run:
        if not GIT_AVAILABLE:
            errors.append("Git is not available")
            result = DeployResult(success=False, dry_run=False, planned_changes=planned_changes, errors=errors)
            audit.log("rollback_stack", {"host": host, "stack_name": stack_name, "to_commit": to_commit}, {"success": False, "error": "git_unavailable"})
            return result.dict()

        try:
            # Step 1: Verify git repository
            repo = git.Repo(stack_path)

            # Step 2: Verify target commit exists
            try:
                target_obj = repo.commit(to_commit)
                deployed_commit = target_obj.hexsha
            except Exception as e:
                errors.append(f"Invalid commit/tag/branch: {to_commit}: {str(e)}")
                result = DeployResult(success=False, dry_run=False, planned_changes=planned_changes, errors=errors)
                audit.log("rollback_stack", {"host": host, "stack_name": stack_name, "to_commit": to_commit}, {"success": False, "error": "invalid_commit"})
                return result.dict()

            # Step 3: Check for uncommitted changes
            if repo.is_dirty() or repo.untracked_files:
                errors.append("Repository has uncommitted changes. Please commit or stash them first.")
                result = DeployResult(success=False, dry_run=False, planned_changes=planned_changes, errors=errors)
                audit.log("rollback_stack", {"host": host, "stack_name": stack_name, "to_commit": to_commit}, {"success": False, "error": "uncommitted_changes"})
                return result.dict()

            # Step 4: Checkout target commit
            try:
                repo.git.checkout(to_commit)
            except Exception as e:
                errors.append(f"Failed to checkout {to_commit}: {str(e)}")
                result = DeployResult(success=False, dry_run=False, planned_changes=planned_changes, errors=errors)
                audit.log("rollback_stack", {"host": host, "stack_name": stack_name, "to_commit": to_commit}, {"success": False, "error": str(e)})
                return result.dict()

            # Step 5: Find compose file
            environment = stack.get("environment", "prod")
            compose_file = stack_path / "docker-compose.yml"
            env_compose_file = stack_path / f"docker-compose.{environment}.yml"

            if not compose_file.exists():
                errors.append("docker-compose.yml not found after checkout")
                # Try to rollback the checkout
                try:
                    if current_commit:
                        repo.git.checkout(current_commit)
                except Exception:
                    pass
                result = DeployResult(success=False, dry_run=False, planned_changes=planned_changes, errors=errors)
                audit.log("rollback_stack", {"host": host, "stack_name": stack_name, "to_commit": to_commit}, {"success": False, "error": "compose_missing"})
                return result.dict()

            compose_files = [str(compose_file)]
            if env_compose_file.exists():
                compose_files.append(str(env_compose_file))

            # Step 6: Stop current services
            try:
                down_cmd = ["docker-compose"] + [f for f_item in compose_files for f in ["-f", f_item]] + ["down"]
                subprocess.run(down_cmd, cwd=stack_path, capture_output=True, text=True, timeout=60)
            except Exception as e:
                errors.append(f"Warning: Failed to stop services: {str(e)}")
                # Continue anyway

            # Step 7: Deploy rollback version
            try:
                up_cmd = ["docker-compose"] + [f for f_item in compose_files for f in ["-f", f_item]] + ["up", "-d"]
                result_up = subprocess.run(
                    up_cmd,
                    cwd=stack_path,
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                if result_up.returncode != 0:
                    errors.append(f"Docker-compose up failed: {result_up.stderr}")
                    result = DeployResult(success=False, dry_run=False, planned_changes=planned_changes, errors=errors, deployed_commit=deployed_commit)
                    audit.log("rollback_stack", {"host": host, "stack_name": stack_name, "to_commit": to_commit}, {"success": False, "error": "compose_up_failed"})
                    return result.dict()
            except Exception as e:
                errors.append(f"Failed to deploy rollback: {str(e)}")
                result = DeployResult(success=False, dry_run=False, planned_changes=planned_changes, errors=errors, deployed_commit=deployed_commit)
                audit.log("rollback_stack", {"host": host, "stack_name": stack_name, "to_commit": to_commit}, {"success": False, "error": str(e)})
                return result.dict()

            # Step 8: Update inventory
            stack["deployed_commit"] = deployed_commit
            stack["last_deployed"] = datetime.utcnow().isoformat() + "Z"
            inv._data["stacks"][stack_name] = stack
            inv.save()

            # Step 9: Record rollback in history
            history_entry = StackHistoryEntry(
                timestamp=datetime.utcnow(),
                actor="mcp-server",
                action="rollback",
                commit=deployed_commit,
                result="success",
            )
            _save_history_entry(stack_name, history_entry)

        except Exception as e:
            errors.append(f"Rollback failed: {str(e)}")
            result = DeployResult(success=False, dry_run=False, planned_changes=planned_changes, errors=errors)
            audit.log("rollback_stack", {"host": host, "stack_name": stack_name, "to_commit": to_commit}, {"success": False, "error": str(e)})
            return result.dict()

    success = len(errors) == 0
    result = DeployResult(
        success=success,
        dry_run=dry_run,
        planned_changes=planned_changes,
        errors=errors,
        deployed_commit=deployed_commit
    )

    audit.log("rollback_stack", {"host": host, "stack_name": stack_name, "to_commit": to_commit}, {"success": success, "dry_run": dry_run})
    return result.dict()


async def get_stack_history(stack_name: str, limit: int = 20) -> List[Dict[str, Any]]:
    """Get deployment history for a stack.

    Returns a list of deployment/rollback actions with timestamps, commits,
    actors, and results.

    Args:
        stack_name: Name of the stack
        limit: Maximum number of history entries to return (default: 20)

    Returns:
        List of history entries, newest first
    """
    history = _load_history(stack_name, limit)
    audit.log("get_stack_history", {"stack_name": stack_name, "limit": limit}, {"success": True, "count": len(history)})
    return history


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
