"""
Docker Compose Stack Management with security hardening.
Similar to Portainer/Komodo stacks - deploy from GitHub repos
"""

import os
import subprocess
import logging
import re
from typing import Dict, Optional
from pathlib import Path
from urllib.parse import urlparse
import git

logger = logging.getLogger(__name__)


class ComposeStackManager:
    """Manage Docker Compose stacks from Git repositories."""

    def __init__(self, stacks_dir: str = "/opt/stacks"):
        self.stacks_dir = Path(stacks_dir)
        self.stacks_dir.mkdir(parents=True, exist_ok=True)

    def _validate_repo_url(self, url: str) -> bool:
        """Securely validate repository URL to prevent command injection.

        Args:
            url: Git repository URL to validate

        Returns:
            True if URL is allowed, False otherwise
        """
        import re

        # Basic input validation
        if not url or not isinstance(url, str):
            return False

        # Get allowed hosts from environment, default to common git providers
        allowed_hosts_str = os.getenv(
            "SYSTEMMANAGER_ALLOWED_GIT_HOSTS", "github.com,gitlab.com,bitbucket.org"
        )
        allowed_hosts = [
            h.strip().lower() for h in allowed_hosts_str.split(",") if h.strip()
        ]

        try:
            # URL format validation
            url_pattern = re.compile(
                r"^(https://|git@)[a-zA-Z0-9.-]+(/.*)?$", re.IGNORECASE
            )
            if not url_pattern.match(url):
                return False

            parsed = urlparse(url)

            # Only allow https and git protocols
            if parsed.scheme not in ["https", "git"]:
                return False

            # Securely extract hostname with proper validation
            host = self._extract_secure_hostname(parsed, url)
            if not host:
                return False

            # Normalize hostname
            host = host.lower().strip()

            # Validate hostname format
            if not self._is_valid_hostname(host):
                return False

            # Check if host is in allowed list
            return any(
                host == allowed or host.endswith("." + allowed)
                for allowed in allowed_hosts
            )
        except Exception as e:
            logger.warning(f"URL validation error for {url}: {str(e)}")
            return False

    def _extract_secure_hostname(self, parsed, url: str) -> Optional[str]:
        """Securely extract hostname from parsed URL."""
        try:
            # Handle SSH git URLs (git@host:repo format)
            if "@" in url and url.startswith("git@"):
                git_match = re.match(r"git@([^:]+):", url)
                if git_match:
                    return git_match.group(1)
                return None

            # Handle standard URLs
            netloc = parsed.netloc

            # Remove port if present
            if ":" in netloc:
                netloc = netloc.split(":")[0]

            # Validate netloc format
            if not netloc or "." not in netloc:
                return None

            return netloc

        except Exception:
            return None

    def _is_valid_hostname(self, hostname: str) -> bool:
        """Validate hostname format to prevent injection."""
        import re

        # Hostname pattern: alphanumeric, hyphens, dots, max 253 chars
        hostname_pattern = re.compile(
            r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
        )

        return (
            len(hostname) <= 253
            and hostname_pattern.match(hostname) is not None
            and not hostname.startswith("-")
            and not hostname.endswith("-")
            and ".." not in hostname
        )

    async def deploy_stack(
        self,
        stack_name: str,
        repo_url: str,
        branch: str = "main",
        compose_file: str = "docker-compose.yml",
        env_vars: Optional[Dict[str, str]] = None,
    ) -> Dict:
        """Deploy a stack from a Git repository.

        Args:
            stack_name: Unique name for the stack
            repo_url: Git repository URL
            branch: Branch to checkout
            compose_file: Path to compose file in repo
            env_vars: Environment variables for the stack

        Returns:
            Deployment status and details
        """
        stack_path = self.stacks_dir / stack_name

        try:
            # Validate repository URL
            if not self._validate_repo_url(repo_url):
                return {
                    "success": False,
                    "error": f"Repository URL not allowed: {repo_url}. Configure SYSTEMMANAGER_ALLOWED_GIT_HOSTS to allow this host.",
                    "stack": stack_name,
                }

            # Clone or pull repository
            if stack_path.exists():
                repo = git.Repo(stack_path)
                origin = repo.remotes.origin
                origin.pull(branch)
                action = "updated"
            else:
                repo = git.Repo.clone_from(repo_url, stack_path, branch=branch)
                action = "cloned"

            # Get current commit
            commit = repo.head.commit.hexsha[:8]

            # Create .env file if env_vars provided
            if env_vars:
                env_file = stack_path / ".env"
                with open(env_file, "w") as f:
                    for key, value in env_vars.items():
                        f.write(f"{key}={value}\n")

            # Deploy with docker compose
            compose_path = stack_path / compose_file
            if not compose_path.exists():
                return {
                    "success": False,
                    "error": f"Compose file not found: {compose_file}",
                }

            # Run docker compose up
            result = subprocess.run(
                ["docker", "compose", "-f", str(compose_path), "up", "-d"],
                cwd=stack_path,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode != 0:
                return {"success": False, "error": result.stderr, "stack": stack_name}

            return {
                "success": True,
                "stack": stack_name,
                "action": action,
                "commit": commit,
                "branch": branch,
                "output": result.stdout,
            }

        except Exception as e:
            return {"success": False, "error": str(e), "stack": stack_name}

    async def list_stacks(self) -> Dict:
        """List all deployed stacks with status."""
        stacks = []

        for stack_dir in self.stacks_dir.iterdir():
            if not stack_dir.is_dir() or stack_dir.name.startswith("."):
                continue

            try:
                # Get git info
                repo = git.Repo(stack_dir)
                commit = repo.head.commit.hexsha[:8]
                branch = repo.active_branch.name

                # Get compose services
                compose_file = stack_dir / "docker-compose.yml"
                if compose_file.exists():
                    result = subprocess.run(
                        [
                            "docker",
                            "compose",
                            "-f",
                            str(compose_file),
                            "ps",
                            "--format",
                            "json",
                        ],
                        cwd=stack_dir,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )

                    stacks.append(
                        {
                            "name": stack_dir.name,
                            "path": str(stack_dir),
                            "commit": commit,
                            "branch": branch,
                            "status": "running" if result.returncode == 0 else "error",
                        }
                    )
            except Exception as e:
                stacks.append(
                    {
                        "name": stack_dir.name,
                        "path": str(stack_dir),
                        "status": "error",
                        "error": str(e),
                    }
                )

        return {"success": True, "stacks": stacks, "count": len(stacks)}

    async def update_stack(self, stack_name: str) -> Dict:
        """Pull latest changes and redeploy stack."""
        stack_path = self.stacks_dir / stack_name

        if not stack_path.exists():
            return {"success": False, "error": f"Stack not found: {stack_name}"}

        try:
            # Pull latest
            repo = git.Repo(stack_path)
            origin = repo.remotes.origin
            origin.pull()

            commit = repo.head.commit.hexsha[:8]

            # Restart services
            compose_file = stack_path / "docker-compose.yml"
            result = subprocess.run(
                [
                    "docker",
                    "compose",
                    "-f",
                    str(compose_file),
                    "up",
                    "-d",
                    "--pull",
                    "always",
                ],
                cwd=stack_path,
                capture_output=True,
                text=True,
                timeout=300,
            )

            return {
                "success": True,
                "stack": stack_name,
                "commit": commit,
                "output": result.stdout,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def remove_stack(self, stack_name: str, delete_data: bool = False) -> Dict:
        """Stop and optionally remove a stack."""
        stack_path = self.stacks_dir / stack_name

        if not stack_path.exists():
            return {"success": False, "error": f"Stack not found: {stack_name}"}

        try:
            # Stop and remove containers
            compose_file = stack_path / "docker-compose.yml"
            cmd = ["docker", "compose", "-f", str(compose_file), "down"]
            if delete_data:
                cmd.append("-v")  # Remove volumes

            result = subprocess.run(
                cmd, cwd=stack_path, capture_output=True, text=True, timeout=60
            )

            # Optionally delete stack directory
            if delete_data:
                import shutil

                shutil.rmtree(stack_path)

            return {
                "success": True,
                "stack": stack_name,
                "removed_volumes": delete_data,
                "output": result.stdout,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}
