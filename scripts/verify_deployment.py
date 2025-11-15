#!/usr/bin/env python3
"""
Deployment Verification Script
==============================

Checks pre-deployment requirements and post-deployment health for SystemManager MCP.

Usage:
    # Check deployment prerequisites
    python scripts/verify_deployment.py --check-prereq --target docker
    python scripts/verify_deployment.py --check-prereq --target systemd
    
    # Verify post-deployment health
    python scripts/verify_deployment.py --check-health --host remote.example.com --port 8080
"""

import sys
import subprocess
import json
import os
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

class DeploymentVerifier:
    """Verify deployment prerequisites and health."""
    
    def __init__(self, target: str = "docker"):
        self.target = target
        self.checks_passed = []
        self.checks_failed = []
        self.warnings = []
    
    # ===== PREREQUISITE CHECKS =====
    
    def check_python_version(self) -> Tuple[bool, str]:
        """Check Python 3.11+ is available."""
        try:
            result = subprocess.run(
                ["python3", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            version = result.stdout.strip()
            
            # Parse version
            parts = version.split()[-1].split(".")
            major, minor = int(parts[0]), int(parts[1])
            
            if (major, minor) >= (3, 11):
                return True, f"✓ Python {version}"
            else:
                return False, f"✗ Python {version} (need 3.11+)"
        except Exception as e:
            return False, f"✗ Python check failed: {e}"
    
    def check_docker_installed(self) -> Tuple[bool, str]:
        """Check Docker is installed."""
        try:
            result = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return True, f"✓ {result.stdout.strip()}"
        except FileNotFoundError:
            return False, "✗ Docker not found (install: https://docs.docker.com/get-docker/)"
        except Exception as e:
            return False, f"✗ Docker check failed: {e}"
    
    def check_docker_daemon_running(self) -> Tuple[bool, str]:
        """Check Docker daemon is running."""
        try:
            subprocess.run(
                ["docker", "ps"],
                capture_output=True,
                timeout=5
            )
            return True, "✓ Docker daemon running"
        except Exception:
            return False, "✗ Docker daemon not running (try: sudo systemctl start docker)"
    
    def check_docker_socket_accessible(self) -> Tuple[bool, str]:
        """Check Docker socket is accessible."""
        try:
            result = subprocess.run(
                ["docker", "ps"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return True, "✓ Docker socket accessible"
            else:
                return False, f"✗ Docker socket not accessible: {result.stderr}"
        except Exception as e:
            return False, f"✗ Docker socket check failed: {e}"
    
    def check_git_installed(self) -> Tuple[bool, str]:
        """Check Git is installed."""
        try:
            result = subprocess.run(
                ["git", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return True, f"✓ {result.stdout.strip()}"
        except FileNotFoundError:
            return False, "✗ Git not found (install: https://git-scm.com/)"
        except Exception as e:
            return False, f"✗ Git check failed: {e}"
    
    def check_systemd_available(self) -> Tuple[bool, str]:
        """Check systemd is available (for systemd deployment)."""
        try:
            result = subprocess.run(
                ["systemctl", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return True, f"✓ systemd available"
        except FileNotFoundError:
            return False, "✗ systemd not found (use Docker deployment on non-systemd systems)"
        except Exception as e:
            return False, f"✗ systemd check failed: {e}"
    
    def check_sudo_access(self) -> Tuple[bool, str]:
        """Check sudo access (for systemd deployment)."""
        try:
            result = subprocess.run(
                ["sudo", "-n", "true"],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                return True, "✓ sudo access available"
            else:
                return False, "⚠ sudo requires password (may be needed for systemd)"
        except Exception as e:
            return False, f"✗ sudo check failed: {e}"
    
    def check_disk_space(self, required_gb: int = 2) -> Tuple[bool, str]:
        """Check available disk space."""
        try:
            result = subprocess.run(
                ["df", "/"],
                capture_output=True,
                text=True,
                timeout=5
            )
            lines = result.stdout.strip().split("\n")
            if len(lines) >= 2:
                parts = lines[1].split()
                available_kb = int(parts[3])
                available_gb = available_kb / 1024 / 1024
                
                if available_gb >= required_gb:
                    return True, f"✓ {available_gb:.1f}GB available (need {required_gb}GB)"
                else:
                    return False, f"✗ Only {available_gb:.1f}GB available (need {required_gb}GB)"
        except Exception as e:
            return (True, f"⚠ Could not check disk space: {e}")
        
        return True, "✓ Disk space check passed"
    
    def check_memory(self, required_gb: int = 2) -> Tuple[bool, str]:
        """Check available memory."""
        try:
            result = subprocess.run(
                ["free", "-g"],
                capture_output=True,
                text=True,
                timeout=5
            )
            lines = result.stdout.strip().split("\n")
            if len(lines) >= 2:
                parts = lines[1].split()
                available_gb = int(parts[6])
                
                if available_gb >= required_gb:
                    return True, f"✓ {available_gb}GB available (need {required_gb}GB)"
                else:
                    return False, f"✗ Only {available_gb}GB available (need {required_gb}GB)"
        except Exception as e:
            return (True, f"⚠ Could not check memory: {e}")
        
        return True, "✓ Memory check passed"
    
    def check_repository_cloned(self) -> Tuple[bool, str]:
        """Check if repository is cloned."""
        repo_path = Path(".git")
        if repo_path.exists():
            try:
                result = subprocess.run(
                    ["git", "remote", "-v"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return True, "✓ Repository cloned"
            except Exception as e:
                return False, f"✗ Git check failed: {e}"
        else:
            return False, "✗ Repository not cloned (run: git clone ...)"
    
    def check_requirements_present(self) -> Tuple[bool, str]:
        """Check requirements.txt exists."""
        req_path = Path("requirements.txt")
        if req_path.exists():
            return True, "✓ requirements.txt found"
        else:
            return False, "✗ requirements.txt not found"
    
    # ===== HEALTH CHECKS =====
    
    def check_server_connectivity(self, host: str, port: int) -> Tuple[bool, str]:
        """Check server is reachable."""
        try:
            url = f"http://{host}:{port}/health"
            request = Request(url, method="GET")
            with urlopen(request, timeout=10) as response:
                if response.status == 200:
                    return True, f"✓ Server reachable at {host}:{port}"
                else:
                    return False, f"✗ Unexpected status {response.status}"
        except HTTPError as e:
            return False, f"✗ HTTP error {e.code}"
        except URLError as e:
            return False, f"✗ Connection error: {e.reason}"
        except Exception as e:
            return False, f"✗ Connectivity check failed: {e}"
    
    def check_health_endpoint(self, host: str, port: int) -> Tuple[bool, str]:
        """Check health endpoint response."""
        try:
            url = f"http://{host}:{port}/health"
            request = Request(url, method="GET")
            with urlopen(request, timeout=10) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode())
                    if "status" in data and data["status"] == "healthy":
                        return True, "✓ Server health: healthy"
                    else:
                        return False, f"✗ Unexpected health status: {data.get('status')}"
                else:
                    return False, f"✗ Health endpoint returned {response.status}"
        except Exception as e:
            return False, f"✗ Health check failed: {e}"
    
    # ===== VERIFICATION METHODS =====
    
    def verify_prerequisites(self) -> bool:
        """Verify deployment prerequisites."""
        print(f"\n=== Checking Prerequisites for {self.target.upper()} ===\n")
        
        common_checks = [
            ("Python 3.11+", self.check_python_version),
            ("Git", self.check_git_installed),
            ("Repository Cloned", self.check_repository_cloned),
            ("requirements.txt", self.check_requirements_present),
            ("Disk Space", self.check_disk_space),
            ("Memory", self.check_memory),
        ]
        
        docker_checks = [
            ("Docker Installed", self.check_docker_installed),
            ("Docker Daemon Running", self.check_docker_daemon_running),
            ("Docker Socket Accessible", self.check_docker_socket_accessible),
        ]
        
        systemd_checks = [
            ("systemd Available", self.check_systemd_available),
            ("sudo Access", self.check_sudo_access),
        ]
        
        checks = common_checks
        if self.target == "docker":
            checks.extend(docker_checks)
        elif self.target == "systemd":
            checks.extend(systemd_checks)
        
        for check_name, check_func in checks:
            passed, message = check_func()
            print(f"  {message}")
            
            if passed:
                self.checks_passed.append(check_name)
            else:
                self.checks_failed.append(check_name)
        
        print(f"\n  Passed: {len(self.checks_passed)}/{len(checks)}")
        
        return len(self.checks_failed) == 0
    
    def verify_health(self, host: str, port: int) -> bool:
        """Verify server health post-deployment."""
        print(f"\n=== Checking Server Health ===\n")
        print(f"  Target: {host}:{port}\n")
        
        checks = [
            ("Connectivity", lambda: self.check_server_connectivity(host, port)),
            ("Health Endpoint", lambda: self.check_health_endpoint(host, port)),
        ]
        
        for check_name, check_func in checks:
            passed, message = check_func()
            print(f"  {message}")
            
            if passed:
                self.checks_passed.append(check_name)
            else:
                self.checks_failed.append(check_name)
        
        print(f"\n  Passed: {len(self.checks_passed)}/{len(checks)}")
        
        return len(self.checks_failed) == 0
    
    def generate_report(self) -> Dict:
        """Generate verification report."""
        return {
            "timestamp": str(os.popen("date -u +%Y-%m-%dT%H:%M:%SZ").read().strip()),
            "checks_passed": self.checks_passed,
            "checks_failed": self.checks_failed,
            "total_checks": len(self.checks_passed) + len(self.checks_failed),
            "success": len(self.checks_failed) == 0
        }


def main():
    parser = argparse.ArgumentParser(description="Verify SystemManager MCP deployment")
    parser.add_argument("--check-prereq", action="store_true", help="Check deployment prerequisites")
    parser.add_argument("--check-health", action="store_true", help="Check server health")
    parser.add_argument("--target", choices=["docker", "systemd"], default="docker", help="Deployment target")
    parser.add_argument("--host", default="localhost", help="Server hostname (for health checks)")
    parser.add_argument("--port", type=int, default=8080, help="Server port (for health checks)")
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    
    args = parser.parse_args()
    
    verifier = DeploymentVerifier(target=args.target)
    success = True
    
    if args.check_prereq:
        success = verifier.verify_prerequisites()
    elif args.check_health:
        success = verifier.verify_health(args.host, args.port)
    else:
        print("Use --check-prereq or --check-health")
        parser.print_help()
        return 1
    
    report = verifier.generate_report()
    
    if args.json:
        print(json.dumps(report, indent=2))
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
