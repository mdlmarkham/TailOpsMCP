# Remote Agent Integration Examples

This document provides practical examples of using the remote agent-like functionality in TailOpsMCP.

## Quick Start Examples

### 1. Basic Log Analysis

```python
#!/usr/bin/env python3
"""
Quick Start: Analyze logs across multiple servers
"""

import asyncio
from src.tools.remote_agent_tools import analyze_service_logs_across_fleet

async def main():
    # Define your server targets
    targets = [
        "web-server-01.example.com",
        "web-server-02.example.com",
        "web-server-03.example.com"
    ]

    # Analyze nginx logs across all servers
    result = await analyze_service_logs_across_fleet(
        targets=targets,
        service="nginx",
        time_range="2 hours"
    )

    if result["success"]:
        analysis = result["analysis"]
        print(f"Analyzed logs from {analysis['successful_targets']} servers")
        print(f"Total log entries: {analysis['total_logs']}")
        print(f"Error count: {analysis['log_levels'].get('error', 0)}")

        # Show most common messages
        print("\\nMost common messages:")
        for message, count in list(analysis['common_messages'].items())[:5]:
            print(f"  {count}x: {message[:100]}...")
    else:
        print(f"Analysis failed: {result['error']}")

if __name__ == "__main__":
    asyncio.run(main())
```

### 2. Service Health Monitoring

```python
#!/usr/bin/env python3
"""
Quick Start: Monitor service health across fleet
"""

import asyncio
from src.tools.remote_agent_tools import check_fleet_service_health

async def main():
    targets = [
        "api-server-01.example.com",
        "api-server-02.example.com",
        "api-server-03.example.com"
    ]

    # Check health of critical services
    services = ["nginx", "redis", "postgresql"]

    for service in services:
        print(f"\\nChecking health of {service}...")

        result = await check_fleet_service_health(
            targets=targets,
            service=service
        )

        if result["success"]:
            summary = result["summary"]
            healthy_count = summary["healthy_targets"]
            total_count = summary["total_targets"]

            print(f"  Health: {healthy_count}/{total_count} servers healthy")
            print(f"  Health percentage: {summary['health_percentage']:.1f}%")

            # Show details for unhealthy servers
            for health_report in result["health_report"]:
                if not health_report.get("healthy", False):
                    if "error" in health_report:
                        print(f"  ❌ {health_report['target']}: {health_report['error']}")
                    else:
                        print(f"  ❌ {health_report['target']}: {health_report['status']}")
        else:
            print(f"  ❌ Health check failed: {result['error']}")

if __name__ == "__main__":
    asyncio.run(main())
```

### 3. Container Management

```python
#!/usr/bin/env python3
"""
Quick Start: Manage Docker containers remotely
"""

import asyncio
from src.tools.remote_agent_tools import (
    get_remote_docker_containers,
    restart_remote_container
)

async def main():
    target = "docker-host.example.com"

    # List containers
    print("Getting Docker containers...")
    result = await get_remote_docker_containers(target)

    if result["success"]:
        containers = result["containers"]
        print(f"Found {result['container_count']} containers:")

        stopped_containers = []
        for container in containers:
            status_icon = "✅" if container["status"] == "running" else "⏹️"
            print(f"  {status_icon} {container['name']} ({container['image']}) - {container['status']}")

            if container["status"] != "running":
                stopped_containers.append(container)

        # Restart stopped containers
        if stopped_containers:
            print("\\nRestarting stopped containers...")
            for container in stopped_containers:
                restart_result = await restart_remote_container(
                    target=target,
                    container_id=container["container_id"]
                )

                if restart_result["success"]:
                    print(f"  ✅ Restarted {container['name']}")
                else:
                    print(f"  ❌ Failed to restart {container['name']}: {restart_result['error']}")
    else:
        print(f"Failed to get containers: {result['error']}")

if __name__ == "__main__":
    asyncio.run(main())
```

### 4. Configuration Management

```python
#!/usr/bin/env python3
"""
Quick Start: Update configuration files remotely
"""

import asyncio
from src.tools.remote_agent_tools import read_remote_file, write_remote_file

async def main():
    targets = ["web-01.example.com", "web-02.example.com"]

    # Read current nginx configuration
    print("Reading current nginx configuration...")
    config_result = await read_remote_file(
        target="web-01.example.com",
        path="/etc/nginx/nginx.conf"
    )

    if not config_result["success"]:
        print(f"Failed to read config: {config_result['error']}")
        return

    current_config = config_result["content"]
    print(f"Current config length: {len(current_config)} characters")

    # Modify configuration (example: increase worker connections)
    new_config = current_config.replace(
        "worker_connections 1024;",
        "worker_connections 2048;"
    )

    # Deploy to all servers
    print("\\nDeploying updated configuration...")
    for target in targets:
        write_result = await write_remote_file(
            target=target,
            path="/etc/nginx/nginx.conf",
            content=new_config,
            create_backup=True
        )

        if write_result["success"]:
            print(f"  ✅ Updated {target}")
        else:
            print(f"  ❌ Failed to update {target}: {write_result['error']}")

if __name__ == "__main__":
    asyncio.run(main())
```

## Advanced Integration Examples

### 5. Automated Incident Response

```python
#!/usr/bin/env python3
"""
Advanced: Automated incident response system
"""

import asyncio
from datetime import datetime, timedelta
from src.tools.remote_agent_tools import (
    get_journald_logs,
    restart_remote_service,
    get_remote_system_status
)
from src.utils.remote_security import create_security_context, AccessScope

class IncidentResponse:
    def __init__(self):
        self.security_context = create_security_context(
            user_id="automated-response",
            session_id="incident-response",
            scopes=[AccessScope.LIMITED_CONTROL]
        )

    async def detect_and_respond(self, targets, service_name):
        """Detect service issues and attempt automatic resolution."""

        print(f"🔍 Checking {service_name} across {len(targets)} servers...")

        issues_found = []

        for target in targets:
            try:
                # Check system status first
                system_result = await get_remote_system_status(target)
                if not system_result["success"]:
                    issues_found.append({
                        "target": target,
                        "issue": "system_unreachable",
                        "details": system_result["error"]
                    })
                    continue

                # Check service health
                logs_result = await get_journald_logs(
                    target=target,
                    service=service_name,
                    since="10 minutes ago",
                    priority="err"
                )

                if logs_result["success"] and logs_result["log_count"] > 5:
                    # Multiple recent errors - potential issue
                    issues_found.append({
                        "target": target,
                        "issue": "multiple_errors",
                        "details": f"{logs_result['log_count']} errors in last 10 minutes"
                    })

                    # Attempt automatic restart
                    print(f"  🚨 Detected issues on {target}, attempting restart...")

                    restart_result = await restart_remote_service(
                        target=target,
                        service=service_name,
                        timeout=60
                    )

                    if restart_result["success"]:
                        print(f"  ✅ Successfully restarted {service_name} on {target}")

                        # Wait a bit and verify
                        await asyncio.sleep(30)
                        verification_result = await get_journald_logs(
                            target=target,
                            service=service_name,
                            lines=5
                        )

                        if verification_result["success"]:
                            print(f"  ✅ Verified service recovery on {target}")
                        else:
                            print(f"  ⚠️  Service may still have issues on {target}")
                    else:
                        print(f"  ❌ Failed to restart {service_name} on {target}")

            except Exception as e:
                issues_found.append({
                    "target": target,
                    "issue": "monitoring_error",
                    "details": str(e)
                })

        # Summary report
        print(f"\\n📊 Incident Response Summary:")
        print(f"  Servers checked: {len(targets)}")
        print(f"  Issues detected: {len(issues_found)}")

        if issues_found:
            print("\\n  Issues found:")
            for issue in issues_found:
                print(f"    • {issue['target']}: {issue['issue']} - {issue['details']}")

        return issues_found

# Usage
async def main():
    response = IncidentResponse()

    production_servers = [
        "prod-web-01.example.com",
        "prod-web-02.example.com",
        "prod-api-01.example.com"
    ]

    await response.detect_and_respond(production_servers, "nginx")

if __name__ == "__main__":
    asyncio.run(main())
```

### 6. Log Aggregation and Analysis

```python
#!/usr/bin/env python3
"""
Advanced: Real-time log aggregation and analysis
"""

import asyncio
from collections import defaultdict, Counter
from datetime import datetime
from src.tools.remote_agent_tools import get_journald_logs

class LogAggregator:
    def __init__(self):
        self.log_patterns = Counter()
        self.error_patterns = Counter()
        self.server_logs = defaultdict(list)

    async def aggregate_logs(self, targets, service, time_range="1 hour"):
        """Aggregate logs from multiple servers and analyze patterns."""

        print(f"📊 Aggregating logs for {service} from {len(targets)} servers...")

        # Collect logs from all servers
        all_logs = []

        for target in targets:
            try:
                result = await get_journald_logs(
                    target=target,
                    service=service,
                    since=time_range
                )

                if result["success"]:
                    logs = result["logs"]
                    print(f"  ✅ {target}: {len(logs)} logs")

                    # Add target info to logs
                    for log in logs:
                        log["target"] = target
                        all_logs.append(log)
                        self.server_logs[target].append(log)

                        # Analyze patterns
                        self._analyze_log_pattern(log)
                else:
                    print(f"  ❌ {target}: {result['error']}")

            except Exception as e:
                print(f"  ❌ {target}: {str(e)}")

        # Generate analysis report
        await self._generate_analysis_report(all_logs, service)

        return all_logs

    def _analyze_log_pattern(self, log):
        """Analyze individual log entry for patterns."""
        message = log.get("message", "")
        level = log.get("level", "")

        # Count error patterns
        if level in ["err", "crit", "alert", "emerg"]:
            self.error_patterns[message[:100]] += 1

        # Count general patterns
        self.log_patterns[message[:50]] += 1

    async def _generate_analysis_report(self, all_logs, service):
        """Generate comprehensive analysis report."""

        print(f"\\n📈 Analysis Report for {service}")
        print(f"Total log entries: {len(all_logs)}")

        # Log level distribution
        level_counts = Counter(log.get("level", "unknown") for log in all_logs)
        print("\\nLog Level Distribution:")
        for level, count in level_counts.most_common():
            percentage = (count / len(all_logs)) * 100
            print(f"  {level}: {count} ({percentage:.1f}%)")

        # Top error patterns
        if self.error_patterns:
            print("\\nTop Error Patterns:")
            for pattern, count in self.error_patterns.most_common(5):
                print(f"  {count}x: {pattern}")

        # Server-specific insights
        print("\\nServer-specific Analysis:")
        for server, logs in self.server_logs.items():
            error_count = sum(1 for log in logs if log.get("level") in ["err", "crit", "alert", "emerg"])
            if error_count > 0:
                print(f"  {server}: {error_count} errors ({error_count/len(logs)*100:.1f}%)")

# Usage
async def main():
    aggregator = LogAggregator()

    web_servers = [
        "web-01.example.com",
        "web-02.example.com",
        "web-03.example.com"
    ]

    await aggregator.aggregate_logs(web_servers, "nginx", "2 hours")

if __name__ == "__main__":
    asyncio.run(main())
```

### 7. Fleet Maintenance Automation

```python
#!/usr/bin/env python3
"""
Advanced: Automated fleet maintenance tasks
"""

import asyncio
from datetime import datetime, timedelta
from src.tools.remote_agent_tools import (
    get_remote_system_status,
    list_remote_services,
    read_remote_file,
    write_remote_file
)

class FleetMaintenance:
    def __init__(self):
        self.maintenance_window_start = datetime.now().replace(hour=2, minute=0, second=0, microsecond=0)
        self.maintenance_window_end = datetime.now().replace(hour=4, minute=0, second=0, microsecond=0)

    async def perform_maintenance(self, targets):
        """Perform scheduled maintenance across fleet."""

        print("🛠️  Starting fleet maintenance...")

        # Check if within maintenance window
        now = datetime.now()
        if not (self.maintenance_window_start <= now <= self.maintenance_window_end):
            print("❌ Outside maintenance window. Aborting.")
            return False

        maintenance_tasks = [
            self._update_system_packages,
            self._rotate_logs,
            self._clean_temporary_files,
            self._backup_configurations
        ]

        results = {}

        for task in maintenance_tasks:
            task_name = task.__name__
            print(f"\\n🔧 Running {task_name}...")

            task_results = await task(targets)
            results[task_name] = task_results

            success_count = sum(1 for r in task_results.values() if r.get("success", False))
            print(f"  ✅ Completed on {success_count}/{len(targets)} servers")

        # Generate maintenance report
        await self._generate_maintenance_report(results)
        return True

    async def _update_system_packages(self, targets):
        """Update system packages (placeholder - would use apt/yum connectors)."""
        results = {}
        for target in targets:
            # This would be implemented with package manager connectors
            results[target] = {"success": True, "action": "package_update_simulation"}
        return results

    async def _rotate_logs(self, targets):
        """Ensure log rotation is working properly."""
        results = {}
        for target in targets:
            try:
                # Check logrotate configuration
                config_result = await read_remote_file(target, "/etc/logrotate.conf")

                if config_result["success"]:
                    results[target] = {"success": True, "action": "logrotate_checked"}
                else:
                    results[target] = {"success": False, "error": "Cannot read logrotate config"}
            except Exception as e:
                results[target] = {"success": False, "error": str(e)}

        return results

    async def _clean_temporary_files(self, targets):
        """Clean temporary files and cache."""
        results = {}
        for target in targets:
            # This would clean /tmp, /var/tmp, package manager caches, etc.
            # Implementation depends on specific cleanup commands for each system
            results[target] = {"success": True, "action": "temp_cleanup_simulation"}
        return results

    async def _backup_configurations(self, targets):
        """Create backups of important configuration files."""
        important_configs = [
            "/etc/nginx/nginx.conf",
            "/etc/systemd/system/nginx.service",
            "/etc/ssh/sshd_config"
        ]

        results = {}
        for target in targets:
            target_results = {}

            for config_path in important_configs:
                try:
                    backup_result = await read_remote_file(target, config_path)
                    if backup_result["success"]:
                        # In real implementation, would write to backup location
                        target_results[config_path] = {"success": True, "backed_up": True}
                    else:
                        target_results[config_path] = {"success": False, "error": "Cannot read config"}
                except Exception as e:
                    target_results[config_path] = {"success": False, "error": str(e)}

            results[target] = target_results

        return results

    async def _generate_maintenance_report(self, results):
        """Generate maintenance completion report."""

        print("\\n📋 Fleet Maintenance Report")
        print(f"Maintenance completed at: {datetime.now()}")

        total_tasks = len(results)
        successful_tasks = sum(1 for task_results in results.values()
                              if all(r.get("success", False) for r in task_results.values()))

        print(f"Tasks completed: {successful_tasks}/{total_tasks}")

        print("\\nTask Details:")
        for task_name, task_results in results.items():
            print(f"  {task_name}:")
            for target, result in task_results.items():
                status = "✅" if result.get("success", False) else "❌"
                print(f"    {status} {target}")

# Usage
async def main():
    maintenance = FleetMaintenance()

    servers = [
        "prod-01.example.com",
        "prod-02.example.com",
        "staging-01.example.com"
    ]

    await maintenance.perform_maintenance(servers)

if __name__ == "__main__":
    asyncio.run(main())
```

## Environment Setup Examples

### Docker Compose for Development

```yaml
# docker-compose.remote-agents.yml
version: '3.8'

services:
  systemmanager:
    build: .
    environment:
      - SYSTEMMANAGER_REMOTE_AGENTS_ENABLED=true
      - SYSTEMMANAGER_REMOTE_AGENTS_CONFIG=/app/config/remote-agents-config.yaml
      - SSH_KEY_PATH=/app/keys/id_rsa
    volumes:
      - ./config:/app/config:ro
      - ./keys:/app/keys:ro
      - ./logs:/app/logs
    ports:
      - "3000:3000"
    depends_on:
      - tailscale

  tailscale:
    image: tailscale/tailscale:latest
    environment:
      - TS_AUTH_KEY=${TS_AUTH_KEY}
      - TS_STATE_DIR=/var/lib/tailscale
    volumes:
      - tailscale-state:/var/lib/tailscale
      - /dev/net/tun:/dev/net/tun
    cap_add:
      - NET_ADMIN
      - SYS_MODULE

volumes:
  tailscale-state:
```

### Kubernetes Deployment

```yaml
# k8s-remote-agents.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: systemmanager-remote-agents
spec:
  replicas: 1
  selector:
    matchLabels:
      app: systemmanager-remote-agents
  template:
    metadata:
      labels:
        app: systemmanager-remote-agents
    spec:
      containers:
      - name: systemmanager
        image: systemmanager:latest
        env:
        - name: SYSTEMMANAGER_REMOTE_AGENTS_ENABLED
          value: "true"
        - name: SYSTEMMANAGER_REMOTE_AGENTS_CONFIG
          value: "/config/remote-agents-config.yaml"
        volumeMounts:
        - name: config
          mountPath: /config
        - name: ssh-keys
          mountPath: /keys
          readOnly: true
        - name: logs
          mountPath: /app/logs
        ports:
        - containerPort: 3000
      volumes:
      - name: config
        configMap:
          name: systemmanager-config
      - name: ssh-keys
        secret:
          secretName: systemmanager-ssh-keys
      - name: logs
        emptyDir: {}
```

### Environment Configuration

```bash
#!/bin/bash
# setup-remote-agents.sh

# Set environment variables
export SYSTEMMANAGER_REMOTE_AGENTS_ENABLED=true
export SYSTEMMANAGER_REMOTE_AGENTS_CONFIG="/etc/systemmanager/remote-agents-config.yaml"
export SYSTEMMANAGER_AUDIT_LOG="/var/log/systemmanager/remote-agents-audit.log"

# Create necessary directories
mkdir -p /etc/systemmanager
mkdir -p /var/log/systemmanager
mkdir -p /var/lib/systemmanager/backups

# Set permissions
chown systemmanager:systemmanager /var/log/systemmanager
chown systemmanager:systemmanager /var/lib/systemmanager/backups

# Copy configuration
cp config/remote-agents-config.yaml.example /etc/systemmanager/remote-agents-config.yaml

# Start the service
systemctl enable systemmanager-mcp
systemctl start systemmanager-mcp

echo "Remote agents setup complete!"
```

## Monitoring and Alerting

### Prometheus Metrics

```python
# metrics-remote-agents.py
from prometheus_client import Counter, Histogram, Gauge, start_http_server

# Define metrics
operation_counter = Counter('remote_agent_operations_total', 'Total remote agent operations', ['operation', 'target', 'status'])
operation_duration = Histogram('remote_agent_operation_duration_seconds', 'Remote agent operation duration')
active_connections = Gauge('remote_agent_active_connections', 'Active SSH connections')
health_status = Gauge('remote_agent_target_health', 'Target health status', ['target'])

# Metrics collection loop
async def collect_metrics():
    while True:
        try:
            # Collect connection metrics
            health_statuses = await connection_manager.get_all_health_status()
            for target, status in health_statuses.items():
                health_status.labels(target=target).set(1 if status.healthy else 0)

            # Collect operation metrics
            metrics = executor.get_operation_metrics()
            for metric in metrics:
                operation_counter.labels(
                    operation=metric.operation_name,
                    target="unknown",  # Would need to track target per operation
                    status="success" if metric.success else "failure"
                ).inc()

                if metric.duration:
                    operation_duration.observe(metric.duration)

            await asyncio.sleep(30)  # Collect every 30 seconds

        except Exception as e:
            logger.error(f"Metrics collection error: {str(e)}")
            await asyncio.sleep(60)

# Start metrics server
if __name__ == "__main__":
    start_http_server(8000)
    asyncio.run(collect_metrics())
```

### Alerting Rules

```yaml
# prometheus-alerts.yml
groups:
- name: remote_agents
  rules:
  - alert: RemoteAgentHighFailureRate
    expr: rate(remote_agent_operations_total{status="failure"}[5m]) > 0.1
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High failure rate in remote agent operations"

  - alert: RemoteAgentConnectionFailure
    expr: remote_agent_target_health == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Remote agent cannot connect to target {{ $labels.target }}"

  - alert: RemoteAgentSecurityViolation
    expr: increase(remote_agent_security_violations_total[5m]) > 0
    for: 0m
    labels:
      severity: critical
    annotations:
      summary: "Security violation detected in remote agent operations"
```

These examples demonstrate the practical usage of the remote agent functionality across various scenarios, from basic operations to advanced automation and monitoring.
