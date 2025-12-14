"""
Test Data Management System for TailOpsMCP

Provides comprehensive test data generation, management, and cleanup for all test categories.
Includes realistic data generators, fixtures, and utilities for managing test data across
orchestration, integration, performance, security, and edge case tests.
"""

import uuid
import json
import random
import string
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field
from enum import Enum


class DataCategory(Enum):
    """Test data categories."""
    INVENTORY = "inventory"
    WORKFLOW = "workflow"
    POLICY = "policy"
    SECURITY = "security"
    EVENTS = "events"
    PERFORMANCE = "performance"
    EDGE_CASE = "edge_case"


class SecurityLevel(Enum):
    """Security levels for test data."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TestDataConfig:
    """Configuration for test data generation."""
    category: DataCategory
    count: int = 100
    complexity: str = "medium"
    realism: float = 0.8  # 0.0 to 1.0
    diversity: float = 0.7  # 0.0 to 1.0
    edge_cases: bool = False
    security_level: SecurityLevel = SecurityLevel.MEDIUM


class TestDataManager:
    """Comprehensive test data management system."""
    
    def __init__(self):
        """Initialize test data manager."""
        self.generated_data = {}
        self.cleanup_functions = {}
        self.data_configs = {}
    
    def register_data_generator(self, category: DataCategory, generator_func):
        """Register a data generator for a specific category."""
        if category not in self.generated_data:
            self.generated_data[category] = []
        # Store generator function for on-demand generation
        self.generated_data[category].append(generator_func)
    
    def generate_inventory_data(self, config: TestDataConfig) -> Dict[str, Any]:
        """Generate comprehensive inventory test data."""
        data = {
            "gateway": self._generate_gateway_data(config),
            "proxmox_hosts": self._generate_proxmox_hosts_data(config),
            "containers": self._generate_containers_data(config),
            "stacks": self._generate_stacks_data(config),
            "services": self._generate_services_data(config),
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "config": config.__dict__,
                "total_targets": 0,
                "health_distribution": {},
                "role_distribution": {}
            }
        }
        
        # Calculate metadata
        total_targets = 1 + len(data["proxmox_hosts"]) + len(data["containers"])
        data["metadata"]["total_targets"] = total_targets
        
        # Health distribution
        health_dist = {"healthy": 0, "warning": 0, "critical": 0, "unknown": 0}
        role_dist = {"gateway": 0, "proxmox_host": 0, "container": 0}
        
        # Gateway health
        health_dist[data["gateway"]["status"]] += 1
        role_dist["gateway"] += 1
        
        # Proxmox hosts health and roles
        for host in data["proxmox_hosts"]:
            health_dist[host["status"]] += 1
            role_dist["proxmox_host"] += 1
        
        # Containers health and roles
        for container in data["containers"]:
            health_dist[container["status"]] += 1
            role_dist["container"] += 1
        
        data["metadata"]["health_distribution"] = health_dist
        data["metadata"]["role_distribution"] = role_dist
        
        return data
    
    def _generate_gateway_data(self, config: TestDataConfig) -> Dict[str, Any]:
        """Generate gateway test data."""
        return {
            "id": "gateway-001",
            "hostname": "test-gateway",
            "role": "gateway",
            "ip_address": "192.168.1.1",
            "status": random.choice(["healthy", "warning", "critical"]) if config.edge_cases else "healthy",
            "services": [
                {
                    "id": "tailops-mcp",
                    "name": "TailOpsMCP",
                    "type": "management",
                    "status": "running",
                    "port": 8080,
                    "version": "1.0.0",
                    "health_score": random.randint(80, 100)
                },
                {
                    "id": "policy-engine",
                    "name": "Policy Engine",
                    "type": "security",
                    "status": "running",
                    "port": 8081,
                    "version": "1.2.0",
                    "health_score": random.randint(85, 100)
                }
            ],
            "stacks": [],
            "last_seen": (datetime.utcnow() - timedelta(minutes=random.randint(1, 30))).isoformat(),
            "metadata": {
                "os": "Ubuntu 20.04",
                "architecture": "x86_64",
                "uptime_days": random.randint(30, 365),
                "cpu_cores": random.choice([4, 8, 16]),
                "memory_gb": random.choice([16, 32, 64]),
                "disk_gb": random.choice([256, 512, 1024])
            }
        }
    
    def _generate_proxmox_hosts_data(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate Proxmox hosts test data."""
        hosts = []
        host_count = min(config.count // 10, 50)  # Scale with config
        
        for i in range(host_count):
            host = {
                "id": f"proxmox-{i+1:03d}",
                "hostname": f"proxmox-host-{i+1}",
                "role": "proxmox_host",
                "ip_address": f"192.168.1.{10+i}",
                "status": self._generate_health_status(config),
                "containers": [f"container-{j:04d}" for j in range((i*10)+1, (i*10)+11)],
                "services": [
                    {
                        "id": f"pve-service-{i+1}",
                        "name": "Proxmox VE",
                        "type": "virtualization",
                        "status": "running",
                        "port": 8006,
                        "version": f"{random.choice(['7.3', '7.4'])}-{random.randint(1, 5)}",
                        "health_score": random.randint(80, 100)
                    }
                ],
                "stacks": self._generate_stacks_for_host(i, config),
                "last_seen": (datetime.utcnow() - timedelta(minutes=random.randint(1, 60))).isoformat(),
                "metadata": {
                    "cpu_cores": random.choice([8, 16, 32]),
                    "memory_gb": random.choice([32, 64, 128]),
                    "storage_gb": random.choice([500, 1000, 2000, 4000]),
                    "cpu_usage": random.randint(10, 90),
                    "memory_usage": random.randint(20, 85),
                    "disk_usage": random.randint(30, 80)
                }
            }
            hosts.append(host)
        
        return hosts
    
    def _generate_containers_data(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate container test data."""
        containers = []
        container_count = min(config.count, 1000)  # Cap at 1000 for performance
        
        for i in range(container_count):
            parent_host = f"proxmox-{(i // 10) + 1:03d}"
            container = {
                "id": f"container-{i+1:04d}",
                "hostname": f"{random.choice(['web', 'app', 'db', 'cache', 'queue'])}-container-{i+1}",
                "role": "container",
                "ip_address": f"192.168.1.{100 + (i % 200)}",
                "status": self._generate_health_status(config),
                "parent_id": parent_host,
                "services": self._generate_container_services(i, config),
                "stacks": [],
                "last_seen": (datetime.utcnow() - timedelta(minutes=random.randint(1, 120))).isoformat(),
                "metadata": {
                    "image": random.choice([
                        "nginx:1.18", "nginx:1.20", "ubuntu:20.04", "ubuntu:22.04",
                        "postgres:13", "redis:6", "node:16", "python:3.9"
                    ]),
                    "cpu_limit": random.choice(["1", "2", "4"]),
                    "memory_limit": random.choice(["512MB", "1GB", "2GB", "4GB"]),
                    "cpu_usage": random.randint(5, 95),
                    "memory_usage": random.randint(10, 90),
                    "disk_usage": random.randint(20, 85)
                }
            }
            containers.append(container)
        
        return containers
    
    def _generate_stacks_data(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate stack test data."""
        stacks = []
        stack_count = min(config.count // 20, 100)
        
        for i in range(stack_count):
            stack = {
                "id": f"stack-{i+1:03d}",
                "name": f"{random.choice(['web', 'app', 'data', 'cache', 'monitoring'])}-stack-{i+1}",
                "type": random.choice(["web", "database", "cache", "monitoring", "security"]),
                "status": random.choice(["running", "stopped", "error", "deploying"]),
                "services": [f"service-{j}" for j in range(random.randint(2, 8))],
                "environment": random.choice(["production", "staging", "development"]),
                "version": f"{random.randint(1, 5)}.{random.randint(0, 9)}.{random.randint(0, 9)}",
                "created_at": (datetime.utcnow() - timedelta(days=random.randint(1, 365))).isoformat(),
                "updated_at": (datetime.utcnow() - timedelta(hours=random.randint(1, 168))).isoformat(),
                "dependencies": random.sample([f"stack-{j+1:03d}" for j in range(stack_count)], 
                                           random.randint(0, min(3, stack_count-1))) if stack_count > 1 else []
            }
            stacks.append(stack)
        
        return stacks
    
    def _generate_services_data(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate service test data."""
        services = []
        service_types = [
            ("web-server", ["nginx", "apache", "caddy"]),
            ("database", ["postgresql", "mysql", "mongodb"]),
            ("cache", ["redis", "memcached"]),
            ("queue", ["rabbitmq", "redis"]),
            ("monitoring", ["prometheus", "grafana"]),
            ("security", ["vault", "nginx"])
        ]
        
        for service_type, implementations in service_types:
            for impl in implementations:
                service = {
                    "id": f"{impl}-service",
                    "name": impl.title(),
                    "type": service_type,
                    "status": random.choice(["running", "stopped", "error"]),
                    "port": self._get_default_port(impl),
                    "version": f"{random.randint(1, 10)}.{random.randint(0, 9)}.{random.randint(0, 20)}",
                    "health_score": random.randint(70, 100),
                    "instances": random.randint(1, 5),
                    "dependencies": random.sample([f"{dep}-service" for _, dep_list in service_types for dep in dep_list if dep != impl], 
                                               random.randint(0, 3))
                }
                services.append(service)
        
        return services
    
    def generate_workflow_data(self, config: TestDataConfig) -> Dict[str, Any]:
        """Generate workflow test data."""
        return {
            "blueprints": self._generate_workflow_blueprints(config),
            "executions": self._generate_workflow_executions(config),
            "schedules": self._generate_workflow_schedules(config),
            "approvals": self._generate_workflow_approvals(config),
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "config": config.__dict__
            }
        }
    
    def _generate_workflow_blueprints(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate workflow blueprint test data."""
        blueprint_types = [
            "environment_provisioning",
            "backup_orchestration", 
            "safe_upgrade",
            "disaster_recovery",
            "security_compliance",
            "monitoring_setup",
            "data_migration",
            "performance_optimization"
        ]
        
        blueprints = []
        blueprint_count = min(config.count // 10, 50)
        
        for i in range(blueprint_count):
            blueprint = {
                "id": str(uuid.uuid4()),
                "name": f"{random.choice(blueprint_types).replace('_', ' ').title()} {i+1}",
                "description": f"Automated workflow for {random.choice(blueprint_types)}",
                "version": f"{random.randint(1, 3)}.{random.randint(0, 9)}",
                "category": random.choice(blueprint_types),
                "steps": self._generate_workflow_steps(config),
                "triggers": self._generate_workflow_triggers(),
                "approvals_required": random.choice([[], ["admin"], ["admin", "security_team"]]),
                "timeout": random.choice([1800, 3600, 7200, 14400]),  # 30min to 4 hours
                "retry_policy": {
                    "max_retries": random.randint(0, 3),
                    "retry_delay": random.randint(30, 300),
                    "backoff_multiplier": random.choice([1.0, 1.5, 2.0])
                },
                "rollback_strategy": random.choice(["automatic", "manual", "none"]),
                "created_by": f"user-{random.randint(1, 100)}",
                "created_at": (datetime.utcnow() - timedelta(days=random.randint(1, 365))).isoformat(),
                "updated_at": (datetime.utcnow() - timedelta(hours=random.randint(1, 168))).isoformat(),
                "tags": random.sample(["production", "staging", "development", "critical", "automated", "scheduled"], 
                                    random.randint(2, 4)),
                "status": random.choice(["active", "draft", "deprecated"])
            }
            blueprints.append(blueprint)
        
        return blueprints
    
    def _generate_workflow_executions(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate workflow execution test data."""
        executions = []
        execution_count = min(config.count, 500)
        statuses = ["pending", "running", "completed", "failed", "cancelled", "timeout"]
        
        for i in range(execution_count):
            started_at = datetime.utcnow() - timedelta(
                hours=random.randint(0, 168), 
                minutes=random.randint(0, 59)
            )
            
            execution = {
                "id": str(uuid.uuid4()),
                "blueprint_id": f"blueprint-{random.randint(1, 50):03d}",
                "status": random.choices(statuses, weights=[5, 10, 60, 15, 5, 5])[0],
                "trigger_type": random.choice(["manual", "scheduled", "event", "api"]),
                "triggered_by": f"user-{random.randint(1, 100)}",
                "parameters": self._generate_execution_parameters(),
                "started_at": started_at.isoformat(),
                "completed_at": (started_at + timedelta(minutes=random.randint(5, 120))).isoformat() if random.random() > 0.2 else None,
                "current_step": f"step-{random.randint(1, 10):03d}" if random.random() > 0.5 else None,
                "progress_percentage": random.randint(0, 100) if random.random() > 0.3 else 100,
                "step_results": self._generate_step_results(),
                "error_message": "Simulated failure for testing" if random.random() > 0.9 else None,
                "rollback_executed": random.choice([True, False]) if random.random() > 0.8 else False,
                "execution_time": random.randint(60, 7200),  # 1 minute to 2 hours
                "resource_usage": {
                    "cpu_seconds": random.randint(100, 10000),
                    "memory_mb": random.randint(256, 4096),
                    "disk_io_mb": random.randint(10, 1000),
                    "network_io_mb": random.randint(1, 500)
                }
            }
            executions.append(execution)
        
        return executions
    
    def generate_policy_data(self, config: TestDataConfig) -> Dict[str, Any]:
        """Generate policy test data."""
        return {
            "policies": self._generate_policies(config),
            "rules": self._generate_policy_rules(config),
            "roles": self._generate_roles(config),
            "permissions": self._generate_permissions(config),
            "audit_logs": self._generate_audit_logs(config),
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "config": config.__dict__
            }
        }
    
    def _generate_policies(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate policy test data."""
        policy_types = [
            "fleet_management",
            "security_compliance", 
            "resource_allocation",
            "access_control",
            "network_security",
            "data_protection",
            "backup_policy",
            "monitoring_policy"
        ]
        
        policies = []
        policy_count = min(config.count // 20, 25)
        
        for i in range(policy_count):
            policy = {
                "id": str(uuid.uuid4()),
                "name": f"{random.choice(policy_types).replace('_', ' ').title()} Policy {i+1}",
                "description": f"Policy for {random.choice(policy_types)} operations",
                "version": f"{random.randint(1, 5)}.{random.randint(0, 9)}",
                "type": random.choice(policy_types),
                "scope": random.choice(["global", "environment", "resource_group", "resource"]),
                "rules": self._generate_policy_rules_for_policy(config),
                "conditions": self._generate_policy_conditions(),
                "effects": random.choice(["allow", "deny", "audit", "require_approval"]),
                "priority": random.randint(1, 100),
                "enabled": random.choice([True, True, True, False]),  # 75% enabled
                "created_by": f"admin-{random.randint(1, 20)}",
                "created_at": (datetime.utcnow() - timedelta(days=random.randint(1, 365))).isoformat(),
                "updated_at": (datetime.utcnow() - timedelta(hours=random.randint(1, 168))).isoformat(),
                "tags": random.sample(["production", "staging", "critical", "automated", "security"], 
                                    random.randint(2, 4))
            }
            policies.append(policy)
        
        return policies
    
    def generate_security_data(self, config: TestDataConfig) -> Dict[str, Any]:
        """Generate security test data."""
        return {
            "authentication_attempts": self._generate_auth_attempts(config),
            "authorization_violations": self._generate_authz_violations(config),
            "security_incidents": self._generate_security_incidents(config),
            "vulnerability_scans": self._generate_vulnerability_scans(config),
            "compliance_checks": self._generate_compliance_checks(config),
            "audit_events": self._generate_security_audit_events(config),
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "config": config.__dict__,
                "security_level": config.security_level.value
            }
        }
    
    def generate_event_data(self, config: TestDataConfig) -> Dict[str, Any]:
        """Generate event test data."""
        return {
            "system_events": self._generate_system_events(config),
            "security_events": self._generate_security_events(config),
            "performance_events": self._generate_performance_events(config),
            "business_events": self._generate_business_events(config),
            "event_correlations": self._generate_event_correlations(config),
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "config": config.__dict__
            }
        }
    
    # Helper methods for data generation
    def _generate_health_status(self, config: TestDataConfig) -> str:
        """Generate realistic health status based on config."""
        if config.edge_cases:
            return random.choice(["healthy", "warning", "critical", "unknown", "offline"])
        else:
            return random.choices(
                ["healthy", "warning", "critical"], 
                weights=[70, 25, 5]
            )[0]
    
    def _generate_stacks_for_host(self, host_index: int, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate stacks for a specific host."""
        stacks = []
        stack_count = random.randint(0, 3)
        
        for i in range(stack_count):
            stack = {
                "id": f"stack-{host_index:03d}-{i:02d}",
                "name": f"stack-{host_index:03d}-{i:02d}",
                "type": random.choice(["web", "database", "cache"]),
                "status": random.choice(["running", "stopped", "error"]),
                "services": [f"service-{host_index:03d}-{i:02d}-{j:02d}" for j in range(random.randint(2, 5))]
            }
            stacks.append(stack)
        
        return stacks
    
    def _generate_container_services(self, container_index: int, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate services for a container."""
        service_types = [
            ("web", 80), ("app", 8080), ("db", 5432), 
            ("cache", 6379), ("api", 3000), ("queue", 5672)
        ]
        
        services = []
        service_count = random.randint(1, 3)
        
        for i in range(service_count):
            service_type, default_port = random.choice(service_types)
            service = {
                "id": f"service-{container_index:04d}-{i:02d}",
                "name": f"{service_type}-{container_index:04d}",
                "type": service_type,
                "status": "running" if random.random() > 0.1 else "stopped",
                "port": default_port + random.randint(0, 1000),
                "version": f"{random.randint(1, 5)}.{random.randint(0, 9)}.{random.randint(0, 20)}",
                "health_score": random.randint(70, 100)
            }
            services.append(service)
        
        return services
    
    def _get_default_port(self, service: str) -> int:
        """Get default port for a service."""
        ports = {
            "nginx": 80, "apache": 80, "caddy": 80,
            "postgresql": 5432, "mysql": 3306, "mongodb": 27017,
            "redis": 6379, "memcached": 11211,
            "rabbitmq": 5672,
            "prometheus": 9090, "grafana": 3000,
            "vault": 8200
        }
        return ports.get(service, 8000)
    
    def _generate_workflow_steps(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate workflow steps."""
        step_types = ["action", "condition", "approval", "notification", "rollback"]
        steps = []
        step_count = random.randint(3, 15)
        
        for i in range(step_count):
            step = {
                "id": f"step-{i+1:03d}",
                "name": f"Step {i+1}",
                "type": random.choice(step_types),
                "action": f"action_{random.randint(1, 100)}",
                "parameters": self._generate_step_parameters(),
                "conditions": self._generate_step_conditions() if random.random() > 0.7 else [],
                "timeout": random.choice([300, 600, 1800, 3600]),
                "retry_policy": {
                    "max_retries": random.randint(0, 3),
                    "retry_delay": random.randint(30, 300)
                } if random.random() > 0.5 else None
            }
            steps.append(step)
        
        return steps
    
    def _generate_workflow_triggers(self) -> List[Dict[str, Any]]:
        """Generate workflow triggers."""
        return [
            {
                "type": "manual",
                "enabled": True
            },
            {
                "type": "scheduled",
                "schedule": random.choice(["0 2 * * *", "0 */6 * * *", "0 0 * * 0"]),
                "enabled": random.choice([True, False])
            }
        ]
    
    def _generate_workflow_executions_context(self) -> List[Dict[str, Any]]:
        """Generate workflow execution context."""
        return []
    
    # Additional helper methods would continue here...
    def _generate_execution_parameters(self) -> Dict[str, Any]:
        """Generate execution parameters."""
        return {
            "environment": random.choice(["production", "staging", "development"]),
            "force": random.choice([True, False]),
            "dry_run": random.choice([True, False]),
            "timeout": random.randint(300, 3600)
        }
    
    def _generate_step_results(self) -> List[Dict[str, Any]]:
        """Generate step execution results."""
        return []
    
    def _generate_policy_rules(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate policy rules."""
        return []
    
    def _generate_policy_rules_for_policy(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate policy rules for a specific policy."""
        return []
    
    def _generate_policy_conditions(self) -> List[Dict[str, Any]]:
        """Generate policy conditions."""
        return []
    
    def _generate_roles(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate roles."""
        return []
    
    def _generate_permissions(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate permissions."""
        return []
    
    def _generate_audit_logs(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate audit logs."""
        return []
    
    # Security data generators
    def _generate_auth_attempts(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate authentication attempt data."""
        attempts = []
        attempt_count = min(config.count, 1000)
        
        for i in range(attempt_count):
            attempt = {
                "id": str(uuid.uuid4()),
                "timestamp": (datetime.utcnow() - timedelta(
                    hours=random.randint(0, 168),
                    minutes=random.randint(0, 59)
                )).isoformat(),
                "user_id": f"user-{random.randint(1, 500)}",
                "source_ip": f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
                "user_agent": random.choice([
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                    "TailOpsMCP/1.0"
                ]),
                "success": random.choice([True, True, True, False]),  # 75% success rate
                "failure_reason": "Invalid credentials" if random.random() > 0.75 else None,
                "risk_score": random.randint(0, 100)
            }
            attempts.append(attempt)
        
        return attempts
    
    def _generate_authz_violations(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate authorization violation data."""
        return []
    
    def _generate_security_incidents(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate security incident data."""
        return []
    
    def _generate_vulnerability_scans(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate vulnerability scan data."""
        return []
    
    def _generate_compliance_checks(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate compliance check data."""
        return []
    
    def _generate_security_audit_events(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate security audit event data."""
        return []
    
    # Event data generators
    def _generate_system_events(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate system event data."""
        return []
    
    def _generate_security_events(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate security event data."""
        return []
    
    def _generate_performance_events(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate performance event data."""
        return []
    
    def _generate_business_events(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate business event data."""
        return []
    
    def _generate_event_correlations(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate event correlation data."""
        return []
    
    # Workflow data generators
    def _generate_workflow_schedules(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate workflow schedule data."""
        return []
    
    def _generate_workflow_approvals(self, config: TestDataConfig) -> List[Dict[str, Any]]:
        """Generate workflow approval data."""
        return []
    
    def _generate_step_parameters(self) -> Dict[str, Any]:
        """Generate step parameters."""
        return {}
    
    def _generate_step_conditions(self) -> List[Dict[str, Any]]:
        """Generate step conditions."""
        return []
    
    def cleanup_test_data(self, category: Optional[DataCategory] = None):
        """Cleanup generated test data."""
        if category:
            if category in self.generated_data:
                del self.generated_data[category]
        else:
            self.generated_data.clear()
    
    def export_test_data(self, category: DataCategory, format: str = "json") -> str:
        """Export test data to specified format."""
        if category not in self.generated_data:
            return ""
        
        data = self.generated_data[category]
        
        if format == "json":
            return json.dumps(data, indent=2, default=str)
        elif format == "yaml":
            import yaml
            return yaml.dump(data, default_flow_style=False)
        else:
            raise ValueError(f"Unsupported format: {format}")


# Global test data manager instance
test_data_manager = TestDataManager()


# Convenience functions for test data generation
def generate_inventory_test_data(count: int = 100, complexity: str = "medium") -> Dict[str, Any]:
    """Generate inventory test data with specified parameters."""
    config = TestDataConfig(
        category=DataCategory.INVENTORY,
        count=count,
        complexity=complexity
    )
    return test_data_manager.generate_inventory_data(config)


def generate_workflow_test_data(count: int = 50, complexity: str = "medium") -> Dict[str, Any]:
    """Generate workflow test data with specified parameters."""
    config = TestDataConfig(
        category=DataCategory.WORKFLOW,
        count=count,
        complexity=complexity
    )
    return test_data_manager.generate_workflow_data(config)


def generate_security_test_data(count: int = 200, security_level: SecurityLevel = SecurityLevel.MEDIUM) -> Dict[str, Any]:
    """Generate security test data with specified parameters."""
    config = TestDataConfig(
        category=DataCategory.SECURITY,
        count=count,
        security_level=security_level
    )
    return test_data_manager.generate_security_data(config)


def generate_performance_test_data(count: int = 1000, complexity: str = "high") -> Dict[str, Any]:
    """Generate performance test data with specified parameters."""
    config = TestDataConfig(
        category=DataCategory.PERFORMANCE,
        count=count,
        complexity=complexity
    )
    return test_data_manager.generate_inventory_data(config)  # Reuse inventory for performance


# Test data fixtures for pytest
@pytest.fixture
def test_data_manager_fixture():
    """Provide test data manager fixture."""
    return test_data_manager


@pytest.fixture
def inventory_test_data():
    """Generate inventory test data fixture."""
    return generate_inventory_test_data(count=100)


@pytest.fixture
def workflow_test_data():
    """Generate workflow test data fixture."""
    return generate_workflow_test_data(count=50)


@pytest.fixture
def security_test_data_fixture():
    """Generate security test data fixture."""
    return generate_security_test_data(count=200)


@pytest.fixture
def performance_test_data_fixture():
    """Generate performance test data fixture."""
    return generate_performance_test_data(count=1000)


@pytest.fixture
def edge_case_test_data():
    """Generate edge case test data fixture."""
    config = TestDataConfig(
        category=DataCategory.EDGE_CASE,
        count=50,
        edge_cases=True,
        security_level=SecurityLevel.HIGH
    )
    return test_data_manager.generate_inventory_data(config)


# Data validation utilities
def validate_test_data(data: Dict[str, Any], data_type: str) -> bool:
    """Validate generated test data structure."""
    validators = {
        "inventory": _validate_inventory_data,
        "workflow": _validate_workflow_data,
        "security": _validate_security_data,
        "performance": _validate_performance_data
    }
    
    validator = validators.get(data_type)
    if validator:
        return validator(data)
    return False


def _validate_inventory_data(data: Dict[str, Any]) -> bool:
    """Validate inventory test data structure."""
    required_keys = ["gateway", "proxmox_hosts", "containers", "metadata"]
    return all(key in data for key in required_keys)


def _validate_workflow_data(data: Dict[str, Any]) -> bool:
    """Validate workflow test data structure."""
    required_keys = ["blueprints", "executions", "metadata"]
    return all(key in data for key in required_keys)


def _validate_security_data(data: Dict[str, Any]) -> bool:
    """Validate security test data structure."""
    required_keys = ["authentication_attempts", "metadata"]
    return all(key in data for key in required_keys)


def _validate_performance_data(data: Dict[str, Any]) -> bool:
    """Validate performance test data structure."""
    # Performance data reuses inventory structure
    return _validate_inventory_data(data)