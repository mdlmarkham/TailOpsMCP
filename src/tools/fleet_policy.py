"""Policy configuration for fleet management operations in Gateway mode."""

import yaml
from typing import Dict, List, Any
from pathlib import Path


# Default policy configuration for fleet management operations
FLEET_MANAGEMENT_POLICY = """
# Fleet Management Policy Configuration
# This policy defines the allowed operations for fleet management in Gateway mode

version: "1.0"
policy_name: "fleet_management"

# Operation definitions for fleet management
default_tier: observe

operations:
  # Discovery and inventory operations (OBSERVE tier)
  fleet_discover:
    tier: observe
    description: "Run fleet discovery to find nodes and services"
    allowed_targets: ["gateway"]

  fleet_inventory_get:
    tier: observe
    description: "Retrieve latest fleet inventory snapshot"
    allowed_targets: ["gateway"]

  fleet_node_health:
    tier: observe
    description: "Check health status of specific nodes"
    allowed_targets: ["*"]  # Can check any managed node

  # Planning operations (CONTROL tier)
  plan_update_packages:
    tier: control
    description: "Plan package update operation"
    allowed_targets: ["*"]
    parameters:
      update_only: [true, false]
      upgrade: [true, false]
      packages: []  # Optional specific packages

  plan_restart_service:
    tier: control
    description: "Plan service restart operation"
    allowed_targets: ["*"]
    parameters:
      service: "*"  # Any service name

  plan_docker_compose_pull_up:
    tier: control
    description: "Plan docker-compose stack update"
    allowed_targets: ["*"]
    parameters:
      stack: "*"  # Any stack name
      detach: [true, false]

  plan_snapshot_or_backup:
    tier: control
    description: "Plan snapshot or backup operation"
    allowed_targets: ["*"]
    parameters:
      type: ["snapshot", "backup"]
      target: ["all", "specific"]

  plan_restore:
    tier: admin
    description: "Plan restore operation (admin only)"
    allowed_targets: ["*"]
    requires_approval: true
    parameters:
      backup_id: "*"
      target: "*"

  # Execution operations (CONTROL/ADMIN tiers)
  update_packages:
    tier: control
    description: "Execute package updates"
    allowed_targets: ["*"]
    parameters:
      update_only: [true, false]
      upgrade: [true, false]
      packages: []

  restart_service:
    tier: control
    description: "Execute service restart"
    allowed_targets: ["*"]
    parameters:
      service: "*"

  docker_compose_pull_up:
    tier: control
    description: "Execute docker-compose stack update"
    allowed_targets: ["*"]
    parameters:
      stack: "*"
      detach: [true, false]

  snapshot_or_backup:
    tier: control
    description: "Execute snapshot or backup"
    allowed_targets: ["*"]
    parameters:
      type: ["snapshot", "backup"]
      target: ["all", "specific"]

  restore:
    tier: admin
    description: "Execute restore operation (admin only)"
    allowed_targets: ["*"]
    requires_approval: true
    parameters:
      backup_id: "*"
      target: "*"

# Target definitions
targets:
  gateway:
    description: "Gateway system managing the fleet"
    capabilities: ["fleet_management", "discovery", "inventory"]

  managed_node:
    description: "Managed node in the fleet"
    capabilities: ["package_management", "service_management", "container_management"]

# Role definitions
roles:
  fleet_operator:
    description: "Operator with fleet management permissions"
    allowed_operations:
      - fleet_discover
      - fleet_inventory_get
      - fleet_node_health
      - plan_update_packages
      - plan_restart_service
      - plan_docker_compose_pull_up
      - plan_snapshot_or_backup
      - update_packages
      - restart_service
      - docker_compose_pull_up
      - snapshot_or_backup

  fleet_admin:
    description: "Administrator with full fleet management permissions"
    allowed_operations:
      - "*"  # All operations

# Default role assignments
default_roles:
  - fleet_operator
"""


def create_fleet_management_policy():
    """Create the fleet management policy configuration file."""
    policy_path = Path("config/fleet_management_policy.yaml")
    policy_path.parent.mkdir(exist_ok=True)

    with open(policy_path, "w") as f:
        f.write(FLEET_MANAGEMENT_POLICY)

    return policy_path


def load_fleet_management_policy() -> Dict[str, Any]:
    """Load the fleet management policy configuration."""
    policy_path = Path("config/fleet_management_policy.yaml")

    if not policy_path.exists():
        # Create default policy if it doesn't exist
        policy_path = create_fleet_management_policy()

    with open(policy_path, "r") as f:
        return yaml.safe_load(f)


# Safe operation implementations for fleet management
SAFE_OPERATIONS = {
    "update_packages": {
        "description": "Safe package updates with apt",
        "commands": ["sudo apt-get update", "sudo apt-get upgrade --yes"],
        "timeout": 1800,
        "risk_level": "low",
    },
    "restart_service": {
        "description": "Safe service restart with systemd",
        "commands": ["sudo systemctl restart {service}"],
        "timeout": 300,
        "risk_level": "medium",
    },
    "docker_compose_pull_up": {
        "description": "Safe docker-compose stack update",
        "commands": ["docker-compose pull", "docker-compose up -d"],
        "timeout": 900,
        "risk_level": "medium",
    },
    "snapshot_or_backup": {
        "description": "Safe snapshot or backup operation",
        "commands": [],  # Implementation depends on backup system
        "timeout": 3600,
        "risk_level": "low",
    },
    "restore": {
        "description": "Restore operation (admin only)",
        "commands": [],  # Implementation depends on backup system
        "timeout": 3600,
        "risk_level": "high",
        "requires_approval": True,
    },
}


def get_safe_operation_config(operation_name: str) -> Dict[str, Any]:
    """Get configuration for a safe operation."""
    return SAFE_OPERATIONS.get(operation_name, {})


def validate_operation_parameters(
    operation_name: str, parameters: Dict[str, Any]
) -> List[str]:
    """Validate operation parameters against safe configuration."""
    errors = []

    config = get_safe_operation_config(operation_name)
    if not config:
        errors.append(f"Unknown operation: {operation_name}")
        return errors

    # Validate service name for restart_service
    if operation_name == "restart_service":
        service = parameters.get("service")
        if not service or not isinstance(service, str):
            errors.append("Service name is required and must be a string")
        elif len(service) > 100:  # Reasonable service name length
            errors.append("Service name is too long")

    # Validate stack name for docker_compose_pull_up
    if operation_name == "docker_compose_pull_up":
        stack = parameters.get("stack")
        if not stack or not isinstance(stack, str):
            errors.append("Stack name is required and must be a string")

    # Validate backup_id for restore
    if operation_name == "restore":
        backup_id = parameters.get("backup_id")
        if not backup_id or not isinstance(backup_id, str):
            errors.append("Backup ID is required and must be a string")

    return errors
