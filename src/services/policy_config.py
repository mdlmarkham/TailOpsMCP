"""
Policy configuration system for Policy Gate.

Provides comprehensive configuration loading, validation, and management for security policies.
Supports loading from YAML/JSON files, environment variables, and programmatic configuration.

ENHANCED: This file now contains all policy configuration functionality including:
- Basic policy configuration loading and validation
- Enhanced validation rules with comprehensive parameter constraints
- Allowlisting capabilities and validation types
- Advanced error handling and warning system
"""

import os
import yaml
import json
from typing import Any, Dict, List, Optional

from src.services.policy_gate import (
    PolicyConfig,
    PolicyRule,
    OperationTier,
    ValidationMode,
)
from src.auth.scopes import Scope
from src.services.input_validator import ParameterType


class PolicyConfigLoader:
    """Load and validate policy configuration from various sources."""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize policy configuration loader.

        Args:
            config_path: Path to policy configuration file
        """
        # Default configuration path
        if os.path.exists("/var/lib/systemmanager"):
            default_path = "/var/lib/systemmanager/policy.yaml"
        else:
            default_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)), "config", "policy.yaml"
            )

        self.config_path = config_path or os.getenv(
            "SYSTEMMANAGER_POLICY_CONFIG", default_path
        )
        self._errors: List[str] = []
        self._warnings: List[str] = []

    def load(self) -> PolicyConfig:
        """Load policy configuration from file.

        Returns:
            PolicyConfig with loaded rules

        Raises:
            SystemManagerError: If configuration loading fails
        """
        self._errors.clear()
        self._warnings.clear()

        # Try to load from file first
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    if self.config_path.endswith(".yaml") or self.config_path.endswith(
                        ".yml"
                    ):
                        config_data = yaml.safe_load(f)
                    else:
                        config_data = json.load(f)

                return self._parse_config(config_data)

            except Exception as e:
                self._errors.append(
                    f"Failed to load policy config from {self.config_path}: {e}"
                )
        else:
            self._warnings.append(f"Policy configuration not found: {self.config_path}")

        # Fallback to environment-based configuration or enhanced defaults
        return self._get_enhanced_default_config()

    def _parse_config(self, config_data: Dict[str, Any]) -> PolicyConfig:
        """Parse configuration data into PolicyConfig object.

        Args:
            config_data: Raw configuration data

        Returns:
            Validated PolicyConfig
        """
        rules = []

        # Parse validation mode
        validation_mode_str = config_data.get("default_validation_mode", "strict")
        try:
            validation_mode = ValidationMode(validation_mode_str.lower())
        except ValueError:
            self._errors.append(f"Invalid validation mode: {validation_mode_str}")
            validation_mode = ValidationMode.STRICT

        # Parse rules
        for rule_data in config_data.get("rules", []):
            try:
                rule = self._parse_rule(rule_data)
                rules.append(rule)
            except Exception as e:
                self._errors.append(
                    f"Failed to parse rule {rule_data.get('name', 'unknown')}: {e}"
                )

        # If no rules were parsed successfully, use enhanced defaults
        if not rules:
            self._warnings.append("No valid rules found, using enhanced defaults")
            return self._get_enhanced_default_config()

        return PolicyConfig(
            rules=rules,
            default_validation_mode=validation_mode,
            enable_dry_run=config_data.get("enable_dry_run", True),
            maintenance_windows=config_data.get("maintenance_windows"),
            lockout_periods=config_data.get("lockout_periods"),
        )

    def _parse_rule(self, rule_data: Dict[str, Any]) -> PolicyRule:
        """Parse individual rule with enhanced parameter constraints.

        Args:
            rule_data: Raw rule data

        Returns:
            Validated PolicyRule with enhanced constraints
        """
        # Validate required fields
        required_fields = [
            "name",
            "description",
            "target_pattern",
            "allowed_operations",
            "required_capabilities",
            "parameter_constraints",
            "operation_tier",
        ]

        for field in required_fields:
            if field not in rule_data:
                raise ValueError(f"Missing required field: {field}")

        # Parse operation tier
        try:
            operation_tier = OperationTier(rule_data["operation_tier"].lower())
        except ValueError:
            raise ValueError(f"Invalid operation tier: {rule_data['operation_tier']}")

        # Validate capabilities
        for capability in rule_data["required_capabilities"]:
            if capability not in [scope.value for scope in Scope]:
                raise ValueError(f"Invalid capability: {capability}")

        # Enhance parameter constraints with validation types
        enhanced_constraints = self._enhance_parameter_constraints(
            rule_data.get("parameter_constraints", {})
        )

        return PolicyRule(
            name=rule_data["name"],
            description=rule_data["description"],
            target_pattern=rule_data["target_pattern"],
            allowed_operations=rule_data["allowed_operations"],
            required_capabilities=rule_data["required_capabilities"],
            parameter_constraints=enhanced_constraints,
            operation_tier=operation_tier,
            requires_approval=rule_data.get("requires_approval", False),
            dry_run_supported=rule_data.get("dry_run_supported", True),
        )

    def _enhance_parameter_constraints(
        self, constraints: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enhance parameter constraints with validation type information.

        Args:
            constraints: Raw parameter constraints

        Returns:
            Enhanced parameter constraints with validation types
        """
        enhanced = {}

        for param_name, constraint in constraints.items():
            enhanced_constraint = constraint.copy()

            # Add validation type based on parameter name patterns
            if param_name.endswith("_name"):
                if "service" in param_name:
                    enhanced_constraint["validation_type"] = (
                        ParameterType.SERVICE_NAME.value
                    )
                elif "container" in param_name:
                    enhanced_constraint["validation_type"] = (
                        ParameterType.CONTAINER_NAME.value
                    )
                elif "stack" in param_name:
                    enhanced_constraint["validation_type"] = (
                        ParameterType.STACK_NAME.value
                    )
            elif param_name == "path" or param_name.endswith("_path"):
                enhanced_constraint["validation_type"] = ParameterType.FILE_PATH.value
            elif param_name == "port" or param_name.endswith("_port"):
                enhanced_constraint["validation_type"] = ParameterType.PORT_NUMBER.value
            elif param_name == "timeout":
                enhanced_constraint["validation_type"] = ParameterType.TIMEOUT.value
            elif param_name == "host" or param_name.endswith("_host"):
                enhanced_constraint["validation_type"] = ParameterType.HOSTNAME.value
            elif param_name == "url" or param_name.endswith("_url"):
                enhanced_constraint["validation_type"] = ParameterType.URL.value

            enhanced[param_name] = enhanced_constraint

        return enhanced

    def _get_enhanced_default_config(self) -> PolicyConfig:
        """Get enhanced default policy configuration with comprehensive validation rules."""
        default_rules = [
            PolicyRule(
                name="docker_container_operations",
                description="Docker container management operations with enhanced validation",
                target_pattern=".*",
                allowed_operations=["start", "stop", "restart", "inspect"],
                required_capabilities=[Scope.CONTAINER_WRITE.value],
                parameter_constraints={
                    "container_name": {
                        "type": "string",
                        "max_length": 256,
                        "validation_type": ParameterType.CONTAINER_NAME.value,
                        "allowlist_source": "list_containers",
                    },
                    "timeout": {
                        "type": "int",
                        "min": 1,
                        "max": 300,
                        "validation_type": ParameterType.TIMEOUT.value,
                    },
                },
                operation_tier=OperationTier.CONTROL,
            ),
            PolicyRule(
                name="docker_image_operations",
                description="Docker image management operations with enhanced validation",
                target_pattern=".*",
                allowed_operations=["pull", "list", "remove"],
                required_capabilities=[Scope.DOCKER_ADMIN.value],
                parameter_constraints={
                    "image_name": {
                        "type": "string",
                        "max_length": 512,
                        "validation_type": ParameterType.CONTAINER_NAME.value,
                    },
                    "tag": {
                        "type": "string",
                        "max_length": 128,
                        "validation_type": ParameterType.CONTAINER_NAME.value,
                    },
                },
                operation_tier=OperationTier.ADMIN,
                requires_approval=True,
                dry_run_supported=True,
            ),
            PolicyRule(
                name="stack_operations",
                description="Docker Compose stack management with enhanced validation",
                target_pattern=".*",
                allowed_operations=["deploy", "pull", "restart"],
                required_capabilities=[Scope.STACK_WRITE.value],
                parameter_constraints={
                    "stack_name": {
                        "type": "string",
                        "max_length": 64,
                        "validation_type": ParameterType.STACK_NAME.value,
                        "allowlist_source": "list_stacks",
                    },
                    "timeout": {
                        "type": "int",
                        "min": 1,
                        "max": 600,
                        "validation_type": ParameterType.TIMEOUT.value,
                    },
                },
                operation_tier=OperationTier.CONTROL,
            ),
            PolicyRule(
                name="service_operations",
                description="System service management with enhanced validation",
                target_pattern=".*",
                allowed_operations=["restart", "status"],
                required_capabilities=[Scope.SYSTEM_WRITE.value],
                parameter_constraints={
                    "service_name": {
                        "type": "string",
                        "max_length": 64,
                        "validation_type": ParameterType.SERVICE_NAME.value,
                        "allowlist_source": "list_services",
                    },
                    "timeout": {
                        "type": "int",
                        "min": 1,
                        "max": 300,
                        "validation_type": ParameterType.TIMEOUT.value,
                    },
                },
                operation_tier=OperationTier.CONTROL,
            ),
            PolicyRule(
                name="file_operations",
                description="File system operations with enhanced validation",
                target_pattern=".*",
                allowed_operations=["read", "list"],
                required_capabilities=[Scope.FILE_READ.value],
                parameter_constraints={
                    "path": {
                        "type": "string",
                        "max_length": 1024,
                        "validation_type": ParameterType.FILE_PATH.value,
                    }
                },
                operation_tier=OperationTier.OBSERVE,
            ),
            PolicyRule(
                name="network_operations",
                description="Network operations with enhanced validation",
                target_pattern=".*",
                allowed_operations=["test", "scan"],
                required_capabilities=[Scope.NETWORK_READ.value],
                parameter_constraints={
                    "host": {
                        "type": "string",
                        "max_length": 253,
                        "validation_type": ParameterType.HOSTNAME.value,
                    },
                    "port": {
                        "type": "int",
                        "min": 1,
                        "max": 65535,
                        "validation_type": ParameterType.PORT_NUMBER.value,
                    },
                },
                operation_tier=OperationTier.OBSERVE,
            ),
            PolicyRule(
                name="fleet_inventory_operations",
                description="Fleet inventory management with enhanced validation",
                target_pattern=".*",
                allowed_operations=["discover", "update", "query"],
                required_capabilities=[Scope.INVENTORY_READ.value],
                parameter_constraints={
                    "target_pattern": {
                        "type": "string",
                        "max_length": 512,
                        "validation_type": ParameterType.HOSTNAME.value,
                    },
                    "timeout": {
                        "type": "int",
                        "min": 1,
                        "max": 1800,
                        "validation_type": ParameterType.TIMEOUT.value,
                    },
                },
                operation_tier=OperationTier.CONTROL,
            ),
        ]

        return PolicyConfig(
            rules=default_rules,
            default_validation_mode=ValidationMode.STRICT,
            enable_dry_run=True,
        )

    def validate_config(self, config: PolicyConfig) -> List[str]:
        """Validate policy configuration for consistency.

        Args:
            config: PolicyConfig to validate

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Validate rules
        for rule in config.rules:
            # Check for duplicate rule names
            rule_names = [r.name for r in config.rules]
            if rule_names.count(rule.name) > 1:
                errors.append(f"Duplicate rule name: {rule.name}")

            # Validate target pattern is valid regex
            try:
                import re

                re.compile(rule.target_pattern)
            except re.error as e:
                errors.append(f"Invalid target pattern in rule {rule.name}: {e}")

            # Validate parameter constraints
            for param_name, constraint in rule.parameter_constraints.items():
                if "type" not in constraint:
                    errors.append(
                        f"Missing type in parameter constraint for {param_name} in rule {rule.name}"
                    )

                constraint_type = constraint.get("type")
                if constraint_type == "int":
                    if "min" in constraint and "max" in constraint:
                        if constraint["min"] > constraint["max"]:
                            errors.append(
                                f"Invalid range for {param_name} in rule {rule.name}: min > max"
                            )

                # Validate enhanced constraint fields
                if "validation_type" in constraint:
                    try:
                        ParameterType(constraint["validation_type"])
                    except ValueError:
                        errors.append(
                            f"Invalid validation type in rule {rule.name}: {constraint['validation_type']}"
                        )

        # Validate maintenance windows
        for window in config.maintenance_windows or []:
            if "start" not in window or "end" not in window:
                errors.append("Maintenance window missing start or end time")

        # Validate lockout periods
        for period in config.lockout_periods or []:
            if "start" not in period or "end" not in period:
                errors.append("Lockout period missing start or end time")

        return errors

    def get_errors(self) -> List[str]:
        """Get configuration errors."""
        return self._errors.copy()

    def get_warnings(self) -> List[str]:
        """Get configuration warnings."""
        return self._warnings.copy()

    def validate_configuration(self) -> bool:
        """Validate the configuration for consistency.

        Returns:
            True if configuration is valid, False otherwise
        """
        config = self.load()

        # Check for critical errors
        if self._errors:
            return False

        # Validate rule consistency
        validation_errors = self.validate_config(config)
        if validation_errors:
            self._errors.extend(validation_errors)
            return False

        return True


# Enhanced convenience function
def get_enhanced_policy_config(config_path: Optional[str] = None) -> PolicyConfig:
    """Get enhanced policy configuration with comprehensive validation.

    Args:
        config_path: Optional path to configuration file

    Returns:
        Enhanced PolicyConfig with validation rules
    """
    config_loader = PolicyConfigLoader(config_path)
    return config_loader.load()


# Example policy configuration
def create_example_policy_config() -> Dict[str, Any]:
    """Create example policy configuration for documentation."""
    return {
        "default_validation_mode": "strict",
        "enable_dry_run": True,
        "rules": [
            {
                "name": "docker_container_operations",
                "description": "Docker container management operations with enhanced validation",
                "target_pattern": ".*",
                "allowed_operations": ["start", "stop", "restart", "inspect"],
                "required_capabilities": ["container:write"],
                "parameter_constraints": {
                    "container_name": {
                        "type": "string",
                        "max_length": 256,
                        "validation_type": "container_name",
                        "allowlist_source": "list_containers",
                    },
                    "timeout": {
                        "type": "int",
                        "min": 1,
                        "max": 300,
                        "validation_type": "timeout",
                    },
                },
                "operation_tier": "control",
                "requires_approval": False,
                "dry_run_supported": True,
            },
            {
                "name": "docker_image_operations",
                "description": "Docker image management operations with enhanced validation",
                "target_pattern": ".*",
                "allowed_operations": ["pull", "list", "remove"],
                "required_capabilities": ["docker:admin"],
                "parameter_constraints": {
                    "image_name": {
                        "type": "string",
                        "max_length": 512,
                        "validation_type": "container_name",
                    },
                    "tag": {
                        "type": "string",
                        "max_length": 128,
                        "validation_type": "container_name",
                    },
                },
                "operation_tier": "admin",
                "requires_approval": True,
                "dry_run_supported": True,
            },
            {
                "name": "fleet_inventory_operations",
                "description": "Fleet inventory management operations",
                "target_pattern": ".*",
                "allowed_operations": ["discover", "update", "query"],
                "required_capabilities": ["inventory:read"],
                "parameter_constraints": {
                    "target_pattern": {
                        "type": "string",
                        "max_length": 512,
                        "validation_type": "hostname",
                    },
                    "timeout": {
                        "type": "int",
                        "min": 1,
                        "max": 1800,
                        "validation_type": "timeout",
                    },
                },
                "operation_tier": "control",
                "requires_approval": False,
                "dry_run_supported": True,
            },
        ],
        "maintenance_windows": [
            {
                "name": "weekly_maintenance",
                "start": "sunday 02:00",
                "end": "sunday 04:00",
                "description": "Weekly system maintenance window",
            }
        ],
        "lockout_periods": [
            {
                "name": "critical_operations_lockout",
                "start": "friday 18:00",
                "end": "monday 06:00",
                "description": "Lockout critical operations during weekend",
            }
        ],
    }


def save_example_config(config_path: str) -> None:
    """Save example policy configuration to file.

    Args:
        config_path: Path where to save the example configuration
    """
    example_config = create_example_policy_config()

    os.makedirs(os.path.dirname(config_path), exist_ok=True)

    with open(config_path, "w") as f:
        if config_path.endswith(".yaml") or config_path.endswith(".yml"):
            yaml.dump(example_config, f, default_flow_style=False, indent=2)
        else:
            json.dump(example_config, f, indent=2)

    print(f"Example policy configuration saved to {config_path}")
