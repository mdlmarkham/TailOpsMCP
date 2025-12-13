"""
Policy configuration system for Policy Gate.

Provides configuration loading, validation, and management for security policies.
Supports loading from YAML/JSON files, environment variables, and programmatic configuration.
"""

import os
import yaml
import json
from typing import Any, Dict, List, Optional
from pathlib import Path

from src.services.policy_gate import PolicyConfig, PolicyRule, OperationTier
from src.auth.scopes import Scope
from src.utils.errors import ErrorCategory, SystemManagerError


class PolicyConfigLoader:
    """Load and validate policy configuration from various sources."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize policy configuration loader.
        
        Args:
            config_path: Path to policy configuration file
        """
        # Default configuration path
        if os.path.exists('/var/lib/systemmanager'):
            default_path = '/var/lib/systemmanager/policy.yaml'
        else:
            default_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "policy.yaml")
        
        self.config_path = config_path or os.getenv("SYSTEMMANAGER_POLICY_CONFIG", default_path)
        self._errors: List[str] = []
    
    def load(self) -> PolicyConfig:
        """Load policy configuration from file.
        
        Returns:
            PolicyConfig with loaded rules
            
        Raises:
            SystemManagerError: If configuration loading fails
        """
        self._errors.clear()
        
        # Try to load from file first
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    if self.config_path.endswith('.yaml') or self.config_path.endswith('.yml'):
                        config_data = yaml.safe_load(f)
                    else:
                        config_data = json.load(f)
                
                return self._parse_config(config_data)
                
            except Exception as e:
                self._errors.append(f"Failed to load policy config from {self.config_path}: {e}")
        
        # Fallback to environment-based configuration
        return self._load_from_environment()
    
    def _parse_config(self, config_data: Dict[str, Any]) -> PolicyConfig:
        """Parse configuration data into PolicyConfig object.
        
        Args:
            config_data: Raw configuration data
            
        Returns:
            Validated PolicyConfig
        """
        rules = []
        
        # Parse rules
        for rule_data in config_data.get("rules", []):
            try:
                rule = self._parse_rule(rule_data)
                rules.append(rule)
            except Exception as e:
                self._errors.append(f"Failed to parse rule {rule_data.get('name', 'unknown')}: {e}")
        
        # Parse configuration settings
        validation_mode_str = config_data.get("default_validation_mode", "strict")
        try:
            from src.services.policy_gate import ValidationMode
            validation_mode = ValidationMode(validation_mode_str.lower())
        except ValueError:
            self._errors.append(f"Invalid validation mode: {validation_mode_str}")
            validation_mode = ValidationMode.STRICT
        
        enable_dry_run = config_data.get("enable_dry_run", True)
        maintenance_windows = config_data.get("maintenance_windows", [])
        lockout_periods = config_data.get("lockout_periods", [])
        
        if self._errors:
            raise SystemManagerError(
                f"Policy configuration validation failed: {', '.join(self._errors)}",
                category=ErrorCategory.CONFIGURATION
            )
        
        return PolicyConfig(
            rules=rules,
            default_validation_mode=validation_mode,
            enable_dry_run=enable_dry_run,
            maintenance_windows=maintenance_windows,
            lockout_periods=lockout_periods
        )
    
    def _parse_rule(self, rule_data: Dict[str, Any]) -> PolicyRule:
        """Parse individual rule data into PolicyRule object.
        
        Args:
            rule_data: Raw rule data
            
        Returns:
            Validated PolicyRule
        """
        # Validate required fields
        required_fields = ["name", "description", "target_pattern", "allowed_operations", 
                          "required_capabilities", "parameter_constraints", "operation_tier"]
        
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
        
        return PolicyRule(
            name=rule_data["name"],
            description=rule_data["description"],
            target_pattern=rule_data["target_pattern"],
            allowed_operations=rule_data["allowed_operations"],
            required_capabilities=rule_data["required_capabilities"],
            parameter_constraints=rule_data["parameter_constraints"],
            operation_tier=operation_tier,
            requires_approval=rule_data.get("requires_approval", False),
            dry_run_supported=rule_data.get("dry_run_supported", True)
        )
    
    def _load_from_environment(self) -> PolicyConfig:
        """Load policy configuration from environment variables."""
        # Use default policy rules when no configuration file exists
        from src.services.policy_gate import PolicyGate
        
        # Create a temporary PolicyGate to get default configuration
        from src.utils.audit import AuditLogger
        from src.services.target_registry import TargetRegistry
        
        audit_logger = AuditLogger()
        target_registry = TargetRegistry()
        policy_gate = PolicyGate(target_registry, audit_logger)
        
        return policy_gate.policy_config
    
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
                    errors.append(f"Missing type in parameter constraint for {param_name} in rule {rule.name}")
                
                constraint_type = constraint.get("type")
                if constraint_type == "int":
                    if "min" in constraint and "max" in constraint:
                        if constraint["min"] > constraint["max"]:
                            errors.append(f"Invalid range for {param_name} in rule {rule.name}: min > max")
        
        # Validate maintenance windows
        for window in config.maintenance_windows or []:
            if "start" not in window or "end" not in window:
                errors.append("Maintenance window missing start or end time")
        
        # Validate lockout periods
        for period in config.lockout_periods or []:
            if "start" not in period or "end" not in period:
                errors.append("Lockout period missing start or end time")
        
        return errors


# Example policy configuration
def create_example_policy_config() -> Dict[str, Any]:
    """Create example policy configuration for documentation."""
    return {
        "default_validation_mode": "strict",
        "enable_dry_run": True,
        "rules": [
            {
                "name": "docker_container_operations",
                "description": "Docker container management operations",
                "target_pattern": ".*",
                "allowed_operations": ["start", "stop", "restart", "inspect"],
                "required_capabilities": ["container:write"],
                "parameter_constraints": {
                    "container_name": {"type": "string", "max_length": 256},
                    "timeout": {"type": "int", "min": 1, "max": 300}
                },
                "operation_tier": "control",
                "requires_approval": False,
                "dry_run_supported": True
            },
            {
                "name": "docker_image_operations",
                "description": "Docker image management operations",
                "target_pattern": ".*",
                "allowed_operations": ["pull", "list", "remove"],
                "required_capabilities": ["docker:admin"],
                "parameter_constraints": {
                    "image_name": {"type": "string", "max_length": 512},
                    "tag": {"type": "string", "max_length": 128}
                },
                "operation_tier": "admin",
                "requires_approval": True,
                "dry_run_supported": True
            }
        ],
        "maintenance_windows": [
            {
                "name": "weekly_maintenance",
                "start": "sunday 02:00",
                "end": "sunday 04:00",
                "description": "Weekly system maintenance window"
            }
        ],
        "lockout_periods": [
            {
                "name": "critical_operations_lockout",
                "start": "friday 18:00",
                "end": "monday 06:00",
                "description": "Lockout critical operations during weekend"
            }
        ]
    }


def save_example_config(config_path: str) -> None:
    """Save example policy configuration to file.
    
    Args:
        config_path: Path where to save the example configuration
    """
    example_config = create_example_policy_config()
    
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    
    with open(config_path, 'w') as f:
        if config_path.endswith('.yaml') or config_path.endswith('.yml'):
            yaml.dump(example_config, f, default_flow_style=False, indent=2)
        else:
            json.dump(example_config, f, indent=2)
    
    print(f"Example policy configuration saved to {config_path}")