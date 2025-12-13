"""
Enhanced Policy Configuration with Comprehensive Validation Rules

Extends the existing policy configuration to support enhanced validation rules
and allowlisting capabilities.
"""

import os
import yaml
from typing import Dict, List, Optional, Any
from pathlib import Path

from src.services.policy_gate import PolicyRule, PolicyConfig, OperationTier
from src.services.input_validator import ParameterType


class EnhancedPolicyConfig:
    """Enhanced policy configuration with comprehensive validation rules."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize enhanced policy configuration.
        
        Args:
            config_path: Path to policy configuration file
        """
        self.config_path = config_path or os.getenv(
            "SYSTEMMANAGER_POLICY_CONFIG", 
            "/etc/systemmanager/policy.yaml"
        )
        self._errors: List[str] = []
        self._warnings: List[str] = []
    
    def load(self) -> PolicyConfig:
        """Load policy configuration from file with enhanced validation.
        
        Returns:
            PolicyConfig with enhanced validation rules
            
        Raises:
            SystemManagerError: If configuration is invalid
        """
        self._errors.clear()
        self._warnings.clear()
        
        if not os.path.exists(self.config_path):
            self._warnings.append(f"Policy configuration not found: {self.config_path}")
            return self._get_default_config()
        
        try:
            with open(self.config_path, 'r') as f:
                config_data = yaml.safe_load(f)
            
            if not config_data:
                self._errors.append("Empty policy configuration")
                return self._get_default_config()
            
            return self._parse_config(config_data)
            
        except Exception as e:
            self._errors.append(f"Failed to load policy configuration: {e}")
            return self._get_default_config()
    
    def _parse_config(self, config_data: Dict[str, Any]) -> PolicyConfig:
        """Parse configuration data into PolicyConfig with enhanced validation."""
        rules = []
        
        # Parse validation mode
        validation_mode_str = config_data.get("default_validation_mode", "strict")
        try:
            from src.services.policy_gate import ValidationMode
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
                self._errors.append(f"Failed to parse rule {rule_data.get('name', 'unknown')}: {e}")
        
        # If no rules were parsed successfully, use defaults
        if not rules:
            self._warnings.append("No valid rules found, using defaults")
            return self._get_default_config()
        
        return PolicyConfig(
            rules=rules,
            default_validation_mode=validation_mode,
            enable_dry_run=config_data.get("enable_dry_run", True),
            maintenance_windows=config_data.get("maintenance_windows"),
            lockout_periods=config_data.get("lockout_periods")
        )
    
    def _parse_rule(self, rule_data: Dict[str, Any]) -> PolicyRule:
        """Parse individual rule with enhanced parameter constraints."""
        # Parse operation tier
        operation_tier_str = rule_data.get("operation_tier", "control").lower()
        try:
            operation_tier = OperationTier(operation_tier_str)
        except ValueError:
            self._errors.append(f"Invalid operation tier: {operation_tier_str}")
            operation_tier = OperationTier.CONTROL
        
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
            dry_run_supported=rule_data.get("dry_run_supported", True)
        )
    
    def _enhance_parameter_constraints(self, constraints: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance parameter constraints with validation type information."""
        enhanced = {}
        
        for param_name, constraint in constraints.items():
            enhanced_constraint = constraint.copy()
            
            # Add validation type based on parameter name patterns
            if param_name.endswith("_name"):
                if "service" in param_name:
                    enhanced_constraint["validation_type"] = ParameterType.SERVICE_NAME.value
                elif "container" in param_name:
                    enhanced_constraint["validation_type"] = ParameterType.CONTAINER_NAME.value
                elif "stack" in param_name:
                    enhanced_constraint["validation_type"] = ParameterType.STACK_NAME.value
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
    
    def _get_default_config(self) -> PolicyConfig:
        """Get default policy configuration with enhanced validation."""
        from src.auth.scopes import Scope
        
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
                        "allowlist_source": "list_containers"
                    },
                    "timeout": {
                        "type": "int", 
                        "min": 1, 
                        "max": 300,
                        "validation_type": ParameterType.TIMEOUT.value
                    }
                },
                operation_tier=OperationTier.CONTROL
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
                        "allowlist_source": "list_stacks"
                    },
                    "timeout": {
                        "type": "int", 
                        "min": 1, 
                        "max": 600,
                        "validation_type": ParameterType.TIMEOUT.value
                    }
                },
                operation_tier=OperationTier.CONTROL
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
                        "allowlist_source": "list_services"
                    },
                    "timeout": {
                        "type": "int", 
                        "min": 1, 
                        "max": 300,
                        "validation_type": ParameterType.TIMEOUT.value
                    }
                },
                operation_tier=OperationTier.CONTROL
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
                        "validation_type": ParameterType.FILE_PATH.value
                    }
                },
                operation_tier=OperationTier.OBSERVE
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
                        "validation_type": ParameterType.HOSTNAME.value
                    },
                    "port": {
                        "type": "int", 
                        "min": 1, 
                        "max": 65535,
                        "validation_type": ParameterType.PORT_NUMBER.value
                    }
                },
                operation_tier=OperationTier.OBSERVE
            )
        ]
        
        return PolicyConfig(rules=default_rules)
    
    def get_errors(self) -> List[str]:
        """Get configuration errors."""
        return self._errors
    
    def get_warnings(self) -> List[str]:
        """Get configuration warnings."""
        return self._warnings
    
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
        for rule in config.rules:
            if not self._validate_rule(rule):
                return False
        
        return True
    
    def _validate_rule(self, rule: PolicyRule) -> bool:
        """Validate individual rule for consistency."""
        # Check parameter constraints
        for param_name, constraint in rule.parameter_constraints.items():
            if "validation_type" in constraint:
                try:
                    ParameterType(constraint["validation_type"])
                except ValueError:
                    self._errors.append(f"Invalid validation type in rule {rule.name}: {constraint['validation_type']}")
                    return False
        
        return True


def get_enhanced_policy_config(config_path: Optional[str] = None) -> PolicyConfig:
    """Get enhanced policy configuration with comprehensive validation.
    
    Args:
        config_path: Optional path to configuration file
        
    Returns:
        Enhanced PolicyConfig with validation rules
    """
    config_loader = EnhancedPolicyConfig(config_path)
    return config_loader.load()