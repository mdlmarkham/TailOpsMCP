"""
Policy-as-Code Configuration System for Gateway Fleet Orchestrator

Provides YAML/JSON configuration support for policy rules, targets, and credentials.
Implements deny-by-default security with explicit allowlists and structured audit logging.
"""

import os
import yaml
import json
import logging
from typing import Dict, List, Optional, Any, Set
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class OperationTier(str, Enum):
    """Operation tiers for policy enforcement."""
    OBSERVE = "observe"      # Read-only operations
    CONTROL = "control"      # Start/stop operations
    ADMIN = "admin"          # Administrative operations


class ConnectionMethod(str, Enum):
    """Supported connection methods for targets."""
    SSH = "ssh"
    DOCKER = "docker"
    TAILSCALE = "tailscale"
    LOCAL = "local"


@dataclass
class TargetConfig:
    """Target configuration for fleet operations."""
    id: str
    host: str
    tags: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    connection_method: ConnectionMethod = ConnectionMethod.SSH
    credential_path: Optional[str] = None  # Path to credentials file, never stored in repo
    capabilities: List[str] = field(default_factory=list)
    description: Optional[str] = None


@dataclass
class PolicyRule:
    """Policy rule definition for operation allowlisting."""
    name: str
    description: str
    target_pattern: str  # Regex pattern for target matching
    allowed_operations: List[str]
    required_capabilities: List[str]
    parameter_constraints: Dict[str, Any]
    operation_tier: OperationTier
    requires_approval: bool = False
    dry_run_supported: bool = True


@dataclass
class PolicyConfig:
    """Complete policy configuration."""
    targets: List[TargetConfig]
    rules: List[PolicyRule]
    default_validation_mode: str = "strict"
    enable_dry_run: bool = True
    audit_log_path: str = "./logs/audit.jsonl"
    audit_rotation_size: int = 100 * 1024 * 1024  # 100MB
    audit_rotation_count: int = 10


class PolicyAsCodeConfig:
    """Policy-as-Code configuration manager."""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.config_cache: Dict[str, Any] = {}
        
    def load_targets_config(self, file_path: str = "targets.yaml") -> List[TargetConfig]:
        """Load targets configuration from YAML file."""
        config_path = self.config_dir / file_path
        
        if not config_path.exists():
            logger.warning(f"Targets config file not found: {config_path}")
            return []
        
        with open(config_path, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
        
        targets = []
        for target_data in config_data.get('targets', []):
            try:
                target = TargetConfig(
                    id=target_data['id'],
                    host=target_data['host'],
                    tags=target_data.get('tags', []),
                    roles=target_data.get('roles', []),
                    connection_method=ConnectionMethod(target_data.get('connection_method', 'ssh')),
                    credential_path=target_data.get('credential_path'),
                    capabilities=target_data.get('capabilities', []),
                    description=target_data.get('description')
                )
                targets.append(target)
            except KeyError as e:
                logger.error(f"Invalid target configuration: missing field {e}")
                continue
        
        return targets
    
    def load_policy_config(self, file_path: str = "policy.yaml") -> List[PolicyRule]:
        """Load policy rules configuration from YAML file."""
        config_path = self.config_dir / file_path
        
        if not config_path.exists():
            logger.warning(f"Policy config file not found: {config_path}")
            return []
        
        with open(config_path, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
        
        rules = []
        for rule_data in config_data.get('rules', []):
            try:
                rule = PolicyRule(
                    name=rule_data['name'],
                    description=rule_data['description'],
                    target_pattern=rule_data['target_pattern'],
                    allowed_operations=rule_data['allowed_operations'],
                    required_capabilities=rule_data['required_capabilities'],
                    parameter_constraints=rule_data.get('parameter_constraints', {}),
                    operation_tier=OperationTier(rule_data['operation_tier']),
                    requires_approval=rule_data.get('requires_approval', False),
                    dry_run_supported=rule_data.get('dry_run_supported', True)
                )
                rules.append(rule)
            except KeyError as e:
                logger.error(f"Invalid policy rule configuration: missing field {e}")
                continue
        
        return rules
    
    def load_credentials_references(self, file_path: str = "credentials.yaml") -> Dict[str, str]:
        """Load credentials references (paths only, never secrets)."""
        config_path = self.config_dir / file_path
        
        if not config_path.exists():
            logger.warning(f"Credentials config file not found: {config_path}")
            return {}
        
        with open(config_path, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
        
        credentials = {}
        for cred_data in config_data.get('credentials', []):
            try:
                target_id = cred_data['target_id']
                credential_path = cred_data['credential_path']
                
                # Validate that path exists and is secure
                if not os.path.exists(credential_path):
                    logger.warning(f"Credential path does not exist: {credential_path}")
                    continue
                
                # Ensure path is not world-readable
                if os.stat(credential_path).st_mode & 0o077:
                    logger.warning(f"Credential path has insecure permissions: {credential_path}")
                
                credentials[target_id] = credential_path
            except KeyError as e:
                logger.error(f"Invalid credential configuration: missing field {e}")
                continue
        
        return credentials
    
    def get_complete_config(self) -> PolicyConfig:
        """Load complete policy configuration."""
        targets = self.load_targets_config()
        rules = self.load_policy_config()
        
        return PolicyConfig(
            targets=targets,
            rules=rules
        )


# Default deny-by-default policy rules
DEFAULT_DENY_RULE = PolicyRule(
    name="default_deny",
    description="Default deny rule - no operations allowed unless explicitly permitted",
    target_pattern=".*",
    allowed_operations=[],  # Empty list means deny all
    required_capabilities=[],
    parameter_constraints={},
    operation_tier=OperationTier.OBSERVE
)


class PolicyAsCodeManager:
    """Manager for Policy-as-Code system with deny-by-default enforcement."""
    
    def __init__(self, config_dir: str = "config"):
        self.config_loader = PolicyAsCodeConfig(config_dir)
        self.config = self.config_loader.get_complete_config()
        
        # Add default deny rule to enforce deny-by-default
        if not any(rule.name == "default_deny" for rule in self.config.rules):
            self.config.rules.insert(0, DEFAULT_DENY_RULE)
    
    def is_operation_allowed(self, target_id: str, operation: str) -> bool:
        """Check if operation is allowed for target (deny-by-default)."""
        for rule in self.config.rules:
            if not re.match(rule.target_pattern, target_id):
                continue
            
            if operation in rule.allowed_operations:
                return True
            
            # If we hit the default deny rule and operation not allowed, deny
            if rule.name == "default_deny":
                return False
        
        # Default deny if no matching rules
        return False
    
    def get_allowed_operations(self, target_id: str) -> Set[str]:
        """Get all allowed operations for a target."""
        allowed_ops = set()
        
        for rule in self.config.rules:
            if not re.match(rule.target_pattern, target_id):
                continue
            
            if rule.name != "default_deny":
                allowed_ops.update(rule.allowed_operations)
        
        return allowed_ops
    
    def validate_operation(self, target_id: str, operation: str, parameters: Dict[str, Any]) -> List[str]:
        """Validate operation against policy rules."""
        errors = []
        
        # Check if operation is allowed
        if not self.is_operation_allowed(target_id, operation):
            errors.append(f"Operation '{operation}' not allowed for target '{target_id}'")
            return errors
        
        # Find matching rule for parameter validation
        matching_rule = None
        for rule in self.config.rules:
            if re.match(rule.target_pattern, target_id) and operation in rule.allowed_operations:
                matching_rule = rule
                break
        
        if matching_rule:
            # Validate parameters against constraints
            errors.extend(self._validate_parameters(parameters, matching_rule.parameter_constraints))
        
        return errors
    
    def _validate_parameters(self, parameters: Dict[str, Any], constraints: Dict[str, Any]) -> List[str]:
        """Validate parameters against constraints."""
        errors = []
        
        for param_name, constraint in constraints.items():
            if param_name not in parameters:
                # Optional parameters are allowed to be missing
                continue
            
            value = parameters[param_name]
            
            # Type validation
            if constraint.get('type') == 'string':
                if not isinstance(value, str):
                    errors.append(f"Parameter '{param_name}' must be string")
                elif 'max_length' in constraint and len(value) > constraint['max_length']:
                    errors.append(f"Parameter '{param_name}' exceeds max length {constraint['max_length']}")
            
            elif constraint.get('type') == 'int':
                if not isinstance(value, int):
                    errors.append(f"Parameter '{param_name}' must be integer")
                else:
                    if 'min' in constraint and value < constraint['min']:
                        errors.append(f"Parameter '{param_name}' below minimum {constraint['min']}")
                    if 'max' in constraint and value > constraint['max']:
                        errors.append(f"Parameter '{param_name}' above maximum {constraint['max']}")
        
        return errors