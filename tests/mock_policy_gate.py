"""
Mock Policy Gate for testing authorization logic without real policy enforcement.
"""

from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import Mock

from src.auth.token_auth import TokenClaims
from src.models.target_registry import TargetMetadata
from src.services.policy_gate import PolicyGate, OperationTier, ValidationMode
from src.utils.audit import AuditLogger


class MockPolicyGate:
    """Mock Policy Gate for testing authorization logic."""
    
    def __init__(self, 
                 default_allow: bool = True,
                 validation_mode: ValidationMode = ValidationMode.STRICT,
                 audit_logger: Optional[AuditLogger] = None):
        """Initialize mock policy gate.
        
        Args:
            default_allow: Whether to allow operations by default
            validation_mode: Validation mode for policy enforcement
            audit_logger: Optional audit logger for testing
        """
        self.default_allow = default_allow
        self.validation_mode = validation_mode
        self.audit_logger = audit_logger or Mock(spec=AuditLogger)
        
        # Track authorization attempts
        self.authorization_history: List[Dict[str, Any]] = []
        
        # Configured responses for specific scenarios
        self.allowed_operations: List[Tuple[str, str]] = []  # (tool, target)
        self.denied_operations: List[Tuple[str, str]] = []
        self.requires_approval: List[Tuple[str, str]] = []
        
    def authorize_operation(self,
                           tool: str,
                           target: Optional[TargetMetadata],
                           claims: TokenClaims,
                           parameters: Dict[str, Any],
                           operation_tier: OperationTier = OperationTier.OBSERVE,
                           dry_run: bool = False) -> Dict[str, Any]:
        """Mock authorization decision.
        
        Args:
            tool: Tool name being executed
            target: Target metadata (optional)
            claims: Token claims
            parameters: Operation parameters
            operation_tier: Operation tier
            dry_run: Whether this is a dry run
            
        Returns:
            Authorization result
        """
        # Record authorization attempt
        auth_attempt = {
            "tool": tool,
            "target": target.id if target else None,
            "claims": claims.agent,
            "parameters": parameters,
            "operation_tier": operation_tier,
            "dry_run": dry_run,
            "timestamp": self._get_timestamp()
        }
        self.authorization_history.append(auth_attempt)
        
        # Check configured responses
        target_id = target.id if target else "local"
        
        if (tool, target_id) in self.denied_operations:
            return {
                "authorized": False,
                "reason": f"Operation {tool} on {target_id} explicitly denied",
                "requires_approval": False,
                "dry_run_result": None
            }
        
        if (tool, target_id) in self.requires_approval:
            return {
                "authorized": True,
                "reason": "Operation requires approval",
                "requires_approval": True,
                "dry_run_result": None
            }
        
        if (tool, target_id) in self.allowed_operations or self.default_allow:
            # Simulate dry run if requested
            dry_run_result = None
            if dry_run:
                dry_run_result = {
                    "simulated": True,
                    "message": f"Dry run of {tool} on {target_id}",
                    "parameters_validated": True
                }
            
            return {
                "authorized": True,
                "reason": "Operation authorized",
                "requires_approval": False,
                "dry_run_result": dry_run_result
            }
        
        # Default deny if not explicitly configured
        return {
            "authorized": False,
            "reason": "Operation not explicitly allowed",
            "requires_approval": False,
            "dry_run_result": None
        }
    
    def allow_operation(self, tool: str, target_id: str = "local"):
        """Configure mock to allow specific operation.
        
        Args:
            tool: Tool name
            target_id: Target identifier
        """
        self.allowed_operations.append((tool, target_id))
    
    def deny_operation(self, tool: str, target_id: str = "local"):
        """Configure mock to deny specific operation.
        
        Args:
            tool: Tool name
            target_id: Target identifier
        """
        self.denied_operations.append((tool, target_id))
    
    def require_approval(self, tool: str, target_id: str = "local"):
        """Configure mock to require approval for specific operation.
        
        Args:
            tool: Tool name
            target_id: Target identifier
        """
        self.requires_approval.append((tool, target_id))
    
    def clear_history(self):
        """Clear authorization history."""
        self.authorization_history.clear()
    
    def get_authorization_count(self) -> int:
        """Get number of authorization attempts."""
        return len(self.authorization_history)
    
    def was_operation_authorized(self, tool: str, target_id: str = "local") -> bool:
        """Check if specific operation was authorized.
        
        Args:
            tool: Tool name
            target_id: Target identifier
            
        Returns:
            True if operation was authorized, False otherwise
        """
        for attempt in self.authorization_history:
            if (attempt["tool"] == tool and 
                attempt["target"] == target_id):
                # Find the corresponding result
                # This is simplified - in real implementation, we'd track results
                return (tool, target_id) in self.allowed_operations or self.default_allow
        
        return False
    
    def _get_timestamp(self) -> str:
        """Get current timestamp for logging."""
        from datetime import datetime
        return datetime.utcnow().isoformat()


class MockPolicyGateWithValidation(MockPolicyGate):
    """Mock Policy Gate with parameter validation capabilities."""
    
    def __init__(self, *args, **kwargs):
        """Initialize mock policy gate with validation."""
        super().__init__(*args, **kwargs)
        self.parameter_validations: List[Dict[str, Any]] = []
        self.validation_rules: Dict[str, Any] = {}
    
    def validate_parameters(self, 
                           tool: str,
                           parameters: Dict[str, Any],
                           target: Optional[TargetMetadata] = None) -> Dict[str, Any]:
        """Mock parameter validation.
        
        Args:
            tool: Tool name
            parameters: Parameters to validate
            target: Optional target metadata
            
        Returns:
            Validation result
        """
        validation_attempt = {
            "tool": tool,
            "target": target.id if target else None,
            "parameters": parameters,
            "timestamp": self._get_timestamp()
        }
        self.parameter_validations.append(validation_attempt)
        
        # Apply validation rules if configured
        if tool in self.validation_rules:
            rules = self.validation_rules[tool]
            errors = []
            
            for param_name, rule in rules.items():
                if param_name in parameters:
                    value = parameters[param_name]
                    
                    # Type validation
                    if "type" in rule and not isinstance(value, rule["type"]):
                        errors.append(f"Parameter {param_name} must be {rule['type']}")
                    
                    # Range validation
                    if "min" in rule and value < rule["min"]:
                        errors.append(f"Parameter {param_name} must be >= {rule['min']}")
                    
                    if "max" in rule and value > rule["max"]:
                        errors.append(f"Parameter {param_name} must be <= {rule['max']}")
                    
                    # Enum validation
                    if "allowed_values" in rule and value not in rule["allowed_values"]:
                        errors.append(f"Parameter {param_name} must be one of {rule['allowed_values']}")
            
            if errors:
                return {
                    "valid": False,
                    "errors": errors,
                    "warnings": []
                }
        
        return {
            "valid": True,
            "errors": [],
            "warnings": []
        }
    
    def set_validation_rule(self, tool: str, parameter: str, rule: Dict[str, Any]):
        """Set validation rule for specific tool parameter.
        
        Args:
            tool: Tool name
            parameter: Parameter name
            rule: Validation rule
        """
        if tool not in self.validation_rules:
            self.validation_rules[tool] = {}
        
        self.validation_rules[tool][parameter] = rule


def create_mock_policy_gate(default_allow: bool = True, 
                           validation_mode: ValidationMode = ValidationMode.STRICT) -> MockPolicyGate:
    """Factory function to create mock policy gates.
    
    Args:
        default_allow: Whether to allow operations by default
        validation_mode: Validation mode
        
    Returns:
        Configured mock policy gate
    """
    return MockPolicyGate(
        default_allow=default_allow,
        validation_mode=validation_mode
    )


def create_mock_policy_gate_with_validation(default_allow: bool = True,
                                           validation_mode: ValidationMode = ValidationMode.STRICT) -> MockPolicyGateWithValidation:
    """Factory function to create mock policy gates with validation.
    
    Args:
        default_allow: Whether to allow operations by default
        validation_mode: Validation mode
        
    Returns:
        Configured mock policy gate with validation
    """
    return MockPolicyGateWithValidation(
        default_allow=default_allow,
        validation_mode=validation_mode
    )


# Predefined policy gate configurations for common test scenarios
class PolicyGateConfigs:
    """Predefined policy gate configurations for testing."""
    
    @staticmethod
    def permissive() -> MockPolicyGate:
        """Create a permissive policy gate that allows all operations."""
        gate = create_mock_policy_gate(default_allow=True)
        return gate
    
    @staticmethod
    def restrictive() -> MockPolicyGate:
        """Create a restrictive policy gate that denies all operations."""
        gate = create_mock_policy_gate(default_allow=False)
        return gate
    
    @staticmethod
    def approval_required() -> MockPolicyGate:
        """Create a policy gate that requires approval for write operations."""
        gate = create_mock_policy_gate(default_allow=True)
        
        # Require approval for write operations
        write_tools = ["start_container", "stop_container", "create_container", 
                      "delete_container", "deploy_stack", "update_system"]
        
        for tool in write_tools:
            gate.require_approval(tool)
        
        return gate
    
    @staticmethod
    def target_specific() -> MockPolicyGate:
        """Create a policy gate with target-specific rules."""
        gate = create_mock_policy_gate(default_allow=False)
        
        # Allow specific operations on specific targets
        gate.allow_operation("get_container_status", "docker-host")
        gate.allow_operation("list_containers", "docker-host")
        gate.allow_operation("get_system_status", "local-host")
        gate.deny_operation("stop_container", "production-host")
        
        return gate
    
    @staticmethod
    def with_parameter_validation() -> MockPolicyGateWithValidation:
        """Create a policy gate with parameter validation."""
        gate = create_mock_policy_gate_with_validation()
        
        # Set validation rules for common tools
        gate.set_validation_rule("start_container", "container_id", {
            "type": str,
            "min_length": 1
        })
        
        gate.set_validation_rule("deploy_stack", "stack_name", {
            "type": str,
            "allowed_values": ["web", "db", "cache"]
        })
        
        gate.set_validation_rule("update_system", "package_count", {
            "type": int,
            "min": 0,
            "max": 100
        })
        
        return gate