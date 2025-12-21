"""
Policy Engine - Comprehensive Policy Evaluation and Enforcement

Provides comprehensive policy evaluation with deny-by-default security posture,
role-based access control, time-based restrictions, and policy inheritance.
"""

import logging
import re
from typing import Dict, List, Optional, Any
from datetime import datetime
from datetime import timezone, timezone, timezone, timezone, time
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

try:
    import json
except ImportError:
    json = None

from src.models.policy_models import (
    PolicyConfig,
    PolicyRule,
    PolicyContext,
    PolicyEvaluation,
    PolicyDecision,
    OperationType,
    TargetRole,
    TimeConstraint,
    PolicyHistory,
    create_default_policy_config,
    validate_policy_config,
)
from src.utils.audit import AuditLogger


logger = logging.getLogger(__name__)


class PolicyEvaluationContext:
    """Context for policy evaluation operations."""

    def __init__(
        self,
        operation_type: str,
        target_role: str,
        user_id: str,
        user_roles: Optional[List[str]] = None,
        target_metadata: Optional[Dict[str, Any]] = None,
        system_state: Optional[Dict[str, Any]] = None,
        environment: str = "production",
        compliance_mode: str = "standard",
    ):
        """Initialize policy evaluation context.

        Args:
            operation_type: Type of operation being evaluated
            target_role: Role of the target system
            user_id: ID of the user requesting the operation
            user_roles: List of user roles and permissions
            target_metadata: Metadata about the target system
            system_state: Current system state
            environment: Environment type (production, development, etc.)
            compliance_mode: Compliance mode level
        """
        self.operation_type = operation_type
        self.target_role = target_role
        self.user_id = user_id
        self.user_roles = user_roles or []
        self.target_metadata = target_metadata or {}
        self.system_state = system_state or {}
        self.environment = environment
        self.compliance_mode = compliance_mode
        self.timestamp = datetime.now(timezone.utc)


class PolicyEngine:
    """Comprehensive policy engine for evaluating operations against policies."""

    def __init__(
        self,
        config_path: Optional[str] = None,
        audit_logger: Optional[AuditLogger] = None,
        enable_caching: bool = True,
    ):
        """Initialize policy engine.

        Args:
            config_path: Path to policy configuration file
            audit_logger: Audit logger for policy decisions
            enable_caching: Whether to enable policy caching
        """
        self.config_path = config_path
        self.audit_logger = audit_logger
        self.enable_caching = enable_caching

        # Policy storage
        self.current_config: Optional[PolicyConfig] = None
        self.policy_cache: Dict[str, Any] = {}
        self.policy_history: List[PolicyHistory] = []

        # Load initial configuration
        self._load_policy_config()

        # Initialize policy evaluation helpers
        self._compile_patterns()

    def _load_policy_config(self):
        """Load policy configuration from file or create default."""
        try:
            if self.config_path and Path(self.config_path).exists():
                self.current_config = self._load_config_from_file(self.config_path)
                logger.info(f"Loaded policy configuration from {self.config_path}")
            else:
                self.current_config = create_default_policy_config()
                logger.info("Using default policy configuration")

                # Save default config if path provided
                if self.config_path:
                    self._save_config_to_file(self.current_config, self.config_path)
        except Exception as e:
            logger.error(f"Failed to load policy configuration: {e}")
            self.current_config = create_default_policy_config()

    def _load_config_from_file(self, config_path: str) -> PolicyConfig:
        """Load policy configuration from file."""
        config_path = Path(config_path)

        with open(config_path, "r") as f:
            if config_path.suffix.lower() in [".yaml", ".yml"]:
                if yaml:
                    data = yaml.safe_load(f)
                else:
                    raise ImportError("PyYAML not available for YAML file loading")
            else:
                if json:
                    data = json.load(f)
                else:
                    raise ImportError("json module not available")

        return PolicyConfig(**data)

    def _save_config_to_file(self, config: PolicyConfig, config_path: str):
        """Save policy configuration to file."""
        config_path = Path(config_path)
        config_path.parent.mkdir(parents=True, exist_ok=True)

        with open(config_path, "w") as f:
            if config_path.suffix.lower() in [".yaml", ".yml"]:
                if yaml:
                    yaml.dump(config.dict(), f, default_flow_style=False, indent=2)
                else:
                    raise ImportError("PyYAML not available for YAML file saving")
            else:
                if json:
                    json.dump(config.dict(), f, indent=2)
                else:
                    raise ImportError("json module not available")

    def _compile_patterns(self):
        """Compile regex patterns for efficient matching."""
        self.compiled_patterns: Dict[str, re.Pattern] = {}

        if not self.current_config:
            return

        # Compile target patterns from all rules
        for rule in self._get_all_rules():
            if rule.target_patterns:
                for pattern in rule.target_patterns:
                    try:
                        self.compiled_patterns[pattern] = re.compile(pattern)
                    except re.error as e:
                        logger.warning(f"Invalid regex pattern '{pattern}': {e}")

    def _get_all_rules(self) -> List[PolicyRule]:
        """Get all policy rules (global + role-based + emergency)."""
        if not self.current_config:
            return []

        all_rules = []
        all_rules.extend(self.current_config.global_policies)

        for role_rules in self.current_config.role_policies.values():
            all_rules.extend(role_rules)

        all_rules.extend(self.current_config.emergency_policies)

        return all_rules

    async def evaluate_operation(
        self, operation: Any, context: PolicyContext
    ) -> PolicyEvaluation:
        """Evaluate an operation against current policies.

        Args:
            operation: Operation to evaluate
            context: Policy evaluation context

        Returns:
            Policy evaluation result
        """
        start_time = datetime.now(timezone.utc)

        try:
            # Generate cache key
            cache_key = self._generate_cache_key(operation, context)

            # Check cache first
            if self.enable_caching and cache_key in self.policy_cache:
                cached_result = self.policy_cache[cache_key]
                logger.debug(f"Using cached policy evaluation for {cache_key}")
                return cached_result

            # Get applicable rules
            applicable_rules = self._get_applicable_rules(operation, context)

            # Evaluate rules in order
            evaluation_result = self._evaluate_rules(
                operation, context, applicable_rules
            )

            # Apply global settings
            evaluation_result = self._apply_global_settings(evaluation_result, context)

            # Cache result
            if self.enable_caching:
                self.policy_cache[cache_key] = evaluation_result

            # Audit the evaluation
            await self._audit_evaluation(operation, context, evaluation_result)

            return evaluation_result

        except Exception as e:
            logger.error(f"Policy evaluation failed: {e}", exc_info=True)
            return PolicyEvaluation(
                decision=PolicyDecision.DENY,
                reason=f"Policy evaluation error: {str(e)}",
                audit_context={"error": str(e), "timestamp": start_time.isoformat()},
            )

    def _generate_cache_key(self, operation: Any, context: PolicyContext) -> str:
        """Generate cache key for policy evaluation."""
        key_parts = [
            str(operation.capability)
            if hasattr(operation, "capability")
            else str(operation),
            context.target_role.value,
            context.user_id,
            context.current_time.strftime("%Y-%m-%d-%H"),  # Hour-based caching
            str(sorted(context.user_roles)) if context.user_roles else "",
            "emergency" if context.emergency_mode else "normal",
            "maintenance" if context.maintenance_mode else "normal",
        ]
        return "|".join(key_parts)

    def _get_applicable_rules(
        self, operation: Any, context: PolicyContext
    ) -> List[PolicyRule]:
        """Get rules that apply to the operation and context."""
        if not self.current_config:
            return []

        applicable_rules = []

        # Check emergency rules first (highest priority)
        for rule in self.current_config.emergency_policies:
            if self._rule_applies(rule, operation, context):
                applicable_rules.append(("emergency", rule))

        # Check role-based rules
        role_rules = self.current_config.role_policies.get(context.target_role, [])
        for rule in role_rules:
            if self._rule_applies(rule, operation, context):
                applicable_rules.append(("role", rule))

        # Check global rules
        for rule in self.current_config.global_policies:
            if self._rule_applies(rule, operation, context):
                applicable_rules.append(("global", rule))

        # Sort by priority: emergency > role > global
        priority_order = {"emergency": 0, "role": 1, "global": 2}
        applicable_rules.sort(key=lambda x: priority_order[x[0]])

        return [rule for _, rule in applicable_rules]

    def _rule_applies(
        self, rule: PolicyRule, operation: Any, context: PolicyContext
    ) -> bool:
        """Check if a rule applies to the operation and context."""
        # Check if rule is enabled
        if not rule.enabled:
            return False

        # Check if operation is in rule's operations
        if hasattr(operation, "capability"):
            operation_type = operation.capability
        else:
            operation_type = operation  # Assume operation is already OperationType

        if operation_type not in rule.operations:
            return False

        # Check target role
        if context.target_role not in rule.target_roles:
            return False

        # Check target patterns
        if rule.target_patterns and context.target_metadata:
            target_id = context.target_metadata.get("id", "")
            if not any(
                pattern.match(target_id)
                for pattern in [
                    self.compiled_patterns.get(p, re.compile(p))
                    for p in rule.target_patterns
                ]
            ):
                return False

        # Check time restrictions
        if rule.time_restrictions:
            current_time = context.current_time
            if not self._check_time_restrictions(rule.time_restrictions, current_time):
                return False

        # Check maintenance window restrictions
        if rule.maintenance_windows_only and not context.maintenance_mode:
            return False

        return True

    def _check_time_restrictions(
        self, time_constraints: List[TimeConstraint], current_time: datetime
    ) -> bool:
        """Check if current time satisfies time constraints."""
        current_time_obj = current_time.time()
        current_weekday = current_time.weekday()  # 0 = Monday, 6 = Sunday

        for constraint in time_constraints:
            # Check day of week
            if current_weekday not in constraint.days_of_week:
                continue

            # Check time range
            start_time_obj = time.fromisoformat(constraint.start_time)
            end_time_obj = time.fromisoformat(constraint.end_time)

            # Handle overnight ranges (e.g., 22:00 to 06:00)
            if start_time_obj <= end_time_obj:
                if start_time_obj <= current_time_obj <= end_time_obj:
                    return True
            else:  # Overnight range
                if (
                    current_time_obj >= start_time_obj
                    or current_time_obj <= end_time_obj
                ):
                    return True

        return False

    def _evaluate_rules(
        self, operation: Any, context: PolicyContext, applicable_rules: List[PolicyRule]
    ) -> PolicyEvaluation:
        """Evaluate applicable rules to make a decision."""
        matched_rules = []
        required_approvals = []
        time_constraints = []
        parameter_validations = {}

        # Evaluate each rule in priority order
        for rule in applicable_rules:
            matched_rules.append(rule.id)

            # Collect time constraints
            if rule.time_restrictions:
                time_constraints.extend(rule.time_restrictions)

            # Check parameter constraints
            if hasattr(operation, "parameters") and rule.parameter_constraints:
                param_validation = self._validate_parameters(
                    operation.parameters, rule.parameter_constraints
                )
                parameter_validations.update(param_validation)

            # First matching rule determines the decision
            if rule.allowed:
                if rule.requires_approval:
                    required_approvals.append(rule.name)
                else:
                    # Allow operation
                    return PolicyEvaluation(
                        decision=PolicyDecision.ALLOW,
                        reason=f"Operation allowed by rule: {rule.name}",
                        matched_rules=matched_rules,
                        required_approvals=required_approvals,
                        time_constraints=time_constraints,
                        parameter_validations=parameter_validations,
                    )
            else:
                # Deny operation
                return PolicyEvaluation(
                    decision=PolicyDecision.DENY,
                    reason=f"Operation denied by rule: {rule.name}",
                    matched_rules=matched_rules,
                    required_approvals=required_approvals,
                    time_constraints=time_constraints,
                    parameter_validations=parameter_validations,
                )

        # No matching rules found
        if self.current_config and self.current_config.deny_by_default:
            return PolicyEvaluation(
                decision=PolicyDecision.DENY,
                reason="No matching policy rule found (deny by default)",
                matched_rules=matched_rules,
                required_approvals=required_approvals,
                time_constraints=time_constraints,
                parameter_validations=parameter_validations,
            )
        else:
            return PolicyEvaluation(
                decision=PolicyDecision.ALLOW,
                reason="No matching policy rule found (allow by default)",
                matched_rules=matched_rules,
                required_approvals=required_approvals,
                time_constraints=time_constraints,
                parameter_validations=parameter_validations,
            )

    def _validate_parameters(
        self, parameters: Dict[str, Any], constraints: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Validate operation parameters against rule constraints."""
        validations = {}

        for param_name, param_value in parameters.items():
            if param_name in constraints:
                constraint = constraints[param_name]
                validation_result = {"valid": True, "errors": [], "warnings": []}

                # Type validation
                expected_type = constraint.get("type", "string")
                if not self._check_parameter_type(param_value, expected_type):
                    validation_result["valid"] = False
                    validation_result["errors"].append(
                        f"Invalid type: expected {expected_type}"
                    )

                # String validations
                if expected_type == "string":
                    if (
                        "max_length" in constraint
                        and len(str(param_value)) > constraint["max_length"]
                    ):
                        validation_result["valid"] = False
                        validation_result["errors"].append(
                            f"Exceeds maximum length: {constraint['max_length']}"
                        )

                    if "pattern" in constraint:
                        pattern = constraint["pattern"]
                        if not re.match(pattern, str(param_value)):
                            validation_result["valid"] = False
                            validation_result["errors"].append(
                                f"Does not match pattern: {pattern}"
                            )

                # Numeric validations
                elif expected_type in ["int", "float"]:
                    if "min" in constraint and param_value < constraint["min"]:
                        validation_result["valid"] = False
                        validation_result["errors"].append(
                            f"Below minimum value: {constraint['min']}"
                        )

                    if "max" in constraint and param_value > constraint["max"]:
                        validation_result["valid"] = False
                        validation_result["errors"].append(
                            f"Above maximum value: {constraint['max']}"
                        )

                # List validations
                elif expected_type == "list":
                    if (
                        "allowed_values" in constraint
                        and param_value not in constraint["allowed_values"]
                    ):
                        validation_result["valid"] = False
                        validation_result["errors"].append(
                            f"Not in allowed values: {constraint['allowed_values']}"
                        )

                validations[param_name] = validation_result

        return validations

    def _check_parameter_type(self, value: Any, expected_type: str) -> bool:
        """Check if parameter value matches expected type."""
        type_map = {
            "string": str,
            "int": int,
            "float": float,
            "bool": bool,
            "list": list,
            "dict": dict,
        }

        expected_python_type = type_map.get(expected_type, str)
        return isinstance(value, expected_python_type)

    def _apply_global_settings(
        self, evaluation: PolicyEvaluation, context: PolicyContext
    ) -> PolicyEvaluation:
        """Apply global policy settings to evaluation result."""
        if not self.current_config:
            return evaluation

        # Check emergency mode
        if context.emergency_mode and self.current_config.emergency_policies:
            # In emergency mode, apply most permissive emergency policy
            for rule in self.current_config.emergency_policies:
                if rule.enabled:
                    return PolicyEvaluation(
                        decision=PolicyDecision.ALLOW,
                        reason="Emergency mode override",
                        matched_rules=evaluation.matched_rules + [rule.id],
                        required_approvals=[],
                        time_constraints=evaluation.time_constraints,
                        parameter_validations=evaluation.parameter_validations,
                    )

        # Check if dry run is enforced
        if (
            self.current_config.enable_dry_run
            and evaluation.decision == PolicyDecision.ALLOW
            and context.operation.dry_run
        ):
            return PolicyEvaluation(
                decision=PolicyDecision.DRY_RUN_ONLY,
                reason="Operation restricted to dry-run only",
                matched_rules=evaluation.matched_rules,
                required_approvals=evaluation.required_approvals,
                time_constraints=evaluation.time_constraints,
                parameter_validations=evaluation.parameter_validations,
            )

        return evaluation

    async def _audit_evaluation(
        self, operation: Any, context: PolicyContext, evaluation: PolicyEvaluation
    ):
        """Audit policy evaluation decisions."""
        if not self.audit_logger:
            return

        audit_data = {
            "evaluation_id": f"eval_{datetime.now().timestamp()}",
            "operation_type": str(operation.capability)
            if hasattr(operation, "capability")
            else str(operation),
            "target_role": context.target_role.value,
            "user_id": context.user_id,
            "decision": evaluation.decision.value,
            "reason": evaluation.reason,
            "matched_rules": evaluation.matched_rules,
            "required_approvals": evaluation.required_approvals,
            "emergency_mode": context.emergency_mode,
            "maintenance_mode": context.maintenance_mode,
            "environment": context.environment,
        }

        await self.audit_logger.log_event(
            event_type="policy_evaluation", event_data=audit_data, severity="info"
        )

    def update_policy_config(
        self,
        new_config: PolicyConfig,
        changed_by: str,
        change_reason: Optional[str] = None,
    ) -> bool:
        """Update policy configuration with validation and history tracking.

        Args:
            new_config: New policy configuration
            changed_by: User making the change
            change_reason: Reason for the change

        Returns:
            True if update was successful
        """
        try:
            # Validate new configuration
            validation_result = validate_policy_config(new_config)
            if not validation_result.is_valid:
                logger.error(
                    f"Policy configuration validation failed: {validation_result.errors}"
                )
                return False

            # Create history entry for the change
            old_config_dict = self.current_config.dict() if self.current_config else {}
            new_config_dict = new_config.dict()

            history_entry = PolicyHistory(
                policy_id=new_config.id,
                change_type="update",
                changes={
                    "before": old_config_dict,
                    "after": new_config_dict,
                    "validation_errors": validation_result.errors,
                    "validation_warnings": validation_result.warnings,
                },
                changed_by=changed_by,
                change_reason=change_reason,
                rollback_data=old_config_dict,
            )

            # Update configuration
            self.current_config = new_config
            self.policy_cache.clear()  # Clear cache on config change

            # Add to history
            self.policy_history.append(history_entry)

            # Recompile patterns
            self._compile_patterns()

            logger.info(f"Policy configuration updated by {changed_by}")
            return True

        except Exception as e:
            logger.error(f"Failed to update policy configuration: {e}")
            return False

    def rollback_policy(self, history_entry_id: str, rolled_back_by: str) -> bool:
        """Rollback policy configuration to a previous version.

        Args:
            history_entry_id: ID of history entry to rollback to
            rolled_back_by: User performing the rollback

        Returns:
            True if rollback was successful
        """
        try:
            # Find history entry
            history_entry = None
            for entry in self.policy_history:
                if entry.id == history_entry_id:
                    history_entry = entry
                    break

            if not history_entry or history_entry.change_type != "update":
                logger.error(
                    f"History entry not found or not an update: {history_entry_id}"
                )
                return False

            if not history_entry.rollback_data:
                logger.error(
                    f"No rollback data available for history entry: {history_entry_id}"
                )
                return False

            # Restore previous configuration
            from src.models.policy_models import PolicyConfig

            old_config = PolicyConfig(**history_entry.rollback_data)

            # Create rollback history entry
            rollback_entry = PolicyHistory(
                policy_id=old_config.id,
                change_type="rollback",
                changes={
                    "rolled_back_from": self.current_config.dict()
                    if self.current_config
                    else {},
                    "rolled_back_to": old_config.dict(),
                    "original_change": history_entry.changes,
                },
                changed_by=rolled_back_by,
                change_reason=f"Rollback of change {history_entry_id}",
            )

            # Apply rollback
            self.current_config = old_config
            self.policy_cache.clear()
            self._compile_patterns()
            self.policy_history.append(rollback_entry)

            logger.info(f"Policy configuration rolled back by {rolled_back_by}")
            return True

        except Exception as e:
            logger.error(f"Failed to rollback policy configuration: {e}")
            return False

    def get_policy_status(self) -> Dict[str, Any]:
        """Get current policy configuration status."""
        if not self.current_config:
            return {"status": "no_config", "message": "No policy configuration loaded"}

        return {
            "status": "active",
            "config_id": self.current_config.id,
            "name": self.current_config.name,
            "version": self.current_config.version.value,
            "enabled": self.current_config.enabled,
            "deny_by_default": self.current_config.deny_by_default,
            "enable_dry_run": self.current_config.enable_dry_run,
            "total_rules": len(self._get_all_rules()),
            "global_rules": len(self.current_config.global_policies),
            "emergency_rules": len(self.current_config.emergency_policies),
            "role_policies": {
                role.value: len(rules)
                for role, rules in self.current_config.role_policies.items()
            },
            "cache_size": len(self.policy_cache),
            "last_updated": self.current_config.updated_at.isoformat()
            if self.current_config.updated_at
            else None,
        }

    def list_allowed_operations(
        self, target_role: TargetRole, user_id: Optional[str] = None
    ) -> List[OperationType]:
        """List operations allowed for a target role and user.

        Args:
            target_role: Target role to check
            user_id: User ID to check permissions for

        Returns:
            List of allowed operation types
        """
        if not self.current_config:
            return []

        allowed_operations = set()

        # Check all applicable rules
        for rule in self._get_all_rules():
            if target_role in rule.target_roles and rule.enabled and rule.allowed:
                allowed_operations.update(rule.operations)

        return list(allowed_operations)

    def simulate_policy_scenario(
        self, operation: Any, context: PolicyContext
    ) -> Dict[str, Any]:
        """Simulate policy evaluation without executing operation.

        Args:
            operation: Operation to simulate
            context: Simulation context

        Returns:
            Simulation results with detailed analysis
        """
        import asyncio

        # Run evaluation in sync mode for simulation
        evaluation = asyncio.run(self.evaluate_operation(operation, context))

        # Analyze which rules matched
        applicable_rules = self._get_applicable_rules(operation, context)

        rule_analysis = []
        for rule in applicable_rules:
            rule_analysis.append(
                {
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "applies": True,
                    "allows": rule.allowed,
                    "requires_approval": rule.requires_approval,
                    "time_restrictions": len(rule.time_restrictions)
                    if rule.time_restrictions
                    else 0,
                    "parameter_constraints": len(rule.parameter_constraints),
                }
            )

        return {
            "decision": evaluation.decision.value,
            "reason": evaluation.reason,
            "applicable_rules": rule_analysis,
            "matched_rules": evaluation.matched_rules,
            "required_approvals": evaluation.required_approvals,
            "time_constraints": len(evaluation.time_constraints),
            "parameter_validations": evaluation.parameter_validations,
            "simulation_timestamp": datetime.now(timezone.utc).isoformat(),
        }
