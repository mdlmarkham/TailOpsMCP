"""
Policy-as-Code + Auditing System Integration

Integrates the new Policy-as-Code system with existing policy gate and security systems.
"""

import time
import logging
from typing import Dict, Any, List, Optional, Tuple

from src.services.policy_as_code import PolicyAsCodeManager, TargetConfig
from src.utils.audit_enhanced import StructuredAuditLogger
from src.services.policy_gate import PolicyGate
from src.services.target_registry import TargetRegistry
from src.utils.audit import AuditLogger

logger = logging.getLogger(__name__)


class PolicyAsCodeIntegration:
    """Integration layer between Policy-as-Code system and existing policy gate."""

    def __init__(self, config_dir: str = "config"):
        self.policy_manager = PolicyAsCodeManager(config_dir)
        self.audit_logger = StructuredAuditLogger()

        # Initialize existing policy gate with enhanced capabilities
        self.target_registry = TargetRegistry()
        self.legacy_audit_logger = AuditLogger()
        self.policy_gate = PolicyGate(self.target_registry, self.legacy_audit_logger)

        # Register targets from Policy-as-Code configuration
        self._register_targets_from_config()

        # Enhance policy gate with Policy-as-Code rules
        self._enhance_policy_gate()

    def _register_targets_from_config(self):
        """Register targets from Policy-as-Code configuration."""
        config = self.policy_manager.config

        for target_config in config.targets:
            try:
                # Convert TargetConfig to TargetMetadata format
                target_metadata = {
                    "id": target_config.id,
                    "host": target_config.host,
                    "tags": target_config.tags,
                    "roles": target_config.roles,
                    "capabilities": target_config.capabilities,
                    "description": target_config.description,
                    "connection_method": target_config.connection_method.value,
                }

                # Register target with existing registry
                self.target_registry.add_target(target_metadata)

                logger.info(
                    f"Registered target from Policy-as-Code config: {target_config.id}"
                )

            except Exception as e:
                logger.error(f"Failed to register target {target_config.id}: {e}")

    def _enhance_policy_gate(self):
        """Enhance existing policy gate with Policy-as-Code rules."""
        config = self.policy_manager.config

        # Convert PolicyRule objects to policy gate format
        for policy_rule in config.rules:
            if policy_rule.name == "default_deny":
                # Skip default deny rule as policy gate already implements deny-by-default
                continue

            # Create policy gate compatible rule
            gate_rule = {
                "name": policy_rule.name,
                "description": policy_rule.description,
                "target_pattern": policy_rule.target_pattern,
                "allowed_operations": policy_rule.allowed_operations,
                "required_capabilities": policy_rule.required_capabilities,
                "parameter_constraints": policy_rule.parameter_constraints,
                "operation_tier": policy_rule.operation_tier.value,
                "requires_approval": policy_rule.requires_approval,
                "dry_run_supported": policy_rule.dry_run_supported,
            }

            # Add rule to policy gate configuration
            self.policy_gate.policy_config.rules.append(gate_rule)

    async def authorize_operation(
        self,
        actor: str,
        target_id: str,
        operation: str,
        parameters: Dict[str, Any],
        dry_run: bool = False,
    ) -> Tuple[bool, List[str], Optional[str]]:
        """Authorize operation using both Policy-as-Code and existing policy gate."""

        start_time = time.time()

        # Step 1: Policy-as-Code validation (deny-by-default)
        policy_errors = self.policy_manager.validate_operation(
            target_id, operation, parameters
        )

        if policy_errors:
            (time.time() - start_time) * 1000
            self.audit_logger.log_policy_decision(
                actor=actor,
                target=target_id,
                operation=operation,
                parameters=parameters,
                authorized=False,
                policy_rule="default_deny",
                validation_errors=policy_errors,
            )
            return False, policy_errors, "default_deny"

        # Step 2: Existing policy gate validation
        # Create mock claims for compatibility
        from src.auth.token_auth import TokenClaims

        claims = TokenClaims(agent=actor, scopes=["system:read"])  # Default scopes

        authorized, validation_errors = self.policy_gate.enforce_policy(
            tool_name="policy_as_code",
            target_id=target_id,
            operation=operation,
            parameters=parameters,
            claims=claims,
            dry_run=dry_run,
        )

        # Find matching policy rule for audit logging
        matching_rule = self.policy_gate.get_matching_policy_rule(
            "policy_as_code", target_id, operation
        )
        policy_rule_name = matching_rule.name if matching_rule else "unknown"

        (time.time() - start_time) * 1000

        # Log policy decision
        self.audit_logger.log_policy_decision(
            actor=actor,
            target=target_id,
            operation=operation,
            parameters=parameters,
            authorized=authorized,
            policy_rule=policy_rule_name,
            validation_errors=validation_errors,
        )

        return authorized, validation_errors, policy_rule_name

    async def execute_remote_operation(
        self, actor: str, target_id: str, operation: str, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a remote operation with full policy enforcement and audit logging."""

        start_time = time.time()

        # Step 1: Authorization check
        authorized, validation_errors, policy_rule = await self.authorize_operation(
            actor, target_id, operation, parameters
        )

        if not authorized:
            duration_ms = (time.time() - start_time) * 1000
            result = {
                "success": False,
                "error": f"Operation not authorized: {validation_errors}",
                "authorized": False,
            }

            self.audit_logger.log_remote_operation(
                actor=actor,
                target=target_id,
                operation=operation,
                parameters=parameters,
                result=result,
                duration_ms=duration_ms,
                authorized=False,
                policy_rule=policy_rule,
                validation_errors=validation_errors,
            )

            return result

        # Step 2: Execute operation through policy-gated executor
        try:
            from src.services.executor_factory import ExecutorFactory

            executor_factory = ExecutorFactory()

            # Get target metadata
            target = self.target_registry.get_target(target_id)
            if not target:
                raise ValueError(f"Target not found: {target_id}")

            # Create executor for target
            executor = executor_factory.create_executor(target)

            # Execute operation
            operation_result = await executor.execute_operation(operation, parameters)

            duration_ms = (time.time() - start_time) * 1000

            # Step 3: Audit log the operation
            self.audit_logger.log_remote_operation(
                actor=actor,
                target=target_id,
                operation=operation,
                parameters=parameters,
                result=operation_result,
                duration_ms=duration_ms,
                authorized=True,
                policy_rule=policy_rule,
                validation_errors=[],
            )

            return {
                "success": True,
                "result": operation_result,
                "authorized": True,
                "duration_ms": duration_ms,
            }

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000

            result = {
                "success": False,
                "error": str(e),
                "authorized": True,  # Was authorized but execution failed
            }

            self.audit_logger.log_remote_operation(
                actor=actor,
                target=target_id,
                operation=operation,
                parameters=parameters,
                result=result,
                duration_ms=duration_ms,
                authorized=True,
                policy_rule=policy_rule,
                validation_errors=[str(e)],
            )

            return result

    def get_allowed_operations(self, target_id: str) -> List[str]:
        """Get all allowed operations for a target."""
        return list(self.policy_manager.get_allowed_operations(target_id))

    def get_target_config(self, target_id: str) -> Optional[TargetConfig]:
        """Get target configuration."""
        config = self.policy_manager.config
        for target in config.targets:
            if target.id == target_id:
                return target
        return None

    def get_audit_statistics(self) -> Dict[str, Any]:
        """Get audit log statistics."""
        return self.audit_logger.get_statistics()

    def search_audit_logs(self, **filters) -> List[Dict[str, Any]]:
        """Search audit logs with filtering."""
        entries = self.audit_logger.search_audit_logs(**filters)

        # Convert to dict for easier serialization
        return [
            {
                "timestamp": entry.timestamp,
                "event_type": entry.event_type.value,
                "actor": entry.actor,
                "target": entry.target,
                "operation": entry.operation,
                "parameters": entry.parameters,
                "result_hash": entry.result_hash,
                "duration_ms": entry.duration_ms,
                "authorized": entry.authorized,
                "policy_rule": entry.policy_rule,
                "validation_errors": entry.validation_errors,
            }
            for entry in entries
        ]


# Global instance for easy access
policy_as_code_integration = PolicyAsCodeIntegration()
