"""
Target Registry loader with schema validation and configuration management.

Extended to support gateway mode operations and gateway-specific configuration.
"""

import json
import os
import yaml
from pathlib import Path
from typing import Dict, List, Optional

from src.models.target_registry import TargetMetadata
from src.models.gateway_models import GatewayMetadata


class TargetRegistry:
    """Target Registry loader and manager.

    Loads and validates target configurations from YAML/JSON files,
    provides access to target metadata, and supports dynamic discovery.
    Extended to support gateway mode operations.
    """

    def __init__(self, config_path: Optional[str] = None):
        """Initialize Target Registry.

        Args:
            config_path: Path to target registry configuration file.
                        Defaults to environment variable or standard location.
        """
        # Default configuration path
        if os.path.exists("/var/lib/systemmanager"):
            default_path = "/var/lib/systemmanager/targets.yaml"
        else:
            default_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)), "targets.yaml"
            )

        self.config_path = config_path or os.getenv(
            "SYSTEMMANAGER_TARGETS_CONFIG", default_path
        )
        self._targets: Dict[str, TargetMetadata] = {}
        self._gateway_metadata: Optional[GatewayMetadata] = None
        self._errors: List[str] = []

        # Load configuration on initialization
        self.load()

    def load(self) -> bool:
        """Load target registry configuration from file.

        Returns:
            True if configuration loaded successfully, False otherwise.
        """
        self._errors.clear()

        if not os.path.exists(self.config_path):
            self._errors.append(f"Configuration file not found: {self.config_path}")
            return False

        try:
            # Determine file type and load accordingly
            path = Path(self.config_path)
            if path.suffix.lower() in [".yaml", ".yml"]:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    config_data = yaml.safe_load(f)
            else:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    config_data = json.load(f)

            # Validate top-level structure
            if not isinstance(config_data, dict):
                self._errors.append("Configuration must be a dictionary")
                return False

            if "version" not in config_data:
                self._errors.append("Configuration missing 'version' field")
                return False

            if "targets" not in config_data:
                self._errors.append("Configuration missing 'targets' field")
                return False

            # Load gateway configuration if present
            if "gateway" in config_data:
                try:
                    self._gateway_metadata = GatewayMetadata.from_dict(
                        config_data["gateway"]
                    )
                    gateway_errors = self._gateway_metadata.validate()
                    if gateway_errors:
                        self._errors.extend(
                            [f"gateway: {error}" for error in gateway_errors]
                        )
                except Exception as e:
                    self._errors.append(
                        f"Failed to parse gateway configuration: {str(e)}"
                    )

            # Load and validate targets
            self._targets = {}
            for target_id, target_data in config_data["targets"].items():
                try:
                    target = TargetMetadata.from_dict(target_data)
                    validation_errors = target.validate()

                    if validation_errors:
                        self._errors.extend(
                            [f"{target_id}: {error}" for error in validation_errors]
                        )
                    else:
                        self._targets[target_id] = target
                except Exception as e:
                    self._errors.append(
                        f"{target_id}: Failed to parse target - {str(e)}"
                    )

            return len(self._errors) == 0

        except Exception as e:
            self._errors.append(f"Failed to load configuration: {str(e)}")
            return False

    def get_target(self, target_id: str) -> Optional[TargetMetadata]:
        """Get target metadata by ID.

        Args:
            target_id: Target identifier.

        Returns:
            TargetMetadata if found, None otherwise.
        """
        return self._targets.get(target_id)

    def list_targets(self) -> Dict[str, TargetMetadata]:
        """Get all registered targets.

        Returns:
            Dictionary mapping target IDs to TargetMetadata.
        """
        return self._targets.copy()

    def get_targets_by_type(self, target_type: str) -> Dict[str, TargetMetadata]:
        """Get targets filtered by type.

        Args:
            target_type: Target type filter ('local' or 'remote').

        Returns:
            Dictionary of matching targets.
        """
        return {
            target_id: target
            for target_id, target in self._targets.items()
            if target.type == target_type
        }

    def get_targets_by_executor(self, executor: str) -> Dict[str, TargetMetadata]:
        """Get targets filtered by executor type.

        Args:
            executor: Executor type filter.

        Returns:
            Dictionary of matching targets.
        """
        return {
            target_id: target
            for target_id, target in self._targets.items()
            if target.executor.value == executor
        }

    def add_target(self, target: TargetMetadata) -> bool:
        """Add a new target to the registry.

        Args:
            target: TargetMetadata to add.

        Returns:
            True if target added successfully, False otherwise.
        """
        validation_errors = target.validate()
        if validation_errors:
            self._errors.extend(validation_errors)
            return False

        if target.id in self._targets:
            self._errors.append(f"Target ID already exists: {target.id}")
            return False

        self._targets[target.id] = target
        return True

    def remove_target(self, target_id: str) -> bool:
        """Remove a target from the registry.

        Args:
            target_id: Target identifier to remove.

        Returns:
            True if target removed successfully, False otherwise.
        """
        if target_id not in self._targets:
            self._errors.append(f"Target not found: {target_id}")
            return False

        del self._targets[target_id]
        return True

    def save(self) -> bool:
        """Save current target registry to configuration file.

        Returns:
            True if saved successfully, False otherwise.
        """
        try:
            config_data = {
                "version": "1.0",
                "targets": {
                    target_id: target.to_dict()
                    for target_id, target in self._targets.items()
                },
            }

            # Add gateway configuration if present
            if self._gateway_metadata:
                config_data["gateway"] = self._gateway_metadata.to_dict()

            # Ensure directory exists
            os.makedirs(os.path.dirname(self.config_path) or ".", exist_ok=True)

            # Save based on file extension
            path = Path(self.config_path)
            if path.suffix.lower() in [".yaml", ".yml"]:
                with open(self.config_path, "w", encoding="utf-8") as f:
                    yaml.dump(config_data, f, default_flow_style=False, indent=2)
            else:
                with open(self.config_path, "w", encoding="utf-8") as f:
                    json.dump(config_data, f, indent=2, ensure_ascii=False)

            return True

        except Exception as e:
            self._errors.append(f"Failed to save configuration: {str(e)}")
            return False

    # Gateway-specific methods
    def get_gateway_metadata(self) -> Optional[GatewayMetadata]:
        """Get gateway metadata if configured.

        Returns:
            GatewayMetadata if gateway mode is configured, None otherwise.
        """
        return self._gateway_metadata

    def set_gateway_metadata(self, gateway_metadata: GatewayMetadata) -> bool:
        """Set gateway metadata.

        Args:
            gateway_metadata: GatewayMetadata to set.

        Returns:
            True if set successfully, False otherwise.
        """
        validation_errors = gateway_metadata.validate()
        if validation_errors:
            self._errors.extend(validation_errors)
            return False

        self._gateway_metadata = gateway_metadata
        return True

    def is_gateway_mode(self) -> bool:
        """Check if target registry is operating in gateway mode.

        Returns:
            True if gateway mode is configured and active, False otherwise.
        """
        if not self._gateway_metadata:
            return False

        return self._gateway_metadata.is_gateway_mode()

    def get_managed_targets(self) -> List[str]:
        """Get list of managed target IDs in gateway mode.

        Returns:
            List of target IDs managed by this gateway.
        """
        if not self.is_gateway_mode() or not self._gateway_metadata:
            return []

        return self._gateway_metadata.managed_targets.copy()

    def add_managed_target(self, target_id: str) -> bool:
        """Add a target to managed targets list in gateway mode.

        Args:
            target_id: Target ID to add to managed targets.

        Returns:
            True if target added successfully, False otherwise.
        """
        if not self.is_gateway_mode() or not self._gateway_metadata:
            self._errors.append("Cannot add managed target: not in gateway mode")
            return False

        return self._gateway_metadata.add_managed_target(target_id)

    def remove_managed_target(self, target_id: str) -> bool:
        """Remove a target from managed targets list in gateway mode.

        Args:
            target_id: Target ID to remove from managed targets.

        Returns:
            True if target removed successfully, False otherwise.
        """
        if not self.is_gateway_mode() or not self._gateway_metadata:
            self._errors.append("Cannot remove managed target: not in gateway mode")
            return False

        return self._gateway_metadata.remove_managed_target(target_id)

    def can_manage_target(self, target_id: str) -> bool:
        """Check if this gateway can manage the specified target.

        Args:
            target_id: Target ID to check.

        Returns:
            True if target can be managed, False otherwise.
        """
        if not self.is_gateway_mode() or not self._gateway_metadata:
            return False

        return self._gateway_metadata.can_manage_target(target_id)

    def get_errors(self) -> List[str]:
        """Get current validation errors.

        Returns:
            List of error messages.
        """
        return self._errors.copy()

    def clear_errors(self) -> None:
        """Clear current validation errors."""
        self._errors.clear()
