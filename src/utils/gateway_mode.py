"""
Gateway mode detection and configuration utilities.

Provides environment-based mode detection and gateway-specific configuration
management for the SystemManager control plane.
"""

import os
import logging
from typing import Optional

from src.models.gateway_models import OperationMode, GatewayRole

logger = logging.getLogger(__name__)


class GatewayModeDetector:
    """Detect and manage gateway mode configuration."""

    def __init__(self):
        self._mode: Optional[OperationMode] = None
        self._role: Optional[GatewayRole] = None

    def detect_mode(self) -> OperationMode:
        """Detect operation mode from environment variables."""
        if self._mode is not None:
            return self._mode

        mode_env = os.getenv("SYSTEMMANAGER_OPERATION_MODE", "local").lower()

        if mode_env == "gateway":
            self._mode = OperationMode.GATEWAY
            logger.info("Detected GATEWAY operation mode")
        else:
            self._mode = OperationMode.LOCAL
            logger.info("Detected LOCAL operation mode")

        return self._mode

    def detect_role(self) -> GatewayRole:
        """Detect gateway role from environment variables."""
        if self._role is not None:
            return self._role

        # Only detect role if in gateway mode
        if self.detect_mode() != OperationMode.GATEWAY:
            self._role = GatewayRole.STANDALONE
            return self._role

        role_env = os.getenv("SYSTEMMANAGER_GATEWAY_ROLE", "standalone").lower()

        if role_env == "primary":
            self._role = GatewayRole.PRIMARY
            logger.info("Detected PRIMARY gateway role")
        elif role_env == "secondary":
            self._role = GatewayRole.SECONDARY
            logger.info("Detected SECONDARY gateway role")
        else:
            self._role = GatewayRole.STANDALONE
            logger.info("Detected STANDALONE gateway role")

        return self._role

    def is_gateway_mode(self) -> bool:
        """Check if system is operating in gateway mode."""
        return self.detect_mode() == OperationMode.GATEWAY

    def is_primary_gateway(self) -> bool:
        """Check if this is a primary gateway."""
        return self.detect_role() == GatewayRole.PRIMARY

    def is_secondary_gateway(self) -> bool:
        """Check if this is a secondary gateway."""
        return self.detect_role() == GatewayRole.SECONDARY

    def is_standalone_gateway(self) -> bool:
        """Check if this is a standalone gateway."""
        return self.detect_role() == GatewayRole.STANDALONE

    def get_gateway_id(self) -> str:
        """Get gateway identifier from environment or generate one."""
        gateway_id = os.getenv("SYSTEMMANAGER_GATEWAY_ID")

        if not gateway_id and self.is_gateway_mode():
            # Generate a unique ID based on hostname and timestamp
            import socket
            import time

            hostname = socket.gethostname()
            timestamp = int(time.time())
            gateway_id = f"{hostname}-{timestamp}"
            logger.info(f"Generated gateway ID: {gateway_id}")

        return gateway_id or "local"

    def get_discovery_config(self) -> dict:
        """Get discovery configuration from environment variables."""
        return {
            "discovery_interval": int(
                os.getenv("SYSTEMMANAGER_DISCOVERY_INTERVAL", "300")
            ),
            "auto_register": os.getenv("SYSTEMMANAGER_AUTO_REGISTER", "false").lower()
            == "true",
            "max_fleet_size": int(os.getenv("SYSTEMMANAGER_MAX_FLEET_SIZE", "50")),
            "health_check_interval": int(
                os.getenv("SYSTEMMANAGER_HEALTH_CHECK_INTERVAL", "60")
            ),
            "state_sync_interval": int(
                os.getenv("SYSTEMMANAGER_STATE_SYNC_INTERVAL", "30")
            ),
        }


# Global mode detector instance
_mode_detector = GatewayModeDetector()


def get_operation_mode() -> OperationMode:
    """Get the current operation mode."""
    return _mode_detector.detect_mode()


def get_gateway_role() -> GatewayRole:
    """Get the current gateway role."""
    return _mode_detector.detect_role()


def is_gateway_mode() -> bool:
    """Check if system is in gateway mode."""
    return _mode_detector.is_gateway_mode()


def get_gateway_id() -> str:
    """Get the gateway identifier."""
    return _mode_detector.get_gateway_id()


def get_discovery_config() -> dict:
    """Get discovery configuration."""
    return _mode_detector.get_discovery_config()
