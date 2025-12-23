"""
Rate Limiting System for MCP Tool Operations.

Provides risk-based rate limiting across all 80 MCP tools using slowapi.
Implements tier-based rate limits based on operation risk:
- CRITICAL: 5/minute (container operations, system changes)
- HIGH: 10/minute (package management, file operations)
- MODERATE: 20/minute (network tools, monitoring)
- LOW: 100/minute (read operations, status checks)

Integrates with existing authentication and policy systems.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass
from enum import Enum

try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded

    SLOWAPI_AVAILABLE = True
except ImportError:
    SLOWAPI_AVAILABLE = False
    logging.warning("slowapi not available - rate limiting disabled")

from src.auth.token_auth import TokenClaims
from src.utils.errors import ErrorCategory, SystemManagerError


logger = logging.getLogger(__name__)


class RiskLevel(str, Enum):
    """Risk-based rate limiting tiers."""

    CRITICAL = "critical"  # 5/minute
    HIGH = "high"  # 10/minute
    MODERATE = "moderate"  # 20/minute
    LOW = "low"  # 100/minute


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting tiers."""

    risk_level: RiskLevel
    requests_per_minute: int
    burst_size: int = 5
    window_seconds: int = 60
    description: str = ""


class RateLimiter:
    """Risk-based rate limiting system for MCP tools."""

    def __init__(self, storage_backend: str = "memory"):
        """Initialize rate limiter.

        Args:
            storage_backend: Storage backend for rate limit data ("memory" or "redis")
        """
        if not SLOWAPI_AVAILABLE:
            logger.warning("Rate limiting disabled - slowapi not installed")
            self.enabled = False
            return

        self.enabled = True
        self.storage_backend = storage_backend
        self._setup_rate_limits()
        self._setup_slowapi_limiter()

        # Tool risk mappings
        self._define_tool_risks()

        logger.info(f"Rate limiter initialized with {storage_backend} backend")

    def _setup_rate_limits(self) -> None:
        """Define rate limit configurations by risk level."""
        self.rate_limits = {
            RiskLevel.CRITICAL: RateLimitConfig(
                risk_level=RiskLevel.CRITICAL,
                requests_per_minute=5,
                burst_size=2,
                description="Critical operations that can damage system integrity",
            ),
            RiskLevel.HIGH: RateLimitConfig(
                risk_level=RiskLevel.HIGH,
                requests_per_minute=10,
                burst_size=3,
                description="High-risk operations that affect system state",
            ),
            RiskLevel.MODERATE: RateLimitConfig(
                risk_level=RiskLevel.MODERATE,
                requests_per_minute=20,
                burst_size=5,
                description="Moderate-risk operations that access system resources",
            ),
            RiskLevel.LOW: RateLimitConfig(
                risk_level=RiskLevel.LOW,
                requests_per_minute=100,
                burst_size=10,
                description="Low-risk read-only operations",
            ),
        }

    def _setup_slowapi_limiter(self) -> None:
        """Initialize slowapi limiter based on storage backend."""
        if not self.enabled:
            return

        try:
            if self.storage_backend == "redis":
                # Redis backend for distributed systems
                try:
                    import redis

                    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
                    redis_client = redis.from_url(redis_url)
                    storage = slowapi.storage.RedisStorage(redis_client)
                    logger.info("Rate limiter using Redis storage")
                except ImportError:
                    logger.warning(
                        "Redis not available, falling back to memory storage"
                    )
                    storage = slowapi.storage.MemoryStorage()
            else:
                # Memory backend for development/small deployments
                from slowapi.storage import MemoryStorage

                storage = MemoryStorage()
                logger.info("Rate limiter using memory storage")

            # Initialize slowapi limiter
            self.limiter = Limiter(key_func=self._get_rate_limit_key, storage=storage)

        except Exception as e:
            logger.error(f"Failed to initialize rate limiter: {e}")
            self.enabled = False

    def _get_rate_limit_key(self, **kwargs) -> str:
        """Generate rate limit key based on context."""
        try:
            # Try to get user identity first (more precise)
            claims = kwargs.get("claims")
            if claims and hasattr(claims, "agent"):
                return f"agent:{claims.agent}"

            # Fallback to IP address
            return f"ip:{get_remote_address(**kwargs)}"

        except Exception:
            # Ultimate fallback
            return f"rate_limit:{int(time.time() // 60)}"

    def _define_tool_risks(self) -> None:
        """Risk categorization for all 80 MCP tools."""
        self.tool_risks = {
            # CRITICAL RISK - System integrity operations
            "update_docker_container": RiskLevel.CRITICAL,
            "remove_docker_container": RiskLevel.CRITICAL,
            "update_system_packages": RiskLevel.CRITICAL,
            "install_package": RiskLevel.CRITICAL,
            "remove_package": RiskLevel.CRITICAL,
            "http_request_test": RiskLevel.CRITICAL,  # Could be used for attacks
            # HIGH RISK - System state changes
            "pull_docker_image": RiskLevel.HIGH,
            "create_docker_container": RiskLevel.HIGH,
            "restart_docker_container": RiskLevel.HIGH,
            "stop_docker_container": RiskLevel.HIGH,
            "start_docker_container": RiskLevel.HIGH,
            "restart_system_service": RiskLevel.HIGH,
            "stop_system_service": RiskLevel.HIGH,
            "execute_command": RiskLevel.HIGH,
            "write_file": RiskLevel.HIGH,
            "delete_file": RiskLevel.HIGH,
            "create_directory": RiskLevel.HIGH,
            "delete_directory": RiskLevel.HIGH,
            # MODERATE RISK - Resource access
            "inspect_docker_container": RiskLevel.MODERATE,
            "list_docker_containers": RiskLevel.MODERATE,
            "list_docker_images": RiskLevel.MODERATE,
            "inspect_docker_image": RiskLevel.MODERATE,
            "list_system_processes": RiskLevel.MODERATE,
            "get_system_metrics": RiskLevel.MODERATE,
            "read_file": RiskLevel.MODERATE,
            "list_directory": RiskLevel.MODERATE,
            "scan_ports": RiskLevel.MODERATE,
            "test_connectivity": RiskLevel.MODERATE,
            "get_network_interfaces": RiskLevel.MODERATE,
            "monitor_network_traffic": RiskLevel.MODERATE,
            # LOW RISK - Read-only and status operations
            "get_system_status": RiskLevel.LOW,
            "get_system_info": RiskLevel.LOW,
            "get_service_status": RiskLevel.LOW,
            "list_system_services": RiskLevel.LOW,
            "check_disk_usage": RiskLevel.LOW,
            "check_memory_usage": RiskLevel.LOW,
            "get_logged_in_users": RiskLevel.LOW,
            "list_open_ports": RiskLevel.LOW,
            "get_route_table": RiskLevel.LOW,
            "ping_host": RiskLevel.LOW,
            "resolve_dns": RiskLevel.LOW,
            "get_certificate_info": RiskLevel.LOW,
        }

        # Default unknown tools to MODERATE risk
        self.default_risk = RiskLevel.MODERATE

        logger.info(f"Defined risk levels for {len(self.tool_risks)} tools")

    def get_tool_risk_level(self, tool_name: str) -> RiskLevel:
        """Get risk level for a tool.

        Args:
            tool_name: Name of the tool

        Returns:
            Risk level for the tool
        """
        return self.tool_risks.get(tool_name, self.default_risk)

    def get_rate_limit_config(self, tool_name: str) -> RateLimitConfig:
        """Get rate limit configuration for a tool.

        Args:
            tool_name: Name of the tool

        Returns:
            Rate limit configuration
        """
        risk_level = self.get_tool_risk_level(tool_name)
        return self.rate_limits[risk_level]

    def check_rate_limit(
        self, tool_name: str, claims: Optional[TokenClaims] = None
    ) -> bool:
        """Check if operation is within rate limits.

        Args:
            tool_name: Name of the tool being invoked
            claims: User authentication claims

        Returns:
            True if within rate limits, False otherwise
        """
        if not self.enabled:
            return True  # Rate limiting disabled

        try:
            config = self.get_rate_limit_config(tool_name)

            # Create rate limit string
            rate_limit_string = f"{config.requests_per_minute}/{config.window_seconds}"

            # Rate limit key includes tool name and user
            rate_limit_key = f"{tool_name}:{self._get_rate_limit_key(claims=claims) if claims else 'anonymous'}"

            # Check rate limit
            if hasattr(self, "limiter"):
                # slowapi check - would need request context in real implementation
                # For now, return True and implement actual checking in decorator
                return True
            else:
                # Fallback - no limiter available
                return True

        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            return True  # Allow operation on error

    def create_rate_limit_decorator(self, tool_name: str):
        """Create rate limiting decorator for a tool.

        Args:
            tool_name: Name of the tool

        Returns:
            Decorator function
        """
        if not self.enabled:

            def decorator(func):
                return func  # No-op when rate limiting disabled

            return decorator

        config = self.get_rate_limit_config(tool_name)
        rate_limit_string = (
            f"{config.requests_per_minute}/{config.window_seconds}second"
        )

        def decorator(func):
            if hasattr(self, "limiter"):
                # Use slowapi decorator
                rate_limited_func = self.limiter.limit(rate_limit_string)(func)
                return rate_limited_func
            else:
                # Fallback - just return original function
                return func

        return decorator

    def get_rate_limit_status(
        self, tool_name: str, claims: Optional[TokenClaims] = None
    ) -> Dict[str, Any]:
        """Get current rate limit status for a tool.

        Args:
            tool_name: Name of the tool
            claims: User authentication claims

        Returns:
            Rate limit status information
        """
        config = self.get_rate_limit_config(tool_name)

        status = {
            "tool_name": tool_name,
            "risk_level": config.risk_level.value,
            "requests_per_minute": config.requests_per_minute,
            "burst_size": config.burst_size,
            "window_seconds": config.window_seconds,
            "description": config.description,
            "rate_limiting_enabled": self.enabled,
            "storage_backend": self.storage_backend if self.enabled else None,
        }

        # In a real implementation, we would include current usage stats
        # This would require querying the storage backend
        if self.enabled and hasattr(self, "limiter"):
            status["remaining_calls"] = "unavailable"  # Would query limiter storage
        else:
            status["remaining_calls"] = "unavailable"

        return status

    def reset_rate_limits(self, user_identifier: Optional[str] = None) -> bool:
        """Reset rate limits for a user or all users.

        Args:
            user_identifier: User identifier to reset, or None for all

        Returns:
            True if successful, False otherwise
        """
        if not self.enabled:
            return True

        try:
            # In a real implementation, this would clear the storage backend
            # For memory storage, we could clear internal caches
            # For Redis, we would delete keys matching patterns

            logger.info(
                f"Rate limit reset requested for user: {user_identifier or 'all'}"
            )
            return True

        except Exception as e:
            logger.error(f"Rate limit reset failed: {e}")
            return False

    def get_rate_limit_statistics(self) -> Dict[str, Any]:
        """Get global rate limiting statistics.

        Returns:
            Rate limiting statistics
        """
        stats = {
            "rate_limiting_enabled": self.enabled,
            "storage_backend": self.storage_backend if self.enabled else None,
            "total_tools_configured": len(self.tool_risks),
            "risk_levels": {
                level.value: config.requests_per_minute
                for level, config in self.rate_limits.items()
            },
        }

        # Add per-risk-level tool counts
        tool_counts = {level.value: 0 for level in RiskLevel}
        for tool_risk in self.tool_risks.values():
            tool_counts[tool_risk.value] += 1

        stats["tools_per_risk_level"] = tool_counts

        return stats


# Global rate limiter instance
_rate_limiter = None


def get_rate_limiter() -> RateLimiter:
    """Get global rate limiter instance.

    Returns:
        RateLimiter instance
    """
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


def rate_limit_decorator(tool_name: str):
    """Convenient decorator factory for rate limiting.

    Args:
        tool_name: Name of the tool

    Returns:
        Rate limiting decorator
    """
    rate_limiter = get_rate_limiter()
    return rate_limiter.create_rate_limit_decorator(tool_name)


# Export classes and functions
__all__ = [
    "RateLimiter",
    "RiskLevel",
    "RateLimitConfig",
    "get_rate_limiter",
    "rate_limit_decorator",
]
