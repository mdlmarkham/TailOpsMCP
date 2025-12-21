"""
Security Access Control Module - Consolidated RBAC & Capabilities Management

This module provides comprehensive access control including:
- Role-based access control (RBAC)
- Capability-based permissions
- Fine-grained access policies
- Resource-level access control
- Security context management

CONSOLIDATED FROM:
- src/services/access_control.py
- src/services/capability_executor.py
- src/services/security_monitor.py
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
import threading

from ..models.security_models import SecurityPermission, SecurityRole, SecurityPolicy

logger = logging.getLogger(__name__)


# Access Control Enums
class PermissionType(Enum):
    """Types of permissions."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    ADMIN = "admin"
    MANAGE = "manage"
    VIEW = "view"
    CREATE = "create"
    UPDATE = "update"


class AccessLevel(Enum):
    """Access level hierarchy."""

    NONE = 0
    MINIMAL = 1
    BASIC = 2
    STANDARD = 3
    ELEVATED = 4
    ADMIN = 5
    SUPER_ADMIN = 6


class ResourceType(Enum):
    """Types of resources that can be protected."""

    SYSTEM = "system"
    APPLICATION = "application"
    DATA = "data"
    CONFIGURATION = "configuration"
    USER = "user"
    ROLE = "role"
    POLICY = "policy"
    AUDIT = "audit"
    SECURITY = "security"
    NETWORK = "network"
    CONTAINER = "container"
    FILE = "file"
    DATABASE = "database"
    API = "api"
    ENDPOINT = "endpoint"


class ContextType(Enum):
    """Security context types."""

    USER = "user"
    SERVICE = "service"
    API_KEY = "api_key"
    SESSION = "session"
    TOKEN = "token"
    CERTIFICATE = "certificate"
    IP_ADDRESS = "ip_address"
    DEVICE = "device"
    APPLICATION = "application"


@dataclass
class SecurityContext:
    """Security context for access decisions."""

    # Identity information
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    token_id: Optional[str] = None
    api_key_id: Optional[str] = None

    # Context attributes
    context_type: ContextType = ContextType.USER
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    device_id: Optional[str] = None
    location: Optional[str] = None

    # Temporal attributes
    login_time: Optional[datetime] = None
    last_activity: Optional[datetime] = None
    session_duration: Optional[timedelta] = None

    # Security attributes
    trust_level: str = "standard"  # low, standard, high, critical
    risk_score: float = 0.0
    mfa_verified: bool = False
    device_trusted: bool = False
    network_secure: bool = False

    # Additional context
    custom_attributes: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AccessRequest:
    """Access control request."""

    # Resource information
    resource_type: ResourceType
    resource_id: str
    action: PermissionType
    context: SecurityContext

    # Request details
    timestamp: datetime = field(default_factory=datetime.now)
    request_id: str = field(default_factory=lambda: f"req_{int(time.time() * 1000)}")

    # Additional parameters
    parameters: Dict[str, Any] = field(default_factory=dict)
    conditions: Dict[str, Any] = field(default_factory=dict)

    # Metadata
    source: str = "application"
    priority: str = "normal"  # low, normal, high, critical


@dataclass
class AccessDecision:
    """Access control decision result."""

    # Decision outcome
    allowed: bool
    reason: str
    confidence: float = 1.0

    # Granted permissions
    permissions: Set[SecurityPermission] = field(default_factory=set)
    access_level: AccessLevel = AccessLevel.NONE

    # Constraints and conditions
    constraints: Dict[str, Any] = field(default_factory=dict)
    expiration: Optional[datetime] = None

    # Risk assessment
    risk_score: float = 0.0
    risk_factors: List[str] = field(default_factory=list)

    # Audit information
    decision_id: str = field(default_factory=lambda: f"dec_{int(time.time() * 1000)}")
    timestamp: datetime = field(default_factory=datetime.now)

    # Additional details
    message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Capability:
    """Security capability."""

    name: str
    description: str
    permission_type: PermissionType
    resource_types: Set[ResourceType]
    access_level: AccessLevel = AccessLevel.BASIC

    # Conditions and constraints
    conditions: Dict[str, Any] = field(default_factory=dict)
    prerequisites: Set[str] = field(default_factory=set)

    # Security attributes
    sensitivity_level: str = "standard"
    audit_required: bool = True
    approval_required: bool = False

    # Metadata
    version: str = "1.0"
    created_at: datetime = field(default_factory=datetime.now)
    tags: Set[str] = field(default_factory=set)


class AccessControlEngine:
    """Comprehensive access control engine."""

    def __init__(self):
        self._roles: Dict[str, SecurityRole] = {}
        self._permissions: Dict[str, SecurityPermission] = {}
        self._capabilities: Dict[str, Capability] = {}
        self._policies: Dict[str, SecurityPolicy] = {}
        self._user_roles: Dict[str, Set[str]] = {}
        self._role_capabilities: Dict[str, Set[str]] = {}

        self._lock = threading.RLock()
        self._cache: Dict[str, AccessDecision] = {}
        self._cache_ttl: Dict[str, datetime] = {}
        self._cache_duration = timedelta(minutes=5)

        # Initialize default capabilities
        self._initialize_default_capabilities()

    def _initialize_default_capabilities(self) -> None:
        """Initialize default system capabilities."""
        default_capabilities = [
            Capability(
                name="read_system",
                description="Read system information",
                permission_type=PermissionType.READ,
                resource_types={ResourceType.SYSTEM, ResourceType.CONFIGURATION},
                access_level=AccessLevel.BASIC,
            ),
            Capability(
                name="write_system",
                description="Modify system configuration",
                permission_type=PermissionType.WRITE,
                resource_types={ResourceType.SYSTEM, ResourceType.CONFIGURATION},
                access_level=AccessLevel.ELEVATED,
            ),
            Capability(
                name="admin_system",
                description="Full system administration",
                permission_type=PermissionType.ADMIN,
                resource_types={ResourceType.SYSTEM},
                access_level=AccessLevel.ADMIN,
            ),
            Capability(
                name="manage_users",
                description="Manage user accounts and roles",
                permission_type=PermissionType.MANAGE,
                resource_types={ResourceType.USER, ResourceType.ROLE},
                access_level=AccessLevel.ELEVATED,
            ),
            Capability(
                name="view_audit",
                description="View audit logs",
                permission_type=PermissionType.VIEW,
                resource_types={ResourceType.AUDIT},
                access_level=AccessLevel.STANDARD,
            ),
            Capability(
                name="manage_security",
                description="Manage security policies",
                permission_type=PermissionType.MANAGE,
                resource_types={ResourceType.SECURITY, ResourceType.POLICY},
                access_level=AccessLevel.ADMIN,
            ),
        ]

        for capability in default_capabilities:
            self._capabilities[capability.name] = capability

    def check_access(self, request: AccessRequest) -> AccessDecision:
        """Check access permissions for a request."""
        with self._lock:
            # Check cache first
            cache_key = self._get_cache_key(request)
            if self._is_cache_valid(cache_key):
                return self._cache[cache_key]

            # Perform access control check
            decision = self._evaluate_access(request)

            # Cache the decision
            if decision.confidence > 0.8:  # Only cache high-confidence decisions
                self._cache[cache_key] = decision
                self._cache_ttl[cache_key] = datetime.now() + self._cache_duration

            return decision

    def grant_role(self, user_id: str, role_name: str) -> bool:
        """Grant a role to a user."""
        with self._lock:
            if role_name not in self._roles:
                logger.warning(f"Role {role_name} does not exist")
                return False

            if user_id not in self._user_roles:
                self._user_roles[user_id] = set()

            self._user_roles[user_id].add(role_name)
            logger.info(f"Granted role {role_name} to user {user_id}")
            return True

    def revoke_role(self, user_id: str, role_name: str) -> bool:
        """Revoke a role from a user."""
        with self._lock:
            if user_id in self._user_roles and role_name in self._user_roles[user_id]:
                self._user_roles[user_id].remove(role_name)
                logger.info(f"Revoked role {role_name} from user {user_id}")
                return True

            return False

    def add_capability_to_role(self, role_name: str, capability_name: str) -> bool:
        """Add capability to a role."""
        with self._lock:
            if role_name not in self._roles:
                logger.warning(f"Role {role_name} does not exist")
                return False

            if capability_name not in self._capabilities:
                logger.warning(f"Capability {capability_name} does not exist")
                return False

            if role_name not in self._role_capabilities:
                self._role_capabilities[role_name] = set()

            self._role_capabilities[role_name].add(capability_name)
            logger.info(f"Added capability {capability_name} to role {role_name}")
            return True

    def remove_capability_from_role(self, role_name: str, capability_name: str) -> bool:
        """Remove capability from a role."""
        with self._lock:
            if (
                role_name in self._role_capabilities
                and capability_name in self._role_capabilities[role_name]
            ):
                self._role_capabilities[role_name].remove(capability_name)
                logger.info(
                    f"Removed capability {capability_name} from role {role_name}"
                )
                return True

            return False

    def get_user_capabilities(self, user_id: str) -> Set[Capability]:
        """Get all capabilities for a user."""
        with self._lock:
            user_capabilities = set()

            # Get user's roles
            user_roles = self._user_roles.get(user_id, set())

            # Get capabilities for each role
            for role_name in user_roles:
                capability_names = self._role_capabilities.get(role_name, set())
                for capability_name in capability_names:
                    capability = self._capabilities.get(capability_name)
                    if capability:
                        user_capabilities.add(capability)

            return user_capabilities

    def get_user_access_level(
        self, user_id: str, resource_type: ResourceType
    ) -> AccessLevel:
        """Get user's access level for a resource type."""
        capabilities = self.get_user_capabilities(user_id)

        max_level = AccessLevel.NONE
        for capability in capabilities:
            if resource_type in capability.resource_types:
                max_level = max(max_level, capability.access_level)

        return max_level

    def can_perform_action(
        self,
        user_id: str,
        action: PermissionType,
        resource_type: ResourceType,
        resource_id: str = None,
    ) -> bool:
        """Check if user can perform specific action."""
        capabilities = self.get_user_capabilities(user_id)

        for capability in capabilities:
            if (
                capability.permission_type == action
                and resource_type in capability.resource_types
            ):
                # Check conditions
                if self._check_capability_conditions(capability, user_id, resource_id):
                    return True

        return False

    def create_role(
        self, name: str, description: str = "", permissions: List[str] = None
    ) -> bool:
        """Create a new role."""
        with self._lock:
            if name in self._roles:
                logger.warning(f"Role {name} already exists")
                return False

            role = SecurityRole(
                name=name, description=description, permissions=permissions or []
            )

            self._roles[name] = role
            logger.info(f"Created role {name}")
            return True

    def delete_role(self, name: str) -> bool:
        """Delete a role."""
        with self._lock:
            if name not in self._roles:
                return False

            # Remove role from all users
            for user_id, user_roles in list(self._user_roles.items()):
                if name in user_roles:
                    user_roles.remove(name)

            # Remove role capabilities
            if name in self._role_capabilities:
                del self._role_capabilities[name]

            # Delete the role
            del self._roles[name]

            logger.info(f"Deleted role {name}")
            return True

    def create_capability(self, capability: Capability) -> bool:
        """Create a new capability."""
        with self._lock:
            if capability.name in self._capabilities:
                logger.warning(f"Capability {capability.name} already exists")
                return False

            self._capabilities[capability.name] = capability
            logger.info(f"Created capability {capability.name}")
            return True

    def update_cache(self, key: str, decision: AccessDecision) -> None:
        """Update access decision cache."""
        with self._lock:
            self._cache[key] = decision
            self._cache_ttl[key] = datetime.now() + self._cache_duration

    def clear_cache(self) -> None:
        """Clear access decision cache."""
        with self._lock:
            self._cache.clear()
            self._cache_ttl.clear()

    def _evaluate_access(self, request: AccessRequest) -> AccessDecision:
        """Evaluate access request."""
        try:
            # Get user capabilities
            user_capabilities = self.get_user_capabilities(
                request.context.user_id or ""
            )

            # Check if user has required capability
            required_capability = None
            for capability in user_capabilities:
                if (
                    capability.permission_type == request.action
                    and request.resource_type in capability.resource_types
                ):
                    # Check capability conditions
                    if self._check_capability_conditions(
                        capability, request.context.user_id, request.resource_id
                    ):
                        required_capability = capability
                        break

            if not required_capability:
                return AccessDecision(
                    allowed=False,
                    reason=f"User lacks required capability for {request.action} on {request.resource_type}",
                    confidence=1.0,
                    access_level=AccessLevel.NONE,
                )

            # Check contextual conditions
            risk_score, risk_factors = self._assess_contextual_risk(request)

            # Evaluate policy constraints
            policy_violations = self._check_policy_constraints(
                request, user_capabilities
            )

            if policy_violations:
                return AccessDecision(
                    allowed=False,
                    reason=f"Policy violations: {', '.join(policy_violations)}",
                    confidence=1.0,
                    risk_score=risk_score,
                    risk_factors=risk_factors,
                )

            # Make final decision
            allowed = self._make_final_decision(
                required_capability, request, risk_score
            )

            return AccessDecision(
                allowed=allowed,
                reason="Access granted based on capability and context",
                confidence=0.9,
                permissions={required_capability},
                access_level=required_capability.access_level,
                risk_score=risk_score,
                risk_factors=risk_factors,
                constraints=required_capability.conditions,
            )

        except Exception as e:
            logger.error(f"Error evaluating access: {e}")
            return AccessDecision(
                allowed=False,
                reason=f"Error during access evaluation: {str(e)}",
                confidence=0.0,
            )

    def _check_capability_conditions(
        self, capability: Capability, user_id: str, resource_id: str
    ) -> bool:
        """Check if capability conditions are satisfied."""
        # Check time-based conditions
        if "time_restrictions" in capability.conditions:
            restrictions = capability.conditions["time_restrictions"]
            current_time = datetime.now()

            if (
                "business_hours_only" in restrictions
                and restrictions["business_hours_only"]
            ):
                # Simple business hours check (9 AM - 5 PM, weekdays)
                if not (9 <= current_time.hour <= 17 and current_time.weekday() < 5):
                    return False

            if "allowed_hours" in restrictions:
                allowed_hours = restrictions["allowed_hours"]
                if current_time.hour not in allowed_hours:
                    return False

        # Check user-specific conditions
        if "user_requirements" in capability.conditions:
            requirements = capability.conditions["user_requirements"]

            if "mfa_required" in requirements and requirements["mfa_required"]:
                # This would need to be checked against user context
                pass  # Simplified for demonstration

        # Add more condition checks as needed
        return True

    def _assess_contextual_risk(
        self, request: AccessRequest
    ) -> Tuple[float, List[str]]:
        """Assess contextual risk factors."""
        risk_score = 0.0
        risk_factors = []

        context = request.context

        # IP-based risk
        if context.source_ip:
            if self._is_suspicious_ip(context.source_ip):
                risk_score += 0.3
                risk_factors.append("suspicious_ip_address")

        # Time-based risk
        if context.login_time:
            time_diff = datetime.now() - context.login_time
            if time_diff > timedelta(hours=8):
                risk_score += 0.2
                risk_factors.append("long_session_duration")

        # Trust level risk
        if context.trust_level == "low":
            risk_score += 0.4
            risk_factors.append("low_trust_level")
        elif context.trust_level == "critical":
            risk_score -= 0.2
            risk_factors.append("critical_trust_level")

        # Device and network risk
        if not context.device_trusted:
            risk_score += 0.2
            risk_factors.append("untrusted_device")

        if not context.network_secure:
            risk_score += 0.2
            risk_factors.append("insecure_network")

        # User activity risk
        if context.last_activity:
            inactive_time = datetime.now() - context.last_activity
            if inactive_time > timedelta(minutes=30):
                risk_score += 0.1
                risk_factors.append("inactive_session")

        return min(risk_score, 1.0), risk_factors

    def _check_policy_constraints(
        self, request: AccessRequest, capabilities: Set[Capability]
    ) -> List[str]:
        """Check policy constraints and violations."""
        violations = []

        # Check resource-specific constraints
        if request.resource_type == ResourceType.AUDIT:
            # Only admins can access audit logs
            if not any(cap.access_level >= AccessLevel.ADMIN for cap in capabilities):
                violations.append("insufficient_privileges_for_audit_access")

        elif request.resource_type == ResourceType.SECURITY:
            # Security management requires high privileges
            if not any(
                cap.access_level >= AccessLevel.ELEVATED for cap in capabilities
            ):
                violations.append("insufficient_privileges_for_security_access")

        # Check action-specific constraints
        if request.action == PermissionType.DELETE:
            # Delete operations require higher privilege
            if not any(
                cap.access_level >= AccessLevel.ELEVATED for cap in capabilities
            ):
                violations.append("insufficient_privileges_for_delete_operation")

        # Check temporal constraints
        if request.context.login_time:
            login_duration = datetime.now() - request.context.login_time
            if login_duration > timedelta(hours=12):
                violations.append("session_too_old_for_critical_operations")

        return violations

    def _make_final_decision(
        self, capability: Capability, request: AccessRequest, risk_score: float
    ) -> bool:
        """Make final access control decision."""
        # Base decision on capability
        base_allowed = True

        # Apply risk-based adjustments
        if risk_score > 0.7:
            base_allowed = False
        elif risk_score > 0.5:
            # Require additional approval for high-risk requests
            if not request.context.mfa_verified:
                base_allowed = False

        # Check time-based restrictions
        if capability.conditions.get("time_restrictions", {}).get("restricted_hours"):
            current_hour = datetime.now().hour
            restricted_hours = capability.conditions["time_restrictions"][
                "restricted_hours"
            ]
            if current_hour in restricted_hours:
                base_allowed = False

        return base_allowed

    def _is_suspicious_ip(self, ip_address: str) -> bool:
        """Check if IP address is suspicious."""
        # Simple heuristics for demonstration
        # In production, integrate with threat intelligence feeds
        suspicious_ranges = ["192.168.1.0/24", "10.0.0.0/8"]

        for ip_range in suspicious_ranges:
            # Simplified range check
            if ip_address.startswith(ip_range.split("/")[0]):
                return True

        return False

    def _get_cache_key(self, request: AccessRequest) -> str:
        """Generate cache key for request."""
        key_data = {
            "user_id": request.context.user_id,
            "action": request.action.value,
            "resource_type": request.resource_type.value,
            "resource_id": request.resource_id,
            "source_ip": request.context.source_ip,
        }

        key_string = json.dumps(key_data, sort_keys=True, default=str)
        return hashlib.sha256(key_string.encode()).hexdigest()

    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cached decision is still valid."""
        if cache_key not in self._cache_ttl:
            return False

        return datetime.now() < self._cache_ttl[cache_key]


# Global access control engine
_access_engine = None


def get_access_engine() -> AccessControlEngine:
    """Get global access control engine instance."""
    global _access_engine
    if _access_engine is None:
        _access_engine = AccessControlEngine()
    return _access_engine


# Convenience functions
def check_access(
    user_id: str, action: str, resource_type: str, resource_id: str = None
) -> bool:
    """Quick access check."""
    engine = get_access_engine()

    try:
        permission_type = PermissionType(action.lower())
        resource_enum = ResourceType(resource_type.lower())

        return engine.can_perform_action(
            user_id, permission_type, resource_enum, resource_id
        )
    except (ValueError, AttributeError):
        return False


def get_user_permissions(user_id: str) -> Dict[str, bool]:
    """Get all user permissions."""
    engine = get_access_engine()
    capabilities = engine.get_user_capabilities(user_id)

    permissions = {}
    for capability in capabilities:
        permissions[f"{capability.permission_type.value}_{capability.name}"] = True

    return permissions


def grant_user_role(user_id: str, role_name: str) -> bool:
    """Grant role to user."""
    engine = get_access_engine()
    return engine.grant_role(user_id, role_name)


def revoke_user_role(user_id: str, role_name: str) -> bool:
    """Revoke role from user."""
    engine = get_access_engine()
    return engine.revoke_role(user_id, role_name)


# Export main classes and functions
__all__ = [
    "AccessControlEngine",
    "SecurityContext",
    "AccessRequest",
    "AccessDecision",
    "Capability",
    "PermissionType",
    "AccessLevel",
    "ResourceType",
    "ContextType",
    "get_access_engine",
    "check_access",
    "get_user_permissions",
    "grant_user_role",
    "revoke_user_role",
]
