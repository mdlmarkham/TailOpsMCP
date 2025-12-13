"""
Security middleware for MCP tool invocations.

Provides defense-in-depth for tailnet deployments:
1. Scope-based authorization (application-level)
2. Tailscale identity verification (network-level already done by Tailscale)
3. Audit logging with Tailscale context
4. Interactive approval for high-risk operations
5. Policy Gate integration for comprehensive security controls
"""

import os
import logging
from typing import Any, Dict, Optional, Callable
from functools import wraps
from fastmcp.server.context import Context

from src.auth.token_auth import TokenVerifier, TokenClaims
from src.auth.scopes import check_authorization, requires_approval, get_tool_risk_level
from src.services.policy_gate import PolicyGate
from src.services.target_registry import TargetRegistry
from src.utils.audit import AuditLogger
from src.utils.errors import ErrorCategory, SystemManagerError


logger = logging.getLogger(__name__)


class SecurityMiddleware:
    """Enforce security policies on MCP tool invocations."""
    
    def __init__(self):
        self.token_verifier = TokenVerifier()
        self.audit_logger = AuditLogger()
        # DEFAULT TO REQUIRING AUTH - fail closed
        self.require_auth = os.getenv("SYSTEMMANAGER_REQUIRE_AUTH", "true").lower() == "true"
        self.enable_approval = os.getenv("SYSTEMMANAGER_ENABLE_APPROVAL", "false").lower() == "true"
        
        # Initialize Policy Gate for comprehensive security controls
        self.target_registry = TargetRegistry()
        self.policy_gate = PolicyGate(self.target_registry, self.audit_logger)
        
    def get_claims_from_context(self, **kwargs) -> Optional[TokenClaims]:
        """Extract and verify token from kwargs or HTTP request.
        
        Args:
            **kwargs: May contain auth_token or headers with Authorization
            
        Returns:
            TokenClaims if token present and valid, None otherwise
        """
        token = None
        
        # Try to get token from HTTP request headers first
        try:
            from fastmcp.server.dependencies import get_http_request
            request = get_http_request()
            if request:
                auth_header = request.headers.get("authorization", "")
                if auth_header.lower().startswith("bearer "):
                    token = auth_header.split(None, 1)[1]
        except Exception:
            pass  # No HTTP request context available
        
        # Fallback: Extract token from kwargs
        if not token:
            if "auth_token" in kwargs:
                token = kwargs.get("auth_token")
            elif "headers" in kwargs and isinstance(kwargs["headers"], dict):
                auth_header = kwargs["headers"].get("Authorization", "")
                if auth_header.lower().startswith("bearer "):
                    token = auth_header.split(None, 1)[1]
        
        if not token:
            if self.require_auth:
                raise SystemManagerError(
                    "Authentication required but no token provided",
                    category=ErrorCategory.UNAUTHORIZED
                )
            # CRITICAL: No default scopes for anonymous users
            # This ensures unauthenticated access is completely blocked
            raise SystemManagerError(
                "No authentication token provided. Set SYSTEMMANAGER_REQUIRE_AUTH=false to allow anonymous access (NOT RECOMMENDED)",
                category=ErrorCategory.UNAUTHORIZED
            )
        
        # Verify token
        try:
            claims = self.token_verifier.verify(token)
            return claims
        except SystemManagerError:
            raise
        except Exception as e:
            raise SystemManagerError(
                f"Token verification failed: {e}",
                category=ErrorCategory.UNAUTHORIZED
            )
    
    def check_authorization(self, tool_name: str, claims: TokenClaims) -> None:
        """Check if user is authorized to invoke tool.
        
        Args:
            tool_name: Name of the tool being invoked
            claims: User's token claims
            
        Raises:
            SystemManagerError: If unauthorized
        """
        authorized, reason = check_authorization(tool_name, claims.scopes or [])
        
        if not authorized:
            logger.warning(
                f"Authorization denied for {claims.agent} invoking {tool_name}: {reason}"
            )
            raise SystemManagerError(
                f"Insufficient privileges: {reason}",
                category=ErrorCategory.FORBIDDEN
            )
    
    def check_target_capability(self, target_capabilities: list, required_scope: str) -> bool:
        """Check if target has the required capability for an operation.
        
        Args:
            target_capabilities: List of capabilities available on the target
            required_scope: Required scope for the operation
            
        Returns:
            True if target has the capability, False otherwise
        """
        return required_scope in target_capabilities
    
    def check_approval(self, tool_name: str, args: Dict[str, Any]) -> bool:
        """Check if operation requires and has approval.
        
        For now, this is a placeholder. In production, you would:
        1. Check if tool requires approval
        2. Prompt via callback/webhook for approval
        3. Wait for human approval
        4. Return approval status
        
        Args:
            tool_name: Name of the tool
            args: Tool arguments
            
        Returns:
            True if approved (or approval not required)
            
        Raises:
            SystemManagerError: If approval required but not granted
        """
        if not self.enable_approval:
            # Approval system disabled
            return True
        
        if not requires_approval(tool_name):
            # Tool doesn't require approval
            return True
        
        # CRITICAL SECURITY FIX: Remove auto_approve bypass
        # In production, implement actual approval flow here
        # For now, DENY all critical operations unless approval system is configured
        
        approval_webhook = os.getenv("SYSTEMMANAGER_APPROVAL_WEBHOOK")
        if not approval_webhook:
            logger.error(
                f"Critical operation {tool_name} requires approval but no approval webhook configured. "
                f"Set SYSTEMMANAGER_APPROVAL_WEBHOOK or disable approval requirement."
            )
            raise SystemManagerError(
                f"Operation requires approval. Configure SYSTEMMANAGER_APPROVAL_WEBHOOK or "
                f"set SYSTEMMANAGER_ENABLE_APPROVAL=false to proceed (NOT RECOMMENDED for production)",
                category=ErrorCategory.FORBIDDEN
            )
        
        # TODO: Implement actual webhook-based approval
        # For now, deny by default
        logger.error(f"Approval workflow not implemented for {tool_name}")
        raise SystemManagerError(
            f"Approval workflow not yet implemented. Operation denied.",
            category=ErrorCategory.FORBIDDEN
        )
    
    def wrap_tool(self, tool_name: str, func: Callable) -> Callable:
        """Wrap a tool function with security checks and audit logging.
        
        Args:
            tool_name: Name of the tool
            func: Tool function to wrap
            
        Returns:
            Wrapped function with security enforcement
        """
        @wraps(func)
        async def wrapped(*args, **kwargs):
            # Extract Context from args (FastMCP injects it as ctx parameter)
            ctx = None
            for arg in args:
                if isinstance(arg, Context):
                    ctx = arg
                    break
            
            # Also check kwargs for ctx/context parameter
            if ctx is None:
                ctx = kwargs.get('ctx') or kwargs.get('context')
            
            # Get claims from Context state (set by HTTP middleware or stored earlier)
            claims = None
            if ctx:
                claims = ctx.get_state("auth_claims")
            
            # Fallback: try to extract from kwargs if not in context
            if claims is None:
                try:
                    claims = self.get_claims_from_context(**kwargs)
                    # Store in context for future use
                    if ctx:
                        ctx.set_state("auth_claims", claims)
                except SystemManagerError as e:
                    result = {"success": False, "error": str(e)}
                    self.audit_logger.log(
                        tool=tool_name,
                        args=kwargs,
                        result=result,
                        subject="unauthenticated",
                        risk_level=get_tool_risk_level(tool_name),
                    )
                    return result
            
            # Check authorization
            try:
                self.check_authorization(tool_name, claims)
            except SystemManagerError as e:
                result = {"success": False, "error": str(e)}
                self.audit_logger.log(
                    tool=tool_name,
                    args=kwargs,
                    result=result,
                    subject=claims.agent,
                    scopes=claims.scopes,
                    risk_level=get_tool_risk_level(tool_name),
                )
                return result
            
            # Apply Policy Gate security controls
            try:
                self._apply_policy_gate(tool_name, kwargs, claims)
            except SystemManagerError as e:
                result = {"success": False, "error": str(e)}
                self.audit_logger.log(
                    tool=tool_name,
                    args=kwargs,
                    result=result,
                    subject=claims.agent,
                    scopes=claims.scopes,
                    risk_level=get_tool_risk_level(tool_name),
                )
                return result
            
            # Check approval for high-risk operations
            approved = False
            try:
                approved = self.check_approval(tool_name, kwargs)
            except SystemManagerError as e:
                result = {"success": False, "error": str(e)}
                self.audit_logger.log(
                    tool=tool_name,
                    args=kwargs,
                    result=result,
                    subject=claims.agent,
                    scopes=claims.scopes,
                    risk_level=get_tool_risk_level(tool_name),
                    approved=False,
                )
                return result
            
            # Execute tool
            try:
                result = await func(*args, **kwargs)
                
                # Ensure result is dict
                if not isinstance(result, dict):
                    result = {"success": True, "data": result}
                
                # Audit log
                self.audit_logger.log(
                    tool=tool_name,
                    args=kwargs,
                    result=result,
                    subject=claims.agent,
                    scopes=claims.scopes,
                    risk_level=get_tool_risk_level(tool_name),
                    approved=approved if requires_approval(tool_name) else None,
                )
                
                return result
                
            except Exception as e:
                logger.exception(f"Tool {tool_name} failed: {e}")
                result = {"success": False, "error": str(e)}
                
                # Audit log failure
                self.audit_logger.log(
                    tool=tool_name,
                    args=kwargs,
                    result=result,
                    subject=claims.agent,
                    scopes=claims.scopes,
                    risk_level=get_tool_risk_level(tool_name),
                )
                
                return result
        
        return wrapped
    
    def _apply_policy_gate(self, tool_name: str, kwargs: Dict[str, Any], claims: TokenClaims) -> None:
        """Apply Policy Gate security controls to tool invocation.
        
        Args:
            tool_name: Tool name
            kwargs: Tool arguments
            claims: User token claims
            
        Raises:
            SystemManagerError: If policy enforcement fails
        """
        # Extract target and operation information from kwargs
        target_id = kwargs.get("target_id", "local")  # Default to local target
        operation = kwargs.get("operation", tool_name.split("_")[-1])  # Extract operation from tool name
        
        # Check if this is a dry-run operation
        dry_run = kwargs.get("dry_run", False)
        
        # Apply policy enforcement
        authorized, validation_errors = self.policy_gate.enforce_policy(
            tool_name=tool_name,
            target_id=target_id,
            operation=operation,
            parameters=kwargs,
            claims=claims,
            dry_run=dry_run
        )
        
        if not authorized:
            error_message = f"Policy enforcement failed: {', '.join(validation_errors)}"
            raise SystemManagerError(error_message, category=ErrorCategory.FORBIDDEN)
        
        # Audit the policy decision
        self.policy_gate.audit_policy_decision(
            tool_name=tool_name,
            target_id=target_id,
            operation=operation,
            parameters=kwargs,
            claims=claims,
            authorized=authorized,
            validation_errors=validation_errors,
            dry_run=dry_run
        )


# Global middleware instance
_middleware = SecurityMiddleware()


def secure_tool(tool_name: str):
    """Decorator to add security middleware to a tool function.
    
    Usage:
        @secure_tool("manage_container")
        async def manage_container(**kwargs):
            ...
    
    Note: This decorator is only active when using token-based authentication.
    When AUTH_MODE=oidc, FastMCP's RemoteAuthProvider handles authentication,
    so this decorator becomes a no-op to avoid conflicts.
    """
    # In OIDC mode, FastMCP handles auth - don't apply our token middleware
    auth_mode = os.getenv("SYSTEMMANAGER_AUTH_MODE", "token").lower()
    if auth_mode == "oidc":
        def decorator(func: Callable) -> Callable:
            return func  # Pass through without wrapping
        return decorator
    
    # In token mode, apply our HMAC token middleware
    def decorator(func: Callable) -> Callable:
        return _middleware.wrap_tool(tool_name, func)
    return decorator
