"""
Security middleware for MCP tool invocations.

Provides defense-in-depth for tailnet deployments:
1. Scope-based authorization (application-level)
2. Tailscale identity verification (network-level already done by Tailscale)
3. Audit logging with Tailscale context
4. Interactive approval for high-risk operations
"""

import os
import logging
from typing import Any, Dict, Optional, Callable
from functools import wraps

from src.auth.token_auth import TokenVerifier, TokenClaims
from src.auth.scopes import check_authorization, requires_approval, get_tool_risk_level
from src.utils.audit import AuditLogger
from src.utils.errors import ErrorCategory, SystemManagerError


logger = logging.getLogger(__name__)


class SecurityMiddleware:
    """Enforce security policies on MCP tool invocations."""
    
    def __init__(self):
        self.token_verifier = TokenVerifier()
        self.audit_logger = AuditLogger()
        self.require_auth = os.getenv("SYSTEMMANAGER_REQUIRE_AUTH", "false").lower() == "true"
        self.enable_approval = os.getenv("SYSTEMMANAGER_ENABLE_APPROVAL", "false").lower() == "true"
        
    def get_claims_from_context(self, **kwargs) -> Optional[TokenClaims]:
        """Extract and verify token from kwargs.
        
        Args:
            **kwargs: May contain auth_token or headers with Authorization
            
        Returns:
            TokenClaims if token present and valid, None otherwise
        """
        token = None
        
        # Extract token from kwargs
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
            # No token, no auth required - return default claims
            return TokenClaims(
                agent="anonymous",
                scopes=["readonly"],  # Default to read-only
                host_tags=[],
                expiry=None
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
        
        # In production, implement actual approval flow here
        # For now, log and deny critical operations without explicit approval flag
        if args.get("auto_approve") is True:
            logger.warning(
                f"High-risk operation {tool_name} auto-approved via auto_approve flag"
            )
            return True
        
        logger.error(
            f"High-risk operation {tool_name} requires approval but none granted"
        )
        raise SystemManagerError(
            f"Operation requires interactive approval. Set auto_approve=True to bypass, "
            f"or configure approval webhook via SYSTEMMANAGER_APPROVAL_WEBHOOK",
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
        async def wrapped(**kwargs):
            # Extract and verify authentication
            try:
                claims = self.get_claims_from_context(**kwargs)
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
                result = await func(**kwargs)
                
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


# Global middleware instance
_middleware = SecurityMiddleware()


def secure_tool(tool_name: str):
    """Decorator to add security middleware to a tool function.
    
    Usage:
        @secure_tool("manage_container")
        async def manage_container(**kwargs):
            ...
    """
    def decorator(func: Callable) -> Callable:
        return _middleware.wrap_tool(tool_name, func)
    return decorator
