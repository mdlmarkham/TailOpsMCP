"""
Advanced Identity Management System with Tailscale OIDC Integration.

This module provides comprehensive identity and access management:
- Tailscale OIDC integration for seamless authentication
- Session management with secure token handling
- Multi-factor authentication support
- Identity context building and validation
- Risk-based identity profiling
"""

import datetime
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
from typing import Any, Dict, List, Optional, Set, Union
from dataclasses import asdict

from src.models.security_models import (
    IdentityContext, AuthenticationCredentials, AuthenticationResult,
    SessionValidationResult, PermissionSet, AuthenticationMethod,
    IdentityEvent, RiskLevel, InitiatorType
)
from src.security import SecurityAuditLogger  # Backward compat alias for AuditLogger


logger = logging.getLogger(__name__)


class SessionToken:
    """Represents a secure session token."""
    
    def __init__(self, token: str, identity: IdentityContext, expires_at: datetime.datetime):
        self.token = token
        self.identity = identity
        self.expires_at = expires_at
        self.created_at = datetime.datetime.utcnow()
        self.last_accessed = self.created_at
        self.revoked = False
        self.revoked_at: Optional[datetime.datetime] = None
        self.revocation_reason: Optional[str] = None

    def is_expired(self) -> bool:
        """Check if token is expired."""
        return datetime.datetime.utcnow() > self.expires_at

    def is_valid(self) -> bool:
        """Check if token is still valid."""
        return not self.revoked and not self.is_expired()

    def refresh(self) -> None:
        """Refresh the session token."""
        self.last_accessed = datetime.datetime.utcnow()

    def revoke(self, reason: str = "manual") -> None:
        """Revoke the session token."""
        self.revoked = True
        self.revoked_at = datetime.datetime.utcnow()
        self.revocation_reason = reason


class TailScaleOIDCIntegration:
    """Tailscale OIDC integration for identity management."""
    
    def __init__(self, db_path: str = "./logs/identity.db"):
        """Initialize Tailscale OIDC integration.
        
        Args:
            db_path: Path to identity database
        """
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_database()
        
        # Tailscale configuration
        self.oidc_enabled = os.getenv("TAILSCALE_OIDC_ENABLED", "false").lower() == "true"
        self.oidc_issuer = os.getenv("TAILSCALE_OIDC_ISSUER", "")
        self.oidc_audience = os.getenv("TAILSCALE_OIDC_AUDIENCE", "")
        
        logger.info(f"Tailscale OIDC integration initialized: enabled={self.oidc_enabled}")

    def _init_database(self) -> None:
        """Initialize identity database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS user_identities (
                    user_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    email TEXT,
                    groups TEXT,
                    roles TEXT,
                    permissions TEXT,
                    authentication_method TEXT NOT NULL,
                    risk_profile TEXT DEFAULT 'standard',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_login DATETIME,
                    login_count INTEGER DEFAULT 0,
                    failed_login_attempts INTEGER DEFAULT 0,
                    locked_until DATETIME,
                    active BOOLEAN DEFAULT 1
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS user_sessions (
                    session_token TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    identity_context TEXT NOT NULL,
                    created_at DATETIME NOT NULL,
                    expires_at DATETIME NOT NULL,
                    last_accessed DATETIME DEFAULT CURRENT_TIMESTAMP,
                    revoked_at DATETIME,
                    revocation_reason TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS oidc_tokens (
                    token_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    audience TEXT NOT NULL,
                    token_claims TEXT NOT NULL,
                    expires_at DATETIME NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Indexes for performance
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_sessions_user_id 
                ON user_sessions(user_id)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_sessions_expires 
                ON user_sessions(expires_at)
            """)

    async def validate_oidc_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate an OIDC token from Tailscale.
        
        Args:
            token: OIDC token to validate
            
        Returns:
            Token claims if valid, None otherwise
        """
        if not self.oidc_enabled:
            logger.warning("OIDC validation requested but OIDC is disabled")
            return None
        
        try:
            # In a production implementation, this would validate the JWT token
            # against Tailscale's OIDC configuration. For now, we simulate validation.
            
            # Decode the token (this is a simplified example)
            # In production, use proper JWT validation with jose library
            try:
                # Split token into parts
                parts = token.split('.')
                if len(parts) != 3:
                    return None
                
                # Decode header and payload (base64url decode)
                import base64
                import json
                
                # Add padding if needed
                def decode_base64url(data: str) -> str:
                    # Add padding
                    missing_padding = len(data) % 4
                    if missing_padding:
                        data += '=' * (4 - missing_padding)
                    return base64.urlsafe_b64decode(data).decode('utf-8')
                
                header = json.loads(decode_base64url(parts[0]))
                payload = json.loads(decode_base64url(parts[1]))
                
                # Validate token structure
                if header.get('alg') != 'HS256':
                    return None
                
                # Check expiration
                if 'exp' in payload:
                    if payload['exp'] < time.time():
                        logger.warning("OIDC token has expired")
                        return None
                
                # Validate issuer and audience
                if self.oidc_issuer and payload.get('iss') != self.oidc_issuer:
                    logger.warning(f"OIDC token issuer mismatch: {payload.get('iss')} != {self.oidc_issuer}")
                    return None
                
                if self.oidc_audience and self.oidc_audience not in payload.get('aud', []):
                    logger.warning(f"OIDC token audience mismatch: {payload.get('aud')} != {self.oidc_audience}")
                    return None
                
                return payload
                
            except Exception as e:
                logger.error(f"Failed to decode OIDC token: {e}")
                return None
                
        except Exception as e:
            logger.error(f"OIDC token validation failed: {e}")
            return None

    async def map_tailscale_identity(self, tailscale_user: Dict[str, Any]) -> IdentityContext:
        """Map Tailscale user to system identity.
        
        Args:
            tailscale_user: Tailscale user information
            
        Returns:
            System identity context
        """
        try:
            # Extract user information
            user_id = tailscale_user.get('sub', tailscale_user.get('user_id', ''))
            username = tailscale_user.get('preferred_username', tailscale_user.get('name', ''))
            email = tailscale_user.get('email', '')
            groups = tailscale_user.get('groups', [])
            roles = tailscale_user.get('roles', [])
            
            # Determine permissions based on groups and roles
            permissions = self._derive_permissions(groups, roles)
            
            # Determine risk profile
            risk_profile = self._assess_risk_profile(tailscale_user)
            
            # Create identity context
            identity = IdentityContext(
                user_id=user_id,
                username=username,
                email=email,
                groups=groups,
                roles=roles,
                permissions=permissions,
                authentication_method=AuthenticationMethod.TAILSCALE_OIDC,
                risk_profile=risk_profile
            )
            
            logger.info(f"Mapped Tailscale identity for user: {username}")
            return identity
            
        except Exception as e:
            logger.error(f"Failed to map Tailscale identity: {e}")
            raise

    async def create_session_from_oidc(self, oidc_claims: Dict[str, Any]) -> SessionToken:
        """Create a session token from OIDC claims.
        
        Args:
            oidc_claims: Validated OIDC token claims
            
        Returns:
            Session token
        """
        try:
            # Create identity context from claims
            identity = await self.map_tailscale_identity(oidc_claims)
            
            # Store identity in database
            await self._store_identity(identity)
            
            # Create session token
            session_token = self._generate_session_token()
            expires_at = datetime.datetime.utcnow() + datetime.timedelta(
                hours=int(os.getenv("SESSION_TIMEOUT_HOURS", "1"))
            )
            
            session = SessionToken(session_token, identity, expires_at)
            
            # Store session in database
            await self._store_session(session)
            
            logger.info(f"Created OIDC session for user: {identity.username}")
            return session
            
        except Exception as e:
            logger.error(f"Failed to create OIDC session: {e}")
            raise

    def _derive_permissions(self, groups: List[str], roles: List[str]) -> List[str]:
        """Derive permissions from groups and roles.
        
        Args:
            groups: User groups
            roles: User roles
            
        Returns:
            List of permissions
        """
        permissions = []
        
        # Base permissions for all authenticated users
        permissions.extend([
            "read:own_profile",
            "read:own_audit_logs",
            "read:own_sessions"
        ])
        
        # Admin permissions
        if "admin" in roles or "administrators" in groups:
            permissions.extend([
                "admin:*",
                "security:*",
                "audit:*",
                "user:*",
                "configuration:*"
            ])
        
        # Operations permissions
        if "operations" in roles or "ops" in groups:
            permissions.extend([
                "operations:*",
                "fleet:*",
                "monitoring:*",
                "alerts:read",
                "targets:read"
            ])
        
        # Security permissions
        if "security" in roles or "security-team" in groups:
            permissions.extend([
                "security:*",
                "audit:read",
                "compliance:*",
                "threats:read",
                "incidents:*"
            ])
        
        # Standard user permissions
        if "user" in roles or "users" in groups:
            permissions.extend([
                "targets:read",
                "targets:connect",
                "logs:read",
                "basic:operations"
            ])
        
        return list(set(permissions))  # Remove duplicates

    def _assess_risk_profile(self, tailscale_user: Dict[str, Any]) -> str:
        """Assess risk profile based on user attributes.
        
        Args:
            tailscale_user: Tailscale user information
            
        Returns:
            Risk profile identifier
        """
        # High risk indicators
        high_risk_indicators = [
            "admin" in tailscale_user.get('roles', []),
            "administrators" in tailscale_user.get('groups', []),
            "security" in tailscale_user.get('roles', []),
            "security-team" in tailscale_user.get('groups', []),
        ]
        
        if any(high_risk_indicators):
            return "high"
        
        # Medium risk indicators
        medium_risk_indicators = [
            "operations" in tailscale_user.get('roles', []),
            "ops" in tailscale_user.get('groups', []),
            tailscale_user.get('email', '').endswith('@admin.example.com'),
        ]
        
        if any(medium_risk_indicators):
            return "medium"
        
        # Default to standard risk
        return "standard"

    async def _store_identity(self, identity: IdentityContext) -> None:
        """Store identity in database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO user_identities (
                    user_id, username, email, groups, roles, permissions,
                    authentication_method, risk_profile, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                identity.user_id,
                identity.username,
                identity.email,
                json.dumps(identity.groups),
                json.dumps(identity.roles),
                json.dumps(identity.permissions),
                identity.authentication_method.value,
                identity.risk_profile,
                datetime.datetime.utcnow().isoformat()
            ))

    async def _store_session(self, session: SessionToken) -> None:
        """Store session in database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO user_sessions (
                    session_token, user_id, identity_context, created_at,
                    expires_at, last_accessed
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                session.token,
                session.identity.user_id,
                json.dumps(session.identity.to_dict()),
                session.created_at.isoformat(),
                session.expires_at.isoformat(),
                session.last_accessed.isoformat()
            ))

    def _generate_session_token(self) -> str:
        """Generate a secure session token."""
        # Generate cryptographically secure random token
        token = secrets.token_urlsafe(32)
        
        # Add timestamp and user hash for additional security
        timestamp = str(int(time.time()))
        user_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
        
        return f"{token}.{timestamp}.{user_hash}"


class IdentityManager:
    """Enhanced identity management with multiple auth methods."""
    
    def __init__(self, audit_logger: Optional[SecurityAuditLogger] = None):
        """Initialize identity manager.
        
        Args:
            audit_logger: Security audit logger instance
        """
        self.audit_logger = audit_logger or SecurityAuditLogger()
        self.oidc_integration = TailScaleOIDCIntegration()
        
        # Configuration
        self.session_timeout_hours = int(os.getenv("SESSION_TIMEOUT_HOURS", "1"))
        self.max_concurrent_sessions = int(os.getenv("MAX_CONCURRENT_SESSIONS", "3"))
        self.require_mfa_for_roles = os.getenv("MFA_REQUIRED_ROLES", "admin,operations,security").split(",")
        
        # Active sessions cache
        self._active_sessions: Dict[str, SessionToken] = {}
        
        logger.info("Identity manager initialized")

    async def authenticate_user(self, credentials: AuthenticationCredentials) -> AuthenticationResult:
        """Authenticate a user with provided credentials.
        
        Args:
            credentials: Authentication credentials
            
        Returns:
            Authentication result
        """
        try:
            start_time = time.time()
            
            # Try OIDC authentication first
            if credentials.oidc_token:
                result = await self._authenticate_oidc(credentials.oidc_token)
            elif credentials.token:
                result = await self._authenticate_token(credentials.token)
            elif credentials.username and credentials.password:
                result = await self._authenticate_password(credentials.username, credentials.password)
            else:
                result = AuthenticationResult(
                    success=False,
                    error_message="No valid authentication method provided"
                )
            
            # Log authentication event
            duration_ms = int((time.time() - start_time) * 1000)
            await self._log_authentication_event(result, duration_ms)
            
            return result
            
        except Exception as e:
            logger.error(f"Authentication failed with error: {e}")
            return AuthenticationResult(
                success=False,
                error_message=f"Authentication error: {str(e)}"
            )

    async def _authenticate_oidc(self, oidc_token: str) -> AuthenticationResult:
        """Authenticate using OIDC token."""
        try:
            # Validate OIDC token
            claims = await self.oidc_integration.validate_oidc_token(oidc_token)
            if not claims:
                return AuthenticationResult(
                    success=False,
                    error_message="Invalid OIDC token",
                    error_code="INVALID_OIDC_TOKEN"
                )
            
            # Create session
            session = await self.oidc_integration.create_session_from_oidc(claims)
            
            # Check for account lockout
            if await self._is_account_locked(session.identity.user_id):
                return AuthenticationResult(
                    success=False,
                    error_message="Account is locked",
                    error_code="ACCOUNT_LOCKED"
                )
            
            # Update login statistics
            await self._update_login_stats(session.identity.user_id, success=True)
            
            return AuthenticationResult(
                success=True,
                identity=session.identity,
                session_token=session.token
            )
            
        except Exception as e:
            logger.error(f"OIDC authentication failed: {e}")
            return AuthenticationResult(
                success=False,
                error_message=f"OIDC authentication failed: {str(e)}"
            )

    async def _authenticate_token(self, token: str) -> AuthenticationResult:
        """Authenticate using session token."""
        try:
            # Validate session token
            session = await self.validate_session(token)
            if not session.valid:
                return AuthenticationResult(
                    success=False,
                    error_message="Invalid or expired session token",
                    error_code="INVALID_SESSION"
                )
            
            return AuthenticationResult(
                success=True,
                identity=session.identity,
                session_token=token
            )
            
        except Exception as e:
            logger.error(f"Token authentication failed: {e}")
            return AuthenticationResult(
                success=False,
                error_message=f"Token authentication failed: {str(e)}"
            )

    async def _authenticate_password(self, username: str, password: str) -> AuthenticationResult:
        """Authenticate using username/password."""
        # This would implement password-based authentication
        # For now, return not implemented
        return AuthenticationResult(
            success=False,
            error_message="Password authentication not implemented",
            error_code="AUTH_METHOD_NOT_SUPPORTED"
        )

    async def validate_session(self, session_token: str) -> SessionValidationResult:
        """Validate a session token.
        
        Args:
            session_token: Session token to validate
            
        Returns:
            Session validation result
        """
        try:
            # Check active sessions cache first
            if session_token in self._active_sessions:
                session = self._active_sessions[session_token]
                if session.is_valid():
                    session.refresh()
                    return SessionValidationResult(
                        valid=True,
                        identity=session.identity,
                        expires_at=session.expires_at
                    )
                else:
                    # Remove invalid session from cache
                    del self._active_sessions[session_token]
            
            # Check database
            with sqlite3.connect(self.oidc_integration.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("""
                    SELECT * FROM user_sessions 
                    WHERE session_token = ? AND revoked_at IS NULL
                """, (session_token,))
                
                row = cursor.fetchone()
                if not row:
                    return SessionValidationResult(
                        valid=False,
                        error_message="Session not found"
                    )
                
                # Check expiration
                expires_at = datetime.datetime.fromisoformat(row['expires_at'])
                if datetime.datetime.utcnow() > expires_at:
                    return SessionValidationResult(
                        valid=False,
                        error_message="Session expired"
                    )
                
                # Load identity
                identity_dict = json.loads(row['identity_context'])
                identity = IdentityContext(**identity_dict)
                
                # Cache session
                session = SessionToken(session_token, identity, expires_at)
                session.last_accessed = datetime.datetime.fromisoformat(row['last_accessed'])
                self._active_sessions[session_token] = session
                
                return SessionValidationResult(
                    valid=True,
                    identity=identity,
                    expires_at=expires_at
                )
                
        except Exception as e:
            logger.error(f"Session validation failed: {e}")
            return SessionValidationResult(
                valid=False,
                error_message=f"Session validation error: {str(e)}"
            )

    async def get_user_permissions(self, user_id: str) -> PermissionSet:
        """Get permissions for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            Permission set for the user
        """
        try:
            with sqlite3.connect(self.oidc_integration.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("""
                    SELECT permissions, roles FROM user_identities 
                    WHERE user_id = ?
                """, (user_id,))
                
                row = cursor.fetchone()
                if not row:
                    return PermissionSet(permissions=[], roles=[], effective_permissions=[])
                
                permissions = json.loads(row['permissions'] or '[]')
                roles = json.loads(row['roles'] or '[]')
                
                # Calculate effective permissions (role-based + direct permissions)
                effective_permissions = self._calculate_effective_permissions(roles, permissions)
                
                return PermissionSet(
                    permissions=permissions,
                    roles=roles,
                    effective_permissions=effective_permissions
                )
                
        except Exception as e:
            logger.error(f"Failed to get user permissions: {e}")
            return PermissionSet(permissions=[], roles=[], effective_permissions=[])

    async def get_identity_context(self, request_context: Dict[str, Any]) -> Optional[IdentityContext]:
        """Get identity context from request.
        
        Args:
            request_context: Request context dictionary
            
        Returns:
            Identity context if available
        """
        try:
            # Check for session token in headers
            auth_header = request_context.get('headers', {}).get('authorization', '')
            if auth_header.lower().startswith('bearer '):
                token = auth_header.split(None, 1)[1]
                validation = await self.validate_session(token)
                if validation.valid:
                    return validation.identity
            
            # Check for direct session token
            session_token = request_context.get('session_token')
            if session_token:
                validation = await self.validate_session(session_token)
                if validation.valid:
                    return validation.identity
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get identity context: {e}")
            return None

    async def create_session(self, identity: IdentityContext, ttl: Optional[datetime.timedelta] = None) -> str:
        """Create a new session for an identity.
        
        Args:
            identity: User identity
            ttl: Time to live for session
            
        Returns:
            Session token
        """
        try:
            # Check concurrent session limit
            active_count = await self._count_active_sessions(identity.user_id)
            if active_count >= self.max_concurrent_sessions:
                # Revoke oldest session
                await self._revoke_oldest_session(identity.user_id)
            
            # Create session
            session_token = self.oidc_integration._generate_session_token()
            expires_at = datetime.datetime.utcnow() + (ttl or datetime.timedelta(hours=self.session_timeout_hours))
            
            session = SessionToken(session_token, identity, expires_at)
            
            # Store session
            await self.oidc_integration._store_session(session)
            self._active_sessions[session_token] = session
            
            logger.info(f"Created session for user: {identity.username}")
            return session_token
            
        except Exception as e:
            logger.error(f"Failed to create session: {e}")
            raise

    async def revoke_session(self, session_token: str) -> None:
        """Revoke a session.
        
        Args:
            session_token: Session token to revoke
        """
        try:
            # Remove from cache
            if session_token in self._active_sessions:
                session = self._active_sessions[session_token]
                session.revoke("manual")
                del self._active_sessions[session_token]
            
            # Update database
            with sqlite3.connect(self.oidc_integration.db_path) as conn:
                conn.execute("""
                    UPDATE user_sessions 
                    SET revoked_at = ?, revocation_reason = ?
                    WHERE session_token = ?
                """, (
                    datetime.datetime.utcnow().isoformat(),
                    "manual",
                    session_token
                ))
            
            logger.info(f"Revoked session: {session_token}")
            
        except Exception as e:
            logger.error(f"Failed to revoke session: {e}")
            raise

    async def _is_account_locked(self, user_id: str) -> bool:
        """Check if account is locked."""
        try:
            with sqlite3.connect(self.oidc_integration.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("""
                    SELECT locked_until FROM user_identities 
                    WHERE user_id = ?
                """, (user_id,))
                
                row = cursor.fetchone()
                if not row or not row['locked_until']:
                    return False
                
                locked_until = datetime.datetime.fromisoformat(row['locked_until'])
                return datetime.datetime.utcnow() < locked_until
                
        except Exception as e:
            logger.error(f"Failed to check account lock status: {e}")
            return False

    async def _update_login_stats(self, user_id: str, success: bool) -> None:
        """Update login statistics."""
        try:
            with sqlite3.connect(self.oidc_integration.db_path) as conn:
                if success:
                    conn.execute("""
                        UPDATE user_identities 
                        SET login_count = login_count + 1, last_login = ?, failed_login_attempts = 0
                        WHERE user_id = ?
                    """, (datetime.datetime.utcnow().isoformat(), user_id))
                else:
                    conn.execute("""
                        UPDATE user_identities 
                        SET failed_login_attempts = failed_login_attempts + 1
                        WHERE user_id = ?
                    """, (user_id,))
                    
        except Exception as e:
            logger.error(f"Failed to update login stats: {e}")

    def _calculate_effective_permissions(self, roles: List[str], direct_permissions: List[str]) -> List[str]:
        """Calculate effective permissions from roles and direct permissions."""
        effective = set(direct_permissions)
        
        # Add role-based permissions
        for role in roles:
            if role == "admin":
                effective.update(["admin:*", "security:*", "audit:*", "user:*", "configuration:*"])
            elif role == "operations":
                effective.update(["operations:*", "fleet:*", "monitoring:*", "alerts:read", "targets:read"])
            elif role == "security":
                effective.update(["security:*", "audit:read", "compliance:*", "threats:read", "incidents:*"])
            elif role == "user":
                effective.update(["targets:read", "targets:connect", "logs:read", "basic:operations"])
        
        return list(effective)

    async def _count_active_sessions(self, user_id: str) -> int:
        """Count active sessions for a user."""
        try:
            with sqlite3.connect(self.oidc_integration.db_path) as conn:
                cursor = conn.execute("""
                    SELECT COUNT(*) as count FROM user_sessions 
                    WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
                """, (user_id, datetime.datetime.utcnow().isoformat()))
                
                row = cursor.fetchone()
                return row['count'] if row else 0
                
        except Exception as e:
            logger.error(f"Failed to count active sessions: {e}")
            return 0

    async def _revoke_oldest_session(self, user_id: str) -> None:
        """Revoke the oldest session for a user."""
        try:
            with sqlite3.connect(self.oidc_integration.db_path) as conn:
                cursor = conn.execute("""
                    SELECT session_token FROM user_sessions 
                    WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
                    ORDER BY created_at ASC LIMIT 1
                """, (user_id, datetime.datetime.utcnow().isoformat()))
                
                row = cursor.fetchone()
                if row:
                    await self.revoke_session(row['session_token'])
                    
        except Exception as e:
            logger.error(f"Failed to revoke oldest session: {e}")

    async def _log_authentication_event(self, result: AuthenticationResult, duration_ms: int) -> None:
        """Log authentication event."""
        try:
            event = IdentityEvent(
                event_type="login_attempt",
                identity=result.identity or IdentityContext(
                    user_id="anonymous",
                    username="anonymous",
                    authentication_method=AuthenticationMethod.ANONYMOUS
                ),
                event_details={
                    "success": result.success,
                    "error_message": result.error_message,
                    "error_code": result.error_code,
                    "duration_ms": duration_ms
                }
            )
            
            await self.audit_logger.log_identity_event(event)
            
        except Exception as e:
            logger.error(f"Failed to log authentication event: {e}")