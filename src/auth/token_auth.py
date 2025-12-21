from __future__ import annotations

import base64
import datetime
from datetime import timezone
import hashlib
import hmac
import json
import os
import inspect
from functools import wraps
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ValidationError

from src.utils.errors import ErrorCategory, SystemManagerError


class TokenClaims(BaseModel):
    agent: Optional[str]
    scopes: List[str]
    host_tags: Optional[List[str]] = None
    expiry: Optional[datetime.datetime]

    def __init__(self, **data):
        if "host_tags" not in data:
            data["host_tags"] = []
        super().__init__(**data)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TokenClaims":
        # Accept ISO8601 expiry strings
        if "expiry" in d and isinstance(d["expiry"], str):
            try:
                d = dict(d)
                d["expiry"] = datetime.datetime.fromisoformat(d["expiry"])
            except Exception:
                pass
        return cls(**d)


class TokenVerifier:
    """Verify tokens using either a shared HMAC secret or JWT (if configured).

    Behavior:
      - If `SYSTEMMANAGER_JWT_SECRET` is set and PyJWT is available, verify JWT.
      - Else if `SYSTEMMANAGER_SHARED_SECRET` is set, accept HMAC signed payloads of
        the form: base64url(JSON).hexsignature where signature = HMAC-SHA256(shared_secret, payload)
      - Else raise a useful error (no verifier configured).
    """

    def __init__(self):
        self.jwt_secret = os.getenv("SYSTEMMANAGER_JWT_SECRET")
        self.shared_secret = os.getenv("SYSTEMMANAGER_SHARED_SECRET")

        # Lazy import flag for PyJWT
        self._jwt = None
        if self.jwt_secret:
            try:
                import jwt as _jwt

                self._jwt = _jwt
            except Exception:
                self._jwt = None

    def verify(self, token: str) -> TokenClaims:
        if not token:
            raise SystemManagerError(
                "missing token", category=ErrorCategory.UNAUTHORIZED
            )

        # Try JWT path first
        if self.jwt_secret and self._jwt:
            try:
                payload = self._jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
            except Exception as e:  # pragma: no cover - runtime handling
                raise SystemManagerError(
                    f"invalid JWT: {e}", category=ErrorCategory.UNAUTHORIZED
                )
            try:
                return TokenClaims.from_dict(payload)
            except ValidationError:
                raise SystemManagerError(
                    "invalid token claims", category=ErrorCategory.UNAUTHORIZED
                )

        # Else try HMAC-shared-secret format: "<base64url_payload>.<hex_signature>"
        if self.shared_secret:
            try:
                payload_b64, sig_hex = token.split(".")
            except ValueError:
                raise SystemManagerError(
                    "malformed token", category=ErrorCategory.UNAUTHORIZED
                )

            try:
                # base64 urlsafe may be missing padding
                padding = "=" * (-len(payload_b64) % 4)
                payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
                expected_sig = hmac.new(
                    key=self.shared_secret.encode("utf-8"),
                    msg=payload_b64.encode("utf-8"),
                    digestmod=hashlib.sha256,
                ).hexdigest()
            except Exception:
                raise SystemManagerError(
                    "malformed token payload", category=ErrorCategory.UNAUTHORIZED
                )

            if not hmac.compare_digest(expected_sig, sig_hex):
                raise SystemManagerError(
                    "invalid token signature", category=ErrorCategory.UNAUTHORIZED
                )

            try:
                payload_json = json.loads(payload_bytes)
            except Exception:
                raise SystemManagerError(
                    "invalid token payload JSON", category=ErrorCategory.UNAUTHORIZED
                )

            try:
                claims = TokenClaims.from_dict(payload_json)
            except ValidationError:
                raise SystemManagerError(
                    "invalid token claims", category=ErrorCategory.UNAUTHORIZED
                )

            # Check expiry if present
            # Use timezone-aware datetime comparison
            now = datetime.datetime.now(datetime.timezone.utc)
            # Handle both naive and aware datetimes
            if claims.expiry:
                expiry = claims.expiry
                if expiry.tzinfo is None:
                    # Assume UTC for naive datetimes
                    expiry = expiry.replace(tzinfo=datetime.timezone.utc)
                if expiry < now:
                    raise SystemManagerError(
                        "token expired", category=ErrorCategory.UNAUTHORIZED
                    )

            return claims

        # No verifier configured
        raise SystemManagerError(
            "no token verifier configured", category=ErrorCategory.CONFIGURATION
        )


def require_scopes(required: List[str]):
    """Decorator to check token scopes for tool functions.

    The decorated function may accept either:
      - a kwarg `auth_token` with the token string, or
      - a kwarg `headers` which is a dict containing `Authorization: Bearer <token>`

    If no token is supplied and no verifier configured, the decorator allows execution
    (to keep Tailscale-only deployments simple). If a verifier is configured, token
    must be present and include the required scopes.
    """

    verifier = TokenVerifier()

    def decorator(fn):
        # Support decorating async and sync functions
        if inspect.iscoroutinefunction(fn):

            @wraps(fn)
            async def async_wrapper(*args, **kwargs):
                token = None
                if "auth_token" in kwargs and kwargs["auth_token"]:
                    token = kwargs.pop("auth_token")
                elif "headers" in kwargs and isinstance(kwargs["headers"], dict):
                    authh = kwargs["headers"].get("Authorization")
                    if authh and authh.lower().startswith("bearer "):
                        token = authh.split(None, 1)[1]

                if not (verifier.jwt_secret or verifier.shared_secret):
                    return await fn(*args, **kwargs)

                claims = verifier.verify(token)
                missing = [s for s in required if s not in (claims.scopes or [])]
                if missing:
                    raise SystemManagerError(
                        "insufficient scopes", category=ErrorCategory.FORBIDDEN
                    )

                kwargs["_token_claims"] = claims
                return await fn(*args, **kwargs)

            return async_wrapper

        else:

            @wraps(fn)
            def sync_wrapper(*args, **kwargs):
                token = None
                if "auth_token" in kwargs and kwargs["auth_token"]:
                    token = kwargs.pop("auth_token")
                elif "headers" in kwargs and isinstance(kwargs["headers"], dict):
                    authh = kwargs["headers"].get("Authorization")
                    if authh and authh.lower().startswith("bearer "):
                        token = authh.split(None, 1)[1]

                if not (verifier.jwt_secret or verifier.shared_secret):
                    return fn(*args, **kwargs)

                claims = verifier.verify(token)
                missing = [s for s in required if s not in (claims.scopes or [])]
                if missing:
                    raise SystemManagerError(
                        "insufficient scopes", category=ErrorCategory.FORBIDDEN
                    )

                kwargs["_token_claims"] = claims
                return fn(*args, **kwargs)

            return sync_wrapper

    return decorator
