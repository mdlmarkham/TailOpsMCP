"""
Tailscale Identity Proxy authentication middleware for FastMCP.

This middleware leverages Tailscale Serve's automatic identity headers
to provide zero-configuration authentication when running behind
`tailscale serve`.

Tailscale Serve automatically injects these headers:
- Tailscale-User-Login: email address of authenticated user
- Tailscale-User-Name: display name of user
- Tailscale-User-Profile-Pic: profile picture URL

This eliminates the need for custom token management.
"""

from typing import Optional
from starlette.requests import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import logging

logger = logging.getLogger(__name__)


class TailscaleIdentity:
    """Represents an authenticated Tailscale user."""

    def __init__(self, login: str, name: str, profile_pic: Optional[str] = None):
        self.login = login  # Email address
        self.name = name  # Display name
        self.profile_pic = profile_pic

    def __repr__(self):
        return f"TailscaleIdentity(login={self.login}, name={self.name})"

    @property
    def email(self) -> str:
        """Alias for login (email address)."""
        return self.login


class TailscaleAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware that extracts Tailscale identity from request headers.

    When deployed behind `tailscale serve`, this middleware automatically
    authenticates users based on Tailscale's identity headers.

    Usage:
        app.add_middleware(TailscaleAuthMiddleware, required=True)

    Args:
        required: If True, reject requests without Tailscale identity headers
                 If False, allow unauthenticated requests (identity will be None)
    """

    def __init__(self, app, required: bool = True):
        super().__init__(app)
        self.required = required

    async def dispatch(self, request: Request, call_next):
        # Extract Tailscale identity headers
        login = request.headers.get("Tailscale-User-Login")
        name = request.headers.get("Tailscale-User-Name")
        profile_pic = request.headers.get("Tailscale-User-Profile-Pic")

        # If authentication is required but headers are missing
        if self.required and not login:
            logger.warning(f"Tailscale identity headers missing for {request.url.path}")
            return JSONResponse(
                status_code=401,
                content={
                    "error": "Unauthorized",
                    "message": "This server requires Tailscale authentication. "
                    "Please access via Tailscale Serve.",
                },
            )

        # Attach identity to request state if present
        if login and name:
            identity = TailscaleIdentity(
                login=login, name=name, profile_pic=profile_pic
            )
            request.state.tailscale_identity = identity
            logger.debug(f"Authenticated request from {identity}")
        else:
            request.state.tailscale_identity = None

        response = await call_next(request)
        return response


def get_tailscale_identity(request: Request) -> Optional[TailscaleIdentity]:
    """
    Dependency function to retrieve Tailscale identity from request.

    Usage in FastMCP tools:
        from fastmcp.server.dependencies import get_http_request
        from src.auth.tailscale_auth import get_tailscale_identity

        @mcp.tool()
        async def my_tool() -> str:
            req = get_http_request()
            identity = get_tailscale_identity(req)
            return f"Hello, {identity.name}!"

    Returns:
        TailscaleIdentity object if authenticated, None otherwise
    """
    return getattr(request.state, "tailscale_identity", None)
