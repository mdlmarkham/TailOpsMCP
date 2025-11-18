"""Server configuration and authentication setup."""
import os
import logging
from fastmcp import FastMCP

logger = logging.getLogger(__name__)

def create_mcp_instance() -> FastMCP:
    """Create and configure FastMCP instance with appropriate auth mode.

    Returns:
        Configured FastMCP instance
    """
    auth_mode = os.getenv("SYSTEMMANAGER_AUTH_MODE", "token").lower()

    if auth_mode == "oidc":
        # TSIDP OIDC Authentication
        tsidp_url = os.getenv("TSIDP_URL", "https://tsidp.tailf9480.ts.net")
        base_url = os.getenv("SYSTEMMANAGER_BASE_URL", "http://localhost:8080")
        client_id = os.getenv("TSIDP_CLIENT_ID")
        client_secret = os.getenv("TSIDP_CLIENT_SECRET")

        if not client_id or not client_secret:
            raise ValueError("TSIDP_CLIENT_ID and TSIDP_CLIENT_SECRET required for OIDC mode")

        logger.info(f"Configuring OIDC authentication with TSIDP: {tsidp_url}")

        from fastmcp.server.auth import RemoteAuthProvider
        from pydantic import AnyHttpUrl
        from src.auth.tsidp_introspection import TSIDPIntrospectionVerifier

        token_verifier = TSIDPIntrospectionVerifier(
            introspection_endpoint=f"{tsidp_url}/introspect",
            client_id=client_id,
            client_secret=client_secret,
            audience=base_url + "/mcp",
        )

        auth = RemoteAuthProvider(
            token_verifier=token_verifier,
            authorization_servers=[AnyHttpUrl(tsidp_url)],
            base_url=base_url,
        )
        mcp = FastMCP("TailOpsMCP", auth=auth)
        logger.info("OIDC authentication enabled - users will authenticate via Tailscale")
        logger.info(f"Token introspection endpoint: {tsidp_url}/introspect")
    else:
        # Token-based authentication (default)
        mcp = FastMCP("TailOpsMCP")
        logger.info("Token-based authentication enabled")

    return mcp

def get_auth_mode() -> str:
    """Get current authentication mode."""
    return os.getenv("SYSTEMMANAGER_AUTH_MODE", "token").lower()
