"""
TailOpsMCP - FastMCP with HTTP Transport

Supports two authentication modes:
1. TSIDP OIDC - Uses Tailscale Identity Provider for zero-trust SSO
2. HMAC Token - Legacy token-based authentication

Set SYSTEMMANAGER_AUTH_MODE environment variable:
- "oidc" - Use TSIDP as OIDC provider (recommended)
- "token" - Use HMAC token authentication (default)
"""

import logging
import os
from src.server.config import create_mcp_instance, get_auth_mode
from src.server.dependencies import deps
from src.tools import register_all_tools

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
# Enable FastMCP auth debugging
logging.getLogger("fastmcp.server.auth").setLevel(logging.DEBUG)

# Create FastMCP instance with auth
mcp = create_mcp_instance()

# Initialize dependencies and system identity
deps.initialize_system_identity()
system_identity = deps.system_identity

# Log system identity
if system_identity:
    logger.info(f"System identity: {system_identity.get_display_name()}")
    if system_identity.get_display_name() != "TailOpsMCP":
        logger.info(f"MCP Server ID: {system_identity.get_display_name()}")

# Register all tools from tool modules
register_all_tools(mcp)

if __name__ == "__main__":
    auth_mode = get_auth_mode()
    logger.info("Starting TailOpsMCP on http://0.0.0.0:8080")
    logger.info(f"Authentication mode: {auth_mode}")

    if auth_mode == "oidc":
        logger.info("OIDC authentication via TSIDP")
        logger.info("Users will authenticate with their Tailscale identity")
        logger.info(f"OIDC Issuer: {os.getenv('TSIDP_URL', 'https://tsidp.tailf9480.ts.net')}")
    else:
        logger.info("Token-based authentication")

    logger.info("Intelligent log analysis with AI sampling enabled")

    # Use HTTP streaming transport
    mcp.run(transport="http", host="0.0.0.0", port=8080)
