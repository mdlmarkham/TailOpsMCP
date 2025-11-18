"""TSIDP Token Introspection Verifier for FastMCP.

TSIDP issues opaque OAuth access tokens (not JWTs), so we must validate them
using RFC 7662 token introspection instead of JWT signature verification.
"""

import asyncio
import requests
from typing import Optional
from fastmcp.server.auth import AccessToken, TokenVerifier


class TSIDPIntrospectionVerifier(TokenVerifier):
    """Verify TSIDP access tokens using RFC 7662 token introspection."""
    
    def __init__(
        self,
        introspection_endpoint: str,
        client_id: str,
        client_secret: str,
        audience: Optional[str] = None,
        required_scopes: Optional[list[str]] = None,
    ):
        """Initialize the introspection verifier.
        
        Args:
            introspection_endpoint: TSIDP's introspection URL
            client_id: OAuth client ID for authentication
            client_secret: OAuth client secret for authentication
            audience: Expected audience (resource server URL)
            required_scopes: List of required OAuth scopes
        """
        self.introspection_endpoint = introspection_endpoint
        self.client_id = client_id
        self.client_secret = client_secret
        self.audience = audience
        self.required_scopes = required_scopes or []
    
    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify an access token using TSIDP introspection (async wrapper).
        
        Args:
            token: The opaque access token from the Authorization header
            
        Returns:
            AccessToken object with token claims, or None if invalid
            
        Raises:
            ValueError: If the token is invalid or inactive
        """
        # Run the blocking HTTP call in a thread pool
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._verify_sync, token)
    
    def _verify_sync(self, token: str) -> AccessToken | None:
        """Synchronous token verification implementation.
        
        Args:
            token: The opaque access token from the Authorization header
            
        Returns:
            dict: The introspection response with token claims
            
        Raises:
            ValueError: If the token is invalid or inactive
        """
        if not token:
            raise ValueError("No token provided")
        
        # Call TSIDP introspection endpoint
        # RFC 7662: POST with client credentials and token parameter
        response = requests.post(
            self.introspection_endpoint,
            auth=(self.client_id, self.client_secret),  # HTTP Basic Auth
            data={"token": token},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )
        
        if response.status_code != 200:
            raise ValueError(
                f"Introspection failed: HTTP {response.status_code} - {response.text}"
            )
        
        introspection_result = response.json()
        
        # RFC 7662: Check if token is active
        if not introspection_result.get("active", False):
            return None  # Token is not active
        
        # Validate audience if specified
        if self.audience:
            token_aud = introspection_result.get("aud")
            # aud can be a string or list of strings
            if isinstance(token_aud, str):
                token_aud = [token_aud]
            if token_aud and self.audience not in token_aud:
                raise ValueError(
                    f"Audience mismatch: expected {self.audience}, got {token_aud}"
                )
        
        # Convert introspection response to AccessToken
        # RFC 7662 fields: active, scope, client_id, username, token_type, exp, iat, nbf, sub, aud, iss, jti
        scopes_str = introspection_result.get("scope", "")
        scopes = scopes_str.split() if scopes_str else []
        
        return AccessToken(
            token=token,
            client_id=introspection_result.get("client_id", ""),
            scopes=scopes,
            expires_at=introspection_result.get("exp"),  # Unix timestamp
            resource=self.audience,
            claims=introspection_result,  # Store full introspection response
        )
