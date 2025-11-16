"""TSIDP Token Introspection Verifier for FastMCP.

TSIDP issues opaque OAuth access tokens (not JWTs), so we must validate them
using RFC 7662 token introspection instead of JWT signature verification.
"""

import requests
from typing import Optional


class TSIDPIntrospectionVerifier:
    """Verify TSIDP access tokens using RFC 7662 token introspection."""
    
    def __init__(
        self,
        introspection_endpoint: str,
        client_id: str,
        client_secret: str,
        audience: Optional[str] = None,
    ):
        """Initialize the introspection verifier.
        
        Args:
            introspection_endpoint: TSIDP's introspection URL
            client_id: OAuth client ID for authentication
            client_secret: OAuth client secret for authentication
            audience: Expected audience (resource server URL)
        """
        self.introspection_endpoint = introspection_endpoint
        self.client_id = client_id
        self.client_secret = client_secret
        self.audience = audience
    
    def verify(self, token: str) -> dict:
        """Verify an access token using TSIDP introspection.
        
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
            raise ValueError("Token is not active (expired, revoked, or invalid)")
        
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
        
        # Return the full introspection response
        # Contains: sub, scope, aud, exp, iat, client_id, etc.
        return introspection_result
