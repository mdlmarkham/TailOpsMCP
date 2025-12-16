"""TSIDP login flow helpers that integrate with the GoFast MCP auth server."""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, Optional
from urllib.parse import urlencode

import requests

from .mcp_auth_service import GoFastMCPAuthService, MCPTokenSession

logger = logging.getLogger(__name__)


@dataclass
class PendingLogin:
    state: str
    code_verifier: str
    created_at: datetime

    def is_expired(self, ttl_seconds: int = 600) -> bool:
        return datetime.utcnow() >= self.created_at + timedelta(seconds=ttl_seconds)


class TSIDPLoginController:
    """Coordinate TSIDP OAuth (PKCE) login with GoFast MCP token exchange."""

    def __init__(
        self,
        *,
        tsidp_url: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        scopes: Optional[str] = None,
        auth_service: Optional[GoFastMCPAuthService] = None,
        http_session: Optional[requests.Session] = None,
    ) -> None:
        self.tsidp_url = tsidp_url or os.getenv(
            "TSIDP_URL", "https://tsidp.tailf9480.ts.net"
        )
        self.client_id = client_id or os.getenv("TSIDP_CLIENT_ID")
        self.client_secret = client_secret or os.getenv("TSIDP_CLIENT_SECRET")
        self.redirect_uri = redirect_uri or os.getenv(
            "TSIDP_REDIRECT_URI", "http://localhost:8900/callback"
        )
        self.scope = scopes or os.getenv("TSIDP_SCOPES", "openid profile email")
        self.auth_service = auth_service or GoFastMCPAuthService()
        self._http = http_session or requests.Session()
        self._metadata: Optional[Dict[str, str]] = None
        self._pending: Dict[str, PendingLogin] = {}
        self._lock = threading.Lock()

    def _discover_metadata(self) -> Dict[str, str]:
        if self._metadata:
            return self._metadata

        well_known = f"{self.tsidp_url}/.well-known/openid-configuration"
        logger.info("Fetching TSIDP metadata", extra={"url": well_known})
        response = self._http.get(well_known, timeout=15)
        response.raise_for_status()
        data = response.json()
        required_keys = {"authorization_endpoint", "token_endpoint"}
        missing = required_keys - data.keys()
        if missing:
            raise RuntimeError(f"TSIDP metadata missing required keys: {missing}")
        self._metadata = data
        return data

    @staticmethod
    def _generate_pkce_pair() -> Dict[str, str]:
        code_verifier = (
            base64.urlsafe_b64encode(os.urandom(64)).rstrip(b"=").decode("utf-8")
        )
        challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = (
            base64.urlsafe_b64encode(challenge).rstrip(b"=").decode("utf-8")
        )
        return {"code_verifier": code_verifier, "code_challenge": code_challenge}

    def start_login(self, state: Optional[str] = None) -> Dict[str, str]:
        """Generate the TSIDP authorization URL for interactive login."""

        if not self.client_id:
            raise RuntimeError("TSIDP_CLIENT_ID is required to start the login flow")

        metadata = self._discover_metadata()
        state_value = state or secrets.token_urlsafe(24)
        pkce = self._generate_pkce_pair()
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "state": state_value,
            "code_challenge": pkce["code_challenge"],
            "code_challenge_method": "S256",
        }
        authorization_url = f"{metadata['authorization_endpoint']}?{urlencode(params)}"

        with self._lock:
            self._pending[state_value] = PendingLogin(
                state=state_value,
                code_verifier=pkce["code_verifier"],
                created_at=datetime.utcnow(),
            )

        logger.debug("Prepared TSIDP login", extra={"state": state_value})
        return {
            "authorization_url": authorization_url,
            "state": state_value,
            "code_verifier": pkce["code_verifier"],
            "code_challenge": pkce["code_challenge"],
            "expires_at": (datetime.utcnow() + timedelta(minutes=10)).isoformat(),
        }

    def _pop_pending(self, state: str) -> PendingLogin:
        with self._lock:
            entry = self._pending.pop(state, None)
        if not entry or entry.is_expired():
            raise RuntimeError("Login state expired or unknown")
        return entry

    def _exchange_code(self, code: str, code_verifier: str) -> Dict[str, str]:
        metadata = self._discover_metadata()
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "code_verifier": code_verifier,
            "client_id": self.client_id,
        }
        if self.client_secret:
            payload["client_secret"] = self.client_secret

        response = self._http.post(metadata["token_endpoint"], data=payload, timeout=15)
        response.raise_for_status()
        return response.json()

    def complete_login(self, *, code: str, state: str) -> Dict[str, Dict[str, str]]:
        """Finalize the login by exchanging the TSIDP code and calling GoFast MCP."""

        if not code or not state:
            raise ValueError("code and state are required")

        pending = self._pop_pending(state)
        tsidp_tokens = self._exchange_code(code, pending.code_verifier)
        mcp_session = self.auth_service.exchange_tsidp_token(
            id_token=tsidp_tokens.get("id_token", ""),
            access_token=tsidp_tokens.get("access_token"),
            refresh_token=tsidp_tokens.get("refresh_token"),
            session_id=tsidp_tokens.get("id_token") or state,
        )

        return {
            "tsidp": {
                "access_token": tsidp_tokens.get("access_token"),
                "refresh_token": tsidp_tokens.get("refresh_token"),
                "id_token": tsidp_tokens.get("id_token"),
                "expires_in": tsidp_tokens.get("expires_in"),
                "token_type": tsidp_tokens.get("token_type"),
                "scope": tsidp_tokens.get("scope"),
            },
            "mcp": mcp_session.to_dict(),
        }

    def refresh_mcp_session(self, session_id: str) -> Optional[MCPTokenSession]:
        """Return a cached MCP session if it remains valid."""

        return self.auth_service.get_session(session_id)

    def cleanup_expired_states(self) -> None:
        """Remove expired pending login states to avoid leaks."""

        with self._lock:
            stale_states = [
                key for key, entry in self._pending.items() if entry.is_expired()
            ]
            for key in stale_states:
                self._pending.pop(key, None)
                logger.debug("Removed stale TSIDP login state", extra={"state": key})
