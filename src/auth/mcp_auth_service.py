"""Utilities for exchanging TSIDP tokens with the GoFast MCP auth server."""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from datetime import timezone, timezone, timezone, timedelta, timezone
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)

DEFAULT_AUTH_URL = "https://gofastmcp.com/servers/auth/authentication"


@dataclass
class MCPTokenSession:
    """Represents an MCP token issued by the GoFast auth server."""

    access_token: str
    expires_at: datetime
    refresh_token: Optional[str] = None
    token_type: str = "Bearer"
    scope: Optional[str] = None
    issued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw_response: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self, skew_seconds: int = 30) -> bool:
        """Return True if the token is expired or about to expire."""

        return datetime.now(timezone.utc) >= (
            self.expires_at - timedelta(seconds=skew_seconds)
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the session for storage/logging."""

        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_type": self.token_type,
            "scope": self.scope,
            "expires_at": self.expires_at.isoformat(),
            "issued_at": self.issued_at.isoformat(),
            "raw_response": self.raw_response,
        }


class GoFastMCPAuthService:
    """Client for exchanging credentials with the GoFast MCP auth server."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        session_store: Optional[Dict[str, MCPTokenSession]] = None,
        http_session: Optional[requests.Session] = None,
    ) -> None:
        self.base_url = base_url or os.getenv(
            "SYSTEMMANAGER_MCP_AUTH_URL", DEFAULT_AUTH_URL
        )
        self.client_id = client_id or os.getenv("MCP_AUTH_CLIENT_ID")
        self.client_secret = client_secret or os.getenv("MCP_AUTH_CLIENT_SECRET")
        self._session_store: Dict[str, MCPTokenSession] = session_store or {}
        self._http = http_session or requests.Session()

        if not self.base_url:
            raise ValueError("SYSTEMMANAGER_MCP_AUTH_URL must be configured")

    def _post_json(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send a POST request to the GoFast auth server."""

        headers = {"Content-Type": "application/json"}
        logger.debug(
            "Sending POST request to GoFast auth server",
            extra={"url": self.base_url},
        )
        response = self._http.post(
            self.base_url, json=payload, timeout=30, headers=headers
        )
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:  # pragma: no cover - network failures in CI
            logger.error(
                "GoFast auth server returned error",
                extra={"status": response.status_code, "body": response.text},
            )
            raise RuntimeError(f"GoFast MCP auth request failed: {exc}") from exc

        return response.json()

    def _persist_session(
        self, session_id: str, token_payload: Dict[str, Any]
    ) -> MCPTokenSession:
        expires_in = token_payload.get("expires_in", 3600)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(expires_in))
        session = MCPTokenSession(
            access_token=token_payload["access_token"],
            refresh_token=token_payload.get("refresh_token"),
            token_type=token_payload.get("token_type", "Bearer"),
            scope=token_payload.get("scope"),
            expires_at=expires_at,
            raw_response=token_payload,
        )
        self._session_store[session_id] = session
        logger.info(
            "Stored MCP token session",
            extra={"session_id": session_id, "expires_at": expires_at.isoformat()},
        )
        return session

    def exchange_tsidp_token(
        self,
        *,
        id_token: str,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        session_id: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> MCPTokenSession:
        """Exchange TSIDP-issued tokens for a GoFast MCP token."""

        if not id_token:
            raise ValueError("id_token is required to exchange with GoFast MCP")

        payload: Dict[str, Any] = {
            "grant_type": "tsidp_token",
            "tsidp_id_token": id_token,
        }
        if access_token:
            payload["tsidp_access_token"] = access_token
        if refresh_token:
            payload["tsidp_refresh_token"] = refresh_token
        if self.client_id:
            payload["client_id"] = self.client_id
        if self.client_secret:
            payload["client_secret"] = self.client_secret
        if extra:
            payload.update(extra)

        token_payload = self._post_json(payload)
        session_key = (
            session_id
            or token_payload.get("subject")
            or token_payload.get("sub")
            or str(int(time.time()))
        )
        return self._persist_session(session_key, token_payload)

    def login_with_credentials(
        self,
        *,
        username: str,
        password: str,
        scope: Optional[str] = None,
        session_id: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> MCPTokenSession:
        """Perform a username/password login with the GoFast server."""

        payload: Dict[str, Any] = {
            "grant_type": "password",
            "username": username,
            "password": password,
        }
        if scope:
            payload["scope"] = scope
        if self.client_id:
            payload["client_id"] = self.client_id
        if self.client_secret:
            payload["client_secret"] = self.client_secret
        if extra:
            payload.update(extra)

        token_payload = self._post_json(payload)
        session_key = session_id or token_payload.get("subject") or username
        return self._persist_session(session_key, token_payload)

    def get_session(self, session_id: str) -> Optional[MCPTokenSession]:
        """Return a cached session if it exists and is not expired."""

        session = self._session_store.get(session_id)
        if not session:
            return None
        if session.is_expired():
            logger.info(
                "MCP session expired; removing", extra={"session_id": session_id}
            )
            self._session_store.pop(session_id, None)
            return None
        return session

    def store_session(self, session_id: str, session: MCPTokenSession) -> None:
        """Manually persist a session issued elsewhere."""

        self._session_store[session_id] = session

    def clear_sessions(self) -> None:
        """Remove all cached sessions (e.g., during logout)."""

        self._session_store.clear()
