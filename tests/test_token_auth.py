import os
import base64
import json
import hmac
import hashlib
import datetime

import pytest

from src.auth.token_auth import TokenVerifier, TokenClaims


def make_hmac_token(claims: dict, secret: bytes) -> str:
    payload = json.dumps(claims, separators=(",",":")).encode()
    payload_b64 = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    sig = hmac.new(secret, payload_b64.encode(), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{sig}"


def test_hmac_token_verify(monkeypatch):
    secret = b"test-shared-secret"
    monkeypatch.setenv("SYSTEMMANAGER_SHARED_SECRET", secret.decode())

    expiry = (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).isoformat()
    claims = {"agent": "test-agent", "scopes": ["monitor"], "expiry": expiry}
    token = make_hmac_token(claims, secret)

    verifier = TokenVerifier()
    verified = verifier.verify(token)

    assert isinstance(verified, TokenClaims)
    assert verified.agent == "test-agent"
    assert "monitor" in verified.scopes


def test_hmac_token_expired(monkeypatch):
    secret = b"test-shared-secret"
    monkeypatch.setenv("SYSTEMMANAGER_SHARED_SECRET", secret.decode())

    expiry = (datetime.datetime.utcnow() - datetime.timedelta(hours=1)).isoformat()
    claims = {"agent": "test-agent", "scopes": ["monitor"], "expiry": expiry}
    token = make_hmac_token(claims, secret)

    verifier = TokenVerifier()
    with pytest.raises(Exception):
        verifier.verify(token)
