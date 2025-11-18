"""Tests for TSIDP OAuth login flow (tsidp_login.py)."""

import pytest
import requests_mock
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from src.auth.tsidp_login import TSIDPLoginController, PendingLogin
from src.auth.mcp_auth_service import MCPTokenSession


@pytest.fixture
def mock_auth_service():
    """Mock GoFast MCP Auth Service."""
    service = Mock()
    session = MCPTokenSession(
        access_token="mcp_token_abc",
        expires_at=datetime.utcnow() + timedelta(hours=1),
        refresh_token="refresh_token_xyz",
        scope="read write"
    )
    service.exchange_tsidp_token.return_value = session
    service.get_session.return_value = session
    return service


@pytest.fixture
def tsidp_controller(mock_auth_service):
    """Create a TSIDP login controller with mocked dependencies."""
    return TSIDPLoginController(
        tsidp_url="https://tsidp.example.ts.net",
        client_id="test-client-id",
        client_secret="test-client-secret",
        redirect_uri="http://localhost:8900/callback",
        scopes="openid profile email",
        auth_service=mock_auth_service
    )


class TestPendingLogin:
    """Test PendingLogin state tracking."""

    def test_pending_login_not_expired(self):
        """Test pending login within TTL."""
        login = PendingLogin(
            state="state123",
            code_verifier="verifier456",
            created_at=datetime.utcnow()
        )
        assert not login.is_expired(ttl_seconds=600)

    def test_pending_login_expired(self):
        """Test pending login past TTL."""
        login = PendingLogin(
            state="state123",
            code_verifier="verifier456",
            created_at=datetime.utcnow() - timedelta(seconds=601)
        )
        assert login.is_expired(ttl_seconds=600)

    def test_pending_login_exactly_at_expiry(self):
        """Test pending login exactly at expiry time."""
        login = PendingLogin(
            state="state123",
            code_verifier="verifier456",
            created_at=datetime.utcnow() - timedelta(seconds=600)
        )
        assert login.is_expired(ttl_seconds=600)


class TestTSIDPLoginController:
    """Test TSIDP OAuth login controller."""

    def test_initialization_from_env(self, monkeypatch):
        """Test controller initialization from environment variables."""
        monkeypatch.setenv("TSIDP_URL", "https://custom.ts.net")
        monkeypatch.setenv("TSIDP_CLIENT_ID", "env-client-id")
        monkeypatch.setenv("TSIDP_CLIENT_SECRET", "env-secret")
        monkeypatch.setenv("TSIDP_REDIRECT_URI", "http://custom/callback")

        controller = TSIDPLoginController()

        assert controller.tsidp_url == "https://custom.ts.net"
        assert controller.client_id == "env-client-id"
        assert controller.client_secret == "env-secret"
        assert controller.redirect_uri == "http://custom/callback"

    def test_initialization_explicit_params(self):
        """Test controller initialization with explicit parameters."""
        controller = TSIDPLoginController(
            tsidp_url="https://explicit.ts.net",
            client_id="explicit-id",
            client_secret="explicit-secret"
        )

        assert controller.tsidp_url == "https://explicit.ts.net"
        assert controller.client_id == "explicit-id"
        assert controller.client_secret == "explicit-secret"

    def test_discover_metadata_success(self, tsidp_controller):
        """Test successful metadata discovery."""
        with requests_mock.Mocker() as m:
            m.get(
                "https://tsidp.example.ts.net/.well-known/openid-configuration",
                json={
                    "authorization_endpoint": "https://tsidp.example.ts.net/authorize",
                    "token_endpoint": "https://tsidp.example.ts.net/oauth/token",
                    "issuer": "https://tsidp.example.ts.net"
                }
            )

            metadata = tsidp_controller._discover_metadata()

            assert metadata["authorization_endpoint"] == "https://tsidp.example.ts.net/authorize"
            assert metadata["token_endpoint"] == "https://tsidp.example.ts.net/oauth/token"

    def test_discover_metadata_caching(self, tsidp_controller):
        """Test metadata is cached after first discovery."""
        with requests_mock.Mocker() as m:
            mock_endpoint = m.get(
                "https://tsidp.example.ts.net/.well-known/openid-configuration",
                json={
                    "authorization_endpoint": "https://tsidp.example.ts.net/authorize",
                    "token_endpoint": "https://tsidp.example.ts.net/oauth/token"
                }
            )

            # First call
            metadata1 = tsidp_controller._discover_metadata()
            # Second call
            metadata2 = tsidp_controller._discover_metadata()

            assert metadata1 == metadata2
            # Should only be called once due to caching
            assert mock_endpoint.call_count == 1

    def test_discover_metadata_missing_required_keys(self, tsidp_controller):
        """Test metadata discovery fails with missing required keys."""
        with requests_mock.Mocker() as m:
            m.get(
                "https://tsidp.example.ts.net/.well-known/openid-configuration",
                json={"issuer": "https://tsidp.example.ts.net"}  # Missing required endpoints
            )

            with pytest.raises(RuntimeError, match="missing required keys"):
                tsidp_controller._discover_metadata()

    def test_generate_pkce_pair(self):
        """Test PKCE code_verifier and code_challenge generation."""
        pkce = TSIDPLoginController._generate_pkce_pair()

        assert "code_verifier" in pkce
        assert "code_challenge" in pkce
        assert len(pkce["code_verifier"]) > 40  # Should be base64-encoded random
        assert len(pkce["code_challenge"]) > 40  # Should be SHA256 hash
        assert pkce["code_verifier"] != pkce["code_challenge"]

    def test_generate_pkce_pair_uniqueness(self):
        """Test PKCE pairs are unique across calls."""
        pkce1 = TSIDPLoginController._generate_pkce_pair()
        pkce2 = TSIDPLoginController._generate_pkce_pair()

        assert pkce1["code_verifier"] != pkce2["code_verifier"]
        assert pkce1["code_challenge"] != pkce2["code_challenge"]

    def test_start_login_success(self, tsidp_controller):
        """Test starting login flow generates correct authorization URL."""
        with requests_mock.Mocker() as m:
            m.get(
                "https://tsidp.example.ts.net/.well-known/openid-configuration",
                json={
                    "authorization_endpoint": "https://tsidp.example.ts.net/authorize",
                    "token_endpoint": "https://tsidp.example.ts.net/oauth/token"
                }
            )

            result = tsidp_controller.start_login()

            assert "authorization_url" in result
            assert "state" in result
            assert "code_verifier" in result
            assert "code_challenge" in result
            assert "expires_at" in result

            # Verify URL contains required parameters
            url = result["authorization_url"]
            assert "response_type=code" in url
            assert "client_id=test-client-id" in url
            assert f"state={result['state']}" in url
            assert "code_challenge=" in url
            assert "code_challenge_method=S256" in url

    def test_start_login_missing_client_id(self, mock_auth_service):
        """Test start_login fails without client_id."""
        controller = TSIDPLoginController(
            tsidp_url="https://tsidp.example.ts.net",
            client_id=None,
            auth_service=mock_auth_service
        )

        with pytest.raises(RuntimeError, match="TSIDP_CLIENT_ID is required"):
            controller.start_login()

    def test_start_login_custom_state(self, tsidp_controller):
        """Test start_login with custom state value."""
        with requests_mock.Mocker() as m:
            m.get(
                "https://tsidp.example.ts.net/.well-known/openid-configuration",
                json={
                    "authorization_endpoint": "https://tsidp.example.ts.net/authorize",
                    "token_endpoint": "https://tsidp.example.ts.net/oauth/token"
                }
            )

            result = tsidp_controller.start_login(state="custom-state-123")

            assert result["state"] == "custom-state-123"
            assert "state=custom-state-123" in result["authorization_url"]

    def test_start_login_stores_pending(self, tsidp_controller):
        """Test start_login stores pending login state."""
        with requests_mock.Mocker() as m:
            m.get(
                "https://tsidp.example.ts.net/.well-known/openid-configuration",
                json={
                    "authorization_endpoint": "https://tsidp.example.ts.net/authorize",
                    "token_endpoint": "https://tsidp.example.ts.net/oauth/token"
                }
            )

            result = tsidp_controller.start_login()
            state = result["state"]

            # Verify pending login is stored
            assert state in tsidp_controller._pending
            assert tsidp_controller._pending[state].code_verifier == result["code_verifier"]

    def test_complete_login_success(self, tsidp_controller, mock_auth_service):
        """Test successful login completion."""
        with requests_mock.Mocker() as m:
            # Mock metadata discovery
            m.get(
                "https://tsidp.example.ts.net/.well-known/openid-configuration",
                json={
                    "authorization_endpoint": "https://tsidp.example.ts.net/authorize",
                    "token_endpoint": "https://tsidp.example.ts.net/oauth/token"
                }
            )

            # Mock token exchange
            m.post(
                "https://tsidp.example.ts.net/oauth/token",
                json={
                    "access_token": "tsidp_access_token",
                    "refresh_token": "tsidp_refresh_token",
                    "id_token": "tsidp_id_token",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                    "scope": "openid profile email"
                }
            )

            # Start login to create pending state
            start_result = tsidp_controller.start_login()
            state = start_result["state"]

            # Complete login
            result = tsidp_controller.complete_login(code="auth_code_123", state=state)

            assert "tsidp" in result
            assert "mcp" in result
            assert result["tsidp"]["access_token"] == "tsidp_access_token"
            assert result["tsidp"]["refresh_token"] == "tsidp_refresh_token"
            assert result["tsidp"]["id_token"] == "tsidp_id_token"

            # Verify auth service was called
            mock_auth_service.exchange_tsidp_token.assert_called_once()

    def test_complete_login_missing_code(self, tsidp_controller):
        """Test complete_login fails without code."""
        with pytest.raises(ValueError, match="code and state are required"):
            tsidp_controller.complete_login(code="", state="some-state")

    def test_complete_login_missing_state(self, tsidp_controller):
        """Test complete_login fails without state."""
        with pytest.raises(ValueError, match="code and state are required"):
            tsidp_controller.complete_login(code="some-code", state="")

    def test_complete_login_expired_state(self, tsidp_controller):
        """Test complete_login fails with expired state."""
        with requests_mock.Mocker() as m:
            m.get(
                "https://tsidp.example.ts.net/.well-known/openid-configuration",
                json={
                    "authorization_endpoint": "https://tsidp.example.ts.net/authorize",
                    "token_endpoint": "https://tsidp.example.ts.net/oauth/token"
                }
            )

            # Create expired pending login
            expired_login = PendingLogin(
                state="expired-state",
                code_verifier="verifier123",
                created_at=datetime.utcnow() - timedelta(seconds=601)
            )
            tsidp_controller._pending["expired-state"] = expired_login

            with pytest.raises(RuntimeError, match="Login state expired or unknown"):
                tsidp_controller.complete_login(code="code123", state="expired-state")

    def test_complete_login_unknown_state(self, tsidp_controller):
        """Test complete_login fails with unknown state."""
        with pytest.raises(RuntimeError, match="Login state expired or unknown"):
            tsidp_controller.complete_login(code="code123", state="unknown-state")

    def test_complete_login_removes_pending_state(self, tsidp_controller, mock_auth_service):
        """Test complete_login removes pending state after use."""
        with requests_mock.Mocker() as m:
            m.get(
                "https://tsidp.example.ts.net/.well-known/openid-configuration",
                json={
                    "authorization_endpoint": "https://tsidp.example.ts.net/authorize",
                    "token_endpoint": "https://tsidp.example.ts.net/oauth/token"
                }
            )

            m.post(
                "https://tsidp.example.ts.net/oauth/token",
                json={
                    "access_token": "token",
                    "id_token": "id_token"
                }
            )

            # Start and complete login
            start_result = tsidp_controller.start_login()
            state = start_result["state"]
            tsidp_controller.complete_login(code="code123", state=state)

            # State should be removed
            assert state not in tsidp_controller._pending

    def test_refresh_mcp_session(self, tsidp_controller, mock_auth_service):
        """Test refreshing MCP session."""
        session = tsidp_controller.refresh_mcp_session("session-123")

        assert session is not None
        mock_auth_service.get_session.assert_called_once_with("session-123")

    def test_cleanup_expired_states(self, tsidp_controller):
        """Test cleanup removes expired states."""
        # Add fresh state
        fresh_login = PendingLogin(
            state="fresh-state",
            code_verifier="verifier1",
            created_at=datetime.utcnow()
        )
        tsidp_controller._pending["fresh-state"] = fresh_login

        # Add expired state
        expired_login = PendingLogin(
            state="expired-state",
            code_verifier="verifier2",
            created_at=datetime.utcnow() - timedelta(seconds=601)
        )
        tsidp_controller._pending["expired-state"] = expired_login

        # Cleanup
        tsidp_controller.cleanup_expired_states()

        # Fresh state should remain, expired should be removed
        assert "fresh-state" in tsidp_controller._pending
        assert "expired-state" not in tsidp_controller._pending

    def test_cleanup_expired_states_no_states(self, tsidp_controller):
        """Test cleanup with no pending states."""
        tsidp_controller.cleanup_expired_states()  # Should not raise

    def test_thread_safety_start_login(self, tsidp_controller):
        """Test start_login thread safety with concurrent calls."""
        import threading

        with requests_mock.Mocker() as m:
            m.get(
                "https://tsidp.example.ts.net/.well-known/openid-configuration",
                json={
                    "authorization_endpoint": "https://tsidp.example.ts.net/authorize",
                    "token_endpoint": "https://tsidp.example.ts.net/oauth/token"
                }
            )

            results = []

            def start_login_thread():
                result = tsidp_controller.start_login()
                results.append(result)

            threads = [threading.Thread(target=start_login_thread) for _ in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            # All states should be unique
            states = [r["state"] for r in results]
            assert len(states) == len(set(states))

            # All states should be in pending
            for state in states:
                assert state in tsidp_controller._pending


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
