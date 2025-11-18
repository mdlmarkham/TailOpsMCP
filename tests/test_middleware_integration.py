"""Integration tests for SecurityMiddleware (middleware.py)."""

import pytest
import os
from unittest.mock import Mock, patch, MagicMock
from src.auth.middleware import SecurityMiddleware, secure_tool
from src.auth.token_auth import TokenClaims
from src.utils.errors import SystemManagerError, ErrorCategory


@pytest.fixture
def middleware():
    """Create SecurityMiddleware instance."""
    os.environ["SYSTEMMANAGER_REQUIRE_AUTH"] = "true"
    os.environ["SYSTEMMANAGER_ENABLE_APPROVAL"] = "false"
    return SecurityMiddleware()


@pytest.fixture
def middleware_with_approval():
    """Create SecurityMiddleware with approval enabled."""
    os.environ["SYSTEMMANAGER_REQUIRE_AUTH"] = "true"
    os.environ["SYSTEMMANAGER_ENABLE_APPROVAL"] = "true"
    return SecurityMiddleware()


@pytest.fixture
def mock_http_request():
    """Mock HTTP request with authorization header."""
    request = Mock()
    request.headers = {"authorization": "Bearer test_token_123"}
    return request


class TestGetClaimsFromContext:
    """Test extracting and verifying token claims from various sources."""

    def test_get_claims_from_http_header(self, middleware, admin_claims):
        """Test extracting token from HTTP Authorization header."""
        mock_request = Mock()
        mock_request.headers = {"authorization": "Bearer test_token"}

        with patch('fastmcp.server.dependencies.get_http_request', return_value=mock_request):
            with patch.object(middleware.token_verifier, 'verify', return_value=admin_claims):
                claims = middleware.get_claims_from_context()

        assert claims == admin_claims
        middleware.token_verifier.verify.assert_called_once_with("test_token")

    def test_get_claims_from_kwargs_auth_token(self, middleware, admin_claims):
        """Test extracting token from kwargs auth_token parameter."""
        with patch.object(middleware.token_verifier, 'verify', return_value=admin_claims):
            claims = middleware.get_claims_from_context(auth_token="token_from_kwargs")

        assert claims == admin_claims
        middleware.token_verifier.verify.assert_called_once_with("token_from_kwargs")

    def test_get_claims_from_kwargs_headers_dict(self, middleware, admin_claims):
        """Test extracting token from kwargs headers dict."""
        headers = {"Authorization": "Bearer token_from_headers"}

        with patch.object(middleware.token_verifier, 'verify', return_value=admin_claims):
            claims = middleware.get_claims_from_context(headers=headers)

        assert claims == admin_claims
        middleware.token_verifier.verify.assert_called_once_with("token_from_headers")

    def test_get_claims_no_token_auth_required(self, middleware):
        """Test error when no token provided and auth is required."""
        with pytest.raises(SystemManagerError) as exc:
            middleware.get_claims_from_context()

        assert exc.value.category == ErrorCategory.UNAUTHORIZED
        assert "Authentication required" in str(exc.value) or "No authentication token" in str(exc.value)

    def test_get_claims_no_token_auth_not_required(self):
        """Test behavior when auth is not required but still blocks anonymous."""
        os.environ["SYSTEMMANAGER_REQUIRE_AUTH"] = "false"
        middleware = SecurityMiddleware()

        # Even with auth not required, anonymous access should be blocked
        with pytest.raises(SystemManagerError) as exc:
            middleware.get_claims_from_context()

        assert exc.value.category == ErrorCategory.UNAUTHORIZED

    def test_get_claims_invalid_token(self, middleware):
        """Test handling of invalid token."""
        with patch.object(middleware.token_verifier, 'verify', side_effect=Exception("Invalid token")):
            with pytest.raises(SystemManagerError) as exc:
                middleware.get_claims_from_context(auth_token="invalid_token")

        assert exc.value.category == ErrorCategory.UNAUTHORIZED
        assert "Token verification failed" in str(exc.value)

    def test_get_claims_http_request_fallback(self, middleware, admin_claims):
        """Test fallback to kwargs when HTTP request not available."""
        with patch('fastmcp.server.dependencies.get_http_request', side_effect=Exception("No HTTP context")):
            with patch.object(middleware.token_verifier, 'verify', return_value=admin_claims):
                claims = middleware.get_claims_from_context(auth_token="fallback_token")

        assert claims == admin_claims

    def test_get_claims_bearer_case_insensitive(self, middleware, admin_claims):
        """Test Bearer prefix is case-insensitive."""
        mock_request = Mock()
        mock_request.headers = {"authorization": "bearer lowercase_token"}

        with patch('fastmcp.server.dependencies.get_http_request', return_value=mock_request):
            with patch.object(middleware.token_verifier, 'verify', return_value=admin_claims):
                claims = middleware.get_claims_from_context()

        middleware.token_verifier.verify.assert_called_once_with("lowercase_token")


class TestCheckAuthorization:
    """Test authorization checks for tool invocations."""

    def test_check_authorization_success(self, middleware, admin_claims):
        """Test successful authorization with admin scope."""
        # Should not raise
        middleware.check_authorization("get_system_status", admin_claims)

    def test_check_authorization_readonly_on_read_tool(self, middleware, readonly_claims):
        """Test readonly scope can access read tools."""
        # Should not raise
        middleware.check_authorization("get_system_status", readonly_claims)

    def test_check_authorization_readonly_on_write_tool(self, middleware, readonly_claims):
        """Test readonly scope cannot access write tools."""
        with pytest.raises(SystemManagerError) as exc:
            middleware.check_authorization("install_package", readonly_claims)

        assert exc.value.category == ErrorCategory.FORBIDDEN
        assert "Insufficient privileges" in str(exc.value)

    def test_check_authorization_unknown_tool(self, middleware, admin_claims):
        """Test authorization check for unknown tool."""
        with pytest.raises(SystemManagerError) as exc:
            middleware.check_authorization("unknown_tool", admin_claims)

        assert exc.value.category == ErrorCategory.FORBIDDEN

    def test_check_authorization_empty_scopes(self, middleware):
        """Test authorization check with empty scopes."""
        empty_claims = TokenClaims(agent="test", scopes=[], host_tags=[], expiry=None)

        with pytest.raises(SystemManagerError):
            middleware.check_authorization("get_system_status", empty_claims)


class TestCheckApproval:
    """Test approval workflow for critical operations."""

    def test_check_approval_disabled(self, middleware):
        """Test approval check when approval is disabled."""
        result = middleware.check_approval("install_package", {"package": "nginx"})
        assert result is True

    def test_check_approval_not_required_for_tool(self, middleware_with_approval):
        """Test approval not required for low-risk tools."""
        result = middleware_with_approval.check_approval("get_system_status", {})
        assert result is True

    def test_check_approval_required_no_webhook(self, middleware_with_approval):
        """Test approval required but no webhook configured."""
        with pytest.raises(SystemManagerError) as exc:
            middleware_with_approval.check_approval("install_package", {"package": "nginx"})

        assert "requires approval" in str(exc.value).lower()

    def test_check_approval_with_webhook_configured(self, middleware_with_approval):
        """Test approval with webhook URL configured."""
        os.environ["SYSTEMMANAGER_APPROVAL_WEBHOOK"] = "https://approval.example.com/webhook"

        # Note: Actual webhook implementation would be tested separately
        # For now, middleware should recognize webhook is configured
        # This is a placeholder - actual approval flow needs to be implemented

        # The current implementation will still raise because approval flow is not implemented
        with pytest.raises(SystemManagerError):
            middleware_with_approval.check_approval("install_package", {"package": "nginx"})


class TestWrapTool:
    """Test the wrap_tool decorator functionality."""

    def test_wrap_tool_basic_functionality(self, middleware, admin_claims):
        """Test wrap_tool decorator wraps function correctly."""
        @middleware.wrap_tool("test_tool")
        async def test_function(**kwargs):
            return {"success": True}

        with patch.object(middleware, 'get_claims_from_context', return_value=admin_claims):
            with patch.object(middleware, 'check_authorization'):
                with patch.object(middleware, 'check_approval', return_value=True):
                    result = test_function(auth_token="test_token")

        # Note: If test_function is async, we need to await it
        import asyncio
        if asyncio.iscoroutine(result):
            result = asyncio.run(result)

        assert result["success"] is True

    def test_wrap_tool_audit_logging(self, middleware, admin_claims):
        """Test wrap_tool logs audit trail."""
        @middleware.wrap_tool("test_tool")
        async def test_function(**kwargs):
            return {"success": True}

        with patch.object(middleware, 'get_claims_from_context', return_value=admin_claims):
            with patch.object(middleware, 'check_authorization'):
                with patch.object(middleware, 'check_approval', return_value=True):
                    with patch.object(middleware.audit_logger, 'log') as mock_log:
                        import asyncio
                        asyncio.run(test_function(auth_token="test_token"))

        # Verify audit log was called
        mock_log.assert_called()
        call_args = mock_log.call_args[1]
        assert call_args['tool'] == 'test_tool'
        assert call_args['subject'] == 'test-admin'


class TestSecureToolDecorator:
    """Test the @secure_tool decorator."""

    def test_secure_tool_decorator(self, admin_claims):
        """Test @secure_tool decorator applies security."""
        @secure_tool
        async def protected_function(**kwargs):
            return {"data": "protected"}

        middleware = SecurityMiddleware()

        with patch.object(middleware, 'get_claims_from_context', return_value=admin_claims):
            with patch.object(middleware, 'check_authorization'):
                with patch.object(middleware, 'check_approval', return_value=True):
                    # The decorator should work
                    import asyncio
                    result = asyncio.run(protected_function(auth_token="test"))

        assert result["data"] == "protected"


class TestEndToEndAuthorization:
    """End-to-end tests for authorization flow."""

    @pytest.mark.asyncio
    async def test_full_authorization_flow_success(self, middleware, admin_claims):
        """Test complete authorization flow from token to execution."""
        @middleware.wrap_tool("get_system_status")
        async def get_status(**kwargs):
            return {"cpu": 50, "memory": 60}

        mock_request = Mock()
        mock_request.headers = {"authorization": "Bearer valid_token"}

        with patch('fastmcp.server.dependencies.get_http_request', return_value=mock_request):
            with patch.object(middleware.token_verifier, 'verify', return_value=admin_claims):
                with patch.object(middleware.audit_logger, 'log'):
                    result = await get_status()

        assert result["cpu"] == 50

    @pytest.mark.asyncio
    async def test_full_authorization_flow_denied(self, middleware, readonly_claims):
        """Test authorization flow denies insufficient privileges."""
        @middleware.wrap_tool("install_package")
        async def install(**kwargs):
            return {"success": True}

        with patch.object(middleware, 'get_claims_from_context', return_value=readonly_claims):
            with pytest.raises(SystemManagerError) as exc:
                await install()

        assert exc.value.category == ErrorCategory.FORBIDDEN

    @pytest.mark.asyncio
    async def test_full_authorization_flow_with_approval(self, middleware_with_approval, admin_claims):
        """Test authorization flow for operation requiring approval."""
        os.environ["SYSTEMMANAGER_APPROVAL_WEBHOOK"] = ""  # No webhook

        @middleware_with_approval.wrap_tool("install_package")
        async def install(**kwargs):
            return {"success": True}

        with patch.object(middleware_with_approval, 'get_claims_from_context', return_value=admin_claims):
            with pytest.raises(SystemManagerError) as exc:
                await install()

        assert "requires approval" in str(exc.value).lower()


class TestErrorHandling:
    """Test error handling in middleware."""

    def test_token_verification_error_handling(self, middleware):
        """Test graceful handling of token verification errors."""
        with patch.object(middleware.token_verifier, 'verify', side_effect=ValueError("Malformed token")):
            with pytest.raises(SystemManagerError) as exc:
                middleware.get_claims_from_context(auth_token="bad_token")

        assert exc.value.category == ErrorCategory.UNAUTHORIZED
        assert "Token verification failed" in str(exc.value)

    def test_authorization_error_has_context(self, middleware, readonly_claims):
        """Test authorization errors include helpful context."""
        with pytest.raises(SystemManagerError) as exc:
            middleware.check_authorization("manage_container", readonly_claims)

        error_message = str(exc.value)
        assert "Insufficient privileges" in error_message
        assert exc.value.category == ErrorCategory.FORBIDDEN


class TestConfigurationModes:
    """Test different configuration modes."""

    def test_auth_required_mode(self):
        """Test middleware with auth required."""
        os.environ["SYSTEMMANAGER_REQUIRE_AUTH"] = "true"
        middleware = SecurityMiddleware()

        assert middleware.require_auth is True

        with pytest.raises(SystemManagerError):
            middleware.get_claims_from_context()

    def test_approval_enabled_mode(self):
        """Test middleware with approval enabled."""
        os.environ["SYSTEMMANAGER_ENABLE_APPROVAL"] = "true"
        middleware = SecurityMiddleware()

        assert middleware.enable_approval is True

    def test_default_configuration(self):
        """Test default middleware configuration."""
        os.environ.pop("SYSTEMMANAGER_REQUIRE_AUTH", None)
        os.environ.pop("SYSTEMMANAGER_ENABLE_APPROVAL", None)
        middleware = SecurityMiddleware()

        # Default should require auth (fail closed)
        assert middleware.require_auth is True
        assert middleware.enable_approval is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
