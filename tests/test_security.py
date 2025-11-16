"""Test security features: scopes, middleware, audit logging."""

import pytest
import os
import json
from src.auth.scopes import (
    Scope, check_authorization, expand_scopes, requires_approval, 
    get_tool_risk_level, TOOL_SCOPES
)
from src.auth.middleware import SecurityMiddleware
from src.auth.token_auth import TokenClaims
from src.utils.audit import AuditLogger


class TestScopes:
    """Test scope-based authorization."""
    
    def test_scope_expansion_readonly(self):
        """Test readonly meta-scope expands correctly."""
        scopes = expand_scopes(["readonly"])
        assert Scope.SYSTEM_READ in scopes
        assert Scope.NETWORK_READ in scopes
        assert Scope.CONTAINER_READ in scopes
        assert Scope.FILE_READ in scopes
        # Should not include write scopes
        assert Scope.CONTAINER_WRITE not in scopes
        assert Scope.SYSTEM_ADMIN not in scopes
    
    def test_scope_expansion_admin(self):
        """Test admin meta-scope grants everything."""
        scopes = expand_scopes(["admin"])
        assert Scope.SYSTEM_READ in scopes
        assert Scope.CONTAINER_WRITE in scopes
        assert Scope.SYSTEM_ADMIN in scopes
        assert Scope.DOCKER_ADMIN in scopes
    
    def test_authorization_success(self):
        """Test authorization succeeds with correct scopes."""
        authorized, reason = check_authorization(
            "get_system_status",
            [Scope.SYSTEM_READ]
        )
        assert authorized is True
        assert reason == "Authorized"
    
    def test_authorization_failure_missing_scope(self):
        """Test authorization fails without required scope."""
        authorized, reason = check_authorization(
            "manage_container",
            [Scope.CONTAINER_READ]  # Has read, needs write
        )
        assert authorized is False
        assert "Missing required scope" in reason
    
    def test_authorization_with_readonly(self):
        """Test readonly scope grants access to read operations."""
        authorized, _ = check_authorization(
            "get_system_status",
            ["readonly"]
        )
        assert authorized is True
    
    def test_authorization_with_admin(self):
        """Test admin scope grants access to everything."""
        for tool_name in TOOL_SCOPES.keys():
            authorized, _ = check_authorization(tool_name, ["admin"])
            assert authorized is True, f"Admin should have access to {tool_name}"
    
    def test_risk_levels(self):
        """Test risk level assignments."""
        assert get_tool_risk_level("get_system_status") == "low"
        assert get_tool_risk_level("ping_host") == "moderate"
        assert get_tool_risk_level("manage_container") == "high"
        assert get_tool_risk_level("install_package") == "critical"
    
    def test_approval_requirements(self):
        """Test approval requirements for critical operations."""
        # Critical operations require approval
        assert requires_approval("install_package") is True
        assert requires_approval("update_docker_container") is True
        assert requires_approval("pull_docker_image") is True
        
        # Read operations don't require approval
        assert requires_approval("get_system_status") is False
        assert requires_approval("get_container_list") is False
    
    def test_unknown_tool_denied(self):
        """Test unknown tools are denied by default."""
        authorized, reason = check_authorization(
            "unknown_dangerous_tool",
            ["admin"]
        )
        assert authorized is False
        assert "Unknown tool" in reason


class TestSecurityMiddleware:
    """Test security middleware."""
    
    def setup_method(self):
        """Set up test environment."""
        os.environ["SYSTEMMANAGER_REQUIRE_AUTH"] = "false"
        os.environ["SYSTEMMANAGER_ENABLE_APPROVAL"] = "false"
        self.middleware = SecurityMiddleware()
    
    def teardown_method(self):
        """Clean up environment."""
        os.environ.pop("SYSTEMMANAGER_REQUIRE_AUTH", None)
        os.environ.pop("SYSTEMMANAGER_ENABLE_APPROVAL", None)
    
    def test_get_claims_anonymous(self):
        """Test anonymous access when auth not required."""
        claims = self.middleware.get_claims_from_context()
        assert claims is not None
        assert claims.agent == "anonymous"
        assert "readonly" in claims.scopes
    
    def test_check_authorization_with_readonly(self):
        """Test authorization check with readonly scope."""
        claims = TokenClaims(
            agent="test",
            scopes=["readonly"],
            host_tags=[],
            expiry=None
        )
        # Should succeed for read operations
        self.middleware.check_authorization("get_system_status", claims)
        
        # Should fail for write operations
        with pytest.raises(Exception) as exc:
            self.middleware.check_authorization("install_package", claims)
        assert "Insufficient privileges" in str(exc.value)
    
    def test_check_approval_disabled(self):
        """Test approval check when approval system disabled."""
        # Should always return True when disabled
        approved = self.middleware.check_approval("install_package", {})
        assert approved is True
    
    def test_check_approval_auto_approve(self):
        """Test auto_approve flag."""
        os.environ["SYSTEMMANAGER_ENABLE_APPROVAL"] = "true"
        middleware = SecurityMiddleware()
        
        approved = middleware.check_approval(
            "install_package",
            {"auto_approve": True}
        )
        assert approved is True
    
    def test_check_approval_required_denied(self):
        """Test approval required but not granted."""
        os.environ["SYSTEMMANAGER_ENABLE_APPROVAL"] = "true"
        middleware = SecurityMiddleware()
        
        with pytest.raises(Exception) as exc:
            middleware.check_approval("install_package", {})
        assert "interactive approval" in str(exc.value).lower()


class TestAuditLogger:
    """Test enhanced audit logging."""
    
    def setup_method(self):
        """Set up test audit log."""
        self.test_log = "logs/test_audit.log"
        os.makedirs("logs", exist_ok=True)
        if os.path.exists(self.test_log):
            os.remove(self.test_log)
        self.logger = AuditLogger(path=self.test_log)
    
    def teardown_method(self):
        """Clean up test log."""
        if os.path.exists(self.test_log):
            os.remove(self.test_log)
    
    def test_basic_logging(self):
        """Test basic audit log entry."""
        self.logger.log(
            tool="get_system_status",
            args={"format": "json"},
            result={"success": True},
            subject="test-user"
        )
        
        # Read log
        with open(self.test_log) as f:
            line = f.readline()
            entry = json.loads(line)
        
        assert entry["tool"] == "get_system_status"
        assert entry["subject"] == "test-user"
        assert entry["result_status"] == "success"
    
    def test_scope_logging(self):
        """Test scopes are logged."""
        self.logger.log(
            tool="manage_container",
            args={"action": "restart"},
            result={"success": True},
            subject="admin",
            scopes=["container:write"],
            risk_level="high"
        )
        
        with open(self.test_log) as f:
            entry = json.loads(f.readline())
        
        assert entry["scopes"] == ["container:write"]
        assert entry["risk_level"] == "high"
    
    def test_approval_logging(self):
        """Test approval status is logged."""
        self.logger.log(
            tool="install_package",
            args={"package_name": "nginx"},
            result={"success": True},
            subject="admin",
            approved=True,
            risk_level="critical"
        )
        
        with open(self.test_log) as f:
            entry = json.loads(f.readline())
        
        assert entry["approved"] is True
        assert entry["risk_level"] == "critical"
    
    def test_error_logging(self):
        """Test error result logging."""
        self.logger.log(
            tool="install_package",
            args={"package_name": "nonexistent"},
            result={"success": False, "error": "Package not found"},
            subject="admin"
        )
        
        with open(self.test_log) as f:
            entry = json.loads(f.readline())
        
        assert entry["result_status"] == "error"
        assert entry["error"] == "Package not found"
    
    def test_token_redaction(self):
        """Test tokens are redacted from audit log."""
        self.logger.log(
            tool="get_system_status",
            args={"auth_token": "secret-token-12345"},
            result={"success": True},
            subject="test"
        )
        
        with open(self.test_log) as f:
            entry = json.loads(f.readline())
        
        assert entry["args"]["auth_token"] == "<REDACTED>"


class TestToolScopeMapping:
    """Test that all tools have scope mappings."""
    
    def test_all_critical_tools_mapped(self):
        """Ensure critical operations have scope requirements."""
        critical_tools = [
            "install_package",
            "update_system_packages",
            "pull_docker_image",
            "update_docker_container",
        ]
        
        for tool in critical_tools:
            assert tool in TOOL_SCOPES, f"{tool} missing scope mapping"
            assert TOOL_SCOPES[tool].risk_level == "critical"
            assert TOOL_SCOPES[tool].requires_approval is True
    
    def test_read_only_tools_low_risk(self):
        """Ensure read-only tools are low risk."""
        readonly_tools = [
            "get_system_status",
            "get_top_processes",
            "get_container_list",
            "health_check",
        ]
        
        for tool in readonly_tools:
            assert tool in TOOL_SCOPES
            assert TOOL_SCOPES[tool].risk_level in ["low", "moderate"]
            assert TOOL_SCOPES[tool].requires_approval is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
