"""Tests for security scanning and hardening tools."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from src.security import SecurityScanner
from src.services.secrets_scanner import SecretsScanner
from src.services.firewall_manager import FirewallManager
from src.services.cis_checker import CISChecker


class TestSecurityScanner:
    """Test SecurityScanner service."""

    @pytest.mark.asyncio
    async def test_scanner_initialization(self):
        """Test scanner initializes correctly."""
        scanner = SecurityScanner()
        assert isinstance(scanner, SecurityScanner)

    @pytest.mark.asyncio
    async def test_get_scanner_info(self):
        """Test getting scanner info."""
        scanner = SecurityScanner()
        info = scanner.get_scanner_info()

        assert "trivy_available" in info
        assert "grype_available" in info
        assert isinstance(info["trivy_available"], bool)
        assert isinstance(info["grype_available"], bool)

    @pytest.mark.asyncio
    async def test_scan_image_no_scanner(self):
        """Test scan when no scanner is available."""
        with patch("shutil.which", return_value=None):
            scanner = SecurityScanner()
            result = await scanner.scan_image("nginx:latest")

            assert result["success"] is False
            assert "No vulnerability scanner found" in result["error"]
            assert "install_hints" in result


class TestSecretsScanner:
    """Test SecretsScanner service."""

    @pytest.mark.asyncio
    async def test_scanner_initialization(self):
        """Test secrets scanner initializes correctly."""
        scanner = SecretsScanner()
        assert isinstance(scanner, SecretsScanner)
        assert len(scanner.compiled_patterns) > 0

    @pytest.mark.asyncio
    async def test_scan_file_not_found(self):
        """Test scanning a non-existent file."""
        scanner = SecretsScanner()
        result = await scanner.scan_file("/nonexistent/file.txt")

        assert result["success"] is False
        assert "not found" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_redact_secret(self):
        """Test secret redaction."""
        scanner = SecretsScanner()

        # Test long secret
        secret = "AKIAIOSFODNN7EXAMPLE"
        redacted = scanner._redact_secret(secret)
        assert "AKIA" in redacted
        assert "MPLE" in redacted
        assert len(redacted) < len(secret)

        # Test short secret
        short = "abc"
        redacted_short = scanner._redact_secret(short)
        assert redacted_short == "***REDACTED***"

    @pytest.mark.asyncio
    async def test_get_severity(self):
        """Test severity classification."""
        scanner = SecretsScanner()

        assert scanner._get_severity("aws_secret_key") == "CRITICAL"
        assert scanner._get_severity("aws_access_key") == "HIGH"
        assert scanner._get_severity("generic_api_key") == "MEDIUM"
        assert scanner._get_severity("unknown_type") == "LOW"


class TestFirewallManager:
    """Test FirewallManager service."""

    @pytest.mark.asyncio
    async def test_manager_initialization(self):
        """Test firewall manager initializes correctly."""
        manager = FirewallManager()
        assert isinstance(manager, FirewallManager)

    @pytest.mark.asyncio
    async def test_get_firewall_info(self):
        """Test getting firewall info."""
        manager = FirewallManager()
        info = manager.get_firewall_info()

        assert "ufw_available" in info
        assert "iptables_available" in info
        assert isinstance(info["ufw_available"], bool)
        assert isinstance(info["iptables_available"], bool)

    @pytest.mark.asyncio
    async def test_add_rule_validation(self):
        """Test add rule validation."""
        manager = FirewallManager()

        # Test invalid action
        result = await manager.add_rule("invalid", 22)
        assert result["success"] is False
        assert "must be" in result["error"]

        # Test invalid protocol
        result = await manager.add_rule("allow", 22, "invalid")
        assert result["success"] is False
        assert "Protocol must be" in result["error"]


class TestCISChecker:
    """Test CISChecker service."""

    @pytest.mark.asyncio
    async def test_checker_initialization(self):
        """Test CIS checker initializes correctly."""
        checker = CISChecker()
        assert isinstance(checker, CISChecker)

    @pytest.mark.asyncio
    async def test_run_assessment_basic(self):
        """Test running basic CIS assessment."""
        checker = CISChecker()
        result = await checker.run_assessment("basic")

        assert result["success"] is True
        assert result["profile"] == "basic"
        assert "total_checks" in result
        assert "passed" in result
        assert "failed" in result
        assert "warnings" in result
        assert "score" in result
        assert "checks" in result
        assert isinstance(result["checks"], list)
        assert result["total_checks"] > 0

    @pytest.mark.asyncio
    async def test_run_assessment_invalid_profile(self):
        """Test running assessment with invalid profile."""
        checker = CISChecker()
        result = await checker.run_assessment("invalid")

        assert result["success"] is False
        assert "Unknown profile" in result["error"]

    @pytest.mark.asyncio
    async def test_check_file_permissions(self):
        """Test file permissions check."""
        checker = CISChecker()

        # Test existing file (should work for /etc/passwd on most systems)
        result = await checker._check_file_permissions("/etc/passwd", "644", "1.1.1")

        assert "id" in result
        assert result["id"] == "1.1.1"
        assert "status" in result
        assert result["status"] in ["PASS", "FAIL", "WARN", "SKIP"]

        # Test non-existent file
        result = await checker._check_file_permissions("/nonexistent/file", "644", "1.1.2")
        assert result["status"] == "SKIP"


# Integration tests (require actual tools)

@pytest.mark.integration
class TestSecurityIntegration:
    """Integration tests for security tools (require actual scanners)."""

    @pytest.mark.asyncio
    async def test_trivy_scan_if_available(self):
        """Test Trivy scan if available."""
        scanner = SecurityScanner()

        if scanner.trivy_available:
            # Test with a small, well-known image
            result = await scanner.scan_image("alpine:latest", "trivy", "CRITICAL")

            assert result["success"] is True
            assert result["scanner"] == "trivy"
            assert "total_vulnerabilities" in result
        else:
            pytest.skip("Trivy not available")

    @pytest.mark.asyncio
    async def test_ufw_status_if_available(self):
        """Test UFW status if available."""
        manager = FirewallManager()

        if manager.ufw_available:
            result = await manager.get_status()

            assert result["success"] is True
            assert result["firewall"] == "ufw"
            assert "active" in result
        else:
            pytest.skip("UFW not available")
