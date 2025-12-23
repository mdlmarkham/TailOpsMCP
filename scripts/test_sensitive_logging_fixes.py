#!/usr/bin/env python3
"""
Test script for sensitive data logging fixes.

This script tests the fixes implemented for the three clear-text logging vulnerabilities:
1. scripts/scan.py - Exception logging and traceback printing
2. src/auth/mcp_auth_service.py - Response body logging

The script verifies that sensitive information is no longer exposed in logs or error messages.
"""

import importlib.util
import sys
import os
from unittest.mock import patch, MagicMock
import tempfile
import json

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


class TestSensitiveDataLoggingFixes:
    """Test suite for sensitive data logging fixes."""

    def test_scan_py_exception_logging(self):
        """Test that scan.py no longer exposes sensitive exception details."""
        print("Testing scan.py exception logging fix...")

        # Import the scan module
        scan_path = os.path.join(os.path.dirname(__file__), "..", "scan.py")
        spec = importlib.util.spec_from_file_location("scan", scan_path)
        scan = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(scan)

        # Mock the scanner to raise an exception with sensitive data
        with patch("scan.SecurityScanner") as mock_scanner:
            scanner_instance = mock_scanner.return_value
            scanner_instance.scan.side_effect = Exception(
                "Database connection failed: user='admin' password='secret123'"
            )

            # Capture stdout
            with patch("builtins.print") as mock_print:
                security_scanner = scan.SecurityScannerCLI()
                result = security_scanner.run_scan(".", {"vulnerabilities"})

                # Check that the exception message is not printed (should be sanitized)
                for call in mock_print.call_args_list:
                    printed_args = call[0]  # Get positional arguments
                    if isinstance(printed_args, tuple) and len(printed_args) > 0:
                        printed_text = str(printed_args[0])
                        # Should not contain the sensitive details
                        assert "admin" not in printed_text, (
                            f"Sensitive username exposed: {printed_text}"
                        )
                        assert "secret123" not in printed_text, (
                            f"Sensitive password exposed: {printed_text}"
                        )
                        assert "Database connection failed" not in printed_text, (
                            f"Sensitive error details exposed: {printed_text}"
                        )

                print("✓ scan.py exception logging fix verified")

    def test_scan_py_traceback_logging(self):
        """Test that scan.py no longer prints full tracebacks to stdout."""
        print("Testing scan.py traceback logging fix...")

        scan_path = os.path.join(os.path.dirname(__file__), "..", "scan.py")
        spec = importlib.util.spec_from_file_location("scan", scan_path)
        scan = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(scan)

        # Mock the scanner to raise an exception
        with patch("scan.SecurityScanner") as mock_scanner:
            scanner_instance = mock_scanner.return_value
            scanner_instance.scan.side_effect = Exception("Test exception")

            with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp_log:
                # Capture file writes
                original_open = open

                def mock_open(*args, **kwargs):
                    if "/tmp/scan_debug.log" in str(args[0]):
                        return temp_log
                    return original_open(*args, **kwargs)

                with patch("builtins.open", side_effect=mock_open):
                    security_scanner = scan.SecurityScannerCLI()
                    result = security_scanner.run_scan(
                        ".", {"vulnerabilities"}, verbose=True
                    )

                    # Traceback should be written to file, not stdout
                    temp_log.seek(0)
                    log_content = temp_log.read()
                    assert "Traceback" in log_content or "Exception" in log_content, (
                        "Traceback should be written to debug log"
                    )
                    assert "Test exception" in log_content, (
                        "Exception should be written to debug log"
                    )

                    print("✓ scan.py traceback logging fix verified")

    def test_mcp_auth_service_logging(self):
        """Test that mcp_auth_service.py no longer logs sensitive response bodies."""
        print("Testing mcp_auth_service.py logging fix...")

        auth_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "src", "auth", "mcp_auth_service.py"
        )
        spec = importlib.util.spec_from_file_location("mcp_auth_service", auth_path)
        auth = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(auth)

        service = auth.GoFastMCPAuthService()

        # Mock requests to return a response with sensitive token data
        with patch("requests.Session.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 401
            mock_response.text = '{"error": "invalid_token", "details": {"access_token": "secret_token_123", "refresh_token": "refresh_secret"}}'
            mock_response.raise_for_status.side_effect = auth.requests.HTTPError(
                "401 Unauthorized"
            )

            mock_post.return_value = mock_response

            with patch("auth.logging.getLogger") as mock_logger:
                mock_logger_instance = mock_logger.return_value

                try:
                    service._post_json({"test": "payload"})
                except RuntimeError:
                    pass  # Expected to raise

                # Check that logger.error was called
                assert mock_logger_instance.error.called, (
                    "logger.error should be called"
                )

                # Get the logging call arguments
                error_call = mock_logger_instance.error.call_args
                extra_data = error_call[1].get(
                    "extra", {} if len(error_call) < 2 else error_call[1]
                )

                # Verify sensitive data is not logged
                assert "secret_token_123" not in str(extra_data), (
                    f"Sensitive token found in logs: {extra_data}"
                )
                assert "refresh_secret" not in str(extra_data), (
                    f"Sensitive refresh token found in logs: {extra_data}"
                )
                assert "invalid_token" not in str(extra_data), (
                    f"Sensitive error details found in logs: {extra_data}"
                )

                # Verify that useful but safe info is logged
                assert "status" in extra_data, "Status should still be logged"
                assert "error_hint" in extra_data, (
                    "Error hint should be logged (instead of body)"
                )

                print("✓ mcp_auth_service.py logging fix verified")


def main():
    """Run all tests for sensitive data logging fixes."""
    print("Testing sensitive data logging fixes...\n")

    tester = TestSensitiveDataLoggingFixes()

    try:
        tester.test_scan_py_exception_logging()
        tester.test_scan_py_traceback_logging()
        tester.test_mcp_auth_service_logging()

        print("\n✅ All sensitive data logging fixes verified successfully!")
        print("\nSummary of fixes:")
        print("1. scripts/scan.py: Exception messages now sanitized")
        print("2. scripts/scan.py: Full tracebacks written to debug file, not stdout")
        print(
            "3. src/auth/mcp_auth_service.py: Response body replaced with safe error hint"
        )

        return 0

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
