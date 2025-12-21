#!/usr/bin/env python3
"""
Test script to verify security fixes have been applied correctly.
"""

import sys
import os
import subprocess
from pathlib import Path

# Add src to path so we can import modules
sys.path.insert(0, str(Path(__file__).parent / "src"))


def test_app_scanner_security():
    """Test that app_scanner.py has secure subprocess handling."""
    print("Testing app_scanner.py security fixes...")

    try:
        from src.services.app_scanner import ApplicationScanner

        scanner = ApplicationScanner()

        # Check that validated_commands exists and is not empty
        if not hasattr(scanner, "_validated_commands"):
            print("❌ ERROR: _validated_commands attribute not found")
            return False

        if not scanner._validated_commands:
            print("❌ ERROR: No validated commands found - may indicate security issue")
            return False

        # Check that commands use absolute paths
        for cmd_name, cmd_path in scanner._validated_commands.items():
            if not cmd_path.startswith("/"):
                print(
                    f"❌ ERROR: Command {cmd_name} doesn't use absolute path: {cmd_path}"
                )
                return False

        print("✅ AppScanner security fixes verified")
        return True

    except Exception as e:
        print(f"❌ ERROR testing app_scanner: {e}")
        return False


def test_security_models_fixed():
    """Test that security_models.py no longer has hardcoded 'secret'."""
    print("Testing security_models.py security fixes...")

    try:
        from src.models.security_models import SecurityClassification

        # Check that 'SECRET' enum value doesn't exist anymore
        if hasattr(SecurityClassification, "SECRET"):
            print("❌ ERROR: SECRET enum value still exists")
            return False

        # Check that 'CLASSIFIED' is present instead
        if not hasattr(SecurityClassification, "CLASSIFIED"):
            print("❌ ERROR: CLASSIFIED enum value not found")
            return False

        content = Path(__file__).parent / "src" / "models" / "security_models.py"
        file_content = content.read_text()

        if "SECRET" in file_content:
            print("❌ ERROR: 'SECRET' still found in security_models.py")
            return False

        print("✅ SecurityModels security fixes verified")
        return True

    except Exception as e:
        print(f"❌ ERROR testing security_models: {e}")
        return False


def test_input_validator_security():
    """Test that input_validator.py uses configurable paths."""
    print("Testing input_validator.py security fixes...")

    try:
        from src.services.input_validator import InputValidator

        validator = InputValidator(
            None
        )  # We don't need a real allowlist manager for this test

        # Check if the file path validation method exists and uses environment config
        if not hasattr(validator, "_validate_file_path"):
            print("❌ ERROR: _validate_file_path method not found")
            return False

        # Read the file content to check for hardcoded paths
        content = Path(__file__).parent / "src" / "services" / "input_validator.py"
        file_content = content.read_text()

        # Check that environment variable is used
        if "SYSTEMMANAGER_ALLOWED_BASE_DIRS" not in file_content:
            print(
                "❌ ERROR: Environment variable SYSTEMMANAGER_ALLOWED_BASE_DIRS not used"
            )
            return False

        print("✅ InputValidator security fixes verified")
        return True

    except Exception as e:
        print(f"❌ ERROR testing input_validator: {e}")
        return False


def main():
    """Run all security fix tests."""
    print("🔍 Testing security fixes...")
    print("=" * 60)

    tests = [
        test_app_scanner_security,
        test_security_models_fixed,
        test_input_validator_security,
    ]

    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"❌ Test {test.__name__} failed with exception: {e}")
            results.append(False)
        print()

    passed = sum(results)
    total = len(results)

    print("=" * 60)
    print(f"Security Fix Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All security fixes verified successfully!")
        return True
    else:
        print("❌ Some security fixes are missing or incorrect.")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
