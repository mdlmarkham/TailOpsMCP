"""
Test configuration and initialization for the enhanced test infrastructure.
"""

# Allow deliberate sys.path manipulation for test imports
# ruff: noqa: E402

# Add the project root to Python path to enable imports
import sys
from pathlib import Path

# Set up path before any other imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import pytest  # Import pytest for fixtures

from tests.fixtures.target_registry_fixtures import TargetRegistryFixtures

# Import all test utilities and fixtures to make them available
from tests.mock_executors import (
    MockDockerExecutor,
    MockHTTPExecutor,
    MockLocalExecutor,
    MockProxmoxExecutor,
    MockSSHExecutor,
)
from tests.mock_policy_gate import PolicyGateConfigs
from tests.test_utils import (
    AuthorizationAssertions,
    ExecutionAssertions,
    PerformanceMetrics,
    TargetAssertions,
    TestDataGenerators,
)

# from tests.integration_test_framework import *  # Commented out due to missing dependencies


# pytest configuration hooks
@pytest.fixture(scope="session")
def test_infrastructure():
    """Session-level fixture providing access to test infrastructure."""
    return {
        "mock_executors": {
            "ssh": MockSSHExecutor,
            "docker": MockDockerExecutor,
            "http": MockHTTPExecutor,
            "local": MockLocalExecutor,
            "proxmox": MockProxmoxExecutor,
        },
        "fixtures": TargetRegistryFixtures,
        "policy_gates": PolicyGateConfigs,
        "assertions": {
            "execution": ExecutionAssertions,
            "target": TargetAssertions,
            "authorization": AuthorizationAssertions,
        },
        "generators": TestDataGenerators,
        "performance": PerformanceMetrics,
    }


@pytest.fixture
def basic_test_target():
    """Fixture providing a basic test target."""
    return TargetRegistryFixtures.create_test_target()


@pytest.fixture
def readonly_test_claims():
    """Fixture providing readonly test claims."""
    return TestDataGenerators.generate_token_claims(
        scopes=["container:read", "system:read"]
    )


@pytest.fixture
def admin_test_claims():
    """Fixture providing admin test claims."""
    return TestDataGenerators.generate_token_claims(scopes=["admin"])


@pytest.fixture
def mock_policy_gate():
    """Fixture providing a mock policy gate."""
    return PolicyGateConfigs.permissive()


@pytest.fixture
def mock_target_registry():
    """Fixture providing a mock target registry."""
    return TargetRegistryFixtures.create_mock_target_registry()


# Test configuration for different environments
class TestConfig:
    """Configuration for different test environments."""

    @staticmethod
    def unit_tests():
        """Configuration for unit tests."""
        return {
            "use_mocks": True,
            "external_dependencies": False,
            "timeout": 30,
            "parallel_execution": False,
        }

    @staticmethod
    def integration_tests():
        """Configuration for integration tests."""
        return {
            "use_mocks": False,
            "external_dependencies": True,
            "timeout": 60,
            "parallel_execution": True,
        }

    @staticmethod
    def performance_tests():
        """Configuration for performance tests."""
        return {
            "use_mocks": True,
            "external_dependencies": False,
            "timeout": 300,
            "parallel_execution": True,
        }


# Test markers for different test types
UNIT_TEST = pytest.mark.unit_test
INTEGRATION_TEST = pytest.mark.integration_test
PERFORMANCE_TEST = pytest.mark.performance_test
SECURITY_TEST = pytest.mark.security_test


# Helper functions for test setup
def setup_test_environment(config_type="unit"):
    """Set up test environment based on configuration type."""
    config_map = {
        "unit": TestConfig.unit_tests,
        "integration": TestConfig.integration_tests,
        "performance": TestConfig.performance_tests,
    }

    if config_type not in config_map:
        raise ValueError(f"Unknown configuration type: {config_type}")

    return config_map[config_type]()


def teardown_test_environment():
    """Clean up test environment."""
    # Clean up any temporary files or resources
    pass


# Test data generators for common scenarios
def generate_security_test_scenarios():
    """Generate security test scenarios."""
    return [
        {
            "name": "privilege_escalation",
            "description": "Test prevention of privilege escalation",
            "setup": "setup_privilege_test",
            "test": "test_privilege_escalation",
        },
        {
            "name": "parameter_injection",
            "description": "Test prevention of parameter injection",
            "setup": "setup_injection_test",
            "test": "test_parameter_injection",
        },
        {
            "name": "path_traversal",
            "description": "Test prevention of path traversal",
            "setup": "setup_traversal_test",
            "test": "test_path_traversal",
        },
    ]


def generate_performance_test_scenarios():
    """Generate performance test scenarios."""
    return [
        {
            "name": "authorization_performance",
            "description": "Test authorization decision performance",
            "operations": 1000,
            "concurrency": 10,
        },
        {
            "name": "execution_performance",
            "description": "Test command execution performance",
            "operations": 500,
            "concurrency": 5,
        },
        {
            "name": "target_retrieval_performance",
            "description": "Test target registry retrieval performance",
            "operations": 2000,
            "concurrency": 1,
        },
    ]
