"""
Test suite for PathConfig central path management system.

Tests critical path configuration scenarios including:
- Environment variable overrides
- Docker socket path configuration
- Application scanning hybrid paths
- Security path validation
- Service-specific path overrides
"""

import os
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from src.utils.path_config import PathConfig


class TestPathConfigCore:
    """Test core PathConfig functionality."""

    def test_docker_socket_default(self):
        """Test Docker socket path works with default value."""
        with patch.dict(os.environ, {}, clear=True):
            path = PathConfig.get_docker_socket_path()
            assert path == Path("/var/run/docker.sock")

    def test_docker_socket_env_override(self):
        """Test Docker socket path can be overridden via environment."""
        with patch.dict(
            os.environ, {"SYSTEMMANAGER_DOCKER_SOCKET_PATH": "/custom/docker.sock"}
        ):
            path = PathConfig.get_docker_socket_path()
            assert path == Path("/custom/docker.sock")

    def test_stacks_dir_configurability(self):
        """Test stacks directory configuration."""
        with patch.dict(os.environ, {"SYSTEMMANAGER_STACKS_DIR": "/opt/custom-stacks"}):
            stacks_dir = PathConfig.get_stacks_dir()
            assert stacks_dir == Path("/opt/custom-stacks")

    def test_base_url_configuration(self):
        """Test base URL can be configured for different environments."""
        test_urls = [
            "http://localhost:8080",
            "https://server.example.com:8443",
            "http://custom-host:9000",
        ]
        for url in test_urls:
            with patch.dict(os.environ, {"SYSTEMMANAGER_BASE_URL": url}):
                base_url = PathConfig.get_base_url()
                assert base_url == url

    def test_install_data_directories(self):
        """Test install and data directory configuration."""
        with patch.dict(
            os.environ,
            {
                "SYSTEMMANAGER_INSTALL_DIR": "/opt/custom-install",
                "SYSTEMMANAGER_DATA_DIR": "/opt/custom-data",
            },
        ):
            install_dir = PathConfig.get_install_dir()
            data_dir = PathConfig.get_data_dir()
            assert install_dir == Path("/opt/custom-install")
            assert data_dir == Path("/opt/custom-data")


class TestHybridApplicationPaths:
    """Test hybrid application path configuration."""

    def test_service_specific_override_priority(self):
        """Test service-specific paths override base directories."""
        with patch.dict(
            os.environ,
            {
                "SYSTEMMANAGER_JELLYFIN_CONFIG_DIR": "/custom/config/jellyfin",
                "SYSTEMMANAGER_JELLYFIN_DATA_DIR": "/custom/data/jellyfin",
            },
        ):
            config_paths, data_paths = PathConfig.get_service_paths("jellyfin")

            # Should use service-specific overrides
            assert len(config_paths) == 1
            assert len(data_paths) == 1
            assert str(config_paths[0]) == "/custom/config/jellyfin"
            assert str(data_paths[0]) == "/custom/data/jellyfin"

    def test_fallback_to_base_directories(self):
        """Test fallback to base directories when service-specific not set."""
        with patch.dict(
            os.environ,
            {
                "SYSTEMMANAGER_APP_SCAN_CONFIG_DIRS": "/etc,/usr/local/etc",
                "SYSTEMMANAGER_APP_SCAN_DATA_DIRS": "/var/lib,/custom/data",
            },
            clear=True,
        ):
            config_paths, data_paths = PathConfig.get_service_paths("unknown_service")

            # Should use base directories
            assert len(config_paths) == 2  # /etc,/usr/local/etc
            assert len(data_paths) == 2  # /var/lib,/custom/data
            assert str(Path("/etc")) in [str(p) for p in config_paths]
            assert str(Path("/var/lib")) in [str(p) for p in data_paths]

    def test_mixed_path_configuration(self):
        """Test mixed configuration with some overrides, some base directories."""
        with patch.dict(
            os.environ,
            {
                "SYSTEMMANAGER_OLLAMA_CONFIG_DIR": "/custom/ollama/config",  # Override
                "SYSTEMMANAGER_APP_SCAN_CONFIG_DIRS": "/etc,/opt/config",  # Base (for other services)
                "SYSTEMMANAGER_APP_SCAN_DATA_DIRS": "/var/lib,/opt/data",  # Base (no override)
            },
        ):
            # Service with override
            ollama_config, ollama_data = PathConfig.get_service_paths("ollama")
            assert str(ollama_config[0]) == "/custom/ollama/config"
            assert len(ollama_config) == 1  # Only override, no base directories

            # Service without override
            jellyfin_config, jellyfin_data = PathConfig.get_service_paths("jellyfin")
            assert len(jellyfin_config) == 2  # Base directories
            assert str(Path("/etc")) in [str(p) for p in jellyfin_config]


class TestSecurityPathValidation:
    """Test security validation for configured paths."""

    def test_safe_paths_allowed(self):
        """Test safe paths pass validation."""
        safe_paths = [
            "/tmp/testfile",
            "/var/log/application.log",
            "/opt/systemmanager/config",
        ]

        for path_str in safe_paths:
            with patch.object(PathConfig, "get_allowed_base_dirs") as mock_allowed:
                mock_allowed.return_value = [
                    Path("/tmp"),
                    Path("/var/log"),
                    Path("/opt"),
                ]
                assert PathConfig.validate_path_safety(Path(path_str)), (
                    f"Path {path_str} should be safe"
                )

    def test_dangerous_paths_blocked(self):
        """Test dangerous paths are blocked."""
        dangerous_paths = [
            "../../../etc/passwd",  # Path traversal
            "/etc/shadow",  # Sensitive system file
            "/proc/version",  # System introspection
            "/sys/kernel",  # System files
        ]

        for path_str in dangerous_paths:
            assert not PathConfig.validate_path_safety(Path(path_str)), (
                f"Path {path_str} should be blocked"
            )

    def test_path_traversal_prevention(self):
        """Test path traversal attempts are prevented."""
        traversal_attempts = [
            "/opt/systemmanager/../../../etc/passwd",
            "/var/log/../../root/.ssh",
            "/tmp/../../../.../.././proc/version",
        ]

        for path_str in traversal_attempts:
            path = Path(path_str)
            # Should not resolve to dangerous locations
            assert not PathConfig.validate_path_safety(path), (
                f"Traversal attempt {path_str} should be blocked"
            )


class TestCategoryBasedOrganization:
    """Test category-based path organization."""

    def test_media_application_directories(self):
        """Test media application category directories."""
        with patch.dict(
            os.environ, {"SYSTEMMANAGER_MEDIA_CONFIG_DIRS": "/media/config,/opt/media"}
        ):
            media_dirs = PathConfig.get_media_app_dirs()
            assert len(media_dirs) == 2
            assert str(Path("/media/config")) in [str(p) for p in media_dirs]
            assert str(Path("/opt/media")) in [str(p) for p in media_dirs]

    def test_network_application_directories(self):
        """Test network application category directories."""
        with patch.dict(
            os.environ, {"SYSTEMMANAGER_NETWORK_CONFIG_DIRS": "/network,/etc/network"}
        ):
            network_dirs = PathConfig.get_network_app_dirs()
            assert len(network_dirs) == 2
            assert Path("/network") in network_dirs
            assert Path("/etc/network") in network_dirs

    def test_database_application_directories(self):
        """Test database application category directories."""
        with patch.dict(
            os.environ,
            {"SYSTEMMANAGER_DATABASE_DATA_DIRS": "/postgres,/mysql,/custom/db"},
        ):
            db_dirs = PathConfig.get_database_app_dirs()
            assert len(db_dirs) == 3
            assert Path("/postgres") in db_dirs
            assert Path("/mysql") in db_dirs
            assert Path("/custom/db") in db_dirs


class TestComprehensiveConfiguration:
    """Test comprehensive configuration scenarios."""

    def test_proxmox_dump_directory(self):
        """Test Proxmox dump directory configuration."""
        with patch.dict(os.environ, {}, clear=True):
            dump_dir = PathConfig.get_proxmox_dump_dir()
            assert dump_dir == Path("/var/lib/vz/dump")

        with patch.dict(
            os.environ, {"SYSTEMMANAGER_PROXMOX_DUMP_DIR": "/backup/proxmox"}
        ):
            dump_dir = PathConfig.get_proxmox_dump_dir()
            assert dump_dir == Path("/backup/proxmox")

    def test_credential_directory(self):
        """Test credential directory configuration."""
        with patch.dict(os.environ, {}, clear=True):
            cred_dir = PathConfig.get_credential_dir()
            assert cred_dir == Path("/etc/systemmanager/credentials")

        with patch.dict(os.environ, {"SYSTEMMANAGER_CREDENTIAL_DIR": "/secure/creds"}):
            cred_dir = PathConfig.get_credential_dir()
            assert cred_dir == Path("/secure/creds")

    def test_temporary_directories(self):
        """Test temporary directory configuration."""
        with patch.dict(os.environ, {"SYSTEMMANAGER_TEMP_DIRS": "/tmp1,/tmp2,/tmp3"}):
            temp_dirs = PathConfig.get_temp_dirs()
            assert len(temp_dirs) == 3
            assert Path("/tmp1") in temp_dirs
            assert Path("/tmp2") in temp_dirs
            assert Path("/tmp3") in temp_dirs

    def test_all_paths_diagnostics(self):
        """Test comprehensive path diagnostics."""
        with patch.dict(
            os.environ,
            {
                "SYSTEMMANAGER_BASE_URL": "http://test:8080",
                "SYSTEMMANAGER_DOCKER_SOCKET_PATH": "/custom/docker.sock",
            },
        ):
            all_paths = PathConfig.get_all_paths()

            # Should include configured values
            assert all_paths["base_url"] == "http://test:8080"
            assert all_paths["docker_socket_path"] == "/custom/docker.sock"

            # Should include all expected keys
            expected_keys = [
                "docker_socket_path",
                "stacks_dir",
                "base_url",
                "install_dir",
                "data_dir",
                "config_dir",
                "log_dir",
                "credential_dir",
                "proxmox_dump_dir",
                "app_scan_config_dirs",
                "app_scan_data_dirs",
                "temp_dirs",
                "allowed_base_dirs",
            ]

            for key in expected_keys:
                assert key in all_paths, f"Missing key: {key}"


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling."""

    def test_empty_environment_variables(self):
        """Test handling of empty environment variables."""
        with patch.dict(
            os.environ,
            {
                "SYSTEMMANAGER_APP_SCAN_CONFIG_DIRS": "",
                "SYSTEMMANAGER_TEMP_DIRS": "/tmp,/var/tmp",  # Normal value for comparison
            },
        ):
            config_dirs = PathConfig.get_app_scan_config_dirs()
            temp_dirs = PathConfig.get_temp_dirs()

            # Empty should result in no directories
            assert len(config_dirs) == 0
            assert len(temp_dirs) == 2  # Normal value should still work

    def test_malformed_paths(self):
        """Test handling of malformed path inputs."""
        # Paths with spaces and special characters should be handled
        with patch.dict(
            os.environ,
            {
                "SYSTEMMANAGER_INSTALL_DIR": "/opt/system manager",
                "SYSTEMMANAGER_APP_SCAN_CONFIG_DIRS": "/etc,/var/ with spaces ",
            },
        ):
            # Should still create Path objects but validation may fail
            install_dir = PathConfig.get_install_dir()
            assert install_dir == Path("/opt/system manager")

            # Filter out empty entries
            config_dirs = PathConfig.get_app_scan_config_dirs()
            assert len(config_dirs) == 2
            assert Path("/etc") in config_dirs
            # The malformed entry should be filtered out or handled gracefully

    def test_path_validation_edge_cases(self):
        """Test edge cases in path validation."""
        # Test with non-existent paths
        non_existent = Path("/non/existent/path")

        # Path safety should work regardless of existence
        with patch.object(PathConfig, "get_allowed_base_dirs") as mock_allowed:
            mock_allowed.return_value = [Path("/non")]
            assert PathConfig.validate_path_safety(non_existent, "general")


@pytest.mark.integration
class TestPathConfigIntegration:
    """Integration tests for PathConfig with other components."""

    def test_docker_backend_integration(self):
        """Test integration with Docker backend."""
        # This would test that docker_backend.py properly uses PathConfig
        # For now, just verify the paths are configurable
        with patch.dict(
            os.environ, {"SYSTEMMANAGER_DOCKER_SOCKET_PATH": "/test/docker.sock"}
        ):
            from src.services.docker_backend import DockerBackend

            # Test that the backend can be instantiated with custom path
            config = {"socket_path": None}  # Should use default from PathConfig
            backend = DockerBackend(config)

            # Verify it picked up the configured socket path
            assert backend.socket_path == "/test/docker.sock"

    def test_compose_manager_integration(self):
        """Test integration with compose manager."""
        with patch.dict(os.environ, {"SYSTEMMANAGER_STACKS_DIR": "/test/stacks"}):
            from src.services.compose_manager import ComposeStackManager

            # Test that manager can be instantiated with custom path
            manager = ComposeStackManager()

            # Verify it picked up the configured stacks directory
            assert str(manager.stacks_dir) == "/test/stacks"

    @pytest.mark.asyncio
    async def test_secrets_scanner_integration(self):
        """Test integration with secrets scanner."""
        with patch.dict(os.environ, {"SYSTEMMANAGER_INSTALL_DIR": "/test/install"}):
            from src.services.secrets_scanner import SecretsScanner

            scanner = SecretsScanner()

            # Test the scanner method accepts the custom directory
            result = await scanner.scan_env_files("/test/install")

            # Should attempt to scan the configured directory
            assert isinstance(result, dict)
            assert "success" in result
