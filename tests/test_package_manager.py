"""Tests for Package Manager service (package_manager.py)."""

import pytest
from unittest.mock import Mock, patch
import subprocess
from src.services.package_manager import PackageManager


@pytest.fixture
def mock_apt_available():
    """Mock environment where apt is available."""

    def mock_run(cmd, **kwargs):
        if cmd == ["which", "apt-get"]:
            return Mock(returncode=0)
        elif cmd == ["which", "yum"]:
            raise subprocess.CalledProcessError(1, cmd)
        return Mock(returncode=0)

    with patch("subprocess.run", side_effect=mock_run):
        yield


@pytest.fixture
def mock_yum_available():
    """Mock environment where yum is available."""

    def mock_run(cmd, **kwargs):
        if cmd == ["which", "apt-get"]:
            raise subprocess.CalledProcessError(1, cmd)
        elif cmd == ["which", "yum"]:
            return Mock(returncode=0)
        return Mock(returncode=0)

    with patch("subprocess.run", side_effect=mock_run):
        yield


@pytest.fixture
def mock_no_package_manager():
    """Mock environment with no package manager."""

    def mock_run(cmd, **kwargs):
        raise subprocess.CalledProcessError(1, cmd)

    with patch("subprocess.run", side_effect=mock_run):
        yield


class TestPackageManagerDetection:
    """Test package manager detection."""

    def test_detect_apt(self, mock_apt_available):
        """Test detecting apt package manager."""
        pm = PackageManager()
        assert pm.package_manager == "apt"

    def test_detect_yum(self, mock_yum_available):
        """Test detecting yum package manager."""
        pm = PackageManager()
        assert pm.package_manager == "yum"

    def test_detect_none(self, mock_no_package_manager):
        """Test when no package manager is found."""
        pm = PackageManager()
        assert pm.package_manager == "unknown"


class TestAptCheckUpdates:
    """Test checking for apt updates."""

    @pytest.mark.asyncio
    async def test_apt_check_updates_success(self):
        """Test successful apt update check."""
        pm = PackageManager()
        pm.package_manager = "apt"

        apt_list_output = """Listing...
nginx/stable 1.18.0-6 amd64 [upgradable from: 1.18.0-5]
python3/stable 3.9.2-1 amd64 [upgradable from: 3.9.1-1]
"""

        def mock_run(cmd, **kwargs):
            if "apt-get" in cmd and "update" in cmd:
                return Mock(returncode=0, stdout="", stderr="")
            elif "apt" in cmd and "list" in cmd:
                return Mock(returncode=0, stdout=apt_list_output, stderr="")
            return Mock(returncode=0)

        with patch("subprocess.run", side_effect=mock_run):
            result = await pm.check_updates()

        assert result["success"] is True
        assert result["package_manager"] == "apt"
        assert result["updates_available"] == 2
        assert len(result["packages"]) == 2
        assert result["packages"][0]["package"] == "nginx"
        assert result["packages"][1]["package"] == "python3"

    @pytest.mark.asyncio
    async def test_apt_check_updates_no_updates(self):
        """Test apt check when no updates available."""
        pm = PackageManager()
        pm.package_manager = "apt"

        def mock_run(cmd, **kwargs):
            if "list" in cmd:
                return Mock(returncode=0, stdout="Listing...", stderr="")
            return Mock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=mock_run):
            result = await pm.check_updates()

        assert result["success"] is True
        assert result["updates_available"] == 0
        assert result["packages"] == []

    @pytest.mark.asyncio
    async def test_apt_check_updates_update_fails(self):
        """Test apt check when apt-get update fails."""
        pm = PackageManager()
        pm.package_manager = "apt"

        def mock_run(cmd, **kwargs):
            if "apt-get" in cmd and "update" in cmd:
                return Mock(returncode=1, stderr="Update failed")
            return Mock(returncode=0)

        with patch("subprocess.run", side_effect=mock_run):
            result = await pm.check_updates()

        assert result["success"] is False
        assert "Update failed" in result["error"]

    @pytest.mark.asyncio
    async def test_apt_check_updates_timeout(self):
        """Test apt check with timeout."""
        pm = PackageManager()
        pm.package_manager = "apt"

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 60)):
            result = await pm.check_updates()

        assert result["success"] is False
        assert "timed out" in result["error"].lower()


class TestYumCheckUpdates:
    """Test checking for yum updates."""

    @pytest.mark.asyncio
    async def test_yum_check_updates_available(self):
        """Test yum check with updates available."""
        pm = PackageManager()
        pm.package_manager = "yum"

        yum_output = """nginx.x86_64    1.18.0-6    updates
python3.x86_64  3.9.2-1     updates
"""

        with patch(
            "subprocess.run", return_value=Mock(returncode=100, stdout=yum_output)
        ):
            result = await pm.check_updates()

        assert result["success"] is True
        assert result["package_manager"] == "yum"
        assert result["updates_available"] == 2

    @pytest.mark.asyncio
    async def test_yum_check_updates_none_available(self):
        """Test yum check with no updates."""
        pm = PackageManager()
        pm.package_manager = "yum"

        with patch("subprocess.run", return_value=Mock(returncode=0, stdout="")):
            result = await pm.check_updates()

        assert result["success"] is True
        assert result["updates_available"] == 0

    @pytest.mark.asyncio
    async def test_yum_check_updates_timeout(self):
        """Test yum check with timeout."""
        pm = PackageManager()
        pm.package_manager = "yum"

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 60)):
            result = await pm.check_updates()

        assert result["success"] is False


class TestUpdateSystem:
    """Test system update operations."""

    @pytest.mark.asyncio
    async def test_apt_update_system_success(self):
        """Test successful apt system update."""
        pm = PackageManager()
        pm.package_manager = "apt"

        upgrade_output = "Reading package lists...\n2 upgraded, 0 newly installed"

        def mock_run(cmd, **kwargs):
            if "update" in cmd:
                return Mock(returncode=0, stdout="", stderr="")
            elif "upgrade" in cmd:
                return Mock(returncode=0, stdout=upgrade_output, stderr="")
            return Mock(returncode=0)

        with patch("subprocess.run", side_effect=mock_run):
            result = await pm.update_system(auto_approve=True)

        assert result["success"] is True
        assert result["packages_upgraded"] == 2
        # Output contains the upgrade result, but not the command flags

    @pytest.mark.asyncio
    async def test_apt_update_system_without_auto_approve(self):
        """Test apt update without auto_approve."""
        pm = PackageManager()
        pm.package_manager = "apt"

        def mock_run(cmd, **kwargs):
            # Verify -y flag is NOT present
            if "upgrade" in cmd:
                assert "-y" not in cmd
                return Mock(returncode=0, stdout="0 upgraded", stderr="")
            return Mock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=mock_run):
            result = await pm.update_system(auto_approve=False)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_apt_update_system_update_fails(self):
        """Test apt update when apt-get update fails."""
        pm = PackageManager()
        pm.package_manager = "apt"

        def mock_run(cmd, **kwargs):
            if "update" in cmd:
                return Mock(returncode=1, stderr="Failed to fetch")
            return Mock(returncode=0)

        with patch("subprocess.run", side_effect=mock_run):
            result = await pm.update_system()

        assert result["success"] is False
        assert "apt-get update failed" in result["error"]

    @pytest.mark.asyncio
    async def test_apt_update_system_upgrade_fails(self):
        """Test apt update when upgrade fails."""
        pm = PackageManager()
        pm.package_manager = "apt"

        def mock_run(cmd, **kwargs):
            if "update" in cmd:
                return Mock(returncode=0, stdout="", stderr="")
            elif "upgrade" in cmd:
                return Mock(returncode=1, stderr="Upgrade failed")
            return Mock(returncode=0)

        with patch("subprocess.run", side_effect=mock_run):
            result = await pm.update_system()

        assert result["success"] is False
        assert "apt-get upgrade failed" in result["error"]

    @pytest.mark.asyncio
    async def test_apt_update_system_timeout(self):
        """Test apt update with timeout (5 minutes)."""
        pm = PackageManager()
        pm.package_manager = "apt"

        def mock_run(cmd, **kwargs):
            if "upgrade" in cmd:
                raise subprocess.TimeoutExpired("cmd", 300)
            return Mock(returncode=0, stdout="")

        with patch("subprocess.run", side_effect=mock_run):
            result = await pm.update_system()

        assert result["success"] is False
        assert "timed out" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_yum_update_system_success(self):
        """Test successful yum system update."""
        pm = PackageManager()
        pm.package_manager = "yum"

        with patch(
            "subprocess.run",
            return_value=Mock(returncode=0, stdout="Complete!", stderr=""),
        ):
            result = await pm.update_system(auto_approve=True)

        assert result["success"] is True
        assert result["package_manager"] == "yum"

    @pytest.mark.asyncio
    async def test_update_system_no_package_manager(self):
        """Test update with no supported package manager."""
        pm = PackageManager()
        pm.package_manager = "unknown"

        result = await pm.update_system()

        assert result["success"] is False
        assert "No supported package manager" in result["error"]


class TestInstallPackage:
    """Test package installation."""

    @pytest.mark.asyncio
    async def test_apt_install_success(self):
        """Test successful apt package install."""
        pm = PackageManager()
        pm.package_manager = "apt"

        with patch(
            "subprocess.run",
            return_value=Mock(returncode=0, stdout="nginx installed", stderr=""),
        ):
            result = await pm.install_package("nginx", auto_approve=True)

        assert result["success"] is True
        assert result["package"] == "nginx"
        assert result["package_manager"] == "apt"

    @pytest.mark.asyncio
    async def test_apt_install_without_auto_approve(self):
        """Test apt install without auto_approve."""
        pm = PackageManager()
        pm.package_manager = "apt"

        def mock_run(cmd, **kwargs):
            assert "-y" not in cmd
            return Mock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=mock_run):
            result = await pm.install_package("nginx", auto_approve=False)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_apt_install_failure(self):
        """Test apt install failure."""
        pm = PackageManager()
        pm.package_manager = "apt"

        with patch(
            "subprocess.run",
            return_value=Mock(returncode=1, stderr="Package not found"),
        ):
            result = await pm.install_package("nonexistent-package")

        assert result["success"] is False
        assert "Package not found" in result["error"]

    @pytest.mark.asyncio
    async def test_apt_install_timeout(self):
        """Test apt install with timeout (3 minutes)."""
        pm = PackageManager()
        pm.package_manager = "apt"

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 180)):
            result = await pm.install_package("nginx")

        assert result["success"] is False
        assert "timed out" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_yum_install_success(self):
        """Test successful yum package install."""
        pm = PackageManager()
        pm.package_manager = "yum"

        with patch(
            "subprocess.run",
            return_value=Mock(returncode=0, stdout="Complete!", stderr=""),
        ):
            result = await pm.install_package("nginx", auto_approve=True)

        assert result["success"] is True
        assert result["package"] == "nginx"
        assert result["package_manager"] == "yum"

    @pytest.mark.asyncio
    async def test_install_package_no_package_manager(self):
        """Test install with no supported package manager."""
        pm = PackageManager()
        pm.package_manager = "unknown"

        result = await pm.install_package("nginx")

        assert result["success"] is False
        assert "No supported package manager" in result["error"]

    @pytest.mark.asyncio
    async def test_install_command_construction_apt(self):
        """Test correct command construction for apt install."""
        pm = PackageManager()
        pm.package_manager = "apt"

        def verify_cmd(cmd, **kwargs):
            assert cmd == ["sudo", "apt-get", "install", "test-package", "-y"]
            assert kwargs.get("timeout") == 180
            return Mock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=verify_cmd):
            await pm.install_package("test-package", auto_approve=True)

    @pytest.mark.asyncio
    async def test_install_command_construction_yum(self):
        """Test correct command construction for yum install."""
        pm = PackageManager()
        pm.package_manager = "yum"

        def verify_cmd(cmd, **kwargs):
            assert cmd == ["sudo", "yum", "install", "test-package", "-y"]
            return Mock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=verify_cmd):
            await pm.install_package("test-package", auto_approve=True)


class TestOutputTruncation:
    """Test output truncation for large outputs."""

    @pytest.mark.asyncio
    async def test_update_output_truncation(self):
        """Test update output is truncated when > 500 chars."""
        pm = PackageManager()
        pm.package_manager = "apt"

        long_output = "x" * 1000

        def mock_run(cmd, **kwargs):
            if "update" in cmd:
                return Mock(returncode=0, stdout="", stderr="")
            elif "upgrade" in cmd:
                return Mock(returncode=0, stdout=long_output, stderr="")
            return Mock(returncode=0)

        with patch("subprocess.run", side_effect=mock_run):
            result = await pm.update_system()

        assert result["success"] is True
        assert len(result["output"]) <= 500

    @pytest.mark.asyncio
    async def test_install_output_truncation(self):
        """Test install output is truncated when > 300 chars."""
        pm = PackageManager()
        pm.package_manager = "apt"

        long_output = "y" * 1000

        with patch(
            "subprocess.run",
            return_value=Mock(returncode=0, stdout=long_output, stderr=""),
        ):
            result = await pm.install_package("nginx")

        assert result["success"] is True
        assert len(result["output"]) <= 300


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
