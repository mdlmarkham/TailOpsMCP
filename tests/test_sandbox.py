"""Tests for sandbox utility (sandbox.py)."""

import pytest
import os
import tempfile
from pathlib import Path
from src.utils.sandbox import (
    is_path_allowed,
    safe_list_directory,
    safe_read_file,
    is_running_as_root,
    _env_allowed_paths
)


@pytest.fixture
def temp_test_dir():
    """Create temporary directory for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


class TestEnvAllowedPaths:
    """Test _env_allowed_paths configuration."""

    def test_env_allowed_paths_default(self, monkeypatch):
        """Test default allowed paths when env var not set."""
        monkeypatch.delenv("SYSTEMMANAGER_ALLOWED_PATHS", raising=False)

        paths = _env_allowed_paths()

        # Should include cwd, home, and /tmp
        assert os.getcwd() in paths
        assert os.path.expanduser("~") in paths
        assert "/tmp" in paths

    def test_env_allowed_paths_custom(self, monkeypatch):
        """Test custom allowed paths from environment."""
        monkeypatch.setenv("SYSTEMMANAGER_ALLOWED_PATHS", "/custom/path1,/custom/path2")

        paths = _env_allowed_paths()

        assert "/custom/path1" in paths
        assert "/custom/path2" in paths
        assert len(paths) == 2

    def test_env_allowed_paths_with_whitespace(self, monkeypatch):
        """Test allowed paths with whitespace are trimmed."""
        monkeypatch.setenv("SYSTEMMANAGER_ALLOWED_PATHS", " /path1 , /path2 ")

        paths = _env_allowed_paths()

        assert "/path1" in paths
        assert "/path2" in paths


class TestIsPathAllowed:
    """Test is_path_allowed checks."""

    def test_is_path_allowed_in_cwd(self, temp_test_dir, monkeypatch):
        """Test path within current directory is allowed."""
        monkeypatch.setenv("SYSTEMMANAGER_ALLOWED_PATHS", temp_test_dir)

        test_file = os.path.join(temp_test_dir, "test.txt")
        Path(test_file).touch()

        assert is_path_allowed(test_file) is True

    def test_is_path_allowed_outside_allowed_paths(self, temp_test_dir, monkeypatch):
        """Test path outside allowed paths is denied."""
        monkeypatch.setenv("SYSTEMMANAGER_ALLOWED_PATHS", temp_test_dir)

        # Try to access /etc/passwd (outside allowed paths)
        assert is_path_allowed("/etc/passwd") is False

    def test_is_path_allowed_empty_path(self):
        """Test empty path is not allowed."""
        assert is_path_allowed("") is False

    def test_is_path_allowed_with_symlink(self, temp_test_dir, monkeypatch):
        """Test symlinks are resolved to real path."""
        monkeypatch.setenv("SYSTEMMANAGER_ALLOWED_PATHS", temp_test_dir)

        # Create a file and symlink
        real_file = os.path.join(temp_test_dir, "real.txt")
        Path(real_file).touch()
        link_file = os.path.join(temp_test_dir, "link.txt")
        os.symlink(real_file, link_file)

        # Symlink within allowed dir should be allowed
        assert is_path_allowed(link_file) is True

    def test_is_path_allowed_custom_paths(self, temp_test_dir):
        """Test is_path_allowed with custom allowed_paths parameter."""
        test_file = os.path.join(temp_test_dir, "test.txt")
        Path(test_file).touch()

        # Explicitly pass allowed paths
        assert is_path_allowed(test_file, allowed_paths=[temp_test_dir]) is True
        assert is_path_allowed(test_file, allowed_paths=["/other/path"]) is False

    def test_is_path_allowed_subdirectory(self, temp_test_dir, monkeypatch):
        """Test subdirectories within allowed paths are allowed."""
        monkeypatch.setenv("SYSTEMMANAGER_ALLOWED_PATHS", temp_test_dir)

        subdir = os.path.join(temp_test_dir, "subdir")
        os.makedirs(subdir)
        test_file = os.path.join(subdir, "test.txt")
        Path(test_file).touch()

        assert is_path_allowed(test_file) is True


class TestSafeListDirectory:
    """Test safe_list_directory function."""

    def test_safe_list_directory_success(self, temp_test_dir, monkeypatch):
        """Test successfully listing allowed directory."""
        monkeypatch.setenv("SYSTEMMANAGER_ALLOWED_PATHS", temp_test_dir)

        # Create some files
        Path(os.path.join(temp_test_dir, "file1.txt")).touch()
        Path(os.path.join(temp_test_dir, "file2.txt")).touch()

        files = safe_list_directory(temp_test_dir)

        assert "file1.txt" in files
        assert "file2.txt" in files

    def test_safe_list_directory_not_allowed(self, monkeypatch):
        """Test listing directory outside allowed paths raises error."""
        monkeypatch.setenv("SYSTEMMANAGER_ALLOWED_PATHS", "/tmp")

        with pytest.raises(PermissionError, match="Access to path not allowed"):
            safe_list_directory("/etc")

    def test_safe_list_directory_empty(self, temp_test_dir, monkeypatch):
        """Test listing empty directory."""
        monkeypatch.setenv("SYSTEMMANAGER_ALLOWED_PATHS", temp_test_dir)

        files = safe_list_directory(temp_test_dir)

        assert files == []


class TestSafeReadFile:
    """Test safe_read_file function."""

    def test_safe_read_file_success(self, temp_test_dir, monkeypatch):
        """Test successfully reading allowed file."""
        monkeypatch.setenv("SYSTEMMANAGER_ALLOWED_PATHS", temp_test_dir)

        test_file = os.path.join(temp_test_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("Hello, World!")

        content = safe_read_file(test_file)

        assert content == "Hello, World!"

    def test_safe_read_file_not_allowed(self, temp_test_dir, monkeypatch):
        """Test reading file outside allowed paths raises error."""
        monkeypatch.setenv("SYSTEMMANAGER_ALLOWED_PATHS", temp_test_dir)

        with pytest.raises(PermissionError, match="Access to path not allowed"):
            safe_read_file("/etc/passwd")

    def test_safe_read_file_max_bytes(self, temp_test_dir, monkeypatch):
        """Test reading file with max_bytes limit."""
        monkeypatch.setenv("SYSTEMMANAGER_ALLOWED_PATHS", temp_test_dir)

        test_file = os.path.join(temp_test_dir, "large.txt")
        with open(test_file, "w") as f:
            f.write("x" * 1000)

        content = safe_read_file(test_file, max_bytes=100)

        assert len(content) <= 100

    def test_safe_read_file_max_lines(self, temp_test_dir, monkeypatch):
        """Test reading file with max_lines limit."""
        monkeypatch.setenv("SYSTEMMANAGER_ALLOWED_PATHS", temp_test_dir)

        test_file = os.path.join(temp_test_dir, "multiline.txt")
        with open(test_file, "w") as f:
            for i in range(100):
                f.write(f"Line {i}\n")

        content = safe_read_file(test_file, max_lines=10)
        lines = content.strip().split("\n")

        assert len(lines) <= 10

    def test_safe_read_file_directory_error(self, temp_test_dir, monkeypatch):
        """Test reading directory raises IsADirectoryError."""
        monkeypatch.setenv("SYSTEMMANAGER_ALLOWED_PATHS", temp_test_dir)

        with pytest.raises(IsADirectoryError):
            safe_read_file(temp_test_dir)

    def test_safe_read_file_encoding_errors(self, temp_test_dir, monkeypatch):
        """Test reading file with encoding errors uses replacement."""
        monkeypatch.setenv("SYSTEMMANAGER_ALLOWED_PATHS", temp_test_dir)

        test_file = os.path.join(temp_test_dir, "binary.txt")
        with open(test_file, "wb") as f:
            f.write(b"Valid \xff Invalid UTF-8")

        # Should not raise, uses error='replace'
        content = safe_read_file(test_file)
        assert "Valid" in content


class TestIsRunningAsRoot:
    """Test is_running_as_root function."""

    def test_is_running_as_root_unix(self):
        """Test root detection on Unix systems."""
        # This test will return True only if actually running as root
        result = is_running_as_root()

        # Result should be boolean
        assert isinstance(result, bool)

        # If running in CI/Docker as root, should detect it
        if os.getenv("USER") == "root" or os.getenv("HOME") == "/root":
            assert result is True

    def test_is_running_as_root_non_root(self):
        """Test non-root detection."""
        # Mock geteuid to return non-zero
        import src.utils.sandbox as sandbox_module

        original_geteuid = os.geteuid if hasattr(os, 'geteuid') else None

        try:
            if hasattr(os, 'geteuid'):
                os.geteuid = lambda: 1000  # Non-root UID
                result = sandbox_module.is_running_as_root()
                assert result is False
        finally:
            if original_geteuid:
                os.geteuid = original_geteuid


class TestPathTraversalPrevention:
    """Test prevention of path traversal attacks."""

    def test_prevent_path_traversal_with_dotdot(self, temp_test_dir, monkeypatch):
        """Test path traversal with .. is prevented."""
        monkeypatch.setenv("SYSTEMMANAGER_ALLOWED_PATHS", temp_test_dir)

        # Try to traverse outside allowed path
        traversal_path = os.path.join(temp_test_dir, "..", "etc", "passwd")

        # Should be denied because realpath resolves to /etc/passwd
        assert is_path_allowed(traversal_path) is False

    def test_prevent_symlink_escape(self, temp_test_dir, monkeypatch):
        """Test symlink escape is prevented."""
        monkeypatch.setenv("SYSTEMMANAGER_ALLOWED_PATHS", temp_test_dir)

        # Create symlink pointing outside allowed paths
        link = os.path.join(temp_test_dir, "escape_link")
        try:
            os.symlink("/etc/passwd", link)

            # Should be denied because realpath resolves outside allowed paths
            assert is_path_allowed(link) is False
        except OSError:
            # Symlink creation might fail in some environments
            pytest.skip("Cannot create symlink in this environment")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
