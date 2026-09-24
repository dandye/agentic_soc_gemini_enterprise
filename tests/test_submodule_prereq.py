"""Unit tests for Git submodule prerequisites and extra_packages pre-flight validation.

Verifies that missing submodule packages trigger automatic submodule resolution
or emit clear configuration error messages instead of unhandled FileNotFoundError.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from installation_scripts.manage_agent_engine import AgentEngineManager


class TestSubmodulePrerequisites:
    """Tests for extra_packages pre-flight validation and submodule handling."""

    @pytest.fixture
    def manager(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("GCP_PROJECT_ID=test-project\n")
        return AgentEngineManager(env_file=env_file)

    def test_all_packages_exist_returns_true(self, manager, tmp_path):
        pkg1 = tmp_path / "pkg1"
        pkg1.mkdir()
        pkg2 = tmp_path / "pkg2"
        pkg2.mkdir()

        result = manager._validate_and_resolve_extra_packages([str(pkg1), str(pkg2)])
        assert result is True

    def test_external_missing_triggers_auto_init_success(self, manager, tmp_path):
        pkg = tmp_path / "external" / "mcp-security" / "server" / "secops"

        def fake_git_submodule_update(*args, **kwargs):
            pkg.mkdir(parents=True, exist_ok=True)
            return MagicMock(returncode=0)

        with patch(
            "subprocess.run", side_effect=fake_git_submodule_update
        ) as mock_subproc:
            result = manager._validate_and_resolve_extra_packages([str(pkg)])
            assert result is True
            mock_subproc.assert_called_once_with(
                ["git", "submodule", "update", "--init", "--recursive"],
                check=True,
                capture_output=True,
                text=True,
            )

    def test_external_missing_auto_init_failure_returns_false(self, manager, tmp_path):
        pkg = tmp_path / "external" / "mcp-security" / "server" / "secops"

        with patch("subprocess.run", side_effect=Exception("network error")):
            result = manager._validate_and_resolve_extra_packages([str(pkg)])
            assert result is False

    def test_non_external_missing_returns_false_without_git(self, manager, tmp_path):
        pkg = tmp_path / "internal_missing_pkg"

        with patch("subprocess.run") as mock_subproc:
            result = manager._validate_and_resolve_extra_packages([str(pkg)])
            assert result is False
            mock_subproc.assert_not_called()

    def test_justfile_defines_submodule_recipes(self):
        justfile_path = Path("justfile")
        assert justfile_path.exists(), "justfile should exist in project root"
        content = justfile_path.read_text()

        assert "submodules:" in content
        assert "git submodule update --init --recursive" in content
        assert "check-submodules:" in content
        assert "check-prereqs: check-submodules" in content
        assert "setup: check-submodules" in content
