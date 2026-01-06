"""
Tests for CLI commands.
"""

import pytest
from typer.testing import CliRunner
from unittest.mock import patch, MagicMock

from jagabaya.cli.app import app


runner = CliRunner()


class TestGlobalFlags:
    """Tests for global CLI flags."""

    def test_version_flag(self):
        """Test --version flag shows version."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "Jagabaya" in result.stdout

    def test_help_flag(self):
        """Test --help flag shows help."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "AI-Powered Penetration Testing CLI" in result.stdout

    def test_quiet_flag_exists(self):
        """Test --quiet flag is recognized."""
        result = runner.invoke(app, ["--help"])
        assert "--quiet" in result.stdout

    def test_debug_flag_exists(self):
        """Test --debug flag is recognized."""
        result = runner.invoke(app, ["--help"])
        assert "--debug" in result.stdout

    def test_no_color_flag_exists(self):
        """Test --no-color flag is recognized."""
        result = runner.invoke(app, ["--help"])
        assert "--no-color" in result.stdout


class TestConfigCommands:
    """Tests for config subcommands."""

    def test_config_help(self):
        """Test config help shows subcommands."""
        result = runner.invoke(app, ["config", "--help"])
        assert result.exit_code == 0
        assert "show" in result.stdout
        assert "validate" in result.stdout
        assert "test-llm" in result.stdout

    def test_config_show(self):
        """Test config show command."""
        result = runner.invoke(app, ["config", "show"])
        # May fail if no config, but should not crash
        assert result.exit_code in [0, 1]

    def test_config_env(self):
        """Test config env shows environment variables."""
        result = runner.invoke(app, ["config", "env"])
        assert result.exit_code == 0
        assert "OPENAI_API_KEY" in result.stdout
        assert "ANTHROPIC_API_KEY" in result.stdout

    def test_config_validate_help(self):
        """Test config validate help."""
        result = runner.invoke(app, ["config", "validate", "--help"])
        assert result.exit_code == 0
        assert "Validate configuration" in result.stdout

    def test_config_test_llm_help(self):
        """Test config test-llm help."""
        result = runner.invoke(app, ["config", "test-llm", "--help"])
        assert result.exit_code == 0
        assert "Test LLM connection" in result.stdout


class TestScanCommands:
    """Tests for scan subcommands."""

    def test_scan_help(self):
        """Test scan help shows subcommands."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "run" in result.stdout
        assert "resume" in result.stdout
        assert "quick" in result.stdout

    def test_scan_resume_help(self):
        """Test scan resume help."""
        result = runner.invoke(app, ["scan", "resume", "--help"])
        assert result.exit_code == 0
        assert "SESSION_ID" in result.stdout
        assert "--max-steps" in result.stdout


class TestSessionCommands:
    """Tests for session subcommands."""

    def test_session_help(self):
        """Test session help shows subcommands."""
        result = runner.invoke(app, ["session", "--help"])
        assert result.exit_code == 0
        assert "list" in result.stdout
        assert "show" in result.stdout
        assert "delete" in result.stdout

    def test_session_list_help(self):
        """Test session list help shows resumable flag."""
        result = runner.invoke(app, ["session", "list", "--help"])
        assert result.exit_code == 0
        assert "--resumable" in result.stdout


class TestToolsCommands:
    """Tests for tools subcommands."""

    def test_tools_help(self):
        """Test tools help shows subcommands."""
        result = runner.invoke(app, ["tools", "--help"])
        assert result.exit_code == 0
        assert "list" in result.stdout
        assert "check" in result.stdout
        assert "install" in result.stdout
