"""Unit tests for CLI commands."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from proxy_tuner.cli import main
from proxy_tuner.config import ConfigManager


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    return tmp_path / "test-config.json"


def _run(runner: CliRunner, config_file: Path, *args: str):
    """Helper to run CLI with a test config."""
    return runner.invoke(main, ["--config", str(config_file)] + list(args))


class TestMainCLI:
    def test_help(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "ProxyTuner" in result.output

    def test_version(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_version_command(self, runner: CliRunner) -> None:
        result = runner.invoke(main, ["version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output


class TestOutboundCommands:
    def test_add_socks5(self, runner: CliRunner, config_file: Path) -> None:
        result = _run(
            runner, config_file,
            "outbound", "add", "my-vpn",
            "--type", "socks5", "--host", "127.0.0.1", "--port", "1080",
        )
        assert result.exit_code == 0
        assert "Added outbound" in result.output

    def test_add_http(self, runner: CliRunner, config_file: Path) -> None:
        result = _run(
            runner, config_file,
            "outbound", "add", "my-http",
            "--type", "http", "--host", "10.0.0.1", "--port", "8080",
        )
        assert result.exit_code == 0
        assert "Added outbound" in result.output

    def test_add_with_auth(self, runner: CliRunner, config_file: Path) -> None:
        result = _run(
            runner, config_file,
            "outbound", "add", "auth-proxy",
            "--type", "socks5", "--host", "proxy.example.com", "--port", "1080",
            "--username", "user", "--password", "pass",
        )
        assert result.exit_code == 0

    def test_add_duplicate_fails(self, runner: CliRunner, config_file: Path) -> None:
        _run(
            runner, config_file,
            "outbound", "add", "my-vpn",
            "--type", "socks5", "--host", "127.0.0.1", "--port", "1080",
        )
        result = _run(
            runner, config_file,
            "outbound", "add", "my-vpn",
            "--type", "socks5", "--host", "127.0.0.1", "--port", "1080",
        )
        assert result.exit_code != 0
        assert "already exists" in result.output

    def test_list_empty(self, runner: CliRunner, config_file: Path) -> None:
        result = _run(runner, config_file, "outbound", "list")
        assert result.exit_code == 0
        assert "No outbounds" in result.output

    def test_list_with_outbounds(self, runner: CliRunner, config_file: Path) -> None:
        _run(
            runner, config_file,
            "outbound", "add", "vpn",
            "--type", "socks5", "--host", "127.0.0.1", "--port", "1080",
        )
        result = _run(runner, config_file, "outbound", "list")
        assert result.exit_code == 0
        assert "vpn" in result.output
        assert "socks5" in result.output

    def test_remove(self, runner: CliRunner, config_file: Path) -> None:
        _run(
            runner, config_file,
            "outbound", "add", "vpn",
            "--type", "socks5", "--host", "127.0.0.1", "--port", "1080",
        )
        result = _run(runner, config_file, "outbound", "remove", "vpn")
        assert result.exit_code == 0
        assert "Removed outbound" in result.output

    def test_remove_nonexistent_fails(self, runner: CliRunner, config_file: Path) -> None:
        result = _run(runner, config_file, "outbound", "remove", "nonexistent")
        assert result.exit_code != 0
        assert "does not exist" in result.output


class TestRuleCommands:
    def test_add_process_rule(self, runner: CliRunner, config_file: Path) -> None:
        result = _run(
            runner, config_file,
            "rule", "add", "firefox-vpn",
            "--process", "firefox",
            "--outbound", "direct",
        )
        assert result.exit_code == 0
        assert "Added rule" in result.output

    def test_add_multi_process_rule(self, runner: CliRunner, config_file: Path) -> None:
        result = _run(
            runner, config_file,
            "rule", "add", "browsers",
            "--process", "firefox,chrome,chromium",
            "--outbound", "direct",
        )
        assert result.exit_code == 0

    def test_add_domain_rule(self, runner: CliRunner, config_file: Path) -> None:
        result = _run(
            runner, config_file,
            "rule", "add", "china-domains",
            "--domain", "*.cn,*.com.cn",
            "--outbound", "direct",
        )
        assert result.exit_code == 0

    def test_add_cidr_rule(self, runner: CliRunner, config_file: Path) -> None:
        result = _run(
            runner, config_file,
            "rule", "add", "local-net",
            "--ip-cidr", "192.168.0.0/16,10.0.0.0/8",
            "--outbound", "direct",
        )
        assert result.exit_code == 0

    def test_add_port_rule(self, runner: CliRunner, config_file: Path) -> None:
        result = _run(
            runner, config_file,
            "rule", "add", "https-only",
            "--port", "443",
            "--outbound", "direct",
        )
        assert result.exit_code == 0

    def test_add_with_priority(self, runner: CliRunner, config_file: Path) -> None:
        result = _run(
            runner, config_file,
            "rule", "add", "high-pri",
            "--process", "curl",
            "--outbound", "direct",
            "--priority", "5",
        )
        assert result.exit_code == 0

    def test_list_empty(self, runner: CliRunner, config_file: Path) -> None:
        result = _run(runner, config_file, "rule", "list")
        assert result.exit_code == 0
        assert "No rules" in result.output

    def test_list_with_rules(self, runner: CliRunner, config_file: Path) -> None:
        _run(
            runner, config_file,
            "rule", "add", "test-rule",
            "--process", "firefox",
            "--outbound", "direct",
        )
        result = _run(runner, config_file, "rule", "list")
        assert result.exit_code == 0
        assert "test-rule" in result.output
        assert "firefox" in result.output

    def test_remove(self, runner: CliRunner, config_file: Path) -> None:
        _run(
            runner, config_file,
            "rule", "add", "test-rule",
            "--process", "firefox",
            "--outbound", "direct",
        )
        result = _run(runner, config_file, "rule", "remove", "test-rule")
        assert result.exit_code == 0
        assert "Removed rule" in result.output

    def test_disable_enable(self, runner: CliRunner, config_file: Path) -> None:
        _run(
            runner, config_file,
            "rule", "add", "test-rule",
            "--process", "firefox",
            "--outbound", "direct",
        )

        result = _run(runner, config_file, "rule", "disable", "test-rule")
        assert result.exit_code == 0
        assert "Disabled" in result.output

        result = _run(runner, config_file, "rule", "list")
        assert "no" in result.output

        result = _run(runner, config_file, "rule", "enable", "test-rule")
        assert result.exit_code == 0
        assert "Enabled" in result.output

    def test_move_priority(self, runner: CliRunner, config_file: Path) -> None:
        _run(
            runner, config_file,
            "rule", "add", "test-rule",
            "--process", "firefox",
            "--outbound", "direct",
            "--priority", "50",
        )
        result = _run(runner, config_file, "rule", "move", "test-rule", "--priority", "5")
        assert result.exit_code == 0
        assert "priority" in result.output


class TestConfigCommands:
    def test_show(self, runner: CliRunner, config_file: Path) -> None:
        result = _run(runner, config_file, "config", "show")
        assert result.exit_code == 0
        assert "version" in result.output

    def test_path(self, runner: CliRunner, config_file: Path) -> None:
        result = _run(runner, config_file, "config", "path")
        assert result.exit_code == 0
        # Check filename is present (may be line-wrapped by terminal)
        assert config_file.name in result.output.replace("\n", "")

    def test_validate_empty(self, runner: CliRunner, config_file: Path) -> None:
        result = _run(runner, config_file, "config", "validate")
        assert result.exit_code == 0
        assert "valid" in result.output.lower()

    def test_validate_bad_reference(self, runner: CliRunner, config_file: Path) -> None:
        _run(
            runner, config_file,
            "rule", "add", "bad-rule",
            "--process", "firefox",
            "--outbound", "nonexistent",
        )
        result = _run(runner, config_file, "config", "validate")
        assert result.exit_code != 0
        assert "nonexistent" in result.output

    def test_init_creates_file(self, runner: CliRunner, config_file: Path) -> None:
        result = _run(runner, config_file, "config", "init")
        assert result.exit_code == 0
        assert config_file.exists()


class TestStatusCommand:
    def test_status_stopped(self, runner: CliRunner, config_file: Path) -> None:
        result = _run(runner, config_file, "status")
        assert result.exit_code == 0
        assert "stopped" in result.output
