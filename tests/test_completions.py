"""Unit tests for shell completions."""

from __future__ import annotations

from click.testing import CliRunner

from proxy_tuner.cli import main
from proxy_tuner.completions import (
    get_bash_completion,
    get_fish_completion,
    get_zsh_completion,
)


class TestCompletionScripts:
    def test_bash_completion_contains_complete(self) -> None:
        script = get_bash_completion()
        assert "complete" in script
        assert "proxy-tuner" in script

    def test_zsh_completion_contains_compdef(self) -> None:
        script = get_zsh_completion()
        assert "compdef" in script

    def test_fish_completion_contains_complete(self) -> None:
        script = get_fish_completion()
        assert "complete" in script
        assert "proxy-tuner" in script


class TestCompletionsCLI:
    def test_bash_command(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["completions", "bash"])
        assert result.exit_code == 0
        assert "complete" in result.output

    def test_zsh_command(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["completions", "zsh"])
        assert result.exit_code == 0
        assert "compdef" in result.output

    def test_fish_command(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["completions", "fish"])
        assert result.exit_code == 0
        assert "proxy-tuner" in result.output

    def test_completions_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["completions", "--help"])
        assert result.exit_code == 0
        assert "bash" in result.output
        assert "zsh" in result.output
        assert "fish" in result.output
