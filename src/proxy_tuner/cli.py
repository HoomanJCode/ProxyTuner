"""Main CLI entry point."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from proxy_tuner import __version__
from proxy_tuner.config import ConfigManager, get_config_path

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="proxy-tuner")
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to config file (default: platform default)",
)
@click.pass_context
def main(ctx: click.Context, config_path: Path | None) -> None:
    """ProxyTuner — cross-platform proxy routing CLI.

    Route network traffic through multiple proxy outbounds with
    flexible rule-based routing.
    """
    ctx.ensure_object(dict)
    ctx.obj["config_manager"] = ConfigManager(config_path)


# Register subcommands
from proxy_tuner.cli_config import config_group  # noqa: E402
from proxy_tuner.cli_outbound import outbound_group  # noqa: E402
from proxy_tuner.cli_rule import rule_group  # noqa: E402
from proxy_tuner.cli_start import start, status, stop  # noqa: E402

main.add_command(outbound_group)
main.add_command(rule_group)
main.add_command(config_group)
main.add_command(start)
main.add_command(stop)
main.add_command(status)


@main.command("version")
def version_cmd() -> None:
    """Show version information."""
    from rich.console import Console

    Console().print(f"proxy-tuner {__version__}")


if __name__ == "__main__":
    main()
