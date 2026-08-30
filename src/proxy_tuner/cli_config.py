"""Config management CLI subcommands."""

from __future__ import annotations

import click
from rich.console import Console
from rich.syntax import Syntax

from proxy_tuner.config import ConfigManager

console = Console()


@click.group("config")
def config_group() -> None:
    """Manage configuration."""


@config_group.command("show")
@click.pass_context
def show_config(ctx: click.Context) -> None:
    """Display the current configuration."""
    import json

    manager: ConfigManager = ctx.obj["config_manager"]
    config = manager.get()

    from proxy_tuner.config import _serialize_config

    output = json.dumps(_serialize_config(config), indent=2, ensure_ascii=False)
    console.print(Syntax(output, "json", theme="monokai"))


@config_group.command("path")
@click.pass_context
def config_path(ctx: click.Context) -> None:
    """Show the config file path."""
    manager: ConfigManager = ctx.obj["config_manager"]
    console.print(str(manager.path))


@config_group.command("edit")
@click.pass_context
def edit_config(ctx: click.Context) -> None:
    """Open the config file in the default editor."""
    import os
    import subprocess

    manager: ConfigManager = ctx.obj["config_manager"]

    # Ensure file exists
    if not manager.path.exists():
        manager.save(manager.get())

    editor = os.environ.get("EDITOR", "vi")
    try:
        subprocess.run([editor, str(manager.path)], check=True)
        console.print(f"[green]✓[/green] Config edited at {manager.path}")
    except FileNotFoundError:
        msg = f"[red]Error:[/red] Editor '{editor}' not found."
        console.print(msg + " Set $EDITOR or use 'config show'.")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Error:[/red] Editor exited with code {e.returncode}")


@config_group.command("validate")
@click.pass_context
def validate_config(ctx: click.Context) -> None:
    """Validate the configuration file."""
    manager: ConfigManager = ctx.obj["config_manager"]

    try:
        config = manager.load()
    except Exception as e:
        console.print(f"[red]Parse error:[/red] {e}")
        raise click.Abort() from e

    errors = config.validate_references()
    if errors:
        console.print("[red]Validation errors:[/red]")
        for err in errors:
            console.print(f"  • {err}")
        raise click.Abort()

    console.print("[green]✓[/green] Configuration is valid")


@config_group.command("init")
@click.pass_context
def init_config(ctx: click.Context) -> None:
    """Create a default config file."""
    from proxy_tuner.config import Config

    manager: ConfigManager = ctx.obj["config_manager"]

    if manager.path.exists():
        console.print(f"[yellow]Config already exists at {manager.path}[/yellow]")
        if not click.confirm("Overwrite?"):
            return

    manager.save(Config())
    console.print(f"[green]✓[/green] Created default config at {manager.path}")


@config_group.command("set")
@click.argument("key")
@click.argument("value")
@click.pass_context
def set_config(ctx: click.Context, key: str, value: str) -> None:
    """Set a configuration value.

    Examples:
        proxy-tuner config set settings.listen_port 9090
        proxy-tuner config set settings.log_level debug
        proxy-tuner config set settings.dns_server 1.1.1.1
    """
    manager: ConfigManager = ctx.obj["config_manager"]
    config = manager.get()

    # Parse the key path
    parts = key.split(".")
    if len(parts) < 2:
        msg = "[red]Error:[/red] Key must be in format 'section.field'"
        console.print(f"{msg} (e.g., settings.listen_port)")
        raise click.Abort()

    section = parts[0]
    field_name = parts[1]

    # Type coercion
    if value.lower() == "true":
        coerced: object = True
    elif value.lower() == "false":
        coerced = False
    elif value.lower() == "null" or value.lower() == "none":
        coerced = None
    else:
        try:
            coerced = int(value)
        except ValueError:
            try:
                coerced = float(value)
            except ValueError:
                coerced = value

    if section == "settings" and hasattr(config.settings, field_name):
        setattr(config.settings, field_name, coerced)
        manager.save(config)
        console.print(f"[green]✓[/green] Set {key} = {coerced}")
    else:
        console.print(f"[red]Error:[/red] Unknown setting '{key}'. Valid sections: settings")
        raise click.Abort()
