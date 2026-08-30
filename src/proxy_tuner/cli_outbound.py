"""Outbound management CLI subcommands."""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

from proxy_tuner.config import ConfigManager, HttpOutbound, Socks5Outbound

console = Console()


@click.group("outbound")
def outbound_group() -> None:
    """Manage proxy outbounds."""


@outbound_group.command("add")
@click.argument("name")
@click.option("--type", "outbound_type", type=click.Choice(["socks5", "http"]), required=True)
@click.option("--host", required=True, help="Proxy server hostname or IP")
@click.option("--port", required=True, type=int, help="Proxy server port")
@click.option("--username", default=None, help="Proxy auth username")
@click.option("--password", default=None, help="Proxy auth password")
@click.option("--timeout", default=10, type=int, show_default=True,
              help="Connection timeout in seconds")
@click.pass_context
def add_outbound(
    ctx: click.Context,
    name: str,
    outbound_type: str,
    host: str,
    port: int,
    username: str | None,
    password: str | None,
    timeout: int,
) -> None:
    """Add a new proxy outbound."""
    manager: ConfigManager = ctx.obj["config_manager"]

    try:
        if outbound_type == "socks5":
            outbound = Socks5Outbound(
                type="socks5",
                host=host,
                port=port,
                username=username,
                password=password,
                timeout=timeout,
            )
        else:
            outbound = HttpOutbound(
                type="http",
                host=host,
                port=port,
                username=username,
                password=password,
                timeout=timeout,
            )

        manager.add_outbound(name, outbound)
        console.print(f"[green]✓[/green] Added outbound '[bold]{name}[/bold]' ({outbound_type}://{host}:{port})")

    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise click.Abort() from e


@outbound_group.command("remove")
@click.argument("name")
@click.pass_context
def remove_outbound(ctx: click.Context, name: str) -> None:
    """Remove an outbound."""
    manager: ConfigManager = ctx.obj["config_manager"]

    try:
        manager.remove_outbound(name)
        console.print(f"[green]✓[/green] Removed outbound '[bold]{name}[/bold]'")
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise click.Abort() from e


@outbound_group.command("list")
@click.pass_context
def list_outbounds(ctx: click.Context) -> None:
    """List all configured outbounds."""
    manager: ConfigManager = ctx.obj["config_manager"]
    config = manager.get()

    if not config.outbounds:
        console.print("[dim]No outbounds configured.[/dim]")
        return

    table = Table(title="Outbounds")
    table.add_column("Name", style="bold")
    table.add_column("Type")
    table.add_column("Host")
    table.add_column("Port")
    table.add_column("Timeout")

    for name, ob in config.outbounds.items():
        if ob.type == "direct":
            table.add_row(name, "direct", "—", "—", "—")
        else:
            table.add_row(
                name,
                ob.type,
                ob.host,
                str(ob.port),
                f"{ob.timeout}s",
            )

    console.print(table)


@outbound_group.command("test")
@click.argument("name")
@click.pass_context
def test_outbound(ctx: click.Context, name: str) -> None:
    """Test connectivity through an outbound proxy."""
    import asyncio

    from proxy_tuner.outbounds import OutboundManager

    manager: ConfigManager = ctx.obj["config_manager"]
    config = manager.get()

    if name not in config.outbounds:
        console.print(f"[red]Error:[/red] Outbound '{name}' does not exist")
        raise click.Abort()

    ob = config.outbounds[name]
    target = f"{ob.type}://{ob.host}:{ob.port}" if ob.type != "direct" else "direct"
    console.print(f"Testing [bold]{name}[/bold] ({target})...")

    ob_manager = OutboundManager(config=config)
    result = asyncio.run(ob_manager.test_outbound(name))

    if result.success:
        console.print(f"  Connection: [green]OK[/green] ({result.latency_ms:.0f}ms)")
        console.print("  Overall: [green]PASS[/green]")
    else:
        console.print(f"  Connection: [red]FAIL[/red] — {result.error}")
        console.print("  Overall: [red]FAIL[/red]")
