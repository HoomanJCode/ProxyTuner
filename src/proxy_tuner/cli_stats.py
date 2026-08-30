"""Stats CLI command for connection statistics."""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

console = Console()


@click.command("stats")
@click.option("--reset", is_flag=True, help="Reset all statistics")
@click.pass_context
def stats(ctx: click.Context, reset: bool) -> None:
    """Show connection statistics per outbound."""
    import json

    from proxy_tuner.config import get_config_dir

    stats_file = get_config_dir() / "stats.json"

    if reset:
        if stats_file.exists():
            stats_file.unlink()
            console.print("[green]✓[/green] Statistics reset")
        else:
            console.print("[dim]No statistics to reset[/dim]")
        return

    if not stats_file.exists():
        console.print("[dim]No statistics available yet. Start ProxyTuner to collect stats.[/dim]")
        return

    try:
        with open(stats_file) as f:
            data = json.load(f)
    except Exception as e:
        console.print(f"[red]Error reading stats:[/red] {e}")
        return

    if not data:
        console.print("[dim]No statistics recorded.[/dim]")
        return

    table = Table(title="Connection Statistics")
    table.add_column("Outbound", style="bold")
    table.add_column("Connections", justify="right")
    table.add_column("Bytes Sent", justify="right")
    table.add_column("Bytes Recv", justify="right")
    table.add_column("Errors", justify="right")
    table.add_column("Avg Latency", justify="right")

    for name, s in data.items():
        conn = s.get("connections", 0)
        sent = _format_bytes(s.get("bytes_sent", 0))
        recv = _format_bytes(s.get("bytes_received", 0))
        errors = s.get("errors", 0)
        latency = f"{s.get('avg_latency_ms', 0):.0f}ms"
        table.add_row(name, str(conn), sent, recv, str(errors), latency)

    console.print(table)


def _format_bytes(n: int) -> str:
    """Format bytes into human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
