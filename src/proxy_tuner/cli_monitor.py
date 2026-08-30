"""Monitor command — live view of connections and activity."""

from __future__ import annotations

import time

import click
from rich.console import Console
from rich.live import Live
from rich.table import Table

console = Console()


def _format_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


@click.command("monitor")
@click.option("--interval", "-i", default=2, type=int, help="Refresh interval in seconds")
@click.pass_context
def monitor(ctx: click.Context, interval: int) -> None:
    """Live monitoring dashboard."""
    import json

    from proxy_tuner.config import get_config_dir

    stats_file = get_config_dir() / "stats.json"
    pid_file = get_config_dir() / "proxytuner.pid"

    def _build_table() -> Table:
        table = Table(title="ProxyTuner Monitor", show_header=True)
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")

        # Status
        running = False
        if pid_file.exists():
            try:
                import os
                pid = int(pid_file.read_text().strip())
                os.kill(pid, 0)
                running = True
            except (ValueError, OSError):
                pass

        status = "[green]Running[/green]" if running else "[red]Stopped[/red]"
        table.add_row("Status", status)

        # Load stats
        data = {}
        if stats_file.exists():
            try:
                with open(stats_file) as f:
                    data = json.load(f)
            except Exception:
                pass

        # Aggregate stats
        total_conns = sum(s.get("connections", 0) for s in data.values())
        total_sent = sum(s.get("bytes_sent", 0) for s in data.values())
        total_recv = sum(s.get("bytes_received", 0) for s in data.values())
        total_errors = sum(s.get("errors", 0) for s in data.values())

        table.add_row("Total connections", str(total_conns))
        table.add_row("Bytes sent", _format_bytes(total_sent))
        table.add_row("Bytes received", _format_bytes(total_recv))
        table.add_row("Errors", str(total_errors))
        table.add_row("Last update", time.strftime("%H:%M:%S"))

        return table

    try:
        refresh = 1 // max(interval, 1)
        with Live(_build_table(), refresh_per_second=refresh, console=console) as live:
            while True:
                time.sleep(interval)
                live.update(_build_table())
    except KeyboardInterrupt:
        pass
