"""Logs viewing CLI command."""

from __future__ import annotations

import click
from rich.console import Console

console = Console()


@click.command("logs")
@click.option("-n", "--lines", default=50, type=int, help="Number of lines to show")
@click.option("-f", "--follow", is_flag=True, help="Follow log output (tail -f)")
@click.pass_context
def logs(ctx: click.Context, lines: int, follow: bool) -> None:
    """View ProxyTuner logs."""

    from proxy_tuner.config import get_config_dir

    log_file = get_config_dir() / "proxy-tuner.log"

    if follow:
        # Tail -f mode
        if not log_file.exists():
            console.print(f"[yellow]Log file not found: {log_file}[/yellow]")
            return

        console.print(f"[dim]Following {log_file} (Ctrl+C to stop)[/dim]")
        try:
            with open(log_file) as f:
                # Seek to end minus some bytes
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - 4096))
                f.readline()  # Skip partial line

                while True:
                    line = f.readline()
                    if line:
                        console.print(line.rstrip())
                    else:
                        import time
                        time.sleep(0.1)
        except KeyboardInterrupt:
            pass
    else:
        # Show last N lines
        if not log_file.exists():
            console.print(f"[yellow]No log file found at {log_file}[/yellow]")
            msg = "[dim]Logs are written when running with "
            console.print(msg + "--log-file or in daemon mode[/dim]")
            return

        with open(log_file) as f:
            all_lines = f.readlines()
            recent = all_lines[-lines:]
            for line in recent:
                console.print(line.rstrip())
