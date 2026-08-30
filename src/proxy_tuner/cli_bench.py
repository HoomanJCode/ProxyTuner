"""Bench command — benchmark proxy performance."""

from __future__ import annotations

import asyncio
import time

import click
from rich.console import Console
from rich.table import Table

console = Console()


@click.command("bench")
@click.option("--target", "-t", default="1.1.1.1:80", help="Target host:port to benchmark")
@click.option("--outbound", "-o", default=None, help="Outbound to test through")
@click.option("--connections", "-n", default=10, type=int, help="Number of connections")
@click.option("--timeout", default=5, type=int, help="Timeout per connection")
@click.pass_context
def bench(
    ctx: click.Context,
    target: str,
    outbound: str | None,
    connections: int,
    timeout: int,
) -> None:
    """Benchmark proxy connection performance."""
    # Parse target
    if ":" in target:
        host, port_str = target.rsplit(":", 1)
        port = int(port_str)
    else:
        host = target
        port = 80

    console.print(f"[bold]Benchmarking {host}:{port}[/bold]")
    console.print(f"  Connections: {connections}")
    if outbound:
        console.print(f"  Outbound: {outbound}")
    console.print()

    asyncio.run(_run_bench(host, port, outbound, connections, timeout))


async def _run_bench(
    host: str,
    port: int,
    outbound: str | None,
    num_connections: int,
    timeout: int,
) -> None:
    """Run the benchmark."""
    from proxy_tuner.config import ConfigManager, get_config_path
    from proxy_tuner.outbounds import OutboundManager

    manager = ConfigManager(get_config_path())
    config = manager.load()
    ob_manager = OutboundManager(config=config)

    results: list[float] = []
    errors = 0

    start_time = time.monotonic()

    for i in range(num_connections):
        conn_start = time.monotonic()
        try:
            if outbound:
                reader, writer = await asyncio.wait_for(
                    ob_manager.connect(outbound, host, port),
                    timeout=timeout,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout,
                )
            writer.close()
            await writer.wait_closed()

            elapsed = (time.monotonic() - conn_start) * 1000
            results.append(elapsed)
        except Exception as e:
            errors += 1
            console.print(f"  [red]Connection {i+1} failed:[/red] {e}")

    total_time = (time.monotonic() - start_time) * 1000

    # Display results
    if results:
        results.sort()
        table = Table(title="Benchmark Results")
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")

        table.add_row("Successful", str(len(results)))
        table.add_row("Failed", str(errors))
        table.add_row("Total time", f"{total_time:.0f}ms")
        table.add_row("Avg latency", f"{sum(results)/len(results):.0f}ms")
        table.add_row("Min latency", f"{results[0]:.0f}ms")
        table.add_row("Max latency", f"{results[-1]:.0f}ms")
        table.add_row("P50 latency", f"{results[len(results)//2]:.0f}ms")
        table.add_row("P95 latency", f"{results[int(len(results)*0.95)]:.0f}ms")
        table.add_row("P99 latency", f"{results[int(len(results)*0.99)]:.0f}ms")
        table.add_row("Throughput", f"{len(results)/(total_time/1000):.1f} conn/s")

        console.print(table)
    else:
        console.print("[red]All connections failed[/red]")
