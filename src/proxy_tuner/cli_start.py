"""Start, stop, and status CLI commands."""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import sys
from pathlib import Path

import click
from rich.console import Console

from proxy_tuner import __version__
from proxy_tuner.config import Config, ConfigManager

console = Console()

PID_FILE = "proxytuner.pid"


def _get_pid_file(config_manager: ConfigManager) -> Path:
    """Get the PID file path."""
    return config_manager.path.parent / PID_FILE


def _read_pid(config_manager: ConfigManager) -> int | None:
    """Read the PID from the PID file. Returns None if not running."""
    pid_path = _get_pid_file(config_manager)
    if not pid_path.exists():
        return None
    try:
        pid = int(pid_path.read_text().strip())
        # Check if process is still alive
        os.kill(pid, 0)
        return pid
    except (ValueError, OSError):
        # Process dead or PID file corrupt — clean up
        pid_path.unlink(missing_ok=True)
        return None


def _write_pid(config_manager: ConfigManager, pid: int) -> None:
    """Write PID to the PID file."""
    pid_path = _get_pid_file(config_manager)
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    pid_path.write_text(str(pid))


def _remove_pid(config_manager: ConfigManager) -> None:
    """Remove the PID file."""
    pid_path = _get_pid_file(config_manager)
    pid_path.unlink(missing_ok=True)


@click.command("start")
@click.option("--foreground", "-f", is_flag=True, help="Run in foreground (don't daemonize)")
@click.option("--log-level", default=None, help="Override log level (debug/info/warning/error)")
@click.option(
    "--transparent",
    is_flag=True,
    help="Redirect local Linux TCP traffic into the proxy (requires root)",
)
@click.option(
    "--bypass-uid",
    "bypass_uids",
    type=click.IntRange(min=0),
    multiple=True,
    help="Additional Linux UID to bypass transparent redirection (repeatable)",
)
@click.option(
    "--bypass-port",
    "bypass_ports",
    type=click.IntRange(min=1, max=65535),
    multiple=True,
    help="Additional local TCP port to bypass transparent redirection (repeatable)",
)
@click.pass_context
def start(
    ctx: click.Context,
    foreground: bool,
    log_level: str | None,
    transparent: bool,
    bypass_uids: tuple[int, ...],
    bypass_ports: tuple[int, ...],
) -> None:
    """Start the proxy tuner."""
    manager: ConfigManager = ctx.obj["config_manager"]

    if transparent and sys.platform not in ("linux", "android"):
        raise click.ClickException("--transparent is currently supported only on Linux")
    if transparent and os.geteuid() != 0:
        raise click.ClickException("--transparent requires root; run with sudo")
    if (bypass_uids or bypass_ports) and not transparent:
        raise click.ClickException("--bypass-uid and --bypass-port require --transparent")

    # Check if already running
    existing_pid = _read_pid(manager)
    if existing_pid is not None:
        console.print(f"[yellow]ProxyTuner is already running (PID {existing_pid})[/yellow]")
        raise click.Abort()

    # Load and validate config
    try:
        config = manager.load()
    except Exception as e:
        console.print(f"[red]Config error:[/red] {e}")
        raise click.Abort() from e

    errors = config.validate_references()
    if errors:
        console.print("[red]Config validation errors:[/red]")
        for err in errors:
            console.print(f"  • {err}")
        raise click.Abort()

    # Check privileges on Linux
    if sys.platform == "linux" and os.geteuid() != 0:
        console.print(
            "[yellow]Warning:[/yellow] Not running as root. "
            "Traffic interception requires elevated privileges."
        )

    # Check privileges on Windows
    if sys.platform == "win32":
        try:
            import ctypes

            if not ctypes.windll.shell32.IsUserAnAdmin():
                console.print(
                    "[yellow]Warning:[/yellow] Not running as Administrator. "
                    "Traffic interception requires elevated privileges."
                )
        except Exception:
            pass

    # Apply log level override
    if log_level:
        config.settings.log_level = log_level

    # Setup logging
    from proxy_tuner.logging import setup_logging
    setup_logging(config.settings.log_level, config.settings.log_file)

    if foreground:
        console.print("[green]Starting ProxyTuner in foreground...[/green]")
        _write_pid(manager, os.getpid())
        try:
            asyncio.run(
                _run_loop(
                    manager,
                    config,
                    transparent=transparent,
                    bypass_uids=bypass_uids,
                    bypass_ports=bypass_ports,
                )
            )
        except KeyboardInterrupt:
            console.print("\n[yellow]Shutting down...[/yellow]")
        finally:
            _remove_pid(manager)
            console.print("[dim]Stopped.[/dim]")
    else:
        # Daemon mode: report success only after the listener and firewall
        # backend have completed startup.
        ready_read, ready_write = os.pipe()
        pid = os.fork()
        if pid > 0:
            os.close(ready_write)
            with os.fdopen(ready_read, encoding="utf-8") as ready_pipe:
                result = ready_pipe.readline().strip()
            if result != "READY":
                with contextlib.suppress(ChildProcessError):
                    os.waitpid(pid, 0)
                message = result.removeprefix("ERROR:").strip() or "daemon exited during startup"
                raise click.ClickException(f"ProxyTuner failed to start: {message}")
            console.print(f"[green]✓[/green] ProxyTuner started (PID {pid})")
            return

        # Child process — daemon
        os.close(ready_read)
        os.setsid()
        _write_pid(manager, os.getpid())
        try:
            asyncio.run(
                _run_loop(
                    manager,
                    config,
                    transparent=transparent,
                    bypass_uids=bypass_uids,
                    bypass_ports=bypass_ports,
                    ready_fd=ready_write,
                )
            )
        except Exception as e:
            with contextlib.suppress(OSError):
                os.write(ready_write, f"ERROR:{e}\n".encode())
        finally:
            os.close(ready_write)
            _remove_pid(manager)


async def _run_loop(
    manager: ConfigManager,
    config: Config,
    transparent: bool = False,
    bypass_uids: tuple[int, ...] = (),
    bypass_ports: tuple[int, ...] = (),
    ready_fd: int | None = None,
) -> None:
    """Main async loop — starts forwarder and waits for shutdown."""
    from proxy_tuner.forwarder import Forwarder

    forwarder = Forwarder(config=config, transparent=transparent)
    backend = None
    try:
        await forwarder.start()
        if transparent:
            from proxy_tuner.platform.linux import LinuxBackend

            backend = LinuxBackend()
            await backend.start(
                config.settings.listen_port,
                config.settings.tun_name,
                config.settings.tun_address,
                bypass_uids=bypass_uids,
                bypass_ports=bypass_ports,
            )
        console.print(
            f"  Listening on 127.0.0.1:{config.settings.listen_port}"
        )
        if transparent:
            console.print("  Linux transparent TCP redirect: enabled")
        console.print(f"  Rules: {len(config.rules)} loaded")
        console.print(f"  Outbounds: {len(config.outbounds)} configured")
        console.print("  Press Ctrl+C to stop.")
        if ready_fd is not None:
            os.write(ready_fd, b"READY\n")

        # Keep running until stopped
        stop_event = asyncio.Event()
        reload_event = asyncio.Event()

        def _handle_signal(sig: int, frame: object) -> None:
            stop_event.set()

        def _handle_reload(sig: int, frame: object) -> None:
            reload_event.set()

        signal.signal(signal.SIGTERM, _handle_signal)
        signal.signal(signal.SIGINT, _handle_signal)
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, _handle_reload)

        while not stop_event.is_set():
            # Wait for either stop or reload
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop_event.wait(), timeout=1.0)

            # Handle reload
            if reload_event.is_set():
                reload_event.clear()
                try:
                    new_config = manager.load()
                    forwarder.update_config(new_config)
                    n_rules = len(new_config.rules)
                    n_outs = len(new_config.outbounds)
                    console.print(
                        f"  [green]Reloaded:[/green] {n_rules} rules, {n_outs} outbounds"
                    )
                except Exception as e:
                    console.print(f"  [red]Reload failed:[/red] {e}")

    finally:
        if backend:
            await backend.stop()
        await forwarder.stop()


@click.command("stop")
@click.pass_context
def stop(ctx: click.Context) -> None:
    """Stop the proxy tuner."""
    manager: ConfigManager = ctx.obj["config_manager"]
    pid = _read_pid(manager)

    if pid is None:
        console.print("[yellow]ProxyTuner is not running.[/yellow]")
        return

    try:
        os.kill(pid, signal.SIGTERM)
        console.print(f"[green]✓[/green] Sent stop signal to PID {pid}")
        _remove_pid(manager)
    except OSError as e:
        console.print(f"[red]Error:[/red] {e}")
        _remove_pid(manager)


@click.command("status")
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show the current status."""
    manager: ConfigManager = ctx.obj["config_manager"]
    pid = _read_pid(manager)

    from rich.table import Table

    if pid is None:
        console.print(f"ProxyTuner v{__version__}")
        console.print("Status: [red]stopped[/red]")
        return

    config = manager.get()

    console.print(f"ProxyTuner v{__version__}")
    console.print(f"Status: [green]running[/green] (PID {pid})")
    console.print(f"Config: {manager.path}")
    console.print("")

    # Outbounds table
    if config.outbounds:
        table = Table(title="Outbounds")
        table.add_column("Name", style="bold")
        table.add_column("Type")
        table.add_column("Target")
        for name, ob in config.outbounds.items():
            if ob.type == "direct":
                table.add_row(name, "direct", "—")
            else:
                table.add_row(name, ob.type, f"{ob.host}:{ob.port}")
        console.print(table)

    # Rules table
    if config.rules:
        rules_table = Table(title="Rules")
        rules_table.add_column("Priority", style="dim")
        rules_table.add_column("Name", style="bold")
        rules_table.add_column("Enabled")
        rules_table.add_column("Outbound")
        rules_table.add_column("Match")

        for rule in sorted(config.rules, key=lambda r: r.priority):
            enabled = "[green]yes[/green]" if rule.enabled else "[red]no[/red]"
            m = rule.match
            parts = []
            if m.process:
                parts.append(f"proc:{','.join(m.process[:2])}")
            if m.domain:
                parts.append(f"dom:{','.join(m.domain[:2])}")
            if m.ip_cidr:
                parts.append(f"ip:{','.join(m.ip_cidr[:1])}")
            if m.port:
                parts.append(f"port:{','.join(str(p) for p in m.port[:2])}")
            match_str = " ".join(parts) if parts else "*"
            rules_table.add_row(str(rule.priority), rule.name, enabled, rule.outbound, match_str)

        console.print(rules_table)

    enabled_count = sum(1 for r in config.rules if r.enabled)
    total_count = len(config.rules)
    port = config.settings.listen_port
    console.print(f"Listen port: {port} | Rules: {enabled_count} active / {total_count} total")
