"""Doctor command — checks prerequisites and diagnoses issues.

Verifies that all required components are available for
ProxyTuner to function correctly.
"""

from __future__ import annotations

import os
import shutil
import sys

import click
from rich.console import Console
from rich.table import Table

console = Console()


class Check:
    """A single diagnostic check."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.passed = False
        self.message = ""
        self.fix = ""

    def ok(self, msg: str = "OK") -> None:
        self.passed = True
        self.message = msg

    def fail(self, msg: str, fix: str = "") -> None:
        self.passed = False
        self.message = msg
        self.fix = fix

    def warn(self, msg: str) -> None:
        self.passed = True
        self.message = f"⚠ {msg}"


def _check_python_version() -> Check:
    c = Check("Python version")
    v = sys.version_info
    if v >= (3, 10):
        c.ok(f"{v.major}.{v.minor}.{v.micro}")
    else:
        c.fail(f"{v.major}.{v.minor}.{v.micro}", "Install Python 3.10+")
    return c


def _check_platform() -> Check:
    c = Check("Platform")
    if sys.platform in ("linux", "android"):
        c.ok(f"{sys.platform}")
    elif sys.platform == "win32":
        c.ok("Windows")
    else:
        c.fail(f"Unsupported: {sys.platform}")
    return c


def _check_root() -> Check:
    c = Check("Root/Admin")
    if sys.platform == "win32":
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin():
                c.ok("Running as Administrator")
            else:
                c.warn("Not running as Administrator (some features limited)")
        except Exception:
            c.warn("Cannot check admin status")
    elif sys.platform in ("linux", "android"):
        if os.geteuid() == 0:
            c.ok("Running as root")
        else:
            c.warn("Not running as root (transparent proxy needs root)")
    else:
        c.ok("Unknown")
    return c


def _check_iptables() -> Check:
    c = Check("iptables")
    if shutil.which("iptables"):
        c.ok(f"Found: {shutil.which('iptables')}")
    elif sys.platform == "win32":
        c.ok("N/A (Windows uses WinDivert)")
    else:
        c.fail("Not found", "Install iptables: apt install iptables")
    return c


def _check_ip_command() -> Check:
    c = Check("ip command")
    if shutil.which("ip"):
        c.ok(f"Found: {shutil.which('ip')}")
    elif sys.platform == "win32":
        c.ok("N/A (Windows)")
    else:
        c.fail("Not found", "Install iproute2: apt install iproute2")
    return c


def _check_click() -> Check:
    c = Check("click library")
    try:
        import click
        c.ok(f"v{click.__version__}")
    except ImportError:
        c.fail("Not installed", "pip install click")
    return c


def _check_rich() -> Check:
    c = Check("rich library")
    try:
        import rich
        v = getattr(rich, "__version__", "unknown")
        c.ok(f"v{v}")
    except ImportError:
        c.fail("Not installed", "pip install rich")
    return c


def _check_config() -> Check:
    c = Check("Config file")
    from proxy_tuner.config import get_config_path

    path = get_config_path()
    if path.exists():
        c.ok(f"{path}")
    else:
        c.warn(f"Not found: {path} (will be created on first run)")
    return c


def _check_windivert() -> Check:
    c = Check("WinDivert")
    if sys.platform != "win32":
        c.ok("N/A (Linux)")
        return c

    try:
        import pydivert  # noqa: F401
        c.ok("pydivert available")
    except ImportError:
        try:
            import ctypes
            ctypes.WinDLL("WinDivert.dll")
            c.ok("WinDivert.dll available")
        except Exception:
            c.fail(
                "Not available",
                "Install from https://reqrypt.org/windivert.html",
            )
    return c


@click.command("doctor")
def doctor() -> None:
    """Check prerequisites and diagnose issues."""
    checks = [
        _check_python_version(),
        _check_platform(),
        _check_root(),
        _check_iptables(),
        _check_ip_command(),
        _check_click(),
        _check_rich(),
        _check_config(),
        _check_windivert(),
    ]

    table = Table(title="ProxyTuner Doctor")
    table.add_column("Check", style="bold")
    table.add_column("Status")
    table.add_column("Details")

    passed = 0
    failed = 0

    for check in checks:
        status = "[green]✓[/green]" if check.passed else "[red]✗[/red]"
        if check.passed and "⚠" in check.message:
            status = "[yellow]⚠[/yellow]"
        detail = check.message
        if check.fix:
            detail += f"\n[dim]Fix: {check.fix}[/dim]"

        table.add_row(check.name, status, detail)

        if check.passed and "⚠" not in check.message:
            passed += 1
        elif not check.passed:
            failed += 1

    console.print(table)
    console.print(f"\n[bold]{passed}[/bold] passed, [bold]{failed}[/bold] failed")

    if failed == 0:
        console.print("[green]All checks passed![/green]")
    else:
        msg = "[yellow]Some checks failed. "
        console.print(msg + "Fix the issues above to use ProxyTuner.[/yellow]")
