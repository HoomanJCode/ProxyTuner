"""Rule management CLI subcommands."""

from __future__ import annotations

from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from proxy_tuner.config import ConfigManager, MatchCondition, Rule

console = Console()


def _parse_list(value: Optional[str]) -> list[str]:
    """Parse a comma-separated string into a list, stripping whitespace."""
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_int_list(value: Optional[str]) -> list[int]:
    """Parse a comma-separated string of ints into a list."""
    if not value:
        return []
    return [int(item.strip()) for item in value.split(",") if item.strip()]


@click.group("rule")
def rule_group() -> None:
    """Manage routing rules."""


@rule_group.command("add")
@click.argument("name")
@click.option("--outbound", required=True, help="Target outbound name")
@click.option("--process", "process_names", default=None, help="Process name(s), comma-separated")
@click.option("--process-path", default=None, help="Process path(s), comma-separated")
@click.option("--domain", default=None, help="Domain pattern(s), comma-separated")
@click.option("--domain-regex", default=None, help="Domain regex pattern(s), comma-separated")
@click.option("--ip", default=None, help="Exact IP(s), comma-separated")
@click.option("--ip-cidr", default=None, help="IP CIDR range(s), comma-separated")
@click.option("--ip-regex", default=None, help="IP regex pattern(s), comma-separated")
@click.option("--port", "port_str", default=None, help="Port(s), comma-separated")
@click.option("--port-range", default=None, help="Port range(s), comma-separated (e.g., 8000-9000)")
@click.option("--url-regex", default=None, help="URL regex pattern(s), comma-separated")
@click.option("--priority", default=50, type=int, show_default=True, help="Rule priority (lower = higher)")
@click.pass_context
def add_rule(
    ctx: click.Context,
    name: str,
    outbound: str,
    process_names: Optional[str],
    process_path: Optional[str],
    domain: Optional[str],
    domain_regex: Optional[str],
    ip: Optional[str],
    ip_cidr: Optional[str],
    ip_regex: Optional[str],
    port_str: Optional[str],
    port_range: Optional[str],
    url_regex: Optional[str],
    priority: int,
) -> None:
    """Add a new routing rule."""
    manager: ConfigManager = ctx.obj["config_manager"]

    match = MatchCondition(
        process=_parse_list(process_names),
        process_path=_parse_list(process_path),
        domain=_parse_list(domain),
        domain_regex=_parse_list(domain_regex),
        ip=_parse_list(ip),
        ip_cidr=_parse_list(ip_cidr),
        ip_regex=_parse_list(ip_regex),
        port=_parse_int_list(port_str),
        port_range=_parse_list(port_range),
        url_regex=_parse_list(url_regex),
    )

    rule = Rule(name=name, outbound=outbound, priority=priority, match=match)

    try:
        manager.add_rule(rule)
        console.print(f"[green]✓[/green] Added rule '[bold]{name}[/bold]' → {outbound}")
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise click.Abort() from e


@rule_group.command("remove")
@click.argument("name")
@click.pass_context
def remove_rule(ctx: click.Context, name: str) -> None:
    """Remove a routing rule."""
    manager: ConfigManager = ctx.obj["config_manager"]

    try:
        manager.remove_rule(name)
        console.print(f"[green]✓[/green] Removed rule '[bold]{name}[/bold]'")
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise click.Abort() from e


@rule_group.command("list")
@click.pass_context
def list_rules(ctx: click.Context) -> None:
    """List all routing rules."""
    manager: ConfigManager = ctx.obj["config_manager"]
    config = manager.get()

    if not config.rules:
        console.print("[dim]No rules configured.[/dim]")
        return

    table = Table(title="Routing Rules")
    table.add_column("Priority", style="dim")
    table.add_column("Name", style="bold")
    table.add_column("Enabled")
    table.add_column("Outbound")
    table.add_column("Match")

    for rule in sorted(config.rules, key=lambda r: r.priority):
        enabled = "[green]yes[/green]" if rule.enabled else "[red]no[/red]"

        # Build match summary
        match_parts: list[str] = []
        m = rule.match
        if m.process:
            match_parts.append(f"process: {', '.join(m.process)}")
        if m.domain:
            match_parts.append(f"domain: {', '.join(m.domain)}")
        if m.domain_regex:
            match_parts.append(f"domain_regex: {', '.join(m.domain_regex)}")
        if m.ip:
            match_parts.append(f"ip: {', '.join(m.ip)}")
        if m.ip_cidr:
            match_parts.append(f"ip_cidr: {', '.join(m.ip_cidr)}")
        if m.ip_regex:
            match_parts.append(f"ip_regex: {', '.join(m.ip_regex)}")
        if m.port:
            match_parts.append(f"port: {', '.join(str(p) for p in m.port)}")
        if m.port_range:
            match_parts.append(f"port_range: {', '.join(m.port_range)}")
        if m.url_regex:
            match_parts.append(f"url_regex: {', '.join(m.url_regex)}")

        match_str = " | ".join(match_parts) if match_parts else "(all traffic)"
        table.add_row(str(rule.priority), rule.name, enabled, rule.outbound, match_str)

    console.print(table)


@rule_group.command("move")
@click.argument("name")
@click.option("--priority", required=True, type=int, help="New priority value")
@click.pass_context
def move_rule(ctx: click.Context, name: str, priority: int) -> None:
    """Change a rule's priority."""
    manager: ConfigManager = ctx.obj["config_manager"]

    try:
        manager.update_rule(name, priority=priority)
        console.print(f"[green]✓[/green] Rule '[bold]{name}[/bold]' priority → {priority}")
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise click.Abort() from e


@rule_group.command("enable")
@click.argument("name")
@click.pass_context
def enable_rule(ctx: click.Context, name: str) -> None:
    """Enable a disabled rule."""
    manager: ConfigManager = ctx.obj["config_manager"]

    try:
        manager.update_rule(name, enabled=True)
        console.print(f"[green]✓[/green] Enabled rule '[bold]{name}[/bold]'")
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise click.Abort() from e


@rule_group.command("disable")
@click.argument("name")
@click.pass_context
def disable_rule(ctx: click.Context, name: str) -> None:
    """Disable a rule without removing it."""
    manager: ConfigManager = ctx.obj["config_manager"]

    try:
        manager.update_rule(name, enabled=False)
        console.print(f"[green]✓[/green] Disabled rule '[bold]{name}[/bold]'")
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise click.Abort() from e


@rule_group.command("test")
@click.argument("name")
@click.option("--process", "process_name", default=None, help="Process name to test")
@click.option("--domain", default=None, help="Domain to test")
@click.option("--ip", default=None, help="IP to test")
@click.option("--port", "port_val", default=None, type=int, help="Port to test")
@click.pass_context
def test_rule(
    ctx: click.Context,
    name: str,
    process_name: Optional[str],
    domain: Optional[str],
    ip: Optional[str],
    port_val: Optional[int],
) -> None:
    """Test if a target matches a rule."""
    # TODO: Phase 2 — implement rule engine matching
    console.print("[yellow]Rule testing not yet implemented (Phase 2)[/yellow]")
    console.print(f"Would test rule '{name}' against:")
    if process_name:
        console.print(f"  process: {process_name}")
    if domain:
        console.print(f"  domain: {domain}")
    if ip:
        console.print(f"  ip: {ip}")
    if port_val:
        console.print(f"  port: {port_val}")
