"""Interactive setup wizard for first-time configuration.

Guides users through setting up their first proxy outbound and routing rules.
"""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

from proxy_tuner.config import (
    Config,
    ConfigManager,
    DirectOutbound,
    HttpOutbound,
    MatchCondition,
    Rule,
    Socks5Outbound,
)

console = Console()


@click.command("setup")
@click.pass_context
def setup_wizard(ctx: click.Context) -> None:
    """Interactive setup wizard for first-time configuration."""
    manager: ConfigManager = ctx.obj["config_manager"]

    console.print("[bold cyan]ProxyTuner Setup Wizard[/bold cyan]")
    console.print("This wizard will help you configure your first proxy setup.\n")

    # Check if config already exists
    if manager.path.exists():
        config = manager.get()
        if config.outbounds or config.rules:
            console.print("[yellow]Configuration already exists with outbounds/rules.[/yellow]")
            if not click.confirm("Overwrite with new setup?"):
                return

    config = Config()

    # Step 1: Choose proxy type
    console.print("[bold]Step 1: Choose your proxy type[/bold]")
    proxy_type = click.prompt(
        "What type of proxy are you using?",
        type=click.Choice(["socks5", "http", "direct", "skip"]),
        default="socks5",
    )

    if proxy_type != "skip" and proxy_type != "direct":
        # Step 2: Proxy details
        console.print("\n[bold]Step 2: Proxy server details[/bold]")
        proxy_host = click.prompt("Proxy host", default="127.0.0.1")
        proxy_port = click.prompt("Proxy port", type=int, default=1080 if proxy_type == "socks5" else 8080)

        use_auth = click.confirm("Does the proxy require authentication?", default=False)
        username = None
        password = None
        if use_auth:
            username = click.prompt("Username")
            password = click.prompt("Password", hide_input=True)

        outbound_name = click.prompt("Name for this proxy", default="my-proxy")

        if proxy_type == "socks5":
            config.outbounds[outbound_name] = Socks5Outbound(
                type="socks5", host=proxy_host, port=proxy_port,
                username=username, password=password,
            )
        else:
            config.outbounds[outbound_name] = HttpOutbound(
                type="http", host=proxy_host, port=proxy_port,
                username=username, password=password,
            )

        target_outbound = outbound_name
    else:
        target_outbound = "direct"
        config.outbounds["direct"] = DirectOutbound()

    # Step 3: Routing rules
    console.print("\n[bold]Step 3: Routing rules[/bold]")
    console.print("What should go through the proxy?\n")

    # Local traffic always direct
    config.rules.append(Rule(
        name="local-network",
        priority=1,
        outbound="direct",
        match=MatchCondition(ip_cidr=[
            "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "127.0.0.0/8",
        ]),
    ))

    # Browser routing
    if click.confirm("Route browser traffic through proxy?", default=True):
        browsers = click.prompt(
            "Browser process names (comma-separated)",
            default="firefox,chrome,chromium,brave,msedge",
        )
        config.rules.append(Rule(
            name="browsers",
            priority=10,
            outbound=target_outbound,
            match=MatchCondition(process=[b.strip() for b in browsers.split(",")]),
        ))

    # Domain routing
    if click.confirm("Route specific domains through proxy?", default=False):
        domains = click.prompt("Domain patterns (comma-separated, e.g., *.blocked.com)")
        config.rules.append(Rule(
            name="blocked-domains",
            priority=5,
            outbound=target_outbound,
            match=MatchCondition(domain=[d.strip() for d in domains.split(",")]),
        ))

    # Default rule
    default_out = click.prompt(
        "Default outbound for unmatched traffic",
        type=click.Choice(["direct", target_outbound]),
        default="direct",
    )
    config.rules.append(Rule(
        name="default",
        priority=100,
        outbound=default_out,
        match=MatchCondition(),
    ))

    # Step 4: Settings
    console.print("\n[bold]Step 4: Settings[/bold]")
    listen_port = click.prompt("Local proxy listen port", type=int, default=10808)
    config.settings.listen_port = listen_port

    # Save
    manager.save(config)
    console.print(f"\n[green]✓[/green] Configuration saved to {manager.path}")

    # Summary
    console.print("\n[bold]Setup Summary:[/bold]")
    table = Table()
    table.add_column("Setting", style="bold")
    table.add_column("Value")
    table.add_row("Listen port", str(config.settings.listen_port))
    table.add_row("Outbounds", str(len(config.outbounds)))
    table.add_row("Rules", str(len(config.rules)))
    console.print(table)

    console.print("\n[bold]Next steps:[/bold]")
    console.print(f"  1. Configure your apps to use SOCKS5/HTTP proxy at 127.0.0.1:{config.settings.listen_port}")
    console.print("  2. Start ProxyTuner: [bold]sudo proxy-tuner start[/bold]")
    console.print("  3. Check status: [bold]proxy-tuner status[/bold]")
