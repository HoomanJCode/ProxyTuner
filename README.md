# ProxyTuner

A cross-platform (Windows & Linux) CLI tool for tuning and routing network traffic through multiple proxy outbounds with flexible rule-based routing.

## What It Does

ProxyTuner lets you:

- **Manage proxy outbounds** — add/remove SOCKS5 or HTTP proxies as named outbounds
- **Define routing rules** — direct traffic to specific outbounds based on:
  - Process name (e.g., `firefox`, `chrome`, `curl`)
  - Domain / hostname patterns (regex)
  - IP addresses and CIDR ranges
  - URL patterns (regex)
  - Port ranges
- **Start/stop tuning** — activate or deactivate traffic redirection at any time
- **Per-platform optimization** — uses native OS mechanisms:
  - **Linux**: nftables/iptables TPROXY + TUN interface
  - **Windows**: WinDivert packet interception

## Quick Start

```bash
# Install
pip install proxy-tuner

# Add a SOCKS5 proxy outbound
proxy-tuner outbound add my-vpn --type socks5 --host 127.0.0.1 --port 1080

# Add an HTTP proxy outbound
proxy-tuner outbound add my-http --type http --host 127.0.0.1 --port 8080

# Add a routing rule: send Firefox traffic through my-vpn
proxy-tuner rule add firefox-vpn --process firefox --outbound my-vpn

# Add a rule: send *.cn domains through a specific proxy
proxy-tuner rule add china-traffic --domain "*.cn" --outbound my-http

# Start tuning
proxy-tuner start

# Stop tuning
proxy-tuner stop

# Show status
proxy-tuner status
```

## How It Works

ProxyTuner creates a local transparent proxy that intercepts traffic based on your rules and forwards it through the configured outbound proxies.

```
Application traffic
        │
        ▼
┌──────────────────┐
│   ProxyTuner     │
│  (rule engine)   │
└──────────────────┘
        │
   ┌────┴────┐
   ▼         ▼
Outbound1  Outbound2
(SOCKS5)    (HTTP)
```

On Linux, traffic is redirected to ProxyTuner via nftables/iptables with per-process (`--uid-owner`) matching. On Windows, WinDivert captures packets from specific processes.

## Requirements

- Python 3.10+
- Linux: `nftables` or `iptables` (root/sudo required)
- Windows: [WinDivert](https://reqrypt.org/windivert.html) driver (admin required)

## Documentation

- [Architecture](docs/architecture.md) — technical design and internals
- [Configuration](docs/configuration.md) — config file reference
- [Usage Guide](docs/usage.md) — CLI commands and examples

## License

MIT
