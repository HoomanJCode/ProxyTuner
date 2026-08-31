# ProxyTuner

> **⚠ Warning: This software is in early development (alpha). Do not use in production or sensitive workspaces.**
> It may contain bugs, insecure defaults, or incomplete security measures.
> Use only for personal testing and experimentation.

**Route different traffic through different proxies — automatically.**

ProxyTuner is a cross-platform CLI tool that splits your network traffic and sends it through the right proxy based on rules you define. Send Firefox through VPN, keep terminal traffic direct, and route streaming through a different proxy — all at the same time.

## The Problem

Most proxy tools send **all** traffic through a single proxy. You either go all-in on a VPN or deal with manual proxy configuration per app. There's no easy way to say *"this app goes here, that app goes there."*

## The Solution

ProxyTuner sits in the middle and **splits traffic per-connection** based on rules you define:

```
Firefox  ──►  *.google.com  ──►  VPN Proxy (SOCKS5)
Chrome   ──►  *.youtube.com ──►  Streaming Proxy (HTTP)
curl     ──►  10.0.0.0/8    ──►  Direct (no proxy)
git      ──►  *             ──►  Work Proxy (SOCKS5)
```

Each connection is evaluated independently. One app can go through a proxy while another goes direct — simultaneously.

## Quick Start

```bash
pip install proxy-tuner
```

**Add your proxies:**
```bash
proxy-tuner outbound add my-vpn    --type socks5 --host 127.0.0.1 --port 1080
proxy-tuner outbound add my-http   --type http   --host 10.0.0.1 --port 8080
proxy-tuner outbound add work-proxy --type socks5 --host proxy.work.com --port 1080 --username user --password pass
```

**Define routing rules (lower priority number = evaluated first):**
```bash
# Firefox and Chrome go through VPN
proxy-tuner rule add browsers-vpn --process "firefox,chrome" --outbound my-vpn --priority 10

# Chinese domains go through HTTP proxy
proxy-tuner rule add china-traffic --domain "*.cn,*.com.cn" --outbound my-http --priority 20

# Local network stays direct
proxy-tuner rule add local-direct --ip-cidr "192.168.0.0/16,10.0.0.0/8" --outbound direct --priority 5

# Everything else goes through work proxy
proxy-tuner rule add default --outbound work-proxy --priority 100
```

**Start splitting traffic:**
```bash
proxy-tuner start
proxy-tuner status
proxy-tuner stop
```

## Routing Options

Rules can match on any combination of these (AND-combined within a rule):

| Match Type | Example | What It Does |
|-----------|---------|-------------|
| `--process` | `firefox,chrome` | Match by process name |
| `--domain` | `*.google.com` | Match by domain pattern |
| `--domain-regex` | `.*\.cdn\..*` | Match by domain regex |
| `--ip-cidr` | `10.0.0.0/8` | Match by IP range |
| `--ip` | `8.8.8.8` | Match by specific IP |
| `--port` | `443,8443` | Match by port |
| `--port-range` | `8000-9000` | Match by port range |

Combine multiple matchers in one rule for precise control:
```bash
# Only Firefox traffic to Google domains on port 443
proxy-tuner rule add firefox-google-ssl \
  --process firefox --domain "*.google.com" --port 443 \
  --outbound my-vpn --priority 10
```

## Outbound Types

| Type | Config | Use Case |
|------|--------|----------|
| **SOCKS5** | `--host`, `--port`, optional `--username/--password` | VPN tunnels, SSH proxies |
| **HTTP** | `--host`, `--port`, optional `--username/--password` | Corporate proxies |
| **Direct** | (none) | Bypass proxy, connect directly |

## How It Works

```
Applications
     │
     ▼
┌─────────────────────┐
│     ProxyTuner      │
│   Rule Engine       │
│                     │
│  process: firefox ──┼──► VPN Proxy (SOCKS5)
│  domain:  *.cn ─────┼──► HTTP Proxy
│  ip: 10.0.0.0/8 ────┼──► Direct
│  default ───────────┼──► Work Proxy
└─────────────────────┘
```

ProxyTuner creates a local transparent proxy that intercepts traffic and evaluates each connection against your rules. On Linux it uses nftables/iptables with TPROXY + TUN interface. On Windows it uses WinDivert packet interception.

## Platform Support

| Platform | Mechanism | Privileges |
|----------|-----------|------------|
| Linux | nftables/iptables TPROXY + TUN | root/sudo |
| Windows | WinDivert | admin |
| macOS | SOCKS5/HTTP CONNECT proxy | none |

## Commands

```bash
# Outbound management
proxy-tuner outbound add <name> --type <socks5|http> --host <host> --port <port>
proxy-tuner outbound list
proxy-tuner outbound remove <name>

# Rule management
proxy-tuner rule add <name> --outbound <outbound> [matchers...]
proxy-tuner rule list
proxy-tuner rule remove <name>
proxy-tuner rule enable/disable <name>
proxy-tuner rule move <name> --priority <number>

# Service control
proxy-tuner start
proxy-tuner stop
proxy-tuner status
proxy-tuner reload

# Configuration
proxy-tuner config show
proxy-tuner config set <key> <value>
proxy-tuner config validate
proxy-tuner config init

# Utilities
proxy-tuner doctor
proxy-tuner stats
proxy-tuner version
```

## Requirements

- Python 3.10+
- Linux: `nftables` or `iptables` (root/sudo required)
- Windows: [WinDivert](https://reqrypt.org/windivert.html) driver (admin required)
- macOS: none (uses standard proxy support)

## Documentation

- [Architecture](docs/architecture.md) — technical design and internals
- [Configuration](docs/configuration.md) — config file reference
- [Usage Guide](docs/usage.md) — CLI commands and examples

## License

MIT
