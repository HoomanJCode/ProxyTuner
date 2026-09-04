# ProxyTuner — Rule-Based Multi-Proxy Traffic Router

[![CI](https://github.com/HoomanJ/ProxyTuner/actions/workflows/ci.yml/badge.svg)](https://github.com/HoomanJ/ProxyTuner/actions/workflows/ci.yml)

> **Alpha software:** ProxyTuner is under active development. Do not use it for production traffic, sensitive workspaces, or security-critical workloads. Review the configuration and test every proxy before relying on it.

**ProxyTuner is a Python CLI that routes network connections through multiple SOCKS5, HTTP CONNECT, or direct outbounds using flexible rules.** Run one local proxy, then send different destinations through different upstream proxies for practical split tunneling and proxy chaining workflows.

Use it as a **multi-proxy router**, **rule-based proxy manager**, **local SOCKS5 proxy**, or **HTTP CONNECT proxy**. Rules can match domains, IP addresses and CIDR ranges, ports, process names, process paths, and regular expressions.

## Why ProxyTuner?

Most proxy clients apply one proxy to an entire application or system. ProxyTuner lets you define routing policies such as:

- Send browser traffic or selected domains through a SOCKS5 VPN.
- Keep private and local network ranges on a direct connection.
- Route corporate, regional, or development traffic through a dedicated HTTP proxy.
- Combine domain, IP, port, and process conditions with first-match-wins priority.
- Inspect configuration, test upstream connectivity, monitor statistics, and diagnose prerequisites from the terminal.

Example routing policy:

```text
Firefox  ──►  *.example.com  ──►  VPN Proxy (SOCKS5)
Chrome   ──►  *.video.example ──► Streaming Proxy (HTTP)
curl     ──►  10.0.0.0/8      ──► Direct connection
Other    ──►  *               ──► Work Proxy (SOCKS5)
```

## Completing V2Portal — The Client-Side Half of the Stack

[**V2Portal**](https://github.com/HoomanJCode/V2Portal) is a cross-platform V2Ray CLI client that manages proxy subscriptions, profiles, proxy groups, and persistent local proxy servers backed by sing-box and Xray-core. It handles VLESS, VMess, Trojan, Shadowsocks, WireGuard, Hysteria2, TUIC, and more — importing share links, running multiple inbound servers, and applying domain/IP/geo routing rules inside the managed proxy engines.

V2Portal does **not** steer traffic at the operating-system level. It exposes local SOCKS5 or HTTP inbound ports and expects each application to be configured manually. ProxyTuner completes the picture by sitting in front of V2Portal's inbound ports and providing **per-process, per-domain, per-IP, and per-port routing** with transparent system-wide interception on Linux and Windows.

```text
Application traffic
        │
        ▼
   ProxyTuner          ◄── process-aware, domain/IP/port rules
   (127.0.0.1:10808)
        │
        ├──► V2Portal server :1080  (balanced VLESS/VMess group)
        ├──► V2Portal server :1081  (single Trojan node)
        ├──► V2Portal server :1082  (HTTP upstream)
        └──► Direct connection
```

### Why use both together?

| Capability | V2Portal alone | V2Portal + ProxyTuner |
| --- | --- | --- |
| Subscription & profile management | ✔ | ✔ |
| Proxy groups & load balancing | ✔ | ✔ |
| Rule-based split routing (engine-level) | ✔ | ✔ |
| **Per-process traffic steering** | ✘ | ✔ |
| **Transparent system-wide interception** | ✘ | ✔ (Linux TUN / Windows WinDivert) |
| **Cross-engine outbound selection** | ✘ | ✔ (route Chrome to VLESS, curl to HTTP, etc.) |
| **Connection pooling & statistics** | Basic | ✔ (async pool, live monitor, bench) |

### Quick integration example

```bash
# 1. Start V2Portal proxy servers.
v2portal server add --port 1080 SUBSCRIPTION_ID --name 'Balanced VLESS'
v2portal server add --port 1081 PROFILE_ID --name 'US node'
v2portal server start --all

# 2. Register each V2Portal inbound as a ProxyTuner outbound.
proxy-tuner outbound add vless-balanced --type socks5 --host 127.0.0.1 --port 1080
proxy-tuner outbound add us-node --type socks5 --host 127.0.0.1 --port 1081

# 3. Create routing rules.

# CRITICAL: Bypass V2Portal's own traffic to avoid routing loops.
# V2Portal connects to remote V2Ray/Xray servers — this traffic must
# go direct so ProxyTuner doesn't try to route it through V2Portal
# (which would route it through V2Portal again, causing a loop).
proxy-tuner rule add v2portal-bypass \
  --process v2portal \
  --outbound direct \
  --priority 1

# Also bypass V2Portal's inbound ports so local proxy-to-proxy
# traffic is not intercepted.
proxy-tuner rule add v2portal-ports-direct \
  --port 1080,1081,1082 \
  --outbound direct \
  --priority 2

# Keep private networks direct.
proxy-tuner rule add private-direct \
  --ip-cidr "10.0.0.0/8,192.168.0.0/16" \
  --outbound direct \
  --priority 5

# Route browser destinations through a specific V2Portal node.
proxy-tuner rule add chrome-youtube \
  --process chrome --domain "*.youtube.com,*.googlevideo.com" \
  --outbound us-node \
  --priority 10

# Catch-all: send everything else through the balanced group.
proxy-tuner rule add default-proxy \
  --outbound vless-balanced \
  --priority 100

# 4. Start ProxyTuner.
sudo proxy-tuner start   # transparent TUN mode on Linux
# or
proxy-tuner start --foreground  # manual proxy mode on any OS
```

### Installation side-by-side

Both tools live on PyPI and use separate config directories, so they coexist without conflict:

```bash
python -m pip install v2portal proxy-tuner
```

V2Portal stores its config under `~/.config/v2portal/` and ProxyTuner under `~/.config/proxy-tuner/`. Each tool manages its own config, rules, and runtime state independently.

> **In short:** V2Portal manages *what* proxies are available. ProxyTuner decides *which traffic goes where*. Together they deliver a complete, rule-driven proxy infrastructure from subscription import through transparent per-process routing.

## Features

- **Multiple upstream outbounds:** SOCKS5, HTTP CONNECT, and direct connections.
- **Rule-based routing:** Priority-ordered rules with AND logic between match fields and OR logic within list fields.
- **Domain routing:** Wildcard patterns such as `*.example.com` and domain regular expressions.
- **IP routing:** Exact IPs, IPv4/IPv6 CIDR ranges, and IP regular expressions.
- **Port routing:** Exact ports and port ranges.
- **Process-aware rules:** Process names and executable paths are modeled for platform interception support.
- **Local proxy server:** Accepts both SOCKS5 and HTTP CONNECT clients on the same listener, with protocol auto-detection.
- **Authenticated proxies:** Optional username/password authentication for SOCKS5 and HTTP outbounds.
- **Async forwarding:** `asyncio`-based connections, bidirectional relay, retries, pooling, DNS caching, and per-outbound statistics.
- **Operations CLI:** Setup wizard, config validation, hot reload on Unix, shell completions, logs, live monitoring, benchmarking, and `doctor` diagnostics.
- **Cross-platform codebase:** Local proxy mode is Python-based; Linux and Windows transparent interception backends are under active development.

## Quick Start

### 1. Install

Requires **Python 3.10 or newer**.

```bash
python -m pip install proxy-tuner
```

For development from source:

```bash
git clone https://github.com/HoomanJ/ProxyTuner.git
cd ProxyTuner
python -m pip install -e ".[dev]"
```

### 2. Add upstream proxies

```bash
proxy-tuner outbound add vpn \
  --type socks5 \
  --host 127.0.0.1 \
  --port 1080

proxy-tuner outbound add work \
  --type http \
  --host proxy.example.net \
  --port 8080 \
  --username my-user \
  --password my-password
```

Test an outbound before using it:

```bash
proxy-tuner outbound test vpn
proxy-tuner outbound list
```

> Proxy credentials are stored in the local JSON configuration file. Avoid placing real credentials in shell history when possible; use `proxy-tuner config edit` or another secure workflow.

### 3. Create routing rules

Rules with lower priority numbers are evaluated first. The built-in `direct` outbound is always available and does not need to be added.

```bash
# Keep private networks direct.
proxy-tuner rule add private-network \
  --ip-cidr "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8" \
  --outbound direct \
  --priority 5

# Route browser destinations through the SOCKS5 VPN.
proxy-tuner rule add browser-sites \
  --domain "*.example.com,*.example.org" \
  --outbound vpn \
  --priority 10

# Route HTTPS traffic not caught by earlier rules through the work proxy.
proxy-tuner rule add work-https \
  --port 443 \
  --outbound work \
  --priority 20

# Optional catch-all rule.
proxy-tuner rule add default \
  --outbound direct \
  --priority 100
```

### 4. Start the local proxy

```bash
proxy-tuner start --foreground
```

The default listener is `127.0.0.1:10808`. Configure an application or command to use it as a SOCKS5 or HTTP proxy:

```bash
# SOCKS5 with hostname resolution through the proxy.
curl --proxy socks5h://127.0.0.1:10808 https://example.com

# HTTP CONNECT proxy.
curl --proxy http://127.0.0.1:10808 https://example.com
```

In another terminal, inspect the service:

```bash
proxy-tuner status
proxy-tuner stats
proxy-tuner monitor
```

For daemon-style operation on supported Unix environments:

```bash
proxy-tuner start
proxy-tuner status
proxy-tuner reload
proxy-tuner stop
```

## Routing Rules

Every non-empty field in a rule must match. Values inside one field are alternatives.

| CLI option | Example | Matches |
| --- | --- | --- |
| `--process` | `firefox,chrome` | Process name |
| `--process-path` | `/opt/apps/*` | Executable path glob |
| `--domain` | `*.example.com` | Domain wildcard |
| `--domain-regex` | `.*\\.cdn\\..*` | Domain regular expression |
| `--ip` | `8.8.8.8` | Exact IP address |
| `--ip-cidr` | `10.0.0.0/8` | IPv4 or IPv6 network range |
| `--ip-regex` | `^10\\.` | IP regular expression |
| `--port` | `80,443` | Exact destination port |
| `--port-range` | `8000-9000` | Destination port range |
| `--url-regex` | `https?://.*` | URL regular expression |

Combine matchers for precise policies:

```bash
# All conditions are AND-combined.
proxy-tuner rule add firefox-google \
  --process firefox \
  --domain "*.google.com" \
  --port 443 \
  --outbound vpn \
  --priority 10
```

Review and test the rule order:

```bash
proxy-tuner rule list
proxy-tuner rule test firefox-google --process firefox --domain google.com --port 443
proxy-tuner rule move firefox-google --priority 5
proxy-tuner rule disable firefox-google
proxy-tuner rule enable firefox-google
```

### Important scope note

The local SOCKS5/HTTP forwarder receives the destination requested by the client, so domain, IP, and port rules are the most useful in the current local-proxy workflow. Process and process-path matching depend on platform-level interception, which is still being implemented. URL-regex matching is available in the rule engine but is not populated by every proxy protocol path yet.

## Outbound Types

| Type | CLI configuration | Typical use |
| --- | --- | --- |
| **SOCKS5** | `--type socks5 --host HOST --port PORT` | VPN tunnels, SSH dynamic forwarding, privacy proxies |
| **HTTP CONNECT** | `--type http --host HOST --port PORT` | Corporate, caching, or regional HTTP proxies |
| **Direct** | Use the special outbound name `direct` | Bypass an upstream proxy |

## How It Works

```text
Application
    │ SOCKS5 or HTTP CONNECT
    ▼
127.0.0.1:10808
    │
    ▼
ProxyTuner rule engine
    │ first matching rule
    ├──► Direct connection
    ├──► SOCKS5 upstream
    └──► HTTP CONNECT upstream
```

ProxyTuner loads a JSON configuration, compiles routing rules, evaluates each incoming connection, connects through the selected outbound, and relays bytes in both directions. The local forwarder supports concurrent connections with asynchronous I/O and connection statistics.

## Platform Support

| Platform | Local SOCKS5/HTTP proxy | Transparent interception | Notes |
| --- | --- | --- | --- |
| Linux | Supported | Experimental / in progress | TUN and iptables components require root and system networking tools |
| Windows | Supported | Experimental / in progress | WinDivert and Administrator privileges are required for interception |
| macOS | Supported | Not complete | Use the local proxy and configure applications manually |

The reliable cross-platform workflow today is to run the local forwarder and configure each application to use `127.0.0.1:10808`. Transparent system-wide routing is not yet production-ready.

## Configuration

ProxyTuner creates a JSON config file on first use:

- **Linux:** `~/.config/proxy-tuner/config.json`
- **macOS:** `~/Library/Application Support/proxy-tuner/config.json`
- **Windows:** `%APPDATA%\\proxy-tuner\\config.json`

Useful configuration commands:

```bash
proxy-tuner config path
proxy-tuner config show
proxy-tuner config validate
proxy-tuner config set settings.listen_port 10808
proxy-tuner config edit
proxy-tuner config init
```

Use a custom config path for isolated profiles or testing:

```bash
proxy-tuner --config ./proxy-tuner.json config validate
proxy-tuner --config ./proxy-tuner.json status
```

ProxyTuner writes restrictive `0600` permissions for config files on Unix systems because proxy credentials may be stored there.

## CLI Reference

```bash
# Global options
proxy-tuner --help
proxy-tuner --version
proxy-tuner --config PATH <command>

# Upstream proxies
proxy-tuner outbound add NAME --type socks5|http --host HOST --port PORT
proxy-tuner outbound list
proxy-tuner outbound test NAME
proxy-tuner outbound remove NAME

# Rule management
proxy-tuner rule add NAME --outbound OUTBOUND [MATCH_OPTIONS]
proxy-tuner rule list
proxy-tuner rule test NAME [OPTIONS]
proxy-tuner rule move NAME --priority NUMBER
proxy-tuner rule enable NAME
proxy-tuner rule disable NAME
proxy-tuner rule remove NAME

# Service and diagnostics
proxy-tuner start [--foreground] [--log-level LEVEL]
proxy-tuner stop
proxy-tuner status
proxy-tuner reload
proxy-tuner doctor
proxy-tuner stats [--reset]
proxy-tuner monitor
proxy-tuner bench
proxy-tuner logs [--lines NUMBER] [--follow]
proxy-tuner setup

# Shell completion
proxy-tuner completions bash
proxy-tuner completions zsh
proxy-tuner completions fish
```

Run `proxy-tuner COMMAND --help` for the complete options for any command.

## Troubleshooting

### Check prerequisites

```bash
proxy-tuner doctor
```

### Proxy connection fails

```bash
proxy-tuner outbound test vpn
proxy-tuner logs --lines 100
proxy-tuner start --foreground --log-level debug
```

### Rules do not match

```bash
proxy-tuner rule list
proxy-tuner rule test RULE_NAME --domain example.com --port 443
proxy-tuner config validate
```

Confirm that the rule has the intended priority, is enabled, and references an existing outbound. Remember that a local proxy cannot infer the originating application process from every client connection.

### Permission or networking errors on Linux/Windows

Use the local proxy mode first. Transparent interception requires elevated privileges and platform-specific dependencies:

- Linux: `iptables`/`iproute2`, a usable TUN device, and root or `sudo`.
- Windows: WinDivert and an Administrator shell.

## Development

```bash
git clone https://github.com/HoomanJ/ProxyTuner.git
cd ProxyTuner
python -m pip install -e ".[dev]"

# Run the test suite
pytest tests/ -v

# Lint and type-check
ruff check src/ tests/
mypy src/proxy_tuner/ --ignore-missing-imports
```

See the [contribution guide](CONTRIBUTING.md), [usage guide](docs/usage.md), [configuration reference](docs/configuration.md), and [architecture notes](docs/architecture.md) for more detail.

## Search Terms

ProxyTuner is relevant to developers searching for a **Python proxy router**, **multi-proxy manager**, **SOCKS5 routing**, **HTTP CONNECT proxy**, **split tunneling**, **per-domain proxy**, **per-IP proxy**, **CIDR-based routing**, **per-port routing**, **proxy chaining**, **local proxy server**, or **rule-based network traffic routing**.

## License

MIT
