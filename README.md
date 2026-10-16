# ProxyTuner — Rule-Based Multi-Proxy Traffic Router

[![CI](https://github.com/HoomanJCode/ProxyTuner/actions/workflows/ci.yml/badge.svg)](https://github.com/HoomanJCode/ProxyTuner/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/proxy-tuner)](https://pypi.org/project/proxy-tuner/)
[![Python](https://img.shields.io/pypi/pyversions/proxy-tuner)](https://pypi.org/project/proxy-tuner/)

> **Alpha software / experimental:** ProxyTuner is under active development and is intended for laboratory use only. Do not use it for production traffic, sensitive workspaces, or security-critical workloads. Review the configuration and test every proxy before relying on it.

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

V2Portal does **not** steer traffic at the operating-system level. It exposes local SOCKS5 or HTTP inbound ports and expects each application to be configured manually. ProxyTuner can route application-configured SOCKS5 and HTTP connections by domain, IP, and port. On Linux, the opt-in `--transparent` mode redirects local IPv4 TCP connections into the same forwarder.

```text
Application traffic
        │
        ▼
   ProxyTuner          ◄── domain/IP/port rules for supported inputs
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
| **Per-process traffic steering** | ✘ | ✘ (not implemented) |
| **Transparent local TCP interception** | ✘ | ✔ (Linux iptables REDIRECT; opt-in) |
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

# Keep private networks direct and route other connections through V2Portal.
proxy-tuner rule add private-direct \
  --ip-cidr "10.0.0.0/8,192.168.0.0/16" \
  --outbound direct \
  --priority 5

# Catch-all: send everything else through the balanced group.
proxy-tuner rule add default-proxy \
  --outbound vless-balanced \
  --priority 100

# 4. Start ProxyTuner. Bypass V2Portal's UID and local inbound ports to avoid loops.
sudo proxy-tuner --config "$HOME/.config/proxy-tuner/config.json" start --transparent \
  --bypass-uid "$(id -u v2portal)" \
  --bypass-port 1080 --bypass-port 1081 --bypass-port 1082
# or
proxy-tuner start --foreground  # manual mode; configure apps to use this listener
```

### Installation side-by-side

Both tools live on PyPI and use separate config directories, so they coexist without conflict:

```bash
python -m pip install v2portal proxy-tuner
```

V2Portal stores its config under `~/.config/v2portal/` and ProxyTuner under `~/.config/proxy-tuner/`. Each tool manages its own config, rules, and runtime state independently.

> **In short:** V2Portal manages *what* proxies are available. ProxyTuner routes app-configured connections and can redirect local TCP traffic on Linux when explicitly enabled.

## Features

- **Multiple upstream outbounds:** SOCKS5, HTTP CONNECT, and direct connections.
- **Rule-based routing:** Priority-ordered rules with AND logic between match fields and OR logic within list fields.
- **Domain routing:** Wildcard patterns such as `*.example.com` and domain regular expressions.
- **IP routing:** Exact IPs, IPv4/IPv6 CIDR ranges, and IP regular expressions.
- **Port routing:** Exact ports and port ranges.
- **Process-aware rules:** Modeled by the rule engine, but not applied by current platform interception.
- **Local proxy server:** Accepts both SOCKS5 and HTTP CONNECT clients on the same listener, with protocol auto-detection.
- **Authenticated proxies:** Optional username/password authentication for SOCKS5 and HTTP outbounds.
- **Async forwarding:** `asyncio`-based connections, bidirectional relay, retries, pooling, DNS caching, and per-outbound statistics.
- **Operations CLI:** Setup wizard, config validation, hot reload on Unix, shell completions, logs, live monitoring, benchmarking, and `doctor` diagnostics.
- **Linux transparent mode:** Opt-in IPv4 TCP redirection through iptables. UDP, IPv6 interception, and process/domain matching for redirected sockets are not supported by this mode.
- **Cross-platform codebase:** Local proxy mode is Python-based; Windows and macOS transparent interception are not implemented.

## Quick Start

### 1. Install

Requires **Python 3.10 or newer**.

```bash
python -m pip install proxy-tuner
```

For development from source:

```bash
git clone https://github.com/HoomanJCode/ProxyTuner.git
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
| Linux | Supported | Experimental: local IPv4 TCP only | `iptables` and root are required; `--transparent` enables OUTPUT redirection |
| Windows | Supported | Not implemented | WinDivert backend is a stub |
| macOS | Supported | Not implemented | pf backend is a stub |

The cross-platform workflow is to run the local forwarder and configure each application to use `127.0.0.1:10808`. Linux local TCP redirection is experimental; it redirects IPv4 TCP connections from other UIDs and leaves ProxyTuner's own upstream connections and its listener port alone. Use `--bypass-uid` and `--bypass-port` for other local proxy services.

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

Use the local proxy mode by configuring applications to use `127.0.0.1:10808`. Linux transparent mode requires root and `iptables`:

- Linux: `sudo proxy-tuner start --transparent` redirects local IPv4 TCP connections. UDP and IPv6 are not intercepted.

## Development

```bash
git clone https://github.com/HoomanJCode/ProxyTuner.git
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
