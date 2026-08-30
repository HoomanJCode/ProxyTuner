# Architecture

## Overview

ProxyTuner is a Python CLI application that acts as a transparent proxy router. It intercepts network traffic from specific processes or matching certain patterns, and forwards it through configurable proxy outbounds (SOCKS5 or HTTP).

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    CLI Layer (click)                     │
│  outbound add/rm │ rule add/rm │ start │ stop │ status  │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│                 Configuration Manager                    │
│              (JSON/YAML config file)                     │
│  outbounds: [...]   rules: [...]   settings: {...}      │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│                    Rule Engine                           │
│                                                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ Process  │ │  Domain  │ │    IP    │ │   Port   │  │
│  │  Match   │ │  Match   │ │  Match   │ │  Match   │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │
│                                                         │
│  Match result → outbound name                           │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│               Platform Abstraction Layer                 │
│                                                         │
│  ┌─────────────────┐    ┌─────────────────────┐        │
│  │  Linux Backend  │    │  Windows Backend    │        │
│  │                 │    │                     │        │
│  │  • nftables     │    │  • WinDivert        │        │
│  │  • TUN iface    │    │  • Process filtering│        │
│  │  • iptables     │    │  • TUN interface    │        │
│  │  • /proc/pid    │    │                     │        │
│  └─────────────────┘    └─────────────────────┘        │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│                 Proxy Forwarder                          │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐             │
│  │ SOCKS5   │  │  HTTP    │  │ Direct   │             │
│  │ Client   │  │ Connect  │  │ (no prox)│             │
│  └──────────┘  └──────────┘  └──────────┘             │
└─────────────────────────────────────────────────────────┘
```

## Core Components

### 1. CLI Layer

**Module**: `proxy_tuner/cli.py`

Uses [Click](https://click.palletsprojects.com/) for the command-line interface. Provides commands for managing outbounds, rules, and the tuning daemon.

```
proxy-tuner
├── outbound
│   ├── add <name> --type <socks5|http> --host <h> --port <p> [--user <u>] [--pass <p>]
│   ├── remove <name>
│   ├── list
│   └── test <name>
├── rule
│   ├── add <name> --outbound <ob> [match options]
│   ├── remove <name>
│   ├── list
│   ├── move <name> --priority <n>    # reorder
│   └── test <name> <target>          # test rule match
├── start [--foreground] [--daemon]
├── stop
├── status
├── config
│   ├── show
│   ├── path
│   └── edit
└── version
```

### 2. Configuration Manager

**Module**: `proxy_tuner/config.py`

Manages a JSON config file at `~/.config/proxy-tuner/config.json` (Linux) or `%APPDATA%/proxy-tuner/config.json` (Windows).

```python
ConfigManager:
    load() -> Config
    save(config: Config)
    add_outbound(name, outbound)
    remove_outbound(name)
    add_rule(name, rule)
    remove_rule(name)
    get_active_outbounds() -> list[Outbound]
    get_rules() -> list[Rule]
```

### 3. Rule Engine

**Module**: `proxy_tuner/rules.py`

Evaluates traffic against rules in priority order and determines the outbound.

```python
class RuleEngine:
    def __init__(self, rules: list[Rule], outbounds: dict[str, Outbound]):
        ...

    def evaluate(self, connection: ConnectionInfo) -> Outbound:
        """Match a connection against rules, return the outbound to use."""
        ...

    def evaluate_batch(self, connections: list[ConnectionInfo]) -> dict[str, Outbound]:
        """Efficiently evaluate multiple connections."""
        ...
```

**Match types** (each rule can combine multiple conditions with AND logic):

| Match Type | Field | Example |
|---|---|---|
| Process name | `process` | `firefox`, `chrome.exe` |
| Process path | `process_path` | `/usr/bin/firefox` |
| Domain | `domain` | `*.google.com`, `example.com` |
| Domain regex | `domain_regex` | `.*\.cdn\..*` |
| IP address | `ip` | `1.2.3.4` |
| IP CIDR | `ip_cidr` | `10.0.0.0/8`, `192.168.1.0/24` |
| IP regex | `ip_regex` | `10\.\d+\.\d+\.\d+` |
| Port | `port` | `443`, `80-8000` |
| URL regex | `url_regex` | `https?://.*\.example\.com/.*` |

**Rule priority**: Rules are evaluated in order. First match wins. A special `default` rule acts as catch-all.

### 4. Outbound Manager

**Module**: `proxy_tuner/outbounds.py`

Manages connections to upstream proxies.

```python
class OutboundManager:
    def __init__(self, config: Config):
        ...

    async def connect(self, name: str, target: tuple[str, int]) -> Stream:
        """Open a proxied connection to target through the named outbound."""
        ...

    async def connect_direct(self, target: tuple[str, int]) -> Stream:
        """Connect directly without a proxy."""
        ...

    def test_outbound(self, name: str) -> OutboundTestResult:
        """Test connectivity through an outbound proxy."""
        ...
```

**Supported outbound types**:
- `socks5` — SOCKS5 proxy (RFC 1928)
- `http` — HTTP CONNECT proxy
- `direct` — No proxy (direct connection, implicit)

### 5. Platform Layer

**Module**: `proxy_tuner/platform/`

Abstracts OS-specific traffic interception.

```python
class PlatformBackend(ABC):
    @abstractmethod
    async def start(self, local_port: int, rules: list[Rule]) -> None:
        """Start intercepting traffic."""
        ...

    @abstractmethod
    async def stop(self) -> None:
        """Stop intercepting and clean up rules."""
        ...

    @abstractmethod
    def get_pid_for_connection(self, src_ip, src_port, dst_ip, dst_port) -> int | None:
        """Resolve which process owns a connection."""
        ...
```

#### Linux Backend (`platform/linux.py`)

**Approach**: nftables TPROXY + TUN interface

```
Application (process X)
    │ (produces traffic)
    ▼
nftables rule: --uid-owner X → REDIRECT to local TUN:port
    │
    ▼
TUN Interface (e.g., 10.0.0.1/24)
    │
    ▼
ProxyTuner TUN reader (reads raw IP packets)
    │ (extracts src/dst, resolves PID via /proc/net/tcp)
    ▼
Rule Engine → picks outbound
    │
    ▼
SOCKS5/HTTP forwarder → upstream proxy → internet
```

**Key components**:
- Creates a TUN interface (`ip tuntap add`)
- Sets up nftables/iptables rules for traffic interception
- Uses `SO_ORIGINAL_DST` or `/proc/net/tcp` to find real destinations
- Per-process matching via `SO_MARK` + `--uid-owner` or cgroups

**Fallback**: If TPROXY unavailable, uses `iptables -j REDIRECT` (less clean but wider compatibility).

#### Windows Backend (`platform/windows.py`)

**Approach**: WinDivert packet interception

```
Application (process X)
    │ (produces traffic)
    ▼
WinDivert driver (intercepts packets from process X)
    │ (WinDivert can filter by process ID)
    ▼
ProxyTuner packet reader
    │ (extracts connection info from IP headers)
    ▼
Rule Engine → picks outbound
    │
    ▼
SOCKS5/HTTP forwarder → upstream proxy → internet
```

**Key components**:
- WinDivert driver for packet capture (requires admin + driver install)
- Process ID extraction from WinDivert filter parameters
- TUN interface (via `wintun` adapter) for return traffic
- `iphlpapi` for connection-to-process mapping

### 6. TUN Interface Manager

**Module**: `proxy_tuner/tun.py`

Manages the TUN/TAP virtual network interface used for transparent proxying.

```python
class TunManager:
    def __init__(self, device_name: str = "proxytun0"):
        ...

    async def open(self) -> None:
        """Create and configure the TUN interface."""
        ...

    async def read_packets(self) -> AsyncIterator[bytes]:
        """Read raw IP packets from the TUN."""
        ...

    async def write_packet(self, data: bytes) -> None:
        """Write a raw IP packet to the TUN."""
        ...

    async def close(self) -> None:
        """Destroy the TUN interface."""
        ...
```

**Linux**: uses `pyroute2` or raw `/dev/net/tun` ioctl
**Windows**: uses `wintun` Python bindings or ctypes calls

### 7. Proxy Forwarder

**Module**: `proxy_tuner/forwarder.py`

The core forwarding loop that bridges intercepted traffic to outbounds.

```python
class Forwarder:
    def __init__(self, rule_engine: RuleEngine, outbound_mgr: OutboundManager):
        ...

    async def run(self, tun: TunManager) -> None:
        """Main forwarding loop."""
        async for packet in tun.read_packets():
            conn = parse_ip_packet(packet)
            pid = platform.get_pid_for_connection(conn)
            process_name = get_process_name(pid)
            outbound = self.rule_engine.evaluate(ConnectionInfo(
                dst_ip=conn.dst_ip,
                dst_port=conn.dst_port,
                dst_host=conn.dst_host,  # from DNS interception
                process_name=process_name,
            ))
            asyncio.create_task(self._forward(conn, outbound))

    async def _forward(self, conn: Connection, outbound: Outbound | None):
        """Forward a single connection through the determined outbound."""
        ...
```

## Data Flow

```
1. User runs `proxy-tuner start`
2. Config is loaded from disk
3. Platform backend starts (creates TUN, sets up iptables/WinDivert)
4. Forwarder loop begins:
   a. Read packet from TUN
   b. Parse connection info (src, dst, port)
   c. Resolve process name from PID
   d. Evaluate rules → determine outbound
   e. Connect to outbound proxy
   f. Forward data bidirectionally
5. User runs `proxy-tuner stop`
6. Platform backend stops (removes iptables rules, destroys TUN)
```

## Configuration Schema

See [docs/configuration.md](configuration.md) for the full schema.

## Error Handling

- **Permission errors**: Check root/admin at startup, fail early with clear message
- **Proxy unreachable**: Mark outbound as failed, use fallback (direct or next rule)
- **Config corruption**: Validate on load, back up before save
- **Platform not supported**: Fail at startup with platform-specific message

## Performance Considerations

- Async I/O throughout (`asyncio`) for handling many concurrent connections
- Connection pooling per outbound
- Rule evaluation uses compiled regex patterns for speed
- Batch evaluation where possible to reduce per-packet overhead
- DNS interception to avoid separate DNS resolution step

## Security Considerations

- Config file permissions: `0600` (user-only read/write)
- Proxy credentials stored in config (not passed via CLI args)
- No logging of user traffic content
- Optional traffic statistics (bytes transferred per outbound)
