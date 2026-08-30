# Configuration Reference

ProxyTuner uses a JSON configuration file located at:

- **Linux**: `~/.config/proxy-tuner/config.json`
- **Windows**: `%APPDATA%\proxy-tuner\config.json`

You can also specify a custom path with `--config <path>`.

## Config File Structure

```json
{
  "version": 1,
  "outbounds": { ... },
  "rules": [ ... ],
  "settings": { ... }
}
```

---

## `version`

Config schema version. Currently `1`.

```json
"version": 1
```

---

## `outbounds`

A dictionary mapping outbound names to their configuration. Outbound names are identifiers used in rules.

### SOCKS5 Outbound

```json
{
  "outbounds": {
    "my-vpn": {
      "type": "socks5",
      "host": "127.0.0.1",
      "port": 1080,
      "username": "user",
      "password": "pass",
      "timeout": 10
    }
  }
}
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `socks5` |
| `host` | string | yes | — | Proxy server hostname or IP |
| `port` | int | yes | — | Proxy server port (1–65535) |
| `username` | string | no | `null` | SOCKS5 auth username (optional) |
| `password` | string | no | `null` | SOCKS5 auth password (optional) |
| `timeout` | int | no | `10` | Connection timeout in seconds |

### HTTP Proxy Outbound

```json
{
  "outbounds": {
    "my-http": {
      "type": "http",
      "host": "127.0.0.1",
      "port": 8080,
      "username": "user",
      "password": "pass",
      "timeout": 10
    }
  }
}
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `type` | string | yes | — | Must be `http` |
| `host` | string | yes | — | Proxy server hostname or IP |
| `port` | int | yes | — | Proxy server port (1–65535) |
| `username` | string | no | `null` | HTTP proxy auth username |
| `password` | string | no | `null` | HTTP proxy auth password |
| `timeout` | int | no | `10` | Connection timeout in seconds |

### Direct Outbound

```json
{
  "outbounds": {
    "direct": {
      "type": "direct"
    }
  }
}
```

The `direct` outbound connects directly without a proxy. You don't need to define it explicitly — it's always available as a special outbound.

---

## `rules`

An ordered array of routing rules. Rules are evaluated top-to-bottom; first match wins.

```json
{
  "rules": [
    {
      "name": "firefox-vpn",
      "enabled": true,
      "priority": 10,
      "outbound": "my-vpn",
      "match": {
        "process": ["firefox"],
        "domain": ["*.google.com", "*.youtube.com"]
      }
    },
    {
      "name": "direct-everything",
      "enabled": true,
      "priority": 100,
      "outbound": "direct",
      "match": {}
    }
  ]
}
```

### Rule Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Unique rule name |
| `enabled` | bool | no | Default `true`. Set `false` to disable |
| `priority` | int | no | Lower = higher priority. Default `50` |
| `outbound` | string | yes | Target outbound name |
| `match` | object | yes | Match conditions (see below) |

### Match Conditions

All conditions in a `match` object are combined with AND logic (all must match). Within a list field (arrays), values are combined with OR logic (any match suffices).

```json
"match": {
  "process": ["firefox"],
  "process_path": ["/usr/bin/firefox"],
  "domain": ["*.google.com"],
  "domain_regex": [".*\\.cdn\\..*"],
  "ip": ["1.2.3.4"],
  "ip_cidr": ["10.0.0.0/8", "172.16.0.0/12"],
  "ip_regex": ["^10\\.\\d+\\.\\d+\\.\\d+$"],
  "port": [443, 80],
  "port_range": ["8000-9000"],
  "url_regex": ["https?://.*\\.example\\.com/.*"]
}
```

| Condition | Type | Description |
|---|---|---|
| `process` | `string[]` | Process name (e.g., `firefox`, `chrome.exe`) |
| `process_path` | `string[]` | Full path to process binary |
| `domain` | `string[]` | Domain pattern (`*` matches any characters) |
| `domain_regex` | `string[]` | Domain regex pattern |
| `ip` | `string[]` | Exact IP address |
| `ip_cidr` | `string[]` | CIDR range (e.g., `10.0.0.0/8`) |
| `ip_regex` | `string[]` | IP regex pattern |
| `port` | `int[]` | Exact port number |
| `port_range` | `string[]` | Port range (e.g., `"8000-9000"`) |
| `url_regex` | `string[]` | Full URL regex pattern |

### Match Examples

**Process-only rule**:
```json
{ "process": ["curl", "wget"], "outbound": "my-vpn" }
```

**Domain + IP rule** (AND logic — both must match):
```json
{ "domain": ["*.example.com"], "ip_cidr": ["93.184.0.0/16"], "outbound": "direct" }
```

**Port-only rule** (all HTTPS traffic):
```json
{ "port": [443], "outbound": "my-vpn" }
```

**Regex IP rule** (private IPs):
```json
{ "ip_regex": ["^(10\\.|172\\.(1[6-9]|2\\d|3[01])\\.|192\\.168\\.)"], "outbound": "direct" }
```

---

## `settings`

Global settings for ProxyTuner.

```json
{
  "settings": {
    "listen_port": 10808,
    "tun_name": "proxytun0",
    "tun_address": "10.0.0.1/24",
    "dns_intercept": true,
    "dns_server": "8.8.8.8",
    "log_level": "info",
    "log_file": null,
    "stats_enabled": true,
    "stats_interval": 60
  }
}
```

| Field | Type | Default | Description |
|---|---|---|---|
| `listen_port` | int | `10808` | Local port for the transparent proxy listener |
| `tun_name` | string | `proxytun0` | TUN interface name |
| `tun_address` | string | `10.0.0.1/24` | TUN interface IP and CIDR |
| `dns_intercept` | bool | `true` | Intercept DNS queries for domain matching |
| `dns_server` | string | `8.8.8.8` | Upstream DNS server for resolution |
| `log_level` | string | `info` | `debug`, `info`, `warning`, `error` |
| `log_file` | string | `null` | Log file path (`null` = stdout only) |
| `stats_enabled` | bool | `true` | Track per-outbound traffic statistics |
| `stats_interval` | int | `60` | Stats logging interval in seconds |

---

## Complete Example Config

```json
{
  "version": 1,
  "outbounds": {
    "socks-vpn": {
      "type": "socks5",
      "host": "127.0.0.1",
      "port": 1080,
      "timeout": 10
    },
    "http-proxy": {
      "type": "http",
      "host": "192.168.1.1",
      "port": 8080,
      "username": "admin",
      "password": "secret",
      "timeout": 15
    },
    "fast-relay": {
      "type": "socks5",
      "host": "10.0.0.100",
      "port": 1080,
      "timeout": 5
    }
  },
  "rules": [
    {
      "name": "browser-vpn",
      "enabled": true,
      "priority": 10,
      "outbound": "socks-vpn",
      "match": {
        "process": ["firefox", "chrome", "chromium", "brave", "msedge"]
      }
    },
    {
      "name": "dev-tools-direct",
      "enabled": true,
      "priority": 20,
      "outbound": "direct",
      "match": {
        "process": ["git", "cargo", "npm", "pip"]
      }
    },
    {
      "name": "blocked-sites",
      "enabled": true,
      "priority": 15,
      "outbound": "socks-vpn",
      "match": {
        "domain": ["*.blocked.com", "*.restricted.org"]
      }
    },
    {
      "name": "local-network",
      "enabled": true,
      "priority": 5,
      "outbound": "direct",
      "match": {
        "ip_cidr": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "127.0.0.0/8"]
      }
    },
    {
      "name": "default",
      "enabled": true,
      "priority": 100,
      "outbound": "http-proxy",
      "match": {}
    }
  ],
  "settings": {
    "listen_port": 10808,
    "tun_name": "proxytun0",
    "tun_address": "10.0.0.1/24",
    "dns_intercept": true,
    "dns_server": "8.8.8.8",
    "log_level": "info",
    "stats_enabled": true
  }
}
```

---

## Config File Permissions

On Linux, ProxyTuner enforces `0600` permissions on the config file to protect stored credentials. If the file has broader permissions, ProxyTuner will warn on startup.

## Config Validation

ProxyTuner validates the config file on load. Common validation errors:

- Outbound referenced in a rule doesn't exist in `outbounds`
- Duplicate rule names
- Invalid CIDR notation
- Invalid regex patterns
- Port numbers outside 1–65535

Validation errors are reported with line numbers and descriptions.
