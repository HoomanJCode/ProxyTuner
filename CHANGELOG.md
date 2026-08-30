# Changelog

All notable changes to ProxyTuner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-08-30

### Added

- **CLI Commands**: `start`, `stop`, `reload`, `status`, `version`
- **Outbound Management**: `outbound add/rm/list/test` for SOCKS5, HTTP, and direct proxies
- **Rule Management**: `rule add/rm/list/move/enable/disable/test` with match by:
  - Process name (exact, wildcard, case-insensitive)
  - Process path (glob patterns)
  - Domain (wildcard patterns like `*.google.com`)
  - Domain regex
  - IP address (exact, CIDR ranges, regex)
  - Port (exact, ranges)
  - URL regex
- **Rule Engine**: Priority-based first-match-wins evaluation with AND/OR logic
- **Proxy Forwarding**:
  - Async SOCKS5 client (RFC 1928) with username/password auth
  - HTTP CONNECT tunnel client with Basic auth
  - Local SOCKS5 + HTTP proxy server with protocol auto-detection
  - Bidirectional data relay
- **Connection Pool**: Per-target pooling with idle timeout and max size
- **DNS Resolver**: Async resolver with cache, system and custom server support
- **Linux Transparent Proxy**:
  - TUN interface creation via raw ioctl
  - iptables MARK + REDIRECT rules
  - UID-based per-process routing
  - `/proc/net/tcp` PID lookup
  - `SO_ORIGINAL_DST` retrieval
- **Windows Backend**:
  - WinDivert integration (pydivert + ctypes fallback)
  - iphlpapi `GetExtendedTcpTable` for PID lookup
  - Admin elevation check and request
- **Configuration**:
  - JSON config with dataclass models and validation
  - `config show/path/edit/validate/init/set` commands
  - Config hot-reload via SIGHUP signal
- **Polish**:
  - Structured logging with color output
  - Shell completions (bash, zsh, fish)
  - GitHub Actions CI/CD
  - Daemon mode with PID file
- **Tests**: 187 unit and integration tests

## [Unreleased]

### Planned

- DNS interception via nftables
- Integration tests with root privileges
- Full WinDivert packet capture
- wintun TUN adapter for Windows
- Connection keepalive and retry logic
