# Development Plan

## Overview

ProxyTuner development is organized into 6 phases. Each phase builds on the previous one and delivers a working (though incomplete) version.

---

## Phase 1: Project Scaffold & CLI Skeleton

**Goal**: Working CLI with config management, no traffic interception yet.

### Tasks
1. Initialize Python project (`pyproject.toml`, `src/proxy_tuner/` layout)
2. Add dependencies: `click`, `rich` (for CLI output), `pydantic` (config validation)
3. Implement `proxy_tuner/config.py` — config file load/save/validate
4. Implement `proxy_tuner/cli.py` — CLI entry point with all subcommands
5. Implement outbound management (add/remove/list/test — config-only, no proxy logic)
6. Implement rule management (add/remove/list/move/test — config-only, no matching logic)
7. Write tests for config and CLI
8. Create example config file

### Deliverable
```bash
proxy-tuner outbound add my-proxy --type socks5 --host 127.0.0.1 --port 1080
proxy-tuner outbound list
proxy-tuner rule add firefox-vpn --process firefox --outbound my-proxy
proxy-tuner rule list
proxy-tuner config show
```

### Dependencies
```
click>=8.0
rich>=13.0
pydantic>=2.0
```

---

## Phase 2: Rule Engine

**Goal**: Complete rule matching logic with all match types.

### Tasks
1. Implement `proxy_tuner/rules.py` — rule evaluation engine
2. Implement process matching (cross-platform process name/PATH resolution)
3. Implement domain matching (wildcard patterns, regex)
4. Implement IP matching (exact, CIDR, regex)
5. Implement port matching (exact, ranges)
6. Implement URL regex matching
7. Implement AND/OR combination logic
8. Write unit tests for all match types

### Deliverable
- Rule engine that can evaluate a `ConnectionInfo` against a list of rules
- Full test coverage for matching logic

---

## Phase 3: Proxy Forwarding (Userspace)

**Goal**: Actual SOCKS5/HTTP proxy connections, usable as a local proxy.

### Tasks
1. Implement `proxy_tuner/outbounds.py` — outbound connection manager
2. Implement SOCKS5 client (`asyncio`-based, RFC 1928)
3. Implement HTTP CONNECT client
4. Implement `proxy_tuner/forwarder.py` — local proxy server (listens on `listen_port`)
5. Integrate rule engine with forwarder (match → select outbound → forward)
6. Implement DNS resolution for domain matching
7. Add connection statistics tracking
8. Write tests for SOCKS5/HTTP clients

### Deliverable
- Users can point browser/system at `127.0.0.1:10808` as HTTP/SOCKS proxy
- Traffic is forwarded based on rules
- Still manual proxy configuration (no auto-redirect)

---

## Phase 4: Platform Layer — Linux

**Goal**: Transparent proxying on Linux (no manual proxy config needed).

### Tasks
1. Implement `proxy_tuner/tun.py` — TUN interface manager
2. Implement `proxy_tuner/platform/base.py` — abstract platform interface
3. Implement `proxy_tuner/platform/linux.py`:
   - TUN interface creation/destruction
   - nftables rules for traffic interception
   - Per-process matching via `--uid-owner` / cgroups
   - `SO_ORIGINAL_DST` / `/proc/net/tcp` for real destination
4. Implement `proxy_tuner/start` and `proxy_tuner stop` commands
5. Implement DNS interception (optional)
6. Handle iptables/nftables cleanup on stop
7. Write integration tests (requires root)

### Deliverable
```bash
sudo proxy-tuner start  # transparently intercepts traffic
# All apps automatically route based on rules
sudo proxy-tuner stop   # cleans up all firewall rules
```

### Dependencies
```
pyroute2>=0.7      # TUN management
netfilter>=0.6     # nftables bindings (or subprocess calls)
```

---

## Phase 5: Platform Layer — Windows

**Goal**: Transparent proxying on Windows.

### Tasks
1. Implement `proxy_tuner/platform/windows.py`:
   - WinDivert packet capture (via `pydivert` or ctypes)
   - Process ID extraction from packets
   - TUN interface via `wintun` adapter
2. Handle WinDivert driver installation/management
3. Implement connection-to-process mapping (`iphlpapi`)
4. Implement cleanup on stop
5. Write tests (mocked, as Windows-specific)

### Deliverable
- Transparent proxying on Windows with per-process routing
- Admin elevation handling

### Dependencies
```
pydivert>=2.1      # WinDivert Python bindings
or
wintun>=0.1        # TUN adapter (ctypes bindings)
```

---

## Phase 6: Polish & Production Readiness

**Goal**: Stable, well-documented, production-ready tool.

### Tasks
1. Add `proxy-tuner status` with live stats
2. Add signal handling (SIGTERM, SIGINT) for clean shutdown
3. Add `--daemon` mode (background with PID file)
4. Add config hot-reload (`proxy-tuner reload`)
5. Add output/logging framework (`loguru` or `logging`)
6. Add `proxy-tuner config validate` command
7. Add `proxy-tuner version` command
8. Write comprehensive README
9. Add CI/CD (GitHub Actions)
10. Publish to PyPI
11. Write man pages
12. Add shell completions (bash, zsh, fish)

### Deliverable
- Fully functional CLI tool
- Published on PyPI
- Comprehensive documentation

---

## Dependency Graph

```
Phase 1 (Scaffold)
    │
    ├──→ Phase 2 (Rules) ──┐
    │                       │
    └──→ Phase 3 (Forward) ─┤
                             │
                    ┌────────┤
                    ▼        ▼
            Phase 4 (Linux)  Phase 5 (Windows)
                    │        │
                    └────────┘
                         │
                         ▼
                    Phase 6 (Polish)
```

Phases 4 and 5 can be developed in parallel by different contributors.

---

## Technology Choices

| Component | Choice | Rationale |
|---|---|---|
| CLI framework | Click | Mature, decorator-based, widely used |
| Config validation | Pydantic v2 | Type-safe, fast, great error messages |
| TUI output | Rich | Beautiful terminal output, tables, progress |
| Async runtime | asyncio | Native Python async, no extra deps |
| SOCKS5 client | Custom (asyncio) | Full control, no heavy dependencies |
| HTTP client | aiohttp or custom | For HTTP CONNECT proxy |
| TUN (Linux) | pyroute2 | Well-maintained, feature-complete |
| Firewall (Linux) | nftables via subprocess | Avoids Python binding complexity |
| Packet capture (Windows) | pydivert / ctypes | WinDivert is the standard for this |
| Testing | pytest + pytest-asyncio | Standard Python testing |

---

## Estimated Effort

| Phase | Effort | Prerequisite |
|---|---|---|
| Phase 1 | 1-2 days | None |
| Phase 2 | 2-3 days | Phase 1 |
| Phase 3 | 3-5 days | Phase 1, 2 |
| Phase 4 | 5-7 days | Phase 2, 3 |
| Phase 5 | 5-7 days | Phase 2, 3 |
| Phase 6 | 3-5 days | Phase 4, 5 |

**Total**: ~20-30 days of focused development.
