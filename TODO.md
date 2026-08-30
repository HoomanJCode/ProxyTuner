# TODO

> **Workflow**: Each completed task is committed individually to master. TODO.md is updated after every commit.

## Phase 1: Project Scaffold & CLI Skeleton

- [ ] Initialize `pyproject.toml` with project metadata and dependencies
- [ ] Set up `src/proxy_tuner/` package structure with `__init__.py`
- [ ] Create `src/proxy_tuner/config.py` — config file load/save
- [ ] Create `src/proxy_tuner/config.py` — Pydantic models for config schema
- [ ] Create `src/proxy_tuner/config.py` — config validation logic
- [ ] Create `src/proxy_tuner/cli.py` — main Click group
- [ ] Create `src/proxy_tuner/cli_outbound.py` — outbound subcommands (add/rm/list/test)
- [ ] Create `src/proxy_tuner/cli_rule.py` — rule subcommands (add/rm/list/move/test)
- [ ] Create `src/proxy_tuner/cli_config.py` — config subcommands (show/path/edit/validate)
- [ ] Create `src/proxy_tuner/cli_start.py` — start/stop/status commands
- [ ] Write unit tests for config load/save/validate
- [ ] Write unit tests for CLI commands
- [x] Create `examples/config.json` — example configuration file
- [ ] Verify `proxy-tuner --help` works and displays all commands

## Phase 2: Rule Engine

- [ ] Create `src/proxy_tuner/rules.py` — RuleEngine class
- [ ] Implement ConnectionInfo dataclass (dst_ip, dst_port, dst_host, process_name, process_path, url)
- [ ] Implement process name matching (cross-platform)
- [ ] Implement process path matching (glob + regex)
- [ ] Implement domain wildcard matching (`*.example.com`)
- [ ] Implement domain regex matching
- [ ] Implement IP exact match
- [ ] Implement IP CIDR matching (use `ipaddress` stdlib)
- [ ] Implement IP regex matching
- [ ] Implement port exact matching
- [ ] Implement port range matching
- [ ] Implement URL regex matching
- [ ] Implement AND combination across match types
- [ ] Implement OR combination within list fields
- [ ] Implement priority-based rule ordering
- [ ] Implement default/catch-all rule handling
- [ ] Write unit tests for all match types
- [ ] Write integration tests for rule evaluation

## Phase 3: Proxy Forwarding

- [ ] Create `src/proxy_tuner/outbounds.py` — OutboundManager class
- [ ] Implement SOCKS5 client (RFC 1928) with auth support
- [ ] Implement HTTP CONNECT client with auth support
- [ ] Implement direct connection (no proxy)
- [ ] Implement outbound health check / test
- [ ] Create `src/proxy_tuner/forwarder.py` — local proxy server
- [ ] Implement HTTP proxy listener (accept HTTP CONNECT + plain HTTP)
- [ ] Implement SOCKS5 proxy listener
- [ ] Integrate rule engine with forwarder
- [ ] Implement DNS interception for domain-based rules
- [ ] Implement connection statistics tracking
- [ ] Implement connection pooling / keepalive
- [ ] Write unit tests for SOCKS5 client
- [ ] Write unit tests for HTTP CONNECT client
- [ ] Write integration tests for forwarder

## Phase 4: Linux Platform

- [ ] Create `src/proxy_tuner/platform/base.py` — PlatformBackend ABC
- [ ] Create `src/proxy_tuner/platform/__init__.py` — platform detection
- [ ] Create `src/proxy_tuner/tun.py` — TunManager class
- [ ] Implement TUN interface creation via pyroute2 or raw ioctl
- [ ] Implement TUN packet reading (async)
- [ ] Implement TUN packet writing
- [ ] Implement TUN interface teardown
- [ ] Create `src/proxy_tuner/platform/linux.py` — LinuxBackend class
- [ ] Implement nftables rule creation for TPROXY/REDIRECT
- [ ] Implement nftables rule cleanup
- [ ] Implement per-process matching via uid-owner
- [ ] Implement `/proc/net/tcp` lookup for real destination
- [ ] Implement `SO_ORIGINAL_DST` retrieval
- [ ] Implement start/stop lifecycle
- [ ] Implement DNS interception via nftables
- [ ] Implement graceful shutdown (signal handling)
- [ ] Write integration tests (requires root)
- [ ] Test on Ubuntu, Fedora, Arch

## Phase 5: Windows Platform

- [ ] Create `src/proxy_tuner/platform/windows.py` — WindowsBackend class
- [ ] Implement WinDivert packet capture
- [ ] Implement process ID extraction from WinDivert
- [ ] Implement TUN interface via wintun
- [ ] Implement connection-to-process mapping (iphlpapi)
- [ ] Implement Windows service management
- [ ] Implement admin elevation check and request
- [ ] Implement cleanup on stop
- [ ] Write unit tests (mocked)

## Phase 6: Polish

- [ ] Add `proxy-tuner status` with live connection stats
- [ ] Add daemon mode (`--daemon`, PID file)
- [ ] Add config hot-reload (`proxy-tuner reload`)
- [ ] Add structured logging framework
- [ ] Add `proxy-tuner config validate` command
- [ ] Add `proxy-tuner version` command
- [ ] Add shell completions (bash, zsh, fish)
- [ ] Write comprehensive error messages
- [ ] Add GitHub Actions CI/CD
- [ ] Add pre-commit hooks (ruff, mypy)
- [ ] Publish to PyPI
- [ ] Write man page

## Done

- [x] Project planning documents (commit `91380b1`)
- [x] Architecture design document
- [x] Configuration reference
- [x] Usage guide
- [x] Development plan
- [x] Example config file
