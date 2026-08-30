# TODO

> **Workflow**: Each completed task is committed individually to master. TODO.md is updated after every commit.

## Phase 1: Project Scaffold & CLI Skeleton

- [x] Initialize `pyproject.toml` with project metadata and dependencies
- [x] Set up `src/proxy_tuner/` package structure with `__init__.py`
- [x] Create `src/proxy_tuner/config.py` — config file load/save
- [x] Create `src/proxy_tuner/config.py` — dataclass models for config schema
- [x] Create `src/proxy_tuner/config.py` — config validation logic
- [x] Create `src/proxy_tuner/cli.py` — main Click group
- [x] Create `src/proxy_tuner/cli_outbound.py` — outbound subcommands (add/rm/list/test)
- [x] Create `src/proxy_tuner/cli_rule.py` — rule subcommands (add/rm/list/move/test)
- [x] Create `src/proxy_tuner/cli_config.py` — config subcommands (show/path/edit/validate)
- [x] Create `src/proxy_tuner/cli_start.py` — start/stop/status commands
- [x] Write unit tests for config load/save/validate (36 tests)
- [x] Write unit tests for CLI commands (28 tests)
- [x] Create `examples/config.json` — example configuration file
- [x] Verify `proxy-tuner --help` works and displays all commands

## Phase 2: Rule Engine

- [x] Create `src/proxy_tuner/rules.py` — RuleEngine class
- [x] Implement ConnectionInfo dataclass (dst_ip, dst_port, dst_host, process_name, process_path, url)
- [x] Implement process name matching (cross-platform)
- [x] Implement process path matching (glob + regex)
- [x] Implement domain wildcard matching (`*.example.com`)
- [x] Implement domain regex matching
- [x] Implement IP exact match
- [x] Implement IP CIDR matching (use `ipaddress` stdlib)
- [x] Implement IP regex matching
- [x] Implement port exact matching
- [x] Implement port range matching
- [x] Implement URL regex matching
- [x] Implement AND combination across match types
- [x] Implement OR combination within list fields
- [x] Implement priority-based rule ordering
- [x] Implement default/catch-all rule handling
- [x] Write unit tests for all match types (50 tests)
- [x] Implement `proxy-tuner rule test` CLI command

## Phase 3: Proxy Forwarding

- [x] Create `src/proxy_tuner/outbounds.py` — OutboundManager class
- [x] Implement SOCKS5 client (RFC 1928) with auth support
- [x] Implement HTTP CONNECT client with auth support
- [x] Implement direct connection (no proxy)
- [x] Implement outbound health check / test
- [x] Create `src/proxy_tuner/forwarder.py` — local proxy server
- [x] Implement HTTP proxy listener (accept HTTP CONNECT)
- [x] Implement SOCKS5 proxy listener
- [x] Integrate rule engine with forwarder
- [ ] Implement DNS interception for domain-based rules
- [x] Implement connection statistics tracking
- [ ] Implement connection pooling / keepalive
- [x] Write unit tests for SOCKS5 client (10 tests)
- [x] Write unit tests for HTTP CONNECT client (5 tests)
- [x] Write integration tests for forwarder (7 tests)

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
- [x] Phase 1 complete: scaffold + CLI + config + 64 tests passing
- [x] Phase 2 complete: rule engine + all match types + 50 tests (114 total passing)
- [x] Phase 3 complete: SOCKS5/HTTP forwarding + forwarder + 22 tests (136 total passing)
