# Contributing to ProxyTuner

Thanks for your interest in contributing! Here's how to get started.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/HoomanJCode/PoxyTuner.git
cd PoxyTuner

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run linter
ruff check src/ tests/

# Format code
ruff format src/ tests/
```

## Project Structure

```
src/proxy_tuner/
├── cli.py              # Main CLI entry point
├── cli_*.py            # CLI subcommands
├── config.py           # Configuration models
├── rules.py            # Rule engine
├── socks5.py           # SOCKS5 client
├── http_proxy.py       # HTTP CONNECT client
├── outbounds.py        # Outbound connection manager
├── forwarder.py        # Local proxy server
├── pool.py             # Connection pool
├── dns.py              # DNS resolver
├── tun.py              # TUN interface (Linux)
├── firewall.py         # iptables rules (Linux)
├── logging.py          # Structured logging
├── completions.py      # Shell completions
├── setup_wizard.py     # Setup wizard
├── doctor.py           # Prerequisite checker
├── cli_logs.py         # Log viewer
├── cli_stats.py        # Stats display
├── cli_monitor.py      # Live monitor
└── platform/
    ├── base.py         # Platform backend ABC
    ├── linux.py        # Linux backend
    └── windows.py      # Windows backend
```

## Adding a New CLI Command

1. Create `src/proxy_tuner/cli_yourcmd.py`
2. Define your Click command/group
3. Import and register in `cli.py`:
   ```python
   from proxy_tuner.cli_yourcmd import your_cmd  # noqa: E402
   main.add_command(your_cmd)
   ```

## Adding a New Match Type

1. Add the field to `MatchCondition` in `config.py`
2. Add validation in `MatchCondition.validate()`
3. Add the matching logic in `rules.py` `_match_*` method
4. Add tests in `tests/test_rules.py`
5. Update CLI in `cli_rule.py` if needed

## Running Tests

```bash
# All tests
pytest tests/ -v

# Specific test file
pytest tests/test_rules.py -v

# With coverage
pytest tests/ --cov=proxy_tuner
```

## Code Style

- Python 3.10+ compatible
- Type hints on all public functions
- Docstrings on all public classes/methods
- Use `ruff` for linting and formatting
- Keep functions under 50 lines
- Keep files under 500 lines

## Commit Messages

Use conventional commits:
- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation
- `test:` adding tests
- `refactor:` code refactoring
- `chore:` maintenance

Example:
```
feat: add YAML config format support

- Add yaml_parser.py for YAML config loading
- Add proxy-tuner config import --format yaml
- Add tests for YAML parsing

🤖 Generated with Codebuff
Co-Authored-By: Codebuff <noreply@codebuff.com>
```

## Pull Request Process

1. Fork the repo
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make your changes
4. Run tests: `pytest tests/ -v`
5. Commit with clear message
6. Push and create PR

## Questions?

Open an issue at https://github.com/HoomanJCode/PoxyTuner/issues
