"""Configuration models, loader, and validator.

Uses stdlib dataclasses + json. Can be swapped to Pydantic on PC
by changing the models only — CLI layer stays the same.
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from copy import deepcopy
from dataclasses import dataclass, field, fields, asdict
from pathlib import Path
from typing import Any, Literal, get_args


# ---------------------------------------------------------------------------
# Outbound models
# ---------------------------------------------------------------------------

@dataclass
class Socks5Outbound:
    """SOCKS5 proxy outbound."""

    type: Literal["socks5"] = "socks5"
    host: str = ""
    port: int = 1080
    username: str | None = None
    password: str | None = None
    timeout: int = 10


@dataclass
class HttpOutbound:
    """HTTP CONNECT proxy outbound."""

    type: Literal["http"] = "http"
    host: str = ""
    port: int = 8080
    username: str | None = None
    password: str | None = None
    timeout: int = 10


@dataclass
class DirectOutbound:
    """Direct connection (no proxy)."""

    type: Literal["direct"] = "direct"


Outbound = Socks5Outbound | HttpOutbound | DirectOutbound

_OUTBOUND_TYPES: dict[str, type] = {
    "socks5": Socks5Outbound,
    "http": HttpOutbound,
    "direct": DirectOutbound,
}


def parse_outbound(name: str, data: dict[str, Any]) -> Outbound:
    """Parse an outbound dict into the correct dataclass."""
    outbound_type = data.get("type")
    if outbound_type not in _OUTBOUND_TYPES:
        raise ValueError(f"Unknown outbound type '{outbound_type}' for '{name}'")
    cls = _OUTBOUND_TYPES[outbound_type]
    # Filter to only known fields
    known = {f.name for f in fields(cls)}
    filtered = {k: v for k, v in data.items() if k in known}
    return cls(**filtered)


# ---------------------------------------------------------------------------
# MatchCondition
# ---------------------------------------------------------------------------

@dataclass
class MatchCondition:
    """Match conditions for a routing rule.

    All top-level fields are AND-combined.
    Within a list field, values are OR-combined.
    Empty list = no constraint for that field.
    """

    process: list[str] = field(default_factory=list)
    process_path: list[str] = field(default_factory=list)
    domain: list[str] = field(default_factory=list)
    domain_regex: list[str] = field(default_factory=list)
    ip: list[str] = field(default_factory=list)
    ip_cidr: list[str] = field(default_factory=list)
    ip_regex: list[str] = field(default_factory=list)
    port: list[int] = field(default_factory=list)
    port_range: list[str] = field(default_factory=list)
    url_regex: list[str] = field(default_factory=list)

    def validate(self) -> list[str]:
        """Validate all fields. Returns list of error strings."""
        import ipaddress

        errors: list[str] = []
        for pattern in self.domain_regex + self.ip_regex + self.url_regex:
            try:
                re.compile(pattern)
            except re.error as e:
                errors.append(f"Invalid regex '{pattern}': {e}")
        for cidr in self.ip_cidr:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as e:
                errors.append(f"Invalid CIDR '{cidr}': {e}")
        for p in self.port:
            if not (1 <= p <= 65535):
                errors.append(f"Port {p} out of range (1-65535)")
        for pr in self.port_range:
            parts = pr.split("-", 1)
            if len(parts) != 2:
                errors.append(f"Invalid port range '{pr}' (expected 'START-END')")
            else:
                try:
                    lo, hi = int(parts[0]), int(parts[1])
                    if not (1 <= lo <= 65535 and 1 <= hi <= 65535):
                        errors.append(f"Port range '{pr}' has values out of range")
                except ValueError:
                    errors.append(f"Invalid port range '{pr}'")
        return errors

    @property
    def is_empty(self) -> bool:
        """Check if this match has any conditions set."""
        return all(
            getattr(self, f.name) == []
            for f in fields(self)
        )


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    """A routing rule."""

    name: str = ""
    enabled: bool = True
    priority: int = 50
    outbound: str = ""
    match: MatchCondition = field(default_factory=MatchCondition)


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

@dataclass
class Settings:
    """Global settings."""

    listen_port: int = 10808
    tun_name: str = "proxytun0"
    tun_address: str = "10.0.0.1/24"
    dns_intercept: bool = True
    dns_server: str = "8.8.8.8"
    log_level: str = "info"
    log_file: str | None = None
    stats_enabled: bool = True
    stats_interval: int = 60


# ---------------------------------------------------------------------------
# Top-level Config
# ---------------------------------------------------------------------------

@dataclass
class Config:
    """Top-level configuration."""

    version: int = 1
    outbounds: dict[str, Outbound] = field(default_factory=dict)
    rules: list[Rule] = field(default_factory=list)
    settings: Settings = field(default_factory=Settings)

    def validate_references(self) -> list[str]:
        """Validate that all rule outbound references exist. Returns errors."""
        errors: list[str] = []
        for rule in self.rules:
            if rule.outbound not in self.outbounds and rule.outbound != "direct":
                errors.append(
                    f"Rule '{rule.name}' references outbound '{rule.outbound}' "
                    f"which does not exist in outbounds"
                )
        seen_names: set[str] = set()
        for rule in self.rules:
            if rule.name in seen_names:
                errors.append(f"Duplicate rule name: '{rule.name}'")
            seen_names.add(rule.name)
        return errors


# ---------------------------------------------------------------------------
# JSON serialization helpers
# ---------------------------------------------------------------------------

def _serialize_match(m: MatchCondition) -> dict[str, Any]:
    return {f.name: getattr(m, f.name) for f in fields(m) if getattr(m, f.name)}


def _serialize_rule(r: Rule) -> dict[str, Any]:
    return {
        "name": r.name,
        "enabled": r.enabled,
        "priority": r.priority,
        "outbound": r.outbound,
        "match": _serialize_match(r.match),
    }


def _serialize_outbound(ob: Outbound) -> dict[str, Any]:
    d = {f.name: getattr(ob, f.name) for f in fields(ob)}
    return d


def _serialize_config(c: Config) -> dict[str, Any]:
    return {
        "version": c.version,
        "outbounds": {name: _serialize_outbound(ob) for name, ob in c.outbounds.items()},
        "rules": [_serialize_rule(r) for r in c.rules],
        "settings": asdict(c.settings),
    }


def _deserialize_match(data: dict[str, Any]) -> MatchCondition:
    known = {f.name for f in fields(MatchCondition)}
    return MatchCondition(**{k: v for k, v in data.items() if k in known})


def _deserialize_rule(data: dict[str, Any]) -> Rule:
    match_data = data.get("match", {})
    return Rule(
        name=data.get("name", ""),
        enabled=data.get("enabled", True),
        priority=data.get("priority", 50),
        outbound=data.get("outbound", ""),
        match=_deserialize_match(match_data),
    )


def _deserialize_settings(data: dict[str, Any]) -> Settings:
    known = {f.name for f in fields(Settings)}
    return Settings(**{k: v for k, v in data.items() if k in known})


def _deserialize_config(data: dict[str, Any]) -> Config:
    outbounds: dict[str, Outbound] = {}
    for name, ob_data in data.get("outbounds", {}).items():
        outbounds[name] = parse_outbound(name, ob_data)
    rules = [_deserialize_rule(r) for r in data.get("rules", [])]
    settings = _deserialize_settings(data.get("settings", {}))
    return Config(
        version=data.get("version", 1),
        outbounds=outbounds,
        rules=rules,
        settings=settings,
    )


# ---------------------------------------------------------------------------
# Config path helpers
# ---------------------------------------------------------------------------

def get_config_dir() -> Path:
    """Get the platform-appropriate config directory."""
    if sys.platform in ("linux", "android"):
        xdg_config = os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
        return Path(xdg_config) / "proxy-tuner"
    elif sys.platform == "win32":
        appdata = os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))
        return Path(appdata) / "proxy-tuner"
    else:
        raise RuntimeError(f"Unsupported platform: {sys.platform}")


def get_config_path() -> Path:
    """Get the default config file path."""
    return get_config_dir() / "config.json"


# ---------------------------------------------------------------------------
# Config manager
# ---------------------------------------------------------------------------

class ConfigManager:
    """Manages loading, saving, and validating the config file."""

    def __init__(self, config_path: Path | None = None) -> None:
        self._path = config_path or get_config_path()
        self._config: Config | None = None

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> Config:
        """Load config from disk. Creates default if missing."""
        if not self._path.exists():
            config = Config()
            self.save(config)
            return config

        with open(self._path, "r", encoding="utf-8") as f:
            raw = json.load(f)

        self._config = _deserialize_config(raw)
        return self._config

    def save(self, config: Config) -> None:
        """Save config to disk. Creates directory if needed."""
        self._config = config
        self._path.parent.mkdir(parents=True, exist_ok=True)

        data = _serialize_config(config)
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        # Set restrictive permissions on Unix
        if sys.platform != "win32":
            os.chmod(
                self._path,
                stat.S_IRUSR | stat.S_IWUSR,  # 0600
            )

    def get(self) -> Config:
        """Get the current config, loading from disk if needed."""
        if self._config is None:
            return self.load()
        return self._config

    def add_outbound(self, name: str, outbound: Outbound) -> Config:
        """Add an outbound to the config."""
        config = self.get()
        if name in config.outbounds:
            raise ValueError(f"Outbound '{name}' already exists")
        config.outbounds[name] = outbound
        self.save(config)
        return config

    def remove_outbound(self, name: str) -> Config:
        """Remove an outbound from the config."""
        config = self.get()
        if name not in config.outbounds:
            raise ValueError(f"Outbound '{name}' does not exist")
        del config.outbounds[name]
        self.save(config)
        return config

    def add_rule(self, rule: Rule) -> Config:
        """Add a rule to the config."""
        config = self.get()
        if any(r.name == rule.name for r in config.rules):
            raise ValueError(f"Rule '{rule.name}' already exists")
        config.rules.append(rule)
        config.rules.sort(key=lambda r: r.priority)
        self.save(config)
        return config

    def remove_rule(self, name: str) -> Config:
        """Remove a rule from the config."""
        config = self.get()
        original_len = len(config.rules)
        config.rules = [r for r in config.rules if r.name != name]
        if len(config.rules) == original_len:
            raise ValueError(f"Rule '{name}' does not exist")
        self.save(config)
        return config

    def update_rule(self, name: str, **kwargs: Any) -> Config:
        """Update fields on an existing rule."""
        config = self.get()
        for rule in config.rules:
            if rule.name == name:
                for key, value in kwargs.items():
                    if hasattr(rule, key):
                        setattr(rule, key, value)
                config.rules.sort(key=lambda r: r.priority)
                self.save(config)
                return config
        raise ValueError(f"Rule '{name}' does not exist")
