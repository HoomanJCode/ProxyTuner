"""Unit tests for config models and manager."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from proxy_tuner.config import (
    Config,
    ConfigManager,
    DirectOutbound,
    HttpOutbound,
    MatchCondition,
    Rule,
    Settings,
    Socks5Outbound,
    _deserialize_config,
    _serialize_config,
    parse_outbound,
)

# ---------------------------------------------------------------------------
# Outbound parsing
# ---------------------------------------------------------------------------

class TestOutboundParsing:
    def test_parse_socks5(self) -> None:
        data = {"type": "socks5", "host": "127.0.0.1", "port": 1080}
        ob = parse_outbound("test", data)
        assert isinstance(ob, Socks5Outbound)
        assert ob.host == "127.0.0.1"
        assert ob.port == 1080
        assert ob.timeout == 10

    def test_parse_http(self) -> None:
        data = {"type": "http", "host": "10.0.0.1", "port": 8080, "timeout": 5}
        ob = parse_outbound("test", data)
        assert isinstance(ob, HttpOutbound)
        assert ob.host == "10.0.0.1"
        assert ob.port == 8080
        assert ob.timeout == 5

    def test_parse_direct(self) -> None:
        data = {"type": "direct"}
        ob = parse_outbound("test", data)
        assert isinstance(ob, DirectOutbound)
        assert ob.type == "direct"

    def test_parse_unknown_type(self) -> None:
        data = {"type": "shadowsocks"}
        with pytest.raises(ValueError, match="Unknown outbound type"):
            parse_outbound("test", data)

    def test_parse_socks5_with_auth(self) -> None:
        data = {
            "type": "socks5",
            "host": "proxy.example.com",
            "port": 1080,
            "username": "user",
            "password": "pass",
        }
        ob = parse_outbound("test", data)
        assert isinstance(ob, Socks5Outbound)
        assert ob.username == "user"
        assert ob.password == "pass"

    def test_parse_socks5_extra_fields_ignored(self) -> None:
        data = {
            "type": "socks5",
            "host": "127.0.0.1",
            "port": 1080,
            "unknown_field": "should be ignored",
        }
        ob = parse_outbound("test", data)
        assert isinstance(ob, Socks5Outbound)


# ---------------------------------------------------------------------------
# MatchCondition validation
# ---------------------------------------------------------------------------

class TestMatchCondition:
    def test_empty_match_is_empty(self) -> None:
        m = MatchCondition()
        assert m.is_empty is True

    def test_non_empty_match(self) -> None:
        m = MatchCondition(process=["firefox"])
        assert m.is_empty is False

    def test_valid_regex(self) -> None:
        m = MatchCondition(domain_regex=[".*\\.com$", "^test\\..*"])
        errors = m.validate()
        assert errors == []

    def test_invalid_regex(self) -> None:
        m = MatchCondition(domain_regex=["[invalid"])
        errors = m.validate()
        assert len(errors) == 1
        assert "Invalid regex" in errors[0]

    def test_valid_cidr(self) -> None:
        m = MatchCondition(ip_cidr=["10.0.0.0/8", "192.168.1.0/24"])
        errors = m.validate()
        assert errors == []

    def test_invalid_cidr(self) -> None:
        m = MatchCondition(ip_cidr=["10.0.0.0/33"])
        errors = m.validate()
        assert len(errors) == 1
        assert "Invalid CIDR" in errors[0]

    def test_valid_port(self) -> None:
        m = MatchCondition(port=[80, 443, 8080])
        errors = m.validate()
        assert errors == []

    def test_invalid_port(self) -> None:
        m = MatchCondition(port=[0, 70000])
        errors = m.validate()
        assert len(errors) == 2

    def test_valid_port_range(self) -> None:
        m = MatchCondition(port_range=["8000-9000"])
        errors = m.validate()
        assert errors == []

    def test_invalid_port_range(self) -> None:
        m = MatchCondition(port_range=["not-a-range"])
        errors = m.validate()
        assert len(errors) == 1

    def test_multiple_validation_errors(self) -> None:
        m = MatchCondition(
            domain_regex=["[bad"],
            ip_cidr=["999.999.999.999/24"],
            port=[99999],
        )
        errors = m.validate()
        assert len(errors) == 3


# ---------------------------------------------------------------------------
# Config serialization roundtrip
# ---------------------------------------------------------------------------

class TestConfigSerialization:
    def test_roundtrip(self) -> None:
        config = Config(
            outbounds={
                "vpn": Socks5Outbound(type="socks5", host="127.0.0.1", port=1080),
                "direct": DirectOutbound(),
            },
            rules=[
                Rule(
                    name="test-rule",
                    priority=10,
                    outbound="vpn",
                    match=MatchCondition(process=["firefox"]),
                ),
            ],
            settings=Settings(listen_port=9090),
        )

        serialized = _serialize_config(config)
        deserialized = _deserialize_config(serialized)

        assert len(deserialized.outbounds) == 2
        assert deserialized.outbounds["vpn"].type == "socks5"
        assert deserialized.outbounds["vpn"].host == "127.0.0.1"
        assert deserialized.outbounds["direct"].type == "direct"
        assert len(deserialized.rules) == 1
        assert deserialized.rules[0].name == "test-rule"
        assert deserialized.rules[0].match.process == ["firefox"]
        assert deserialized.settings.listen_port == 9090

    def test_roundtrip_empty_config(self) -> None:
        config = Config()
        serialized = _serialize_config(config)
        deserialized = _deserialize_config(serialized)
        assert deserialized.version == 1
        assert len(deserialized.outbounds) == 0
        assert len(deserialized.rules) == 0

    def test_json_roundtrip(self) -> None:
        config = Config(
            outbounds={
                "proxy": HttpOutbound(
                    type="http", host="10.0.0.1", port=3128, username="admin"
                ),
            },
            rules=[
                Rule(
                    name="block-ads",
                    enabled=False,
                    priority=5,
                    outbound="proxy",
                    match=MatchCondition(
                        domain=["*.ads.com"],
                        ip_cidr=["10.0.0.0/8"],
                    ),
                ),
            ],
        )
        serialized = _serialize_config(config)
        json_str = json.dumps(serialized, indent=2)
        loaded = json.loads(json_str)
        deserialized = _deserialize_config(loaded)

        assert deserialized.outbounds["proxy"].username == "admin"
        assert deserialized.rules[0].enabled is False
        assert deserialized.rules[0].match.domain == ["*.ads.com"]


# ---------------------------------------------------------------------------
# ConfigManager
# ---------------------------------------------------------------------------

class TestConfigManager:
    def test_load_creates_default(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.json"
        manager = ConfigManager(config_file)
        config = manager.load()

        assert config.version == 1
        assert len(config.outbounds) == 0
        assert config_file.exists()

    def test_save_and_load(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.json"
        manager = ConfigManager(config_file)

        config = Config(
            outbounds={"vpn": Socks5Outbound(type="socks5", host="127.0.0.1", port=1080)},
            rules=[Rule(name="test", outbound="vpn", match=MatchCondition(process=["curl"]))],
        )
        manager.save(config)

        # Reload
        manager2 = ConfigManager(config_file)
        loaded = manager2.load()
        assert "vpn" in loaded.outbounds
        assert loaded.outbounds["vpn"].host == "127.0.0.1"
        assert loaded.rules[0].match.process == ["curl"]

    def test_add_outbound(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.json"
        manager = ConfigManager(config_file)
        manager.load()

        ob = Socks5Outbound(type="socks5", host="1.2.3.4", port=1080)
        manager.add_outbound("my-proxy", ob)

        config = manager.get()
        assert "my-proxy" in config.outbounds

    def test_add_duplicate_outbound_raises(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.json"
        manager = ConfigManager(config_file)
        manager.load()

        ob = Socks5Outbound(type="socks5", host="1.2.3.4", port=1080)
        manager.add_outbound("my-proxy", ob)

        with pytest.raises(ValueError, match="already exists"):
            manager.add_outbound("my-proxy", ob)

    def test_remove_outbound(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.json"
        manager = ConfigManager(config_file)
        manager.load()

        ob = Socks5Outbound(type="socks5", host="1.2.3.4", port=1080)
        manager.add_outbound("my-proxy", ob)
        manager.remove_outbound("my-proxy")

        config = manager.get()
        assert "my-proxy" not in config.outbounds

    def test_remove_nonexistent_outbound_raises(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.json"
        manager = ConfigManager(config_file)
        manager.load()

        with pytest.raises(ValueError, match="does not exist"):
            manager.remove_outbound("nonexistent")

    def test_add_rule(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.json"
        manager = ConfigManager(config_file)
        manager.load()

        rule = Rule(name="test-rule", outbound="direct", priority=10)
        manager.add_rule(rule)

        config = manager.get()
        assert len(config.rules) == 1
        assert config.rules[0].name == "test-rule"

    def test_add_duplicate_rule_raises(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.json"
        manager = ConfigManager(config_file)
        manager.load()

        rule = Rule(name="test-rule", outbound="direct")
        manager.add_rule(rule)

        with pytest.raises(ValueError, match="already exists"):
            manager.add_rule(rule)

    def test_remove_rule(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.json"
        manager = ConfigManager(config_file)
        manager.load()

        rule = Rule(name="test-rule", outbound="direct")
        manager.add_rule(rule)
        manager.remove_rule("test-rule")

        config = manager.get()
        assert len(config.rules) == 0

    def test_remove_nonexistent_rule_raises(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.json"
        manager = ConfigManager(config_file)
        manager.load()

        with pytest.raises(ValueError, match="does not exist"):
            manager.remove_rule("nonexistent")

    def test_update_rule(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.json"
        manager = ConfigManager(config_file)
        manager.load()

        rule = Rule(name="test-rule", outbound="direct", priority=50)
        manager.add_rule(rule)
        manager.update_rule("test-rule", priority=10)

        config = manager.get()
        assert config.rules[0].priority == 10

    def test_rules_sorted_by_priority(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.json"
        manager = ConfigManager(config_file)
        manager.load()

        manager.add_rule(Rule(name="low-pri", outbound="direct", priority=100))
        manager.add_rule(Rule(name="high-pri", outbound="direct", priority=5))

        config = manager.get()
        assert config.rules[0].name == "high-pri"
        assert config.rules[1].name == "low-pri"

    def test_validate_references(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.json"
        manager = ConfigManager(config_file)
        manager.load()

        manager.add_outbound("vpn", Socks5Outbound(type="socks5", host="1.2.3.4", port=1080))
        manager.add_rule(Rule(name="good-rule", outbound="vpn"))
        manager.add_rule(Rule(name="bad-rule", outbound="nonexistent"))

        config = manager.get()
        errors = config.validate_references()
        assert len(errors) == 1
        assert "bad-rule" in errors[0]

    def test_validate_duplicate_rule_names(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.json"
        manager = ConfigManager(config_file)
        manager.load()

        # Manually add duplicate names (shouldn't normally happen)
        config = manager.get()
        config.rules.append(Rule(name="dup", outbound="direct"))
        config.rules.append(Rule(name="dup", outbound="direct"))
        manager.save(config)

        errors = config.validate_references()
        assert any("Duplicate" in e for e in errors)

    def test_config_file_permissions(self, tmp_path: Path) -> None:
        """Config file should be 0600 on Unix."""
        if os.name == "nt":
            pytest.skip("Skipping permission test on Windows")

        config_file = tmp_path / "config.json"
        manager = ConfigManager(config_file)
        manager.save(Config())

        mode = os.stat(config_file).st_mode
        assert mode & 0o777 == 0o600


# ---------------------------------------------------------------------------
# Config.from_json_file
# ---------------------------------------------------------------------------

class TestConfigFromFile:
    def test_load_example_config(self) -> None:
        """Test loading the example config file."""
        example = Path(__file__).parent.parent / "examples" / "config.json"
        if not example.exists():
            pytest.skip("Example config not found")

        with open(example) as f:
            data = json.load(f)

        config = _deserialize_config(data)
        assert config.version == 1
        assert len(config.outbounds) == 3
        assert len(config.rules) == 8
        assert "socks-vpn" in config.outbounds
        assert "http-proxy" in config.outbounds
        assert "fast-relay" in config.outbounds
