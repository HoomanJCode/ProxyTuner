"""Edge case tests for robustness."""

from __future__ import annotations

import asyncio
import json
import struct

import pytest

from proxy_tuner.config import Config, ConfigManager, MatchCondition, Rule, Settings
from proxy_tuner.rules import ConnectionInfo, RuleEngine
from proxy_tuner.socks5 import Socks5Error, _encode_address, _decode_address
from proxy_tuner.dns import DnsCache


class TestConfigEdgeCases:
    def test_empty_config_roundtrip(self, tmp_path) -> None:
        config_file = tmp_path / "empty.json"
        manager = ConfigManager(config_file)
        config = manager.load()
        assert config.version == 1

    def test_config_with_all_match_types(self, tmp_path) -> None:
        config_file = tmp_path / "full.json"
        manager = ConfigManager(config_file)
        from proxy_tuner.config import Socks5Outbound
        config = manager.get()

        config.outbounds["proxy"] = Socks5Outbound(type="socks5", host="127.0.0.1", port=1080)
        config.rules.append(Rule(
            name="full-rule",
            priority=10,
            outbound="proxy",
            match=MatchCondition(
                process=["firefox", "chrome"],
                process_path=["/usr/bin/*"],
                domain=["*.google.com"],
                domain_regex=[r".*\.cdn\..*"],
                ip=["1.2.3.4"],
                ip_cidr=["10.0.0.0/8"],
                ip_regex=[r"^192\.168\."],
                port=[80, 443],
                port_range=["8000-9000"],
                url_regex=[r"https?://.*\.example\.com"],
            ),
        ))
        manager.save(config)

        # Reload and verify
        manager2 = ConfigManager(config_file)
        loaded = manager2.load()
        assert len(loaded.rules) == 1
        m = loaded.rules[0].match
        assert len(m.process) == 2
        assert len(m.domain) == 1
        assert len(m.ip_cidr) == 1
        assert len(m.port) == 2


class TestRuleEngineEdgeCases:
    def test_no_rules(self) -> None:
        config = Config(outbounds={"direct": {"type": "direct"}})
        engine = RuleEngine(config)
        assert engine.evaluate(ConnectionInfo(dst_host="example.com")) is None

    def test_disabled_rules_skipped(self) -> None:
        config = Config(
            outbounds={"direct": {"type": "direct"}},
            rules=[
                Rule(name="disabled", enabled=False, outbound="direct", match=MatchCondition(process=["firefox"])),
                Rule(name="catch-all", priority=100, outbound="direct", match=MatchCondition()),
            ],
        )
        engine = RuleEngine(config)
        # Disabled rule should be skipped, catch-all matches
        result = engine.evaluate(ConnectionInfo(process_name="firefox"))
        assert result == "direct"

    def test_empty_connection_info(self) -> None:
        config = Config(
            outbounds={"direct": {"type": "direct"}},
            rules=[
                Rule(name="rule", outbound="direct", match=MatchCondition(domain=["*.com"])),
            ],
        )
        engine = RuleEngine(config)
        # Empty connection should not match domain rule
        assert engine.evaluate(ConnectionInfo()) is None

    def test_unicode_process_name(self) -> None:
        config = Config(
            outbounds={"direct": {"type": "direct"}},
            rules=[
                Rule(name="rule", outbound="direct", match=MatchCondition(process=["日本語"])),
            ],
        )
        engine = RuleEngine(config)
        assert engine.evaluate(ConnectionInfo(process_name="日本語")) == "direct"

    def test_very_long_domain(self) -> None:
        config = Config(
            outbounds={"direct": {"type": "direct"}},
            rules=[
                Rule(name="rule", outbound="direct", match=MatchCondition(domain=["*.example.com"])),
            ],
        )
        engine = RuleEngine(config)
        long_domain = "a" * 200 + ".com"
        assert engine.evaluate(ConnectionInfo(dst_host=long_domain)) is None

    def test_invalid_regex_in_rule(self) -> None:
        config = Config(
            outbounds={"direct": {"type": "direct"}},
            rules=[
                Rule(name="rule", outbound="direct", match=MatchCondition(
                    domain_regex=["[invalid"],
                    port=[443],
                )),
            ],
        )
        # Invalid regex ignored, but port=443 still applies
        engine = RuleEngine(config)
        assert engine.evaluate(ConnectionInfo(dst_host="example.com", dst_port=80)) is None
        assert engine.evaluate(ConnectionInfo(dst_host="example.com", dst_port=443)) == "direct"


class TestDnsCacheEdgeCases:
    def test_concurrent_access(self) -> None:
        cache = DnsCache()
        cache.put("a.com", "1.1.1.1")
        cache.put("b.com", "2.2.2.2")
        assert cache.size == 2
        cache.clear()
        assert cache.size == 0

    def test_overwrite_entry(self) -> None:
        cache = DnsCache()
        cache.put("a.com", "1.1.1.1")
        cache.put("a.com", "2.2.2.2")
        assert cache.get("a.com") == "2.2.2.2"
        assert cache.size == 1

    def test_cleanup_empty(self) -> None:
        cache = DnsCache()
        assert cache.cleanup() == 0


class TestSocks5EdgeCases:
    def test_encode_decode_roundtrip(self) -> None:
        encoded = _encode_address("example.com", 443)
        assert encoded[0] == 3  # ATYP_DOMAIN
        decoded_host, decoded_port, _ = _decode_address(
            b"\x05\x00\x00" + encoded, offset=3
        )
        assert decoded_host == "example.com"
        assert decoded_port == 443

    def test_encode_ipv4_roundtrip(self) -> None:
        encoded = _encode_address("10.0.0.1", 8080)
        assert encoded[0] == 1  # ATYP_IPV4
        decoded_host, decoded_port, _ = _decode_address(
            b"\x05\x00\x00" + encoded, offset=3
        )
        assert decoded_host == "10.0.0.1"
        assert decoded_port == 8080

    def test_encode_ipv6_roundtrip(self) -> None:
        encoded = _encode_address("::1", 443)
        assert encoded[0] == 4  # ATYP_IPV6
        decoded_host, decoded_port, _ = _decode_address(
            b"\x05\x00\x00" + encoded, offset=3
        )
        assert decoded_host == "::1"
        assert decoded_port == 443


class TestForwarderEdgeCases:
    def test_forwarder_start_stop(self) -> None:
        async def _test() -> None:
            from proxy_tuner.forwarder import Forwarder
            from proxy_tuner.config import Config, DirectOutbound, Settings

            config = Config(
                outbounds={"direct": DirectOutbound()},
                rules=[Rule(name="default", outbound="direct")],
                settings=Settings(listen_port=0),
            )
            forwarder = Forwarder(config=config)
            await forwarder.start()
            assert forwarder.is_running
            await forwarder.stop()
            assert not forwarder.is_running

        asyncio.run(_test())

    def test_pool_stats(self) -> None:
        from proxy_tuner.outbounds import OutboundStats

        stats = OutboundStats()
        stats.record_connection(100.0)
        stats.record_bytes(1024, 2048)
        assert stats.connections == 1
        assert stats.bytes_sent == 1024
        assert stats.bytes_received == 2048
        assert stats.avg_latency_ms == 100.0
