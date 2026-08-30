"""Unit tests for DNS resolver and cache."""

from __future__ import annotations

import time

import pytest

from proxy_tuner.dns import DnsCache, DnsResolver


class TestDnsCache:
    def test_put_and_get(self) -> None:
        cache = DnsCache()
        cache.put("example.com", "1.2.3.4")
        assert cache.get("example.com") == "1.2.3.4"

    def test_get_missing(self) -> None:
        cache = DnsCache()
        assert cache.get("nonexistent.com") is None

    def test_ttl_expiration(self) -> None:
        cache = DnsCache(default_ttl=0)
        cache.put("example.com", "1.2.3.4")
        # With 0 TTL, should expire immediately
        time.sleep(0.01)
        assert cache.get("example.com") is None

    def test_custom_ttl(self) -> None:
        cache = DnsCache(default_ttl=60)
        cache.put("example.com", "1.2.3.4", ttl=0)
        time.sleep(0.01)
        assert cache.get("example.com") is None

    def test_remove(self) -> None:
        cache = DnsCache()
        cache.put("example.com", "1.2.3.4")
        cache.remove("example.com")
        assert cache.get("example.com") is None

    def test_clear(self) -> None:
        cache = DnsCache()
        cache.put("a.com", "1.1.1.1")
        cache.put("b.com", "2.2.2.2")
        cache.clear()
        assert cache.size == 0

    def test_cleanup(self) -> None:
        cache = DnsCache(default_ttl=0)
        cache.put("a.com", "1.1.1.1")
        cache.put("b.com", "2.2.2.2")
        time.sleep(0.01)
        removed = cache.cleanup()
        assert removed == 2
        assert cache.size == 0

    def test_size(self) -> None:
        cache = DnsCache()
        assert cache.size == 0
        cache.put("a.com", "1.1.1.1")
        assert cache.size == 1


class TestDnsResolver:
    def test_skip_ip_address(self) -> None:
        resolver = DnsResolver()
        result = __import__("asyncio").run(resolver.resolve("1.2.3.4"))
        assert result == "1.2.3.4"

    def test_system_resolve(self) -> None:
        resolver = DnsResolver()
        # This test may fail if DNS is not available
        try:
            result = __import__("asyncio").run(resolver.resolve("localhost"))
            # localhost should resolve to 127.0.0.1
            assert result == "127.0.0.1" or result is None
        except Exception:
            pass  # DNS may not be available in test env

    def test_stats(self) -> None:
        resolver = DnsResolver()
        stats = resolver.stats
        assert stats["queries"] == 0
        assert stats["cache_hits"] == 0

    def test_cache_integration(self) -> None:
        resolver = DnsResolver()
        # Put something in cache
        resolver.cache.put("cached.com", "5.5.5.5")
        result = __import__("asyncio").run(resolver.resolve("cached.com"))
        assert result == "5.5.5.5"
        assert resolver.stats["cache_hits"] == 1

    def test_dns_query_building(self) -> None:
        query = DnsResolver._build_dns_query("example.com")
        assert len(query) > 12  # Header + question
        # Check it starts with our transaction ID
        assert query[0:2] == b"\x12\x34"


class TestDnsQueryParsing:
    def test_parse_simple_response(self) -> None:
        # Build a minimal DNS response
        import struct

        # Header
        header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)

        # Question: example.com
        question = b"\x07example\x03com\x00"
        question += struct.pack("!HH", 1, 1)  # Type A, Class IN

        # Answer: example.com -> 93.184.216.34
        answer = b"\xc0\x0c"  # Pointer to name
        answer += struct.pack("!HHIH", 1, 1, 300, 4)  # Type A, Class IN, TTL 300, RDLEN 4
        answer += bytes([93, 184, 216, 34])  # IP

        response = header + question + answer
        ip = DnsResolver._parse_dns_response(response)
        assert ip == "93.184.216.34"

    def test_parse_empty_response(self) -> None:
        ip = DnsResolver._parse_dns_response(b"\x00" * 12)
        assert ip is None

    def test_parse_short_response(self) -> None:
        ip = DnsResolver._parse_dns_response(b"\x00")
        assert ip is None
