"""Tests for the forwarder.

Uses asyncio.run() instead of pytest-asyncio for portability.
"""

from __future__ import annotations

import asyncio
import struct

from proxy_tuner.config import Config, DirectOutbound, MatchCondition, Rule, Settings
from proxy_tuner.forwarder import Forwarder, ForwarderStats
from proxy_tuner.rules import ConnectionInfo
from proxy_tuner.socks5 import SOCKS5_ATYP_IPV4, SOCKS5_VERSION


def _make_config(port: int = 0, rules: list[Rule] | None = None) -> Config:
    return Config(
        outbounds={"direct": DirectOutbound(type="direct")},
        rules=rules or [Rule(name="default", outbound="direct", match=MatchCondition())],
        settings=Settings(listen_port=port),
    )


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

class TestForwarderLifecycle:
    def test_start_and_stop(self) -> None:
        async def _test() -> None:
            config = _make_config()
            forwarder = Forwarder(config=config)
            assert not forwarder.is_running

            await forwarder.start()
            assert forwarder.is_running

            await forwarder.stop()
            assert not forwarder.is_running

        asyncio.run(_test())

    def test_config_update(self) -> None:
        async def _test() -> None:
            config = _make_config()
            forwarder = Forwarder(config=config)
            await forwarder.start()

            new_config = _make_config()
            match = MatchCondition(process=["curl"])
            new_config.rules = [Rule(name="updated", outbound="direct", match=match)]
            forwarder.update_config(new_config)
            assert len(forwarder.config.rules) == 1
            assert forwarder.config.rules[0].name == "updated"

            await forwarder.stop()

        asyncio.run(_test())


# ---------------------------------------------------------------------------
# SOCKS5 handling
# ---------------------------------------------------------------------------

class TestSocks5Handling:
    def test_socks5_connect_direct(self) -> None:
        async def _test() -> None:
            config = _make_config(port=0)
            forwarder = Forwarder(config=config)
            await forwarder.start()

            server = forwarder._server
            assert server is not None
            sockets = server.sockets
            assert sockets is not None
            port = sockets[0].getsockname()[1]

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", port),
                    timeout=5,
                )

                try:
                    # Send SOCKS5 auth negotiation
                    writer.write(struct.pack("!BB", SOCKS5_VERSION, 1) + bytes([0x00]))
                    await writer.drain()

                    # Read auth response
                    auth_response = await asyncio.wait_for(reader.readexactly(2), timeout=5)
                    assert auth_response[0] == SOCKS5_VERSION
                    assert auth_response[1] == 0x00  # No auth

                    # Send CONNECT
                    import ipaddress

                    writer.write(
                        struct.pack("!BBBB", SOCKS5_VERSION, 1, 0x00, SOCKS5_ATYP_IPV4)
                        + ipaddress.IPv4Address("1.1.1.1").packed
                        + struct.pack("!H", 80)
                    )
                    await writer.drain()

                    # Read SOCKS5 response header
                    reply = await asyncio.wait_for(reader.readexactly(4), timeout=10)
                    assert reply[0] == SOCKS5_VERSION
                    # Should be success or error (not a crash)
                    assert reply[1] in (0x00, 0x01, 0x04, 0x05)

                finally:
                    writer.close()
                    await writer.wait_closed()
            finally:
                await forwarder.stop()

        asyncio.run(_test())


# ---------------------------------------------------------------------------
# HTTP CONNECT handling
# ---------------------------------------------------------------------------

class TestHttpConnectHandling:
    def test_http_connect_direct(self) -> None:
        async def _test() -> None:
            config = _make_config(port=0)
            forwarder = Forwarder(config=config)
            await forwarder.start()

            server = forwarder._server
            assert server is not None
            sockets = server.sockets
            assert sockets is not None
            port = sockets[0].getsockname()[1]

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", port),
                    timeout=5,
                )

                try:
                    writer.write(b"CONNECT 1.1.1.1:80 HTTP/1.1\r\nHost: 1.1.1.1:80\r\n\r\n")
                    await writer.drain()

                    response = await asyncio.wait_for(reader.readline(), timeout=10)
                    response_str = response.decode("utf-8", errors="replace")
                    assert "HTTP/1.1" in response_str
                    assert any(code in response_str for code in ["200", "502", "400"])

                finally:
                    writer.close()
                    await writer.wait_closed()
            finally:
                await forwarder.stop()

        asyncio.run(_test())


# ---------------------------------------------------------------------------
# Rule integration
# ---------------------------------------------------------------------------

class TestRuleIntegration:
    def test_rules_applied(self) -> None:
        config = _make_config(
            port=0,
            rules=[
                Rule(name="block", outbound="direct", match=MatchCondition(port=[80])),
                Rule(name="allow", outbound="direct", match=MatchCondition(port=[443])),
                Rule(name="default", outbound="direct", match=MatchCondition()),
            ],
        )
        forwarder = Forwarder(config=config)

        conn = ConnectionInfo(dst_host="example.com", dst_port=80)
        result = forwarder.rule_engine.evaluate_rules(conn)
        assert result is not None
        assert result[0] == "block"

        conn2 = ConnectionInfo(dst_host="example.com", dst_port=443)
        result2 = forwarder.rule_engine.evaluate_rules(conn2)
        assert result2 is not None
        assert result2[0] == "allow"


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class TestForwarderStats:
    def test_initial_stats(self) -> None:
        stats = ForwarderStats()
        assert stats.total_connections == 0
        assert stats.active_connections == 0
        assert stats.bytes_sent == 0
        assert stats.uptime_seconds == 0.0

    def test_connection_counted(self) -> None:
        async def _test() -> None:
            config = _make_config(port=0)
            forwarder = Forwarder(config=config)
            await forwarder.start()

            server = forwarder._server
            assert server is not None
            sockets = server.sockets
            assert sockets is not None
            port = sockets[0].getsockname()[1]

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port),
                timeout=5,
            )
            writer.close()
            await writer.wait_closed()

            # Give time for the handler to process
            await asyncio.sleep(0.2)

            assert forwarder.stats.total_connections >= 1

            await forwarder.stop()

        asyncio.run(_test())
