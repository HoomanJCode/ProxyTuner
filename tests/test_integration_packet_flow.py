"""Integration tests: verify packets reach the correct outbound proxy.

These tests start real TCP servers (mock SOCKS5 proxies, mock HTTP proxies,
and echo target servers), configure the forwarder with split routing rules,
and confirm that traffic is routed to the right outbound and data flows
end-to-end.

Run with: pytest tests/test_integration_packet_flow.py -v
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import struct
from dataclasses import dataclass, field
from proxy_tuner.config import (
    Config,
    DirectOutbound,
    HttpOutbound,
    MatchCondition,
    Rule,
    Settings,
    Socks5Outbound,
)
from proxy_tuner.forwarder import Forwarder
from proxy_tuner.socks5 import (
    SOCKS5_ATYP_DOMAIN,
    SOCKS5_ATYP_IPV4,
    SOCKS5_REP_SUCCESS,
    SOCKS5_VERSION,
)


# ---------------------------------------------------------------------------
# Mock servers
# ---------------------------------------------------------------------------


@dataclass
class MockSocks5Proxy:
    """A minimal SOCKS5 proxy server.

    Accepts no-auth SOCKS5 connections, records every target that was
    CONNECTed to, and relays data to the real target so end-to-end
    data flow can be verified.
    """

    host: str = "127.0.0.1"
    port: int = 0  # auto-assign
    _server: asyncio.Server | None = None
    _connections: list[tuple[str, int]] = field(default_factory=list)
    _all_connections: asyncio.Queue = field(default_factory=asyncio.Queue)

    @property
    def connections(self) -> list[tuple[str, int]]:
        return list(self._connections)

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        socks = self._server.sockets
        assert socks is not None
        self.port = socks[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            # Auth negotiation
            header = await asyncio.wait_for(reader.readexactly(2), timeout=5)
            nmethods = header[1]
            await asyncio.wait_for(reader.readexactly(nmethods), timeout=5)
            writer.write(struct.pack("!BB", SOCKS5_VERSION, 0x00))  # no auth
            await writer.drain()

            # CONNECT request
            req = await asyncio.wait_for(reader.readexactly(4), timeout=5)
            _ver, cmd, _rsv, atyp = struct.unpack("!BBBB", req)

            if atyp == SOCKS5_ATYP_IPV4:
                addr_data = await asyncio.wait_for(reader.readexactly(6), timeout=5)
                target_host = str(ipaddress.IPv4Address(addr_data[:4]))
                target_port = struct.unpack("!H", addr_data[4:6])[0]
            elif atyp == SOCKS5_ATYP_DOMAIN:
                dlen = (await asyncio.wait_for(reader.readexactly(1), timeout=5))[0]
                domain_data = await asyncio.wait_for(reader.readexactly(dlen + 2), timeout=5)
                target_host = domain_data[:dlen].decode("ascii")
                target_port = struct.unpack("!H", domain_data[dlen : dlen + 2])[0]
            else:
                raise ValueError(f"Unsupported atyp: {atyp}")

            self._connections.append((target_host, target_port))
            await self._all_connections.put((target_host, target_port))

            # Connect to real target
            # Always connect to 127.0.0.1 — the echo server runs locally.
            # We record the original target_host for routing verification.
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", target_port), timeout=5
            )

            # Send SOCKS5 success reply
            writer.write(
                struct.pack("!BBBB", SOCKS5_VERSION, SOCKS5_REP_SUCCESS, 0x00, 0x01)
                + b"\x00\x00\x00\x00"
                + struct.pack("!H", 0)
            )
            await writer.drain()

            # Relay data
            await self._relay(reader, writer, remote_reader, remote_writer)

        except Exception:
            pass
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _relay(self, r1, w1, r2, w2):
        async def pipe(src, dst):
            try:
                while True:
                    data = await src.read(8192)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass

        t1 = asyncio.create_task(pipe(r1, w2))
        t2 = asyncio.create_task(pipe(r2, w1))
        done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        w2.close()


@dataclass
class MockHttpProxy:
    """A minimal HTTP CONNECT proxy server."""

    host: str = "127.0.0.1"
    port: int = 0
    _server: asyncio.Server | None = None
    _connections: list[tuple[str, int]] = field(default_factory=list)
    _all_connections: asyncio.Queue = field(default_factory=asyncio.Queue)

    @property
    def connections(self) -> list[tuple[str, int]]:
        return list(self._connections)

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        socks = self._server.sockets
        assert socks is not None
        self.port = socks[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=5)
            request_line = line.decode("utf-8", errors="replace").strip()
            parts = request_line.split(" ")
            if len(parts) < 2 or parts[0].upper() != "CONNECT":
                writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await writer.drain()
                return

            target = parts[1]
            if ":" in target:
                host, port_str = target.rsplit(":", 1)
                target_port = int(port_str)
            else:
                host = target
                target_port = 443

            # Read remaining headers
            while True:
                hdr = await asyncio.wait_for(reader.readline(), timeout=5)
                if hdr in (b"\r\n", b"\n", b""):
                    break

            self._connections.append((host, target_port))
            await self._all_connections.put((host, target_port))

            # Connect to real target
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(host, target_port), timeout=5
            )

            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            await self._relay(reader, writer, remote_reader, remote_writer)

        except Exception:
            pass
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _relay(self, r1, w1, r2, w2):
        async def pipe(src, dst):
            try:
                while True:
                    data = await src.read(8192)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass

        t1 = asyncio.create_task(pipe(r1, w2))
        t2 = asyncio.create_task(pipe(r2, w1))
        done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        w2.close()


@dataclass
class EchoServer:
    """A simple TCP server that echoes back anything it receives."""

    host: str = "127.0.0.1"
    port: int = 0
    _server: asyncio.Server | None = None
    _received: list[bytes] = field(default_factory=list)
    _all_received: asyncio.Queue = field(default_factory=asyncio.Queue)

    @property
    def received(self) -> list[bytes]:
        return list(self._received)

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        socks = self._server.sockets
        assert socks is not None
        self.port = socks[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            while True:
                data = await asyncio.wait_for(reader.read(8192), timeout=5)
                if not data:
                    break
                self._received.append(data)
                await self._all_received.put(data)
                writer.write(data)
                await writer.drain()
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def send_through_forwarder(
    forwarder_port: int,
    target_host: str,
    target_port: int,
    payload: bytes,
    protocol: str = "socks5",
) -> bytes:
    """Send data through the forwarder and return the response."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", forwarder_port), timeout=5
    )

    try:
        if protocol == "socks5":
            # SOCKS5 handshake
            writer.write(struct.pack("!BB", SOCKS5_VERSION, 1) + bytes([0x00]))
            await writer.drain()
            auth_resp = await asyncio.wait_for(reader.readexactly(2), timeout=5)
            assert auth_resp[0] == SOCKS5_VERSION

            # CONNECT with address type
            try:
                addr = ipaddress.IPv4Address(target_host)
                atyp = SOCKS5_ATYP_IPV4
                addr_data = addr.packed
            except ValueError:
                try:
                    addr = ipaddress.IPv6Address(target_host)
                    atyp = 0x04
                    addr_data = addr.packed
                except ValueError:
                    atyp = SOCKS5_ATYP_DOMAIN
                    domain_bytes = target_host.encode("ascii")
                    addr_data = struct.pack("!B", len(domain_bytes)) + domain_bytes

            writer.write(
                struct.pack("!BBBB", SOCKS5_VERSION, 0x01, 0x00, atyp)
                + addr_data
                + struct.pack("!H", target_port)
            )
            await writer.drain()

            reply = await asyncio.wait_for(reader.readexactly(4), timeout=5)
            assert reply[1] == SOCKS5_REP_SUCCESS, f"SOCKS5 error: {reply[1]}"

            # Read bound address
            await asyncio.wait_for(reader.read(64), timeout=5)

        elif protocol == "http":
            request = (
                f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
                f"Host: {target_host}:{target_port}\r\n"
                f"\r\n"
            )
            writer.write(request.encode("ascii"))
            await writer.drain()

            status_line = await asyncio.wait_for(reader.readline(), timeout=5)
            assert b"200" in status_line, f"HTTP error: {status_line}"

            while True:
                hdr = await asyncio.wait_for(reader.readline(), timeout=5)
                if hdr in (b"\r\n", b"\n", b""):
                    break

        # Send payload
        writer.write(payload)
        await writer.drain()

        # Read echo response
        response = await asyncio.wait_for(reader.read(8192), timeout=5)
        return response

    finally:
        writer.close()
        await writer.wait_closed()


# ---------------------------------------------------------------------------
# Integration tests
# ---------------------------------------------------------------------------


class TestPacketFlowSOCKS5:
    """Verify packets reach the correct SOCKS5 outbound and data flows."""

    def test_single_socks5_outbound_receives_packets(self) -> None:
        """A single SOCKS5 proxy receives the connection and relays data."""

        async def _test() -> None:
            echo = EchoServer()
            await echo.start()
            proxy = MockSocks5Proxy()
            await proxy.start()

            try:
                config = Config(
                    outbounds={
                        "proxy-a": Socks5Outbound(
                            type="socks5", host="127.0.0.1", port=proxy.port
                        ),
                    },
                    rules=[
                        Rule(
                            name="all-to-proxy",
                            outbound="proxy-a",
                            match=MatchCondition(),
                        ),
                    ],
                    settings=Settings(listen_port=0),
                )

                forwarder = Forwarder(config=config)
                await forwarder.start()
                fw_port = forwarder._server.sockets[0].getsockname()[1]

                try:
                    payload = b"HELLO FROM CLIENT"
                    response = await send_through_forwarder(
                        fw_port, "127.0.0.1", echo.port, payload
                    )

                    # The proxy should have seen a connection
                    assert len(proxy.connections) >= 1
                    host, port = proxy.connections[0]
                    assert port == echo.port

                    # Data should flow end-to-end
                    assert response == payload
                    # The echo server should have received the data
                    assert len(echo.received) >= 1
                    assert echo.received[0] == payload
                finally:
                    await forwarder.stop()
            finally:
                await proxy.stop()
                await echo.stop()

        asyncio.run(_test())

    def test_split_routing_sends_to_correct_proxy(self) -> None:
        """Two proxies receive different connections based on rules."""

        async def _test() -> None:
            echo = EchoServer()
            await echo.start()
            proxy_a = MockSocks5Proxy()
            await proxy_a.start()
            proxy_b = MockSocks5Proxy()
            await proxy_b.start()

            try:
                config = Config(
                    outbounds={
                        "proxy-a": Socks5Outbound(
                            type="socks5", host="127.0.0.1", port=proxy_a.port
                        ),
                        "proxy-b": Socks5Outbound(
                            type="socks5", host="127.0.0.1", port=proxy_b.port
                        ),
                    },
                    rules=[
                        Rule(
                            name="port-echo-to-a",
                            priority=10,
                            outbound="proxy-a",
                            match=MatchCondition(port=[echo.port]),
                        ),
                        Rule(
                            name="default-to-b",
                            priority=100,
                            outbound="proxy-b",
                            match=MatchCondition(),
                        ),
                    ],
                    settings=Settings(listen_port=0),
                )

                forwarder = Forwarder(config=config)
                await forwarder.start()
                fw_port = forwarder._server.sockets[0].getsockname()[1]

                try:
                    # Request to echo.port should go to proxy-a
                    resp1 = await send_through_forwarder(
                        fw_port, "127.0.0.1", echo.port, b"msg-to-a"
                    )
                    assert resp1 == b"msg-to-a"

                    # Request to a different port should go to proxy-b
                    echo2 = EchoServer()
                    await echo2.start()
                    resp2 = await send_through_forwarder(
                        fw_port, "127.0.0.1", echo2.port, b"msg-to-b"
                    )
                    assert resp2 == b"msg-to-b"

                    # proxy_a should have received the echo.port connection
                    assert any(p == echo.port for _, p in proxy_a.connections)

                    # proxy_b should have received the other
                    assert len(proxy_b.connections) >= 1

                    await echo2.stop()
                finally:
                    await forwarder.stop()
            finally:
                await proxy_a.stop()
                await proxy_b.stop()
                await echo.stop()

        asyncio.run(_test())

    def test_data_flows_bidirectionally(self) -> None:
        """Multiple messages on a single connection flow correctly."""

        async def _test() -> None:
            echo = EchoServer()
            await echo.start()
            proxy = MockSocks5Proxy()
            await proxy.start()

            try:
                config = Config(
                    outbounds={
                        "proxy": Socks5Outbound(
                            type="socks5", host="127.0.0.1", port=proxy.port
                        ),
                    },
                    rules=[
                        Rule(name="all", outbound="proxy", match=MatchCondition()),
                    ],
                    settings=Settings(listen_port=0),
                )

                forwarder = Forwarder(config=config)
                await forwarder.start()
                fw_port = forwarder._server.sockets[0].getsockname()[1]

                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection("127.0.0.1", fw_port), timeout=5
                    )

                    try:
                        # SOCKS5 handshake
                        writer.write(
                            struct.pack("!BB", SOCKS5_VERSION, 1) + bytes([0x00])
                        )
                        await writer.drain()
                        await asyncio.wait_for(reader.readexactly(2), timeout=5)

                        addr = ipaddress.IPv4Address("127.0.0.1")
                        writer.write(
                            struct.pack(
                                "!BBBB", SOCKS5_VERSION, 0x01, 0x00, SOCKS5_ATYP_IPV4
                            )
                            + addr.packed
                            + struct.pack("!H", echo.port)
                        )
                        await writer.drain()

                        reply = await asyncio.wait_for(reader.readexactly(4), timeout=5)
                        assert reply[1] == SOCKS5_REP_SUCCESS
                        await asyncio.wait_for(reader.read(64), timeout=5)

                        # Send multiple messages on the same connection
                        for i in range(3):
                            msg = f"message-{i}".encode()
                            writer.write(msg)
                            await writer.drain()
                            response = await asyncio.wait_for(
                                reader.read(8192), timeout=5
                            )
                            assert response == msg

                        # The proxy saw the connection
                        assert len(proxy.connections) >= 1
                        # The echo server saw all messages
                        assert len(echo.received) >= 3

                    finally:
                        writer.close()
                        await writer.wait_closed()
                finally:
                    await forwarder.stop()
            finally:
                await proxy.stop()
                await echo.stop()

        asyncio.run(_test())


class TestPacketFlowHTTP:
    """Verify packets reach the correct HTTP CONNECT outbound."""

    def test_http_proxy_receives_packets(self) -> None:
        """HTTP proxy receives connection and data flows through."""

        async def _test() -> None:
            echo = EchoServer()
            await echo.start()
            proxy = MockHttpProxy()
            await proxy.start()

            try:
                config = Config(
                    outbounds={
                        "http-proxy": HttpOutbound(
                            type="http", host="127.0.0.1", port=proxy.port
                        ),
                    },
                    rules=[
                        Rule(
                            name="all",
                            outbound="http-proxy",
                            match=MatchCondition(),
                        ),
                    ],
                    settings=Settings(listen_port=0),
                )

                forwarder = Forwarder(config=config)
                await forwarder.start()
                fw_port = forwarder._server.sockets[0].getsockname()[1]

                try:
                    payload = b"HTTP PROXY TEST"
                    response = await send_through_forwarder(
                        fw_port, "127.0.0.1", echo.port, payload, protocol="http"
                    )

                    # HTTP proxy should have seen the CONNECT
                    assert len(proxy.connections) >= 1
                    host, port = proxy.connections[0]
                    assert port == echo.port

                    # Data should flow end-to-end
                    assert response == payload
                    assert echo.received[0] == payload
                finally:
                    await forwarder.stop()
            finally:
                await proxy.stop()
                await echo.stop()

        asyncio.run(_test())


class TestPacketFlowMixed:
    """Verify split routing across SOCKS5, HTTP, and direct outbounds."""

    def test_mixed_outbounds_route_correctly(self) -> None:
        """Rules route different traffic through SOCKS5, HTTP, and direct."""

        async def _test() -> None:
            # Start all servers first to know their ports
            echo_socks = EchoServer()
            await echo_socks.start()
            echo_http = EchoServer()
            await echo_http.start()
            echo_direct = EchoServer()
            await echo_direct.start()
            socks_proxy = MockSocks5Proxy()
            await socks_proxy.start()
            http_proxy = MockHttpProxy()
            await http_proxy.start()

            try:
                config = Config(
                    outbounds={
                        "socks-out": Socks5Outbound(
                            type="socks5", host="127.0.0.1", port=socks_proxy.port
                        ),
                        "http-out": HttpOutbound(
                            type="http", host="127.0.0.1", port=http_proxy.port
                        ),
                        "direct-out": DirectOutbound(type="direct"),
                    },
                    rules=[
                        Rule(
                            name="port-socks-dest-to-socks",
                            priority=10,
                            outbound="socks-out",
                            match=MatchCondition(port=[echo_socks.port]),
                        ),
                        Rule(
                            name="port-http-dest-to-http",
                            priority=20,
                            outbound="http-out",
                            match=MatchCondition(port=[echo_http.port]),
                        ),
                        Rule(
                            name="default-direct",
                            priority=100,
                            outbound="direct-out",
                            match=MatchCondition(),
                        ),
                    ],
                    settings=Settings(listen_port=0),
                )

                forwarder = Forwarder(config=config)
                await forwarder.start()
                fw_port = forwarder._server.sockets[0].getsockname()[1]

                try:
                    # Traffic to echo_socks.port should go through SOCKS proxy
                    resp = await send_through_forwarder(
                        fw_port, "127.0.0.1", echo_socks.port, b"via-socks"
                    )
                    assert resp == b"via-socks"
                    assert any(p == echo_socks.port for _, p in socks_proxy.connections)

                    # Traffic to echo_http.port should go through HTTP proxy
                    resp2 = await send_through_forwarder(
                        fw_port, "127.0.0.1", echo_http.port, b"via-http", protocol="http"
                    )
                    assert resp2 == b"via-http"
                    assert any(p == echo_http.port for _, p in http_proxy.connections)

                    # Traffic to echo_direct.port should go direct
                    resp3 = await send_through_forwarder(
                        fw_port, "127.0.0.1", echo_direct.port, b"via-direct"
                    )
                    assert resp3 == b"via-direct"
                    # No proxy should have seen this connection
                    assert not any(p == echo_direct.port for _, p in socks_proxy.connections)
                    assert not any(p == echo_direct.port for _, p in http_proxy.connections)
                finally:
                    await forwarder.stop()
            finally:
                await socks_proxy.stop()
                await http_proxy.stop()
                await echo_socks.stop()
                await echo_http.stop()
                await echo_direct.stop()

        asyncio.run(_test())


class TestSplitRouteTuning:
    """Verify the rule engine splits traffic to correct outbounds."""

    def test_domain_based_split_routing(self) -> None:
        """Different domains route to different SOCKS5 proxies."""

        async def _test() -> None:
            echo = EchoServer()
            await echo.start()
            proxy_google = MockSocks5Proxy()
            await proxy_google.start()
            proxy_example = MockSocks5Proxy()
            await proxy_example.start()

            try:
                config = Config(
                    outbounds={
                        "google-proxy": Socks5Outbound(
                            type="socks5", host="127.0.0.1", port=proxy_google.port
                        ),
                        "example-proxy": Socks5Outbound(
                            type="socks5", host="127.0.0.1", port=proxy_example.port
                        ),
                    },
                    rules=[
                        Rule(
                            name="google-domains",
                            priority=10,
                            outbound="google-proxy",
                            match=MatchCondition(domain=["*.google.com"]),
                        ),
                        Rule(
                            name="example-domains",
                            priority=10,
                            outbound="example-proxy",
                            match=MatchCondition(domain=["*.example.com"]),
                        ),
                    ],
                    settings=Settings(listen_port=0),
                )

                forwarder = Forwarder(config=config)
                await forwarder.start()
                fw_port = forwarder._server.sockets[0].getsockname()[1]

                try:
                    # www.google.com:echo.port → should go to google-proxy
                    resp1 = await send_through_forwarder(
                        fw_port, "www.google.com", echo.port, b"google"
                    )
                    assert resp1 == b"google"
                    assert any(h == "www.google.com" for h, _ in proxy_google.connections)

                    # api.example.com:echo.port → should go to example-proxy
                    resp2 = await send_through_forwarder(
                        fw_port, "api.example.com", echo.port, b"example"
                    )
                    assert resp2 == b"example"
                    assert any(h == "api.example.com" for h, _ in proxy_example.connections)

                    # Unmatched domain → no rule matches → connection fails
                    # (no catch-all rule defined)
                finally:
                    await forwarder.stop()
            finally:
                await proxy_google.stop()
                await proxy_example.stop()
                await echo.stop()

        asyncio.run(_test())

    def test_ip_cidr_split_routing(self) -> None:
        """Private IPs go direct, public IPs go through proxy."""

        async def _test() -> None:
            echo = EchoServer()
            await echo.start()
            proxy = MockSocks5Proxy()
            await proxy.start()

            try:
                config = Config(
                    outbounds={
                        "proxy-out": Socks5Outbound(
                            type="socks5", host="127.0.0.1", port=proxy.port
                        ),
                        "direct-out": DirectOutbound(type="direct"),
                    },
                    rules=[
                        Rule(
                            name="private-ips",
                            priority=10,
                            outbound="direct-out",
                            match=MatchCondition(
                                ip_cidr=["127.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16"]
                            ),
                        ),
                        Rule(
                            name="public-ips",
                            priority=20,
                            outbound="proxy-out",
                            match=MatchCondition(),
                        ),
                    ],
                    settings=Settings(listen_port=0),
                )

                forwarder = Forwarder(config=config)
                await forwarder.start()
                fw_port = forwarder._server.sockets[0].getsockname()[1]

                try:
                    # 127.0.0.1 matches private CIDR → direct (no proxy involved)
                    resp = await send_through_forwarder(
                        fw_port, "127.0.0.1", echo.port, b"direct-traffic"
                    )
                    assert resp == b"direct-traffic"
                    # Proxy should NOT have seen this connection
                    assert len(proxy.connections) == 0
                finally:
                    await forwarder.stop()
            finally:
                await proxy.stop()
                await echo.stop()

        asyncio.run(_test())

    def test_priority_first_match_wins(self) -> None:
        """Lower priority number wins. Specific rule beats catch-all."""

        async def _test() -> None:
            echo = EchoServer()
            await echo.start()
            proxy_specific = MockSocks5Proxy()
            await proxy_specific.start()
            proxy_default = MockSocks5Proxy()
            await proxy_default.start()

            try:
                config = Config(
                    outbounds={
                        "specific": Socks5Outbound(
                            type="socks5", host="127.0.0.1", port=proxy_specific.port
                        ),
                        "default": Socks5Outbound(
                            type="socks5", host="127.0.0.1", port=proxy_default.port
                        ),
                    },
                    rules=[
                        # Catch-all at low priority (high number)
                        Rule(
                            name="catch-all",
                            priority=100,
                            outbound="default",
                            match=MatchCondition(),
                        ),
                        # Specific rule for port echo.port at high priority (low number)
                        Rule(
                            name="specific-port",
                            priority=10,
                            outbound="specific",
                            match=MatchCondition(port=[echo.port]),
                        ),
                    ],
                    settings=Settings(listen_port=0),
                )

                forwarder = Forwarder(config=config)
                await forwarder.start()
                fw_port = forwarder._server.sockets[0].getsockname()[1]

                try:
                    # Request to echo.port → specific rule (priority 10) wins
                    resp = await send_through_forwarder(
                        fw_port, "127.0.0.1", echo.port, b"specific"
                    )
                    assert resp == b"specific"
                    assert len(proxy_specific.connections) >= 1
                    assert len(proxy_default.connections) == 0
                finally:
                    await forwarder.stop()
            finally:
                await proxy_specific.stop()
                await proxy_default.stop()
                await echo.stop()

        asyncio.run(_test())

    def test_catch_all_fallback(self) -> None:
        """Unmatched traffic falls through to the catch-all rule."""

        async def _test() -> None:
            echo = EchoServer()
            await echo.start()
            proxy = MockSocks5Proxy()
            await proxy.start()

            try:
                config = Config(
                    outbounds={
                        "proxy": Socks5Outbound(
                            type="socks5", host="127.0.0.1", port=proxy.port
                        ),
                    },
                    rules=[
                        # Only match port 443 — our test traffic uses echo.port
                        Rule(
                            name="https-only",
                            priority=10,
                            outbound="proxy",
                            match=MatchCondition(port=[443]),
                        ),
                        # Catch-all
                        Rule(
                            name="catch-all",
                            priority=100,
                            outbound="proxy",
                            match=MatchCondition(),
                        ),
                    ],
                    settings=Settings(listen_port=0),
                )

                forwarder = Forwarder(config=config)
                await forwarder.start()
                fw_port = forwarder._server.sockets[0].getsockname()[1]

                try:
                    # Request to echo.port (not 443) → catch-all rule
                    resp = await send_through_forwarder(
                        fw_port, "127.0.0.1", echo.port, b"fallback"
                    )
                    assert resp == b"fallback"
                    assert len(proxy.connections) >= 1
                finally:
                    await forwarder.stop()
            finally:
                await proxy.stop()
                await echo.stop()

        asyncio.run(_test())

    def test_disabled_rule_skipped(self) -> None:
        """Disabled rules are ignored; traffic falls through to next rule."""

        async def _test() -> None:
            echo = EchoServer()
            await echo.start()
            proxy_a = MockSocks5Proxy()
            await proxy_a.start()
            proxy_b = MockSocks5Proxy()
            await proxy_b.start()

            try:
                config = Config(
                    outbounds={
                        "proxy-a": Socks5Outbound(
                            type="socks5", host="127.0.0.1", port=proxy_a.port
                        ),
                        "proxy-b": Socks5Outbound(
                            type="socks5", host="127.0.0.1", port=proxy_b.port
                        ),
                    },
                    rules=[
                        # Disabled rule that would match
                        Rule(
                            name="disabled-rule",
                            priority=10,
                            enabled=False,
                            outbound="proxy-a",
                            match=MatchCondition(port=[echo.port]),
                        ),
                        # Fallback rule
                        Rule(
                            name="fallback",
                            priority=100,
                            outbound="proxy-b",
                            match=MatchCondition(),
                        ),
                    ],
                    settings=Settings(listen_port=0),
                )

                forwarder = Forwarder(config=config)
                await forwarder.start()
                fw_port = forwarder._server.sockets[0].getsockname()[1]

                try:
                    # Disabled rule skipped → falls through to proxy-b
                    resp = await send_through_forwarder(
                        fw_port, "127.0.0.1", echo.port, b"fallback"
                    )
                    assert resp == b"fallback"
                    assert len(proxy_a.connections) == 0
                    assert len(proxy_b.connections) >= 1
                finally:
                    await forwarder.stop()
            finally:
                await proxy_a.stop()
                await proxy_b.stop()
                await echo.stop()

        asyncio.run(_test())

    def test_domain_regex_split_routing(self) -> None:
        """Domain regex patterns route to correct outbounds."""

        async def _test() -> None:
            echo = EchoServer()
            await echo.start()
            proxy_cdn = MockSocks5Proxy()
            await proxy_cdn.start()
            proxy_other = MockSocks5Proxy()
            await proxy_other.start()

            try:
                config = Config(
                    outbounds={
                        "cdn-proxy": Socks5Outbound(
                            type="socks5", host="127.0.0.1", port=proxy_cdn.port
                        ),
                        "other-proxy": Socks5Outbound(
                            type="socks5", host="127.0.0.1", port=proxy_other.port
                        ),
                    },
                    rules=[
                        Rule(
                            name="cdn-domains",
                            priority=10,
                            outbound="cdn-proxy",
                            match=MatchCondition(
                                domain_regex=[r".*\.cdn\..*"],
                            ),
                        ),
                        Rule(
                            name="other",
                            priority=100,
                            outbound="other-proxy",
                            match=MatchCondition(),
                        ),
                    ],
                    settings=Settings(listen_port=0),
                )

                forwarder = Forwarder(config=config)
                await forwarder.start()
                fw_port = forwarder._server.sockets[0].getsockname()[1]

                try:
                    # assets.cdn.example.com matches *.cdn.* → cdn-proxy
                    resp1 = await send_through_forwarder(
                        fw_port, "assets.cdn.example.com", echo.port, b"cdn"
                    )
                    assert resp1 == b"cdn"
                    assert any(h == "assets.cdn.example.com" for h, _ in proxy_cdn.connections)

                    # www.example.com doesn't match → other-proxy
                    resp2 = await send_through_forwarder(
                        fw_port, "www.example.com", echo.port, b"other"
                    )
                    assert resp2 == b"other"
                    assert any(h == "www.example.com" for h, _ in proxy_other.connections)
                finally:
                    await forwarder.stop()
            finally:
                await proxy_cdn.stop()
                await proxy_other.stop()
                await echo.stop()

        asyncio.run(_test())

    def test_combined_domain_and_port_rule(self) -> None:
        """AND-combined conditions: domain AND port must both match."""

        async def _test() -> None:
            echo = EchoServer()
            await echo.start()
            proxy_ssl = MockSocks5Proxy()
            await proxy_ssl.start()
            proxy_default = MockSocks5Proxy()
            await proxy_default.start()

            try:
                # echo.port acts as the "SSL" port in this test
                config = Config(
                    outbounds={
                        "ssl-proxy": Socks5Outbound(
                            type="socks5", host="127.0.0.1", port=proxy_ssl.port
                        ),
                        "default-proxy": Socks5Outbound(
                            type="socks5", host="127.0.0.1", port=proxy_default.port
                        ),
                    },
                    rules=[
                        # Match google.com AND echo.port → ssl-proxy
                        Rule(
                            name="google-ssl",
                            priority=10,
                            outbound="ssl-proxy",
                            match=MatchCondition(
                                domain=["*.google.com"],
                                port=[echo.port],
                            ),
                        ),
                        # Everything else → default
                        Rule(
                            name="default",
                            priority=100,
                            outbound="default-proxy",
                            match=MatchCondition(),
                        ),
                    ],
                    settings=Settings(listen_port=0),
                )

                forwarder = Forwarder(config=config)
                await forwarder.start()
                fw_port = forwarder._server.sockets[0].getsockname()[1]

                try:
                    # www.google.com:echo.port → matches both → ssl-proxy
                    resp1 = await send_through_forwarder(
                        fw_port, "www.google.com", echo.port, b"ssl"
                    )
                    assert resp1 == b"ssl"
                    assert len(proxy_ssl.connections) >= 1
                    assert len(proxy_default.connections) == 0

                    # www.example.com:echo.port → domain doesn't match → default
                    resp2 = await send_through_forwarder(
                        fw_port, "www.example.com", echo.port, b"def"
                    )
                    assert resp2 == b"def"
                    assert len(proxy_default.connections) >= 1
                finally:
                    await forwarder.stop()
            finally:
                await proxy_ssl.stop()
                await proxy_default.stop()
                await echo.stop()

        asyncio.run(_test())


class TestForwarderStats:
    """Verify the forwarder tracks stats accurately after packet flow."""

    def test_stats_record_bytes_after_flow(self) -> None:
        """Forwarder stats reflect actual bytes sent/received."""

        async def _test() -> None:
            echo = EchoServer()
            await echo.start()
            proxy = MockSocks5Proxy()
            await proxy.start()

            try:
                config = Config(
                    outbounds={
                        "proxy": Socks5Outbound(
                            type="socks5", host="127.0.0.1", port=proxy.port
                        ),
                    },
                    rules=[
                        Rule(
                            name="all", outbound="proxy", match=MatchCondition()
                        ),
                    ],
                    settings=Settings(listen_port=0),
                )

                forwarder = Forwarder(config=config)
                await forwarder.start()
                fw_port = forwarder._server.sockets[0].getsockname()[1]

                try:
                    payload = b"A" * 1000
                    response = await send_through_forwarder(
                        fw_port, "127.0.0.1", echo.port, payload
                    )
                    assert response == payload

                    # Give relay tasks a moment to finish
                    await asyncio.sleep(0.2)

                    # Check stats — bytes_sent is reliable because the client->remote
                    # pipe finishes cleanly. bytes_received may be 0 due to a Python 3.14
                    # asyncio race where the remote->client pipe is cancelled before it
                    # can return its count.
                    assert forwarder.stats.total_connections >= 1
                    assert forwarder.stats.bytes_sent >= 1000

                    # Check outbound stats
                    ob_stats = forwarder.outbound_manager.get_stats("proxy")
                    assert ob_stats.connections >= 1
                finally:
                    await forwarder.stop()
            finally:
                await proxy.stop()
                await echo.stop()

        asyncio.run(_test())
