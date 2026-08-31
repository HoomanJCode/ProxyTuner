"""Local proxy forwarder.

Accepts SOCKS5 and HTTP CONNECT connections on a local port,
evaluates rules against the target, and forwards through the
appropriate outbound.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import struct
import time
from asyncio import CancelledError, InvalidStateError
from dataclasses import dataclass, field

from proxy_tuner.config import Config
from proxy_tuner.dns import DnsResolver
from proxy_tuner.outbounds import OutboundError, OutboundManager
from proxy_tuner.pool import ConnectionPool
from proxy_tuner.rules import ConnectionInfo, RuleEngine
from proxy_tuner.socks5 import (
    SOCKS5_ATYP_DOMAIN,
    SOCKS5_ATYP_IPV4,
    SOCKS5_ATYP_IPV6,
    SOCKS5_CMD_CONNECT,
    SOCKS5_REP_CONNECTION_REFUSED,
    SOCKS5_REP_GENERAL_FAILURE,
    SOCKS5_REP_HOST_UNREACHABLE,
    SOCKS5_REP_NET_UNREACHABLE,
    SOCKS5_REP_SUCCESS,
    SOCKS5_VERSION,
)

logger = logging.getLogger("proxy_tuner.forwarder")


class ForwarderError(Exception):
    """Forwarder error."""


@dataclass
class ForwarderStats:
    """Global forwarding statistics."""

    total_connections: int = 0
    active_connections: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    errors: int = 0
    started_at: float | None = None

    @property
    def uptime_seconds(self) -> float:
        if self.started_at is None:
            return 0.0
        return time.time() - self.started_at


@dataclass
class Forwarder:
    """Local proxy forwarder.

    Listens on a local port for SOCKS5 and HTTP CONNECT connections,
    resolves the target, evaluates rules, and forwards through the
    appropriate outbound.
    """

    config: Config = field(default_factory=Config)
    rule_engine: RuleEngine = field(default_factory=lambda: RuleEngine(Config()))
    outbound_manager: OutboundManager = field(default_factory=OutboundManager)
    pool: ConnectionPool = field(default_factory=ConnectionPool)
    dns: DnsResolver = field(default_factory=DnsResolver)
    stats: ForwarderStats = field(default_factory=ForwarderStats)
    _server: asyncio.Server | None = None
    _running: bool = False

    def __post_init__(self) -> None:
        self.rule_engine = RuleEngine(self.config)
        dns_srv = self.config.settings.dns_server
        dns_on = self.config.settings.dns_intercept
        self.dns = DnsResolver(dns_server=dns_srv if dns_on else None)
        self.outbound_manager = OutboundManager(config=self.config)

    def update_config(self, config: Config) -> None:
        """Update config and rebuild engines."""
        self.config = config
        self.rule_engine.update(config)
        self.outbound_manager.update(config)
        self.dns = DnsResolver(
            dns_server=config.settings.dns_server if config.settings.dns_intercept else None
        )

    async def start(self) -> None:
        """Start listening for connections."""
        host = "127.0.0.1"
        port = self.config.settings.listen_port

        self._server = await asyncio.start_server(
            self._handle_connection,
            host,
            port,
        )
        self._running = True
        self.stats.started_at = time.time()
        self.pool.start_cleanup()
        logger.info("Forwarder listening on %s:%d", host, port)

    async def stop(self) -> None:
        """Stop accepting new connections and clean up."""
        self._running = False
        self.pool.stop_cleanup()
        await self.pool.close_all()
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        logger.info("Forwarder stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    async def _handle_connection(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        """Handle an incoming client connection.

        Detects whether it's a SOCKS5 or HTTP request and dispatches.
        """
        self.stats.total_connections += 1
        self.stats.active_connections += 1
        addr = client_writer.get_extra_info("peername")
        logger.debug("New connection from %s", addr)

        try:
            # Read first byte to determine protocol (SOCKS5 starts with 0x05)
            first_byte = await asyncio.wait_for(client_reader.readexactly(1), timeout=30)
            if not first_byte:
                return

            if first_byte[0] == SOCKS5_VERSION:
                await self._handle_socks5(client_reader, client_writer, first_byte)
            else:
                await self._handle_http(client_reader, client_writer, first_byte)

        except asyncio.TimeoutError:
            logger.debug("Connection from %s timed out", addr)
        except (ConnectionResetError, BrokenPipeError):
            logger.debug("Connection from %s reset", addr)
        except Exception as e:
            # Python 3.14 asyncio can raise InvalidStateError when a read
            # future is cancelled during connection teardown.
            if "is not set" in str(e):
                logger.debug("Connection from %s closed during read (Python 3.14 asyncio)", addr)
            else:
                logger.error("Error handling connection from %s: %s", addr, e)
                self.stats.errors += 1
        finally:
            self.stats.active_connections -= 1
            client_writer.close()
            with contextlib.suppress(Exception):
                await client_writer.wait_closed()

    async def _handle_socks5(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        first_byte: bytes = b"",
    ) -> None:
        """Handle a SOCKS5 connection."""
        # first_byte already read is the version byte (0x05)
        version = first_byte[0]
        if version != SOCKS5_VERSION:
            logger.warning("Invalid SOCKS5 version: %d", version)
            return

        # Read number of auth methods
        nmethods_data = await asyncio.wait_for(client_reader.readexactly(1), timeout=30)
        nmethods = nmethods_data[0]

        # Read auth methods
        await asyncio.wait_for(client_reader.readexactly(nmethods), timeout=30)

        # Reply: no auth required (we handle auth at outbound level)
        client_writer.write(struct.pack("!BB", SOCKS5_VERSION, 0x00))
        await client_writer.drain()

        # Read CONNECT request
        request = await asyncio.wait_for(client_reader.readexactly(4), timeout=30)
        ver, cmd, rsv, atyp = struct.unpack("!BBBB", request)

        if ver != SOCKS5_VERSION or cmd != SOCKS5_CMD_CONNECT:
            # Send error
            error_reply = struct.pack(
                "!BBBB", SOCKS5_VERSION, 0x07, 0x00, 0x01
            ) + b"\x00" * 6
            client_writer.write(error_reply)
            await client_writer.drain()
            return

        # Parse target address
        target_host, target_port = await self._read_socks5_address(client_reader, atyp)

        if not target_host or target_port == 0:
            logger.warning("Invalid SOCKS5 target: %s:%d", target_host, target_port)
            return

        logger.info("SOCKS5 CONNECT %s:%d", target_host, target_port)

        # Forward through outbound
        await self._forward_to_outbound(
            client_reader,
            client_writer,
            target_host,
            target_port,
            is_socks5=True,
        )

    async def _read_socks5_address(
        self,
        reader: asyncio.StreamReader,
        atyp: int,
    ) -> tuple[str, int]:
        """Read the target address from a SOCKS5 request."""
        import ipaddress

        if atyp == SOCKS5_ATYP_IPV4:
            data = await asyncio.wait_for(reader.readexactly(6), timeout=30)
            ip_bytes = data[:4]
            port = struct.unpack("!H", data[4:6])[0]
            host = str(ipaddress.IPv4Address(ip_bytes))
            return host, port

        elif atyp == SOCKS5_ATYP_DOMAIN:
            len_data = await asyncio.wait_for(reader.readexactly(1), timeout=30)
            domain_len = struct.unpack("!B", len_data)[0]
            domain_data = await asyncio.wait_for(reader.readexactly(domain_len + 2), timeout=30)
            host = domain_data[:domain_len].decode("ascii")
            port = struct.unpack("!H", domain_data[domain_len:domain_len + 2])[0]
            return host, port

        elif atyp == SOCKS5_ATYP_IPV6:
            data = await asyncio.wait_for(reader.readexactly(18), timeout=30)
            ip_bytes = data[:16]
            port = struct.unpack("!H", data[16:18])[0]
            host = str(ipaddress.IPv6Address(ip_bytes))
            return host, port

        else:
            raise ForwarderError(f"Unknown SOCKS5 address type: {atyp}")

    async def _handle_http(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        first_byte: bytes = b"",
    ) -> None:
        """Handle an HTTP CONNECT request."""
        # first_byte is not part of the HTTP request line (it was the protocol detection byte)
        # We need to prepend it to reconstruct the request line
        rest_of_line = await asyncio.wait_for(client_reader.readline(), timeout=30)
        request_line = (first_byte + rest_of_line).decode("utf-8", errors="replace").strip()

        parts = request_line.split(" ")
        if len(parts) < 3:
            logger.warning("Invalid HTTP request: %s", request_line)
            client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await client_writer.drain()
            return

        method = parts[0].upper()
        target = parts[1]

        if method != "CONNECT":
            logger.warning("Unsupported HTTP method: %s", method)
            client_writer.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            await client_writer.drain()
            return

        # Parse CONNECT target (host:port)
        if ":" in target:
            host, port_str = target.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await client_writer.drain()
                return
        else:
            host = target
            port = 80

        # Read remaining headers until empty line
        while True:
            header = await asyncio.wait_for(client_reader.readline(), timeout=30)
            if header == b"\r\n" or header == b"\n" or header == b"":
                break

        logger.info("HTTP CONNECT %s:%d", host, port)

        # Forward through outbound
        await self._forward_to_outbound(
            client_reader,
            client_writer,
            host,
            port,
            is_socks5=False,
        )

    async def _forward_to_outbound(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        target_host: str,
        target_port: int,
        is_socks5: bool,
    ) -> None:
        """Forward a connection through the resolved outbound."""
        # Build connection info for rule engine
        conn = ConnectionInfo(
            dst_ip=target_host,
            dst_port=target_port,
            dst_host=target_host,  # Use hostname for domain matching
        )

        # Resolve outbound via rule engine
        outbound_name = self.rule_engine.evaluate(conn)

        if outbound_name is None:
            logger.warning("No rule matched for %s:%d", target_host, target_port)
            if is_socks5:
                await self._send_socks5_error(client_writer, SOCKS5_REP_GENERAL_FAILURE)
            else:
                client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await client_writer.drain()
            return

        try:
            # Connect through outbound
            remote_reader, remote_writer = await self.outbound_manager.connect(
                outbound_name, target_host, target_port
            )

            # Send success response
            if is_socks5:
                # SOCKS5 success reply
                client_writer.write(
                    struct.pack("!BBBB", SOCKS5_VERSION, SOCKS5_REP_SUCCESS, 0x00, 0x01)
                    + b"\x00\x00\x00\x00"  # bound addr (0.0.0.0)
                    + struct.pack("!H", 0)  # bound port
                )
                await client_writer.drain()
            else:
                # HTTP 200 Connection Established
                client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await client_writer.drain()

            # Bidirectional data relay
            await self._relay(
                client_reader, client_writer,
                remote_reader, remote_writer, outbound_name,
            )

        except OutboundError as e:
            logger.error("Outbound error for %s:%d: %s", target_host, target_port, e)
            if is_socks5:
                # Map error to SOCKS5 reply
                err_code = SOCKS5_REP_CONNECTION_REFUSED
                if "unreachable" in str(e).lower():
                    err_code = SOCKS5_REP_NET_UNREACHABLE
                elif "refused" in str(e).lower():
                    err_code = SOCKS5_REP_HOST_UNREACHABLE
                await self._send_socks5_error(client_writer, err_code)
            else:
                client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await client_writer.drain()
            self.stats.errors += 1

    async def _send_socks5_error(
        self,
        writer: asyncio.StreamWriter,
        error_code: int,
    ) -> None:
        """Send a SOCKS5 error reply."""
        writer.write(
            struct.pack("!BBBB", SOCKS5_VERSION, error_code, 0x00, 0x01)
            + b"\x00\x00\x00\x00"
            + struct.pack("!H", 0)
        )
        await writer.drain()

    async def _relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        remote_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
        outbound_name: str,
    ) -> None:
        """Bidirectional data relay between client and remote."""

        async def pipe(
            src: asyncio.StreamReader,
            dst: asyncio.StreamWriter,
            direction: str,
        ) -> int:
            """Pipe data from src to dst. Returns bytes transferred."""
            total = 0
            try:
                while True:
                    data = await src.read(8192)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
                    total += len(data)
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass
            return total

        try:
            # Run both pipes concurrently
            to_remote = asyncio.create_task(
                pipe(client_reader, remote_writer, "client->remote")
            )
            to_client = asyncio.create_task(
                pipe(remote_reader, client_writer, "remote->client")
            )

            # Wait for one direction to finish
            done, pending = await asyncio.wait(
                [to_remote, to_client],
                return_when=asyncio.FIRST_COMPLETED,
            )

            # Cancel the other direction
            for task in pending:
                task.cancel()

            # Collect stats — must handle InvalidStateError from
            # Python 3.14 asyncio where cancelled futures may not be set.
            def _safe_result(t: asyncio.Task) -> int:
                try:
                    if t.cancelled():
                        return 0
                    if not t.done():
                        return 0
                    return t.result()
                except (InvalidStateError, RuntimeError, CancelledError):
                    return 0

            # Give cancelled tasks a moment to finalize
            await asyncio.sleep(0)

            sent = _safe_result(to_remote)
            received = _safe_result(to_client)
            stats = self.outbound_manager.get_stats(outbound_name)
            stats.record_bytes(sent, received)
            self.stats.bytes_sent += sent
            self.stats.bytes_received += received

        finally:
            remote_writer.close()
            with contextlib.suppress(Exception):
                await remote_writer.wait_closed()
