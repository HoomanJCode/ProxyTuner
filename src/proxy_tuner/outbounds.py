"""Outbound connection manager.

Manages connections to upstream proxies (SOCKS5, HTTP CONNECT, direct).
Provides a unified interface for the forwarder to establish proxied connections.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import NamedTuple

from proxy_tuner.config import Config, DirectOutbound, HttpOutbound, Outbound, Socks5Outbound
from proxy_tuner.http_proxy import HttpProxyConnection, http_connect, HttpProxyError
from proxy_tuner.socks5 import Socks5Connection, socks5_connect, Socks5Error


class OutboundError(Exception):
    """Base error for outbound operations."""


class OutboundTestResult(NamedTuple):
    """Result of testing an outbound proxy."""

    success: bool
    latency_ms: float | None = None
    error: str | None = None


@dataclass
class OutboundStats:
    """Traffic statistics for an outbound."""

    connections: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    errors: int = 0
    last_connected: float | None = None
    last_error: float | None = None
    avg_latency_ms: float = 0.0

    def record_connection(self, latency_ms: float) -> None:
        self.connections += 1
        self.last_connected = time.time()
        # Exponential moving average
        if self.connections == 1:
            self.avg_latency_ms = latency_ms
        else:
            self.avg_latency_ms = 0.8 * self.avg_latency_ms + 0.2 * latency_ms

    def record_bytes(self, sent: int, received: int) -> None:
        self.bytes_sent += sent
        self.bytes_received += received

    def record_error(self) -> None:
        self.errors += 1
        self.last_error = time.time()


@dataclass
class OutboundManager:
    """Manages connections to upstream proxy outbounds.

    Provides a unified interface for the forwarder to establish proxied
    connections based on the resolved outbound name.
    """

    config: Config = field(default_factory=Config)
    stats: dict[str, OutboundStats] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Initialize stats for all outbounds."""
        for name in self.config.outbounds:
            if name not in self.stats:
                self.stats[name] = OutboundStats()

    def update(self, config: Config) -> None:
        """Update config and add stats for new outbounds."""
        self.config = config
        for name in config.outbounds:
            if name not in self.stats:
                self.stats[name] = OutboundStats()

    def get_stats(self, name: str) -> OutboundStats:
        """Get stats for an outbound."""
        return self.stats.setdefault(name, OutboundStats())

    async def connect(self, outbound_name: str, target_host: str, target_port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Open a proxied connection to target through the named outbound.

        Returns (reader, writer) for the tunneled connection.
        Raises OutboundError if the connection fails.
        """
        if outbound_name not in self.config.outbounds:
            raise OutboundError(f"Outbound '{outbound_name}' does not exist")

        ob = self.config.outbounds[outbound_name]
        start = time.monotonic()

        try:
            if isinstance(ob, Socks5Outbound):
                result = await socks5_connect(
                    proxy_host=ob.host,
                    proxy_port=ob.port,
                    target_host=target_host,
                    target_port=target_port,
                    username=ob.username,
                    password=ob.password,
                    timeout=ob.timeout,
                )
                latency = (time.monotonic() - start) * 1000
                self.stats.setdefault(outbound_name, OutboundStats()).record_connection(latency)
                return result.reader, result.writer

            elif isinstance(ob, HttpOutbound):
                result = await http_connect(
                    proxy_host=ob.host,
                    proxy_port=ob.port,
                    target_host=target_host,
                    target_port=target_port,
                    username=ob.username,
                    password=ob.password,
                    timeout=ob.timeout,
                )
                latency = (time.monotonic() - start) * 1000
                self.stats.setdefault(outbound_name, OutboundStats()).record_connection(latency)
                return result.reader, result.writer

            elif isinstance(ob, DirectOutbound):
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target_host, target_port),
                    timeout=10.0,
                )
                latency = (time.monotonic() - start) * 1000
                self.stats.setdefault(outbound_name, OutboundStats()).record_connection(latency)
                return reader, writer

            else:
                raise OutboundError(f"Unknown outbound type: {type(ob)}")

        except (Socks5Error, HttpProxyError, OSError, asyncio.TimeoutError) as e:
            self.stats.setdefault(outbound_name, OutboundStats()).record_error()
            raise OutboundError(f"Failed to connect through '{outbound_name}': {e}") from e

    async def test_outbound(self, name: str, test_host: str = "1.1.1.1", test_port: int = 80) -> OutboundTestResult:
        """Test connectivity through an outbound proxy.

        Attempts to connect to test_host:test_port through the proxy.
        """
        start = time.monotonic()
        try:
            reader, writer = await self.connect(name, test_host, test_port)
            latency = (time.monotonic() - start) * 1000
            writer.close()
            await writer.wait_closed()
            return OutboundTestResult(success=True, latency_ms=latency)
        except OutboundError as e:
            latency = (time.monotonic() - start) * 1000
            return OutboundTestResult(success=False, latency_ms=latency, error=str(e))
