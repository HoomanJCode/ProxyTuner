"""DNS interception and resolution for domain-based rules.

Intercepts DNS queries to resolve hostnames for domain-based routing,
and caches results for performance.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
import time
from dataclasses import dataclass, field

logger = logging.getLogger("proxy_tuner.dns")


@dataclass
class DnsCache:
    """Simple DNS cache with TTL-based expiration."""

    _cache: dict[str, tuple[str, float]] = field(default_factory=dict)
    default_ttl: float = 300.0  # 5 minutes

    def get(self, hostname: str) -> str | None:
        """Look up a hostname in the cache. Returns IP or None."""
        entry = self._cache.get(hostname)
        if entry is None:
            return None
        ip, expires_at = entry
        if time.time() > expires_at:
            del self._cache[hostname]
            return None
        return ip

    def put(self, hostname: str, ip: str, ttl: float | None = None) -> None:
        """Store a DNS resolution in the cache."""
        if ttl is not None:
            expires_at = time.time() + ttl
        else:
            expires_at = time.time() + self.default_ttl
        self._cache[hostname] = (ip, expires_at)

    def remove(self, hostname: str) -> None:
        """Remove an entry from the cache."""
        self._cache.pop(hostname, None)

    def clear(self) -> None:
        """Clear the entire cache."""
        self._cache.clear()

    @property
    def size(self) -> int:
        return len(self._cache)

    def cleanup(self) -> int:
        """Remove expired entries. Returns number removed."""
        now = time.time()
        expired = [k for k, (_, exp) in self._cache.items() if now > exp]
        for k in expired:
            del self._cache[k]
        return len(expired)


class DnsResolver:
    """Async DNS resolver with caching.

    Resolves hostnames to IP addresses for domain-based routing rules.
    Supports both system resolution and custom DNS servers.
    """

    def __init__(
        self,
        dns_server: str | None = None,
        cache_ttl: float = 300.0,
    ) -> None:
        self.dns_server = dns_server
        self.cache = DnsCache(default_ttl=cache_ttl)
        self._stats = {"queries": 0, "cache_hits": 0, "failures": 0}

    @property
    def stats(self) -> dict:
        return self._stats.copy()

    async def resolve(self, hostname: str) -> str | None:
        """Resolve a hostname to an IP address.

        Checks cache first, then performs DNS resolution.
        """
        # Skip resolution for IP addresses
        try:
            socket.inet_aton(hostname)
            return hostname
        except socket.error:
            pass

        # Check cache
        cached = self.cache.get(hostname)
        if cached is not None:
            self._stats["cache_hits"] += 1
            return cached

        # Perform DNS resolution
        self._stats["queries"] += 1
        try:
            if self.dns_server:
                ip = await self._resolve_via_server(hostname)
            else:
                ip = await self._resolve_system(hostname)

            if ip:
                self.cache.put(hostname, ip)
                logger.debug("Resolved %s -> %s", hostname, ip)
            return ip

        except Exception as e:
            self._stats["failures"] += 1
            logger.warning("DNS resolution failed for %s: %s", hostname, e)
            return None

    async def _resolve_system(self, hostname: str) -> str | None:
        """Resolve using system DNS (getaddrinfo)."""
        loop = asyncio.get_event_loop()
        try:
            infos = await loop.run_in_executor(
                None,
                socket.getaddrinfo,
                hostname,
                None,
                socket.AF_INET,
            )
            if infos:
                return infos[0][4][0]  # First IPv4 address
        except socket.gaierror:
            pass
        return None

    async def _resolve_via_server(self, hostname: str) -> str | None:
        """Resolve via a custom DNS server using UDP."""
        if not self.dns_server:
            return await self._resolve_system(hostname)

        try:
            # Build a simple DNS query
            query = self._build_dns_query(hostname)
            loop = asyncio.get_event_loop()

            # Send UDP query
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: DnsProtocol(),
                remote_addr=(self.dns_server, 53),
            )

            try:
                transport.sendto(query)
                # Wait for response with timeout
                response = await asyncio.wait_for(protocol.wait_response(), timeout=5.0)
                if response:
                    return self._parse_dns_response(response)
            finally:
                transport.close()

        except asyncio.TimeoutError:
            logger.debug("DNS query to %s timed out for %s", self.dns_server, hostname)
        except Exception as e:
            logger.debug("DNS query failed: %s", e)

        return None

    @staticmethod
    def _build_dns_query(hostname: str) -> bytes:
        """Build a DNS A record query."""
        # Transaction ID
        tx_id = 0x1234

        # Flags: standard query, recursion desired
        flags = 0x0100

        # Questions: 1, Answer/Auth/Additional: 0
        header = struct.pack("!HHHHHH", tx_id, flags, 1, 0, 0, 0)

        # Question section
        question = b""
        for label in hostname.split("."):
            question += struct.pack("!B", len(label)) + label.encode("ascii")
        question += b"\x00"  # Root label

        # Type A (1), Class IN (1)
        question += struct.pack("!HH", 1, 1)

        return header + question

    @staticmethod
    def _parse_dns_response(data: bytes) -> str | None:
        """Parse a DNS A record response. Returns the IP address."""
        if len(data) < 12:
            return None

        # Skip header (12 bytes) and question section
        offset = 12

        # Skip question section
        while offset < len(data) and data[offset] != 0:
            length = data[offset]
            if length >= 192:  # Compression pointer
                offset += 2
                break
            offset += 1 + length
        else:
            offset += 1  # Skip null terminator

        offset += 4  # Skip QTYPE + QCLASS

        # Parse answer section
        while offset < len(data) - 12:
            # Skip name (handle compression)
            if data[offset] >= 192:
                offset += 2
            else:
                while offset < len(data) and data[offset] != 0:
                    offset += 1 + data[offset]
                offset += 1

            rtype = struct.unpack("!H", data[offset:offset + 2])[0]
            offset += 8  # Type, Class, TTL
            rdlength = struct.unpack("!H", data[offset:offset + 2])[0]
            offset += 2

            if rtype == 1 and rdlength == 4:  # A record
                ip = socket.inet_ntoa(data[offset:offset + 4])
                return ip

            offset += rdlength

        return None


class DnsProtocol(asyncio.DatagramProtocol):
    """Simple DNS protocol for receiving UDP responses."""

    def __init__(self) -> None:
        self._response: bytes | None = None
        self._event = asyncio.Event()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        pass

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        self._response = data
        self._event.set()

    async def wait_response(self) -> bytes | None:
        try:
            await asyncio.wait_for(self._event.wait(), timeout=5.0)
            return self._response
        except asyncio.TimeoutError:
            return None

    def error_received(self, exc: Exception) -> None:
        logger.debug("DNS protocol error: %s", exc)
