"""Async SOCKS5 client implementing RFC 1928.

Supports:
- No auth (0x00)
- Username/password auth (0x02)
- CONNECT command (IPv4, domain, IPv6)
- UDP ASSOCIATE (stub — not implemented)
"""

from __future__ import annotations

import asyncio
import struct
from typing import NamedTuple


class Socks5Error(Exception):
    """SOCKS5 protocol or connection error."""


class Socks5AuthError(Socks5Error):
    """SOCKS5 authentication failed."""


class Socks5RefusedError(Socks5Error):
    """SOCKS5 connection refused by server."""


# SOCKS5 constants
SOCKS5_VERSION = 0x05
SOCKS5_AUTH_NONE = 0x00
SOCKS5_AUTH_USERPASS = 0x02
SOCKS5_AUTH_NO_ACCEPTABLE = 0xFF

SOCKS5_CMD_CONNECT = 0x01
SOCKS5_CMD_BIND = 0x02
SOCKS5_CMD_UDP = 0x03

SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOMAIN = 0x03
SOCKS5_ATYP_IPV6 = 0x04

# Reply codes
SOCKS5_REP_SUCCESS = 0x00
SOCKS5_REP_GENERAL_FAILURE = 0x01
SOCKS5_REP_NOT_ALLOWED = 0x02
SOCKS5_REP_NET_UNREACHABLE = 0x03
SOCKS5_REP_HOST_UNREACHABLE = 0x04
SOCKS5_REP_CONNECTION_REFUSED = 0x05
SOCKS5_REP_TTL_EXPIRED = 0x06
SOCKS5_REP_COMMAND_NOT_SUPPORTED = 0x07
SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08

REPLY_NAMES = {
    SOCKS5_REP_SUCCESS: "success",
    SOCKS5_REP_GENERAL_FAILURE: "general failure",
    SOCKS5_REP_NOT_ALLOWED: "not allowed",
    SOCKS5_REP_NET_UNREACHABLE: "network unreachable",
    SOCKS5_REP_HOST_UNREACHABLE: "host unreachable",
    SOCKS5_REP_CONNECTION_REFUSED: "connection refused",
    SOCKS5_REP_TTL_EXPIRED: "TTL expired",
    SOCKS5_REP_COMMAND_NOT_SUPPORTED: "command not supported",
    SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED: "address type not supported",
}


class Socks5Connection(NamedTuple):
    """Result of a SOCKS5 CONNECT handshake."""

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    bound_host: str
    bound_port: int


def _encode_address(host: str, port: int) -> bytes:
    """Encode an address for SOCKS5 request.

    Returns the ATYP byte + encoded address + port.
    """
    # Try IPv4
    import ipaddress

    try:
        addr = ipaddress.IPv4Address(host)
        return struct.pack("!B", SOCKS5_ATYP_IPV4) + addr.packed + struct.pack("!H", port)
    except ValueError:
        pass

    # Try IPv6
    try:
        addr = ipaddress.IPv6Address(host)
        return struct.pack("!B", SOCKS5_ATYP_IPV6) + addr.packed + struct.pack("!H", port)
    except ValueError:
        pass

    # Domain name
    domain_bytes = host.encode("ascii")
    if len(domain_bytes) > 255:
        raise Socks5Error(f"Domain name too long: {len(domain_bytes)} bytes")
    return struct.pack("!B", SOCKS5_ATYP_DOMAIN) + struct.pack("!B", len(domain_bytes)) + domain_bytes + struct.pack("!H", port)


def _decode_address(data: bytes, offset: int = 3) -> tuple[str, int, int]:
    """Decode a SOCKS5 address from response data.

    Returns (host, port, new_offset).
    """
    if offset >= len(data):
        raise Socks5Error("Response too short for address")

    atyp = data[offset]
    offset += 1

    if atyp == SOCKS5_ATYP_IPV4:
        if offset + 4 + 2 > len(data):
            raise Socks5Error("Response too short for IPv4 address")
        import ipaddress

        host = str(ipaddress.IPv4Address(data[offset : offset + 4]))
        offset += 4
    elif atyp == SOCKS5_ATYP_IPV6:
        if offset + 16 + 2 > len(data):
            raise Socks5Error("Response too short for IPv6 address")
        import ipaddress

        host = str(ipaddress.IPv6Address(data[offset : offset + 16]))
        offset += 16
    elif atyp == SOCKS5_ATYP_DOMAIN:
        domain_len = data[offset]
        offset += 1
        if offset + domain_len + 2 > len(data):
            raise Socks5Error("Response too short for domain")
        host = data[offset : offset + domain_len].decode("ascii")
        offset += domain_len
    else:
        raise Socks5Error(f"Unknown address type: {atyp}")

    port = struct.unpack("!H", data[offset : offset + 2])[0]
    offset += 2
    return host, port, offset


async def socks5_connect(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    username: str | None = None,
    password: str | None = None,
    timeout: float = 10.0,
) -> Socks5Connection:
    """Perform a SOCKS5 CONNECT handshake.

    Opens a connection to the SOCKS5 proxy and requests a CONNECT to target_host:target_port.
    Returns the connected reader/writer pair.
    """
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(proxy_host, proxy_port),
        timeout=timeout,
    )

    try:
        # --- Authentication negotiation ---
        if username and password:
            # Offer username/password auth
            writer.write(struct.pack("!BB", SOCKS5_VERSION, 2) + bytes([SOCKS5_AUTH_NONE, SOCKS5_AUTH_USERPASS]))
        else:
            # Offer no-auth only
            writer.write(struct.pack("!BB", SOCKS5_VERSION, 1) + bytes([SOCKS5_AUTH_NONE]))
        await writer.drain()

        # Read server's auth method choice
        auth_response = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if auth_response[0] != SOCKS5_VERSION:
            raise Socks5Error(f"Unexpected SOCKS version: {auth_response[0]}")

        chosen_auth = auth_response[1]
        if chosen_auth == SOCKS5_AUTH_NO_ACCEPTABLE:
            raise Socks5AuthError("No acceptable authentication methods")
        elif chosen_auth == SOCKS5_AUTH_USERPASS:
            # Username/password auth (RFC 1929)
            if not username or not password:
                raise Socks5AuthError("Server requires auth but no credentials provided")
            user_bytes = username.encode("utf-8")
            pass_bytes = password.encode("utf-8")
            if len(user_bytes) > 255 or len(pass_bytes) > 255:
                raise Socks5AuthError("Username or password too long")
            writer.write(
                struct.pack("!B", 0x01)
                + struct.pack("!B", len(user_bytes))
                + user_bytes
                + struct.pack("!B", len(pass_bytes))
                + pass_bytes
            )
            await writer.drain()

            auth_result = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
            if auth_result[1] != 0x00:
                raise Socks5AuthError("Authentication failed")
        elif chosen_auth == SOCKS5_AUTH_NONE:
            pass  # No auth needed
        else:
            raise Socks5Error(f"Unexpected auth method: {chosen_auth}")

        # --- CONNECT request ---
        request = (
            struct.pack("!BBB", SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00)  # RSV=0x00
            + _encode_address(target_host, target_port)
        )
        writer.write(request)
        await writer.drain()

        # Read reply header (at least 4 bytes)
        reply_header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        if reply_header[0] != SOCKS5_VERSION:
            raise Socks5Error(f"Unexpected SOCKS version in reply: {reply_header[0]}")

        reply_status = reply_header[1]
        if reply_status != SOCKS5_REP_SUCCESS:
            reason = REPLY_NAMES.get(reply_status, f"unknown ({reply_status})")
            raise Socks5RefusedError(f"SOCKS5 CONNECT failed: {reason}")

        # Read the bound address (variable length)
        # We need to read the remaining address. Read more data.
        remaining = await asyncio.wait_for(reader.read(64), timeout=timeout)
        full_reply = reply_header + remaining
        bound_host, bound_port, _ = _decode_address(full_reply, offset=3)

        return Socks5Connection(reader=reader, writer=writer, bound_host=bound_host, bound_port=bound_port)

    except Exception:
        writer.close()
        await writer.wait_closed()
        raise
