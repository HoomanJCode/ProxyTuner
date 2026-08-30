"""Async HTTP CONNECT proxy client.

Implements HTTP tunneling via CONNECT method (RFC 7231 §4.3.6).
Also supports simple HTTP proxy for plain HTTP requests.
"""

from __future__ import annotations

import asyncio
import base64
from typing import NamedTuple


class HttpProxyError(Exception):
    """HTTP proxy connection error."""


class HttpProxyAuthError(HttpProxyError):
    """HTTP proxy authentication failed."""


class HttpProxyConnection(NamedTuple):
    """Result of an HTTP CONNECT handshake."""

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    status_code: int
    status_line: str


def _build_connect_request(
    host: str,
    port: int,
    username: str | None = None,
    password: str | None = None,
) -> bytes:
    """Build an HTTP CONNECT request."""
    lines = [f"CONNECT {host}:{port} HTTP/1.1"]

    # Host header
    lines.append(f"Host: {host}:{port}")

    # Proxy-Authorization
    if username and password:
        credentials = f"{username}:{password}"
        encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
        lines.append(f"Proxy-Authorization: Basic {encoded}")

    lines.append("")  # Empty line terminates headers
    lines.append("")  # Second empty line for safety

    return "\r\n".join(lines).encode("ascii")


def _build_http_request(
    method: str,
    url: str,
    host: str,
    port: int,
    username: str | None = None,
    password: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> bytes:
    """Build a plain HTTP proxy request (non-CONNECT)."""
    lines = [f"{method} {url} HTTP/1.1"]
    lines.append(f"Host: {host}")

    if username and password:
        credentials = f"{username}:{password}"
        encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
        lines.append(f"Proxy-Authorization: Basic {encoded}")

    if extra_headers:
        for k, v in extra_headers.items():
            lines.append(f"{k}: {v}")

    lines.append("")
    lines.append("")

    return "\r\n".join(lines).encode("ascii")


async def http_connect(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    username: str | None = None,
    password: str | None = None,
    timeout: float = 10.0,
) -> HttpProxyConnection:
    """Perform an HTTP CONNECT tunnel.

    Returns the connected reader/writer pair after successful CONNECT.
    """
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(proxy_host, proxy_port),
        timeout=timeout,
    )

    try:
        request = _build_connect_request(target_host, target_port, username, password)
        writer.write(request)
        await writer.drain()

        # Read status line
        status_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        status_line = status_line.decode("utf-8", errors="replace").strip()

        # Parse status code
        parts = status_line.split(" ", 2)
        if len(parts) < 2:
            raise HttpProxyError(f"Invalid HTTP response: {status_line}")

        try:
            status_code = int(parts[1])
        except ValueError:
            raise HttpProxyError(
                f"Invalid status code: {parts[1]}"
            ) from None

        if status_code == 407:
            raise HttpProxyAuthError("Proxy authentication required")

        if status_code != 200:
            raise HttpProxyError(f"CONNECT failed: {status_line}")

        # Read remaining headers until empty line
        while True:
            header_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if header_line == b"\r\n" or header_line == b"\n" or header_line == b"":
                break

        return HttpProxyConnection(
            reader=reader, writer=writer,
            status_code=status_code, status_line=status_line,
        )

    except Exception:
        writer.close()
        await writer.wait_closed()
        raise
