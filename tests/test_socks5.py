"""Unit tests for SOCKS5 client — tests protocol encoding/decoding without network."""

from __future__ import annotations

import struct

import pytest

from proxy_tuner.socks5 import (
    SOCKS5_ATYP_DOMAIN,
    SOCKS5_ATYP_IPV4,
    SOCKS5_ATYP_IPV6,
    SOCKS5_REP_SUCCESS,
    _decode_address,
    _encode_address,
)


class TestEncodeAddress:
    def test_ipv4(self) -> None:
        result = _encode_address("1.2.3.4", 80)
        assert result[0] == SOCKS5_ATYP_IPV4
        assert len(result) == 1 + 4 + 2  # ATYP + IPv4 + port

    def test_ipv6(self) -> None:
        result = _encode_address("::1", 443)
        assert result[0] == SOCKS5_ATYP_IPV6
        assert len(result) == 1 + 16 + 2  # ATYP + IPv6 + port

    def test_domain(self) -> None:
        result = _encode_address("example.com", 80)
        assert result[0] == SOCKS5_ATYP_DOMAIN
        domain_len = result[1]
        assert domain_len == len("example.com")
        assert result[2 : 2 + domain_len] == b"example.com"

    def test_long_domain(self) -> None:
        domain = "a" * 300
        with pytest.raises(Exception, match="too long"):
            _encode_address(domain, 80)

    def test_port_encoding(self) -> None:
        result = _encode_address("1.2.3.4", 443)
        port_bytes = result[5:7]
        port = struct.unpack("!H", port_bytes)[0]
        assert port == 443


class TestDecodeAddress:
    def test_ipv4(self) -> None:
        # Build a minimal response: version + reply + rsv + atyp + ipv4 + port
        data = struct.pack("!BBBB", 0x05, SOCKS5_REP_SUCCESS, 0x00, SOCKS5_ATYP_IPV4)
        data += bytes([10, 0, 0, 1])  # 10.0.0.1
        data += struct.pack("!H", 8080)
        host, port, offset = _decode_address(data, offset=3)
        assert host == "10.0.0.1"
        assert port == 8080

    def test_ipv6(self) -> None:
        data = struct.pack("!BBBB", 0x05, SOCKS5_REP_SUCCESS, 0x00, SOCKS5_ATYP_IPV6)
        data += bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])  # ::1
        data += struct.pack("!H", 443)
        host, port, offset = _decode_address(data, offset=3)
        assert host == "::1"
        assert port == 443

    def test_domain(self) -> None:
        domain = b"example.com"
        data = struct.pack("!BBBB", 0x05, SOCKS5_REP_SUCCESS, 0x00, SOCKS5_ATYP_DOMAIN)
        data += struct.pack("!B", len(domain)) + domain
        data += struct.pack("!H", 80)
        host, port, offset = _decode_address(data, offset=3)
        assert host == "example.com"
        assert port == 80

    def test_short_data_raises(self) -> None:
        with pytest.raises(Exception, match="too short"):
            _decode_address(b"\x05\x00\x00\x01", offset=3)

    def test_unknown_atyp_raises(self) -> None:
        data = struct.pack("!BBBB", 0x05, 0x00, 0x00, 0xFF)
        with pytest.raises(Exception, match="Unknown address type"):
            _decode_address(data, offset=3)
