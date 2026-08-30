"""Unit tests for TUN manager and IP header parsing.

Tests the IP header parsing without requiring actual TUN access.
"""

from __future__ import annotations

import struct

import pytest

from proxy_tuner.tun import TunManager


class TestIPHeaderParsing:
    """Test IP header parsing from raw packets."""

    def _build_tcp_packet(
        self,
        src_ip: str = "192.168.1.1",
        dst_ip: str = "10.0.0.1",
        src_port: int = 12345,
        dst_port: int = 80,
        payload: bytes = b"",
    ) -> bytes:
        """Build a minimal IPv4+TCP packet for testing."""
        import ipaddress

        src_bytes = ipaddress.IPv4Address(src_ip).packed
        dst_bytes = ipaddress.IPv4Address(dst_ip).packed

        # TCP header (minimal: 20 bytes)
        tcp_header = struct.pack(
            "!HHIIHHH",
            src_port,
            dst_port,
            0,  # seq
            0,  # ack
            (5 << 12),  # data offset (5 words) + flags
            65535,  # window
            0,  # checksum (ignored for testing)
        )

        # IP header
        total_length = 20 + len(tcp_header) + len(payload)
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,  # version=4, ihl=5
            0,  # DSCP/ECN
            total_length,
            0,  # identification
            0,  # flags + fragment offset
            64,  # TTL
            6,  # protocol = TCP
            0,  # checksum (ignored for testing)
            src_bytes,
            dst_bytes,
        )

        return ip_header + tcp_header + payload

    def test_parse_tcp_packet(self) -> None:
        packet = self._build_tcp_packet(
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
        )

        tun = TunManager()
        info = tun.get_ip_header_info(packet)

        assert info is not None
        assert info["src_ip"] == "192.168.1.1"
        assert info["dst_ip"] == "10.0.0.1"
        assert info["protocol"] == 6  # TCP
        assert info["src_port"] == 12345
        assert info["dst_port"] == 80

    def test_parse_udp_packet(self) -> None:
        import ipaddress

        src_bytes = ipaddress.IPv4Address("10.0.0.1").packed
        dst_bytes = ipaddress.IPv4Address("8.8.8.8").packed

        # UDP header (8 bytes)
        udp_header = struct.pack("!HHHH", 5353, 53, 8, 0)

        # IP header
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + 8,  # total length
            0,
            0,
            64,
            17,  # protocol = UDP
            0,
            src_bytes,
            dst_bytes,
        )

        tun = TunManager()
        info = tun.get_ip_header_info(ip_header + udp_header)

        assert info is not None
        assert info["protocol"] == 17  # UDP
        assert info["src_port"] == 5353
        assert info["dst_port"] == 53

    def test_non_ipv4_returns_none(self) -> None:
        """IPv6 packets should return None."""
        packet = b"\x60" + b"\x00" * 39  # Version 6 header
        tun = TunManager()
        info = tun.get_ip_header_info(packet)
        assert info is None

    def test_short_packet_returns_none(self) -> None:
        packet = b"\x45" + b"\x00" * 10  # Too short
        tun = TunManager()
        info = tun.get_ip_header_info(packet)
        assert info is None

    def test_empty_packet_returns_none(self) -> None:
        tun = TunManager()
        info = tun.get_ip_header_info(b"")
        assert info is None

    def test_basic_header_fields(self) -> None:
        packet = self._build_tcp_packet(src_ip="1.2.3.4", dst_ip="5.6.7.8")
        tun = TunManager()
        info = tun.get_ip_header_info(packet)

        assert info is not None
        assert info["version"] == 4
        assert info["ihl"] == 20  # 5 * 4
        assert info["total_length"] > 0


class TestCIDRConversion:
    def test_cidr_to_prefix(self) -> None:
        assert TunManager._cidr_to_prefix("24") == 24
        assert TunManager._cidr_to_prefix("8") == 8
        assert TunManager._cidr_to_prefix("32") == 32
        assert TunManager._cidr_to_prefix("16") == 16
