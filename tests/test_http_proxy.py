"""Unit tests for HTTP CONNECT proxy client — tests protocol encoding without network."""

from __future__ import annotations

import pytest

from proxy_tuner.http_proxy import _build_connect_request


class TestBuildConnectRequest:
    def test_basic_request(self) -> None:
        request = _build_connect_request("example.com", 443)
        text = request.decode("ascii")
        assert "CONNECT example.com:443 HTTP/1.1" in text
        assert "Host: example.com:443" in text

    def test_request_with_auth(self) -> None:
        request = _build_connect_request("example.com", 443, username="user", password="pass")
        text = request.decode("ascii")
        assert "Proxy-Authorization: Basic" in text
        # Verify it's base64 encoded
        import base64

        expected = base64.b64encode(b"user:pass").decode("ascii")
        assert expected in text

    def test_request_no_auth(self) -> None:
        request = _build_connect_request("10.0.0.1", 1080)
        text = request.decode("ascii")
        assert "Proxy-Authorization" not in text
        assert "CONNECT 10.0.0.1:1080 HTTP/1.1" in text

    def test_request_terminated_correctly(self) -> None:
        request = _build_connect_request("example.com", 80)
        # Should end with \r\n\r\n
        assert request.endswith(b"\r\n\r\n")

    def test_ipv4_address(self) -> None:
        request = _build_connect_request("192.168.1.1", 3128)
        text = request.decode("ascii")
        assert "CONNECT 192.168.1.1:3128 HTTP/1.1" in text
        assert "Host: 192.168.1.1:3128" in text
