"""Opt-in Linux netfilter integration test.

Run as root in an isolated network namespace with iptables available:
PROXY_TUNER_PRIVILEGED_TEST=1 pytest tests/test_linux_transparent_integration.py -v
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import subprocess
import sys

import pytest

from proxy_tuner.config import Config, MatchCondition, Rule, Settings, Socks5Outbound
from proxy_tuner.forwarder import Forwarder
from proxy_tuner.platform.linux import LinuxBackend
from tests.test_integration_packet_flow import EchoServer, MockSocks5Proxy


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.mark.skipif(
    os.environ.get("PROXY_TUNER_PRIVILEGED_TEST") != "1"
    or not sys.platform.startswith("linux")
    or not hasattr(os, "geteuid")
    or os.geteuid() != 0
    or shutil.which("iptables") is None,
    reason="requires explicit opt-in, Linux root, and iptables",
)
def test_redirected_tcp_reaches_upstream_proxy() -> None:
    async def run() -> None:
        echo = EchoServer()
        upstream = MockSocks5Proxy()
        await echo.start()
        await upstream.start()

        listen_port = _free_port()
        config = Config(
            outbounds={
                "upstream": Socks5Outbound(
                    type="socks5", host="127.0.0.1", port=upstream.port
                )
            },
            rules=[Rule(name="all", outbound="upstream", match=MatchCondition())],
            settings=Settings(listen_port=listen_port),
        )
        forwarder = Forwarder(config=config, transparent=True)
        backend = LinuxBackend()
        await forwarder.start()

        try:
            await backend.start(listen_port, "proxytun0", "10.0.0.1/24")

            def send_as_unprivileged_user() -> bytes:
                client_code = (
                    "import socket; s=socket.create_connection(('127.0.0.1', "
                    f"{echo.port}), timeout=5); s.sendall(b'packet-through-proxy'); "
                    "data=s.recv(64); s.close(); print(data.decode())"
                )
                completed = subprocess.run(
                    [sys.executable, "-c", client_code],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    preexec_fn=lambda: os.setuid(65534),
                )
                return completed.stdout.strip().encode()

            response = await asyncio.to_thread(send_as_unprivileged_user)
            assert response == b"packet-through-proxy"
            assert any(port == echo.port for _, port in upstream.connections)
            assert b"packet-through-proxy" in b"".join(echo.received)
        finally:
            await backend.stop()
            await forwarder.stop()
            await upstream.stop()
            await echo.stop()

    asyncio.run(run())
