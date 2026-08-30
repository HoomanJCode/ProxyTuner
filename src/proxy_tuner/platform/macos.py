"""macOS platform backend — transparent proxying via pf (packet filter).

macOS uses pf (packet filter) for traffic redirection instead of iptables.
This backend provides the interface but full transparent proxying on macOS
requires further implementation with pf anchors and dummynet.
"""

from __future__ import annotations

import logging

from proxy_tuner.platform.base import PlatformBackend

logger = logging.getLogger("proxy_tuner.platform.macos")


class MacosBackend(PlatformBackend):
    """macOS transparent proxying via pf (packet filter)."""

    def __init__(self) -> None:
        self._running = False

    async def start(self, local_port: int, tun_name: str, tun_address: str) -> None:
        logger.info(
            "macOS backend starting (port=%d, tun=%s)", local_port, tun_name
        )
        self._running = True

    async def stop(self) -> None:
        self._running = False
        logger.info("macOS backend stopped")

    async def is_running(self) -> bool:
        return self._running

    def get_pid_for_connection(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
    ) -> int | None:
        return None

    def get_process_name(self, pid: int) -> str | None:
        return None
