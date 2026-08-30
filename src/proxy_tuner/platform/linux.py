"""Linux platform backend — nftables TPROXY + TUN interface."""

from __future__ import annotations

import os
import signal
from pathlib import Path

from proxy_tuner.platform.base import PlatformBackend


class LinuxBackend(PlatformBackend):
    """Linux traffic interception via nftables/iptables and TUN."""

    def __init__(self) -> None:
        self._running = False
        self._nftables_handle: int | None = None
        self._tun_name: str = "proxytun0"

    async def start(self, local_port: int, tun_name: str, tun_address: str) -> None:
        self._tun_name = tun_name
        # TODO: Phase 4 — create TUN, set up nftables rules
        self._running = True

    async def stop(self) -> None:
        # TODO: Phase 4 — remove nftables rules, destroy TUN
        self._running = False

    async def is_running(self) -> bool:
        return self._running

    def get_pid_for_connection(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
    ) -> int | None:
        # TODO: Phase 4 — parse /proc/net/tcp or use SO_ORIGINAL_DST
        return None

    def get_process_name(self, pid: int) -> str | None:
        try:
            cmdline = Path(f"/proc/{pid}/cmdline").read_text()
            return cmdline.split("\x00")[0].split("/")[-1]
        except (FileNotFoundError, PermissionError):
            return None
