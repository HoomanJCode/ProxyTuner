"""Windows platform backend — WinDivert packet interception."""

from __future__ import annotations

from proxy_tuner.platform.base import PlatformBackend


class WindowsBackend(PlatformBackend):
    """Windows traffic interception via WinDivert driver."""

    def __init__(self) -> None:
        self._running = False

    async def start(self, local_port: int, tun_name: str, tun_address: str) -> None:
        # TODO: Phase 5 — install WinDivert, create TUN, start capture
        self._running = True

    async def stop(self) -> None:
        # TODO: Phase 5 — stop WinDivert, remove TUN
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
        # TODO: Phase 5 — use WinDivert process ID
        return None

    def get_process_name(self, pid: int) -> str | None:
        # TODO: Phase 5 — use psutil or ctypes
        return None
