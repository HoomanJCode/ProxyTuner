"""Linux transparent TCP proxying through netfilter REDIRECT."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from proxy_tuner.firewall import FirewallManager
from proxy_tuner.platform.base import PlatformBackend

logger = logging.getLogger("proxy_tuner.platform.linux")


class LinuxBackend(PlatformBackend):
    """Redirect local TCP connections into the transparent forwarder."""

    def __init__(self) -> None:
        self._running = False
        self._firewall: FirewallManager | None = None

    async def start(
        self,
        local_port: int,
        tun_name: str,
        tun_address: str,
        bypass_uids: tuple[int, ...] = (),
        bypass_ports: tuple[int, ...] = (),
    ) -> None:
        if os.geteuid() != 0:
            raise PermissionError("Linux transparent proxying requires root privileges")

        firewall = FirewallManager(
            tun_name=tun_name,
            tun_address=tun_address.split("/", 1)[0],
            listen_port=local_port,
            bypass_uids=list(bypass_uids),
            bypass_ports=list(bypass_ports),
        )
        firewall.setup()
        self._firewall = firewall
        self._running = True
        logger.info("Linux transparent TCP redirect started on port %d", local_port)

    async def stop(self) -> None:
        if self._firewall:
            self._firewall.teardown()
            self._firewall = None
        self._running = False
        logger.info("Linux transparent TCP redirect stopped")

    async def is_running(self) -> bool:
        return self._running

    def get_pid_for_connection(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
    ) -> int | None:
        """Resolve a connection PID by matching its socket inode in procfs."""
        del src_ip, dst_ip
        inode = self._find_inode(src_port, dst_port)
        return self._inode_to_pid(inode) if inode is not None else None

    def _find_inode(self, local_port: int, remote_port: int) -> int | None:
        try:
            lines = Path("/proc/net/tcp").read_text().splitlines()[1:]
        except (FileNotFoundError, PermissionError):
            return None

        local_port_hex = f"{local_port:04X}"
        remote_port_hex = f"{remote_port:04X}"
        for line in lines:
            parts = line.split()
            if len(parts) >= 10:
                local = parts[1].rsplit(":", 1)[-1]
                remote = parts[2].rsplit(":", 1)[-1]
                if local == local_port_hex and remote == remote_port_hex:
                    try:
                        return int(parts[9])
                    except ValueError:
                        return None
        return None

    @staticmethod
    def _inode_to_pid(inode: int) -> int | None:
        target = f"socket:[{inode}]"
        try:
            processes = Path("/proc").iterdir()
            for pid_dir in processes:
                if not pid_dir.name.isdigit():
                    continue
                try:
                    for fd in (pid_dir / "fd").iterdir():
                        try:
                            if os.readlink(fd) == target:
                                return int(pid_dir.name)
                        except OSError:
                            continue
                except OSError:
                    continue
        except OSError:
            return None
        return None

    def get_process_name(self, pid: int) -> str | None:
        try:
            return Path(f"/proc/{pid}/comm").read_text().strip()
        except (FileNotFoundError, PermissionError):
            return None

    def get_process_exe(self, pid: int) -> str | None:
        try:
            return os.readlink(f"/proc/{pid}/exe")
        except OSError:
            return None
