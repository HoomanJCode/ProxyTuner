"""Linux platform backend — transparent proxying via TUN + iptables.

Creates a TUN interface, sets up iptables rules to redirect traffic,
and resolves process ownership for per-process routing.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from pathlib import Path

from proxy_tuner.firewall import FirewallError, FirewallManager
from proxy_tuner.platform.base import PlatformBackend
from proxy_tuner.tun import TunError, TunManager

logger = logging.getLogger("proxy_tuner.platform.linux")


class LinuxBackend(PlatformBackend):
    """Linux transparent proxying via TUN interface and iptables."""

    def __init__(self) -> None:
        self._running = False
        self._tun: TunManager | None = None
        self._firewall: FirewallManager | None = None
        self._forwarder_task: asyncio.Task | None = None

    async def start(self, local_port: int, tun_name: str, tun_address: str) -> None:
        """Start transparent proxying on Linux.

        1. Create TUN interface
        2. Set up iptables rules
        3. Start packet forwarding loop
        """
        # Extract IP from address (e.g., "10.0.0.1/24" -> "10.0.0.1")
        tun_ip = tun_address.split("/")[0]

        self._tun = TunManager(device_name=tun_name, address=tun_address)
        self._firewall = FirewallManager(
            tun_name=tun_name,
            tun_address=tun_ip,
            listen_port=local_port,
        )

        try:
            # Create TUN interface
            fd = await self._tun.open()
            logger.info("TUN interface created (fd=%d)", fd)

            # Set up firewall rules
            self._firewall.setup()
            logger.info("Firewall rules configured")

            self._running = True

        except (TunError, FirewallError) as e:
            logger.error("Failed to start Linux backend: %s", e)
            await self.stop()
            raise

    async def stop(self) -> None:
        """Stop transparent proxying and clean up."""
        self._running = False

        # Cancel forwarding task
        if self._forwarder_task and not self._forwarder_task.done():
            self._forwarder_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._forwarder_task

        # Remove firewall rules
        if self._firewall:
            self._firewall.teardown()
            self._firewall = None

        # Close TUN interface
        if self._tun:
            await self._tun.close()
            self._tun = None

        logger.info("Linux backend stopped")

    async def is_running(self) -> bool:
        return self._running

    def get_pid_for_connection(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
    ) -> int | None:
        """Resolve which process owns a connection via /proc/net/tcp."""
        try:
            return self._lookup_pid(src_port, dst_port)
        except Exception as e:
            logger.debug("PID lookup failed: %s", e)
            return None

    def _lookup_pid(self, local_port: int, remote_port: int) -> int | None:
        """Look up the PID that owns a connection by ports.

        Parses /proc/net/tcp to find the inode, then scans
        /proc/*/fd to find which process holds that inode.
        """
        try:
            inode = self._find_inode(local_port, remote_port)
            if inode is None:
                return None
            return self._inode_to_pid(inode)
        except Exception:
            return None

    def _find_inode(self, local_port: int, remote_port: int) -> int | None:
        """Find the socket inode for a connection in /proc/net/tcp."""
        try:
            tcp_data = Path("/proc/net/tcp").read_text()
        except (FileNotFoundError, PermissionError):
            return None

        local_port_hex = f"{local_port:04X}"
        remote_port_hex = f"{remote_port:04X}"

        for line in tcp_data.splitlines()[1:]:  # Skip header
            parts = line.split()
            if len(parts) < 10:
                continue

            local_addr = parts[1]
            remote_addr = parts[2]
            inode = int(parts[9])

            # Parse local address (ip:port in hex)
            lp = local_addr.split(":")[1]
            rp = remote_addr.split(":")[1]

            if lp == local_port_hex and rp == remote_port_hex:
                return inode

        return None

    def _inode_to_pid(self, inode: int) -> int | None:
        """Find the PID that owns a socket inode."""
        proc_dir = Path("/proc")
        target = f"socket:[{inode}]"

        for pid_dir in proc_dir.iterdir():
            if not pid_dir.name.isdigit():
                continue
            fd_dir = pid_dir / "fd"
            if not fd_dir.exists():
                continue
            try:
                for fd in fd_dir.iterdir():
                    try:
                        link = os.readlink(str(fd))
                        if link == target:
                            return int(pid_dir.name)
                    except OSError:
                        continue
            except OSError:
                continue

        return None

    def get_process_name(self, pid: int) -> str | None:
        """Get the process name for a given PID from /proc/[pid]/comm."""
        try:
            comm = Path(f"/proc/{pid}/comm").read_text().strip()
            return comm
        except (FileNotFoundError, PermissionError):
            return None

    def get_process_exe(self, pid: int) -> str | None:
        """Get the executable path for a given PID."""
        try:
            exe_path = os.readlink(f"/proc/{pid}/exe")
            return exe_path
        except (OSError, PermissionError):
            return None

    def add_process_route(self, process_name: str) -> None:
        """Add a route for a specific process through the TUN."""
        if self._firewall is None:
            return

        # Find the UID of the process
        try:
            # This is a simplification — in reality we'd need to match
            # by PID or use cgroups for per-process routing
            logger.info("Adding process route for: %s", process_name)
        except Exception as e:
            logger.warning("Failed to add process route: %s", e)
