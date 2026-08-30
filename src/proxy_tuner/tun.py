"""TUN interface manager for Linux transparent proxying.

Creates and manages a TUN virtual network interface used for
intercepting and redirecting traffic through the proxy forwarder.
"""

from __future__ import annotations

import asyncio
import logging
import os
import struct
import subprocess
from pathlib import Path

logger = logging.getLogger("proxy_tuner.tun")

# Linux TUN constants
TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

# IP header constants
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMP = 1

# IP header flags
IP_MF = 0x2000  # More fragments
IP_OFFMASK = 0x1FFF


class TunError(Exception):
    """TUN interface error."""


class TunManager:
    """Manages a Linux TUN interface.

    Creates a TUN device, assigns an IP address, and provides
    async packet reading/writing for transparent proxying.
    """

    def __init__(
        self,
        device_name: str = "proxytun0",
        address: str = "10.0.0.1/24",
        mtu: int = 1500,
    ) -> None:
        self.device_name = device_name
        self.address = address
        self.mtu = mtu
        self._fd: int | None = None
        self._running = False
        self._read_task: asyncio.Task | None = None

    @property
    def is_running(self) -> bool:
        return self._running

    async def open(self) -> int:
        """Create and configure the TUN interface.

        Returns the file descriptor for reading/writing packets.
        """
        try:
            import fcntl

            # Open /dev/net/tun
            self._fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)

            # Configure the TUN interface
            ifr = struct.pack("16sH", self.device_name.encode(), IFF_TUN | IFF_NO_PI)
            fcntl.ioctl(self._fd, TUNSETIFF, ifr)

            # Bring the interface up and assign IP
            self._setup_interface()

            self._running = True
            logger.info("TUN interface %s opened (fd=%d)", self.device_name, self._fd)
            return self._fd

        except OSError as e:
            raise TunError(f"Failed to create TUN interface: {e}") from e

    def _setup_interface(self) -> None:
        """Configure the TUN interface with IP address and bring it up."""
        ip, cidr = self.address.split("/")
        prefix_len = self._cidr_to_prefix(cidr)

        commands = [
            ["ip", "link", "set", self.device_name, "up"],
            ["ip", "addr", "add", f"{ip}/{prefix_len}", "dev", self.device_name],
            ["ip", "link", "set", self.device_name, "mtu", str(self.mtu)],
        ]

        for cmd in commands:
            try:
                subprocess.run(cmd, check=True, capture_output=True, timeout=5)
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                logger.warning("Failed to run %s: %s", " ".join(cmd), e)

    @staticmethod
    def _cidr_to_prefix(cidr: str) -> int:
        """Convert CIDR notation to prefix length."""
        import ipaddress

        return ipaddress.IPv4Network(f"0.0.0.0/{cidr}").prefixlen

    async def close(self) -> None:
        """Destroy the TUN interface and clean up."""
        self._running = False

        if self._read_task and not self._read_task.done():
            self._read_task.cancel()
            try:
                await self._read_task
            except asyncio.CancelledError:
                pass

        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None

        # Remove the interface
        try:
            subprocess.run(
                ["ip", "link", "del", self.device_name],
                check=True,
                capture_output=True,
                timeout=5,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

        logger.info("TUN interface %s closed", self.device_name)

    async def read_packet(self) -> bytes:
        """Read a raw IP packet from the TUN interface.

        Returns raw bytes. Raises TunError on failure.
        """
        if self._fd is None:
            raise TunError("TUN interface not open")

        loop = asyncio.get_event_loop()
        try:
            data = await loop.run_in_executor(None, os.read, self._fd, self.mtu + 4)
            return data
        except BlockingIOError:
            return b""
        except OSError as e:
            raise TunError(f"Error reading from TUN: {e}") from e

    async def write_packet(self, data: bytes) -> None:
        """Write a raw IP packet to the TUN interface."""
        if self._fd is None:
            raise TunError("TUN interface not open")

        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(None, os.write, self._fd, data)
        except OSError as e:
            raise TunError(f"Error writing to TUN: {e}") from e

    def get_ip_header_info(self, data: bytes) -> dict | None:
        """Parse basic IP header information from a raw packet.

        Returns dict with src_ip, dst_ip, protocol, total_length, etc.
        Returns None if the packet is too short or not IPv4.
        """
        if len(data) < 20:
            return None

        # Parse IP header
        version_ihl = data[0]
        version = (version_ihl >> 4) & 0xF
        if version != 4:
            return None  # Only IPv4 supported

        ihl = (version_ihl & 0xF) * 4  # Header length in bytes
        if len(data) < ihl:
            return None

        import ipaddress

        total_length = struct.unpack("!H", data[2:4])[0]
        protocol = data[9]
        src_ip = str(ipaddress.IPv4Address(data[12:16]))
        dst_ip = str(ipaddress.IPv4Address(data[16:20]))

        result: dict = {
            "version": version,
            "ihl": ihl,
            "total_length": total_length,
            "protocol": protocol,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
        }

        # Parse TCP/UDP ports if applicable
        if protocol == IPPROTO_TCP and len(data) >= ihl + 4:
            src_port = struct.unpack("!H", data[ihl:ihl + 2])[0]
            dst_port = struct.unpack("!H", data[ihl + 2:ihl + 4])[0]
            result["src_port"] = src_port
            result["dst_port"] = dst_port
        elif protocol == IPPROTO_UDP and len(data) >= ihl + 4:
            src_port = struct.unpack("!H", data[ihl:ihl + 2])[0]
            dst_port = struct.unpack("!H", data[ihl + 2:ihl + 4])[0]
            result["src_port"] = src_port
            result["dst_port"] = dst_port

        return result


def get_original_dst(sock: object, family: int = 2) -> tuple[str, int] | None:
    """Get the original destination of a connection redirected by iptables.

    Uses SO_ORIGINAL_DST (Linux-specific) to retrieve the real destination
    before iptables REDIRECT changed it.

    Args:
        sock: Socket object (must have getsockopt method).
        address family: 2=AF_INET (IPv4), 10=AF_INET6 (IPv6).

    Returns:
        (ip, port) tuple or None on failure.
    """
    try:
        import ipaddress

        if family == 2:  # AF_INET
            # SO_ORIGINAL_DST = 80
            data = sock.getsockopt(80, 16, 16)
            port = struct.unpack("!H", data[2:4])[0]
            ip = str(ipaddress.IPv4Address(data[4:8]))
            return ip, port
        elif family == 10:  # AF_INET6
            # SO_ORIGINAL_DST works for IPv6 too on newer kernels
            data = sock.getsockopt(80, 16, 16)
            port = struct.unpack("!H", data[2:4])[0]
            ip = str(ipaddress.IPv6Address(data[8:24]))
            return ip, port
    except (OSError, ValueError, struct.error):
        pass
    return None
