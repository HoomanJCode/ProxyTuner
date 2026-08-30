"""Windows platform backend — WinDivert packet interception.

Uses WinDivert driver for packet capture and process-based routing.
Requires admin privileges and WinDivert driver installed.

Dependencies: pydivert (pip install pydivert) or ctypes bindings.
"""

from __future__ import annotations

import asyncio
import ctypes
import logging
import os
import sys
from pathlib import Path

from proxy_tuner.platform.base import PlatformBackend

logger = logging.getLogger("proxy_tuner.platform.windows")


class WindowsBackend(PlatformBackend):
    """Windows transparent proxying via WinDivert driver.

    WinDivert intercepts packets at the network layer, allowing
    per-process filtering and transparent proxying.
    """

    def __init__(self) -> None:
        self._running = False
        self._handle = None  # WinDivert handle
        self._forwarder_task: asyncio.Task | None = None

    def _check_admin(self) -> bool:
        """Check if running with administrator privileges."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (AttributeError, OSError):
            return False

    async def start(self, local_port: int, tun_name: str, tun_address: str) -> None:
        """Start transparent proxying on Windows.

        Requires administrator privileges and WinDivert driver.
        """
        if sys.platform != "win32":
            raise RuntimeError("WindowsBackend can only run on Windows")

        if not self._check_admin():
            raise RuntimeError(
                "Administrator privileges required for WinDivert. "
                "Please run as Administrator."
            )

        # Check if WinDivert is available
        try:
            self._load_windivert()
        except Exception as e:
            raise RuntimeError(
                f"WinDivert driver not available: {e}\n"
                "Install from https://reqrypt.org/windivert.html"
            ) from e

        self._running = True
        logger.info("Windows backend started (WinDivert)")

    def _load_windivert(self) -> None:
        """Load WinDivert library."""
        # Try pydivert first
        try:
            import pydivert

            self._pydivert = pydivert
            logger.info("Using pydivert for WinDivert")
            return
        except ImportError:
            pass

        # Fallback: try ctypes
        try:
            self._windivert = ctypes.WinDLL("WinDivert.dll")
            logger.info("Using WinDivert.dll via ctypes")
            return
        except OSError:
            pass

        raise RuntimeError(
            "WinDivert not available. Install pydivert: pip install pydivert"
        )

    async def stop(self) -> None:
        """Stop transparent proxying and clean up."""
        self._running = False

        if self._forwarder_task and not self._forwarder_task.done():
            self._forwarder_task.cancel()
            try:
                await self._forwarder_task
            except asyncio.CancelledError:
                pass

        if self._handle is not None:
            try:
                self._handle.close()
            except Exception:
                pass
            self._handle = None

        logger.info("Windows backend stopped")

    async def is_running(self) -> bool:
        return self._running

    def get_pid_for_connection(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
    ) -> int | None:
        """Resolve which process owns a connection.

        Uses the Windows IP Helper API (GetExtendedTcpTable).
        """
        if sys.platform != "win32":
            return None

        try:
            return self._get_pid_from_tcp_table(src_port, dst_port)
        except Exception as e:
            logger.debug("PID lookup failed: %s", e)
            return None

    def _get_pid_from_tcp_table(self, local_port: int, remote_port: int) -> int | None:
        """Use GetExtendedTcpTable to find process owning a connection."""
        try:
            import ctypes
            from ctypes import wintypes

            iphlpapi = ctypes.WinDLL("iphlpapi.dll")

            # Get TCP table size
            size = wintypes.DWORD(0)
            result = iphlpapi.GetExtendedTcpTable(
                None,
                ctypes.byref(size),
                False,
                2,  # AF_INET
                1,  # TCP_TABLE_OWNER_PID_ALL
                0,
            )

            if result != 122:  # ERROR_BUFFER_OVERFLOW
                return None

            # Allocate buffer and get table
            buffer = (ctypes.c_byte * size.value)()
            result = iphlpapi.GetExtendedTcpTable(
                buffer,
                ctypes.byref(size),
                False,
                2,
                1,
                0,
            )

            if result != 0:
                return None

            # Parse MIB_TCPTABLE_OWNER_PID
            # Header: DWORD dwNumEntries
            num_entries = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value

            for i in range(num_entries):
                offset = 4 + i * 24  # Each MIB_TCPROW_OWNER_PID is 24 bytes
                row = buffer[offset : offset + 24]

                # State, local addr/port, remote addr/port, OwningPid
                state = int.from_bytes(row[0:4], "little")
                local_addr = int.from_bytes(row[4:8], "little")
                local_port = int.from_bytes(row[8:10], "big")
                remote_addr = int.from_bytes(row[12:16], "little")
                remote_port = int.from_bytes(row[16:18], "big")
                pid = int.from_bytes(row[20:24], "little")

                if local_port == local_port and remote_port == remote_port:
                    return pid

            return None

        except Exception:
            return None

    def get_process_name(self, pid: int) -> str | None:
        """Get the process name for a given PID."""
        if sys.platform != "win32":
            return None

        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32.dll")

            PROCESS_QUERY_INFORMATION = 0x0400
            PROCESS_VM_READ = 0x0010

            handle = kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                False,
                pid,
            )

            if not handle:
                return None

            try:
                # Get process image name
                buffer = ctypes.create_unicode_buffer(260)
                size = wintypes.DWORD(260)
                kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size))
                return Path(buffer.value).name
            finally:
                kernel32.CloseHandle(handle)

        except Exception:
            return None

    def _check_admin(self) -> bool:
        """Check if running as Administrator."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (AttributeError, OSError):
            return False

    def request_admin_elevation(self) -> None:
        """Re-launch with admin privileges via UAC."""
        if sys.platform != "win32":
            return

        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            sys.exit(0)
        except Exception:
            pass
