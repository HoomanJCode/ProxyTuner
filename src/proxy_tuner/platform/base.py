"""Abstract base class for platform backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ConnectionInfo:
    """Information about a network connection for rule matching."""

    dst_ip: str
    dst_port: int
    dst_host: str | None = None
    process_name: str | None = None
    process_path: str | None = None
    url: str | None = None
    protocol: str = "tcp"


class PlatformBackend(ABC):
    """Abstract interface for OS-specific traffic interception."""

    @abstractmethod
    async def start(self, local_port: int, tun_name: str, tun_address: str) -> None:
        """Start intercepting traffic and redirecting to the local proxy."""
        ...

    @abstractmethod
    async def stop(self) -> None:
        """Stop intercepting and clean up all rules/interfaces."""
        ...

    @abstractmethod
    async def is_running(self) -> bool:
        """Check if the backend is currently active."""
        ...

    @abstractmethod
    def get_pid_for_connection(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
    ) -> int | None:
        """Resolve which process owns a connection. Returns PID or None."""
        ...

    @abstractmethod
    def get_process_name(self, pid: int) -> str | None:
        """Get the process name for a given PID."""
        ...
