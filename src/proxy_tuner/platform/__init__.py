"""Platform detection and backend factory."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from proxy_tuner.platform.base import PlatformBackend


def get_platform() -> str:
    """Return the current platform identifier."""
    if sys.platform in ("linux", "android"):
        return "linux"
    elif sys.platform == "win32":
        return "windows"
    else:
        raise RuntimeError(f"Unsupported platform: {sys.platform}")


def create_backend() -> PlatformBackend:
    """Create the appropriate platform backend for the current OS."""
    platform = get_platform()
    if platform == "linux":
        from proxy_tuner.platform.linux import LinuxBackend

        return LinuxBackend()
    elif platform == "windows":
        from proxy_tuner.platform.windows import WindowsBackend

        return WindowsBackend()
    else:
        raise RuntimeError(f"No backend for platform: {platform}")
