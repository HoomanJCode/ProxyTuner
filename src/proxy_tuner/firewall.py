"""nftables/iptables rule management for traffic redirection.

Handles setting up and tearing down firewall rules that redirect
traffic to the TUN interface for transparent proxying.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass

logger = logging.getLogger("proxy_tuner.firewall")


class FirewallError(Exception):
    """Firewall rule management error."""


@dataclass
class FirewallManager:
    """Manages nftables/iptables rules for transparent proxying.

    Strategy:
    1. Create a routing rule that sends traffic from specific UIDs
       to the TUN interface (ip rule add fwmark ... lookup tun).
    2. Use iptables MARK to tag packets from specific processes.
    3. Route marked packets through the TUN.
    """

    tun_name: str = "proxytun0"
    tun_address: str = "10.0.0.1"
    listen_port: int = 10808
    _tables_added: bool = False
    _rules_added: bool = False

    def setup(self) -> None:
        """Set up all firewall rules for transparent proxying."""
        if self._rules_added:
            return

        try:
            self._setup_routing()
            self._setup_iptables()
            self._rules_added = True
            logger.info("Firewall rules set up for TUN %s", self.tun_name)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            raise FirewallError(f"Failed to set up firewall rules: {e}") from e

    def teardown(self) -> None:
        """Remove all firewall rules."""
        if not self._rules_added:
            return

        try:
            self._remove_iptables()
            self._remove_routing()
            self._rules_added = False
            logger.info("Firewall rules removed")
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.warning("Error during firewall teardown: %s", e)

    def _run(self, cmd: list[str]) -> subprocess.CompletedProcess:
        """Run a shell command, return result."""
        return subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=10)

    def _setup_routing(self) -> None:
        """Set up routing rules to direct traffic through TUN."""
        # Create a custom routing table for the TUN
        # Table 100 = proxytuner
        table_id = 100

        # Add table entry (idempotent)
        self._run(["ip", "rule", "add", "fwmark", "0x1", "lookup", str(table_id)])
        # Add default route through TUN in custom table
        self._run([
            "ip", "route", "add", "default",
            "dev", self.tun_name,
            "table", str(table_id),
        ])

        logger.info("Routing rules added (table %d via %s)", table_id, self.tun_name)

    def _remove_routing(self) -> None:
        """Remove routing rules."""
        table_id = 100
        try:
            self._run(["ip", "rule", "del", "fwmark", "0x1", "lookup", str(table_id)])
        except subprocess.CalledProcessError:
            pass
        try:
            self._run(["ip", "route", "flush", "table", str(table_id)])
        except subprocess.CalledProcessError:
            pass

    def _setup_iptables(self) -> None:
        """Set up iptables rules for traffic interception."""
        # Mark packets from the local proxy process so they're NOT re-routed
        # (prevents routing loops)
        pid = str(os.getpid()) if hasattr(os, "getpid") else "0"
        uid = str(os.getuid()) if hasattr(os, "getuid") else "0"

        # MARK all traffic (except from our own process) and route through TUN
        # Using mangle table for MARK
        self._run([
            "iptables", "-t", "mangle", "-A", "PREROUTING",
            "-j", "MARK", "--set-mark", "0x1",
        ])

        # Allow traffic from our process through normally (prevent loop)
        self._run([
            "iptables", "-t", "mangle", "-I", "PREROUTING",
            "-m", "owner", "--uid-owner", uid,
            "-j", "ACCEPT",
        ])

        # Redirect TCP/UDP traffic to the local proxy port
        # This makes the traffic go through our forwarder
        self._run([
            "iptables", "-t", "nat", "-A", "PREROUTING",
            "-p", "tcp", "--syn",
            "-j", "REDIRECT", "--to-port", str(self.listen_port),
        ])

        logger.info("iptables rules added")

    def _remove_iptables(self) -> None:
        """Remove iptables rules."""
        uid = str(os.getuid()) if hasattr(os, "getuid") else "0"
        try:
            self._run([
                "iptables", "-t", "mangle", "-D", "PREROUTING",
                "-j", "MARK", "--set-mark", "0x1",
            ])
        except subprocess.CalledProcessError:
            pass
        try:
            self._run([
                "iptables", "-t", "mangle", "-D", "PREROUTING",
                "-m", "owner", "--uid-owner", uid,
                "-j", "ACCEPT",
            ])
        except subprocess.CalledProcessError:
            pass
        try:
            self._run([
                "iptables", "-t", "nat", "-D", "PREROUTING",
                "-p", "tcp", "--syn",
                "-j", "REDIRECT", "--to-port", str(self.listen_port),
            ])
        except subprocess.CalledProcessError:
            pass

    def add_uid_rule(self, uid: int) -> None:
        """Add a rule to route traffic from a specific UID through the TUN."""
        try:
            # Mark packets from this UID
            self._run([
                "iptables", "-t", "mangle", "-I", "PREROUTING",
                "-m", "owner", "--uid-owner", str(uid),
                "-j", "MARK", "--set-mark", "0x1",
            ])
            logger.info("Added iptables rule for UID %d", uid)
        except subprocess.CalledProcessError as e:
            logger.warning("Failed to add UID rule for %d: %s", uid, e)

    def remove_uid_rule(self, uid: int) -> None:
        """Remove a UID-based routing rule."""
        try:
            self._run([
                "iptables", "-t", "mangle", "-D", "PREROUTING",
                "-m", "owner", "--uid-owner", str(uid),
                "-j", "MARK", "--set-mark", "0x1",
            ])
        except subprocess.CalledProcessError:
            pass

    def is_setup(self) -> bool:
        """Check if firewall rules are currently active."""
        return self._rules_added


# Need os for getuid
import os
