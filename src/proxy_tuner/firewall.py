"""Linux iptables rules for transparent TCP proxying."""

from __future__ import annotations

import contextlib
import logging
import os
import subprocess
from dataclasses import dataclass, field

logger = logging.getLogger("proxy_tuner.firewall")

CHAIN = "PROXYTUNER"


class FirewallError(Exception):
    """Firewall rule management error."""


@dataclass
class FirewallManager:
    """Redirect locally generated TCP connections to the proxy listener.

    The proxy process UID is exempted so its upstream connections do not loop
    back into the listener. Rules live in a dedicated chain for safe cleanup.
    """

    tun_name: str = "proxytun0"  # Retained for config compatibility.
    tun_address: str = "10.0.0.1"
    listen_port: int = 10808
    bypass_uids: list[int] = field(default_factory=list)
    bypass_ports: list[int] = field(default_factory=list)
    _rules_added: bool = False

    def setup(self) -> None:
        """Install an IPv4 OUTPUT redirect, rolling back partial setup."""
        if self._rules_added:
            return

        try:
            self._setup_iptables()
            self._rules_added = True
            logger.info("Local TCP traffic redirected to port %d", self.listen_port)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
            self._remove_iptables()
            raise FirewallError(f"Failed to set up transparent proxy rules: {e}") from e

    def teardown(self) -> None:
        """Remove only ProxyTuner's redirect rules."""
        if not self._rules_added:
            return
        self._remove_iptables()
        self._rules_added = False

    def _run(self, cmd: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=10)

    @staticmethod
    def _rule_exists(rule: list[str]) -> bool:
        try:
            subprocess.run(
                ["iptables", "-t", "nat", "-C", *rule],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            return True
        except subprocess.CalledProcessError:
            return False
        except FileNotFoundError:
            return False

    def _setup_iptables(self) -> None:
        chain = ["-t", "nat", CHAIN]
        try:
            self._run(["iptables", "-t", "nat", "-N", CHAIN])
        except subprocess.CalledProcessError:
            # A prior crashed process may have left our chain behind.
            self._run(["iptables", *chain[:2], "-F", CHAIN])

        proxy_uid = os.getuid() if hasattr(os, "getuid") else 0
        for uid in dict.fromkeys([proxy_uid, *self.bypass_uids]):
            self._run([
                "iptables", "-t", "nat", "-A", CHAIN,
                "-m", "owner", "--uid-owner", str(uid), "-j", "RETURN",
            ])
        for port in dict.fromkeys([self.listen_port, *self.bypass_ports]):
            self._run([
                "iptables", "-t", "nat", "-A", CHAIN,
                "-p", "tcp", "--dport", str(port), "-j", "RETURN",
            ])
        self._run([
            "iptables", "-t", "nat", "-A", CHAIN,
            "-p", "tcp", "-j", "REDIRECT", "--to-ports", str(self.listen_port),
        ])

        output_rule = ["OUTPUT", "-p", "tcp", "-j", CHAIN]
        if not self._rule_exists(output_rule):
            self._run(["iptables", "-t", "nat", "-I", *output_rule])

    def _remove_iptables(self) -> None:
        output_rule = ["OUTPUT", "-p", "tcp", "-j", CHAIN]
        for cmd in (
            ["iptables", "-t", "nat", "-D", *output_rule],
            ["iptables", "-t", "nat", "-F", CHAIN],
            ["iptables", "-t", "nat", "-X", CHAIN],
        ):
            with contextlib.suppress(subprocess.CalledProcessError, FileNotFoundError):
                self._run(cmd)

    def add_uid_rule(self, uid: int) -> None:
        """Kept for API compatibility; transparent routing currently uses a process UID bypass."""
        logger.debug("Per-UID routing is not implemented (requested UID %d)", uid)

    def remove_uid_rule(self, uid: int) -> None:
        """Kept for API compatibility; no per-UID rule is installed."""
        logger.debug("No per-UID rule to remove for UID %d", uid)

    def is_setup(self) -> bool:
        """Return whether setup completed in this process."""
        return self._rules_added
