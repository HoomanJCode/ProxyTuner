"""Rule engine — evaluates traffic connections against routing rules.

All match conditions in a rule are AND-combined (all must match).
Within a list field (e.g. process, domain), values are OR-combined (any match suffices).
Rules are evaluated in priority order (lower number = higher priority).
First match wins.
"""

from __future__ import annotations

import contextlib
import fnmatch
import ipaddress
import re
from dataclasses import dataclass

from proxy_tuner.config import Config, MatchCondition, Outbound, Rule


@dataclass
class ConnectionInfo:
    """Information about a network connection for rule matching."""

    dst_ip: str = ""
    dst_port: int = 0
    dst_host: str | None = None
    process_name: str | None = None
    process_path: str | None = None
    url: str | None = None
    protocol: str = "tcp"


class CompiledMatch:
    """Pre-compiled match patterns for efficient repeated evaluation."""

    def __init__(self, match: MatchCondition) -> None:
        self.process: list[str] = match.process
        self.process_path: list[str] = match.process_path
        self.domain: list[str] = match.domain
        self.ip: list[str] = match.ip
        self.port: list[int] = match.port
        self.port_range: list[tuple[int, int]] = self._parse_port_ranges(match.port_range)
        self.url_regex: list[re.Pattern] = self._compile_patterns(match.url_regex)
        self.domain_regex: list[re.Pattern] = self._compile_patterns(match.domain_regex)
        self.ip_regex: list[re.Pattern] = self._compile_patterns(match.ip_regex)
        self.ip_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in match.ip_cidr:
            with contextlib.suppress(ValueError):
                self.ip_networks.append(ipaddress.ip_network(cidr, strict=False))

    @staticmethod
    def _compile_patterns(patterns: list[str]) -> list[re.Pattern]:
        compiled: list[re.Pattern] = []
        for p in patterns:
            with contextlib.suppress(re.error):
                compiled.append(re.compile(p))
        return compiled

    @staticmethod
    def _parse_port_ranges(ranges: list[str]) -> list[tuple[int, int]]:
        result: list[tuple[int, int]] = []
        for r in ranges:
            parts = r.split("-", 1)
            if len(parts) == 2:
                try:
                    lo, hi = int(parts[0]), int(parts[1])
                    if 1 <= lo <= 65535 and 1 <= hi <= 65535 and lo <= hi:
                        result.append((lo, hi))
                except ValueError:
                    pass
        return result


class CompiledRule:
    """A rule with pre-compiled patterns for fast matching."""

    def __init__(self, rule: Rule) -> None:
        self.name = rule.name
        self.enabled = rule.enabled
        self.priority = rule.priority
        self.outbound = rule.outbound
        self.match = CompiledMatch(rule.match)
        self._is_empty = rule.match.is_empty

    @property
    def is_catch_all(self) -> bool:
        """Check if this is a catch-all rule (empty match)."""
        return self._is_empty


class RuleEngine:
    """Evaluates connections against rules to determine the outbound.

    Rules are sorted by priority (ascending). First match wins.
    """

    def __init__(self, config: Config) -> None:
        self._rules: list[CompiledRule] = []
        self._outbounds = config.outbounds
        self._rebuild(config.rules)

    def _rebuild(self, rules: list[Rule]) -> None:
        """Rebuild the compiled rules list."""
        self._rules = [CompiledRule(r) for r in rules if r.enabled]
        self._rules.sort(key=lambda r: r.priority)

    def update(self, config: Config) -> None:
        """Rebuild from updated config."""
        self._outbounds = config.outbounds
        self._rebuild(config.rules)

    def evaluate(self, conn: ConnectionInfo) -> str | None:
        """Evaluate a connection against rules.

        Returns the outbound name or None if no rule matched.
        """
        for rule in self._rules:
            if self._match_rule(rule, conn):
                return rule.outbound
        return None

    def evaluate_with_outbound(self, conn: ConnectionInfo) -> Outbound | None:
        """Evaluate and return the actual Outbound object."""
        name = self.evaluate(conn)
        if name is None:
            return None
        return self._outbounds.get(name)

    def evaluate_rules(self, conn: ConnectionInfo) -> tuple[str, str] | None:
        """Evaluate and return (rule_name, outbound_name) for matched rule."""
        for rule in self._rules:
            if self._match_rule(rule, conn):
                return (rule.name, rule.outbound)
        return None

    def _match_rule(self, rule: CompiledRule, conn: ConnectionInfo) -> bool:
        """Check if a connection matches a compiled rule."""
        m = rule.match

        # AND combination: all non-empty fields must match
        if m.process and not self._match_process(m.process, conn):
            return False
        if m.process_path and not self._match_process_path(m.process_path, conn):
            return False
        if (m.domain or m.domain_regex) and not self._match_domain(m.domain, m.domain_regex, conn):
            return False
        if m.ip and not self._match_ip(m.ip, conn):
            return False
        if m.ip_networks and not self._match_ip_cidr(m.ip_networks, conn):
            return False
        if m.ip_regex and not self._match_ip_regex(m.ip_regex, conn):
            return False
        if m.port and not self._match_port(m.port, conn):
            return False
        if m.port_range and not self._match_port_range(m.port_range, conn):
            return False
        return not (m.url_regex and not self._match_url_regex(m.url_regex, conn))

    # ------------------------------------------------------------------
    # Individual matchers — each returns True if ANY value in the list
    # matches (OR combination within a field).
    # ------------------------------------------------------------------

    def _match_process(self, patterns: list[str], conn: ConnectionInfo) -> bool:
        """Match process name. Supports exact match and fnmatch wildcards."""
        if not conn.process_name:
            return False
        name = conn.process_name.lower()
        for pattern in patterns:
            if fnmatch.fnmatch(name, pattern.lower()):
                return True
            # Also match without extension on Windows
            if name.endswith(".exe") and fnmatch.fnmatch(name[:-4], pattern.lower()):
                return True
        return False

    def _match_process_path(self, patterns: list[str], conn: ConnectionInfo) -> bool:
        """Match process path. Supports fnmatch wildcards."""
        if not conn.process_path:
            return False
        path = conn.process_path.lower()
        return any(fnmatch.fnmatch(path, pattern.lower()) for pattern in patterns)

    def _match_domain(
        self,
        domains: list[str],
        domain_regex: list[re.Pattern],
        conn: ConnectionInfo,
    ) -> bool:
        """Match domain. Supports wildcard patterns and compiled regex."""
        if not conn.dst_host:
            return False
        host = conn.dst_host.lower()

        # Wildcard matching
        for pattern in domains:
            if fnmatch.fnmatch(host, pattern.lower()):
                return True

        # Regex matching
        return any(regex.search(host) for regex in domain_regex)

    def _match_ip(self, ips: list[str], conn: ConnectionInfo) -> bool:
        """Match exact IP address."""
        if not conn.dst_ip:
            return False
        return any(conn.dst_ip == ip for ip in ips)

    def _match_ip_cidr(
        self,
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
        conn: ConnectionInfo,
    ) -> bool:
        """Match IP against CIDR ranges."""
        if not conn.dst_ip:
            return False
        try:
            addr = ipaddress.ip_address(conn.dst_ip)
        except ValueError:
            return False
        return any(addr in network for network in networks)

    def _match_ip_regex(self, patterns: list[re.Pattern], conn: ConnectionInfo) -> bool:
        """Match IP against regex patterns."""
        if not conn.dst_ip:
            return False
        return any(regex.search(conn.dst_ip) for regex in patterns)

    def _match_port(self, ports: list[int], conn: ConnectionInfo) -> bool:
        """Match exact port."""
        if conn.dst_port <= 0:
            return False
        return conn.dst_port in ports

    def _match_port_range(self, ranges: list[tuple[int, int]], conn: ConnectionInfo) -> bool:
        """Match port against ranges."""
        if conn.dst_port <= 0:
            return False
        return any(lo <= conn.dst_port <= hi for lo, hi in ranges)

    def _match_url_regex(self, patterns: list[re.Pattern], conn: ConnectionInfo) -> bool:
        """Match URL against regex patterns."""
        if not conn.url:
            return False
        return any(regex.search(conn.url) for regex in patterns)


def match_condition_matches(match: MatchCondition, conn: ConnectionInfo) -> bool:
    """Check if a single MatchCondition matches a connection.

    Standalone function for use outside RuleEngine (e.g., CLI rule test).
    """
    compiled = CompiledRule(Rule(match=match))
    engine = RuleEngine.__new__(RuleEngine)
    return engine._match_rule(compiled, conn)
