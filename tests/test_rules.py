"""Comprehensive unit tests for the rule engine."""

from __future__ import annotations

from proxy_tuner.config import Config, MatchCondition, Rule
from proxy_tuner.rules import (
    _BYPASS_PROCESSES,
    CompiledMatch,
    CompiledRule,
    ConnectionInfo,
    RuleEngine,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(rules: list[Rule]) -> Config:
    """Create a Config with given rules and a 'direct' outbound."""
    return Config(
        outbounds={"direct": {"type": "direct"}},
        rules=rules,
    )


def _conn(**kwargs) -> ConnectionInfo:
    """Create a ConnectionInfo with defaults."""
    defaults = {"dst_ip": "", "dst_port": 0, "dst_host": None, "process_name": None}
    defaults.update(kwargs)
    return ConnectionInfo(**defaults)


# ---------------------------------------------------------------------------
# Process matching
# ---------------------------------------------------------------------------

class TestProcessMatching:
    def test_exact_match(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(process=["firefox"])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(process_name="firefox")) == "direct"

    def test_case_insensitive(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(process=["Firefox"])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(process_name="firefox")) == "direct"
        assert engine.evaluate(_conn(process_name="FIREFOX")) == "direct"

    def test_wildcard_match(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(process=["chrom*"])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(process_name="chrome")) == "direct"
        assert engine.evaluate(_conn(process_name="chromium")) == "direct"
        assert engine.evaluate(_conn(process_name="firefox")) is None

    def test_multiple_process_names(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(process=["firefox", "chrome"])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(process_name="firefox")) == "direct"
        assert engine.evaluate(_conn(process_name="chrome")) == "direct"
        assert engine.evaluate(_conn(process_name="curl")) is None

    def test_windows_exe_suffix(self) -> None:
        """Rule for 'firefox' should also match 'firefox.exe'."""
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(process=["firefox"])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(process_name="firefox.exe")) == "direct"

    def test_no_process_in_conn(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(process=["firefox"])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn()) is None

    def test_no_process_in_rule(self) -> None:
        """Rule with no process constraint should match any process."""
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition()),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(process_name="anything")) == "direct"


# ---------------------------------------------------------------------------
# Process path matching
# ---------------------------------------------------------------------------

class TestProcessPathMatching:
    def test_exact_path(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct",
                 match=MatchCondition(process_path=["/usr/bin/firefox"])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(process_path="/usr/bin/firefox")) == "direct"
        assert engine.evaluate(_conn(process_path="/usr/bin/chrome")) is None

    def test_wildcard_path(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(process_path=["/opt/*/bin/*"])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(process_path="/opt/myapp/bin/tool")) == "direct"
        assert engine.evaluate(_conn(process_path="/usr/bin/tool")) is None

    def test_case_insensitive_path(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(process_path=["/USR/BIN/*"])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(process_path="/usr/bin/firefox")) == "direct"


# ---------------------------------------------------------------------------
# Domain matching
# ---------------------------------------------------------------------------

class TestDomainMatching:
    def test_exact_domain(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(domain=["example.com"])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(dst_host="example.com")) == "direct"
        assert engine.evaluate(_conn(dst_host="other.com")) is None

    def test_wildcard_domain(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(domain=["*.google.com"])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(dst_host="www.google.com")) == "direct"
        assert engine.evaluate(_conn(dst_host="mail.google.com")) == "direct"
        assert engine.evaluate(_conn(dst_host="google.com")) is None

    def test_multiple_domains(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(domain=["*.cn", "*.com.cn"])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(dst_host="example.cn")) == "direct"
        assert engine.evaluate(_conn(dst_host="example.com.cn")) == "direct"
        assert engine.evaluate(_conn(dst_host="example.com")) is None

    def test_case_insensitive_domain(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(domain=["*.Google.Com"])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(dst_host="www.google.com")) == "direct"

    def test_no_host_in_conn(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(domain=["example.com"])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(dst_ip="1.2.3.4")) is None


# ---------------------------------------------------------------------------
# Domain regex matching
# ---------------------------------------------------------------------------

class TestDomainRegexMatching:
    def test_domain_regex(self) -> None:
        # Pattern matches any host with ".cdn." substring
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(
                domain_regex=[r".*\.cdn\..*"],
            )),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(dst_host="assets.cdn.example.com")) == "direct"
        assert engine.evaluate(_conn(dst_host="www.cdn.io")) == "direct"
        assert engine.evaluate(_conn(dst_host="cdn.example.com")) is None  # no dot before cdn
        assert engine.evaluate(_conn(dst_host="example.com")) is None

    def test_domain_regex_anchored(self) -> None:
        # ^cdn\. ensures "cdn." only at start
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(
                domain_regex=[r"^cdn\.com$"],
            )),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(dst_host="cdn.com")) == "direct"
        assert engine.evaluate(_conn(dst_host="www.cdn.com")) is None

    def test_domain_regex_anchored_prefix(self) -> None:
        # ^cdn\. matches prefix
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(
                domain_regex=[r"^cdn\."],
            )),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(dst_host="cdn.example.com")) == "direct"
        assert engine.evaluate(_conn(dst_host="www.cdn.example.com")) is None


# ---------------------------------------------------------------------------
# IP matching
# ---------------------------------------------------------------------------

class TestIPMatching:
    def test_exact_ip(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(ip=["1.2.3.4"])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(dst_ip="1.2.3.4")) == "direct"
        assert engine.evaluate(_conn(dst_ip="1.2.3.5")) is None

    def test_multiple_ips(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(ip=["1.2.3.4", "5.6.7.8"])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(dst_ip="1.2.3.4")) == "direct"
        assert engine.evaluate(_conn(dst_ip="5.6.7.8")) == "direct"
        assert engine.evaluate(_conn(dst_ip="9.9.9.9")) is None


# ---------------------------------------------------------------------------
# IP CIDR matching
# ---------------------------------------------------------------------------

class TestIPCIDRMatching:
    def test_cidr_match(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(ip_cidr=["10.0.0.0/8"])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(dst_ip="10.0.0.1")) == "direct"
        assert engine.evaluate(_conn(dst_ip="10.255.255.255")) == "direct"
        assert engine.evaluate(_conn(dst_ip="11.0.0.1")) is None

    def test_multiple_cidrs(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(
                ip_cidr=["192.168.0.0/16", "10.0.0.0/8"],
            )),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(dst_ip="192.168.1.1")) == "direct"
        assert engine.evaluate(_conn(dst_ip="10.0.0.1")) == "direct"
        assert engine.evaluate(_conn(dst_ip="172.16.0.1")) is None

    def test_cidr_exact_network(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(ip_cidr=["192.168.1.0/24"])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(dst_ip="192.168.1.0")) == "direct"
        assert engine.evaluate(_conn(dst_ip="192.168.1.255")) == "direct"
        assert engine.evaluate(_conn(dst_ip="192.168.2.0")) is None

    def test_loopback_cidr(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(ip_cidr=["127.0.0.0/8"])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(dst_ip="127.0.0.1")) == "direct"


# ---------------------------------------------------------------------------
# IP regex matching
# ---------------------------------------------------------------------------

class TestIPRegexMatching:
    def test_ip_regex(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(
                ip_regex=[r"^10\.\d+\.\d+\.\d+$"],
            )),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(dst_ip="10.1.2.3")) == "direct"
        assert engine.evaluate(_conn(dst_ip="11.1.2.3")) is None

    def test_private_ip_regex(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(
                ip_regex=[r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)"],
            )),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(dst_ip="10.0.0.1")) == "direct"
        assert engine.evaluate(_conn(dst_ip="172.16.0.1")) == "direct"
        assert engine.evaluate(_conn(dst_ip="192.168.1.1")) == "direct"
        assert engine.evaluate(_conn(dst_ip="8.8.8.8")) is None


# ---------------------------------------------------------------------------
# Port matching
# ---------------------------------------------------------------------------

class TestPortMatching:
    def test_exact_port(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(port=[443])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(dst_port=443)) == "direct"
        assert engine.evaluate(_conn(dst_port=80)) is None

    def test_multiple_ports(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(port=[80, 443, 8080])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(dst_port=80)) == "direct"
        assert engine.evaluate(_conn(dst_port=443)) == "direct"
        assert engine.evaluate(_conn(dst_port=8080)) == "direct"
        assert engine.evaluate(_conn(dst_port=3000)) is None

    def test_port_zero_not_matched(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(port=[0])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(dst_port=0)) is None


# ---------------------------------------------------------------------------
# Port range matching
# ---------------------------------------------------------------------------

class TestPortRangeMatching:
    def test_port_range(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(port_range=["8000-9000"])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(dst_port=8000)) == "direct"
        assert engine.evaluate(_conn(dst_port=8500)) == "direct"
        assert engine.evaluate(_conn(dst_port=9000)) == "direct"
        assert engine.evaluate(_conn(dst_port=7999)) is None
        assert engine.evaluate(_conn(dst_port=9001)) is None

    def test_multiple_ranges(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct",
                 match=MatchCondition(port_range=["1000-2000", "8000-9000"])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(dst_port=1500)) == "direct"
        assert engine.evaluate(_conn(dst_port=8500)) == "direct"
        assert engine.evaluate(_conn(dst_port=5000)) is None


# ---------------------------------------------------------------------------
# URL regex matching
# ---------------------------------------------------------------------------

class TestURLRegexMatching:
    def test_url_regex(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(
                url_regex=[r"https?://.*\.example\.com/.*"],
            )),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(url="https://api.example.com/v1")) == "direct"
        assert engine.evaluate(_conn(url="http://cdn.example.com/img.png")) == "direct"
        assert engine.evaluate(_conn(url="https://other.com/page")) is None


# ---------------------------------------------------------------------------
# AND combination (all fields must match)
# ---------------------------------------------------------------------------

class TestANDCombination:
    def test_process_and_domain(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(
                process=["firefox"],
                domain=["*.google.com"],
            )),
        ])
        engine = RuleEngine(config)
        # Both match
        assert engine.evaluate(_conn(process_name="firefox", dst_host="www.google.com")) == "direct"
        # Only process matches
        assert engine.evaluate(_conn(process_name="firefox", dst_host="example.com")) is None
        # Only domain matches
        assert engine.evaluate(_conn(process_name="chrome", dst_host="www.google.com")) is None
        # Neither matches
        assert engine.evaluate(_conn(process_name="curl", dst_host="example.com")) is None

    def test_domain_and_port(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(
                domain=["*.google.com"],
                port=[443],
            )),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(dst_host="www.google.com", dst_port=443)) == "direct"
        assert engine.evaluate(_conn(dst_host="www.google.com", dst_port=80)) is None
        assert engine.evaluate(_conn(dst_host="example.com", dst_port=443)) is None

    def test_ip_and_port(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(
                ip_cidr=["10.0.0.0/8"],
                port=[443],
            )),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(dst_ip="10.0.0.1", dst_port=443)) == "direct"
        assert engine.evaluate(_conn(dst_ip="10.0.0.1", dst_port=80)) is None
        assert engine.evaluate(_conn(dst_ip="8.8.8.8", dst_port=443)) is None

    def test_process_and_ip_and_port(self) -> None:
        config = _make_config([
            Rule(name="r1", outbound="direct", match=MatchCondition(
                process=["curl"],
                ip_cidr=["10.0.0.0/8"],
                port=[443],
            )),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(
            process_name="curl", dst_ip="10.0.0.1", dst_port=443,
        )) == "direct"
        assert engine.evaluate(_conn(
            process_name="curl", dst_ip="10.0.0.1", dst_port=80,
        )) is None


# ---------------------------------------------------------------------------
# Priority and first-match-wins
# ---------------------------------------------------------------------------

class TestPriority:
    def test_first_match_wins(self) -> None:
        config = _make_config([
            Rule(name="low-pri", priority=100, outbound="direct",
                 match=MatchCondition()),
            Rule(name="high-pri", priority=10, outbound="direct",
                 match=MatchCondition(process=["firefox"])),
        ])
        engine = RuleEngine(config)
        result = engine.evaluate_rules(_conn(process_name="firefox"))
        assert result is not None
        assert result[0] == "high-pri"

    def test_priority_ordering(self) -> None:
        config = _make_config([
            Rule(name="third", priority=30, outbound="direct",
                 match=MatchCondition()),
            Rule(name="first", priority=10, outbound="direct",
                 match=MatchCondition(process=["firefox"])),
            Rule(name="second", priority=20, outbound="direct",
                 match=MatchCondition(domain=["*.com"])),
        ])
        engine = RuleEngine(config)

        # firefox matches "first" (priority 10)
        result = engine.evaluate_rules(_conn(process_name="firefox"))
        assert result is not None
        assert result[0] == "first"

        # google.com matches "second" (priority 20) since it doesn't match process
        result = engine.evaluate_rules(_conn(dst_host="google.com"))
        assert result is not None
        assert result[0] == "second"

        # curl matches "third" (priority 30, catch-all)
        result = engine.evaluate_rules(_conn(process_name="curl"))
        assert result is not None
        assert result[0] == "third"


# ---------------------------------------------------------------------------
# Catch-all rules
# ---------------------------------------------------------------------------

class TestCatchAll:
    def test_empty_match_catches_everything(self) -> None:
        config = _make_config([
            Rule(name="default", priority=100, outbound="direct", match=MatchCondition()),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(process_name="anything")) == "direct"
        assert engine.evaluate(_conn(dst_host="example.com")) == "direct"
        assert engine.evaluate(_conn(dst_ip="1.2.3.4", dst_port=443)) == "direct"

    def test_disabled_rule_skipped(self) -> None:
        config = _make_config([
            Rule(name="disabled", priority=10, enabled=False, outbound="direct",
                 match=MatchCondition(process=["firefox"])),
            Rule(name="default", priority=100, outbound="direct", match=MatchCondition()),
        ])
        engine = RuleEngine(config)
        # Disabled rule should be skipped, catch-all should match
        result = engine.evaluate_rules(_conn(process_name="firefox"))
        assert result is not None
        assert result[0] == "default"

    def test_no_rules_returns_none(self) -> None:
        config = Config(outbounds={"direct": {"type": "direct"}}, rules=[])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(process_name="firefox")) is None


# ---------------------------------------------------------------------------
# Engine update
# ---------------------------------------------------------------------------

class TestEngineUpdate:
    def test_update_rebuilds_rules(self) -> None:
        config = _make_config([
            Rule(name="r1", priority=10, outbound="direct",
                 match=MatchCondition(process=["firefox"])),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(process_name="firefox")) == "direct"

        # Update config with different rules
        new_config = _make_config([
            Rule(name="r2", priority=10, outbound="direct",
                 match=MatchCondition(process=["chrome"])),
        ])
        engine.update(new_config)
        assert engine.evaluate(_conn(process_name="firefox")) is None
        assert engine.evaluate(_conn(process_name="chrome")) == "direct"


# ---------------------------------------------------------------------------
# CompiledMatch edge cases
# ---------------------------------------------------------------------------

class TestCompiledMatch:
    def test_invalid_regex_ignored(self) -> None:
        """Invalid regex patterns should be silently ignored."""
        match = MatchCondition(domain_regex=["[invalid"])
        compiled = CompiledMatch(match)
        assert compiled.domain_regex == []

    def test_invalid_cidr_ignored(self) -> None:
        match = MatchCondition(ip_cidr=["999.999.999.999/24"])
        compiled = CompiledMatch(match)
        assert compiled.ip_networks == []

    def test_invalid_port_range_ignored(self) -> None:
        match = MatchCondition(port_range=["not-a-range"])
        compiled = CompiledMatch(match)
        assert compiled.port_range == []

    def test_empty_match_is_catch_all(self) -> None:
        rule = CompiledRule(Rule(match=MatchCondition()))
        assert rule.is_catch_all is True

    def test_non_empty_match_not_catch_all(self) -> None:
        rule = CompiledRule(Rule(match=MatchCondition(process=["firefox"])))
        assert rule.is_catch_all is False


# ---------------------------------------------------------------------------
# Bypassed processes (hardcoded loop prevention)
# ---------------------------------------------------------------------------

class TestBypassProcesses:
    """V2Portal and other bypassed processes must always route direct."""

    def test_v2portal_bypassed(self) -> None:
        config = _make_config([
            Rule(name="proxy", priority=10, outbound="some-proxy",
                 match=MatchCondition(process=["firefox"])),
            Rule(name="default", priority=100, outbound="some-proxy",
                 match=MatchCondition()),
        ])
        engine = RuleEngine(config)
        # Even though there is no rule targeting v2portal, it should
        # always resolve to "direct" via the hardcoded bypass.
        assert engine.evaluate(_conn(process_name="v2portal")) == "direct"

    def test_v2portal_case_insensitive(self) -> None:
        config = _make_config([
            Rule(name="default", priority=100, outbound="some-proxy",
                 match=MatchCondition()),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(process_name="V2Portal")) == "direct"
        assert engine.evaluate(_conn(process_name="V2PORTAL")) == "direct"

    def test_bypass_prevents_loop(self) -> None:
        """A catch-all proxy rule must not capture v2portal traffic."""
        config = _make_config([
            Rule(name="catch-all", priority=1, outbound="my-vpn",
                 match=MatchCondition()),
        ])
        engine = RuleEngine(config)
        # The bypass fires before any user rules, so v2portal goes direct.
        assert engine.evaluate(_conn(process_name="v2portal")) == "direct"

    def test_other_processes_not_bypassed(self) -> None:
        config = _make_config([
            Rule(name="default", priority=100, outbound="my-proxy",
                 match=MatchCondition()),
        ])
        engine = RuleEngine(config)
        assert engine.evaluate(_conn(process_name="firefox")) == "my-proxy"
        assert engine.evaluate(_conn(process_name="chrome")) == "my-proxy"

    def test_all_bypass_processes_in_set(self) -> None:
        """Every process in _BYPASS_PROCESSES goes direct."""
        config = _make_config([
            Rule(name="default", priority=100, outbound="my-proxy",
                 match=MatchCondition()),
        ])
        engine = RuleEngine(config)
        for proc in _BYPASS_PROCESSES:
            assert engine.evaluate(_conn(process_name=proc)) == "direct"


# ---------------------------------------------------------------------------
# Complex real-world scenarios
# ---------------------------------------------------------------------------

class TestRealWorldScenarios:
    def test_browsers_to_vpn_local_direct(self) -> None:
        """Browsers go through VPN, local traffic stays direct."""
        config = _make_config([
            Rule(name="local", priority=1, outbound="direct", match=MatchCondition(
                ip_cidr=["192.168.0.0/16", "10.0.0.0/8", "127.0.0.0/8"],
            )),
            Rule(name="browsers", priority=10, outbound="direct", match=MatchCondition(
                process=["firefox", "chrome", "chromium", "brave"],
            )),
            Rule(name="default", priority=100, outbound="direct", match=MatchCondition()),
        ])
        engine = RuleEngine(config)

        # Local traffic → direct (priority 1)
        result = engine.evaluate_rules(_conn(process_name="firefox", dst_ip="192.168.1.1"))
        assert result is not None
        assert result[0] == "local"

        # Browser external traffic → browsers rule
        result = engine.evaluate_rules(_conn(process_name="firefox", dst_ip="8.8.8.8"))
        assert result is not None
        assert result[0] == "browsers"

        # Non-browser external → default
        result = engine.evaluate_rules(_conn(process_name="curl", dst_ip="8.8.8.8"))
        assert result is not None
        assert result[0] == "default"

    def test_blocked_sites_priority(self) -> None:
        """Blocked sites go through proxy regardless of process."""
        config = _make_config([
            Rule(name="blocked", priority=1, outbound="direct", match=MatchCondition(
                domain=["*.blocked.com", "*.restricted.org"],
            )),
            Rule(name="default", priority=100, outbound="direct", match=MatchCondition()),
        ])
        engine = RuleEngine(config)

        assert engine.evaluate(_conn(dst_host="www.blocked.com")) == "direct"
        assert engine.evaluate(_conn(dst_host="site.restricted.org")) == "direct"
        assert engine.evaluate(_conn(dst_host="example.com")) == "direct"

    def test_dev_tools_direct_browsers_proxy(self) -> None:
        """Dev tools direct, browsers through proxy."""
        config = _make_config([
            Rule(name="dev-tools", priority=10, outbound="direct", match=MatchCondition(
                process=["git", "cargo", "npm", "pip", "go"],
            )),
            Rule(name="browsers", priority=20, outbound="direct", match=MatchCondition(
                process=["firefox", "chrome"],
            )),
            Rule(name="default", priority=100, outbound="direct", match=MatchCondition()),
        ])
        engine = RuleEngine(config)

        assert engine.evaluate_rules(_conn(process_name="git"))[0] == "dev-tools"
        assert engine.evaluate_rules(_conn(process_name="firefox"))[0] == "browsers"
        assert engine.evaluate_rules(_conn(process_name="curl"))[0] == "default"
