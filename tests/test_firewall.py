"""Unit tests for firewall rule management.

Tests the FirewallManager in isolation using mocked subprocess calls.
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from proxy_tuner.firewall import FirewallError, FirewallManager


class TestFirewallManager:
    def test_setup_calls_commands(self) -> None:
        """Install a dedicated OUTPUT redirect chain and owner bypass."""
        fm = FirewallManager(tun_name="proxytun0", listen_port=10808)

        with patch("subprocess.run") as mock_run:
            def run(cmd, **kwargs):
                if "-C" in cmd:
                    raise subprocess.CalledProcessError(1, cmd)
                return MagicMock(returncode=0, stdout="", stderr="")

            mock_run.side_effect = run
            fm.setup()

            calls = [call.args[0] for call in mock_run.call_args_list]
            assert any(c[:5] == ["iptables", "-t", "nat", "-N", "PROXYTUNER"] for c in calls)
            assert any("--uid-owner" in c and "RETURN" in c for c in calls)
            assert any("--dport" in c and "RETURN" in c for c in calls)
            assert any("REDIRECT" in c and "10808" in c for c in calls)
            assert any("-I" in c and "OUTPUT" in c for c in calls)

    def test_teardown_removes_commands(self) -> None:
        """Test that teardown removes rules."""
        fm = FirewallManager(tun_name="proxytun0", listen_port=10808)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            fm.setup()
            fm.teardown()

            # Should have removal calls
            calls = [call.args[0] for call in mock_run.call_args_list]
            assert any("-D" in c and "OUTPUT" in c for c in calls)
            assert any("-X" in c and "PROXYTUNER" in c for c in calls)

    def test_setup_idempotent(self) -> None:
        """Calling setup twice should not double-apply rules."""
        fm = FirewallManager(tun_name="proxytun0", listen_port=10808)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            fm.setup()
            first_count = mock_run.call_count

            fm.setup()  # Second call should be no-op
            assert mock_run.call_count == first_count

    def test_additional_bypass_uids(self) -> None:
        fm = FirewallManager(bypass_uids=[1000, 1001], bypass_ports=[1080, 1081])
        with patch("subprocess.run") as mock_run:
            def run(cmd, **kwargs):
                if "-C" in cmd:
                    raise subprocess.CalledProcessError(1, cmd)
                return MagicMock(returncode=0, stdout="", stderr="")

            mock_run.side_effect = run
            fm.setup()
            owner_rules = [
                entry.args[0]
                for entry in mock_run.call_args_list
                if "--uid-owner" in entry.args[0]
            ]
            assert any("1000" in rule for rule in owner_rules)
            assert any("1001" in rule for rule in owner_rules)
            bypass_rules = [
                entry.args[0]
                for entry in mock_run.call_args_list
                if "--dport" in entry.args[0]
            ]
            assert any("1080" in rule for rule in bypass_rules)
            assert any("1081" in rule for rule in bypass_rules)

    def test_teardown_without_setup_is_noop(self) -> None:
        fm = FirewallManager()
        with patch("subprocess.run") as mock_run:
            fm.teardown()
            mock_run.assert_not_called()

    def test_is_setup(self) -> None:
        fm = FirewallManager()
        assert fm.is_setup() is False

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            fm.setup()
            assert fm.is_setup() is True

            fm.teardown()
            assert fm.is_setup() is False

    def test_add_uid_rule(self) -> None:
        fm = FirewallManager()
        fm._rules_added = True  # Pretend rules are set up

        with patch("subprocess.run") as mock_run:
            fm.add_uid_rule(1000)
            mock_run.assert_not_called()

    def test_setup_failure_raises(self) -> None:
        import subprocess

        fm = FirewallManager()
        with (
            patch("subprocess.run",
                  side_effect=subprocess.CalledProcessError(1, "ip")),
            pytest.raises(FirewallError),
        ):
            fm.setup()
