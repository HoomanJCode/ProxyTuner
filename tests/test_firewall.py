"""Unit tests for firewall rule management.

Tests the FirewallManager in isolation using mocked subprocess calls.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from proxy_tuner.firewall import FirewallError, FirewallManager


class TestFirewallManager:
    def test_setup_calls_commands(self) -> None:
        """Test that setup runs the expected commands."""
        fm = FirewallManager(tun_name="proxytun0", listen_port=10808)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            fm.setup()

            # Should have been called at least 4 times (routing + iptables)
            assert mock_run.call_count >= 4

            # Check some key commands were called
            calls = [str(c) for c in mock_run.call_args_list]
            assert any("ip" in c and "rule" in c for c in calls)
            assert any("iptables" in c for c in calls)

    def test_teardown_removes_commands(self) -> None:
        """Test that teardown removes rules."""
        fm = FirewallManager(tun_name="proxytun0", listen_port=10808)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            fm.setup()
            fm.teardown()

            # Should have removal calls
            calls = [str(c) for c in mock_run.call_args_list]
            assert any("del" in c or "-D" in c for c in calls)

    def test_setup_idempotent(self) -> None:
        """Calling setup twice should not double-apply rules."""
        fm = FirewallManager(tun_name="proxytun0", listen_port=10808)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            fm.setup()
            first_count = mock_run.call_count

            fm.setup()  # Second call should be no-op
            assert mock_run.call_count == first_count

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
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            fm.add_uid_rule(1000)

            calls = [str(c) for c in mock_run.call_args_list]
            assert any("1000" in c for c in calls)

    def test_setup_failure_raises(self) -> None:
        import subprocess

        fm = FirewallManager()
        with (
            patch("subprocess.run",
                  side_effect=subprocess.CalledProcessError(1, "ip")),
            pytest.raises(FirewallError),
        ):
            fm.setup()
