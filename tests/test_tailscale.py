"""Tests for Tailscale integration functions."""

import json
from unittest.mock import MagicMock, patch

import pytest

from tobcloud.config import TailscaleConfig
from tobcloud.main import (
    check_local_tailscale,
    is_tailscale_ip,
    lock_down_to_tailscale,
    run_tailscale_up,
    verify_tailscale_ssh,
)


class TestIsTailscaleIP:
    """Tests for is_tailscale_ip function."""

    def test_valid_tailscale_ip_lower_bound(self):
        """Test lower bound of CGNAT range (100.64.0.0)."""
        assert is_tailscale_ip("100.64.0.0") is True
        assert is_tailscale_ip("100.64.0.1") is True

    def test_valid_tailscale_ip_upper_bound(self):
        """Test upper bound of CGNAT range (100.127.255.255)."""
        assert is_tailscale_ip("100.127.255.255") is True
        assert is_tailscale_ip("100.127.0.1") is True

    def test_valid_tailscale_ip_middle_range(self):
        """Test middle of CGNAT range."""
        assert is_tailscale_ip("100.100.50.25") is True
        assert is_tailscale_ip("100.80.1.1") is True

    def test_invalid_ip_below_cgnat_range(self):
        """Test IPs below CGNAT range (100.0.0.0 - 100.63.255.255)."""
        assert is_tailscale_ip("100.0.0.1") is False
        assert is_tailscale_ip("100.63.255.255") is False

    def test_invalid_ip_above_cgnat_range(self):
        """Test IPs above CGNAT range (100.128.0.0+)."""
        assert is_tailscale_ip("100.128.0.0") is False
        assert is_tailscale_ip("100.200.1.1") is False

    def test_invalid_ip_wrong_first_octet(self):
        """Test IPs with wrong first octet."""
        assert is_tailscale_ip("192.168.1.1") is False
        assert is_tailscale_ip("10.0.0.1") is False
        assert is_tailscale_ip("172.16.0.1") is False

    def test_invalid_ip_format_too_few_octets(self):
        """Test invalid IP format with too few octets."""
        assert is_tailscale_ip("100.64.0") is False
        assert is_tailscale_ip("100.64") is False
        assert is_tailscale_ip("100") is False

    def test_invalid_ip_format_too_many_octets(self):
        """Test invalid IP format with too many octets."""
        assert is_tailscale_ip("100.64.0.1.5") is False

    def test_invalid_ip_format_non_numeric(self):
        """Test invalid IP format with non-numeric values."""
        assert is_tailscale_ip("100.64.abc.1") is False
        assert is_tailscale_ip("foo.bar.baz.qux") is False

    def test_invalid_ip_format_out_of_range_octets(self):
        """Test IPs with octets out of 0-255 range."""
        assert is_tailscale_ip("100.64.256.1") is False
        assert is_tailscale_ip("100.64.0.-1") is False

    def test_invalid_ip_empty_string(self):
        """Test empty string."""
        assert is_tailscale_ip("") is False

    def test_invalid_ip_none_type(self):
        """Test None type (should return False, not raise)."""
        assert is_tailscale_ip(None) is False  # type: ignore


class TestCheckLocalTailscale:
    """Tests for check_local_tailscale function."""

    @patch("tobcloud.main.subprocess.run")
    def test_tailscale_running(self, mock_run):
        """Test when Tailscale is running locally."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"BackendState": "Running"}).encode("utf-8"),
        )
        assert check_local_tailscale() is True

    @patch("tobcloud.main.subprocess.run")
    def test_tailscale_not_running(self, mock_run):
        """Test when Tailscale is installed but not running."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"BackendState": "Stopped"}).encode("utf-8"),
        )
        assert check_local_tailscale() is False

    @patch("tobcloud.main.subprocess.run")
    def test_tailscale_command_fails(self, mock_run):
        """Test when tailscale command returns non-zero."""
        mock_run.return_value = MagicMock(returncode=1)
        assert check_local_tailscale() is False

    @patch("tobcloud.main.subprocess.run")
    def test_tailscale_not_installed(self, mock_run):
        """Test when tailscale is not installed."""
        mock_run.side_effect = FileNotFoundError()
        assert check_local_tailscale() is False

    @patch("tobcloud.main.subprocess.run")
    def test_tailscale_timeout(self, mock_run):
        """Test when tailscale command times out."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("tailscale", 5)
        assert check_local_tailscale() is False

    @patch("tobcloud.main.subprocess.run")
    def test_invalid_json_response(self, mock_run):
        """Test when tailscale returns invalid JSON."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"not valid json",
        )
        assert check_local_tailscale() is False


class TestRunTailscaleUp:
    """Tests for run_tailscale_up function."""

    @patch("tobcloud.main.subprocess.run")
    def test_extracts_auth_url(self, mock_run):
        """Test that auth URL is extracted from output."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"To authenticate, visit:\n\n\thttps://login.tailscale.com/a/abc123\n",
        )
        url = run_tailscale_up("tobcloud.test")
        assert url == "https://login.tailscale.com/a/abc123"

    @patch("tobcloud.main.subprocess.run")
    def test_strips_trailing_punctuation(self, mock_run):
        """Test that trailing punctuation is stripped from URL."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"Visit: https://login.tailscale.com/a/abc123.\n",
        )
        url = run_tailscale_up("tobcloud.test")
        assert url == "https://login.tailscale.com/a/abc123"

    @patch("tobcloud.main.subprocess.run")
    def test_no_url_in_output(self, mock_run):
        """Test when no URL is found in output."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"Some other output without URL",
        )
        url = run_tailscale_up("tobcloud.test")
        assert url is None

    @patch("tobcloud.main.subprocess.run")
    def test_non_tailscale_url_ignored(self, mock_run):
        """Test that non-tailscale URLs are ignored."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"Visit https://example.com/login for more info",
        )
        url = run_tailscale_up("tobcloud.test")
        assert url is None

    @patch("tobcloud.main.subprocess.run")
    def test_ssh_timeout(self, mock_run):
        """Test when SSH connection times out."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("ssh", 30)
        url = run_tailscale_up("tobcloud.test")
        assert url is None


class TestLockDownToTailscale:
    """Tests for lock_down_to_tailscale function."""

    @patch("tobcloud.main.subprocess.run")
    def test_all_commands_succeed(self, mock_run):
        """Test when all UFW commands succeed."""
        mock_run.return_value = MagicMock(returncode=0, stderr=b"")
        result = lock_down_to_tailscale("tobcloud.test")
        assert result is True
        # Should have called 5 commands
        assert mock_run.call_count == 5

    @patch("tobcloud.main.subprocess.run")
    def test_first_command_fails(self, mock_run):
        """Test when first UFW command fails."""
        mock_run.return_value = MagicMock(returncode=1, stderr=b"ufw error")
        result = lock_down_to_tailscale("tobcloud.test")
        assert result is False
        # Should stop after first failure
        assert mock_run.call_count == 1

    @patch("tobcloud.main.subprocess.run")
    def test_middle_command_fails(self, mock_run):
        """Test when a middle command fails."""
        # First two succeed, third fails
        mock_run.side_effect = [
            MagicMock(returncode=0, stderr=b""),
            MagicMock(returncode=0, stderr=b""),
            MagicMock(returncode=1, stderr=b"deny error"),
        ]
        result = lock_down_to_tailscale("tobcloud.test")
        assert result is False
        assert mock_run.call_count == 3

    @patch("tobcloud.main.subprocess.run")
    def test_ssh_timeout(self, mock_run):
        """Test when SSH connection times out."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("ssh", 30)
        result = lock_down_to_tailscale("tobcloud.test")
        assert result is False


class TestVerifyTailscaleSsh:
    """Tests for verify_tailscale_ssh function."""

    @patch("tobcloud.main.subprocess.run")
    def test_ssh_success(self, mock_run):
        """Test when SSH via Tailscale works."""
        mock_run.return_value = MagicMock(returncode=0)
        result = verify_tailscale_ssh("100.64.1.1", "testuser", "~/.ssh/id_ed25519")
        assert result is True

    @patch("tobcloud.main.subprocess.run")
    def test_ssh_failure(self, mock_run):
        """Test when SSH via Tailscale fails."""
        mock_run.return_value = MagicMock(returncode=255)
        result = verify_tailscale_ssh("100.64.1.1", "testuser", "~/.ssh/id_ed25519")
        assert result is False

    @patch("tobcloud.main.subprocess.run")
    def test_ssh_timeout(self, mock_run):
        """Test when SSH times out."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("ssh", 15)
        result = verify_tailscale_ssh("100.64.1.1", "testuser", "~/.ssh/id_ed25519")
        assert result is False


class TestTailscaleConfig:
    """Tests for TailscaleConfig Pydantic model."""

    def test_defaults(self):
        """Test default values."""
        config = TailscaleConfig()
        assert config.enabled is True
        assert config.lock_down_firewall is True
        assert config.auth_timeout == 300

    def test_custom_values(self):
        """Test custom values."""
        config = TailscaleConfig(enabled=False, lock_down_firewall=False, auth_timeout=600)
        assert config.enabled is False
        assert config.lock_down_firewall is False
        assert config.auth_timeout == 600

    def test_auth_timeout_minimum(self):
        """Test that auth_timeout has minimum validation."""
        with pytest.raises(ValueError):
            TailscaleConfig(auth_timeout=10)  # Below minimum of 30

    def test_auth_timeout_at_minimum(self):
        """Test auth_timeout at minimum value."""
        config = TailscaleConfig(auth_timeout=30)
        assert config.auth_timeout == 30
