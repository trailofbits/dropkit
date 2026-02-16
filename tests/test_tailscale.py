"""Tests for Tailscale integration functions."""

import json
from unittest.mock import MagicMock, patch

import pytest

from dropkit.config import TailscaleConfig
from dropkit.main import (
    check_local_tailscale,
    check_tailscale_installed,
    find_tailscale_cli,
    install_tailscale_on_droplet,
    is_tailscale_ip,
    lock_down_to_tailscale,
    run_tailscale_up,
    setup_tailscale,
    tailscale_logout,
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


class TestFindTailscaleCli:
    """Tests for find_tailscale_cli function."""

    @patch("dropkit.main.shutil.which", return_value="/usr/bin/tailscale")
    def test_found_in_path(self, mock_which):
        """Test when tailscale is found in PATH."""
        assert find_tailscale_cli() == "/usr/bin/tailscale"

    @patch("dropkit.main.Path.exists", return_value=True)
    @patch("dropkit.main.sys.platform", "darwin")
    @patch("dropkit.main.shutil.which", return_value=None)
    def test_macos_app_store_fallback(self, mock_which, mock_exists):
        """Test fallback to macOS App Store location."""
        assert find_tailscale_cli() == "/Applications/Tailscale.app/Contents/MacOS/Tailscale"

    @patch("dropkit.main.Path.exists", return_value=False)
    @patch("dropkit.main.sys.platform", "darwin")
    @patch("dropkit.main.shutil.which", return_value=None)
    def test_macos_app_not_installed(self, mock_which, mock_exists):
        """Test when Tailscale is not installed on macOS."""
        assert find_tailscale_cli() is None

    @patch("dropkit.main.sys.platform", "linux")
    @patch("dropkit.main.shutil.which", return_value=None)
    def test_linux_not_in_path(self, mock_which):
        """Test when tailscale is not in PATH on Linux (no macOS fallback)."""
        assert find_tailscale_cli() is None

    @patch("dropkit.main.Path.exists")
    @patch("dropkit.main.shutil.which", return_value="/opt/bin/tailscale")
    def test_which_returns_path_skips_fallback(self, mock_which, mock_exists):
        """Test that PATH hit skips macOS App Store check."""
        assert find_tailscale_cli() == "/opt/bin/tailscale"
        mock_exists.assert_not_called()


class TestCheckLocalTailscale:
    """Tests for check_local_tailscale function."""

    @patch("dropkit.main.find_tailscale_cli", return_value="/usr/bin/tailscale")
    @patch("dropkit.main.subprocess.run")
    def test_tailscale_running(self, mock_run, mock_find):
        """Test when Tailscale is running locally."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"BackendState": "Running"}).encode("utf-8"),
        )
        assert check_local_tailscale() is True

    @patch("dropkit.main.find_tailscale_cli", return_value="/usr/bin/tailscale")
    @patch("dropkit.main.subprocess.run")
    def test_tailscale_not_running(self, mock_run, mock_find):
        """Test when Tailscale is installed but not running."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"BackendState": "Stopped"}).encode("utf-8"),
        )
        assert check_local_tailscale() is False

    @patch("dropkit.main.find_tailscale_cli", return_value="/usr/bin/tailscale")
    @patch("dropkit.main.subprocess.run")
    def test_tailscale_command_fails(self, mock_run, mock_find):
        """Test when tailscale command returns non-zero."""
        mock_run.return_value = MagicMock(returncode=1)
        assert check_local_tailscale() is False

    @patch("dropkit.main.find_tailscale_cli", return_value=None)
    def test_tailscale_not_installed(self, mock_find):
        """Test when tailscale binary is not found."""
        assert check_local_tailscale() is False

    @patch("dropkit.main.find_tailscale_cli", return_value="/usr/bin/tailscale")
    @patch("dropkit.main.subprocess.run")
    def test_tailscale_timeout(self, mock_run, mock_find):
        """Test when tailscale command times out."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("tailscale", 5)
        assert check_local_tailscale() is False

    @patch("dropkit.main.find_tailscale_cli", return_value="/usr/bin/tailscale")
    @patch("dropkit.main.subprocess.run")
    def test_invalid_json_response(self, mock_run, mock_find):
        """Test when tailscale returns invalid JSON."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"not valid json",
        )
        assert check_local_tailscale() is False


class TestRunTailscaleUp:
    """Tests for run_tailscale_up function."""

    @patch("dropkit.main.subprocess.run")
    def test_extracts_auth_url(self, mock_run):
        """Test that auth URL is extracted from output."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"To authenticate, visit:\n\n\thttps://login.tailscale.com/a/abc123\n",
        )
        url = run_tailscale_up("dropkit.test")
        assert url == "https://login.tailscale.com/a/abc123"

    @patch("dropkit.main.subprocess.run")
    def test_strips_trailing_punctuation(self, mock_run):
        """Test that trailing punctuation is stripped from URL."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"Visit: https://login.tailscale.com/a/abc123.\n",
        )
        url = run_tailscale_up("dropkit.test")
        assert url == "https://login.tailscale.com/a/abc123"

    @patch("dropkit.main.subprocess.run")
    def test_no_url_in_output(self, mock_run):
        """Test when no URL is found in output."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"Some other output without URL",
        )
        url = run_tailscale_up("dropkit.test")
        assert url is None

    @patch("dropkit.main.subprocess.run")
    def test_non_tailscale_url_ignored(self, mock_run):
        """Test that non-tailscale URLs are ignored."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"Visit https://example.com/login for more info",
        )
        url = run_tailscale_up("dropkit.test")
        assert url is None

    @patch("dropkit.main.subprocess.run")
    def test_ssh_timeout(self, mock_run):
        """Test when SSH connection times out."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("ssh", 30)
        url = run_tailscale_up("dropkit.test")
        assert url is None


class TestLockDownToTailscale:
    """Tests for lock_down_to_tailscale function."""

    @patch("dropkit.main.subprocess.run")
    def test_all_commands_succeed(self, mock_run):
        """Test when all UFW commands succeed."""
        mock_run.return_value = MagicMock(returncode=0, stderr=b"")
        result = lock_down_to_tailscale("dropkit.test")
        assert result is True
        # Should have called 5 commands
        assert mock_run.call_count == 5

    @patch("dropkit.main.subprocess.run")
    def test_first_command_fails(self, mock_run):
        """Test when first UFW command fails."""
        mock_run.return_value = MagicMock(returncode=1, stderr=b"ufw error")
        result = lock_down_to_tailscale("dropkit.test")
        assert result is False
        # Should stop after first failure
        assert mock_run.call_count == 1

    @patch("dropkit.main.subprocess.run")
    def test_middle_command_fails(self, mock_run):
        """Test when a middle command fails."""
        # First two succeed, third fails
        mock_run.side_effect = [
            MagicMock(returncode=0, stderr=b""),
            MagicMock(returncode=0, stderr=b""),
            MagicMock(returncode=1, stderr=b"deny error"),
        ]
        result = lock_down_to_tailscale("dropkit.test")
        assert result is False
        assert mock_run.call_count == 3

    @patch("dropkit.main.subprocess.run")
    def test_ssh_timeout(self, mock_run):
        """Test when SSH connection times out."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("ssh", 30)
        result = lock_down_to_tailscale("dropkit.test")
        assert result is False


class TestVerifyTailscaleSsh:
    """Tests for verify_tailscale_ssh function."""

    @patch("dropkit.main.subprocess.run")
    def test_ssh_success(self, mock_run):
        """Test when SSH via Tailscale works."""
        mock_run.return_value = MagicMock(returncode=0)
        result = verify_tailscale_ssh("100.64.1.1", "testuser", "~/.ssh/id_ed25519")
        assert result is True

    @patch("dropkit.main.subprocess.run")
    def test_ssh_failure(self, mock_run):
        """Test when SSH via Tailscale fails."""
        mock_run.return_value = MagicMock(returncode=255)
        result = verify_tailscale_ssh("100.64.1.1", "testuser", "~/.ssh/id_ed25519")
        assert result is False

    @patch("dropkit.main.subprocess.run")
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


class TestCheckTailscaleInstalled:
    """Tests for check_tailscale_installed function."""

    @patch("dropkit.main.subprocess.run")
    def test_tailscale_installed(self, mock_run):
        """Test when Tailscale is installed."""
        mock_run.return_value = MagicMock(returncode=0)
        assert check_tailscale_installed("dropkit.test") is True

    @patch("dropkit.main.subprocess.run")
    def test_tailscale_not_installed(self, mock_run):
        """Test when Tailscale is not installed."""
        mock_run.return_value = MagicMock(returncode=1)
        assert check_tailscale_installed("dropkit.test") is False

    @patch("dropkit.main.subprocess.run")
    def test_ssh_timeout(self, mock_run):
        """Test when SSH connection times out."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("ssh", 15)
        assert check_tailscale_installed("dropkit.test") is False

    @patch("dropkit.main.subprocess.run")
    def test_ssh_connection_failed(self, mock_run):
        """Test when SSH connection fails."""
        import subprocess

        mock_run.side_effect = subprocess.SubprocessError("Connection refused")
        assert check_tailscale_installed("dropkit.test") is False


class TestInstallTailscaleOnDroplet:
    """Tests for install_tailscale_on_droplet function."""

    @patch("dropkit.main.subprocess.run")
    def test_install_success(self, mock_run):
        """Test successful Tailscale installation."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"Installation complete!",
        )
        assert install_tailscale_on_droplet("dropkit.test") is True

    @patch("dropkit.main.subprocess.run")
    def test_install_failure(self, mock_run):
        """Test failed Tailscale installation."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout=b"Error: curl failed",
        )
        assert install_tailscale_on_droplet("dropkit.test") is False

    @patch("dropkit.main.subprocess.run")
    def test_install_timeout(self, mock_run):
        """Test when installation times out."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("ssh", 120)
        assert install_tailscale_on_droplet("dropkit.test") is False

    @patch("dropkit.main.subprocess.run")
    def test_ssh_connection_failed(self, mock_run):
        """Test when SSH connection fails during install."""
        import subprocess

        mock_run.side_effect = subprocess.SubprocessError("Connection refused")
        assert install_tailscale_on_droplet("dropkit.test") is False


def create_mock_config(lock_down_firewall: bool = True, auth_timeout: int = 300) -> MagicMock:
    """Create a mock DropkitConfig for testing."""
    config = MagicMock()
    config.tailscale = MagicMock()
    config.tailscale.lock_down_firewall = lock_down_firewall
    config.tailscale.auth_timeout = auth_timeout
    config.ssh = MagicMock()
    config.ssh.config_path = "~/.ssh/config"
    config.ssh.identity_file = "~/.ssh/id_ed25519"
    return config


class TestSetupTailscale:
    """Tests for setup_tailscale function."""

    @patch("dropkit.main.verify_tailscale_ssh")
    @patch("dropkit.main.lock_down_to_tailscale")
    @patch("dropkit.main.check_local_tailscale")
    @patch("dropkit.main.add_ssh_host")
    @patch("dropkit.main.wait_for_tailscale_ip")
    @patch("dropkit.main.run_tailscale_up")
    def test_already_authenticated_succeeds(
        self,
        mock_tailscale_up,
        mock_wait_ip,
        mock_add_ssh,
        mock_check_local,
        mock_lockdown,
        mock_verify,
    ):
        """Test setup succeeds when Tailscale is already authenticated (no auth URL)."""
        # No auth URL returned (already authenticated)
        mock_tailscale_up.return_value = None
        # But Tailscale IP is available
        mock_wait_ip.return_value = "100.64.1.1"
        mock_check_local.return_value = True
        mock_lockdown.return_value = True
        mock_verify.return_value = True

        config = create_mock_config()
        result = setup_tailscale("dropkit.test", "testuser", config)

        assert result == "100.64.1.1"
        # Should have called wait_for_tailscale_ip with short timeout
        mock_wait_ip.assert_called_once_with(
            "dropkit.test", timeout=10, poll_interval=2, verbose=False
        )
        mock_add_ssh.assert_called_once()
        mock_lockdown.assert_called_once()

    @patch("dropkit.main.wait_for_tailscale_ip")
    @patch("dropkit.main.run_tailscale_up")
    def test_no_auth_url_and_not_connected_fails(
        self,
        mock_tailscale_up,
        mock_wait_ip,
    ):
        """Test setup fails when no auth URL and Tailscale not connected."""
        # No auth URL returned
        mock_tailscale_up.return_value = None
        # And no Tailscale IP available
        mock_wait_ip.return_value = None

        config = create_mock_config()
        result = setup_tailscale("dropkit.test", "testuser", config)

        assert result is None

    @patch("dropkit.main.verify_tailscale_ssh")
    @patch("dropkit.main.lock_down_to_tailscale")
    @patch("dropkit.main.check_local_tailscale")
    @patch("dropkit.main.add_ssh_host")
    @patch("dropkit.main.wait_for_tailscale_ip")
    @patch("dropkit.main.run_tailscale_up")
    def test_normal_auth_flow_succeeds(
        self,
        mock_tailscale_up,
        mock_wait_ip,
        mock_add_ssh,
        mock_check_local,
        mock_lockdown,
        mock_verify,
    ):
        """Test normal flow with auth URL succeeds."""
        # Auth URL returned (needs authentication)
        mock_tailscale_up.return_value = "https://login.tailscale.com/a/abc123"
        # Tailscale IP available after authentication
        mock_wait_ip.return_value = "100.64.1.1"
        mock_check_local.return_value = True
        mock_lockdown.return_value = True
        mock_verify.return_value = True

        config = create_mock_config()
        result = setup_tailscale("dropkit.test", "testuser", config)

        assert result == "100.64.1.1"
        # Should have called wait_for_tailscale_ip with full auth_timeout
        mock_wait_ip.assert_called_once_with("dropkit.test", timeout=300, verbose=False)

    @patch("dropkit.main.wait_for_tailscale_ip")
    @patch("dropkit.main.run_tailscale_up")
    def test_auth_timeout_fails(
        self,
        mock_tailscale_up,
        mock_wait_ip,
    ):
        """Test setup fails when authentication times out."""
        # Auth URL returned
        mock_tailscale_up.return_value = "https://login.tailscale.com/a/abc123"
        # But no IP received (user didn't authenticate in time)
        mock_wait_ip.return_value = None

        config = create_mock_config()
        result = setup_tailscale("dropkit.test", "testuser", config)

        assert result is None

    @patch("dropkit.main.check_local_tailscale")
    @patch("dropkit.main.add_ssh_host")
    @patch("dropkit.main.wait_for_tailscale_ip")
    @patch("dropkit.main.run_tailscale_up")
    def test_skips_lockdown_when_disabled(
        self,
        mock_tailscale_up,
        mock_wait_ip,
        mock_add_ssh,
        mock_check_local,
    ):
        """Test firewall lockdown is skipped when disabled in config."""
        mock_tailscale_up.return_value = None
        mock_wait_ip.return_value = "100.64.1.1"

        config = create_mock_config(lock_down_firewall=False)
        result = setup_tailscale("dropkit.test", "testuser", config)

        assert result == "100.64.1.1"
        mock_check_local.assert_not_called()  # Lockdown logic not entered


class TestTailscaleLogout:
    """Tests for tailscale_logout function."""

    @patch("dropkit.main.subprocess.run")
    def test_logout_success(self, mock_run):
        """Test successful Tailscale logout."""
        mock_run.return_value = MagicMock(returncode=0, stderr=b"")
        result = tailscale_logout("dropkit.test")
        assert result is True
        # Verify correct SSH command was called
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert "ssh" in call_args
        assert "dropkit.test" in call_args
        assert "sudo tailscale logout" in call_args

    @patch("dropkit.main.subprocess.run")
    def test_logout_command_fails(self, mock_run):
        """Test when tailscale logout command fails."""
        mock_run.return_value = MagicMock(returncode=1, stderr=b"logout failed")
        result = tailscale_logout("dropkit.test")
        assert result is False

    @patch("dropkit.main.subprocess.run")
    def test_ssh_connection_fails(self, mock_run):
        """Test when SSH connection fails."""
        import subprocess

        mock_run.side_effect = subprocess.SubprocessError("Connection refused")
        result = tailscale_logout("dropkit.test")
        assert result is False

    @patch("dropkit.main.subprocess.run")
    def test_ssh_timeout(self, mock_run):
        """Test when SSH connection times out."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("ssh", 30)
        result = tailscale_logout("dropkit.test")
        assert result is False
