"""Tests for main module helper functions."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer

from dropkit.main import (
    _resize_hibernated_snapshot,
    add_temporary_ssh_rule,
    build_droplet_tags,
    complete_droplet_or_snapshot_name,
    find_snapshot_action,
    get_droplet_name_from_snapshot,
    get_snapshot_name,
    get_ssh_hostname,
    get_user_tag,
    is_droplet_tailscale_locked,
    prepare_for_hibernate,
)


class TestGetSnapshotName:
    """Tests for get_snapshot_name function."""

    def test_simple_name(self):
        """Test snapshot name for simple droplet name."""
        assert get_snapshot_name("myvm") == "dropkit-myvm"

    def test_name_with_hyphen(self):
        """Test snapshot name for droplet name with hyphen."""
        assert get_snapshot_name("my-droplet") == "dropkit-my-droplet"

    def test_name_with_numbers(self):
        """Test snapshot name for droplet name with numbers."""
        assert get_snapshot_name("test123") == "dropkit-test123"

    def test_empty_name(self):
        """Test snapshot name for empty droplet name."""
        assert get_snapshot_name("") == "dropkit-"


class TestGetDropletNameFromSnapshot:
    """Tests for get_droplet_name_from_snapshot function."""

    def test_valid_dropkit_snapshot(self):
        """Test extracting droplet name from valid dropkit snapshot."""
        assert get_droplet_name_from_snapshot("dropkit-myvm") == "myvm"

    def test_snapshot_with_hyphen_in_name(self):
        """Test extracting droplet name with hyphens."""
        assert get_droplet_name_from_snapshot("dropkit-my-droplet") == "my-droplet"

    def test_non_dropkit_snapshot(self):
        """Test with non-dropkit snapshot name."""
        assert get_droplet_name_from_snapshot("other-snapshot") is None

    def test_partial_prefix(self):
        """Test with partial prefix (should not match)."""
        assert get_droplet_name_from_snapshot("dropkit") is None

    def test_different_prefix(self):
        """Test with different prefix."""
        assert get_droplet_name_from_snapshot("snapshot-myvm") is None

    def test_empty_after_prefix(self):
        """Test snapshot name that is just the prefix."""
        assert get_droplet_name_from_snapshot("dropkit-") == ""


class TestGetSshHostname:
    """Tests for get_ssh_hostname function."""

    def test_simple_name(self):
        """Test SSH hostname for simple droplet name."""
        assert get_ssh_hostname("myvm") == "dropkit.myvm"

    def test_name_with_hyphen(self):
        """Test SSH hostname for droplet name with hyphen."""
        assert get_ssh_hostname("my-droplet") == "dropkit.my-droplet"


class TestGetUserTag:
    """Tests for get_user_tag function."""

    def test_simple_username(self):
        """Test user tag for simple username."""
        assert get_user_tag("john") == "owner:john"

    def test_username_with_underscore(self):
        """Test user tag for username with underscore."""
        assert get_user_tag("john_doe") == "owner:john_doe"


class TestBuildDropletTags:
    """Tests for build_droplet_tags function."""

    def test_no_extra_tags(self):
        """Test building tags without extra tags."""
        tags = build_droplet_tags("john")
        assert tags == ["owner:john", "firewall"]

    def test_with_extra_tags(self):
        """Test building tags with extra tags."""
        tags = build_droplet_tags("john", ["production", "webserver"])
        assert tags == ["owner:john", "firewall", "production", "webserver"]

    def test_extra_tags_no_duplicates(self):
        """Test that duplicate tags are not added."""
        tags = build_droplet_tags("john", ["firewall", "production"])
        assert tags == ["owner:john", "firewall", "production"]

    def test_empty_extra_tags(self):
        """Test with empty extra tags list."""
        tags = build_droplet_tags("john", [])
        assert tags == ["owner:john", "firewall"]

    def test_none_extra_tags(self):
        """Test with None extra tags."""
        tags = build_droplet_tags("john", None)
        assert tags == ["owner:john", "firewall"]


class TestFindSnapshotAction:
    """Tests for find_snapshot_action function."""

    def test_finds_snapshot_action(self):
        """Test finding a snapshot action in the actions list."""
        mock_api = MagicMock()
        mock_api.list_droplet_actions.return_value = [
            {"id": 1, "type": "power_off", "status": "completed"},
            {"id": 2, "type": "snapshot", "status": "in-progress"},
            {"id": 3, "type": "power_on", "status": "completed"},
        ]

        result = find_snapshot_action(mock_api, 12345)

        assert result is not None
        assert result["id"] == 2
        assert result["type"] == "snapshot"
        mock_api.list_droplet_actions.assert_called_once_with(12345)

    def test_returns_first_snapshot_action(self):
        """Test that it returns the first (most recent) snapshot action."""
        mock_api = MagicMock()
        mock_api.list_droplet_actions.return_value = [
            {"id": 10, "type": "snapshot", "status": "in-progress"},
            {"id": 5, "type": "snapshot", "status": "completed"},
        ]

        result = find_snapshot_action(mock_api, 12345)

        assert result is not None
        assert result["id"] == 10

    def test_returns_none_when_no_snapshot_action(self):
        """Test returning None when no snapshot action exists."""
        mock_api = MagicMock()
        mock_api.list_droplet_actions.return_value = [
            {"id": 1, "type": "power_off", "status": "completed"},
            {"id": 2, "type": "power_on", "status": "completed"},
        ]

        result = find_snapshot_action(mock_api, 12345)

        assert result is None

    def test_returns_none_when_empty_actions(self):
        """Test returning None when actions list is empty."""
        mock_api = MagicMock()
        mock_api.list_droplet_actions.return_value = []

        result = find_snapshot_action(mock_api, 12345)

        assert result is None


@pytest.fixture
def temp_ssh_config(tmp_path):
    """Create a temporary SSH config file."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir(mode=0o700)
    config_path = ssh_dir / "config"
    return str(config_path)


class TestIsDropletTailscaleLocked:
    """Tests for is_droplet_tailscale_locked function."""

    def test_tailscale_ip_returns_true(self, temp_ssh_config):
        """Test returns True when SSH config has Tailscale IP."""
        # Create SSH config with Tailscale IP
        Path(temp_ssh_config).write_text("""Host dropkit.myvm
    HostName 100.80.123.45
    User ubuntu
""")

        mock_config = MagicMock()
        mock_config.ssh.config_path = temp_ssh_config

        result = is_droplet_tailscale_locked(mock_config, "myvm")
        assert result is True

    def test_public_ip_returns_false(self, temp_ssh_config):
        """Test returns False when SSH config has public IP."""
        # Create SSH config with public IP
        Path(temp_ssh_config).write_text("""Host dropkit.myvm
    HostName 192.168.1.100
    User ubuntu
""")

        mock_config = MagicMock()
        mock_config.ssh.config_path = temp_ssh_config

        result = is_droplet_tailscale_locked(mock_config, "myvm")
        assert result is False

    def test_missing_entry_returns_false(self, temp_ssh_config):
        """Test returns False when SSH config has no entry for droplet."""
        # Create SSH config without the target host
        Path(temp_ssh_config).write_text("""Host dropkit.othervm
    HostName 100.80.123.45
    User ubuntu
""")

        mock_config = MagicMock()
        mock_config.ssh.config_path = temp_ssh_config

        result = is_droplet_tailscale_locked(mock_config, "myvm")
        assert result is False

    def test_nonexistent_config_file_returns_false(self, temp_ssh_config):
        """Test returns False when SSH config file doesn't exist."""
        mock_config = MagicMock()
        mock_config.ssh.config_path = "/nonexistent/path/config"

        result = is_droplet_tailscale_locked(mock_config, "myvm")
        assert result is False


class TestAddTemporarySshRule:
    """Tests for add_temporary_ssh_rule function."""

    @patch("dropkit.main.subprocess.run")
    def test_success(self, mock_run):
        """Test successful SSH rule addition."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        result = add_temporary_ssh_rule("dropkit.myvm")

        assert result is True
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert "dropkit.myvm" in call_args[0][0]
        assert "sudo ufw allow in on eth0 to any port 22" in call_args[0][0]

    @patch("dropkit.main.subprocess.run")
    def test_failure(self, mock_run):
        """Test failed SSH rule addition."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")

        result = add_temporary_ssh_rule("dropkit.myvm")

        assert result is False

    @patch("dropkit.main.subprocess.run")
    def test_timeout(self, mock_run):
        """Test SSH timeout."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("ssh", 30)

        result = add_temporary_ssh_rule("dropkit.myvm")

        assert result is False


class TestPrepareForHibernate:
    """Tests for prepare_for_hibernate function."""

    def test_not_tailscale_locked_returns_false(self, temp_ssh_config):
        """Test returns False when droplet is not Tailscale locked."""
        # Create SSH config with public IP (not Tailscale locked)
        Path(temp_ssh_config).write_text("""Host dropkit.myvm
    HostName 192.168.1.100
    User ubuntu
""")

        mock_config = MagicMock()
        mock_config.ssh.config_path = temp_ssh_config

        mock_api = MagicMock()
        mock_droplet = {"networks": {"v4": [{"type": "public", "ip_address": "192.168.1.100"}]}}

        result = prepare_for_hibernate(mock_config, mock_api, mock_droplet, "myvm")

        assert result is False

    @patch("dropkit.main.tailscale_logout")
    @patch("dropkit.main.add_temporary_ssh_rule")
    @patch("dropkit.main.add_ssh_host")
    def test_tailscale_locked_returns_true(
        self, mock_add_ssh_host, mock_add_temp_rule, mock_logout, temp_ssh_config
    ):
        """Test returns True when droplet is Tailscale locked."""
        # Create SSH config with Tailscale IP
        Path(temp_ssh_config).write_text("""Host dropkit.myvm
    HostName 100.80.123.45
    User ubuntu
""")

        mock_config = MagicMock()
        mock_config.ssh.config_path = temp_ssh_config
        mock_config.ssh.identity_file = "~/.ssh/id_ed25519"

        mock_api = MagicMock()
        mock_api.get_username.return_value = "testuser"

        mock_droplet = {"networks": {"v4": [{"type": "public", "ip_address": "203.0.113.50"}]}}

        mock_add_temp_rule.return_value = True
        mock_logout.return_value = True

        result = prepare_for_hibernate(mock_config, mock_api, mock_droplet, "myvm")

        assert result is True
        mock_add_temp_rule.assert_called_once()
        mock_logout.assert_called_once()
        mock_add_ssh_host.assert_called_once()

    @patch("dropkit.main.tailscale_logout")
    @patch("dropkit.main.add_temporary_ssh_rule")
    @patch("dropkit.main.add_ssh_host")
    def test_temp_rule_failure_skips_logout(
        self, mock_add_ssh_host, mock_add_temp_rule, mock_logout, temp_ssh_config
    ):
        """Test returns True but skips logout if temp rule fails (safety)."""
        # Create SSH config with Tailscale IP
        Path(temp_ssh_config).write_text("""Host dropkit.myvm
    HostName 100.80.123.45
    User ubuntu
""")

        mock_config = MagicMock()
        mock_config.ssh.config_path = temp_ssh_config
        mock_config.ssh.identity_file = "~/.ssh/id_ed25519"

        mock_api = MagicMock()
        mock_api.get_username.return_value = "testuser"

        mock_droplet = {"networks": {"v4": [{"type": "public", "ip_address": "203.0.113.50"}]}}

        mock_add_temp_rule.return_value = False  # Simulating failure

        result = prepare_for_hibernate(mock_config, mock_api, mock_droplet, "myvm")

        # Should still return True because we detected Tailscale lockdown
        assert result is True
        # But logout should NOT be called (safety - need public IP fallback first)
        mock_logout.assert_not_called()
        # And SSH config should NOT be updated (early return)
        mock_add_ssh_host.assert_not_called()


class TestResizeHibernatedSnapshot:
    """Tests for _resize_hibernated_snapshot function."""

    def test_no_snapshot_id_exits(self):
        """Test exits with error when snapshot has no ID."""
        mock_api = MagicMock()
        snapshot = {"tags": ["size:s-1vcpu-1gb"]}

        with pytest.raises(typer.Exit):
            _resize_hibernated_snapshot(mock_api, snapshot, "myvm", "s-2vcpu-4gb")

    def test_no_size_tag_exits(self):
        """Test exits with error when snapshot has no size: tag."""
        mock_api = MagicMock()
        snapshot = {"id": "12345", "tags": ["owner:testuser", "firewall"]}

        with pytest.raises(typer.Exit):
            _resize_hibernated_snapshot(mock_api, snapshot, "myvm", "s-2vcpu-4gb")

    @patch("dropkit.main.Prompt.ask", return_value="yes")
    def test_same_size_exits(self, mock_prompt):
        """Test exits when new size matches current size."""
        mock_api = MagicMock()
        snapshot = {"id": "12345", "tags": ["size:s-1vcpu-1gb", "owner:testuser"]}

        with pytest.raises(typer.Exit):
            _resize_hibernated_snapshot(mock_api, snapshot, "myvm", "s-1vcpu-1gb")

    @patch("dropkit.main.Prompt.ask", return_value="yes")
    def test_successful_resize_swaps_tags(self, mock_prompt):
        """Test successful resize creates new tag, tags resource, then untags old."""
        mock_api = MagicMock()
        mock_api.get_available_sizes.return_value = [
            {"slug": "s-2vcpu-4gb", "vcpus": 2, "memory": 4096, "disk": 80, "price_monthly": 24},
        ]
        snapshot = {"id": "12345", "tags": ["size:s-1vcpu-1gb", "owner:testuser"]}

        _resize_hibernated_snapshot(mock_api, snapshot, "myvm", "s-2vcpu-4gb")

        # Verify tag operations: add new first, then remove old
        mock_api.create_tag.assert_called_once_with("size:s-2vcpu-4gb")
        mock_api.tag_resource.assert_called_once_with("size:s-2vcpu-4gb", "12345", "image")
        mock_api.untag_resource.assert_called_once_with("size:s-1vcpu-1gb", "12345", "image")

    @patch("dropkit.main.Prompt.ask", return_value="no")
    def test_cancelled_resize_no_api_calls(self, mock_prompt):
        """Test that cancelling resize makes no tag API calls."""
        mock_api = MagicMock()
        mock_api.get_available_sizes.return_value = [
            {"slug": "s-2vcpu-4gb", "vcpus": 2, "memory": 4096, "disk": 80, "price_monthly": 24},
        ]
        snapshot = {"id": "12345", "tags": ["size:s-1vcpu-1gb", "owner:testuser"]}

        with pytest.raises(typer.Exit):
            _resize_hibernated_snapshot(mock_api, snapshot, "myvm", "s-2vcpu-4gb")

        mock_api.create_tag.assert_not_called()
        mock_api.tag_resource.assert_not_called()
        mock_api.untag_resource.assert_not_called()

    @patch("dropkit.main.Prompt.ask", return_value="yes")
    def test_invalid_size_exits(self, mock_prompt):
        """Test exits when provided size slug doesn't exist."""
        mock_api = MagicMock()
        mock_api.get_available_sizes.return_value = [
            {"slug": "s-1vcpu-1gb", "vcpus": 1, "memory": 1024, "disk": 25, "price_monthly": 6},
        ]
        snapshot = {"id": "12345", "tags": ["size:s-1vcpu-1gb", "owner:testuser"]}

        with pytest.raises(typer.Exit):
            _resize_hibernated_snapshot(mock_api, snapshot, "myvm", "nonexistent-size")


class TestCompleteDropletOrSnapshotName:
    """Tests for complete_droplet_or_snapshot_name function."""

    @patch("dropkit.main.complete_snapshot_name", return_value=["snap-vm"])
    @patch("dropkit.main.complete_droplet_name", return_value=["live-vm"])
    def test_combines_both_sources(self, mock_droplet, mock_snapshot):
        """Test that results from both completers are combined."""
        result = complete_droplet_or_snapshot_name("")
        assert "live-vm" in result
        assert "snap-vm" in result

    @patch("dropkit.main.complete_snapshot_name", return_value=["shared-vm"])
    @patch("dropkit.main.complete_droplet_name", return_value=["shared-vm"])
    def test_deduplicates(self, mock_droplet, mock_snapshot):
        """Test that duplicate names appear only once."""
        result = complete_droplet_or_snapshot_name("")
        assert result.count("shared-vm") == 1

    @patch("dropkit.main.complete_snapshot_name", return_value=["snap-vm"])
    @patch("dropkit.main.complete_droplet_name", return_value=["live-vm"])
    def test_droplets_first(self, mock_droplet, mock_snapshot):
        """Test that live droplet names appear before snapshot names."""
        result = complete_droplet_or_snapshot_name("")
        assert result.index("live-vm") < result.index("snap-vm")
