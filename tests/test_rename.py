"""Tests for the rename command functionality."""

from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from dropkit.main import app

runner = CliRunner()


def create_mock_droplet(
    droplet_id: int = 12345,
    name: str = "test-droplet",
    status: str = "active",
    ip_address: str = "192.168.1.100",
) -> dict:
    """Create a mock droplet dictionary."""
    return {
        "id": droplet_id,
        "name": name,
        "status": status,
        "networks": {
            "v4": [
                {"type": "public", "ip_address": ip_address},
                {"type": "private", "ip_address": "10.0.0.1"},
            ]
        },
    }


def create_mock_config():
    """Create a mock config object."""
    mock_config = MagicMock()
    mock_config.ssh.config_path = "~/.ssh/config"
    mock_config.ssh.identity_file = "~/.ssh/id_ed25519"
    return mock_config


class TestRenameCommand:
    """Tests for the rename command."""

    @patch("dropkit.main.add_ssh_host")
    @patch("dropkit.main.remove_ssh_host")
    @patch("dropkit.main.host_exists")
    @patch("dropkit.main.Prompt.ask")
    @patch("dropkit.main.find_user_droplet")
    @patch("dropkit.main.load_config_and_api")
    def test_successful_rename(
        self,
        mock_load_config,
        mock_find_droplet,
        mock_prompt,
        mock_host_exists,
        mock_remove_ssh,
        mock_add_ssh,
    ):
        """Test successful droplet rename."""
        # Setup mocks
        mock_api = MagicMock()
        mock_config_manager = MagicMock()
        mock_config_manager.config = create_mock_config()
        mock_load_config.return_value = (mock_config_manager, mock_api)

        mock_droplet = create_mock_droplet(name="old-name", status="active")
        mock_find_droplet.return_value = (mock_droplet, "testuser")

        # No existing droplets with new name
        mock_api.list_droplets.return_value = [mock_droplet]
        mock_api.get_droplet.return_value = mock_droplet
        mock_api.rename_droplet.return_value = {"id": 99999}
        mock_api.wait_for_action_complete.return_value = {"status": "completed"}

        mock_prompt.return_value = "yes"
        mock_host_exists.return_value = True

        # Run command
        result = runner.invoke(app, ["rename", "old-name", "new-name"])

        # Verify
        assert result.exit_code == 0
        assert "successfully renamed" in result.output.lower()
        mock_api.rename_droplet.assert_called_once_with(12345, "new-name")
        mock_remove_ssh.assert_called_once()
        mock_add_ssh.assert_called_once()

    @patch("dropkit.main.find_user_droplet")
    @patch("dropkit.main.load_config_and_api")
    def test_rename_same_name_exits_early(self, mock_load_config, mock_find_droplet):
        """Test that renaming to the same name exits early."""
        mock_api = MagicMock()
        mock_config_manager = MagicMock()
        mock_config_manager.config = create_mock_config()
        mock_load_config.return_value = (mock_config_manager, mock_api)

        mock_droplet = create_mock_droplet(name="test-droplet")
        mock_find_droplet.return_value = (mock_droplet, "testuser")

        result = runner.invoke(app, ["rename", "test-droplet", "test-droplet"])

        assert result.exit_code == 0
        assert "same as current name" in result.output.lower()
        mock_api.rename_droplet.assert_not_called()

    @patch("dropkit.main.find_user_droplet")
    @patch("dropkit.main.load_config_and_api")
    def test_rename_droplet_not_found(self, mock_load_config, mock_find_droplet):
        """Test rename when droplet is not found."""
        mock_api = MagicMock()
        mock_config_manager = MagicMock()
        mock_config_manager.config = create_mock_config()
        mock_load_config.return_value = (mock_config_manager, mock_api)

        mock_find_droplet.return_value = (None, "testuser")

        result = runner.invoke(app, ["rename", "nonexistent", "new-name"])

        assert result.exit_code == 1
        assert "not found" in result.output.lower()
        mock_api.rename_droplet.assert_not_called()

    @patch("dropkit.main.find_user_droplet")
    @patch("dropkit.main.load_config_and_api")
    def test_rename_name_conflict(self, mock_load_config, mock_find_droplet):
        """Test rename fails when new name already exists for the same user."""
        mock_api = MagicMock()
        mock_config_manager = MagicMock()
        mock_config_manager.config = create_mock_config()
        mock_load_config.return_value = (mock_config_manager, mock_api)

        mock_droplet = create_mock_droplet(droplet_id=12345, name="old-name")
        mock_find_droplet.return_value = (mock_droplet, "testuser")

        # Another droplet with the target name already exists
        existing_droplet = create_mock_droplet(droplet_id=99999, name="existing-name")
        mock_api.list_droplets.return_value = [mock_droplet, existing_droplet]

        result = runner.invoke(app, ["rename", "old-name", "existing-name"])

        assert result.exit_code == 1
        assert "already exists" in result.output.lower()
        mock_api.rename_droplet.assert_not_called()

    @patch("dropkit.main.find_user_droplet")
    @patch("dropkit.main.load_config_and_api")
    def test_rename_droplet_not_active(self, mock_load_config, mock_find_droplet):
        """Test rename fails when droplet is not active (powered off)."""
        mock_api = MagicMock()
        mock_config_manager = MagicMock()
        mock_config_manager.config = create_mock_config()
        mock_load_config.return_value = (mock_config_manager, mock_api)

        # Droplet is off
        mock_droplet = create_mock_droplet(name="old-name", status="off")
        mock_find_droplet.return_value = (mock_droplet, "testuser")

        mock_api.list_droplets.return_value = [mock_droplet]

        result = runner.invoke(app, ["rename", "old-name", "new-name"])

        assert result.exit_code == 1
        assert "off" in result.output.lower()
        assert "dropkit on" in result.output.lower()
        mock_api.rename_droplet.assert_not_called()

    @patch("dropkit.main.find_user_droplet")
    @patch("dropkit.main.load_config_and_api")
    def test_rename_droplet_status_new(self, mock_load_config, mock_find_droplet):
        """Test rename fails when droplet status is 'new' (still initializing)."""
        mock_api = MagicMock()
        mock_config_manager = MagicMock()
        mock_config_manager.config = create_mock_config()
        mock_load_config.return_value = (mock_config_manager, mock_api)

        mock_droplet = create_mock_droplet(name="old-name", status="new")
        mock_find_droplet.return_value = (mock_droplet, "testuser")

        mock_api.list_droplets.return_value = [mock_droplet]

        result = runner.invoke(app, ["rename", "old-name", "new-name"])

        assert result.exit_code == 1
        assert "new" in result.output.lower()
        mock_api.rename_droplet.assert_not_called()

    @patch("dropkit.main.Prompt.ask")
    @patch("dropkit.main.find_user_droplet")
    @patch("dropkit.main.load_config_and_api")
    def test_rename_user_cancels(self, mock_load_config, mock_find_droplet, mock_prompt):
        """Test rename cancelled when user says no."""
        mock_api = MagicMock()
        mock_config_manager = MagicMock()
        mock_config_manager.config = create_mock_config()
        mock_load_config.return_value = (mock_config_manager, mock_api)

        mock_droplet = create_mock_droplet(name="old-name", status="active")
        mock_find_droplet.return_value = (mock_droplet, "testuser")

        mock_api.list_droplets.return_value = [mock_droplet]
        mock_api.get_droplet.return_value = mock_droplet

        mock_prompt.return_value = "no"

        result = runner.invoke(app, ["rename", "old-name", "new-name"])

        assert result.exit_code == 0
        assert "cancelled" in result.output.lower()
        mock_api.rename_droplet.assert_not_called()

    @patch("dropkit.main.host_exists")
    @patch("dropkit.main.Prompt.ask")
    @patch("dropkit.main.find_user_droplet")
    @patch("dropkit.main.load_config_and_api")
    def test_rename_no_ssh_config_entry(
        self, mock_load_config, mock_find_droplet, mock_prompt, mock_host_exists
    ):
        """Test rename when no SSH config entry exists for old name."""
        mock_api = MagicMock()
        mock_config_manager = MagicMock()
        mock_config_manager.config = create_mock_config()
        mock_load_config.return_value = (mock_config_manager, mock_api)

        mock_droplet = create_mock_droplet(name="old-name", status="active")
        mock_find_droplet.return_value = (mock_droplet, "testuser")

        mock_api.list_droplets.return_value = [mock_droplet]
        mock_api.get_droplet.return_value = mock_droplet
        mock_api.rename_droplet.return_value = {"id": 99999}
        mock_api.wait_for_action_complete.return_value = {"status": "completed"}

        mock_prompt.return_value = "yes"
        mock_host_exists.return_value = False  # No SSH entry

        result = runner.invoke(app, ["rename", "old-name", "new-name"])

        assert result.exit_code == 0
        assert "successfully renamed" in result.output.lower()
        assert "not found" in result.output.lower()  # SSH config not found message

    @patch("dropkit.main.find_user_droplet")
    @patch("dropkit.main.load_config_and_api")
    def test_rename_only_checks_user_droplets(self, mock_load_config, mock_find_droplet):
        """Test that name conflict check only considers user's own droplets."""
        mock_api = MagicMock()
        mock_config_manager = MagicMock()
        mock_config_manager.config = create_mock_config()
        mock_load_config.return_value = (mock_config_manager, mock_api)

        mock_droplet = create_mock_droplet(droplet_id=12345, name="old-name")
        mock_find_droplet.return_value = (mock_droplet, "testuser")

        # Only user's droplet is returned (filtered by tag)
        mock_api.list_droplets.return_value = [mock_droplet]

        # Existing droplet with same name but different user won't be in list
        # because list_droplets is called with tag_name=owner:testuser

        runner.invoke(app, ["rename", "old-name", "target-name"])

        # Should proceed past name conflict check
        # Verify list_droplets was called with the user tag
        mock_api.list_droplets.assert_called_once()
        call_kwargs = mock_api.list_droplets.call_args
        assert "owner:testuser" in str(call_kwargs)


class TestRenameEdgeCases:
    """Edge case tests for rename command."""

    @patch("dropkit.main.find_user_droplet")
    @patch("dropkit.main.load_config_and_api")
    def test_rename_droplet_missing_id(self, mock_load_config, mock_find_droplet):
        """Test rename when droplet has no ID."""
        mock_api = MagicMock()
        mock_config_manager = MagicMock()
        mock_config_manager.config = create_mock_config()
        mock_load_config.return_value = (mock_config_manager, mock_api)

        # Droplet without ID
        mock_droplet = {"name": "old-name", "status": "active"}
        mock_find_droplet.return_value = (mock_droplet, "testuser")

        result = runner.invoke(app, ["rename", "old-name", "new-name"])

        assert result.exit_code == 1
        assert "could not determine droplet id" in result.output.lower()

    @patch("dropkit.main.add_ssh_host")
    @patch("dropkit.main.remove_ssh_host")
    @patch("dropkit.main.host_exists")
    @patch("dropkit.main.Prompt.ask")
    @patch("dropkit.main.find_user_droplet")
    @patch("dropkit.main.load_config_and_api")
    def test_rename_ssh_update_failure_continues(
        self,
        mock_load_config,
        mock_find_droplet,
        mock_prompt,
        mock_host_exists,
        mock_remove_ssh,
        mock_add_ssh,
    ):
        """Test that SSH config update failure doesn't block rename success."""
        mock_api = MagicMock()
        mock_config_manager = MagicMock()
        mock_config_manager.config = create_mock_config()
        mock_load_config.return_value = (mock_config_manager, mock_api)

        mock_droplet = create_mock_droplet(name="old-name", status="active")
        mock_find_droplet.return_value = (mock_droplet, "testuser")

        mock_api.list_droplets.return_value = [mock_droplet]
        mock_api.get_droplet.return_value = mock_droplet
        mock_api.rename_droplet.return_value = {"id": 99999}
        mock_api.wait_for_action_complete.return_value = {"status": "completed"}

        mock_prompt.return_value = "yes"
        mock_host_exists.return_value = True
        mock_remove_ssh.side_effect = Exception("SSH config error")

        result = runner.invoke(app, ["rename", "old-name", "new-name"])

        # Rename should still succeed even if SSH config update fails
        assert result.exit_code == 0
        assert "successfully renamed" in result.output.lower()
        assert "could not update ssh config" in result.output.lower()

    @patch("dropkit.main.find_user_droplet")
    @patch("dropkit.main.load_config_and_api")
    def test_rename_multiple_droplets_same_user(self, mock_load_config, mock_find_droplet):
        """Test name conflict when user has multiple droplets."""
        mock_api = MagicMock()
        mock_config_manager = MagicMock()
        mock_config_manager.config = create_mock_config()
        mock_load_config.return_value = (mock_config_manager, mock_api)

        droplet_to_rename = create_mock_droplet(droplet_id=111, name="droplet-a")
        other_droplet = create_mock_droplet(droplet_id=222, name="droplet-b")
        target_droplet = create_mock_droplet(droplet_id=333, name="droplet-c")

        mock_find_droplet.return_value = (droplet_to_rename, "testuser")

        # User has 3 droplets
        mock_api.list_droplets.return_value = [
            droplet_to_rename,
            other_droplet,
            target_droplet,
        ]

        # Try to rename to existing name
        result = runner.invoke(app, ["rename", "droplet-a", "droplet-c"])

        assert result.exit_code == 1
        assert "already exists" in result.output.lower()
