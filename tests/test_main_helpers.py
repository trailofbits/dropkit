"""Tests for main module helper functions."""

from unittest.mock import MagicMock

from tobcloud.main import (
    build_droplet_tags,
    find_snapshot_action,
    get_droplet_name_from_snapshot,
    get_snapshot_name,
    get_ssh_hostname,
    get_user_tag,
)


class TestGetSnapshotName:
    """Tests for get_snapshot_name function."""

    def test_simple_name(self):
        """Test snapshot name for simple droplet name."""
        assert get_snapshot_name("myvm") == "tobcloud-myvm"

    def test_name_with_hyphen(self):
        """Test snapshot name for droplet name with hyphen."""
        assert get_snapshot_name("my-droplet") == "tobcloud-my-droplet"

    def test_name_with_numbers(self):
        """Test snapshot name for droplet name with numbers."""
        assert get_snapshot_name("test123") == "tobcloud-test123"

    def test_empty_name(self):
        """Test snapshot name for empty droplet name."""
        assert get_snapshot_name("") == "tobcloud-"


class TestGetDropletNameFromSnapshot:
    """Tests for get_droplet_name_from_snapshot function."""

    def test_valid_tobcloud_snapshot(self):
        """Test extracting droplet name from valid tobcloud snapshot."""
        assert get_droplet_name_from_snapshot("tobcloud-myvm") == "myvm"

    def test_snapshot_with_hyphen_in_name(self):
        """Test extracting droplet name with hyphens."""
        assert get_droplet_name_from_snapshot("tobcloud-my-droplet") == "my-droplet"

    def test_non_tobcloud_snapshot(self):
        """Test with non-tobcloud snapshot name."""
        assert get_droplet_name_from_snapshot("other-snapshot") is None

    def test_partial_prefix(self):
        """Test with partial prefix (should not match)."""
        assert get_droplet_name_from_snapshot("tobcloud") is None

    def test_different_prefix(self):
        """Test with different prefix."""
        assert get_droplet_name_from_snapshot("snapshot-myvm") is None

    def test_empty_after_prefix(self):
        """Test snapshot name that is just the prefix."""
        assert get_droplet_name_from_snapshot("tobcloud-") == ""


class TestGetSshHostname:
    """Tests for get_ssh_hostname function."""

    def test_simple_name(self):
        """Test SSH hostname for simple droplet name."""
        assert get_ssh_hostname("myvm") == "tobcloud.myvm"

    def test_name_with_hyphen(self):
        """Test SSH hostname for droplet name with hyphen."""
        assert get_ssh_hostname("my-droplet") == "tobcloud.my-droplet"


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
