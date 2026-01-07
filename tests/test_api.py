"""Tests for DigitalOcean API client."""

import pytest

from tobcloud.api import DigitalOceanAPI


class TestDigitalOceanAPI:
    """Tests for DigitalOceanAPI class."""

    def test_sanitize_email_for_username_trailofbits(self):
        """Test sanitizing trailofbits.com email."""
        username = DigitalOceanAPI._sanitize_email_for_username("john.doe@trailofbits.com")
        assert username == "john_doe"

    def test_sanitize_email_for_username_other_domain(self):
        """Test sanitizing other domain email."""
        username = DigitalOceanAPI._sanitize_email_for_username("john.doe@example.com")
        assert username == "john_doe"

    def test_sanitize_email_for_username_special_chars(self):
        """Test sanitizing email with special characters."""
        username = DigitalOceanAPI._sanitize_email_for_username("john-doe+test@trailofbits.com")
        assert username == "john_doe_test"

    def test_sanitize_email_for_username_starts_with_number(self):
        """Test sanitizing email that starts with number."""
        username = DigitalOceanAPI._sanitize_email_for_username("123user@trailofbits.com")
        assert username == "u123user"

    def test_sanitize_email_for_username_empty_fallback(self):
        """Test sanitizing empty email."""
        username = DigitalOceanAPI._sanitize_email_for_username("@trailofbits.com")
        assert username == "user"


class TestValidatePositiveInt:
    """Tests for _validate_positive_int method."""

    def test_valid_positive_int(self):
        """Test validation passes for positive integer."""
        # Should not raise
        DigitalOceanAPI._validate_positive_int(1, "test_id")
        DigitalOceanAPI._validate_positive_int(100, "test_id")
        DigitalOceanAPI._validate_positive_int(999999, "test_id")

    def test_zero_raises_error(self):
        """Test validation fails for zero."""
        with pytest.raises(ValueError, match="test_id must be a positive integer"):
            DigitalOceanAPI._validate_positive_int(0, "test_id")

    def test_negative_raises_error(self):
        """Test validation fails for negative integer."""
        with pytest.raises(ValueError, match="droplet_id must be a positive integer"):
            DigitalOceanAPI._validate_positive_int(-1, "droplet_id")

        with pytest.raises(ValueError, match="action_id must be a positive integer"):
            DigitalOceanAPI._validate_positive_int(-100, "action_id")

    def test_error_message_includes_value(self):
        """Test error message includes the invalid value."""
        with pytest.raises(ValueError, match="got: -5"):
            DigitalOceanAPI._validate_positive_int(-5, "snapshot_id")


class TestGetDropletUrn:
    """Tests for get_droplet_urn static method."""

    def test_urn_format(self):
        """Test URN is in correct format."""
        assert DigitalOceanAPI.get_droplet_urn(12345) == "do:droplet:12345"

    def test_urn_with_large_id(self):
        """Test URN with large droplet ID."""
        assert DigitalOceanAPI.get_droplet_urn(999999999) == "do:droplet:999999999"


class TestListDropletActions:
    """Tests for list_droplet_actions method validation."""

    def test_list_droplet_actions_invalid_id_zero(self):
        """Test that list_droplet_actions raises ValueError for zero droplet_id."""
        api = DigitalOceanAPI("fake-token")
        with pytest.raises(ValueError, match="droplet_id must be a positive integer"):
            api.list_droplet_actions(0)

    def test_list_droplet_actions_invalid_id_negative(self):
        """Test that list_droplet_actions raises ValueError for negative droplet_id."""
        api = DigitalOceanAPI("fake-token")
        with pytest.raises(ValueError, match="droplet_id must be a positive integer"):
            api.list_droplet_actions(-1)


class TestRenameDroplet:
    """Tests for rename_droplet method validation."""

    def test_rename_droplet_invalid_id_zero(self):
        """Test that rename_droplet raises ValueError for zero droplet_id."""
        api = DigitalOceanAPI("fake-token")
        with pytest.raises(ValueError, match="droplet_id must be a positive integer"):
            api.rename_droplet(0, "new-name")

    def test_rename_droplet_invalid_id_negative(self):
        """Test that rename_droplet raises ValueError for negative droplet_id."""
        api = DigitalOceanAPI("fake-token")
        with pytest.raises(ValueError, match="droplet_id must be a positive integer"):
            api.rename_droplet(-1, "new-name")
