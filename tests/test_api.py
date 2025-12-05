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
        """Test that positive integers pass validation."""
        # Should not raise
        DigitalOceanAPI._validate_positive_int(1, "test_id")
        DigitalOceanAPI._validate_positive_int(100, "test_id")
        DigitalOceanAPI._validate_positive_int(999999, "test_id")

    def test_zero_raises_value_error(self):
        """Test that zero raises ValueError."""
        with pytest.raises(ValueError, match="test_id must be a positive integer"):
            DigitalOceanAPI._validate_positive_int(0, "test_id")

    def test_negative_raises_value_error(self):
        """Test that negative integers raise ValueError."""
        with pytest.raises(ValueError, match="droplet_id must be a positive integer"):
            DigitalOceanAPI._validate_positive_int(-1, "droplet_id")

        with pytest.raises(ValueError, match="action_id must be a positive integer"):
            DigitalOceanAPI._validate_positive_int(-100, "action_id")


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
