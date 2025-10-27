"""Tests for DigitalOcean API client."""

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
