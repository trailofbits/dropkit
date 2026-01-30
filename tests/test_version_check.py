"""Tests for version_check module."""

import json
import subprocess
import time
from unittest.mock import Mock, patch

from dropkit.version_check import (
    commits_differ,
    extract_commit_from_version,
    get_last_check_file,
    get_latest_git_commit,
    should_check_version,
    update_last_check_time,
)


class TestGetLastCheckFile:
    """Tests for get_last_check_file function."""

    def test_returns_correct_path(self, tmp_path, monkeypatch):
        """Test that get_last_check_file returns correct path."""
        # Mock Config.get_config_dir to return tmp_path
        from dropkit.config import Config

        monkeypatch.setattr(Config, "get_config_dir", lambda: tmp_path)

        result = get_last_check_file()

        assert result == tmp_path / ".last_version_check"
        assert result.name == ".last_version_check"


class TestShouldCheckVersion:
    """Tests for should_check_version function."""

    def test_no_file_returns_true(self, tmp_path, monkeypatch):
        """Test returns True when check file doesn't exist."""
        from dropkit.config import Config

        monkeypatch.setattr(Config, "get_config_dir", lambda: tmp_path)

        result = should_check_version()

        assert result is True

    def test_expired_check_returns_true(self, tmp_path, monkeypatch):
        """Test returns True when more than 24 hours have passed."""
        from dropkit.config import Config

        monkeypatch.setattr(Config, "get_config_dir", lambda: tmp_path)

        # Create check file with old timestamp (25 hours ago)
        check_file = tmp_path / ".last_version_check"
        old_timestamp = time.time() - (25 * 3600)  # 25 hours ago
        check_file.write_text(json.dumps({"timestamp": old_timestamp}))

        result = should_check_version()

        assert result is True

    def test_not_expired_returns_false(self, tmp_path, monkeypatch):
        """Test returns False when less than 24 hours have passed."""
        from dropkit.config import Config

        monkeypatch.setattr(Config, "get_config_dir", lambda: tmp_path)

        # Create check file with recent timestamp (1 hour ago)
        check_file = tmp_path / ".last_version_check"
        recent_timestamp = time.time() - 3600  # 1 hour ago
        check_file.write_text(json.dumps({"timestamp": recent_timestamp}))

        result = should_check_version()

        assert result is False

    def test_corrupted_file_returns_true(self, tmp_path, monkeypatch):
        """Test returns True when file contains invalid JSON."""
        from dropkit.config import Config

        monkeypatch.setattr(Config, "get_config_dir", lambda: tmp_path)

        # Create check file with invalid JSON
        check_file = tmp_path / ".last_version_check"
        check_file.write_text("not valid json {{{")

        result = should_check_version()

        assert result is True

    def test_missing_timestamp_returns_true(self, tmp_path, monkeypatch):
        """Test returns True when file missing timestamp key."""
        from dropkit.config import Config

        monkeypatch.setattr(Config, "get_config_dir", lambda: tmp_path)

        # Create check file without timestamp
        check_file = tmp_path / ".last_version_check"
        check_file.write_text(json.dumps({"other_key": "value"}))

        result = should_check_version()

        # Should return True because timestamp defaults to 0, making it very old
        assert result is True


class TestUpdateLastCheckTime:
    """Tests for update_last_check_time function."""

    def test_creates_file_with_correct_structure(self, tmp_path, monkeypatch):
        """Test creates file with timestamp and current_version."""
        from dropkit.config import Config

        monkeypatch.setattr(Config, "get_config_dir", lambda: tmp_path)

        before_time = time.time()
        update_last_check_time()
        after_time = time.time()

        check_file = tmp_path / ".last_version_check"
        assert check_file.exists()

        data = json.loads(check_file.read_text())
        assert "timestamp" in data
        assert "current_version" in data

        # Verify timestamp is recent (within the test execution window)
        assert before_time <= data["timestamp"] <= after_time

    def test_creates_parent_directory(self, tmp_path, monkeypatch):
        """Test creates parent directory if it doesn't exist."""
        from dropkit.config import Config

        nested_path = tmp_path / "nested" / "config"
        monkeypatch.setattr(Config, "get_config_dir", lambda: nested_path)

        update_last_check_time()

        check_file = nested_path / ".last_version_check"
        assert check_file.exists()
        assert check_file.parent == nested_path

    def test_silent_failure_on_permission_error(self, tmp_path, monkeypatch):
        """Test silently fails if can't write file."""
        from dropkit.config import Config

        monkeypatch.setattr(Config, "get_config_dir", lambda: tmp_path)

        # Mock open to raise OSError
        with patch("builtins.open", side_effect=OSError("Permission denied")):
            # Should not raise exception
            update_last_check_time()


class TestExtractCommitFromVersion:
    """Tests for extract_commit_from_version function."""

    def test_format_git_dot(self):
        """Test extraction from '0.1.0+git.abc1234' format."""
        result = extract_commit_from_version("0.1.0+git.abc1234")
        assert result == "abc1234"

    def test_format_plus_only(self):
        """Test extraction from '0.1.0+abc1234' format."""
        result = extract_commit_from_version("0.1.0+abc1234")
        assert result == "abc1234"

    def test_truncates_long_hash(self):
        """Test truncates hash to 7 characters."""
        result = extract_commit_from_version("0.1.0+git.abc1234567890")
        assert result == "abc1234"
        assert len(result) == 7

    def test_dev_version_returns_none(self):
        """Test returns None for 'dev' version."""
        result = extract_commit_from_version("dev")
        assert result is None

    def test_no_commit_returns_none(self):
        """Test returns None for version without commit."""
        result = extract_commit_from_version("0.1.0")
        assert result is None

    def test_empty_string_returns_none(self):
        """Test returns None for empty string."""
        result = extract_commit_from_version("")
        assert result is None

    def test_format_with_dots_in_suffix(self):
        """Test extraction when suffix contains dots."""
        result = extract_commit_from_version("0.1.0+dev.123.abc1234")
        # Should extract the last part after splitting by '.'
        assert result == "abc1234"


class TestCommitsDiffer:
    """Tests for commits_differ function."""

    def test_same_commit_returns_false(self):
        """Test returns False when commits match."""
        result = commits_differ("0.1.0+git.abc1234", "abc1234")
        assert result is False

    def test_different_commits_returns_true(self):
        """Test returns True when commits differ."""
        result = commits_differ("0.1.0+git.abc1234", "xyz9876")
        assert result is True

    def test_no_current_commit_returns_false(self):
        """Test returns False when current version has no commit."""
        result = commits_differ("0.1.0", "abc1234")
        assert result is False

    def test_case_insensitive_comparison(self):
        """Test comparison is case-insensitive."""
        result1 = commits_differ("0.1.0+git.ABC1234", "abc1234")
        result2 = commits_differ("0.1.0+git.abc1234", "ABC1234")

        assert result1 is False
        assert result2 is False

    def test_dev_version_returns_false(self):
        """Test returns False for dev version."""
        result = commits_differ("dev", "abc1234")
        assert result is False


class TestGetLatestGitCommit:
    """Tests for get_latest_git_commit function."""

    @patch("subprocess.run")
    def test_success_returns_short_hash(self, mock_run):
        """Test successful fetch returns 7-char hash."""
        # Mock successful git ls-remote
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "abc1234567890abcdef1234567890abcdef1234\tHEAD\n"
        mock_run.return_value = mock_result

        result = get_latest_git_commit()

        assert result == "abc1234"
        assert len(result) == 7

    @patch("subprocess.run")
    def test_nonzero_returncode_returns_none(self, mock_run):
        """Test non-zero return code returns None."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_run.return_value = mock_result

        result = get_latest_git_commit()

        assert result is None

    @patch("subprocess.run")
    def test_empty_output_returns_none(self, mock_run):
        """Test empty stdout returns None."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_run.return_value = mock_result

        result = get_latest_git_commit()

        assert result is None

    @patch("subprocess.run")
    def test_timeout_returns_none(self, mock_run):
        """Test timeout returns None."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="git", timeout=5)

        result = get_latest_git_commit()

        assert result is None

    @patch("subprocess.run")
    def test_subprocess_error_returns_none(self, mock_run):
        """Test subprocess error returns None."""
        mock_run.side_effect = subprocess.SubprocessError("Command failed")

        result = get_latest_git_commit()

        assert result is None

    @patch("subprocess.run")
    def test_os_error_returns_none(self, mock_run):
        """Test OS error returns None."""
        mock_run.side_effect = OSError("Git not found")

        result = get_latest_git_commit()

        assert result is None

    @patch("subprocess.run")
    def test_calls_git_with_correct_args(self, mock_run):
        """Test calls git ls-remote with correct arguments."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "abc1234567890\tHEAD\n"
        mock_run.return_value = mock_result

        get_latest_git_commit()

        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert call_args == [
            "git",
            "ls-remote",
            "https://github.com/trailofbits/dropkit.git",
            "HEAD",
        ]
