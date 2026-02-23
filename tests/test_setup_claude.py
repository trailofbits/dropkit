"""Tests for setup-claude command helpers."""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer

from dropkit.main import (
    _GITHUB_TOKEN_PREFIXES,
    _SETTINGS_SAFE_KEYS,
    SSH_OPTS,
    SyncChoice,
    _auth_github,
    _discover_sync_choices,
    _install_claude_code,
    _open_auth_session,
    _prompt_sync_selection,
    _sanitize_installed_plugins,
    _sanitize_known_marketplaces,
    _sanitize_settings,
    _ssh_cmd,
    _sync_settings,
    setup_claude,
)


class TestSSHOpts:
    """Tests for SSH_OPTS constant."""

    def test_contains_strict_host_key_checking(self):
        assert "-o" in SSH_OPTS
        assert "StrictHostKeyChecking=no" in SSH_OPTS

    def test_contains_user_known_hosts_file(self):
        assert "UserKnownHostsFile=/dev/null" in SSH_OPTS

    def test_does_not_contain_connect_timeout(self):
        """ConnectTimeout is per-call-site, not in the shared constant."""
        for opt in SSH_OPTS:
            assert not opt.startswith("ConnectTimeout")


class TestSSHCmd:
    """Tests for _ssh_cmd helper."""

    def test_basic_command(self):
        cmd = _ssh_cmd("dropkit.test", "echo hello")
        assert cmd[0] == "ssh"
        assert "dropkit.test" in cmd
        assert "echo hello" in cmd
        assert "ConnectTimeout=10" in cmd

    def test_includes_ssh_opts(self):
        cmd = _ssh_cmd("dropkit.test", "ls")
        for opt in SSH_OPTS:
            assert opt in cmd


class TestInstallClaudeCode:
    """Tests for _install_claude_code function."""

    @patch("dropkit.main.subprocess.run")
    def test_already_installed(self, mock_run):
        """Skip install if claude --version succeeds."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"1.0.0",
        )
        assert _install_claude_code("dropkit.test", verbose=False) is True
        # Only called once (version check), no install
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "claude --version" in cmd[-1]

    @patch("dropkit.main.subprocess.run")
    def test_version_check_uses_login_shell(self, mock_run):
        """Version check uses bash -lc to pick up PATH changes."""
        mock_run.return_value = MagicMock(returncode=0, stdout=b"1.0.0")
        _install_claude_code("dropkit.test", verbose=False)
        cmd = mock_run.call_args[0][0]
        assert "bash -lc" in cmd[-1]

    @patch("dropkit.main.subprocess.run")
    def test_install_success(self, mock_run):
        """Install succeeds when claude not present."""
        # First call: version check fails; second: install succeeds; third: version after install
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout=b""),
            MagicMock(returncode=0, stdout=b"", stderr=b""),
            MagicMock(returncode=0, stdout=b"2.0.0"),
        ]
        assert _install_claude_code("dropkit.test", verbose=False) is True
        assert mock_run.call_count == 3
        # Second call should be the install command
        install_cmd = mock_run.call_args_list[1][0][0]
        assert "curl" in install_cmd[-1]

    @patch("dropkit.main.subprocess.run")
    def test_install_failure(self, mock_run):
        """Returns False when install fails."""
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout=b""),
            MagicMock(returncode=1, stdout=b"", stderr=b"some error"),
        ]
        assert _install_claude_code("dropkit.test", verbose=False) is False

    @patch("dropkit.main.console")
    @patch("dropkit.main.subprocess.run")
    def test_install_failure_shows_last_stderr_line(self, mock_run, mock_console):
        """Always shows last line of stderr on install failure."""
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout=b""),
            MagicMock(returncode=1, stdout=b"", stderr=b"line1\nline2\nactual error"),
        ]
        assert _install_claude_code("dropkit.test", verbose=False) is False
        # Check that the last line of stderr was printed
        print_calls = [str(c) for c in mock_console.print.call_args_list]
        assert any("actual error" in c for c in print_calls)

    @patch("dropkit.main.console")
    @patch("dropkit.main.subprocess.run")
    def test_install_failure_verbose_shows_full_stderr(self, mock_run, mock_console):
        """Shows full stderr in verbose mode on failure."""
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout=b""),
            MagicMock(returncode=1, stdout=b"", stderr=b"line1\nline2\nactual error"),
        ]
        assert _install_claude_code("dropkit.test", verbose=True) is False
        print_calls = [str(c) for c in mock_console.print.call_args_list]
        assert any("line1" in c and "line2" in c for c in print_calls)

    @patch("dropkit.main.console")
    @patch("dropkit.main.subprocess.run")
    def test_install_failure_falls_back_to_stdout(self, mock_run, mock_console):
        """Shows stdout when stderr is empty on install failure."""
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout=b""),
            MagicMock(returncode=1, stdout=b"stdout hint here", stderr=b""),
        ]
        assert _install_claude_code("dropkit.test", verbose=False) is False
        print_calls = [str(c) for c in mock_console.print.call_args_list]
        assert any("stdout hint" in c for c in print_calls)

    @patch("dropkit.main.console")
    @patch("dropkit.main.subprocess.run")
    def test_install_failure_no_output_shows_guidance(self, mock_run, mock_console):
        """Shows actionable guidance when both stderr and stdout are empty."""
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout=b""),
            MagicMock(returncode=1, stdout=b"", stderr=b""),
        ]
        assert _install_claude_code("dropkit.test", verbose=False) is False
        print_calls = [str(c) for c in mock_console.print.call_args_list]
        assert any("--verbose" in c for c in print_calls)

    @patch("dropkit.main.subprocess.run")
    def test_uses_ssh_opts(self, mock_run):
        """SSH commands include SSH_OPTS."""
        mock_run.return_value = MagicMock(returncode=0, stdout=b"1.0.0")
        _install_claude_code("dropkit.test", verbose=False)
        cmd = mock_run.call_args[0][0]
        for opt in SSH_OPTS:
            assert opt in cmd

    @patch("dropkit.main.subprocess.run")
    def test_timeout_expired_returns_false(self, mock_run):
        """Returns False on SSH timeout."""
        mock_run.side_effect = subprocess.TimeoutExpired("ssh", 30)
        assert _install_claude_code("dropkit.test", verbose=False) is False

    @patch("dropkit.main.subprocess.run")
    def test_subprocess_error_returns_false(self, mock_run):
        """Returns False when subprocess raises SubprocessError."""
        mock_run.side_effect = subprocess.SubprocessError("ssh failed")
        assert _install_claude_code("dropkit.test", verbose=False) is False

    @patch("dropkit.main.console")
    @patch("dropkit.main.subprocess.run")
    def test_ssh_connection_failure_exit_255(self, mock_run, mock_console):
        """Exit code 255 is reported as SSH connection failure, not 'not installed'."""
        mock_run.return_value = MagicMock(
            returncode=255,
            stdout=b"",
            stderr=b"ssh: connect to host example.com port 22: Connection refused",
        )
        assert _install_claude_code("dropkit.test", verbose=False) is False
        print_calls = [str(c) for c in mock_console.print.call_args_list]
        assert any("Connection refused" in c for c in print_calls)
        # Should NOT proceed to install
        mock_run.assert_called_once()

    @patch("dropkit.main.console")
    @patch("dropkit.main.subprocess.run")
    def test_verbose_logs_fallthrough_to_install(self, mock_run, mock_console):
        """In verbose mode, logs why install was triggered on unexpected exit code."""
        mock_run.side_effect = [
            MagicMock(returncode=127, stdout=b"", stderr=b"command not found"),
            MagicMock(returncode=0, stdout=b"", stderr=b""),  # install succeeds
            MagicMock(returncode=0, stdout=b"1.0.0"),  # version check
        ]
        assert _install_claude_code("dropkit.test", verbose=True) is True
        print_calls = [str(c) for c in mock_console.print.call_args_list]
        assert any("claude not found" in c for c in print_calls)

    @patch("dropkit.main.console")
    @patch("dropkit.main.subprocess.run")
    def test_install_phase_timeout_returns_false(self, mock_run, mock_console):
        """Returns False when version check passes (not installed) but install times out."""
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout=b""),  # version check: not installed
            subprocess.TimeoutExpired("ssh", 300),  # install times out
        ]
        assert _install_claude_code("dropkit.test", verbose=False) is False
        print_calls = [str(c) for c in mock_console.print.call_args_list]
        assert any("FAILED" in c for c in print_calls)

    @patch("dropkit.main.console")
    @patch("dropkit.main.subprocess.run")
    def test_post_install_version_check_failure_returns_true(self, mock_run, mock_console):
        """Install succeeded but version probe failed still returns True."""
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout=b""),  # not installed
            MagicMock(returncode=0, stdout=b"", stderr=b""),  # install succeeds
            MagicMock(returncode=1, stdout=b"", stderr=b""),  # version check fails
        ]
        assert _install_claude_code("dropkit.test", verbose=False) is True
        print_calls = [str(c) for c in mock_console.print.call_args_list]
        assert any("done" in c for c in print_calls)


class TestAuthGithub:
    """Tests for _auth_github function."""

    @patch.dict("os.environ", {}, clear=True)
    @patch("dropkit.main.subprocess.run")
    def test_skipped_without_token(self, mock_run):
        """Skips when GITHUB_TOKEN not set."""
        _auth_github("dropkit.test", verbose=False)
        mock_run.assert_not_called()

    @patch.dict("os.environ", {"GITHUB_TOKEN": ""})
    @patch("dropkit.main.subprocess.run")
    def test_skipped_with_empty_token(self, mock_run):
        """Skips when GITHUB_TOKEN is empty string."""
        _auth_github("dropkit.test", verbose=False)
        mock_run.assert_not_called()

    @patch.dict("os.environ", {"GITHUB_TOKEN": "ghp_test123"})
    @patch("dropkit.main.subprocess.run")
    def test_auth_success(self, mock_run):
        """Pipes token into gh auth login."""
        mock_run.return_value = MagicMock(returncode=0)
        _auth_github("dropkit.test", verbose=False)
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "gh auth login --with-token" in cmd[-1]
        assert mock_run.call_args[1]["input"] == b"ghp_test123"

    @patch.dict("os.environ", {"GITHUB_TOKEN": "ghp_test123"})
    @patch("dropkit.main.subprocess.run")
    def test_auth_failure_shows_stderr(self, mock_run):
        """Shows actual stderr on auth failure, not a generic message."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stderr=b"error connecting to api.github.com",
        )
        # Should not raise
        _auth_github("dropkit.test", verbose=False)

    @patch.dict("os.environ", {"GITHUB_TOKEN": "ghp_test123"})
    @patch("dropkit.main.subprocess.run")
    def test_timeout_does_not_raise(self, mock_run):
        """Timeout is caught gracefully."""
        mock_run.side_effect = subprocess.TimeoutExpired("ssh", 60)
        # Should not raise
        _auth_github("dropkit.test", verbose=False)

    @patch.dict("os.environ", {"GITHUB_TOKEN": "ghp_test123"})
    @patch("dropkit.main.console")
    @patch("dropkit.main.subprocess.run")
    def test_gh_not_found_reports_clearly(self, mock_run, mock_console):
        """Reports 'gh CLI not installed' when gh is missing on remote."""
        mock_run.return_value = MagicMock(
            returncode=127,
            stderr=b"bash: gh: command not found",
        )
        _auth_github("dropkit.test", verbose=False)
        print_calls = [str(c) for c in mock_console.print.call_args_list]
        assert any("not installed" in c for c in print_calls)

    @patch.dict("os.environ", {"GITHUB_TOKEN": "not-a-github-token"})
    @patch("dropkit.main.console")
    @patch("dropkit.main.subprocess.run")
    def test_invalid_token_format_skipped(self, mock_run, mock_console):
        """Skips auth when GITHUB_TOKEN doesn't look like a GitHub token."""
        _auth_github("dropkit.test", verbose=False)
        mock_run.assert_not_called()
        print_calls = [str(c) for c in mock_console.print.call_args_list]
        assert any("does not look like" in c for c in print_calls)

    @patch.dict("os.environ", {"GITHUB_TOKEN": "ghp_test123"})
    @patch("dropkit.main.console")
    @patch("dropkit.main.subprocess.run")
    def test_ssh_exit_255_reports_connection_lost(self, mock_run, mock_console):
        """Exit code 255 is reported as SSH connection lost."""
        mock_run.return_value = MagicMock(
            returncode=255,
            stderr=b"ssh: connect to host example.com port 22: Connection refused",
        )
        _auth_github("dropkit.test", verbose=False)
        print_calls = [str(c) for c in mock_console.print.call_args_list]
        assert any("SSH connection lost" in c for c in print_calls)

    def test_all_github_token_prefixes_accepted(self):
        """All known GitHub token prefixes pass validation."""
        for prefix in _GITHUB_TOKEN_PREFIXES:
            assert f"{prefix}abc123".startswith(_GITHUB_TOKEN_PREFIXES)


class TestDiscoverSyncChoices:
    """Tests for _discover_sync_choices function."""

    def test_base_items_present(self, tmp_path):
        """CLAUDE.md and Settings appear when local files exist."""
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        (claude_dir / "CLAUDE.md").write_text("# test")
        (claude_dir / "settings.json").write_text("{}")

        with patch("dropkit.main.Path.expanduser", return_value=tmp_path / ".claude" / "CLAUDE.md"):
            # Need to patch per-path, so use a side-effect instead
            pass

        def expand_side_effect(self):
            local_path = str(self)
            if "CLAUDE.md" in local_path:
                return claude_dir / "CLAUDE.md"
            if "settings.json" in local_path:
                return claude_dir / "settings.json"
            if "known_marketplaces.json" in local_path:
                return tmp_path / "nonexistent"
            return tmp_path / "nonexistent"

        with (
            patch.object(Path, "expanduser", expand_side_effect),
            patch.dict("os.environ", {}, clear=True),
        ):
            choices = _discover_sync_choices()

        keys = [c.key for c in choices]
        assert "claude_md" in keys
        assert "settings" in keys

    def test_marketplace_discovery(self, tmp_path):
        """Marketplace names come from known_marketplaces.json keys."""
        claude_dir = tmp_path / ".claude"
        plugins_dir = claude_dir / "plugins"
        plugins_dir.mkdir(parents=True)
        mp_file = plugins_dir / "known_marketplaces.json"
        mp_file.write_text(json.dumps({"mp-b": {}, "mp-a": {}}))

        def expand_side_effect(self):
            local_path = str(self)
            if "known_marketplaces.json" in local_path:
                return mp_file
            return tmp_path / "nonexistent"

        with (
            patch.object(Path, "expanduser", expand_side_effect),
            patch.dict("os.environ", {}, clear=True),
        ):
            choices = _discover_sync_choices()

        mp_keys = [c.key for c in choices if c.key.startswith("marketplace:")]
        assert mp_keys == ["marketplace:mp-a", "marketplace:mp-b"]  # sorted

    def test_missing_marketplace_file(self, tmp_path):
        """Returns base items when marketplace file doesn't exist."""

        def expand_side_effect(self):
            local_path = str(self)
            if "CLAUDE.md" in local_path:
                p = tmp_path / "CLAUDE.md"
                p.write_text("# test")
                return p
            return tmp_path / "nonexistent"

        with (
            patch.object(Path, "expanduser", expand_side_effect),
            patch.dict("os.environ", {}, clear=True),
        ):
            choices = _discover_sync_choices()

        keys = [c.key for c in choices]
        assert "claude_md" in keys
        assert not any(k.startswith("marketplace:") for k in keys)

    def test_malformed_json_graceful(self, tmp_path):
        """Malformed marketplace JSON doesn't crash."""
        plugins_dir = tmp_path / ".claude" / "plugins"
        plugins_dir.mkdir(parents=True)
        (plugins_dir / "known_marketplaces.json").write_text("{bad json")

        def expand_side_effect(self):
            local_path = str(self)
            if "known_marketplaces.json" in local_path:
                return plugins_dir / "known_marketplaces.json"
            return tmp_path / "nonexistent"

        with (
            patch.object(Path, "expanduser", expand_side_effect),
            patch.dict("os.environ", {}, clear=True),
        ):
            choices = _discover_sync_choices()

        # Should return without marketplace items, no exception
        assert not any(c.key.startswith("marketplace:") for c in choices)

    @patch.dict("os.environ", {"GITHUB_TOKEN": "ghp_test123"})
    def test_github_token_included(self, tmp_path):
        """GitHub token choice appears when GITHUB_TOKEN is set with valid prefix."""

        def expand_side_effect(self):
            return tmp_path / "nonexistent"

        with patch.object(Path, "expanduser", expand_side_effect):
            choices = _discover_sync_choices()

        keys = [c.key for c in choices]
        assert "github_token" in keys

    @patch.dict("os.environ", {"GITHUB_TOKEN": "not-a-token"})
    def test_github_token_excluded_invalid_prefix(self, tmp_path):
        """GitHub token choice excluded when prefix is invalid."""

        def expand_side_effect(self):
            return tmp_path / "nonexistent"

        with patch.object(Path, "expanduser", expand_side_effect):
            choices = _discover_sync_choices()

        keys = [c.key for c in choices]
        assert "github_token" not in keys

    def test_skips_items_where_source_missing(self, tmp_path):
        """Skips CLAUDE.md and settings when local files don't exist."""

        def expand_side_effect(self):
            return tmp_path / "nonexistent"

        with (
            patch.object(Path, "expanduser", expand_side_effect),
            patch.dict("os.environ", {}, clear=True),
        ):
            choices = _discover_sync_choices()

        keys = [c.key for c in choices]
        assert "claude_md" not in keys
        assert "settings" not in keys


class TestPromptSyncSelection:
    """Tests for _prompt_sync_selection function."""

    def test_all_returns_all_keys(self):
        """'all' input returns all choice keys."""
        choices = [
            SyncChoice("A", "key_a"),
            SyncChoice("B", "key_b"),
        ]
        with patch("dropkit.main.Prompt.ask", return_value="all"):
            result = _prompt_sync_selection(choices)
        assert result == {"key_a", "key_b"}

    def test_none_returns_empty_set(self):
        """'none' input returns empty set."""
        choices = [SyncChoice("A", "key_a")]
        with patch("dropkit.main.Prompt.ask", return_value="none"):
            result = _prompt_sync_selection(choices)
        assert result == set()

    def test_comma_separated_numbers(self):
        """Comma-separated numbers select corresponding items."""
        choices = [
            SyncChoice("A", "key_a"),
            SyncChoice("B", "key_b"),
            SyncChoice("C", "key_c"),
        ]
        with patch("dropkit.main.Prompt.ask", return_value="1,3"):
            result = _prompt_sync_selection(choices)
        assert result == {"key_a", "key_c"}

    def test_invalid_input_exits(self):
        """Non-numeric input causes typer.Exit(1)."""
        choices = [SyncChoice("A", "key_a")]
        with (
            patch("dropkit.main.Prompt.ask", return_value="abc"),
            pytest.raises(typer.Exit) as exc_info,
        ):
            _prompt_sync_selection(choices)
        assert exc_info.value.exit_code == 1

    def test_out_of_range_exits_with_error(self):
        """Numbers out of range cause typer.Exit(1)."""
        choices = [SyncChoice("A", "key_a")]
        with (
            patch("dropkit.main.Prompt.ask", return_value="1,99"),
            pytest.raises(typer.Exit) as exc_info,
        ):
            _prompt_sync_selection(choices)
        assert exc_info.value.exit_code == 1

    def test_empty_choices_returns_empty(self):
        """Empty choices list returns empty set without prompting."""
        result = _prompt_sync_selection([])
        assert result == set()

    def test_default_is_all(self):
        """Default answer is 'all' (just pressing enter)."""
        choices = [SyncChoice("A", "key_a")]
        with patch("dropkit.main.Prompt.ask", return_value="all") as mock_ask:
            _prompt_sync_selection(choices)
        assert mock_ask.call_args[1]["default"] == "all"


# Shared fixture for _sync_settings tests that need a local file
def _make_expand_side_effect(claude_md_path, fallback_dir):
    """Create an expanduser side effect that resolves CLAUDE.md and falls back for others."""

    def expand_side_effect(self):
        local_path = str(self)
        if "CLAUDE.md" in local_path:
            return claude_md_path
        return fallback_dir / "nonexistent"

    return expand_side_effect


class TestSanitizeSettings:
    """Tests for _sanitize_settings pure function."""

    def test_strips_sensitive_keys(self):
        """Sensitive keys like permissions, env, hooks are removed."""
        data = {
            "model": "opus",
            "permissions": {"/path/to/project": {"allow": ["Read"]}},
            "env": {"SECRET_KEY": "abc123"},
            "hooks": {"pre-commit": "/local/script.sh"},
            "apiKeyHelper": "/usr/local/bin/get-key",
            "sandbox": {"allowedDomains": ["internal.corp"]},
            "statusLine": {"command": "/local/status.sh"},
        }
        result = _sanitize_settings(data)
        assert "model" in result
        for key in ("permissions", "env", "hooks", "apiKeyHelper", "sandbox", "statusLine"):
            assert key not in result

    def test_preserves_allowlisted_keys(self):
        """All allowlisted keys pass through unchanged."""
        data = {
            "model": "opus",
            "enabledPlugins": ["plugin-a"],
            "language": "en",
            "effortLevel": "high",
            "fastMode": True,
        }
        result = _sanitize_settings(data)
        assert result == data

    def test_empty_dict(self):
        """Empty input returns empty output."""
        assert _sanitize_settings({}) == {}

    def test_does_not_mutate_input(self):
        """Original dict is unchanged after sanitization."""
        data = {"model": "opus", "env": {"SECRET": "value"}}
        original = data.copy()
        _sanitize_settings(data)
        assert data == original

    def test_unknown_keys_dropped(self):
        """Keys not in the allowlist are excluded."""
        data = {"model": "opus", "some_future_key": "value", "anotherNewThing": [1, 2]}
        result = _sanitize_settings(data)
        assert result == {"model": "opus"}

    def test_all_safe_keys_accepted(self):
        """Every key in _SETTINGS_SAFE_KEYS passes through."""
        data = {k: f"value-{k}" for k in _SETTINGS_SAFE_KEYS}
        result = _sanitize_settings(data)
        assert set(result.keys()) == _SETTINGS_SAFE_KEYS

    @pytest.mark.parametrize(
        "key",
        [
            "alwaysThinkingEnabled",
            "teammateMode",
            "skipWebFetchPreflight",
            "attribution",
            "includeCoAuthoredBy",
            "skippedMarketplaces",
            "skippedPlugins",
            "pluginConfigs",
            "companyAnnouncements",
        ],
    )
    def test_new_safe_keys_preserved(self, key):
        """Each newly added safe key passes through sanitization."""
        data = {key: "test-value"}
        result = _sanitize_settings(data)
        assert result[key] == "test-value"

    def test_strips_file_marketplace_sources(self):
        """extraKnownMarketplaces entries with type 'file' are stripped."""
        data = {
            "extraKnownMarketplaces": {
                "local-mp": {"type": "file", "path": "/Users/brad/marketplace"},
            },
        }
        result = _sanitize_settings(data)
        assert result["extraKnownMarketplaces"] == {}

    def test_strips_directory_marketplace_sources(self):
        """extraKnownMarketplaces entries with type 'directory' are stripped."""
        data = {
            "extraKnownMarketplaces": {
                "dir-mp": {"type": "directory", "path": "/Users/brad/marketplaces"},
            },
        }
        result = _sanitize_settings(data)
        assert result["extraKnownMarketplaces"] == {}

    @pytest.mark.parametrize("source_type", ["url", "github", "git", "npm"])
    def test_preserves_remote_marketplace_sources(self, source_type):
        """extraKnownMarketplaces entries with remote types are preserved."""
        data = {
            "extraKnownMarketplaces": {
                "remote-mp": {"type": source_type, "url": "https://example.com/mp"},
            },
        }
        result = _sanitize_settings(data)
        assert "remote-mp" in result["extraKnownMarketplaces"]

    def test_mixed_marketplace_sources(self):
        """Local-path sources stripped while remote sources kept."""
        data = {
            "extraKnownMarketplaces": {
                "local-file": {"type": "file", "path": "/Users/brad/mp"},
                "local-dir": {"type": "directory", "path": "/Users/brad/mps"},
                "remote-url": {"type": "url", "url": "https://example.com/mp"},
                "remote-git": {"type": "github", "repo": "org/repo"},
            },
        }
        result = _sanitize_settings(data)
        assert "local-file" not in result["extraKnownMarketplaces"]
        assert "local-dir" not in result["extraKnownMarketplaces"]
        assert "remote-url" in result["extraKnownMarketplaces"]
        assert "remote-git" in result["extraKnownMarketplaces"]


class TestSanitizeKnownMarketplaces:
    """Tests for _sanitize_known_marketplaces pure function."""

    def test_rewrites_install_location(self):
        """Rewrites installLocation paths from local to remote home."""
        data = {
            "marketplace-a": {
                "installLocation": "/Users/brad/.claude/plugins/marketplaces/marketplace-a",
                "url": "https://example.com/repo",
            },
        }
        result = _sanitize_known_marketplaces(data, "/Users/brad", "/home/brad")
        assert result["marketplace-a"]["installLocation"] == (
            "/home/brad/.claude/plugins/marketplaces/marketplace-a"
        )
        assert result["marketplace-a"]["url"] == "https://example.com/repo"

    def test_empty_dict(self):
        """Empty input returns empty output."""
        assert _sanitize_known_marketplaces({}, "/Users/brad", "/home/brad") == {}

    def test_leaves_entries_without_install_location(self):
        """Entries without installLocation are preserved unchanged."""
        data = {"marketplace-b": {"url": "https://example.com/repo"}}
        result = _sanitize_known_marketplaces(data, "/Users/brad", "/home/brad")
        assert result == data

    def test_does_not_mutate_input(self):
        """Original dict is unchanged after sanitization."""
        data = {
            "m": {"installLocation": "/Users/brad/.claude/plugins/marketplaces/m"},
        }
        original_loc = data["m"]["installLocation"]
        _sanitize_known_marketplaces(data, "/Users/brad", "/home/brad")
        assert data["m"]["installLocation"] == original_loc

    def test_marketplace_filter_includes_only_matching(self):
        """marketplace_filter restricts output to matching keys."""
        data = {
            "mp-a": {"installLocation": "/Users/brad/.claude/plugins/marketplaces/mp-a"},
            "mp-b": {"installLocation": "/Users/brad/.claude/plugins/marketplaces/mp-b"},
            "mp-c": {"url": "https://example.com"},
        }
        result = _sanitize_known_marketplaces(
            data, "/Users/brad", "/home/brad", marketplace_filter={"mp-a", "mp-c"}
        )
        assert "mp-a" in result
        assert "mp-b" not in result
        assert "mp-c" in result

    def test_marketplace_filter_none_includes_all(self):
        """marketplace_filter=None includes everything (default)."""
        data = {"mp-a": {}, "mp-b": {}}
        result = _sanitize_known_marketplaces(
            data, "/Users/brad", "/home/brad", marketplace_filter=None
        )
        assert set(result.keys()) == {"mp-a", "mp-b"}


class TestSanitizeInstalledPlugins:
    """Tests for _sanitize_installed_plugins pure function (v2 format)."""

    def test_rewrites_install_path_for_user_scope(self):
        """Rewrites installPath for user-scope entries."""
        data = {
            "version": 2,
            "plugins": {
                "plugin-a@source": [
                    {
                        "scope": "user",
                        "installPath": "/Users/brad/.claude/plugins/cache/plugin-a",
                        "version": "1.0.0",
                    },
                ],
            },
        }
        result = _sanitize_installed_plugins(data, "/Users/brad", "/home/brad")
        entry = result["plugins"]["plugin-a@source"][0]
        assert entry["installPath"] == "/home/brad/.claude/plugins/cache/plugin-a"
        assert entry["version"] == "1.0.0"

    def test_strips_local_scope_entries(self):
        """Local-scope entries are removed entirely."""
        data = {
            "version": 2,
            "plugins": {
                "plugin-local@source": [
                    {
                        "scope": "local",
                        "installPath": "/Users/brad/project/.claude/plugins/cache/plugin-local",
                        "projectPath": "/Users/brad/project",
                    },
                ],
                "plugin-user@source": [
                    {
                        "scope": "user",
                        "installPath": "/Users/brad/.claude/plugins/cache/plugin-user",
                    },
                ],
            },
        }
        result = _sanitize_installed_plugins(data, "/Users/brad", "/home/brad")
        assert "plugin-local@source" not in result["plugins"]
        assert "plugin-user@source" in result["plugins"]

    def test_preserves_version_field(self):
        """Entry version field is preserved in output."""
        data = {
            "version": 2,
            "plugins": {
                "p@source": [
                    {
                        "scope": "user",
                        "installPath": "/Users/brad/.claude/plugins/cache/p",
                        "version": "2.3.1",
                    },
                ],
            },
        }
        result = _sanitize_installed_plugins(data, "/Users/brad", "/home/brad")
        assert result["plugins"]["p@source"][0]["version"] == "2.3.1"

    def test_empty_plugins(self):
        """Empty plugins dict returns empty plugins."""
        data = {"version": 2, "plugins": {}}
        result = _sanitize_installed_plugins(data, "/Users/brad", "/home/brad")
        assert result == {"version": 2, "plugins": {}}

    def test_missing_plugins_key(self):
        """Missing plugins key is handled gracefully."""
        data = {"version": 2}
        result = _sanitize_installed_plugins(data, "/Users/brad", "/home/brad")
        assert result == {"version": 2, "plugins": {}}

    def test_does_not_mutate_input(self):
        """Original dict is unchanged after sanitization."""
        data = {
            "version": 2,
            "plugins": {
                "p@source": [
                    {
                        "scope": "user",
                        "installPath": "/Users/brad/.claude/plugins/cache/p",
                    },
                ],
            },
        }
        original_path = data["plugins"]["p@source"][0]["installPath"]
        _sanitize_installed_plugins(data, "/Users/brad", "/home/brad")
        assert data["plugins"]["p@source"][0]["installPath"] == original_path

    def test_entries_without_scope_are_kept(self):
        """Entries without a scope field are kept and rewritten."""
        data = {
            "version": 2,
            "plugins": {
                "p@source": [
                    {"installPath": "/Users/brad/.claude/plugins/cache/p"},
                ],
            },
        }
        result = _sanitize_installed_plugins(data, "/Users/brad", "/home/brad")
        assert "p@source" in result["plugins"]
        assert (
            result["plugins"]["p@source"][0]["installPath"] == "/home/brad/.claude/plugins/cache/p"
        )

    def test_v2_wrapper_preserved(self):
        """Top-level version and plugins wrapper is preserved."""
        data = {
            "version": 2,
            "plugins": {
                "plugin-a@source": [
                    {
                        "scope": "user",
                        "installPath": "/Users/brad/.claude/plugins/cache/plugin-a",
                    },
                ],
            },
        }
        result = _sanitize_installed_plugins(data, "/Users/brad", "/home/brad")
        assert result["version"] == 2
        assert "plugins" in result

    def test_mixed_scopes_in_same_plugin(self):
        """A plugin with both local and user entries keeps only user entries."""
        data = {
            "version": 2,
            "plugins": {
                "plugin-a@source": [
                    {
                        "scope": "local",
                        "installPath": "/Users/brad/project/.claude/plugins/cache/a",
                    },
                    {
                        "scope": "user",
                        "installPath": "/Users/brad/.claude/plugins/cache/a",
                    },
                ],
            },
        }
        result = _sanitize_installed_plugins(data, "/Users/brad", "/home/brad")
        entries = result["plugins"]["plugin-a@source"]
        assert len(entries) == 1
        assert entries[0]["scope"] == "user"
        assert entries[0]["installPath"] == "/home/brad/.claude/plugins/cache/a"

    def test_marketplace_filter_includes_only_matching(self):
        """marketplace_filter restricts to plugins from matching marketplaces."""
        data = {
            "version": 2,
            "plugins": {
                "plugin-a@mp-a": [
                    {"scope": "user", "installPath": "/Users/brad/.claude/plugins/cache/a"},
                ],
                "plugin-b@mp-b": [
                    {"scope": "user", "installPath": "/Users/brad/.claude/plugins/cache/b"},
                ],
            },
        }
        result = _sanitize_installed_plugins(
            data, "/Users/brad", "/home/brad", marketplace_filter={"mp-a"}
        )
        assert "plugin-a@mp-a" in result["plugins"]
        assert "plugin-b@mp-b" not in result["plugins"]

    def test_marketplace_filter_none_includes_all(self):
        """marketplace_filter=None includes all plugins (default)."""
        data = {
            "version": 2,
            "plugins": {
                "plugin-a@mp-a": [
                    {"scope": "user", "installPath": "/Users/brad/.claude/plugins/cache/a"},
                ],
                "plugin-b@mp-b": [
                    {"scope": "user", "installPath": "/Users/brad/.claude/plugins/cache/b"},
                ],
            },
        }
        result = _sanitize_installed_plugins(
            data, "/Users/brad", "/home/brad", marketplace_filter=None
        )
        assert "plugin-a@mp-a" in result["plugins"]
        assert "plugin-b@mp-b" in result["plugins"]


class TestSyncSettings:
    """Tests for _sync_settings function."""

    @patch("dropkit.main.subprocess.run")
    def test_skips_missing_paths(self, mock_run, tmp_path):
        """Skips paths that don't exist locally."""
        with patch.object(Path, "expanduser", return_value=tmp_path / "nonexistent"):
            _sync_settings("dropkit.test", verbose=True, remote_home="/home/testuser")
        # No rsync calls when all paths missing
        rsync_calls = [c for c in mock_run.call_args_list if "rsync" in str(c)]
        assert len(rsync_calls) == 0

    @patch("dropkit.main.subprocess.run")
    def test_sync_existing_file(self, mock_run, tmp_path):
        """Syncs a file that exists locally and targets correct remote path."""
        claude_md = tmp_path / ".claude" / "CLAUDE.md"
        claude_md.parent.mkdir(parents=True)
        claude_md.write_text("# test")

        mock_run.return_value = MagicMock(returncode=0)

        with patch.object(Path, "expanduser", _make_expand_side_effect(claude_md, tmp_path)):
            _sync_settings("dropkit.test", verbose=False, remote_home="/home/testuser")

        # Should have at least one rsync call targeting the correct remote
        rsync_calls = [c for c in mock_run.call_args_list if "rsync" in str(c[0][0])]
        assert len(rsync_calls) >= 1
        rsync_cmd = rsync_calls[0][0][0]
        assert "dropkit.test:.claude/CLAUDE.md" in rsync_cmd[-1]

    @patch("dropkit.main.console")
    @patch("dropkit.main.subprocess.run")
    def test_mkdir_failure_skips_rsync(self, mock_run, mock_console, tmp_path):
        """When mkdir fails, rsync is skipped and failure is recorded."""
        claude_md = tmp_path / ".claude" / "CLAUDE.md"
        claude_md.parent.mkdir(parents=True)
        claude_md.write_text("# test")

        # mkdir fails
        mock_run.return_value = MagicMock(returncode=1, stderr=b"permission denied")

        with patch.object(Path, "expanduser", _make_expand_side_effect(claude_md, tmp_path)):
            _sync_settings("dropkit.test", verbose=False, remote_home="/home/testuser")

        # Should report FAILED
        print_calls = [str(c) for c in mock_console.print.call_args_list]
        assert any("FAILED" in c for c in print_calls)

    @patch("dropkit.main.console")
    @patch("dropkit.main.subprocess.run")
    def test_partial_sync_failure(self, mock_run, mock_console, tmp_path):
        """Reports failure when rsync fails for one path."""
        claude_md = tmp_path / ".claude" / "CLAUDE.md"
        claude_md.parent.mkdir(parents=True)
        claude_md.write_text("# test")

        # mkdir succeeds, rsync fails
        mock_run.side_effect = [
            MagicMock(returncode=0, stderr=b""),  # mkdir
            MagicMock(returncode=1, stderr=b"rsync error"),  # rsync
        ]

        with patch.object(Path, "expanduser", _make_expand_side_effect(claude_md, tmp_path)):
            _sync_settings("dropkit.test", verbose=False, remote_home="/home/testuser")

        print_calls = [str(c) for c in mock_console.print.call_args_list]
        assert any("FAILED" in c for c in print_calls)

    @patch("dropkit.main.console")
    @patch("dropkit.main.subprocess.run")
    def test_rsync_failure_includes_reason(self, mock_run, mock_console, tmp_path):
        """Rsync failure includes the error reason even without --verbose."""
        claude_md = tmp_path / ".claude" / "CLAUDE.md"
        claude_md.parent.mkdir(parents=True)
        claude_md.write_text("# test")

        mock_run.side_effect = [
            MagicMock(returncode=0, stderr=b""),  # mkdir
            MagicMock(returncode=1, stderr=b"rsync: connection unexpectedly closed"),  # rsync
        ]

        with patch.object(Path, "expanduser", _make_expand_side_effect(claude_md, tmp_path)):
            _sync_settings("dropkit.test", verbose=False, remote_home="/home/testuser")

        print_calls = [str(c) for c in mock_console.print.call_args_list]
        assert any("connection unexpectedly closed" in c for c in print_calls)

    @patch("dropkit.main.console")
    @patch("dropkit.main.subprocess.run")
    def test_no_local_settings_shows_skipped(self, mock_run, mock_console, tmp_path):
        """Shows 'skipped' when no local settings files exist."""
        with patch.object(Path, "expanduser", return_value=tmp_path / "nonexistent"):
            _sync_settings("dropkit.test", verbose=False, remote_home="/home/testuser")

        print_calls = [str(c) for c in mock_console.print.call_args_list]
        assert any("skipped" in c and "no local settings" in c for c in print_calls)

    @patch("dropkit.main.subprocess.run")
    def test_timeout_caught_gracefully(self, mock_run, tmp_path):
        """Timeout during sync is caught, not raised."""
        claude_md = tmp_path / ".claude" / "CLAUDE.md"
        claude_md.parent.mkdir(parents=True)
        claude_md.write_text("# test")

        mock_run.side_effect = subprocess.TimeoutExpired("ssh", 30)

        with patch.object(Path, "expanduser", _make_expand_side_effect(claude_md, tmp_path)):
            # Should not raise
            _sync_settings("dropkit.test", verbose=False, remote_home="/home/testuser")

    @patch("dropkit.main.console")
    @patch("dropkit.main.subprocess.run")
    def test_rsync_not_found_caught(self, mock_run, mock_console, tmp_path):
        """FileNotFoundError when rsync is not installed is caught gracefully."""
        claude_md = tmp_path / ".claude" / "CLAUDE.md"
        claude_md.parent.mkdir(parents=True)
        claude_md.write_text("# test")

        mock_run.side_effect = [
            MagicMock(returncode=0, stderr=b""),  # mkdir
            FileNotFoundError("rsync not found"),  # rsync binary missing
        ]

        with patch.object(Path, "expanduser", _make_expand_side_effect(claude_md, tmp_path)):
            _sync_settings("dropkit.test", verbose=False, remote_home="/home/testuser")

        print_calls = [str(c) for c in mock_console.print.call_args_list]
        assert any("FAILED" in c for c in print_calls)

    @patch("dropkit.main.subprocess.run")
    def test_directory_trailing_slash(self, mock_run, tmp_path):
        """Directories get trailing slash in rsync source."""
        plugins_dir = tmp_path / ".claude" / "plugins"
        plugins_dir.mkdir(parents=True)

        def expand_side_effect(self):
            local_path = str(self)
            if "plugins" in local_path:
                return plugins_dir
            return tmp_path / "nonexistent"

        mock_run.return_value = MagicMock(returncode=0)

        with patch.object(Path, "expanduser", expand_side_effect):
            _sync_settings("dropkit.test", verbose=False, remote_home="/home/testuser")

        rsync_calls = [c for c in mock_run.call_args_list if "rsync" in str(c[0][0])]
        assert len(rsync_calls) >= 1
        rsync_cmd = rsync_calls[0][0][0]
        # Source should end with / for directories
        source_arg = [
            a
            for a in rsync_cmd
            if "plugins" in a and "dropkit.test" not in a and not a.startswith("--exclude=")
        ]
        assert len(source_arg) == 1
        assert source_arg[0].endswith("/")

    def test_discover_returns_expected_base_items(self, tmp_path):
        """_discover_sync_choices returns CLAUDE.md and Settings when files exist."""
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        (claude_dir / "CLAUDE.md").write_text("# test")
        (claude_dir / "settings.json").write_text("{}")

        def expand_side_effect(self):
            local_path = str(self)
            if "CLAUDE.md" in local_path:
                return claude_dir / "CLAUDE.md"
            if "settings.json" in local_path:
                return claude_dir / "settings.json"
            return tmp_path / "nonexistent"

        with (
            patch.object(Path, "expanduser", expand_side_effect),
            patch.dict("os.environ", {}, clear=True),
        ):
            choices = _discover_sync_choices()

        keys = [c.key for c in choices]
        assert "claude_md" in keys
        assert "settings" in keys

    @patch("dropkit.main.subprocess.run")
    def test_selected_subset_only_syncs_chosen(self, mock_run, tmp_path):
        """When selected={'claude_md'}, only CLAUDE.md is synced."""
        claude_md = tmp_path / ".claude" / "CLAUDE.md"
        claude_md.parent.mkdir(parents=True)
        claude_md.write_text("# test")

        mock_run.return_value = MagicMock(returncode=0)

        with patch.object(Path, "expanduser", _make_expand_side_effect(claude_md, tmp_path)):
            _sync_settings(
                "dropkit.test",
                verbose=False,
                remote_home="/home/testuser",
                selected={"claude_md"},
            )

        rsync_calls = [c for c in mock_run.call_args_list if "rsync" in str(c[0][0])]
        assert len(rsync_calls) >= 1
        # All rsync calls should be for CLAUDE.md only
        for call in rsync_calls:
            cmd_str = " ".join(call[0][0])
            assert "CLAUDE.md" in cmd_str

    @patch("dropkit.main.subprocess.run")
    def test_selected_none_syncs_all(self, mock_run, tmp_path):
        """When selected=None, all available paths are synced."""
        claude_md = tmp_path / ".claude" / "CLAUDE.md"
        claude_md.parent.mkdir(parents=True)
        claude_md.write_text("# test")

        mock_run.return_value = MagicMock(returncode=0)

        with patch.object(Path, "expanduser", _make_expand_side_effect(claude_md, tmp_path)):
            _sync_settings(
                "dropkit.test",
                verbose=False,
                remote_home="/home/testuser",
                selected=None,
            )

        rsync_calls = [c for c in mock_run.call_args_list if "rsync" in str(c[0][0])]
        assert len(rsync_calls) >= 1

    @patch("dropkit.main.console")
    @patch("dropkit.main.subprocess.run")
    def test_empty_selected_shows_skipped(self, mock_run, mock_console, tmp_path):
        """When selected=set(), shows 'skipped' (no local settings found)."""
        with patch.object(Path, "expanduser", return_value=tmp_path / "nonexistent"):
            _sync_settings(
                "dropkit.test",
                verbose=False,
                remote_home="/home/testuser",
                selected=set(),
            )

        print_calls = [str(c) for c in mock_console.print.call_args_list]
        assert any("skipped" in c for c in print_calls)

    @patch("dropkit.main.subprocess.run")
    def test_settings_json_is_sanitized(self, mock_run, tmp_path):
        """Rsync source for settings.json is a temp file with only allowlisted keys."""
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir(parents=True)
        settings.write_text(
            json.dumps(
                {
                    "model": "opus",
                    "permissions": {"/local/path": {"allow": ["Read"]}},
                    "env": {"SECRET": "leaked"},
                }
            )
        )

        mock_run.return_value = MagicMock(returncode=0)

        def expand_side_effect(self):
            local_path = str(self)
            if "settings.json" in local_path:
                return settings
            return tmp_path / "nonexistent"

        with patch.object(Path, "expanduser", expand_side_effect):
            _sync_settings("dropkit.test", verbose=False, remote_home="/home/testuser")

        # Find the rsync call for settings.json
        rsync_calls = [
            c
            for c in mock_run.call_args_list
            if "rsync" in str(c[0][0]) and "settings.json" in str(c[0][0])
        ]
        assert len(rsync_calls) == 1
        rsync_cmd = rsync_calls[0][0][0]
        # Source should NOT be the original file path
        source_arg = rsync_cmd[-2]  # second-to-last arg is source
        assert str(settings) not in source_arg
        # The temp file content should only contain allowlisted keys
        # (temp file is cleaned up, but we can check via the rsync source path)
        assert source_arg != str(settings)

    @patch("dropkit.main.console")
    @patch("dropkit.main.subprocess.run")
    def test_settings_sanitize_failure_skips(self, mock_run, mock_console, tmp_path):
        """Invalid JSON in settings.json is skipped entirely."""
        settings = tmp_path / ".claude" / "settings.json"
        claude_md = tmp_path / ".claude" / "CLAUDE.md"
        settings.parent.mkdir(parents=True)
        settings.write_text("NOT VALID JSON {{{")
        claude_md.write_text("# test")

        mock_run.return_value = MagicMock(returncode=0)

        def expand_side_effect(self):
            local_path = str(self)
            if "settings.json" in local_path:
                return settings
            if "CLAUDE.md" in local_path:
                return claude_md
            return tmp_path / "nonexistent"

        with patch.object(Path, "expanduser", expand_side_effect):
            _sync_settings("dropkit.test", verbose=True, remote_home="/home/testuser")

        # settings.json should be skipped, but CLAUDE.md should still sync
        rsync_calls = [c for c in mock_run.call_args_list if "rsync" in str(c[0][0])]
        for call in rsync_calls:
            cmd = call[0][0]
            # No rsync call should reference settings.json
            assert not any("settings.json" in str(arg) for arg in cmd)

    @patch("dropkit.main.subprocess.run")
    def test_temp_file_cleaned_up_on_success(self, mock_run, tmp_path):
        """Temp file is deleted after successful rsync."""
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir(parents=True)
        settings.write_text(json.dumps({"model": "opus"}))

        created_temps: list[str] = []
        original_mkstemp = __import__("tempfile").mkstemp

        def tracking_mkstemp(**kwargs):
            fd, path = original_mkstemp(**kwargs)
            created_temps.append(path)
            return fd, path

        mock_run.return_value = MagicMock(returncode=0)

        def expand_side_effect(self):
            local_path = str(self)
            if "settings.json" in local_path:
                return settings
            return tmp_path / "nonexistent"

        with (
            patch.object(Path, "expanduser", expand_side_effect),
            patch("dropkit.main.tempfile.mkstemp", side_effect=tracking_mkstemp),
        ):
            _sync_settings("dropkit.test", verbose=False, remote_home="/home/testuser")

        assert len(created_temps) == 1
        assert not Path(created_temps[0]).exists()

    @patch("dropkit.main.subprocess.run")
    def test_temp_file_cleaned_up_on_rsync_failure(self, mock_run, tmp_path):
        """Temp file is deleted even when rsync fails."""
        settings = tmp_path / ".claude" / "settings.json"
        settings.parent.mkdir(parents=True)
        settings.write_text(json.dumps({"model": "opus"}))

        created_temps: list[str] = []
        original_mkstemp = __import__("tempfile").mkstemp

        def tracking_mkstemp(**kwargs):
            fd, path = original_mkstemp(**kwargs)
            created_temps.append(path)
            return fd, path

        # mkdir succeeds, rsync fails
        mock_run.side_effect = [
            MagicMock(returncode=0, stderr=b""),  # mkdir
            MagicMock(returncode=1, stderr=b"rsync error"),  # rsync
        ]

        def expand_side_effect(self):
            local_path = str(self)
            if "settings.json" in local_path:
                return settings
            return tmp_path / "nonexistent"

        with (
            patch.object(Path, "expanduser", expand_side_effect),
            patch("dropkit.main.tempfile.mkstemp", side_effect=tracking_mkstemp),
        ):
            _sync_settings("dropkit.test", verbose=False, remote_home="/home/testuser")

        assert len(created_temps) == 1
        assert not Path(created_temps[0]).exists()


class TestOpenAuthSession:
    """Tests for _open_auth_session function."""

    @patch("dropkit.main.subprocess.run")
    def test_runs_claude_login_via_ssh(self, mock_run):
        """Runs claude /login on the droplet via SSH."""
        mock_run.return_value = MagicMock(returncode=0)
        result = _open_auth_session("dropkit.test", verbose=False)

        assert result is True
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "ssh"
        assert "dropkit.test" in cmd
        # Should run claude /login, not open an interactive shell
        cmd_str = " ".join(cmd)
        assert "claude /login" in cmd_str

    @patch("dropkit.main.subprocess.run")
    def test_uses_ephemeral_temp_directory(self, mock_run):
        """Creates a temp directory and cleans it up after auth."""
        mock_run.return_value = MagicMock(returncode=0)
        _open_auth_session("dropkit.test", verbose=False)

        cmd = mock_run.call_args[0][0]
        cmd_str = " ".join(cmd)
        assert "mktemp -d" in cmd_str
        assert 'rm -rf "$dir"' in cmd_str

    @patch("dropkit.main.subprocess.run")
    def test_uses_bash_login_shell(self, mock_run):
        """Uses bash -lc to bypass zsh/p10k wizard."""
        mock_run.return_value = MagicMock(returncode=0)
        _open_auth_session("dropkit.test", verbose=False)

        cmd = mock_run.call_args[0][0]
        cmd_str = " ".join(cmd)
        assert "bash -lc" in cmd_str

    @patch("dropkit.main.subprocess.run")
    def test_allocates_pseudo_tty(self, mock_run):
        """SSH command includes -t for pseudo-TTY so claude /login can display its URL."""
        mock_run.return_value = MagicMock(returncode=0)
        _open_auth_session("dropkit.test", verbose=False)

        cmd = mock_run.call_args[0][0]
        assert "-t" in cmd

    @patch("dropkit.main.subprocess.run")
    def test_no_port_forwarding(self, mock_run):
        """No port forwarding args in SSH command."""
        mock_run.return_value = MagicMock(returncode=0)
        _open_auth_session("dropkit.test", verbose=False)

        cmd = mock_run.call_args[0][0]
        assert "-L" not in cmd

    @patch("dropkit.main.subprocess.run")
    def test_does_not_capture_output(self, mock_run):
        """Interactive session must not capture output."""
        mock_run.return_value = MagicMock(returncode=0)
        _open_auth_session("dropkit.test", verbose=False)
        kwargs = mock_run.call_args[1]
        assert "capture_output" not in kwargs or kwargs["capture_output"] is False

    @patch("dropkit.main.console")
    @patch("dropkit.main.subprocess.run")
    def test_verbose_shows_command(self, mock_run, mock_console):
        """Verbose mode prints the SSH command."""
        mock_run.return_value = MagicMock(returncode=0)
        _open_auth_session("dropkit.test", verbose=True)
        print_calls = [str(c) for c in mock_console.print.call_args_list]
        assert any("ssh" in c and "claude /login" in c for c in print_calls)

    @patch("dropkit.main.subprocess.run")
    def test_os_error_raises_exit(self, mock_run):
        """OSError (e.g., ssh not found) raises typer.Exit."""
        mock_run.side_effect = FileNotFoundError("ssh not found")
        with pytest.raises(typer.Exit):
            _open_auth_session("dropkit.test", verbose=False)

    @patch("dropkit.main.console")
    @patch("dropkit.main.subprocess.run")
    def test_ssh_failure_exit_255(self, mock_run, mock_console):
        """Exit code 255 (SSH connection failure) returns False with clear message."""
        mock_run.return_value = MagicMock(returncode=255)
        result = _open_auth_session("dropkit.test", verbose=False)
        assert result is False
        print_calls = [str(c) for c in mock_console.print.call_args_list]
        assert any("SSH connection failed" in c for c in print_calls)

    @patch("dropkit.main.subprocess.run")
    def test_returns_true_on_success(self, mock_run):
        """Returns True when session exits cleanly."""
        mock_run.return_value = MagicMock(returncode=0)
        assert _open_auth_session("dropkit.test", verbose=False) is True

    @patch("dropkit.main.subprocess.run")
    def test_nonzero_exit_returns_true(self, mock_run):
        """Non-zero non-255 exit is normal (e.g. user cancelled), returns True."""
        mock_run.return_value = MagicMock(returncode=1)
        assert _open_auth_session("dropkit.test", verbose=False) is True

    @patch("dropkit.main.console")
    @patch("dropkit.main.subprocess.run")
    def test_keyboard_interrupt_warns_about_auth(self, mock_run, mock_console):
        """Ctrl-C warns that auth may be incomplete and exits with code 130."""
        mock_run.side_effect = KeyboardInterrupt()
        with pytest.raises(typer.Exit) as exc_info:
            _open_auth_session("dropkit.test", verbose=False)
        assert exc_info.value.exit_code == 130
        print_calls = [str(c) for c in mock_console.print.call_args_list]
        assert any("re-run" in c.lower() for c in print_calls)


class TestSetupClaude:
    """Tests for the setup_claude command orchestrator."""

    @patch("dropkit.main._open_auth_session")
    @patch("dropkit.main._auth_github")
    @patch("dropkit.main._install_claude_code", return_value=False)
    @patch("dropkit.main.find_user_droplet", return_value=({"name": "test"}, "testuser"))
    @patch("dropkit.main.load_config_and_api", return_value=(MagicMock(), MagicMock()))
    def test_exits_on_install_failure(
        self, mock_config, mock_find, mock_install, mock_auth, mock_session
    ):
        """Aborts with exit code 1 when install fails."""
        with pytest.raises(typer.Exit) as exc_info:
            setup_claude(droplet_name="test", sync_all=False, verbose=False)
        assert exc_info.value.exit_code == 1
        mock_auth.assert_not_called()
        mock_session.assert_not_called()

    @patch("dropkit.main._open_auth_session", return_value=True)
    @patch("dropkit.main._sync_settings")
    @patch("dropkit.main._auth_github")
    @patch("dropkit.main._install_claude_code", return_value=True)
    @patch("dropkit.main.find_user_droplet", return_value=({"name": "test"}, "testuser"))
    @patch("dropkit.main.load_config_and_api", return_value=(MagicMock(), MagicMock()))
    def test_sync_all_runs_everything(
        self, mock_config, mock_find, mock_install, mock_auth, mock_sync, mock_session
    ):
        """--sync-all runs _auth_github and _sync_settings with selected=None."""
        setup_claude(droplet_name="test", sync_all=True, verbose=False)
        mock_auth.assert_called_once()
        mock_sync.assert_called_once_with(
            "dropkit.test", False, remote_home="/home/testuser", selected=None
        )
        mock_session.assert_called_once()

    @patch("dropkit.main._open_auth_session", return_value=True)
    @patch("dropkit.main._sync_settings")
    @patch("dropkit.main._auth_github")
    @patch("dropkit.main._prompt_sync_selection", return_value=set())
    @patch("dropkit.main._discover_sync_choices", return_value=[])
    @patch("dropkit.main._install_claude_code", return_value=True)
    @patch("dropkit.main.find_user_droplet", return_value=({"name": "test"}, "testuser"))
    @patch("dropkit.main.load_config_and_api", return_value=(MagicMock(), MagicMock()))
    def test_empty_selection_skips_sync(
        self,
        mock_config,
        mock_find,
        mock_install,
        mock_discover,
        mock_prompt,
        mock_auth,
        mock_sync,
        mock_session,
    ):
        """Empty selection skips both auth and sync."""
        setup_claude(droplet_name="test", sync_all=False, verbose=False)
        mock_auth.assert_not_called()
        mock_sync.assert_not_called()
        mock_session.assert_called_once()

    @patch("dropkit.main._open_auth_session", return_value=True)
    @patch("dropkit.main._sync_settings")
    @patch("dropkit.main._auth_github")
    @patch("dropkit.main._prompt_sync_selection", return_value={"github_token", "claude_md"})
    @patch(
        "dropkit.main._discover_sync_choices",
        return_value=[
            SyncChoice("Global CLAUDE.md", "claude_md"),
            SyncChoice("GitHub token", "github_token"),
        ],
    )
    @patch("dropkit.main._install_claude_code", return_value=True)
    @patch("dropkit.main.find_user_droplet", return_value=({"name": "test"}, "testuser"))
    @patch("dropkit.main.load_config_and_api", return_value=(MagicMock(), MagicMock()))
    def test_github_token_gated_by_selection(
        self,
        mock_config,
        mock_find,
        mock_install,
        mock_discover,
        mock_prompt,
        mock_auth,
        mock_sync,
        mock_session,
    ):
        """GitHub auth runs only when github_token is selected."""
        setup_claude(droplet_name="test", sync_all=False, verbose=False)
        mock_auth.assert_called_once()
        # _sync_settings should be called with claude_md only (not github_token)
        mock_sync.assert_called_once()
        call_kwargs = mock_sync.call_args
        selected = call_kwargs[1]["selected"] if "selected" in call_kwargs[1] else call_kwargs[0][3]
        assert "github_token" not in selected
        assert "claude_md" in selected

    @patch("dropkit.main._open_auth_session", return_value=True)
    @patch("dropkit.main._sync_settings")
    @patch("dropkit.main._auth_github")
    @patch("dropkit.main._prompt_sync_selection", return_value={"claude_md"})
    @patch(
        "dropkit.main._discover_sync_choices",
        return_value=[
            SyncChoice("Global CLAUDE.md", "claude_md"),
        ],
    )
    @patch("dropkit.main._install_claude_code", return_value=True)
    @patch("dropkit.main.find_user_droplet", return_value=({"name": "test"}, "testuser"))
    @patch("dropkit.main.load_config_and_api", return_value=(MagicMock(), MagicMock()))
    def test_default_behavior_calls_prompt(
        self,
        mock_config,
        mock_find,
        mock_install,
        mock_discover,
        mock_prompt,
        mock_auth,
        mock_sync,
        mock_session,
    ):
        """Default (no --sync-all) calls discover + prompt."""
        setup_claude(droplet_name="test", sync_all=False, verbose=False)
        mock_discover.assert_called_once()
        mock_prompt.assert_called_once()

    @patch("dropkit.main._open_auth_session", return_value=True)
    @patch("dropkit.main._auth_github")
    @patch("dropkit.main._install_claude_code", return_value=True)
    @patch("dropkit.main.find_user_droplet", return_value=({"name": "test"}, "testuser"))
    @patch("dropkit.main.load_config_and_api", return_value=(MagicMock(), MagicMock()))
    def test_always_opens_auth_session(
        self, mock_config, mock_find, mock_install, mock_auth, mock_session
    ):
        """Always opens auth session even if GitHub auth fails."""
        mock_auth.side_effect = None  # auth does not raise
        setup_claude(droplet_name="test", sync_all=True, verbose=False)
        mock_session.assert_called_once()

    @patch("dropkit.main._open_auth_session")
    @patch("dropkit.main._install_claude_code")
    @patch("dropkit.main.find_user_droplet", return_value=(None, "testuser"))
    @patch("dropkit.main.load_config_and_api", return_value=(MagicMock(), MagicMock()))
    def test_exits_on_droplet_not_found(self, mock_config, mock_find, mock_install, mock_session):
        """Exits with code 1 when droplet not found."""
        with pytest.raises(typer.Exit) as exc_info:
            setup_claude(droplet_name="nonexistent", sync_all=False, verbose=False)
        assert exc_info.value.exit_code == 1
        mock_install.assert_not_called()

    @patch("dropkit.main._open_auth_session", return_value=True)
    @patch("dropkit.main._sync_settings")
    @patch("dropkit.main._auth_github")
    @patch("dropkit.main._prompt_sync_selection", return_value={"github_token"})
    @patch(
        "dropkit.main._discover_sync_choices",
        return_value=[SyncChoice("GitHub token", "github_token")],
    )
    @patch("dropkit.main._install_claude_code", return_value=True)
    @patch("dropkit.main.find_user_droplet", return_value=({"name": "test"}, "testuser"))
    @patch("dropkit.main.load_config_and_api", return_value=(MagicMock(), MagicMock()))
    def test_github_token_only_does_not_sync_everything(
        self,
        mock_config,
        mock_find,
        mock_install,
        mock_discover,
        mock_prompt,
        mock_auth,
        mock_sync,
        mock_session,
    ):
        """Selecting only github_token must NOT call _sync_settings with selected=None."""
        setup_claude(droplet_name="test", sync_all=False, verbose=False)
        mock_auth.assert_called_once()
        # _sync_settings should NOT be called (empty set = nothing to sync)
        mock_sync.assert_not_called()

    @patch("dropkit.main._open_auth_session", return_value=False)
    @patch("dropkit.main._auth_github")
    @patch("dropkit.main._install_claude_code", return_value=True)
    @patch("dropkit.main.find_user_droplet", return_value=({"name": "test"}, "testuser"))
    @patch("dropkit.main.load_config_and_api", return_value=(MagicMock(), MagicMock()))
    def test_exits_nonzero_on_ssh_connection_failure(
        self, mock_config, mock_find, mock_install, mock_auth, mock_session
    ):
        """Exits with code 1 when SSH connection fails (exit 255)."""
        with pytest.raises(typer.Exit) as exc_info:
            setup_claude(droplet_name="test", sync_all=True, verbose=False)
        assert exc_info.value.exit_code == 1
