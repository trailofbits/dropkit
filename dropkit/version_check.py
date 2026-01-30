"""Version checking functionality for dropkit."""

import json
import subprocess
import time
from pathlib import Path

from dropkit import __version__
from dropkit.config import Config


def get_last_check_file() -> Path:
    """Get the path to the last version check file."""
    return Config.get_config_dir() / ".last_version_check"


def should_check_version() -> bool:
    """
    Check if we should check for a new version.

    Only checks once per day to avoid slowing down commands.
    """
    check_file = get_last_check_file()

    if not check_file.exists():
        return True

    try:
        with open(check_file) as f:
            data = json.load(f)
            last_check = data.get("timestamp", 0)
            # Check if more than 24 hours have passed
            return (time.time() - last_check) > 86400  # 24 hours in seconds
    except (json.JSONDecodeError, OSError):
        return True


def update_last_check_time() -> None:
    """Update the last version check timestamp."""
    check_file = get_last_check_file()
    check_file.parent.mkdir(parents=True, exist_ok=True)

    data = {"timestamp": time.time(), "current_version": __version__}

    try:
        with open(check_file, "w") as f:
            json.dump(data, f)
    except OSError:
        # Silently fail if we can't write the file
        pass


def get_latest_git_commit() -> str | None:
    """
    Get the latest git commit hash from the main branch.

    Returns:
        Latest commit hash (short, 7 chars) or None if unable to fetch
    """
    try:
        # Get the latest commit from main branch
        result = subprocess.run(
            [
                "git",
                "ls-remote",
                "https://github.com/trailofbits/dropkit.git",
                "HEAD",
            ],
            capture_output=True,
            timeout=5,
            text=True,
        )

        if result.returncode != 0:
            return None

        # Parse the output to get the commit hash
        # Format: "commit_hash\tHEAD"
        lines = result.stdout.strip().split("\n")
        if not lines or not lines[0]:
            return None

        # Extract commit hash (first column)
        commit_hash = lines[0].split("\t")[0]
        # Return short hash (first 7 chars)
        return commit_hash[:7] if commit_hash else None

    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        return None


def extract_commit_from_version(version: str) -> str | None:
    """
    Extract commit hash from version string.

    Version format: "0.1.0+git.a1b2c3d" or similar

    Args:
        version: Version string potentially containing a commit hash

    Returns:
        Commit hash (short) or None if not found
    """
    # Version format from hatchling-vcs: "0.1.0+git.a1b2c3d" or "0.1.0.dev123+a1b2c3d"
    if "+git." in version:
        # Format: "0.1.0+git.a1b2c3d"
        parts = version.split("+git.")
        if len(parts) == 2:
            return parts[1][:7]  # Return first 7 chars
    elif "+" in version:
        # Format: "0.1.0+a1b2c3d" or similar
        parts = version.split("+")
        if len(parts) == 2:
            commit = parts[1]
            # Extract hash if it contains other info
            if "." in commit:
                commit = commit.split(".")[-1]
            return commit[:7]

    return None


def commits_differ(current_version: str, latest_commit: str) -> bool:
    """
    Check if current version's commit differs from latest commit.

    Args:
        current_version: Current version string (e.g., "0.1.0+git.a1b2c3d")
        latest_commit: Latest commit hash from remote

    Returns:
        True if commits differ (update available), False otherwise
    """
    current_commit = extract_commit_from_version(current_version)

    if not current_commit:
        # Can't determine current commit, don't show update
        return False

    # Compare commit hashes (case-insensitive)
    return current_commit.lower() != latest_commit.lower()


def check_for_updates() -> None:
    """
    Check for updates and display a message if a new version is available.

    This function:
    - Skips check in development mode (version == "dev")
    - Only runs once per day for installed versions
    - Fetches the latest git commit from main branch
    - Compares with current version's commit
    - Shows a non-blocking message if commits differ
    """
    # Skip check in development mode
    if __version__ == "dev" or "dev" in __version__.lower():
        return

    # Only check once per day
    if not should_check_version():
        return

    # Update the check time regardless of success
    update_last_check_time()

    # Try to get latest commit
    latest_commit = get_latest_git_commit()

    if not latest_commit:
        # Silently fail if we can't check
        return

    # Compare commits
    if commits_differ(__version__, latest_commit):
        # Import here to avoid circular dependency
        from rich.console import Console

        console = Console()

        current_commit = extract_commit_from_version(__version__)
        console.print(
            f"\n[yellow]New version available:[/yellow] [cyan]{latest_commit}[/cyan] "
            f"[dim](current: {current_commit or __version__})[/dim]"
        )
        console.print(
            "[yellow]Run[/yellow] [cyan]uv tool upgrade dropkit[/cyan] [yellow]to update[/yellow]\n"
        )
