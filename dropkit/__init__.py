"""dropkit - Manage DigitalOcean droplets for ToB engineers."""

import subprocess
from pathlib import Path


def _get_version() -> str:
    """
    Get version string.

    Returns:
        - "dev" if running from git repository (development mode)
        - "0.1.0+git.<commit>" if installed (commit hash embedded at build time)
        - "0.1.0" fallback if version cannot be determined
    """
    # Check if we're in a git repository (development mode)
    try:
        repo_root = Path(__file__).parent.parent
        if (repo_root / ".git").exists():
            return "dev"
    except Exception:
        pass

    # Installed mode - check for embedded version file (created at build time)
    try:
        version_file = Path(__file__).parent / "_version.txt"
        if version_file.exists():
            commit = version_file.read_text().strip()
            if commit:
                return f"0.1.0+git.{commit}"
    except Exception:
        pass

    # Fallback: try to get commit from git (in case running from source)
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short=7", "HEAD"],
            capture_output=True,
            text=True,
            timeout=1,
            cwd=Path(__file__).parent,
        )
        if result.returncode == 0:
            commit = result.stdout.strip()
            if commit:
                return f"0.1.0+git.{commit}"
    except Exception:
        pass

    # Final fallback to base version
    return "0.1.0"


__version__ = _get_version()
