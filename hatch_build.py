"""Hatchling build hook to embed git commit at build time."""

import subprocess
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    """Build hook to capture git commit hash."""

    def initialize(self, version, build_data):
        """Run before the build starts."""
        # Get git commit hash
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--short=7", "HEAD"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0:
                commit = result.stdout.strip()
                if commit:
                    # Write commit to a file that will be included in the package
                    version_file = Path(self.root) / "tobcloud" / "_version.txt"
                    version_file.write_text(commit)
                    print(f"Embedded git commit: {commit}")
        except Exception as e:
            print(f"Warning: Could not capture git commit: {e}")
