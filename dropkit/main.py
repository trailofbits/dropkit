"""Main CLI application for dropkit."""

import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from dropkit.api import DigitalOceanAPI, DigitalOceanAPIError
from dropkit.cloudinit import render_cloud_init
from dropkit.config import Config, DropkitConfig
from dropkit.lock import requires_lock
from dropkit.ssh_config import (
    add_ssh_host,
    get_ssh_host_ip,
    host_exists,
    remove_known_hosts_entry,
    remove_ssh_host,
)
from dropkit.ui import (
    display_images,
    display_projects,
    display_regions,
    display_sizes,
    prompt_with_help,
)
from dropkit.version_check import check_for_updates

app = typer.Typer(
    name="dropkit",
    help="Manage DigitalOcean droplets for ToB engineers",
)
console = Console()


@app.callback()
def main_callback():
    """Run before any command - checks for updates once per day."""
    check_for_updates()


# Helper functions


def complete_droplet_name(incomplete: str) -> list[str]:
    """
    Autocompletion function for droplet names.

    Fetches droplet names from DigitalOcean for the current user.
    This is used by Typer for shell completion (e.g., bash, zsh).

    Args:
        incomplete: Partial text entered by the user

    Returns:
        List of matching droplet names
    """
    try:
        # Check if config exists
        if not Config.exists():
            return []

        # Load config and create API client
        config_manager = Config()
        config_manager.load()
        config = config_manager.config
        api = DigitalOceanAPI(config.digitalocean.token)

        # Get username and fetch droplets with user tag
        username = api.get_username()
        tag_name = get_user_tag(username)
        droplets = api.list_droplets(tag_name=tag_name)

        # Extract droplet names
        droplet_names = [d.get("name", "") for d in droplets if d.get("name")]

        # Filter by incomplete text (case-insensitive)
        if incomplete:
            droplet_names = [
                name for name in droplet_names if name.lower().startswith(incomplete.lower())
            ]

        return droplet_names
    except Exception:
        # Silently fail on errors - completion should never break the CLI
        return []


def complete_project_name(incomplete: str) -> list[str]:
    """
    Autocompletion function for project names.

    Fetches project names from DigitalOcean.
    This is used by Typer for shell completion (e.g., bash, zsh).

    Args:
        incomplete: Partial text entered by the user

    Returns:
        List of matching project names
    """
    try:
        # Check if config exists
        if not Config.exists():
            return []

        # Load config and create API client
        config_manager = Config()
        config_manager.load()
        config = config_manager.config
        api = DigitalOceanAPI(config.digitalocean.token)

        # Fetch all projects
        projects = api.list_projects()

        # Extract project names
        project_names = [p.get("name", "") for p in projects if p.get("name")]

        # Filter by incomplete text (case-insensitive)
        if incomplete:
            project_names = [
                name for name in project_names if name.lower().startswith(incomplete.lower())
            ]

        return project_names
    except Exception:
        # Silently fail on errors - completion should never break the CLI
        return []


def complete_snapshot_name(incomplete: str) -> list[str]:
    """
    Autocompletion function for hibernated snapshot names.

    Fetches dropkit snapshots from DigitalOcean for the current user
    and extracts the droplet name from the snapshot name.
    This is used by Typer for shell completion (e.g., bash, zsh).

    Args:
        incomplete: Partial text entered by the user

    Returns:
        List of matching droplet names (without dropkit- prefix)
    """
    try:
        if not Config.exists():
            return []

        config_manager = Config()
        config_manager.load()
        config = config_manager.config
        api = DigitalOceanAPI(config.digitalocean.token)

        username = api.get_username()
        user_tag = get_user_tag(username)
        snapshots = get_user_hibernated_snapshots(api, user_tag)

        # Extract droplet names from snapshots
        names = []
        for snapshot in snapshots:
            droplet_name = get_droplet_name_from_snapshot(snapshot.get("name", ""))
            if droplet_name:
                names.append(droplet_name)

        # Filter by incomplete text (case-insensitive)
        if incomplete:
            names = [n for n in names if n.lower().startswith(incomplete.lower())]

        return names
    except Exception:
        # Silently fail on errors - completion should never break the CLI
        return []


def complete_droplet_or_snapshot_name(incomplete: str) -> list[str]:
    """
    Autocompletion function for both live droplet and hibernated snapshot names.

    Combines results from complete_droplet_name and complete_snapshot_name,
    deduplicating names that appear in both.

    Args:
        incomplete: Partial text entered by the user

    Returns:
        List of matching names (live droplets and hibernated snapshots)
    """
    droplet_names = complete_droplet_name(incomplete)
    snapshot_names = complete_snapshot_name(incomplete)
    # Deduplicate while preserving order (live droplets first)
    return list(dict.fromkeys(droplet_names + snapshot_names))


def load_config_and_api() -> tuple[Config, DigitalOceanAPI]:
    """
    Load configuration and create API client.

    Returns:
        Tuple of (Config instance, DigitalOceanAPI instance)

    Raises:
        typer.Exit: If config doesn't exist or fails to load
    """
    if not Config.exists():
        console.print("[red]Error: Config not found. Run 'dropkit init' first.[/red]")
        raise typer.Exit(1)

    config_manager = Config()
    try:
        config_manager.load()
    except Exception as e:
        console.print(f"[red]Error loading config: {e}[/red]")
        console.print(
            "[yellow]Config file may be invalid. Try running[/yellow] [cyan]dropkit init --force[/cyan]"
        )
        raise typer.Exit(1)

    config = config_manager.config
    api = DigitalOceanAPI(config.digitalocean.token)

    return config_manager, api


def get_ssh_hostname(droplet_name: str) -> str:
    """
    Convert droplet name to SSH config hostname.

    Args:
        droplet_name: Name of the droplet

    Returns:
        SSH hostname with dropkit prefix (e.g., "dropkit.my-droplet")
    """
    return f"dropkit.{droplet_name}"


def get_snapshot_name(droplet_name: str) -> str:
    """
    Convert droplet name to snapshot name.

    Args:
        droplet_name: Name of the droplet

    Returns:
        Snapshot name with dropkit prefix (e.g., "dropkit-my-droplet")
    """
    return f"dropkit-{droplet_name}"


def get_droplet_name_from_snapshot(snapshot_name: str) -> str | None:
    """
    Extract droplet name from a dropkit snapshot name.

    Args:
        snapshot_name: Snapshot name (e.g., "dropkit-my-droplet")

    Returns:
        Droplet name if snapshot name is in dropkit format, None otherwise
    """
    prefix = "dropkit-"
    if snapshot_name.startswith(prefix):
        return snapshot_name[len(prefix) :]
    return None


def get_user_hibernated_snapshots(api: DigitalOceanAPI, user_tag: str) -> list[dict[str, Any]]:
    """
    Get hibernated dropkit snapshots owned by the user.

    Note: DO API doesn't support tag_name filter for snapshots, so we filter client-side.

    Args:
        api: DigitalOcean API client
        user_tag: User's owner tag (e.g., "owner:username")

    Returns:
        List of snapshot objects that are dropkit hibernations owned by this user
    """
    snapshots = api.list_snapshots()
    return [
        s
        for s in snapshots
        if s.get("name", "").startswith("dropkit-") and user_tag in s.get("tags", [])
    ]


def find_snapshot_action(api: DigitalOceanAPI, droplet_id: int) -> dict[str, Any] | None:
    """
    Find the most recent snapshot action for a droplet.

    Args:
        api: DigitalOcean API client
        droplet_id: Droplet ID

    Returns:
        Most recent snapshot action dict, or None if not found
    """
    actions = api.list_droplet_actions(droplet_id)
    for action in actions:
        if action.get("type") == "snapshot":
            return action
    return None


def ensure_ssh_config(
    droplet: dict,
    droplet_name: str,
    username: str,
    config: DropkitConfig,
) -> str:
    """
    Ensure SSH config entry exists for a droplet.

    Checks if the SSH config already has an entry for this droplet.
    If not, extracts the public IP and adds an SSH config entry.

    Args:
        droplet: Droplet dict from DigitalOcean API
        droplet_name: Name of the droplet
        username: Username for SSH connection
        config: DropkitConfig instance with SSH settings

    Returns:
        SSH hostname (e.g., "dropkit.my-droplet")

    Raises:
        ValueError: If droplet has no public IP
    """
    ssh_hostname = get_ssh_hostname(droplet_name)

    if not host_exists(config.ssh.config_path, ssh_hostname):
        # Get public IP from droplet networks
        networks = droplet.get("networks", {})
        public_ip = None
        for network in networks.get("v4", []):
            if network.get("type") == "public":
                public_ip = network.get("ip_address")
                break

        if not public_ip:
            raise ValueError("Could not find public IP for droplet")

        console.print(f"[dim]Adding SSH config for {ssh_hostname}...[/dim]")
        add_ssh_host(
            config_path=config.ssh.config_path,
            host_name=ssh_hostname,
            hostname=public_ip,
            user=username,
            identity_file=config.ssh.identity_file,
        )
        console.print(f"[green]✓[/green] Added SSH config: {ssh_hostname} -> {public_ip}")

    return ssh_hostname


def cleanup_ssh_entries(
    config: DropkitConfig,
    droplet_name: str,
    prompt_known_hosts: bool = True,
    public_ip: str | None = None,
    tailscale_ip: str | None = None,
) -> None:
    """
    Remove SSH config entry and optionally clean up known_hosts for a droplet.

    Args:
        config: DropkitConfig instance with SSH settings.
        droplet_name: Name of the droplet being removed.
        prompt_known_hosts: If True, prompt user before removing known_hosts entries.
        public_ip: Public IP of the droplet (for known_hosts cleanup when SSH config
            has a different IP, e.g., Tailscale IP).
        tailscale_ip: Tailscale IP of the droplet (for known_hosts cleanup when SSH
            config has the public IP but user also connected via Tailscale).
    """
    ssh_hostname = get_ssh_hostname(droplet_name)

    # Get IP BEFORE removing SSH config (needed for known_hosts cleanup)
    ssh_ip = get_ssh_host_ip(config.ssh.config_path, ssh_hostname)
    console.print(f"[dim]Found IP: {ssh_ip}[/dim]")

    # Remove SSH config entry
    if host_exists(config.ssh.config_path, ssh_hostname):
        try:
            remove_ssh_host(config.ssh.config_path, ssh_hostname)
            console.print(
                f"[green]✓[/green] Removed SSH config entry for [cyan]{ssh_hostname}[/cyan]"
            )
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] Could not remove SSH config entry: {e}")
    else:
        console.print(f"[dim]SSH config entry for {ssh_hostname} not found (skipped)[/dim]")

    # Clean up known_hosts
    should_remove = not prompt_known_hosts or Confirm.ask(
        "Remove SSH fingerprint from known_hosts?", default=True
    )

    if should_remove:
        known_hosts_path = str(Path(config.ssh.config_path).parent / "known_hosts")
        hostnames_to_remove = [ssh_hostname]
        if ssh_ip:
            hostnames_to_remove.append(ssh_ip)
        # Include public IP if different from SSH config IP (e.g., when using Tailscale)
        if public_ip and public_ip not in hostnames_to_remove:
            hostnames_to_remove.append(public_ip)
        # Include Tailscale IP if different from SSH config IP
        if tailscale_ip and tailscale_ip not in hostnames_to_remove:
            hostnames_to_remove.append(tailscale_ip)
        console.print(f"[dim]Hostnames to find: {hostnames_to_remove}[/dim]")
        try:
            removed = remove_known_hosts_entry(known_hosts_path, hostnames_to_remove)
            if removed:
                console.print(
                    f"[green]✓[/green] Removed {removed} known_hosts "
                    f"{'entry' if removed == 1 else 'entries'}"
                )
            else:
                console.print("[dim]No matching entries in known_hosts[/dim]")
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] Could not remove known_hosts entry: {e}")


def get_user_tag(username: str) -> str:
    """
    Get the user tag for filtering droplets.

    Args:
        username: Username from DigitalOcean account

    Returns:
        Tag string for filtering (e.g., "owner:username")
    """
    return f"owner:{username}"


def build_droplet_tags(username: str, extra_tags: list[str] | None = None) -> list[str]:
    """
    Build complete list of tags for a droplet.

    Combines mandatory tags (owner:<username>, firewall) with extra tags,
    avoiding duplicates.

    Args:
        username: Username from DigitalOcean account
        extra_tags: Optional list of additional tags

    Returns:
        Complete list of tags with mandatory tags first
    """
    # Mandatory tags
    tags = [get_user_tag(username), "firewall"]

    # Add extra tags, avoiding duplicates
    if extra_tags:
        for tag in extra_tags:
            if tag not in tags:
                tags.append(tag)

    return tags


def register_ssh_keys_with_do(api: DigitalOceanAPI) -> tuple[list[str], list[int], str]:
    """
    Detect, select, validate, and register SSH keys with DigitalOcean.

    This function handles the entire SSH key workflow:
    - Detects SSH keys in ~/.ssh/
    - Prompts user to select which keys to use
    - Validates keys are proper public keys
    - Gets username from DigitalOcean for key naming
    - Registers keys with DO (or reuses existing ones)

    Args:
        api: DigitalOceanAPI instance

    Returns:
        Tuple of (ssh_key_paths, ssh_key_ids, username)

    Raises:
        typer.Exit: If any step fails
    """
    # Auto-detect SSH keys
    console.print("\n[bold]SSH Keys[/bold]")
    detected_keys = Config.detect_ssh_keys()

    if not detected_keys:
        console.print("[yellow]⚠[/yellow] No SSH keys detected in ~/.ssh/")
        console.print("[dim]Please add SSH keys to ~/.ssh/ and run init again[/dim]")
        raise typer.Exit(1)

    # Show detected keys
    console.print("[green]✓[/green] Detected SSH public keys:")
    for i, key in enumerate(detected_keys, 1):
        console.print(f"  {i}. [cyan]{key}[/cyan]")

    # Let user select which keys to use
    if len(detected_keys) == 1:
        ssh_keys = detected_keys
        console.print(f"\n[dim]Using SSH key: {ssh_keys[0]}[/dim]")
    else:
        selection = Prompt.ask(
            "\n[cyan]Select SSH keys to use (comma-separated numbers, or 'all')[/cyan]",
            default="all",
        )

        if selection.lower() == "all":
            ssh_keys = detected_keys
        else:
            try:
                indices = [int(s.strip()) - 1 for s in selection.split(",") if s.strip()]
                ssh_keys = [detected_keys[i] for i in indices if 0 <= i < len(detected_keys)]
                if not ssh_keys:
                    console.print("[red]Error: No valid keys selected[/red]")
                    raise typer.Exit(1)
            except (ValueError, IndexError):
                console.print("[red]Error: Invalid selection[/red]")
                raise typer.Exit(1)

    # Validate SSH keys are valid public keys
    for key_path in ssh_keys:
        try:
            Config.validate_ssh_public_key(key_path)
        except FileNotFoundError as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)

    # Get username from DigitalOcean account (needed for SSH key naming)
    try:
        username = api.get_username()
        console.print(
            f"\n[green]✓[/green] Using username from DigitalOcean: [cyan]{username}[/cyan]"
        )
    except DigitalOceanAPIError:
        # Fallback to system username if API call fails
        username = Config.get_system_username()
        console.print(
            f"\n[yellow]⚠[/yellow] Could not fetch username from DigitalOcean, "
            f"using system username: [cyan]{username}[/cyan]"
        )

    # Register SSH keys with DigitalOcean
    console.print("\n[dim]Checking SSH keys in DigitalOcean...[/dim]")
    ssh_key_ids = []

    try:
        for key_path in ssh_keys:
            key_content = Config.read_ssh_key_content(key_path)

            # Compute fingerprint
            try:
                fingerprint = Config.compute_ssh_key_fingerprint(key_content)
            except ValueError as e:
                console.print(
                    f"[red]Error computing fingerprint for {Path(key_path).name}: {e}[/red]"
                )
                raise typer.Exit(1)

            # Check if key already exists by fingerprint
            existing_key = api.get_ssh_key_by_fingerprint(fingerprint)

            if existing_key:
                ssh_key_ids.append(existing_key["id"])
                console.print(f"[green]✓[/green] Key already registered: {Path(key_path).name}")
            else:
                # Register new key with format: dropkit-{username}-{fingerprint_prefix}
                # Use first 8 characters of fingerprint (without colons)
                fingerprint_prefix = fingerprint.replace(":", "")[:8]
                key_name = f"dropkit-{username}-{fingerprint_prefix}"
                console.print(f"[dim]Registering new key: {Path(key_path).name}...[/dim]")
                new_key = api.add_ssh_key(key_name, key_content)
                ssh_key_ids.append(new_key["id"])
                console.print(f"[green]✓[/green] Registered new key: {key_name}")

    except DigitalOceanAPIError as e:
        console.print(f"[red]Error managing SSH keys in DigitalOcean: {e}[/red]")
        raise typer.Exit(1)

    return ssh_keys, ssh_key_ids, username


def wait_for_cloud_init(ssh_hostname: str, verbose: bool = False) -> tuple[bool, bool]:
    """
    Wait for cloud-init to complete on a droplet via SSH.

    This function polls the droplet via SSH to check cloud-init status.
    It waits up to 10 minutes for cloud-init to complete.

    Args:
        ssh_hostname: SSH hostname to connect to (e.g., "dropkit.my-droplet")
        verbose: If True, show debug output

    Returns:
        Tuple of (cloud_init_done, cloud_init_error) where:
        - cloud_init_done: True if cloud-init completed successfully
        - cloud_init_error: True if cloud-init completed with errors
        - Both False if timeout occurred

    Raises:
        None - errors are handled internally and reported to console
    """
    console.print("[dim]Waiting for cloud-init to complete...[/dim]")
    console.print(
        "[dim]This may take several minutes for packages to install and setup to finish[/dim]"
    )

    max_attempts = 60  # 10 minutes max (60 * 10 seconds)
    attempt = 0
    cloud_init_done = False
    cloud_init_error = False

    if verbose:
        console.print(
            f"[dim][DEBUG] Will poll cloud-init status up to {max_attempts} times (10 minutes)[/dim]"
        )

    # Wait for SSH to be ready and user to be created
    if verbose:
        console.print(
            "[dim][DEBUG] Sleeping 30 seconds to allow SSH service to start and user to be created...[/dim]"
        )
    time.sleep(30)

    while attempt < max_attempts and not cloud_init_done:
        try:
            # Use the SSH config hostname alias we just created
            if verbose:
                console.print(
                    f"[dim][DEBUG] Attempt {attempt + 1}/{max_attempts}: Checking cloud-init status via SSH...[/dim]"
                )

            result = subprocess.run(
                [
                    "ssh",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "ConnectTimeout=5",
                    "-o",
                    "BatchMode=yes",
                    ssh_hostname,  # Use hostname alias from SSH config
                    "sudo cloud-init status --format=json --wait",
                ],
                capture_output=True,
                timeout=30,
            )

            if verbose:
                console.print(f"[dim][DEBUG] SSH return code: {result.returncode}[/dim]")
                if result.stdout:
                    console.print(
                        f"[dim][DEBUG] SSH stdout: {result.stdout.decode('utf-8', errors='ignore')}[/dim]"
                    )
                if result.stderr:
                    console.print(
                        f"[dim][DEBUG] SSH stderr: {result.stderr.decode('utf-8', errors='ignore')}[/dim]"
                    )

            # Always try to parse JSON output, regardless of return code
            # (cloud-init may return non-zero even with valid JSON on error status)
            try:
                stdout = result.stdout.decode("utf-8", errors="ignore").strip()
                if not stdout:
                    raise json.JSONDecodeError("Empty output", "", 0)

                status_data = json.loads(stdout)
                status = status_data.get("status", "")

                if verbose:
                    console.print(f"[dim][DEBUG] Cloud-init status from JSON: {status}[/dim]")
                    if status_data.get("errors"):
                        console.print(
                            f"[dim][DEBUG] Cloud-init errors: {status_data.get('errors')}[/dim]"
                        )

                if status == "done":
                    cloud_init_done = True
                    console.print("[green]✓[/green] Cloud-init completed successfully")
                elif status == "error":
                    # Cloud-init failed
                    cloud_init_error = True
                    console.print("[red]✗[/red] Cloud-init completed with errors")

                    # Show error details if available
                    errors = status_data.get("errors", [])
                    if errors:
                        console.print(f"[red]Cloud-init errors:[/red] {', '.join(errors)}")

                    # Show recovery messages if available
                    recoverable_errors = status_data.get("recoverable_errors", {})
                    if recoverable_errors:
                        console.print(f"[yellow]Recoverable errors:[/yellow] {recoverable_errors}")

                    console.print(
                        "\n[yellow]The droplet is running but cloud-init failed.[/yellow]"
                    )
                    console.print("[yellow]You can investigate by running:[/yellow]")
                    console.print(f"  [cyan]ssh {ssh_hostname} 'sudo cloud-init status'[/cyan]")
                    console.print(
                        f"  [cyan]ssh {ssh_hostname} 'sudo cat /var/log/cloud-init.log'[/cyan]"
                    )
                    console.print(
                        f"  [cyan]ssh {ssh_hostname} 'sudo cat /var/log/cloud-init-output.log'[/cyan]"
                    )

                    # Break out of the loop - no point continuing
                    break
                else:
                    # Status exists but not "done" or "error" yet (e.g., "running")
                    attempt += 1
                    if verbose:
                        console.print(
                            f"[dim][DEBUG] Cloud-init status is '{status}', not 'done' yet. Sleeping 10 seconds...[/dim]"
                        )
                    time.sleep(10)
            except json.JSONDecodeError as e:
                # Failed to parse JSON or empty output - SSH might not be ready yet
                attempt += 1
                if verbose:
                    console.print(
                        f"[dim][DEBUG] Failed to parse JSON output: {e}. SSH may not be ready. Sleeping 10 seconds...[/dim]"
                    )
                time.sleep(10)
        except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
            if verbose:
                console.print(
                    f"[dim][DEBUG] SSH attempt failed with exception: {type(e).__name__}[/dim]"
                )
            attempt += 1
            time.sleep(10)

    if not cloud_init_done and not cloud_init_error:
        console.print(
            "[yellow]⚠[/yellow] Cloud-init status check timed out, but droplet may still be initializing"
        )
        console.print(
            f"[yellow]⚠[/yellow] You can check status manually with: ssh {ssh_hostname} 'cloud-init status'"
        )

    return cloud_init_done, cloud_init_error


# Tailscale helper functions

_MACOS_TAILSCALE_PATH = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"


def find_tailscale_cli() -> str | None:
    """
    Find the Tailscale CLI binary.

    Checks PATH first, then falls back to the macOS App Store location
    where Tailscale is installed as a GUI app without a symlink in PATH.

    Returns:
        Path to the Tailscale CLI binary, or None if not found
    """
    path = shutil.which("tailscale")
    if path is not None:
        return path
    if sys.platform == "darwin" and Path(_MACOS_TAILSCALE_PATH).exists():
        return _MACOS_TAILSCALE_PATH
    return None


def check_local_tailscale() -> bool:
    """
    Check if Tailscale is running and connected on the local machine.

    Returns:
        True if Tailscale is running and the user is connected to a tailnet
    """
    tailscale_bin = find_tailscale_cli()
    if tailscale_bin is None:
        return False

    try:
        result = subprocess.run(
            [tailscale_bin, "status", "--json"],
            capture_output=True,
            timeout=5,
        )
        if result.returncode != 0:
            return False

        status = json.loads(result.stdout.decode("utf-8", errors="ignore"))
        return status.get("BackendState") == "Running"
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return False


def run_tailscale_up(ssh_hostname: str, verbose: bool = False) -> str | None:
    """
    Run 'tailscale up' on the droplet and extract the auth URL.

    Args:
        ssh_hostname: SSH hostname to connect to
        verbose: Show debug output

    Returns:
        Auth URL if found, None if tailscale up failed
    """
    if verbose:
        console.print("[dim][DEBUG] Running tailscale up on droplet...[/dim]")

    try:
        # Run tailscale up with a timeout on the remote side.
        # tailscale up blocks waiting for authentication, so we use `timeout`
        # to kill it after 5 seconds - the auth URL is printed immediately.
        # The `|| true` ensures we don't fail due to timeout's exit code.
        result = subprocess.run(
            [
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=10",
                ssh_hostname,
                "timeout 5 sudo tailscale up 2>&1 || true",
            ],
            capture_output=True,
            timeout=30,
        )

        output = result.stdout.decode("utf-8", errors="ignore")

        if verbose:
            console.print(f"[dim][DEBUG] tailscale up output: {output}[/dim]")

        # Parse auth URL from output
        # Format: "To authenticate, visit:\n\n\thttps://login.tailscale.com/a/..."
        for line in output.split("\n"):
            # Match URL and strip trailing punctuation that's unlikely to be part of URL
            url_match = re.search(r"https://[^\s]+", line)
            if url_match:
                url = url_match.group(0).rstrip(".,;:!?'\")>]}")
                # Validate domain to prevent URL substring attacks
                # e.g., reject "https://evil.com/login.tailscale.com"
                parsed = urlparse(url)
                if parsed.netloc.endswith(".tailscale.com") or parsed.netloc == "tailscale.com":
                    return url

        return None

    except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
        if verbose:
            console.print(f"[dim][DEBUG] tailscale up failed: {e}[/dim]")
        return None


def tailscale_logout(ssh_hostname: str, verbose: bool = False) -> bool:
    """
    Logout from Tailscale on a droplet before destroy/hibernate.

    This removes the device from the Tailscale admin console, preventing
    stale entries from accumulating.

    Args:
        ssh_hostname: SSH hostname to connect to
        verbose: Show debug output

    Returns:
        True if logout succeeded, False if it failed
    """
    if verbose:
        console.print("[dim][DEBUG] Running tailscale logout on droplet...[/dim]")

    try:
        result = subprocess.run(
            [
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=10",
                ssh_hostname,
                "sudo tailscale logout",
            ],
            capture_output=True,
            timeout=30,
        )

        if result.returncode == 0:
            if verbose:
                console.print("[dim][DEBUG] tailscale logout succeeded[/dim]")
            return True
        else:
            stderr = result.stderr.decode("utf-8", errors="ignore")
            if verbose:
                console.print(f"[dim][DEBUG] tailscale logout failed: {stderr}[/dim]")
            return False

    except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
        if verbose:
            console.print(f"[dim][DEBUG] tailscale logout failed: {e}[/dim]")
        return False


def is_tailscale_ip(ip: str) -> bool:
    """
    Check if an IP address is in the Tailscale CGNAT range.

    Tailscale uses the CGNAT IP range 100.64.0.0/10 (100.64.0.0 - 100.127.255.255).

    Args:
        ip: IP address string to validate

    Returns:
        True if the IP is in the Tailscale CGNAT range
    """
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False

        octets = [int(p) for p in parts]

        # Check all octets are valid (0-255)
        if not all(0 <= o <= 255 for o in octets):
            return False

        # Tailscale CGNAT range: 100.64.0.0/10
        # First octet must be 100
        # Second octet must be 64-127 (the /10 covers 64 addresses in second octet)
        return octets[0] == 100 and 64 <= octets[1] <= 127

    except (ValueError, AttributeError):
        return False


def is_droplet_tailscale_locked(config: DropkitConfig, droplet_name: str) -> bool:
    """
    Check if droplet is under Tailscale lockdown by examining SSH config IP.

    A droplet is considered locked if its SSH config entry points to a
    Tailscale IP (100.64.0.0/10 range) rather than a public IP.

    Args:
        config: DropkitConfig instance with SSH settings
        droplet_name: Name of the droplet to check

    Returns:
        True if droplet SSH config points to Tailscale IP, False otherwise
    """
    ssh_hostname = get_ssh_hostname(droplet_name)
    current_ip = get_ssh_host_ip(config.ssh.config_path, ssh_hostname)

    if not current_ip:
        return False

    return is_tailscale_ip(current_ip)


def add_temporary_ssh_rule(ssh_hostname: str, verbose: bool = False) -> bool:
    """
    Add temporary UFW rule to allow SSH on public interface (eth0).

    This allows SSH access via public IP even when firewall is locked
    to Tailscale only. Used before hibernate to ensure droplet can be
    accessed after wake (before Tailscale re-authentication).

    Args:
        ssh_hostname: SSH hostname to connect to
        verbose: Show debug output

    Returns:
        True on success, False on failure
    """
    cmd = [
        "ssh",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "ConnectTimeout=10",
        ssh_hostname,
        "sudo ufw allow in on eth0 to any port 22",
    ]

    if verbose:
        console.print(f"[dim]Running: {' '.join(cmd)}[/dim]")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if verbose:
            if result.stdout:
                console.print(f"[dim]stdout: {result.stdout}[/dim]")
            if result.stderr:
                console.print(f"[dim]stderr: {result.stderr}[/dim]")

        return result.returncode == 0
    except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
        if verbose:
            console.print(f"[dim]SSH command failed: {e}[/dim]")
        return False


def prepare_for_hibernate(
    config: DropkitConfig,
    api: DigitalOceanAPI,
    droplet: dict,
    droplet_name: str,
    verbose: bool = False,
) -> bool:
    """
    Prepare droplet for hibernation, handling Tailscale lockdown if present.

    If droplet is under Tailscale lockdown:
    1. Add temporary UFW rule to allow SSH on eth0
    2. Update SSH config to use public IP instead of Tailscale IP

    Args:
        config: DropkitConfig instance
        api: DigitalOceanAPI instance
        droplet: Droplet dict from API
        droplet_name: Name of the droplet
        verbose: Show debug output

    Returns:
        True if droplet was under Tailscale lockdown, False otherwise
    """
    if not is_droplet_tailscale_locked(config, droplet_name):
        return False

    console.print("[dim]Detected Tailscale lockdown - preparing for hibernate...[/dim]")

    ssh_hostname = get_ssh_hostname(droplet_name)

    # Add temporary SSH rule via Tailscale connection (must succeed before logout)
    console.print("[dim]Adding temporary SSH rule for eth0...[/dim]")
    if not add_temporary_ssh_rule(ssh_hostname, verbose):
        # Temp rule failed - abort logout to keep Tailscale connectivity
        console.print(
            "[yellow]⚠[/yellow] Could not add temporary SSH rule - "
            "skipping Tailscale logout to maintain connectivity"
        )
        # Continue without logout - snapshot will preserve Tailscale state
        return True

    console.print("[green]✓[/green] Temporary SSH rule added")

    # Update SSH config to public IP BEFORE tailscale logout so the SSH
    # session for the logout command routes over the public IP instead of
    # the Tailscale IP (which dies when tailscale logs out).
    networks = droplet.get("networks", {})
    v4_networks = networks.get("v4", [])
    public_ip = None

    for network in v4_networks:
        if network.get("type") == "public":
            public_ip = network.get("ip_address")
            break

    if public_ip:
        console.print(f"[dim]Updating SSH config to public IP: {public_ip}[/dim]")
        try:
            username = api.get_username()
            add_ssh_host(
                config_path=config.ssh.config_path,
                host_name=ssh_hostname,
                hostname=public_ip,
                user=username,
                identity_file=config.ssh.identity_file,
            )
            console.print("[green]✓[/green] SSH config updated to public IP")
        except Exception as e:
            if verbose:
                console.print(f"[dim]Could not update SSH config: {e}[/dim]")

    # Now safe to logout from Tailscale (SSH config points to public IP)
    console.print("[dim]Logging out from Tailscale...[/dim]")
    if tailscale_logout(ssh_hostname, verbose):
        console.print("[green]✓[/green] Logged out from Tailscale")
    else:
        console.print(
            "[yellow]⚠[/yellow] Could not logout from Tailscale "
            "(device may remain in Tailscale admin console)"
        )

    return True


def get_tailscale_ip(ssh_hostname: str) -> str | None:
    """
    Get Tailscale IP address from a running droplet.

    SSHes to the droplet and runs 'tailscale ip -4' to get the Tailscale IP.
    This is a single attempt (not polling) and will return None if unreachable
    or Tailscale is not running.

    Args:
        ssh_hostname: SSH hostname to connect to

    Returns:
        Tailscale IP address if found, None otherwise
    """
    try:
        result = subprocess.run(
            [
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "BatchMode=yes",
                ssh_hostname,
                "tailscale ip -4 2>/dev/null",
            ],
            capture_output=True,
            timeout=15,
        )

        output = result.stdout.decode("utf-8", errors="ignore").strip()

        # Validate it's a valid Tailscale CGNAT IP (100.64.0.0/10 range)
        if output and is_tailscale_ip(output):
            return output

    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
        pass

    return None


def wait_for_tailscale_ip(
    ssh_hostname: str,
    timeout: int = 300,
    poll_interval: int = 5,
    verbose: bool = False,
) -> str | None:
    """
    Poll for Tailscale IP address after user authenticates.

    Args:
        ssh_hostname: SSH hostname to connect to
        timeout: Maximum time to wait in seconds
        poll_interval: Time between polls in seconds
        verbose: Show debug output

    Returns:
        Tailscale IP address if found, None if timeout
    """
    start_time = time.time()

    if verbose:
        console.print(f"[dim][DEBUG] Polling for Tailscale IP (timeout: {timeout}s)...[/dim]")

    while time.time() - start_time < timeout:
        try:
            result = subprocess.run(
                [
                    "ssh",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "ConnectTimeout=5",
                    "-o",
                    "BatchMode=yes",
                    ssh_hostname,
                    "tailscale ip -4 2>/dev/null",
                ],
                capture_output=True,
                timeout=15,
            )

            output = result.stdout.decode("utf-8", errors="ignore").strip()

            # Validate it's a valid Tailscale CGNAT IP (100.64.0.0/10 range)
            if output and is_tailscale_ip(output):
                if verbose:
                    console.print(f"[dim][DEBUG] Got Tailscale IP: {output}[/dim]")
                return output

        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass

        if verbose:
            elapsed = time.time() - start_time
            console.print(
                f"[dim][DEBUG] Waiting for Tailscale auth ({elapsed:.0f}s elapsed)...[/dim]"
            )

        time.sleep(poll_interval)

    return None


def lock_down_to_tailscale(ssh_hostname: str, verbose: bool = False) -> bool:
    """
    Lock down UFW to only allow traffic on the tailscale0 interface.

    This resets UFW and configures it to only allow inbound traffic
    on the Tailscale interface, effectively blocking all public access.

    Args:
        ssh_hostname: SSH hostname to connect to (should use Tailscale IP now)
        verbose: Show debug output

    Returns:
        True if all UFW commands succeeded, False if any command failed
    """
    if verbose:
        console.print("[dim][DEBUG] Locking down UFW to tailscale0 only...[/dim]")

    try:
        # UFW commands to lock down to Tailscale only
        # These must all succeed for proper firewall lockdown
        commands = [
            ("sudo ufw --force reset", "reset UFW"),
            ("sudo ufw allow in on tailscale0", "allow tailscale0 traffic"),
            ("sudo ufw default deny incoming", "deny incoming by default"),
            ("sudo ufw default allow outgoing", "allow outgoing by default"),
            ('echo "y" | sudo ufw enable', "enable UFW"),
        ]

        for cmd, description in commands:
            result = subprocess.run(
                [
                    "ssh",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "ConnectTimeout=10",
                    ssh_hostname,
                    cmd,
                ],
                capture_output=True,
                timeout=30,
            )

            if verbose:
                console.print(f"[dim][DEBUG] {cmd}: returncode={result.returncode}[/dim]")

            # Check return code - any failure means firewall is in unknown state
            if result.returncode != 0:
                stderr = result.stderr.decode("utf-8", errors="ignore").strip()
                if verbose:
                    console.print(
                        f"[dim][DEBUG] UFW command failed to {description}: {stderr}[/dim]"
                    )
                return False

        return True

    except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
        if verbose:
            console.print(f"[dim][DEBUG] Failed to lock down UFW: {e}[/dim]")
        return False


def verify_tailscale_ssh(
    tailscale_ip: str,
    username: str,
    identity_file: str,
    verbose: bool = False,
) -> bool:
    """
    Verify SSH access works via Tailscale IP.

    Args:
        tailscale_ip: Tailscale IP address to connect to
        username: SSH username
        identity_file: SSH identity file path
        verbose: Show debug output

    Returns:
        True if SSH works, False otherwise
    """
    try:
        result = subprocess.run(
            [
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "BatchMode=yes",
                "-i",
                identity_file,
                f"{username}@{tailscale_ip}",
                "echo 'SSH via Tailscale working'",
            ],
            capture_output=True,
            timeout=15,
        )

        if verbose:
            console.print(
                f"[dim][DEBUG] Tailscale SSH verify: returncode={result.returncode}[/dim]"
            )

        return result.returncode == 0

    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
        return False


def check_tailscale_installed(ssh_hostname: str, verbose: bool = False) -> bool:
    """
    Check if Tailscale is installed on a droplet.

    Args:
        ssh_hostname: SSH hostname to connect to
        verbose: Show debug output

    Returns:
        True if Tailscale is installed, False otherwise
    """
    try:
        result = subprocess.run(
            [
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "BatchMode=yes",
                ssh_hostname,
                "which tailscale",
            ],
            capture_output=True,
            timeout=15,
        )

        if verbose:
            console.print(f"[dim][DEBUG] which tailscale: returncode={result.returncode}[/dim]")

        return result.returncode == 0

    except (subprocess.TimeoutExpired, subprocess.SubprocessError):
        return False


def install_tailscale_on_droplet(ssh_hostname: str, verbose: bool = False) -> bool:
    """
    Install Tailscale on a droplet via SSH.

    Uses the official Tailscale install script.

    Args:
        ssh_hostname: SSH hostname to connect to
        verbose: Show debug output

    Returns:
        True if installation succeeded, False otherwise
    """
    if verbose:
        console.print("[dim][DEBUG] Installing Tailscale on droplet...[/dim]")

    try:
        result = subprocess.run(
            [
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=10",
                ssh_hostname,
                "curl -fsSL https://tailscale.com/install.sh | sudo sh",
            ],
            capture_output=True,
            timeout=120,  # Installation may take a while
        )

        if verbose:
            stdout = result.stdout.decode("utf-8", errors="ignore")
            stderr = result.stderr.decode("utf-8", errors="ignore")
            console.print(f"[dim][DEBUG] Install stdout: {stdout[:500]}...[/dim]")
            if stderr:
                console.print(f"[dim][DEBUG] Install stderr: {stderr[:500]}[/dim]")
            console.print(f"[dim][DEBUG] Install returncode: {result.returncode}[/dim]")

        return result.returncode == 0

    except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
        if verbose:
            console.print(f"[dim][DEBUG] Install failed: {e}[/dim]")
        return False


def setup_tailscale(
    ssh_hostname: str,
    username: str,
    config: DropkitConfig,
    verbose: bool = False,
) -> str | None:
    """
    Set up Tailscale VPN on a droplet after cloud-init completes.

    This function handles the full Tailscale setup flow:
    1. Run `tailscale up` and extract auth URL
    2. Display auth URL to user for browser authentication
    3. Poll for Tailscale IP after authentication
    4. Update SSH config with Tailscale IP
    5. Optionally lock down firewall to Tailscale only

    Args:
        ssh_hostname: SSH hostname to connect to (e.g., "dropkit.my-droplet")
        username: Username for SSH config
        config: DropkitConfig instance with tailscale and ssh settings
        verbose: Show debug output

    Returns:
        Tailscale IP address if setup succeeded, None otherwise
    """
    console.print("\n[bold]Setting up Tailscale VPN[/bold]")

    # Run tailscale up and get auth URL
    auth_url = run_tailscale_up(ssh_hostname, verbose)

    if not auth_url:
        # No auth URL - could mean already authenticated or an error
        # Check if Tailscale is already connected by trying to get IP
        console.print("[dim]No authentication URL received, checking if already connected...[/dim]")

        tailscale_ip = wait_for_tailscale_ip(
            ssh_hostname, timeout=10, poll_interval=2, verbose=verbose
        )

        if tailscale_ip:
            console.print(
                f"[green]✓[/green] Tailscale already connected: [cyan]{tailscale_ip}[/cyan]"
            )
        else:
            console.print("[yellow]⚠[/yellow] Could not connect to Tailscale")
            console.print("[dim]Tailscale is installed but not connected.[/dim]")
            console.print(f"[dim]Connect later with: ssh {ssh_hostname} 'sudo tailscale up'[/dim]")
            return None
    else:
        # Normal flow: display auth URL and wait for user to authenticate
        console.print("\n[bold yellow]Tailscale Authentication Required[/bold yellow]")
        console.print("\nOpen this URL in your browser to authenticate:")
        console.print(f"  [cyan]{auth_url}[/cyan]\n")
        console.print("[dim]Waiting for you to complete authentication...[/dim]")

        # Poll for Tailscale IP
        tailscale_ip = wait_for_tailscale_ip(
            ssh_hostname,
            timeout=config.tailscale.auth_timeout,
            verbose=verbose,
        )

        if not tailscale_ip:
            console.print("[yellow]⚠[/yellow] Tailscale authentication timed out")
            console.print("[dim]You can authenticate later with:[/dim]")
            console.print(f"[dim]  ssh {ssh_hostname} 'sudo tailscale up'[/dim]")
            return None

        console.print(f"[green]✓[/green] Tailscale connected: [cyan]{tailscale_ip}[/cyan]")

    # Update SSH config with Tailscale IP
    console.print("[dim]Updating SSH config with Tailscale IP...[/dim]")
    try:
        add_ssh_host(
            config_path=config.ssh.config_path,
            host_name=ssh_hostname,
            hostname=tailscale_ip,
            user=username,
            identity_file=config.ssh.identity_file,
        )
        console.print(
            f"[green]✓[/green] Updated SSH config: [cyan]{ssh_hostname}[/cyan] -> {tailscale_ip}"
        )
    except OSError as e:
        console.print(f"[yellow]⚠[/yellow] Could not update SSH config: {e}")
        console.print(
            f"[dim]You can connect manually: ssh -i {config.ssh.identity_file} "
            f"{username}@{tailscale_ip}[/dim]"
        )

    # Lock down firewall if configured
    if config.tailscale.lock_down_firewall:
        if check_local_tailscale():
            console.print("[dim]Locking down firewall to Tailscale only...[/dim]")
            if lock_down_to_tailscale(ssh_hostname, verbose):
                console.print("[green]✓[/green] Firewall locked down to Tailscale")
            else:
                console.print("[yellow]⚠[/yellow] Could not lock down firewall")

            # Verify SSH via Tailscale
            if verify_tailscale_ssh(tailscale_ip, username, config.ssh.identity_file, verbose):
                console.print("[green]✓[/green] Verified SSH access via Tailscale")
            else:
                console.print(
                    "[yellow]⚠[/yellow] SSH verification failed - you may need to wait a moment"
                )
        else:
            reason = (
                "not running — skipping firewall lockdown"
                if find_tailscale_cli()
                else "not found — install it or add it to PATH"
            )
            console.print(f"[yellow]⚠[/yellow] Tailscale {reason}")
            console.print(
                "[dim]Public SSH access remains available. Start Tailscale locally and run:[/dim]"
            )
            console.print(
                f"[dim]  ssh {ssh_hostname} "
                "'sudo ufw --force reset && "
                "sudo ufw allow in on tailscale0 && "
                "sudo ufw default deny incoming && "
                "sudo ufw default allow outgoing && "
                "sudo ufw --force enable'[/dim]"
            )

    return tailscale_ip


def find_user_droplet(api: DigitalOceanAPI, droplet_name: str) -> tuple[dict | None, str]:
    """
    Find a droplet by name, filtered by current user's tag.

    Args:
        api: DigitalOceanAPI instance
        droplet_name: Name of the droplet to find

    Returns:
        Droplet dict if found, None otherwise

    Raises:
        typer.Exit: If username cannot be fetched
    """
    try:
        username = api.get_username()
    except DigitalOceanAPIError as e:
        console.print(f"[red]Error fetching username from DigitalOcean: {e}[/red]")
        raise typer.Exit(1)

    # Get droplets tagged with this user
    try:
        tag_name = get_user_tag(username)
        droplets = api.list_droplets(tag_name=tag_name)
    except DigitalOceanAPIError as e:
        console.print(f"[red]Error listing droplets: {e}[/red]")
        raise typer.Exit(1)

    # Find droplet by name
    for droplet in droplets:
        if droplet.get("name") == droplet_name:
            return droplet, username

    return None, username


def find_project_by_name_or_id(
    api: DigitalOceanAPI, name_or_id: str
) -> tuple[str | None, str | None]:
    """
    Find a project by name or UUID.

    Optimized to use direct API call for UUIDs, only lists all projects for name search.

    Args:
        api: DigitalOceanAPI instance
        name_or_id: Project name or UUID

    Returns:
        Tuple of (project_id, project_name) if found, (None, None) otherwise
    """
    # Check if input looks like a UUID (36 chars with hyphens at positions 8, 13, 18, 23)
    if len(name_or_id) == 36 and name_or_id.count("-") == 4:
        # Try direct API call for UUID (more efficient than listing all)
        try:
            project = api.get_project(name_or_id)
            if project:
                return project.get("id"), project.get("name")
        except DigitalOceanAPIError:
            # If direct lookup fails, fall through to name search
            pass

    # Not a UUID or UUID lookup failed - search by name
    try:
        projects = api.list_projects()
    except DigitalOceanAPIError:
        return None, None

    # Try exact name match (case-insensitive)
    for project in projects:
        if project.get("name", "").lower() == name_or_id.lower():
            return project.get("id"), project.get("name")

    return None, None


@app.command()
@requires_lock("init")
def init(
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite existing configuration",
    ),
) -> None:
    """
    Initialize dropkit configuration.

    This will create a config directory at ~/.config/dropkit/ and prompt
    you for your DigitalOcean API token and default settings.
    """
    # Check if config already exists
    if Config.exists() and not force:
        console.print(
            f"[yellow]Configuration already exists at[/yellow] [cyan]{Config.CONFIG_FILE}[/cyan]"
        )
        console.print("[yellow]Use[/yellow] [cyan]--force[/cyan] [yellow]to overwrite[/yellow]")
        raise typer.Exit(1)

    console.print(
        Panel.fit(
            "[bold cyan]dropkit initialization[/bold cyan]\n\n"
            "This will set up your dropkit configuration.",
            border_style="cyan",
        )
    )

    # Create config directory
    Config.ensure_config_dir()
    console.print(f"[green]✓[/green] Created config directory: [cyan]{Config.CONFIG_DIR}[/cyan]")

    # Prompt for DigitalOcean API token
    console.print("\n[bold]DigitalOcean API Token[/bold]")
    console.print("Get your token from: https://cloud.digitalocean.com/account/api/tokens")
    token = Prompt.ask("[cyan]Enter your DO API token[/cyan]", password=True)

    if not token or not token.strip():
        console.print("[red]Error: API token is required[/red]")
        raise typer.Exit(1)

    # Initialize API client to fetch regions and sizes
    console.print("\n[dim]Validating token and fetching available options...[/dim]")
    api = DigitalOceanAPI(token.strip())

    # Try to fetch regions, sizes, and images
    regions = None
    sizes = None
    images = None
    try:
        regions = api.get_available_regions()
        sizes = api.get_available_sizes()
        images = api.get_available_images()
        console.print("[green]✓[/green] Token validated successfully")
    except DigitalOceanAPIError as e:
        console.print(f"[yellow]⚠[/yellow] Could not fetch regions/sizes/images: {e}")
        console.print("[yellow]⚠[/yellow] You can still continue with manual entry")

    # Register SSH keys with DigitalOcean
    ssh_keys, ssh_key_ids, username = register_ssh_keys_with_do(api)

    # Prompt for default region
    console.print("\n[bold]Default Settings[/bold]")

    if regions:
        region = prompt_with_help(
            "Default region",
            default="nyc3",
            display_func=display_regions,
            data=regions,
        )
    else:
        region = Prompt.ask(
            "[cyan]Default region[/cyan]",
            default="nyc3",
        )

    # Prompt for default size
    if sizes:
        size = prompt_with_help(
            "Default droplet size",
            default="s-2vcpu-4gb",
            display_func=display_sizes,
            data=sizes,
        )
    else:
        size = Prompt.ask(
            "[cyan]Default droplet size[/cyan]",
            default="s-2vcpu-4gb",
        )

    # Prompt for default image
    if images:
        image = prompt_with_help(
            "Default image",
            default="ubuntu-25-04-x64",
            display_func=display_images,
            data=images,
        )
    else:
        image = Prompt.ask(
            "[cyan]Default image[/cyan]",
            default="ubuntu-25-04-x64",
        )

    # Prompt for extra tags
    console.print("\n[bold]Tags[/bold]")
    console.print(f"[dim]Mandatory tags (always added): owner:{username}, firewall[/dim]")
    extra_tags_input = Prompt.ask(
        "[cyan]Extra tags (comma-separated, optional)[/cyan]",
        default="",
    )

    # Parse extra tags
    extra_tags = []
    if extra_tags_input.strip():
        extra_tags = [t.strip() for t in extra_tags_input.split(",") if t.strip()]

    # Prompt for default project (optional)
    console.print("\n[bold]Default Project (optional)[/bold]")
    console.print("[dim]You can assign new droplets to a specific project by default[/dim]")

    project_id = None
    default_project_name = None

    try:
        # Try to get the default project
        default_project = api.get_default_project()
        if default_project:
            default_project_name = default_project.get("name", "")
            console.print(
                f"[dim]Your DigitalOcean default project: [cyan]{default_project_name}[/cyan][/dim]"
            )

        # Fetch all projects for help display
        projects = api.list_projects()
        if projects:
            console.print(f"[dim]Found {len(projects)} project(s)[/dim]")

            # Offer default project name as the default choice
            prompt_default = default_project_name if default_project_name else ""

            use_project = prompt_with_help(
                "Default project name or ID (? for help, or press Enter to skip)",
                default=prompt_default,
                display_func=display_projects,
                data=projects,
            )

            if use_project.strip():
                # Resolve project name or ID to UUID (config stores UUID)
                resolved_id, resolved_name = find_project_by_name_or_id(api, use_project)
                if resolved_id:
                    project_id = resolved_id
                    console.print(f"[green]✓[/green] Default project: [cyan]{resolved_name}[/cyan]")
                else:
                    console.print(f"[yellow]⚠[/yellow] Project '{use_project}' not found[/yellow]")
                    console.print("[dim]Skipping default project[/dim]")
        else:
            console.print("[dim]No projects found in your account[/dim]")
    except DigitalOceanAPIError as e:
        console.print(f"[yellow]⚠[/yellow] Could not fetch projects: {e}")
        console.print("[dim]Skipping default project[/dim]")

    # Create config
    config = Config()
    config.create_default_config(
        token=token.strip(),
        username=username,
        region=region,
        size=size,
        image=image,
        ssh_keys=ssh_keys,
        ssh_key_ids=ssh_key_ids,
        extra_tags=extra_tags,
        project_id=project_id,
    )
    config.save()

    console.print(f"\n[green]✓[/green] Saved configuration to [cyan]{Config.CONFIG_FILE}[/cyan]")

    # Show summary
    console.print("\n[bold green]Configuration complete![/bold green]")
    console.print("\n[bold]Summary:[/bold]")

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="cyan")
    table.add_column()

    table.add_row("Config directory:", str(Config.CONFIG_DIR))
    table.add_row("Default region:", region)
    table.add_row("Default size:", size)
    table.add_row("Default image:", image)
    table.add_row(
        "Mandatory tags:",
        f"owner:{username}, firewall (always added)",
    )
    if config.config.defaults.extra_tags:
        table.add_row("Extra tags:", ", ".join(config.config.defaults.extra_tags))
    if project_id:
        # Try to get project name for display
        try:
            projects_list = api.list_projects()
            project_obj = next((p for p in projects_list if p.get("id") == project_id), None)
            if project_obj:
                table.add_row("Default project:", project_obj.get("name", project_id))
        except Exception:
            # If we can't get the name, just show the ID
            table.add_row("Default project:", project_id)
    table.add_row("SSH keys:", f"{len(ssh_keys)} key(s)")

    console.print(table)

    console.print("\n[bold]Next steps:[/bold]")
    console.print("  • Create a droplet: [cyan]dropkit create <name>[/cyan]")
    console.print(
        "  • Customize cloud-init template (optional): copy from package and set template_path in config"
    )


@app.command()
@requires_lock("create")
def create(
    name: str | None = typer.Argument(None, help="Name for the droplet"),
    region: str | None = typer.Option(None, "--region", "-r", help="Region slug"),
    size: str | None = typer.Option(None, "--size", "-s", help="Droplet size slug"),
    image: str | None = typer.Option(None, "--image", "-i", help="Image slug"),
    tags: str | None = typer.Option(
        None, "--tags", "-t", help="Comma-separated tags (extends default tags)"
    ),
    user: str | None = typer.Option(None, "--user", "-u", help="Username to create"),
    project: str | None = typer.Option(
        None,
        "--project",
        "-p",
        help="Project name or ID to assign droplet to",
        autocompletion=complete_project_name,
    ),
    no_tailscale: bool = typer.Option(
        False, "--no-tailscale", help="Disable Tailscale VPN setup for this droplet"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show verbose debug output"),
) -> None:
    """
    Create a new DigitalOcean droplet with cloud-init configuration.

    This will create a droplet with the specified name, applying your cloud-init
    template and automatically adding an SSH config entry.
    """
    # Load configuration
    config_manager = Config()
    try:
        config_manager.load()
    except FileNotFoundError as e:
        console.print(f"[red]Error: {e}[/red]")
        console.print("[yellow]Run[/yellow] [cyan]dropkit init[/cyan] [yellow]first[/yellow]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error loading config: {e}[/red]")
        console.print(
            "[yellow]Config file may be invalid. Try running[/yellow] [cyan]dropkit init --force[/cyan]"
        )
        raise typer.Exit(1)

    # Get validated config
    config = config_manager.config

    # Get values from config or use provided values
    token = config.digitalocean.token

    # Create API client
    api = DigitalOceanAPI(token)

    # Interactive mode: prompt for missing values
    if name is None:
        console.print("\n[bold cyan]Create New Droplet[/bold cyan]")
        name = Prompt.ask("\n[bold]Droplet name[/bold]")

    # Get region (interactive if not provided)
    if region is None:
        try:
            available_regions = api.get_available_regions()
            region = prompt_with_help(
                "\n[bold]Region[/bold]",
                default=config.defaults.region,
                display_func=display_regions,
                data=available_regions,
            )
        except DigitalOceanAPIError as e:
            console.print(f"[yellow]Warning: Could not fetch regions: {e}[/yellow]")
            console.print(f"[dim]Using default region: {config.defaults.region}[/dim]")
            region = config.defaults.region

    # Get size (interactive if not provided)
    if size is None:
        try:
            available_sizes = api.get_available_sizes()
            size = prompt_with_help(
                "\n[bold]Size[/bold]",
                default=config.defaults.size,
                display_func=display_sizes,
                data=available_sizes,
            )
        except DigitalOceanAPIError as e:
            console.print(f"[yellow]Warning: Could not fetch sizes: {e}[/yellow]")
            console.print(f"[dim]Using default size: {config.defaults.size}[/dim]")
            size = config.defaults.size

    # Get image (interactive if not provided)
    if image is None:
        try:
            available_images = api.get_available_images()
            image = prompt_with_help(
                "\n[bold]Image[/bold]",
                default=config.defaults.image,
                display_func=display_images,
                data=available_images,
            )
        except DigitalOceanAPIError as e:
            console.print(f"[yellow]Warning: Could not fetch images: {e}[/yellow]")
            console.print(f"[dim]Using default image: {config.defaults.image}[/dim]")
            image = config.defaults.image

    # Type guard - values are guaranteed non-None after interactive prompts
    if name is None or region is None or size is None or image is None:
        console.print("[red]Error: Missing required parameters[/red]")
        raise typer.Exit(1)

    # Get project (use flag if provided, otherwise use config default or skip)
    # The parameter can be a name or UUID; config always stores UUID
    project_input = project if project is not None else config.defaults.project_id
    project_id = None
    project_name = None

    if project_input:
        # Resolve project name or UUID to get both ID and name
        resolved_id, resolved_name = find_project_by_name_or_id(api, project_input)
        if resolved_id:
            project_id = resolved_id
            project_name = resolved_name
            if verbose:
                console.print(f"[dim][DEBUG] Project: {project_name} ({project_id})[/dim]")
        else:
            console.print(f"[yellow]Warning: Project '{project_input}' not found[/yellow]")
            console.print("[yellow]Droplet will be created without project assignment[/yellow]")

    # Get username, email, and full name for droplet (use flag if provided, otherwise fetch from DO API)
    try:
        account = api.get_account()
        email = account.get("email", "")
        if not email:
            console.print("[red]Error: No email found in DigitalOcean account[/red]")
            raise typer.Exit(1)

        do_username = api.get_username()
    except DigitalOceanAPIError as e:
        console.print(f"[red]Error fetching account info from DigitalOcean: {e}[/red]")
        raise typer.Exit(1)

    # Determine final username
    username = do_username if user is None else user

    # Get full name from account (fallback to username if not available)
    full_name = account.get("name", "") or username

    if verbose:
        console.print(f"[dim][DEBUG] Username: {username}[/dim]")
        console.print(f"[dim][DEBUG] Full name: {full_name}[/dim]")
        console.print(f"[dim][DEBUG] Email: {email}[/dim]")

    # Build tags list: mandatory tags + extra_tags from config + command-line tags
    extra_tags_list = list(config.defaults.extra_tags)  # Start with config tags

    if tags:
        additional_tags = [t.strip() for t in tags.split(",") if t.strip()]
        extra_tags_list.extend(additional_tags)

    tags_list = build_droplet_tags(do_username, extra_tags_list)

    if verbose:
        console.print(f"[dim][DEBUG] Using tags: {tags_list}[/dim]")

    # Check for existing droplet with same name
    user_tag = get_user_tag(do_username)
    existing_droplet, _ = find_user_droplet(api, name)
    if existing_droplet:
        console.print(f"[red]Error: A droplet named '{name}' already exists[/red]")
        console.print(
            f"[yellow]Use [cyan]dropkit destroy {name}[/cyan] to delete it first, "
            f"or choose a different name[/yellow]"
        )
        raise typer.Exit(1)

    # Check for hibernated snapshot with same name
    snapshot_name = get_snapshot_name(name)
    try:
        snapshot = api.get_snapshot_by_name(snapshot_name, tag=user_tag)
        if snapshot:
            console.print(
                f"[red]Error: A hibernated snapshot '{snapshot_name}' already exists[/red]"
            )
            console.print(
                f"[yellow]Use [cyan]dropkit wake {name}[/cyan] to restore it, "
                f"[cyan]dropkit destroy {name}[/cyan] to delete the snapshot, "
                f"or choose a different name[/yellow]"
            )
            raise typer.Exit(1)
    except DigitalOceanAPIError as e:
        if verbose:
            console.print(f"[dim][DEBUG] Could not check for existing snapshots: {e}[/dim]")
        # Continue anyway - snapshot check is best-effort

    # Get SSH keys
    ssh_keys = config.cloudinit.ssh_keys

    if verbose:
        console.print(f"[dim][DEBUG] SSH keys: {ssh_keys}[/dim]")

    # Get cloud-init template path (use package default if not specified)
    template_path = (
        config.cloudinit.template_path
        if config.cloudinit.template_path
        else str(config_manager.get_default_template_path())
    )

    if verbose:
        source = "custom" if config.cloudinit.template_path else "package default"
        console.print(f"[dim][DEBUG] Cloud-init template ({source}): {template_path}[/dim]")

    console.print(
        Panel.fit(
            f"[bold cyan]Creating droplet: {name}[/bold cyan]",
            border_style="cyan",
        )
    )

    # Show configuration
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="dim")
    table.add_column(style="white")

    table.add_row("Region:", region)
    table.add_row("Size:", size)
    table.add_row("Image:", image)
    table.add_row("User:", username)
    table.add_row("Tags:", ", ".join(tags_list))
    if project_id and project_name:
        table.add_row("Project:", project_name)

    console.print(table)
    console.print()

    # Determine if Tailscale should be enabled
    tailscale_enabled = not no_tailscale and config.tailscale.enabled

    # Render cloud-init
    try:
        console.print("[dim]Rendering cloud-init template...[/dim]")
        user_data = render_cloud_init(
            template_path, username, full_name, email, ssh_keys, tailscale_enabled
        )

        if verbose:
            console.print("\n[dim][DEBUG] Rendered cloud-init template:[/dim]")
            console.print("[dim]" + "=" * 60 + "[/dim]")
            console.print(f"[dim]{user_data}[/dim]")
            console.print("[dim]" + "=" * 60 + "[/dim]\n")
    except Exception as e:
        console.print(f"[red]Error rendering cloud-init: {e}[/red]")
        raise typer.Exit(1)

    # Create droplet
    try:
        if verbose:
            console.print(
                f"[dim][DEBUG] Creating droplet with API endpoint: {config.digitalocean.api_base}/droplets[/dim]"
            )
        console.print("[dim]Creating droplet via API...[/dim]")
        droplet = api.create_droplet(
            name=name,
            region=region,
            size=size,
            image=image,
            user_data=user_data,
            tags=tags_list,
            ssh_keys=config.cloudinit.ssh_key_ids,
        )

        droplet_id = droplet.get("id")
        if not droplet_id:
            console.print("[red]Error: Failed to get droplet ID from API response[/red]")
            raise typer.Exit(1)

        console.print(f"[green]✓[/green] Droplet created with ID: [cyan]{droplet_id}[/cyan]")

        if verbose:
            console.print(f"[dim][DEBUG] Droplet status: {droplet.get('status')}[/dim]")
            console.print(f"[dim][DEBUG] Full droplet response: {droplet}[/dim]")

        # Wait for droplet to become active
        console.print("[dim]Waiting for droplet to become active...[/dim]")
        if verbose:
            console.print("[dim][DEBUG] Polling droplet status every 5 seconds...[/dim]")

        with console.status("[cyan]Waiting...[/cyan]"):
            active_droplet = api.wait_for_droplet_active(droplet_id)

        console.print("[green]✓[/green] Droplet is now active")

        if verbose:
            console.print(
                f"[dim][DEBUG] Active droplet networks: {active_droplet.get('networks')}[/dim]"
            )

        # Assign droplet to project if specified
        if project_id:
            try:
                console.print(f"[dim]Assigning droplet to project '{project_name}'...[/dim]")
                droplet_urn = api.get_droplet_urn(droplet_id)
                api.assign_resources_to_project(project_id, [droplet_urn])
                console.print(f"[green]✓[/green] Assigned to project: [cyan]{project_name}[/cyan]")
            except DigitalOceanAPIError as e:
                console.print(f"[yellow]⚠[/yellow] Could not assign to project: {e}")

        # Get IP address
        networks = active_droplet.get("networks", {})
        v4_networks = networks.get("v4", [])
        ip_address = None

        for network in v4_networks:
            if network.get("type") == "public":
                ip_address = network.get("ip_address")
                break

        # Initialize for type safety - ssh_hostname needed for output regardless of path
        ssh_hostname = get_ssh_hostname(name)
        tailscale_ip: str | None = None

        if not ip_address:
            console.print("[yellow]⚠[/yellow] Could not determine IP address")
            cloud_init_done = False
            cloud_init_error = False
        else:
            console.print(f"[green]✓[/green] IP address: [cyan]{ip_address}[/cyan]")
            if verbose:
                console.print(f"[dim][DEBUG] All v4 networks: {v4_networks}[/dim]")

            # Add SSH config entry first so we can use it for cloud-init checks
            if config.ssh.auto_update:
                try:
                    console.print("[dim]Adding SSH config entry...[/dim]")
                    if verbose:
                        console.print(
                            f"[dim][DEBUG] SSH config path: {config.ssh.config_path}[/dim]"
                        )
                        console.print(
                            f"[dim][DEBUG] Adding host '{name}' -> {username}@{ip_address}[/dim]"
                        )
                        console.print(
                            f"[dim][DEBUG] Identity file: {config.ssh.identity_file}[/dim]"
                        )

                    add_ssh_host(
                        config_path=config.ssh.config_path,
                        host_name=ssh_hostname,
                        hostname=ip_address,
                        user=username,
                        identity_file=config.ssh.identity_file,
                    )
                    console.print(
                        f"[green]✓[/green] Added SSH config: [cyan]ssh {ssh_hostname}[/cyan]"
                    )
                except Exception as e:
                    console.print(f"[yellow]⚠[/yellow] Could not update SSH config: {e}")

            # Wait for cloud-init to complete using helper function
            cloud_init_done, cloud_init_error = wait_for_cloud_init(ssh_hostname, verbose)

            # Tailscale setup (if enabled and cloud-init succeeded)
            if tailscale_enabled and cloud_init_done:
                tailscale_ip = setup_tailscale(ssh_hostname, username, config, verbose)

        # Show summary based on cloud-init and Tailscale status
        console.print()
        if tailscale_enabled and tailscale_ip:
            console.print("[bold green]Droplet ready with Tailscale VPN![/bold green]")
            console.print("\n[bold]Connect via Tailscale with:[/bold]")
            console.print(f"  [cyan]ssh {ssh_hostname}[/cyan]")
            if not config.tailscale.lock_down_firewall or not check_local_tailscale():
                console.print("\n[bold]Or via public IP:[/bold]")
                console.print(f"  [cyan]ssh {username}@{ip_address}[/cyan]")
        elif cloud_init_done:
            console.print("[bold green]Droplet created successfully![/bold green]")
            console.print("\n[bold]Droplet is fully ready! Connect with:[/bold]")
            if ip_address:
                console.print(f"  [cyan]ssh {ssh_hostname}[/cyan]")
                console.print(f"  or: [cyan]ssh {username}@{ip_address}[/cyan]")
        elif cloud_init_error:
            console.print("[bold yellow]Droplet created with cloud-init errors[/bold yellow]")
            console.print(
                "\n[bold]The droplet is running but needs investigation. Connect with:[/bold]"
            )
            if ip_address:
                console.print(f"  [cyan]ssh {ssh_hostname}[/cyan]")
                console.print(f"  or: [cyan]ssh {username}@{ip_address}[/cyan]")
        else:
            console.print("[bold green]Droplet created successfully![/bold green]")
            console.print("\n[bold]Connect with:[/bold]")
            if ip_address:
                console.print(f"  [cyan]ssh {ssh_hostname}[/cyan]")
                console.print(f"  or: [cyan]ssh {username}@{ip_address}[/cyan]")

        if ip_address and not cloud_init_done and not cloud_init_error:
            console.print(
                "\n[dim]Note: Cloud-init may still be running. You can check status with:[/dim]"
            )
            console.print(f"[dim]  ssh {ssh_hostname} 'cloud-init status'[/dim]")

    except DigitalOceanAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="list")
@app.command(name="ls", hidden=True)
def list_droplets():
    """List droplets and hibernated snapshots tagged with owner:<username>."""
    try:
        # Load config and API
        config_manager, api = load_config_and_api()
        config = config_manager.config

        # Get username from DigitalOcean for tag filtering
        try:
            username = api.get_username()
        except DigitalOceanAPIError as e:
            console.print(f"[red]Error fetching username from DigitalOcean: {e}[/red]")
            raise typer.Exit(1)

        tag_name = get_user_tag(username)

        console.print(f"[dim]Fetching resources with tag: [cyan]{tag_name}[/cyan][/dim]\n")

        # List droplets
        droplets = api.list_droplets(tag_name=tag_name)

        if droplets:
            # Create droplets table
            console.print("[bold]Droplets:[/bold]")
            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("Name", style="white", no_wrap=True)
            table.add_column("Status", style="white", no_wrap=True)
            table.add_column("IP Address", style="cyan", no_wrap=True)
            table.add_column("Region", style="white", no_wrap=True)
            table.add_column("Size", style="white", no_wrap=True)
            table.add_column("SSH", style="white", no_wrap=True)

            # Add rows
            for droplet in droplets:
                name = droplet.get("name", "N/A")
                status = droplet.get("status", "N/A")

                # Get public IP
                ip_address = "N/A"
                v4_networks = droplet.get("networks", {}).get("v4", [])
                for network in v4_networks:
                    if network.get("type") == "public":
                        ip_address = network.get("ip_address", "N/A")
                        break

                region = droplet.get("region", {}).get("slug", "N/A")
                size = droplet.get("size_slug", "N/A")

                # Check if in SSH config
                ssh_hostname = get_ssh_hostname(name)
                in_ssh_config = "✓" if host_exists(config.ssh.config_path, ssh_hostname) else "✗"

                # Color status
                if status == "active":
                    status_colored = f"[green]{status}[/green]"
                elif status == "new":
                    status_colored = f"[yellow]{status}[/yellow]"
                else:
                    status_colored = f"[red]{status}[/red]"

                table.add_row(name, status_colored, ip_address, region, size, in_ssh_config)

            console.print(table)

        # List hibernated snapshots
        hibernated = get_user_hibernated_snapshots(api, tag_name)

        if hibernated:
            if droplets:
                console.print()  # Spacing between tables
            console.print("[bold]Hibernated:[/bold]")
            snap_table = Table(show_header=True, header_style="bold cyan")
            snap_table.add_column("Name", style="white", no_wrap=True)
            snap_table.add_column("Droplet Size", style="white", no_wrap=True)
            snap_table.add_column("Image Size", style="white", no_wrap=True)
            snap_table.add_column("Region", style="white", no_wrap=True)

            for snapshot in hibernated:
                snapshot_name = snapshot.get("name", "")
                # Extract droplet name from snapshot name (remove "dropkit-" prefix)
                droplet_name = get_droplet_name_from_snapshot(snapshot_name) or snapshot_name

                # Extract droplet size slug from size: tag
                droplet_size = "N/A"
                for tag in snapshot.get("tags", []):
                    if tag.startswith("size:"):
                        droplet_size = tag.removeprefix("size:")

                size_gb = snapshot.get("size_gigabytes", 0)
                regions = snapshot.get("regions", [])
                region = regions[0] if regions else "N/A"

                snap_table.add_row(droplet_name, droplet_size, f"{size_gb} GB", region)

            console.print(snap_table)
            console.print()
            console.print("[dim]Wake with: dropkit wake <name>[/dim]")

        # Summary
        if droplets or hibernated:
            console.print()
            parts = []
            if droplets:
                parts.append(f"{len(droplets)} droplet(s)")
            if hibernated:
                parts.append(f"{len(hibernated)} hibernated")
            console.print(f"[dim]Total: {', '.join(parts)}[/dim]")
        else:
            console.print(
                f"[yellow]No droplets or hibernated snapshots found with tag: {tag_name}[/yellow]"
            )

    except DigitalOceanAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
@requires_lock("config-ssh")
def config_ssh(
    droplet_name: str = typer.Argument(..., autocompletion=complete_droplet_name),
    user: str | None = typer.Option(None, "--user", "-u", help="SSH username"),
    identity_file: str | None = typer.Option(
        None, "--identity-file", "-i", help="SSH identity file path"
    ),
):
    """Configure SSH for an existing droplet."""
    try:
        # Load config and API
        config_manager, api = load_config_and_api()
        config = config_manager.config

        # Find the droplet
        console.print(f"[dim]Looking for droplet: [cyan]{droplet_name}[/cyan][/dim]")
        droplet, username = find_user_droplet(api, droplet_name)

        if not droplet:
            tag = get_user_tag(username)
            console.print(f"[red]Error: Droplet '{droplet_name}' not found with tag {tag}[/red]")
            raise typer.Exit(1)

        # Get IP address
        ip_address = None
        v4_networks = droplet.get("networks", {}).get("v4", [])
        for network in v4_networks:
            if network.get("type") == "public":
                ip_address = network.get("ip_address")
                break

        if not ip_address:
            console.print(
                f"[red]Error: No public IP address found for droplet '{droplet_name}'[/red]"
            )
            raise typer.Exit(1)

        console.print(f"[green]✓[/green] Found droplet with IP: [cyan]{ip_address}[/cyan]\n")

        # Check if already in SSH config
        ssh_hostname = get_ssh_hostname(droplet_name)
        if host_exists(config.ssh.config_path, ssh_hostname):
            console.print(
                f"[yellow]⚠[/yellow] SSH config entry for '{ssh_hostname}' already exists"
            )
            if not Confirm.ask("Do you want to update it?", default=False):
                console.print("[dim]Aborted[/dim]")
                return

        # Get SSH user (from flag or prompt)
        if user is None:
            # Use droplet username from DO as default
            ssh_user: str = Prompt.ask(
                "[cyan]SSH username[/cyan]",
                default=username,
            )
        else:
            ssh_user = user
            console.print(f"[dim]Using SSH user: [cyan]{ssh_user}[/cyan][/dim]")

        # Get identity file (from flag or prompt)
        if identity_file is None:
            default_identity = config.ssh.identity_file
            identity_file = Prompt.ask(
                "[cyan]SSH identity file path[/cyan]",
                default=default_identity,
            )
        else:
            console.print(f"[dim]Using identity file: [cyan]{identity_file}[/cyan][/dim]")

        # Add to SSH config
        console.print("[dim]Adding SSH config entry...[/dim]")
        add_ssh_host(
            config_path=config.ssh.config_path,
            host_name=ssh_hostname,
            hostname=ip_address,
            user=ssh_user,
            identity_file=identity_file,
        )

        console.print(f"[green]✓[/green] SSH config updated for [cyan]{droplet_name}[/cyan]")
        console.print("\n[bold]Connect with:[/bold]")
        console.print(f"  [cyan]ssh {ssh_hostname}[/cyan]")

    except DigitalOceanAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def info(droplet_name: str = typer.Argument(..., autocompletion=complete_droplet_name)):
    """Show detailed information about a droplet."""
    try:
        # Load config and API
        config_manager, api = load_config_and_api()
        config = config_manager.config

        # Find the droplet
        console.print(f"[dim]Looking for droplet: [cyan]{droplet_name}[/cyan][/dim]\n")
        droplet, username = find_user_droplet(api, droplet_name)

        if not droplet:
            tag = get_user_tag(username)
            console.print(f"[red]Error: Droplet '{droplet_name}' not found with tag {tag}[/red]")
            raise typer.Exit(1)

        # Get detailed droplet info
        droplet_id = droplet.get("id")
        if droplet_id:
            droplet = api.get_droplet(droplet_id)

        # Display information in a nice format
        console.print(
            Panel.fit(
                f"[bold cyan]Droplet Information: {droplet_name}[/bold cyan]",
                border_style="cyan",
            )
        )

        # Basic info table
        basic_table = Table(show_header=False, box=None, padding=(0, 2))
        basic_table.add_column(style="dim")
        basic_table.add_column(style="white")

        status = droplet.get("status", "unknown")
        status_colored = (
            f"[green]{status}[/green]" if status == "active" else f"[yellow]{status}[/yellow]"
        )

        basic_table.add_row("ID:", str(droplet.get("id", "N/A")))
        basic_table.add_row("Name:", droplet.get("name", "N/A"))
        basic_table.add_row("Status:", status_colored)
        basic_table.add_row("Created:", droplet.get("created_at", "N/A"))

        console.print("\n[bold]Basic Information:[/bold]")
        console.print(basic_table)

        # Network info
        networks = droplet.get("networks", {})
        v4_networks = networks.get("v4", [])
        v6_networks = networks.get("v6", [])

        console.print("\n[bold]Network:[/bold]")
        network_table = Table(show_header=False, box=None, padding=(0, 2))
        network_table.add_column(style="dim")
        network_table.add_column(style="cyan")

        # IPv4 addresses
        for network in v4_networks:
            net_type = network.get("type", "").title()
            ip_address = network.get("ip_address", "N/A")
            network_table.add_row(f"{net_type} IPv4:", ip_address)

        # IPv6 addresses
        for network in v6_networks:
            net_type = network.get("type", "").title()
            ip_address = network.get("ip_address", "N/A")
            network_table.add_row(f"{net_type} IPv6:", ip_address)

        if not v4_networks and not v6_networks:
            network_table.add_row("IP Addresses:", "None")

        console.print(network_table)

        # Configuration
        console.print("\n[bold]Configuration:[/bold]")
        config_table = Table(show_header=False, box=None, padding=(0, 2))
        config_table.add_column(style="dim")
        config_table.add_column(style="white")

        region_info = droplet.get("region", {})
        size_info = droplet.get("size", {})
        image_info = droplet.get("image", {})

        config_table.add_row("Region:", region_info.get("slug", "N/A"))
        config_table.add_row("Size:", droplet.get("size_slug", "N/A"))
        config_table.add_row("vCPUs:", f"{size_info.get('vcpus', 'N/A')} vCPU(s)")
        config_table.add_row("Memory:", f"{size_info.get('memory', 'N/A')} MB")
        config_table.add_row("Disk:", f"{size_info.get('disk', 'N/A')} GB")
        config_table.add_row("Transfer:", f"{size_info.get('transfer', 'N/A')} TB")
        config_table.add_row("Price:", f"${size_info.get('price_monthly', 'N/A')}/month")

        console.print(config_table)

        # Image info
        console.print("\n[bold]Image:[/bold]")
        image_table = Table(show_header=False, box=None, padding=(0, 2))
        image_table.add_column(style="dim")
        image_table.add_column(style="white")

        image_table.add_row("Distribution:", image_info.get("distribution", "N/A"))
        image_table.add_row("Name:", image_info.get("name", "N/A"))
        image_table.add_row("Slug:", image_info.get("slug", "N/A"))

        console.print(image_table)

        # Tags
        tags = droplet.get("tags", [])
        console.print("\n[bold]Tags:[/bold]")
        if tags:
            console.print(f"  {', '.join(tags)}")
        else:
            console.print("  [dim]None[/dim]")

        # Features
        features = droplet.get("features", [])
        if features:
            console.print("\n[bold]Features:[/bold]")
            console.print(f"  {', '.join(features)}")

        # SSH info
        console.print("\n[bold]SSH Access:[/bold]")
        ssh_hostname = get_ssh_hostname(droplet_name)
        in_ssh_config = host_exists(config.ssh.config_path, ssh_hostname)
        if in_ssh_config:
            console.print(f"  [green]✓[/green] In SSH config: [cyan]ssh {ssh_hostname}[/cyan]")
        else:
            console.print("  [yellow]✗[/yellow] Not in SSH config")
            console.print(f"  [dim]Run: [cyan]dropkit config-ssh {droplet_name}[/cyan][/dim]")

        # Public IP for manual SSH
        public_ip = None
        for network in v4_networks:
            if network.get("type") == "public":
                public_ip = network.get("ip_address")
                break

        if public_ip:
            console.print(f"  [dim]Manual SSH: ssh root@{public_ip}[/dim]")

    except DigitalOceanAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
@app.command(name="rm", hidden=True)
@requires_lock("destroy")
def destroy(droplet_name: str = typer.Argument(..., autocompletion=complete_droplet_name)):
    """
    Destroy a droplet or hibernated snapshot (DESTRUCTIVE - requires confirmation).

    This will permanently delete the droplet (or hibernated snapshot) and remove
    its SSH config entry. Only resources tagged with owner:<your-username> can be destroyed.

    If no droplet is found, this command will check for a hibernated snapshot
    with the same name and offer to delete that instead.
    """
    try:
        # Load config and API
        config_manager, api = load_config_and_api()
        config = config_manager.config

        # Find the droplet
        console.print(f"[dim]Looking for droplet: [cyan]{droplet_name}[/cyan][/dim]\n")
        droplet, username = find_user_droplet(api, droplet_name)

        # If no droplet found, check for hibernated snapshot
        if not droplet:
            # Check for hibernated snapshot
            snapshot_name = get_snapshot_name(droplet_name)
            user_tag = get_user_tag(username)
            snapshot = api.get_snapshot_by_name(snapshot_name, tag=user_tag)

            if snapshot:
                # Found a hibernated snapshot - handle deletion
                _destroy_hibernated_snapshot(api, snapshot, droplet_name, snapshot_name)
                return

            # Neither droplet nor snapshot found
            console.print(
                f"[red]Error: No droplet or hibernated snapshot found for '{droplet_name}'[/red]"
            )
            console.print(f"[dim]Checked for droplet with tag: {user_tag}[/dim]")
            console.print(f"[dim]Checked for snapshot named: {snapshot_name}[/dim]")
            raise typer.Exit(1)

        # Get detailed droplet info for display
        droplet_id = droplet.get("id")
        if not droplet_id:
            console.print("[red]Error: Could not determine droplet ID[/red]")
            raise typer.Exit(1)

        droplet = api.get_droplet(droplet_id)

        # Display droplet information before deletion
        console.print(
            Panel.fit(
                f"[bold red]⚠ DESTROY DROPLET: {droplet_name}[/bold red]",
                border_style="red",
            )
        )

        # Show key information
        info_table = Table(show_header=False, box=None, padding=(0, 2))
        info_table.add_column(style="dim")
        info_table.add_column(style="white")

        status = droplet.get("status", "unknown")
        info_table.add_row("Name:", droplet.get("name", "N/A"))
        info_table.add_row("ID:", str(droplet.get("id", "N/A")))
        info_table.add_row("Status:", status)

        # Get IP address
        droplet_public_ip = None
        networks = droplet.get("networks", {})
        v4_networks = networks.get("v4", [])
        for network in v4_networks:
            if network.get("type") == "public":
                droplet_public_ip = network.get("ip_address")
                info_table.add_row("IP:", droplet_public_ip or "N/A")
                break

        info_table.add_row("Region:", droplet.get("region", {}).get("slug", "N/A"))
        info_table.add_row("Size:", droplet.get("size_slug", "N/A"))
        info_table.add_row("Created:", droplet.get("created_at", "N/A"))

        # Show tags
        tags = droplet.get("tags", [])
        if tags:
            info_table.add_row("Tags:", ", ".join(tags))

        console.print(info_table)
        console.print()

        # First confirmation: yes/no
        console.print("[bold red]⚠ WARNING: This action cannot be undone![/bold red]")
        console.print()

        first_confirm = Prompt.ask(
            "[yellow]Are you sure you want to destroy this droplet?[/yellow]",
            choices=["yes", "no"],
            default="no",
        )

        if first_confirm != "yes":
            console.print("[dim]Cancelled.[/dim]")
            raise typer.Exit(0)

        # Second confirmation: type droplet name
        console.print()
        name_confirm = Prompt.ask(
            f"[yellow]Type the droplet name '[cyan]{droplet_name}[/cyan]' to confirm deletion[/yellow]"
        )

        if name_confirm != droplet_name:
            console.print(
                f"[red]Error: Name mismatch. Expected '{droplet_name}', got '{name_confirm}'[/red]"
            )
            console.print("[dim]Cancelled.[/dim]")
            raise typer.Exit(1)

        # Get Tailscale IP before destroying (for known_hosts cleanup)
        ssh_hostname = get_ssh_hostname(droplet_name)
        droplet_tailscale_ip = None
        tailscale_locked = is_droplet_tailscale_locked(config, droplet_name)

        if tailscale_locked:
            # SSH config has the Tailscale IP - save it for cleanup
            droplet_tailscale_ip = get_ssh_host_ip(config.ssh.config_path, ssh_hostname)

            # Add temporary SSH rule so we can reach the droplet via public IP
            console.print()
            console.print("[dim]Adding temporary SSH rule for eth0...[/dim]")
            if not add_temporary_ssh_rule(ssh_hostname):
                console.print(
                    "[yellow]⚠[/yellow] Could not add temporary SSH rule - "
                    "skipping Tailscale logout to maintain connectivity"
                )
            else:
                console.print("[green]✓[/green] Temporary SSH rule added")

                # Update SSH config to public IP before logout so the SSH
                # session routes over the public IP instead of Tailscale
                if droplet_public_ip:
                    try:
                        username = api.get_username()
                        add_ssh_host(
                            config_path=config.ssh.config_path,
                            host_name=ssh_hostname,
                            hostname=droplet_public_ip,
                            user=username,
                            identity_file=config.ssh.identity_file,
                        )
                    except Exception:
                        pass

                # Now safe to logout from Tailscale
                console.print("[dim]Logging out from Tailscale...[/dim]")
                if tailscale_logout(ssh_hostname):
                    console.print("[green]✓[/green] Logged out from Tailscale")
                else:
                    console.print(
                        "[yellow]⚠[/yellow] Could not logout from Tailscale "
                        "(device may remain in Tailscale admin console)"
                    )
        else:
            # SSH config has public IP, try to get Tailscale IP via SSH
            console.print("[dim]Checking for Tailscale IP...[/dim]")
            droplet_tailscale_ip = get_tailscale_ip(ssh_hostname)
            if droplet_tailscale_ip:
                console.print(f"[dim]Found Tailscale IP: {droplet_tailscale_ip}[/dim]")

        # Proceed with deletion
        console.print()
        console.print("[dim]Deleting droplet...[/dim]")

        api.delete_droplet(droplet_id)
        console.print("[green]✓[/green] Droplet destroyed")

        # Remove SSH config entry and clean up known_hosts
        cleanup_ssh_entries(
            config,
            droplet_name,
            prompt_known_hosts=True,
            public_ip=droplet_public_ip,
            tailscale_ip=droplet_tailscale_ip,
        )

        console.print()
        console.print("[bold green]Droplet successfully destroyed[/bold green]")

    except DigitalOceanAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


def _complete_hibernate(
    api: DigitalOceanAPI,
    config: DropkitConfig,
    droplet_id: int,
    droplet_name: str,
    snapshot_name: str,
    username: str,
    size_slug: str,
    tailscale_locked: bool = False,
    public_ip: str | None = None,
    tailscale_ip: str | None = None,
) -> None:
    """
    Complete hibernate after snapshot is done (tag, destroy, cleanup, success message).

    This handles steps 8-11 of the hibernate flow:
    - Tag the snapshot with owner, size, and tailscale-lockdown (if applicable)
    - Destroy the droplet
    - Remove SSH config entry
    - Print success message

    Args:
        api: DigitalOceanAPI instance
        config: DropkitConfig instance
        droplet_id: ID of the droplet to destroy
        droplet_name: Name of the droplet
        snapshot_name: Name of the snapshot
        username: Username for tagging
        size_slug: Size slug for tagging
        tailscale_locked: If True, tag snapshot with tailscale-lockdown
        public_ip: Public IP of the droplet (for known_hosts cleanup)
        tailscale_ip: Tailscale IP of the droplet (for known_hosts cleanup)
    """
    user_tag = get_user_tag(username)

    # Tag the snapshot
    snapshot = api.get_snapshot_by_name(snapshot_name)
    if snapshot:
        snapshot_id = snapshot.get("id")
        if snapshot_id:
            try:
                api.create_tag(user_tag)
                api.tag_resource(user_tag, str(snapshot_id), "image")
                size_tag = f"size:{size_slug}"
                api.create_tag(size_tag)
                api.tag_resource(size_tag, str(snapshot_id), "image")

                # Tag with tailscale-lockdown if droplet was under Tailscale lockdown
                if tailscale_locked:
                    lockdown_tag = "tailscale-lockdown"
                    api.create_tag(lockdown_tag)
                    api.tag_resource(lockdown_tag, str(snapshot_id), "image")
            except DigitalOceanAPIError as e:
                console.print(f"[yellow]⚠[/yellow] Could not tag snapshot (non-critical): {e}")

    # Destroy droplet
    console.print("\n[dim]Destroying droplet...[/dim]")
    api.delete_droplet(droplet_id)
    console.print("[green]✓[/green] Droplet destroyed")

    # Remove SSH config entry and clean up known_hosts
    cleanup_ssh_entries(
        config,
        droplet_name,
        prompt_known_hosts=True,
        public_ip=public_ip,
        tailscale_ip=tailscale_ip,
    )

    # Summary
    console.print()
    console.print(f"[bold green]Droplet '{droplet_name}' is now hibernated.[/bold green]")
    if snapshot:
        size_gb = snapshot.get("size_gigabytes", 0)
        if size_gb:
            console.print(f"Snapshot size: {size_gb} GB")
    console.print(f"Restore anytime with: [cyan]dropkit wake {droplet_name}[/cyan]")


def _destroy_hibernated_snapshot(
    api: DigitalOceanAPI,
    snapshot: dict,
    droplet_name: str,
    snapshot_name: str,
) -> None:
    """
    Handle destruction of a hibernated snapshot.

    This is called by the destroy command when no droplet is found but a
    hibernated snapshot exists.
    """
    snapshot_id_str = snapshot.get("id")
    if not snapshot_id_str:
        console.print("[red]Error: Could not determine snapshot ID[/red]")
        raise typer.Exit(1)
    snapshot_id = int(snapshot_id_str)  # API returns string, convert to int

    size_gb = snapshot.get("size_gigabytes", 0)
    regions = snapshot.get("regions", [])
    region = regions[0] if regions else "N/A"
    created_at = snapshot.get("created_at", "N/A")

    # Display snapshot information
    console.print(
        Panel.fit(
            f"[bold red]⚠ DESTROY HIBERNATED SNAPSHOT: {droplet_name}[/bold red]",
            border_style="red",
        )
    )

    console.print("[dim]No active droplet found, but found a hibernated snapshot.[/dim]")
    console.print()

    info_table = Table(show_header=False, box=None, padding=(0, 2))
    info_table.add_column(style="dim")
    info_table.add_column(style="white")

    info_table.add_row("Snapshot name:", snapshot_name)
    info_table.add_row("Snapshot ID:", str(snapshot_id))
    info_table.add_row("Size:", f"{size_gb} GB")
    info_table.add_row("Region:", region)
    info_table.add_row("Created:", created_at)

    console.print(info_table)
    console.print()

    # Warning and confirmation
    console.print("[bold red]⚠ WARNING: This action cannot be undone![/bold red]")
    console.print("[dim]The hibernated snapshot will be permanently deleted.[/dim]")
    console.print()

    confirm = Prompt.ask(
        f"[yellow]Delete hibernated snapshot '{snapshot_name}'?[/yellow]",
        choices=["yes", "no"],
        default="no",
    )

    if confirm != "yes":
        console.print("[dim]Cancelled.[/dim]")
        raise typer.Exit(0)

    # Delete snapshot
    console.print()
    console.print("[dim]Deleting snapshot...[/dim]")
    api.delete_snapshot(snapshot_id)
    console.print("[green]✓[/green] Snapshot deleted")

    console.print()
    console.print(
        f"[bold green]Hibernated snapshot '{droplet_name}' successfully destroyed[/bold green]"
    )


def _resize_hibernated_snapshot(
    api: DigitalOceanAPI,
    snapshot: dict,
    droplet_name: str,
    size: str | None,
) -> None:
    """
    Handle resizing of a hibernated snapshot by swapping its size: tag.

    This is called by the resize command when no live droplet is found but a
    hibernated snapshot exists. The resize is instant — it just updates the
    size: tag so the next wake uses the new size.
    """
    raw_id = snapshot.get("id")
    if not raw_id:
        console.print("[red]Error: Could not determine snapshot ID[/red]")
        raise typer.Exit(1)
    snapshot_id = str(raw_id)

    # Read current size from tags
    current_size_slug = None
    for tag in snapshot.get("tags", []):
        if tag.startswith("size:"):
            current_size_slug = tag.removeprefix("size:")

    if not current_size_slug:
        console.print("[yellow]Could not determine current size from snapshot tags.[/yellow]")
        console.print("[dim]The snapshot may not have a size tag. Try waking it first.[/dim]")
        raise typer.Exit(1)

    # Display header
    console.print(
        Panel.fit(
            f"[bold cyan]RESIZE HIBERNATED SNAPSHOT: {droplet_name}[/bold cyan]",
            border_style="cyan",
        )
    )

    console.print(
        "[dim]No active droplet found, but found a hibernated snapshot.\n"
        "Resizing a hibernated snapshot is instant — it updates the size tag\n"
        "so the next wake creates the droplet with the new size.[/dim]\n"
    )

    # Display current size
    console.print(f"[bold]Current Size:[/bold] [cyan]{current_size_slug}[/cyan]")

    # Fetch available sizes once (needed for both interactive prompt and validation)
    try:
        available_sizes = api.get_available_sizes()
    except DigitalOceanAPIError as e:
        console.print(f"[red]Error fetching sizes: {e}[/red]")
        raise typer.Exit(1)

    # Get new size (interactive if not provided)
    if size is None:
        new_size_slug = prompt_with_help(
            "\n[bold]New size[/bold]",
            default=current_size_slug,
            display_func=display_sizes,
            data=available_sizes,
        )
    else:
        new_size_slug = size

    # Check if same size
    if new_size_slug == current_size_slug:
        console.print(
            f"\n[yellow]New size is the same as current size ({current_size_slug})[/yellow]"
        )
        console.print("[dim]No resize needed.[/dim]")
        raise typer.Exit(0)

    # Validate the new size exists
    new_size_info = next((s for s in available_sizes if s.get("slug") == new_size_slug), None)
    if not new_size_info:
        console.print(f"[red]Error: Size '{new_size_slug}' not found or not available[/red]")
        raise typer.Exit(1)

    # Display new size details
    console.print(f"\n[bold]New Size:[/bold] [cyan]{new_size_slug}[/cyan]")
    new_table = Table(show_header=False, box=None, padding=(0, 2))
    new_table.add_column(style="dim")
    new_table.add_column(style="white")

    new_table.add_row("vCPUs:", str(new_size_info.get("vcpus", "N/A")))
    new_table.add_row("Memory:", f"{new_size_info.get('memory', 'N/A')} MB")
    new_table.add_row("Disk:", f"{new_size_info.get('disk', 'N/A')} GB")
    new_table.add_row("Price:", f"${new_size_info.get('price_monthly', 0):.2f}/month")

    console.print(new_table)

    # Confirmation
    console.print()
    confirm = Prompt.ask(
        "[yellow]Are you sure you want to resize this hibernated snapshot?[/yellow]",
        choices=["yes", "no"],
        default="no",
    )

    if confirm != "yes":
        console.print("[dim]Cancelled.[/dim]")
        raise typer.Exit(0)

    # Swap the size tag: add new first, then remove old
    # This ensures the snapshot always has at least one size: tag even if we crash mid-operation
    console.print()
    console.print("[dim]Updating size tag...[/dim]")

    new_tag = f"size:{new_size_slug}"
    old_tag = f"size:{current_size_slug}"

    api.create_tag(new_tag)
    api.tag_resource(new_tag, snapshot_id, "image")
    api.untag_resource(old_tag, snapshot_id, "image")

    console.print("[green]✓[/green] Size tag updated")
    console.print()
    console.print(
        f"[bold green]Hibernated snapshot '{droplet_name}' resized from "
        f"{current_size_slug} to {new_size_slug}[/bold green]"
    )
    console.print(f"[dim]Next wake will create the droplet with size {new_size_slug}.[/dim]")


@app.command()
@requires_lock("rename")
def rename(
    old_name: str = typer.Argument(..., autocompletion=complete_droplet_name),
    new_name: str = typer.Argument(..., help="New name for the droplet"),
):
    """
    Rename a droplet (requires confirmation).

    This will rename the droplet and update the SSH config entry.
    Only droplets tagged with owner:<your-username> can be renamed.
    """
    try:
        # Load config and API
        config_manager, api = load_config_and_api()
        config = config_manager.config

        # Find the droplet
        console.print(f"[dim]Looking for droplet: [cyan]{old_name}[/cyan][/dim]\n")
        droplet, username = find_user_droplet(api, old_name)

        if not droplet:
            tag = get_user_tag(username)
            console.print(f"[red]Error: Droplet '{old_name}' not found with tag {tag}[/red]")
            raise typer.Exit(1)

        # Get droplet ID
        droplet_id = droplet.get("id")
        if not droplet_id:
            console.print("[red]Error: Could not determine droplet ID[/red]")
            raise typer.Exit(1)

        # Check if new name is same as old name
        if old_name == new_name:
            console.print(f"[yellow]New name is the same as current name ({old_name})[/yellow]")
            console.print("[dim]No rename needed.[/dim]")
            raise typer.Exit(0)

        # Check if new name already exists among user's droplets
        user_droplets = api.list_droplets(tag_name=get_user_tag(username))
        for d in user_droplets:
            if d.get("name") == new_name:
                console.print(
                    f"[red]Error:[/red] A droplet with name '[cyan]{new_name}[/cyan]' already exists."
                )
                raise typer.Exit(1)

        # Check droplet status - must be active for rename
        status = droplet.get("status", "unknown")
        if status != "active":
            console.print(
                f"[red]Error:[/red] Droplet '[cyan]{old_name}[/cyan]' "
                f"is currently [bold]{status}[/bold]."
            )
            console.print(f"[dim]Power on the droplet first with: dropkit on {old_name}[/dim]")
            raise typer.Exit(1)

        # Get detailed droplet info for display
        droplet = api.get_droplet(droplet_id)

        # Get IP address for SSH config update
        ip_address = None
        v4_networks = droplet.get("networks", {}).get("v4", [])
        for network in v4_networks:
            if network.get("type") == "public":
                ip_address = network.get("ip_address")
                break

        # Display droplet information
        console.print(
            Panel.fit(
                "[bold cyan]RENAME DROPLET[/bold cyan]",
                border_style="cyan",
            )
        )

        info_table = Table(show_header=False, box=None, padding=(0, 2))
        info_table.add_column(style="dim")
        info_table.add_column(style="white")

        info_table.add_row("Current name:", f"[cyan]{old_name}[/cyan]")
        info_table.add_row("New name:", f"[green]{new_name}[/green]")
        info_table.add_row("ID:", str(droplet_id))
        if ip_address:
            info_table.add_row("IP:", ip_address)
        info_table.add_row("Status:", droplet.get("status", "unknown"))

        console.print(info_table)
        console.print()

        # Show SSH config change
        old_ssh_hostname = get_ssh_hostname(old_name)
        new_ssh_hostname = get_ssh_hostname(new_name)
        console.print(f"[dim]SSH config will change: {old_ssh_hostname} → {new_ssh_hostname}[/dim]")
        console.print()

        # Confirmation
        confirm = Prompt.ask(
            "[yellow]Are you sure you want to rename this droplet?[/yellow]",
            choices=["yes", "no"],
            default="no",
        )

        if confirm != "yes":
            console.print("[dim]Cancelled.[/dim]")
            raise typer.Exit(0)

        # Perform rename via API
        console.print()
        console.print("[dim]Renaming droplet...[/dim]")

        action = api.rename_droplet(droplet_id, new_name)

        # Wait for rename action to complete
        action_id = action.get("id")
        if action_id:
            api.wait_for_action_complete(action_id, timeout=60, poll_interval=2)

        console.print(f"[green]✓[/green] Droplet renamed to [cyan]{new_name}[/cyan]")

        # Update SSH config
        if host_exists(config.ssh.config_path, old_ssh_hostname):
            try:
                # Remove old SSH entry
                remove_ssh_host(config.ssh.config_path, old_ssh_hostname)
                console.print(
                    f"[green]✓[/green] Removed old SSH config entry: [dim]{old_ssh_hostname}[/dim]"
                )

                # Add new SSH entry if we have the IP
                if ip_address:
                    add_ssh_host(
                        config_path=config.ssh.config_path,
                        host_name=new_ssh_hostname,
                        hostname=ip_address,
                        user=username,
                        identity_file=config.ssh.identity_file,
                    )
                    console.print(
                        f"[green]✓[/green] Added new SSH config entry: [cyan]{new_ssh_hostname}[/cyan]"
                    )
            except Exception as e:
                console.print(f"[yellow]⚠[/yellow] Could not update SSH config: {e}")
                console.print(
                    f"[dim]Run 'dropkit config-ssh {new_name}' to configure SSH manually[/dim]"
                )
        else:
            console.print(f"[dim]SSH config entry for {old_ssh_hostname} not found (skipped)[/dim]")

        console.print()
        console.print(f"[bold green]Droplet successfully renamed to {new_name}[/bold green]")
        if ip_address and host_exists(config.ssh.config_path, new_ssh_hostname):
            console.print("\n[bold]Connect with:[/bold]")
            console.print(f"  [cyan]ssh {new_ssh_hostname}[/cyan]")

    except DigitalOceanAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
@requires_lock("resize")
def resize(
    droplet_name: str = typer.Argument(..., autocompletion=complete_droplet_or_snapshot_name),
    size: str | None = typer.Option(None, "--size", "-s", help="New size slug (e.g., s-4vcpu-8gb)"),
    disk: bool = typer.Option(
        True, "--disk/--no-disk", help="Resize disk (permanent, default: True)"
    ),
):
    """
    Resize a droplet or hibernated snapshot.

    For live droplets, this causes downtime (requires power off) and changes
    the droplet's vCPUs, memory, and optionally disk size.

    For hibernated snapshots, this is instant — it updates the size tag so the
    next wake creates the droplet with the new size. The --disk/--no-disk flag
    is ignored for hibernated snapshots.

    Only resources tagged with owner:<your-username> can be resized.
    """
    try:
        # Load config and API
        _, api = load_config_and_api()

        # Find the droplet
        console.print(f"[dim]Looking for droplet: [cyan]{droplet_name}[/cyan][/dim]\n")
        droplet, username = find_user_droplet(api, droplet_name)

        # If no droplet found, check for hibernated snapshot
        if not droplet:
            snapshot_name = get_snapshot_name(droplet_name)
            user_tag = get_user_tag(username)
            snapshot = api.get_snapshot_by_name(snapshot_name, tag=user_tag)

            if snapshot:
                _resize_hibernated_snapshot(api, snapshot, droplet_name, size)
                return

            console.print(
                f"[red]Error: No droplet or hibernated snapshot found for '{droplet_name}'[/red]"
            )
            console.print(f"[dim]Checked for droplet with tag: {user_tag}[/dim]")
            console.print(f"[dim]Checked for snapshot named: {snapshot_name}[/dim]")
            raise typer.Exit(1)

        # Get detailed droplet info
        droplet_id = droplet.get("id")
        if not droplet_id:
            console.print("[red]Error: Could not determine droplet ID[/red]")
            raise typer.Exit(1)

        droplet = api.get_droplet(droplet_id)

        # Get current size info
        current_size_slug = droplet.get("size_slug", "")
        current_size_info = droplet.get("size", {})

        if not current_size_slug:
            console.print("[red]Error: Could not determine current droplet size[/red]")
            raise typer.Exit(1)

        # Display header
        console.print(
            Panel.fit(
                f"[bold cyan]RESIZE DROPLET: {droplet_name}[/bold cyan]",
                border_style="cyan",
            )
        )

        # Display current size
        console.print("\n[bold]Current Size:[/bold] [cyan]" + current_size_slug + "[/cyan]")
        current_table = Table(show_header=False, box=None, padding=(0, 2))
        current_table.add_column(style="dim")
        current_table.add_column(style="white")

        current_vcpus = current_size_info.get("vcpus", "N/A")
        current_memory = current_size_info.get("memory", "N/A")
        current_disk = current_size_info.get("disk", "N/A")
        current_price = current_size_info.get("price_monthly", 0)

        current_table.add_row("vCPUs:", str(current_vcpus))
        current_table.add_row("Memory:", f"{current_memory} MB")
        current_table.add_row("Disk:", f"{current_disk} GB")
        current_table.add_row("Price:", f"${current_price:.2f}/month")

        console.print(current_table)

        # Get new size (interactive if not provided)
        if size is None:
            console.print()
            # Fetch available sizes for interactive selection
            try:
                available_sizes = api.get_available_sizes()
            except DigitalOceanAPIError as e:
                console.print(f"[red]Error fetching sizes: {e}[/red]")
                raise typer.Exit(1)

            new_size_slug = prompt_with_help(
                "\n[bold]New size[/bold]",
                default=current_size_slug,
                display_func=display_sizes,
                data=available_sizes,
            )
        else:
            new_size_slug = size

        # Check if same size
        if new_size_slug == current_size_slug:
            console.print(
                f"[yellow]Error: New size is the same as current size ({current_size_slug})[/yellow]"
            )
            console.print("[dim]No resize needed.[/dim]")
            raise typer.Exit(0)

        # Fetch all sizes to get the new size details
        try:
            all_sizes = api.get_available_sizes()
            new_size_info = None
            for s in all_sizes:
                if s.get("slug") == new_size_slug:
                    new_size_info = s
                    break

            if not new_size_info:
                console.print(
                    f"[red]Error: Size '{new_size_slug}' not found or not available[/red]"
                )
                raise typer.Exit(1)

        except DigitalOceanAPIError as e:
            console.print(f"[red]Error fetching size details: {e}[/red]")
            raise typer.Exit(1)

        # Display new size
        console.print("\n[bold]New Size:[/bold] [cyan]" + new_size_slug + "[/cyan]")
        new_table = Table(show_header=False, box=None, padding=(0, 2))
        new_table.add_column(style="dim")
        new_table.add_column(style="white")

        new_vcpus = new_size_info.get("vcpus", "N/A")
        new_memory = new_size_info.get("memory", "N/A")
        new_disk = new_size_info.get("disk", "N/A")
        new_price = new_size_info.get("price_monthly", 0)

        new_table.add_row("vCPUs:", str(new_vcpus))
        new_table.add_row("Memory:", f"{new_memory} MB")
        new_table.add_row("Disk:", f"{new_disk} GB")
        new_table.add_row("Price:", f"${new_price:.2f}/month")

        console.print(new_table)

        # Display changes
        console.print("\n[bold]Changes:[/bold]")
        changes_table = Table(show_header=False, box=None, padding=(0, 2))
        changes_table.add_column(style="dim")
        changes_table.add_column(style="white")

        # vCPUs
        vcpu_diff = (
            new_vcpus - current_vcpus
            if isinstance(new_vcpus, int) and isinstance(current_vcpus, int)
            else 0
        )
        vcpu_change = f"{current_vcpus} → {new_vcpus}"
        if vcpu_diff > 0:
            vcpu_change += f" [green](+{vcpu_diff})[/green]"
        elif vcpu_diff < 0:
            vcpu_change += f" [yellow]({vcpu_diff})[/yellow]"
        changes_table.add_row("vCPUs:", vcpu_change)

        # Memory
        mem_diff = (
            new_memory - current_memory
            if isinstance(new_memory, int) and isinstance(current_memory, int)
            else 0
        )
        mem_change = f"{current_memory} MB → {new_memory} MB"
        if mem_diff > 0:
            mem_change += f" [green](+{mem_diff} MB)[/green]"
        elif mem_diff < 0:
            mem_change += f" [yellow]({mem_diff} MB)[/yellow]"
        changes_table.add_row("Memory:", mem_change)

        # Disk
        disk_diff = (
            new_disk - current_disk
            if isinstance(new_disk, int) and isinstance(current_disk, int)
            else 0
        )
        disk_change = f"{current_disk} GB → {new_disk} GB"
        if disk and disk_diff > 0:
            disk_change += f" [green](+{disk_diff} GB)[/green]"
        elif disk and disk_diff < 0:
            disk_change += f" [yellow]({disk_diff} GB)[/yellow]"
        elif not disk:
            disk_change = f"{current_disk} GB (not resized)"
        changes_table.add_row("Disk:", disk_change)

        # Price
        price_diff = new_price - current_price
        price_change = f"${current_price:.2f}/month → ${new_price:.2f}/month"
        if price_diff > 0:
            price_change += f" [yellow](+${price_diff:.2f}/month)[/yellow]"
        elif price_diff < 0:
            price_change += f" [green](-${abs(price_diff):.2f}/month)[/green]"
        changes_table.add_row("Price:", price_change)

        console.print(changes_table)

        # Show warnings
        console.print()
        console.print(
            "[bold yellow]⚠ WARNING: This operation will cause downtime (droplet will be powered off)[/bold yellow]"
        )

        if disk:
            console.print(
                "[bold red]⚠ WARNING: Disk resize is PERMANENT and cannot be undone![/bold red]"
            )
        else:
            console.print(
                "[dim]Note: Disk will NOT be resized. You can resize it later, but it's permanent.[/dim]"
            )

        # Confirmation
        console.print()
        confirm = Prompt.ask(
            "[yellow]Are you sure you want to resize this droplet?[/yellow]",
            choices=["yes", "no"],
            default="no",
        )

        if confirm != "yes":
            console.print("[dim]Cancelled.[/dim]")
            raise typer.Exit(0)

        # Initiate resize
        console.print()
        console.print("[dim]Initiating resize...[/dim]")

        action = api.resize_droplet(droplet_id, new_size_slug, disk=disk)
        action_id = action.get("id")

        if not action_id:
            console.print("[red]Error: Failed to get action ID from API response[/red]")
            raise typer.Exit(1)

        console.print(f"[green]✓[/green] Resize action started (ID: [cyan]{action_id}[/cyan])")

        # Wait for action to complete
        console.print(
            "[dim]Waiting for resize to complete (this may take several minutes)...[/dim]"
        )

        with console.status("[cyan]Resizing...[/cyan]"):
            api.wait_for_action_complete(action_id, timeout=600)  # 10 minutes

        console.print("[green]✓[/green] Resize completed successfully")
        console.print()
        console.print(
            f"[bold green]Droplet {droplet_name} has been resized to {new_size_slug}[/bold green]"
        )

    except DigitalOceanAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
@requires_lock("on")
def on(droplet_name: str = typer.Argument(..., autocompletion=complete_droplet_name)):
    """
    Power on a droplet.

    Only droplets tagged with owner:<your-username> can be powered on.
    """
    try:
        # Load config and API
        config_manager, api = load_config_and_api()

        # Find the droplet
        console.print(f"[dim]Looking for droplet: [cyan]{droplet_name}[/cyan][/dim]\n")
        droplet, username = find_user_droplet(api, droplet_name)

        if not droplet:
            tag = get_user_tag(username)
            console.print(f"[red]Error: Droplet '{droplet_name}' not found with tag {tag}[/red]")
            raise typer.Exit(1)

        # Get droplet ID and status
        droplet_id = droplet.get("id")
        if not droplet_id:
            console.print("[red]Error: Could not determine droplet ID[/red]")
            raise typer.Exit(1)

        status = droplet.get("status", "")

        # Check if already active
        if status == "active":
            console.print(f"[yellow]Droplet '{droplet_name}' is already active[/yellow]")
            raise typer.Exit(0)

        # Show current status
        console.print(
            Panel.fit(
                f"[bold cyan]POWER ON DROPLET: {droplet_name}[/bold cyan]",
                border_style="cyan",
            )
        )
        console.print(f"Current status: [yellow]{status}[/yellow]")
        console.print()

        # Power on
        console.print("[dim]Powering on droplet...[/dim]")

        action = api.power_on_droplet(droplet_id)
        action_id = action.get("id")

        if not action_id:
            console.print("[red]Error: Failed to get action ID from API response[/red]")
            raise typer.Exit(1)

        console.print(f"[green]✓[/green] Power on action started (ID: [cyan]{action_id}[/cyan])")

        # Wait for action to complete
        console.print("[dim]Waiting for droplet to power on...[/dim]")

        with console.status("[cyan]Powering on...[/cyan]"):
            api.wait_for_action_complete(action_id, timeout=120)  # 2 minutes

        console.print("[green]✓[/green] Droplet powered on successfully")
        console.print()
        console.print(f"[bold green]Droplet {droplet_name} is now active[/bold green]")

    except DigitalOceanAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
@requires_lock("off")
def off(droplet_name: str = typer.Argument(..., autocompletion=complete_droplet_name)):
    """
    Power off a droplet (requires confirmation).

    Only droplets tagged with owner:<your-username> can be powered off.
    """
    try:
        # Load config and API
        config_manager, api = load_config_and_api()

        # Find the droplet
        console.print(f"[dim]Looking for droplet: [cyan]{droplet_name}[/cyan][/dim]\n")
        droplet, username = find_user_droplet(api, droplet_name)

        if not droplet:
            tag = get_user_tag(username)
            console.print(f"[red]Error: Droplet '{droplet_name}' not found with tag {tag}[/red]")
            raise typer.Exit(1)

        # Get droplet ID and status
        droplet_id = droplet.get("id")
        if not droplet_id:
            console.print("[red]Error: Could not determine droplet ID[/red]")
            raise typer.Exit(1)

        status = droplet.get("status", "")

        # Check if already off
        if status == "off":
            console.print(f"[yellow]Droplet '{droplet_name}' is already powered off[/yellow]")
            raise typer.Exit(0)

        # Show current status
        console.print(
            Panel.fit(
                f"[bold yellow]POWER OFF DROPLET: {droplet_name}[/bold yellow]",
                border_style="yellow",
            )
        )
        console.print(f"Current status: [green]{status}[/green]")
        console.print()

        # Show billing warning
        console.print(
            "[bold yellow]⚠  Warning:[/bold yellow] DigitalOcean bills for stopped droplets "
            "at the full hourly rate."
        )
        console.print(
            "   Consider using [cyan]dropkit hibernate[/cyan] to snapshot and destroy instead."
        )
        console.print()

        # Confirmation
        confirm = Prompt.ask(
            "[yellow]Are you sure you want to power off this droplet?[/yellow]",
            choices=["yes", "no"],
            default="no",
        )

        if confirm != "yes":
            console.print("[dim]Cancelled.[/dim]")
            raise typer.Exit(0)

        # Power off
        console.print()
        console.print("[dim]Powering off droplet...[/dim]")

        action = api.power_off_droplet(droplet_id)
        action_id = action.get("id")

        if not action_id:
            console.print("[red]Error: Failed to get action ID from API response[/red]")
            raise typer.Exit(1)

        console.print(f"[green]✓[/green] Power off action started (ID: [cyan]{action_id}[/cyan])")

        # Wait for action to complete
        console.print("[dim]Waiting for droplet to power off...[/dim]")

        with console.status("[cyan]Powering off...[/cyan]"):
            api.wait_for_action_complete(action_id, timeout=120)  # 2 minutes

        console.print("[green]✓[/green] Droplet powered off successfully")
        console.print()
        console.print(f"[bold green]Droplet {droplet_name} is now off[/bold green]")

    except DigitalOceanAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
@requires_lock("hibernate")
def hibernate(
    droplet_name: str = typer.Argument(..., autocompletion=complete_droplet_name),
    continue_: bool = typer.Option(
        False, "--continue", "-c", help="Continue a timed-out hibernate operation"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show debug output"),
):
    """
    Hibernate a droplet (snapshot and destroy to save costs).

    This will create a snapshot of the droplet, then destroy it.
    You can restore it later with 'dropkit wake <name>'.

    Only droplets tagged with owner:<your-username> can be hibernated.

    Use --continue to resume a hibernate operation that timed out while
    creating the snapshot. This will find the in-progress snapshot action
    and wait for it to complete, then finish the hibernate process.
    """
    try:
        # Load config and API
        config_manager, api = load_config_and_api()
        config = config_manager.config

        # Find the droplet
        console.print(f"[dim]Looking for droplet: [cyan]{droplet_name}[/cyan][/dim]\n")
        droplet, username = find_user_droplet(api, droplet_name)

        if not droplet:
            tag = get_user_tag(username)
            console.print(f"[red]Error: Droplet '{droplet_name}' not found with tag {tag}[/red]")
            raise typer.Exit(1)

        # Get droplet details
        droplet_id = droplet.get("id")
        if not droplet_id:
            console.print("[red]Error: Could not determine droplet ID[/red]")
            raise typer.Exit(1)

        droplet = api.get_droplet(droplet_id)
        status = droplet.get("status", "")
        size_slug = droplet.get("size_slug", "")

        # Extract public IP for known_hosts cleanup
        droplet_public_ip = None
        networks = droplet.get("networks", {})
        v4_networks = networks.get("v4", [])
        for network in v4_networks:
            if network.get("type") == "public":
                droplet_public_ip = network.get("ip_address")
                break

        # Get Tailscale IP for known_hosts cleanup
        # Must be done BEFORE prepare_for_tailscale_hibernate() changes the SSH config
        ssh_hostname = get_ssh_hostname(droplet_name)
        droplet_tailscale_ip = None
        tailscale_locked = is_droplet_tailscale_locked(config, droplet_name)
        if tailscale_locked:
            # SSH config currently has the Tailscale IP - save it before it gets changed
            droplet_tailscale_ip = get_ssh_host_ip(config.ssh.config_path, ssh_hostname)
            if droplet_tailscale_ip:
                console.print(f"[dim]Saved Tailscale IP: {droplet_tailscale_ip}[/dim]")
        else:
            # SSH config has public IP, try to get Tailscale IP via SSH
            console.print("[dim]Checking for Tailscale IP...[/dim]")
            droplet_tailscale_ip = get_tailscale_ip(ssh_hostname)
            if droplet_tailscale_ip:
                console.print(f"[dim]Found Tailscale IP: {droplet_tailscale_ip}[/dim]")

        # Generate snapshot name
        snapshot_name = get_snapshot_name(droplet_name)

        # Handle --continue flag: resume a timed-out hibernate
        if continue_:
            snapshot_action = find_snapshot_action(api, droplet_id)

            if not snapshot_action:
                console.print("[red]Error: No snapshot action found for this droplet[/red]")
                console.print("[dim]Run hibernate without --continue to start fresh[/dim]")
                raise typer.Exit(1)

            action_status = snapshot_action.get("status")
            action_id = snapshot_action.get("id")

            if not action_id:
                console.print("[red]Error: Snapshot action has no ID[/red]")
                raise typer.Exit(1)

            if action_status == "errored":
                console.print("[red]Error: Previous snapshot action failed[/red]")
                console.print("[dim]Run hibernate without --continue to retry[/dim]")
                raise typer.Exit(1)
            if action_status == "in-progress":
                console.print(f"[dim]Found in-progress snapshot action (ID: {action_id})[/dim]")
                try:
                    with console.status("[cyan]Waiting for snapshot to complete...[/cyan]"):
                        api.wait_for_action_complete(action_id, timeout=3600)
                    console.print("[green]✓[/green] Snapshot completed")
                except DigitalOceanAPIError as e:
                    console.print(f"[red]Error: Snapshot wait failed: {e}[/red]")
                    console.print(
                        "[yellow]⚠[/yellow] Droplet remains powered off. "
                        "Run [cyan]dropkit hibernate --continue[/cyan] again to retry."
                    )
                    raise typer.Exit(1)
            elif action_status == "completed":
                console.print("[green]✓[/green] Snapshot already completed")

            # Complete the hibernate (tag, destroy, cleanup)
            # Note: tailscale_locked was already detected earlier
            if tailscale_locked:
                console.print("[dim]Detected Tailscale lockdown[/dim]")

            _complete_hibernate(
                api,
                config,
                droplet_id,
                droplet_name,
                snapshot_name,
                username,
                size_slug,
                tailscale_locked=tailscale_locked,
                public_ip=droplet_public_ip,
                tailscale_ip=droplet_tailscale_ip,
            )
            return  # Exit early, skip normal flow

        # Check if snapshot already exists
        user_tag = get_user_tag(username)
        existing_snapshot = api.get_snapshot_by_name(snapshot_name, tag=user_tag)

        if existing_snapshot:
            console.print(f"[yellow]⚠[/yellow] Snapshot '{snapshot_name}' already exists.")
            overwrite = Prompt.ask(
                "[yellow]Overwrite existing snapshot?[/yellow]",
                choices=["yes", "no"],
                default="no",
            )
            if overwrite != "yes":
                console.print("[dim]Aborted.[/dim]")
                raise typer.Exit(0)

            # Delete existing snapshot
            console.print("[dim]Deleting existing snapshot...[/dim]")
            api.delete_snapshot(int(existing_snapshot["id"]))
            console.print("[green]✓[/green] Existing snapshot deleted")

        # Display header
        console.print(
            Panel.fit(
                f"[bold cyan]HIBERNATE DROPLET: {droplet_name}[/bold cyan]",
                border_style="cyan",
            )
        )
        console.print("This will snapshot the droplet and then destroy it.")
        console.print(f"You can restore it later with [cyan]dropkit wake {droplet_name}[/cyan]")
        console.print()

        # Confirmation
        confirm = Prompt.ask(
            "[yellow]Are you sure?[/yellow]",
            choices=["yes", "no"],
            default="no",
        )

        if confirm != "yes":
            console.print("[dim]Cancelled.[/dim]")
            raise typer.Exit(0)

        console.print()

        # Step 0: Prepare for hibernate (handle Tailscale lockdown if present)
        tailscale_locked = prepare_for_hibernate(config, api, droplet, droplet_name, verbose)

        # Step 1: Power off if not already off
        if status != "off":
            console.print("[dim]Powering off droplet...[/dim]")
            action = api.power_off_droplet(droplet_id)
            action_id = action.get("id")

            if action_id:
                with console.status("[cyan]Powering off...[/cyan]"):
                    api.wait_for_action_complete(action_id, timeout=120)
            console.print("[green]✓[/green] Droplet powered off")
        else:
            console.print("[dim]Droplet already powered off[/dim]")

        # Step 2: Create snapshot
        console.print(f"\n[dim]Creating snapshot '{snapshot_name}'...[/dim]")
        start_time = time.time()

        action = api.create_snapshot(droplet_id, snapshot_name)
        action_id = action.get("id")

        if not action_id:
            console.print("[red]Error: Failed to get action ID for snapshot[/red]")
            console.print(
                "[yellow]⚠[/yellow] Droplet remains powered off but intact. "
                "Please check DigitalOcean console."
            )
            raise typer.Exit(1)

        try:
            with console.status(
                "[cyan]Creating snapshot (this may take several minutes)...[/cyan]"
            ):
                api.wait_for_action_complete(action_id, timeout=3600)  # 60 minutes max

            elapsed = time.time() - start_time
            minutes = int(elapsed // 60)
            seconds = int(elapsed % 60)
            time_str = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"
            console.print(f"[green]✓[/green] Snapshot created (took {time_str})")
        except DigitalOceanAPIError as e:
            console.print(f"[red]Error: Snapshot creation failed: {e}[/red]")
            console.print(
                "[yellow]⚠[/yellow] Droplet remains powered off but intact. "
                f"Run [cyan]dropkit hibernate --continue {droplet_name}[/cyan] to retry."
            )
            raise typer.Exit(1)

        # Complete hibernate: tag snapshot, destroy droplet, remove SSH config
        _complete_hibernate(
            api,
            config,
            droplet_id,
            droplet_name,
            snapshot_name,
            username,
            size_slug,
            tailscale_locked=tailscale_locked,
            public_ip=droplet_public_ip,
            tailscale_ip=droplet_tailscale_ip,
        )

    except DigitalOceanAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
@requires_lock("wake")
def wake(
    droplet_name: str = typer.Argument(
        ..., autocompletion=complete_snapshot_name, help="Name of the hibernated droplet to restore"
    ),
    no_tailscale: bool = typer.Option(False, "--no-tailscale", help="Skip Tailscale VPN re-setup"),
):
    """
    Wake a hibernated droplet (restore from snapshot).

    This will create a new droplet from the hibernated snapshot.
    After successful restoration, you'll be prompted to delete the snapshot.

    If the original droplet had Tailscale lockdown enabled, this command will
    re-setup Tailscale after the droplet becomes active. Use --no-tailscale to
    skip this and keep public SSH access.

    Use 'dropkit destroy <name>' to delete a hibernated snapshot without restoring.
    """
    try:
        # Load config and API
        config_manager, api = load_config_and_api()
        config = config_manager.config

        # Get username
        try:
            username = api.get_username()
        except DigitalOceanAPIError as e:
            console.print(f"[red]Error fetching username from DigitalOcean: {e}[/red]")
            raise typer.Exit(1)

        # Check if a droplet with this name already exists
        existing_droplet, _ = find_user_droplet(api, droplet_name)
        if existing_droplet:
            console.print(f"[red]Error: A droplet named '{droplet_name}' already exists.[/red]")
            console.print("[dim]Destroy or rename the existing droplet first.[/dim]")
            raise typer.Exit(1)

        # Find the hibernated snapshot
        snapshot_name = get_snapshot_name(droplet_name)
        user_tag = get_user_tag(username)

        console.print(f"[dim]Looking for hibernated snapshot: [cyan]{snapshot_name}[/cyan][/dim]\n")
        snapshot = api.get_snapshot_by_name(snapshot_name, tag=user_tag)

        if not snapshot:
            console.print(f"[red]Error: No hibernated snapshot found for '{droplet_name}'[/red]")
            console.print(f"[dim]Expected snapshot name: {snapshot_name}[/dim]")
            raise typer.Exit(1)

        snapshot_id_str = snapshot.get("id")
        if not snapshot_id_str:
            console.print("[red]Error: Could not determine snapshot ID[/red]")
            raise typer.Exit(1)
        snapshot_id = int(snapshot_id_str)  # API returns string, convert to int

        # Get snapshot details
        size_gb = snapshot.get("size_gigabytes", 0)
        regions = snapshot.get("regions", [])
        original_region = regions[0] if regions else None

        # Get original size and check for tailscale-lockdown tag
        tags = snapshot.get("tags", [])
        original_size = None
        was_tailscale_locked = False
        for tag in tags:
            if tag.startswith("size:"):
                original_size = tag.removeprefix("size:")
            elif tag == "tailscale-lockdown":
                was_tailscale_locked = True

        if not original_region:
            console.print("[red]Error: Could not determine original region from snapshot[/red]")
            raise typer.Exit(1)

        if not original_size:
            console.print(
                "[yellow]⚠[/yellow] Could not determine original size from snapshot tags."
            )
            console.print("[dim]Using default size from config.[/dim]")
            original_size = config.defaults.size

        # Display snapshot info
        console.print(f"Found hibernated snapshot: [cyan]{snapshot_name}[/cyan] ({size_gb} GB)")
        console.print(
            f"Original config: [cyan]{original_region}[/cyan], [cyan]{original_size}[/cyan]"
        )
        console.print()

        # Create droplet from snapshot
        console.print(f"[dim]Creating droplet '{droplet_name}' from snapshot...[/dim]")

        # Build tags for new droplet
        tags_list = build_droplet_tags(username, list(config.defaults.extra_tags))

        droplet = api.create_droplet_from_snapshot(
            name=droplet_name,
            region=original_region,
            size=original_size,
            snapshot_id=snapshot_id,
            tags=tags_list,
            ssh_keys=config.cloudinit.ssh_key_ids,
        )

        droplet_id = droplet.get("id")
        if not droplet_id:
            console.print("[red]Error: Failed to get droplet ID from API response[/red]")
            raise typer.Exit(1)

        console.print(f"[green]✓[/green] Droplet created (ID: [cyan]{droplet_id}[/cyan])")

        # Wait for droplet to become active
        console.print("[dim]Waiting for droplet to become active...[/dim]")

        with console.status("[cyan]Waiting...[/cyan]"):
            active_droplet = api.wait_for_droplet_active(droplet_id)

        # Get IP address
        networks = active_droplet.get("networks", {})
        v4_networks = networks.get("v4", [])
        ip_address = None

        for network in v4_networks:
            if network.get("type") == "public":
                ip_address = network.get("ip_address")
                break

        if ip_address:
            console.print(f"[green]✓[/green] Droplet is active (IP: [cyan]{ip_address}[/cyan])")
        else:
            console.print("[green]✓[/green] Droplet is active")
            console.print("[yellow]⚠[/yellow] Could not determine IP address")

        # Add SSH config entry
        if ip_address and config.ssh.auto_update:
            try:
                console.print("[dim]Configuring SSH...[/dim]")
                ssh_hostname = get_ssh_hostname(droplet_name)
                add_ssh_host(
                    config_path=config.ssh.config_path,
                    host_name=ssh_hostname,
                    hostname=ip_address,
                    user=username,
                    identity_file=config.ssh.identity_file,
                )
                console.print("[green]✓[/green] SSH config updated")
            except Exception as e:
                console.print(f"[yellow]⚠[/yellow] Could not update SSH config: {e}")

        # Handle Tailscale re-setup if the original droplet had Tailscale lockdown
        if was_tailscale_locked and ip_address:
            ssh_hostname = get_ssh_hostname(droplet_name)
            if no_tailscale:
                console.print()
                console.print("[yellow]⚠[/yellow] Original droplet had Tailscale lockdown enabled.")
                console.print(
                    "[dim]Skipping Tailscale setup (--no-tailscale). "
                    "Public SSH access available.[/dim]"
                )
                console.print(
                    f"[dim]Enable Tailscale later with: "
                    f"[cyan]dropkit enable-tailscale {droplet_name}[/cyan][/dim]"
                )
            else:
                console.print()
                console.print(
                    "[dim]Original droplet had Tailscale lockdown - re-setting up Tailscale...[/dim]"
                )
                # Wait a bit for droplet to be fully ready for SSH
                console.print("[dim]Waiting for droplet to be ready for SSH...[/dim]")
                time.sleep(10)

                # Re-setup Tailscale (clean state from hibernate logout)
                tailscale_ip = setup_tailscale(ssh_hostname, username, config)

                if not tailscale_ip:
                    console.print(
                        "[yellow]⚠[/yellow] Tailscale setup incomplete. "
                        "Public SSH access remains available."
                    )
                    console.print(
                        f"[dim]Complete setup later with: "
                        f"[cyan]dropkit enable-tailscale {droplet_name}[/cyan][/dim]"
                    )

        # Prompt to delete snapshot
        console.print()
        delete_snapshot = Prompt.ask(
            f"[yellow]Delete snapshot '{snapshot_name}'?[/yellow]",
            choices=["yes", "no"],
            default="yes",
        )

        if delete_snapshot == "yes":
            api.delete_snapshot(snapshot_id)
            console.print("[green]✓[/green] Snapshot deleted")
        else:
            console.print("[dim]Snapshot kept[/dim]")

        # Summary
        console.print()
        console.print(f"[bold green]Droplet '{droplet_name}' is awake![/bold green]")
        if ip_address:
            ssh_hostname = get_ssh_hostname(droplet_name)
            console.print(f"Connect with: [cyan]ssh {ssh_hostname}[/cyan]")

    except DigitalOceanAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="enable-tailscale")
@requires_lock("enable-tailscale")
def enable_tailscale(
    droplet_name: str = typer.Argument(..., autocompletion=complete_droplet_name),
    no_lockdown: bool = typer.Option(
        False, "--no-lockdown", help="Don't lock down firewall to Tailscale only"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show debug output"),
):
    """
    Enable Tailscale VPN on an existing droplet.

    This command sets up Tailscale on a droplet that was created without it
    (using --no-tailscale) or on older droplets.

    The command will:
    1. Install Tailscale if not already installed
    2. Start Tailscale and display auth URL for browser login
    3. Update SSH config with Tailscale IP after authentication
    4. Lock down firewall to only allow Tailscale traffic (unless --no-lockdown)

    Only droplets tagged with owner:<your-username> can be modified.
    """
    try:
        # Load config and API
        config_manager, api = load_config_and_api()

        # Find the droplet
        console.print(f"[dim]Looking for droplet: [cyan]{droplet_name}[/cyan][/dim]\n")
        droplet, username = find_user_droplet(api, droplet_name)

        if not droplet:
            tag = get_user_tag(username)
            console.print(f"[red]Error: Droplet '{droplet_name}' not found with tag {tag}[/red]")
            raise typer.Exit(1)

        # Check droplet status
        status = droplet.get("status", "")
        if status != "active":
            console.print(
                f"[red]Error: Droplet must be active to enable Tailscale "
                f"(current status: {status})[/red]"
            )
            console.print("[dim]Use 'dropkit on' to power on the droplet first.[/dim]")
            raise typer.Exit(1)

        # Ensure SSH config exists for this droplet
        try:
            ssh_hostname = ensure_ssh_config(droplet, droplet_name, username, config_manager.config)
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)

        # Show panel
        console.print(
            Panel.fit(
                f"[bold cyan]ENABLE TAILSCALE: {droplet_name}[/bold cyan]",
                border_style="cyan",
            )
        )

        # Check if Tailscale is already installed
        console.print("[dim]Checking if Tailscale is installed...[/dim]")
        if check_tailscale_installed(ssh_hostname, verbose):
            console.print("[green]✓[/green] Tailscale is already installed")
        else:
            console.print("[dim]Installing Tailscale...[/dim]")
            with console.status("[cyan]Installing Tailscale (this may take a minute)...[/cyan]"):
                if not install_tailscale_on_droplet(ssh_hostname, verbose):
                    console.print("[red]Error: Failed to install Tailscale[/red]")
                    console.print(
                        f"[dim]Try manually: ssh {ssh_hostname} "
                        f"'curl -fsSL https://tailscale.com/install.sh | sudo sh'[/dim]"
                    )
                    raise typer.Exit(1)
            console.print("[green]✓[/green] Tailscale installed successfully")

        # Handle --no-lockdown by temporarily modifying config
        config = config_manager.config
        if no_lockdown:
            # Override lock_down_firewall setting
            config.tailscale.lock_down_firewall = False

        # Run the Tailscale setup flow
        tailscale_ip = setup_tailscale(
            ssh_hostname=ssh_hostname,
            username=username,
            config=config,
            verbose=verbose,
        )

        if tailscale_ip:
            console.print()
            console.print(f"[bold green]Tailscale enabled on {droplet_name}![/bold green]")
            console.print(f"Connect via: [cyan]ssh {ssh_hostname}[/cyan]")
        else:
            console.print()
            console.print(f"[yellow]Tailscale setup incomplete for {droplet_name}[/yellow]")
            console.print(
                f"[dim]You can complete setup later: ssh {ssh_hostname} 'sudo tailscale up'[/dim]"
            )

    except DigitalOceanAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="list-ssh-keys")
def list_ssh_keys_cmd():
    """List SSH keys registered via dropkit.

    Use 'dropkit add-ssh-key' to add or import additional SSH keys.
    """
    try:
        # Load config and API
        _, api = load_config_and_api()

        # Get username from DigitalOcean for filtering
        try:
            username = api.get_username()
        except DigitalOceanAPIError as e:
            console.print(f"[red]Error fetching username from DigitalOcean: {e}[/red]")
            raise typer.Exit(1)

        # Fetch all SSH keys
        console.print("[dim]Fetching SSH keys from DigitalOcean...[/dim]\n")
        all_keys = api.list_ssh_keys()

        # Filter keys registered via dropkit (prefixed with dropkit-{username}-)
        prefix = f"dropkit-{username}-"
        dropkit_keys = [key for key in all_keys if key.get("name", "").startswith(prefix)]

        if not dropkit_keys:
            console.print(
                f"[yellow]No SSH keys found registered via dropkit for user: {username}[/yellow]"
            )
            console.print("[dim]Keys are automatically registered during 'dropkit init'[/dim]")
            console.print(
                "[dim]Use 'dropkit add-ssh-key <path>' to add or import additional keys[/dim]"
            )
            return

        # Display keys in a table
        table = Table(title=f"SSH Keys for {username}", show_header=True)
        table.add_column("Name", style="cyan", no_wrap=True)
        table.add_column("ID", style="dim")
        table.add_column("Fingerprint", style="white")

        for key in dropkit_keys:
            table.add_row(
                key.get("name", "N/A"),
                str(key.get("id", "N/A")),
                key.get("fingerprint", "N/A"),
            )

        console.print(table)
        console.print(f"\n[dim]Total: {len(dropkit_keys)} key(s)[/dim]")

    except DigitalOceanAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="add-ssh-key")
@requires_lock("add-ssh-key")
def add_ssh_key_cmd(
    key_path: str = typer.Argument(..., help="Path to SSH public key file"),
):
    """Add or import an SSH public key to DigitalOcean.

    This command can:
    - Register a new SSH key with DigitalOcean
    - Import an existing key by renaming it to follow dropkit naming convention

    If the key already exists in DigitalOcean with a different name, you'll be
    prompted to rename it to the standard dropkit format.
    """
    try:
        # Load config and API
        _, api = load_config_and_api()

        # Get username from DigitalOcean for key naming
        try:
            username = api.get_username()
        except DigitalOceanAPIError as e:
            console.print(f"[red]Error fetching username from DigitalOcean: {e}[/red]")
            raise typer.Exit(1)

        # Expand path
        key_file = Path(key_path).expanduser()

        # Validate SSH key
        console.print(f"[dim]Validating SSH key: {key_file.name}...[/dim]")
        try:
            Config.validate_ssh_public_key(str(key_file))
        except FileNotFoundError as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)

        # Read key content
        key_content = Config.read_ssh_key_content(str(key_file))

        # Compute fingerprint
        try:
            fingerprint = Config.compute_ssh_key_fingerprint(key_content)
        except ValueError as e:
            console.print(f"[red]Error computing fingerprint: {e}[/red]")
            raise typer.Exit(1)

        console.print(f"[dim]Fingerprint: {fingerprint}[/dim]\n")

        # Check if key already exists by fingerprint
        existing_key = api.get_ssh_key_by_fingerprint(fingerprint)

        # Determine the desired key name
        fingerprint_prefix = fingerprint.replace(":", "")[:8]
        desired_key_name = f"dropkit-{username}-{fingerprint_prefix}"

        if existing_key:
            existing_name = existing_key.get("name", "")
            existing_id = existing_key.get("id")

            if not existing_id:
                console.print("[red]Error: SSH key ID not found in API response[/red]")
                raise typer.Exit(1)

            # Check if key already has the correct dropkit name
            if existing_name == desired_key_name:
                console.print("[yellow]⚠[/yellow] SSH key already registered with correct name:")
                console.print(f"  Name:        [cyan]{existing_name}[/cyan]")
                console.print(f"  ID:          [dim]{existing_id}[/dim]")
                console.print(f"  Fingerprint: {fingerprint}")
                return

            # Key exists but has different name - offer to rename
            console.print("[yellow]⚠[/yellow] SSH key already registered in DigitalOcean:")
            console.print(f"  Current name: [cyan]{existing_name}[/cyan]")
            console.print(f"  ID:           [dim]{existing_id}[/dim]")
            console.print(f"  Fingerprint:  {fingerprint}")
            console.print()
            console.print(f"  Suggested dropkit name: [cyan]{desired_key_name}[/cyan]")
            console.print()

            # Ask for confirmation to rename
            confirm = Confirm.ask(
                "Do you want to rename this key to follow dropkit naming convention?",
                default=True,
            )

            if not confirm:
                console.print("[dim]Key not renamed[/dim]")
                return

            # Rename the key
            console.print(f"\n[dim]Renaming SSH key to: {desired_key_name}...[/dim]")
            updated_key = api.update_ssh_key(existing_id, desired_key_name)

            console.print(
                f"[green]✓[/green] SSH key renamed successfully: [cyan]{desired_key_name}[/cyan]"
            )
            console.print(f"  ID:          [dim]{updated_key.get('id', 'N/A')}[/dim]")
            console.print(f"  Fingerprint: {updated_key.get('fingerprint', 'N/A')}")
            return

        # Register new key with format: dropkit-{username}-{fingerprint_prefix}
        console.print(f"[dim]Registering SSH key as: {desired_key_name}...[/dim]")
        new_key = api.add_ssh_key(desired_key_name, key_content)

        console.print(
            f"\n[green]✓[/green] SSH key registered successfully: [cyan]{desired_key_name}[/cyan]"
        )
        console.print(f"  ID:          [dim]{new_key.get('id', 'N/A')}[/dim]")
        console.print(f"  Fingerprint: {new_key.get('fingerprint', 'N/A')}")

    except DigitalOceanAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="delete-ssh-key")
@requires_lock("delete-ssh-key")
def delete_ssh_key_cmd(
    key_name: str = typer.Argument(..., help="SSH key name to delete"),
):
    """Delete an SSH key registered via dropkit."""
    try:
        # Load config and API
        _, api = load_config_and_api()

        # Get username from DigitalOcean for validation
        try:
            username = api.get_username()
        except DigitalOceanAPIError as e:
            console.print(f"[red]Error fetching username from DigitalOcean: {e}[/red]")
            raise typer.Exit(1)

        # Verify it's a dropkit key for this user
        prefix = f"dropkit-{username}-"

        if not key_name.startswith(prefix):
            console.print(f"[red]Error: Key '{key_name}' is not a dropkit-managed key[/red]")
            console.print(
                f"[dim]Only keys with prefix '{prefix}' can be deleted via this command[/dim]"
            )
            raise typer.Exit(1)

        # Fetch all SSH keys to find the one being deleted
        console.print("[dim]Fetching SSH key information...[/dim]\n")
        all_keys = api.list_ssh_keys()

        # Find the key by name
        target_key = None
        for key in all_keys:
            if key.get("name") == key_name:
                target_key = key
                break

        if not target_key:
            console.print(f"[red]Error: SSH key '{key_name}' not found[/red]")
            console.print("[dim]Run 'dropkit list-ssh-keys' to see available keys[/dim]")
            raise typer.Exit(1)

        # Display key information
        key_id = target_key.get("id")
        if not key_id:
            console.print("[red]Error: SSH key ID not found in API response[/red]")
            raise typer.Exit(1)

        console.print("[bold]SSH Key to delete:[/bold]")
        console.print(f"  Name:        [cyan]{key_name}[/cyan]")
        console.print(f"  ID:          [dim]{key_id}[/dim]")
        console.print(f"  Fingerprint: {target_key.get('fingerprint', 'N/A')}")

        # Ask for confirmation
        console.print()
        confirm = Confirm.ask(
            "[yellow]Are you sure you want to delete this SSH key?[/yellow]",
            default=False,
        )

        if not confirm:
            console.print("[dim]Deletion cancelled[/dim]")
            return

        # Delete the key
        console.print("\n[dim]Deleting SSH key...[/dim]")
        api.delete_ssh_key(key_id)

        console.print(f"[green]✓[/green] SSH key deleted successfully: [cyan]{key_name}[/cyan]")

    except DigitalOceanAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def version():
    """Show the version of dropkit."""
    from dropkit import __version__

    console.print(f"dropkit version [cyan]{__version__}[/cyan]")


def main():
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
