"""Main CLI application for tobcloud."""

import json
import shutil
import subprocess
import time
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from tobcloud.api import DigitalOceanAPI, DigitalOceanAPIError
from tobcloud.cloudinit import render_cloud_init
from tobcloud.config import Config
from tobcloud.ssh_config import add_ssh_host, host_exists, remove_ssh_host
from tobcloud.ui import display_images, display_regions, display_sizes, prompt_with_help

app = typer.Typer(
    name="tobcloud",
    help="Manage DigitalOcean droplets for ToB engineers",
)
console = Console()


# Helper functions


def load_config_and_api() -> tuple[Config, DigitalOceanAPI]:
    """
    Load configuration and create API client.

    Returns:
        Tuple of (Config instance, DigitalOceanAPI instance)

    Raises:
        typer.Exit: If config doesn't exist or fails to load
    """
    if not Config.exists():
        console.print("[red]Error: Config not found. Run 'tobcloud init' first.[/red]")
        raise typer.Exit(1)

    config_manager = Config()
    try:
        config_manager.load()
    except Exception as e:
        console.print(f"[red]Error loading config: {e}[/red]")
        console.print(
            "[yellow]Config file may be invalid. Try running[/yellow] [cyan]tobcloud init --force[/cyan]"
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
        SSH hostname with tobcloud prefix (e.g., "tobcloud.my-droplet")
    """
    return f"tobcloud.{droplet_name}"


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
                # Register new key with format: tobcloud-{username}-{fingerprint_prefix}
                # Use first 8 characters of fingerprint (without colons)
                fingerprint_prefix = fingerprint.replace(":", "")[:8]
                key_name = f"tobcloud-{username}-{fingerprint_prefix}"
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
        ssh_hostname: SSH hostname to connect to (e.g., "tobcloud.my-droplet")
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


def find_user_droplet(api: DigitalOceanAPI, droplet_name: str) -> tuple[dict | None, str | None]:
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

    return None, None


@app.command()
def init(
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite existing configuration",
    ),
) -> None:
    """
    Initialize tobcloud configuration.

    This will create a config directory at ~/.config/tobcloud/ and prompt
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
            "[bold cyan]tobcloud initialization[/bold cyan]\n\n"
            "This will set up your tobcloud configuration.",
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
    )
    config.save()

    console.print(f"\n[green]✓[/green] Saved configuration to [cyan]{Config.CONFIG_FILE}[/cyan]")

    # Copy cloud-init template
    template_src = Path(__file__).parent / "templates" / "default-cloud-init.yaml"
    template_dst = Config.CLOUD_INIT_FILE

    shutil.copy(template_src, template_dst)
    console.print(f"[green]✓[/green] Copied cloud-init template to [cyan]{template_dst}[/cyan]")

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
    table.add_row("SSH keys:", f"{len(ssh_keys)} key(s)")

    console.print(table)

    console.print("\n[bold]Next steps:[/bold]")
    console.print("  • Edit cloud-init template: [cyan]" + str(template_dst) + "[/cyan]")
    console.print("  • Create a droplet: [cyan]tobcloud create <name>[/cyan]")


@app.command()
def create(
    name: str = typer.Argument(..., help="Name for the droplet"),
    region: str | None = typer.Option(None, "--region", "-r", help="Region slug"),
    size: str | None = typer.Option(None, "--size", "-s", help="Droplet size slug"),
    image: str | None = typer.Option(None, "--image", "-i", help="Image slug"),
    tags: str | None = typer.Option(
        None, "--tags", "-t", help="Comma-separated tags (extends default tags)"
    ),
    user: str | None = typer.Option(None, "--user", "-u", help="Username to create"),
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
        console.print("[yellow]Run[/yellow] [cyan]tobcloud init[/cyan] [yellow]first[/yellow]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error loading config: {e}[/red]")
        console.print(
            "[yellow]Config file may be invalid. Try running[/yellow] [cyan]tobcloud init --force[/cyan]"
        )
        raise typer.Exit(1)

    # Get validated config
    config = config_manager.config

    # Get values from config or use provided values
    token = config.digitalocean.token

    # Create API client
    api = DigitalOceanAPI(token)

    region = region or config.defaults.region
    size = size or config.defaults.size
    image = image or config.defaults.image

    # Get username for droplet (use flag if provided, otherwise fetch from DO API)
    try:
        do_username = api.get_username()
    except DigitalOceanAPIError as e:
        console.print(f"[red]Error fetching username from DigitalOcean: {e}[/red]")
        raise typer.Exit(1)

    username = do_username if user is None else user
    if verbose:
        console.print(f"[dim][DEBUG] Username: {username}[/dim]")

    # Build tags list: mandatory tags + extra_tags from config + command-line tags
    extra_tags_list = list(config.defaults.extra_tags)  # Start with config tags

    if tags:
        additional_tags = [t.strip() for t in tags.split(",") if t.strip()]
        extra_tags_list.extend(additional_tags)

    tags_list = build_droplet_tags(do_username, extra_tags_list)

    if verbose:
        console.print(f"[dim][DEBUG] Using tags: {tags_list}[/dim]")

    # Get SSH keys
    ssh_keys = config.cloudinit.ssh_keys

    if verbose:
        console.print(f"[dim][DEBUG] SSH keys: {ssh_keys}[/dim]")

    # Get cloud-init template path
    template_path = config.cloudinit.template_path

    if verbose:
        console.print(f"[dim][DEBUG] Cloud-init template: {template_path}[/dim]")

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

    console.print(table)
    console.print()

    # Render cloud-init
    try:
        console.print("[dim]Rendering cloud-init template...[/dim]")
        user_data = render_cloud_init(template_path, username, ssh_keys)

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

        # Get IP address
        networks = active_droplet.get("networks", {})
        v4_networks = networks.get("v4", [])
        ip_address = None

        for network in v4_networks:
            if network.get("type") == "public":
                ip_address = network.get("ip_address")
                break

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

                    ssh_hostname = get_ssh_hostname(name)
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

        # Show summary based on cloud-init status
        console.print()
        if cloud_init_done:
            console.print("[bold green]Droplet created successfully![/bold green]")
            console.print("\n[bold]Droplet is fully ready! Connect with:[/bold]")
        elif cloud_init_error:
            console.print("[bold yellow]Droplet created with cloud-init errors[/bold yellow]")
            console.print(
                "\n[bold]The droplet is running but needs investigation. Connect with:[/bold]"
            )
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
def list_droplets():
    """List droplets tagged with owner:<username>."""
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

        console.print(f"[dim]Fetching droplets with tag: [cyan]{tag_name}[/cyan][/dim]\n")

        # List droplets
        droplets = api.list_droplets(tag_name=tag_name)

        if not droplets:
            console.print(f"[yellow]No droplets found with tag: {tag_name}[/yellow]")
            return

        # Create table
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Name", style="white", no_wrap=True)
        table.add_column("Status", style="white", no_wrap=True)
        table.add_column("IP Address", style="cyan", no_wrap=True)
        table.add_column("Region", style="white", no_wrap=True)
        table.add_column("Size", style="white", no_wrap=True)
        table.add_column("In SSH Config", style="white", no_wrap=True)

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
        console.print(f"\n[dim]Total: {len(droplets)} droplet(s)[/dim]")

    except DigitalOceanAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def config_ssh(
    droplet_name: str,
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

        if not droplet or not username:
            tag = get_user_tag(username) if username else "owner:<unknown>"
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
def info(droplet_name: str):
    """Show detailed information about a droplet."""
    try:
        # Load config and API
        config_manager, api = load_config_and_api()
        config = config_manager.config

        # Find the droplet
        console.print(f"[dim]Looking for droplet: [cyan]{droplet_name}[/cyan][/dim]\n")
        droplet, username = find_user_droplet(api, droplet_name)

        if not droplet or not username:
            tag = get_user_tag(username) if username else "owner:<unknown>"
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
            console.print(f"  [dim]Run: [cyan]tobcloud config-ssh {droplet_name}[/cyan][/dim]")

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
def destroy(droplet_name: str):
    """
    Destroy a droplet (DESTRUCTIVE - requires confirmation).

    This will permanently delete the droplet and remove its SSH config entry.
    Only droplets tagged with owner:<your-username> can be destroyed.
    """
    try:
        # Load config and API
        config_manager, api = load_config_and_api()
        config = config_manager.config

        # Find the droplet
        console.print(f"[dim]Looking for droplet: [cyan]{droplet_name}[/cyan][/dim]\n")
        droplet, username = find_user_droplet(api, droplet_name)

        if not droplet or not username:
            tag = get_user_tag(username) if username else "owner:<unknown>"
            console.print(f"[red]Error: Droplet '{droplet_name}' not found with tag {tag}[/red]")
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
        networks = droplet.get("networks", {})
        v4_networks = networks.get("v4", [])
        for network in v4_networks:
            if network.get("type") == "public":
                info_table.add_row("IP:", network.get("ip_address", "N/A"))
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

        # Proceed with deletion
        console.print()
        console.print("[dim]Deleting droplet...[/dim]")

        api.delete_droplet(droplet_id)
        console.print("[green]✓[/green] Droplet destroyed")

        # Remove SSH config entry
        ssh_hostname = get_ssh_hostname(droplet_name)
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

        console.print()
        console.print("[bold green]Droplet successfully destroyed[/bold green]")

    except DigitalOceanAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def resize(
    droplet_name: str,
    size: str | None = typer.Option(None, "--size", "-s", help="New size slug (e.g., s-4vcpu-8gb)"),
    disk: bool = typer.Option(
        True, "--disk/--no-disk", help="Resize disk (permanent, default: True)"
    ),
):
    """
    Resize a droplet (causes downtime - requires power off).

    This will change the droplet's vCPUs, memory, and optionally disk size.
    Only droplets tagged with owner:<your-username> can be resized.
    """
    try:
        # Load config and API
        _, api = load_config_and_api()

        # Find the droplet
        console.print(f"[dim]Looking for droplet: [cyan]{droplet_name}[/cyan][/dim]\n")
        droplet, username = find_user_droplet(api, droplet_name)

        if not droplet or not username:
            tag = get_user_tag(username) if username else "owner:<unknown>"
            console.print(f"[red]Error: Droplet '{droplet_name}' not found with tag {tag}[/red]")
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


@app.command(name="list-ssh-keys")
def list_ssh_keys_cmd():
    """List SSH keys registered via tobcloud.

    Use 'tobcloud add-ssh-key' to add or import additional SSH keys.
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

        # Filter keys registered via tobcloud (prefixed with tobcloud-{username}-)
        prefix = f"tobcloud-{username}-"
        tobcloud_keys = [key for key in all_keys if key.get("name", "").startswith(prefix)]

        if not tobcloud_keys:
            console.print(
                f"[yellow]No SSH keys found registered via tobcloud for user: {username}[/yellow]"
            )
            console.print("[dim]Keys are automatically registered during 'tobcloud init'[/dim]")
            console.print(
                "[dim]Use 'tobcloud add-ssh-key <path>' to add or import additional keys[/dim]"
            )
            return

        # Display keys in a table
        table = Table(title=f"SSH Keys for {username}", show_header=True)
        table.add_column("Name", style="cyan", no_wrap=True)
        table.add_column("ID", style="dim")
        table.add_column("Fingerprint", style="white")

        for key in tobcloud_keys:
            table.add_row(
                key.get("name", "N/A"),
                str(key.get("id", "N/A")),
                key.get("fingerprint", "N/A"),
            )

        console.print(table)
        console.print(f"\n[dim]Total: {len(tobcloud_keys)} key(s)[/dim]")

    except DigitalOceanAPIError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command(name="add-ssh-key")
def add_ssh_key_cmd(
    key_path: str = typer.Argument(..., help="Path to SSH public key file"),
):
    """Add or import an SSH public key to DigitalOcean.

    This command can:
    - Register a new SSH key with DigitalOcean
    - Import an existing key by renaming it to follow tobcloud naming convention

    If the key already exists in DigitalOcean with a different name, you'll be
    prompted to rename it to the standard tobcloud format.
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
        desired_key_name = f"tobcloud-{username}-{fingerprint_prefix}"

        if existing_key:
            existing_name = existing_key.get("name", "")
            existing_id = existing_key.get("id")

            if not existing_id:
                console.print("[red]Error: SSH key ID not found in API response[/red]")
                raise typer.Exit(1)

            # Check if key already has the correct tobcloud name
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
            console.print(f"  Suggested tobcloud name: [cyan]{desired_key_name}[/cyan]")
            console.print()

            # Ask for confirmation to rename
            confirm = Confirm.ask(
                "Do you want to rename this key to follow tobcloud naming convention?",
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

        # Register new key with format: tobcloud-{username}-{fingerprint_prefix}
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
def delete_ssh_key_cmd(
    key_name: str = typer.Argument(..., help="SSH key name to delete"),
):
    """Delete an SSH key registered via tobcloud."""
    try:
        # Load config and API
        _, api = load_config_and_api()

        # Get username from DigitalOcean for validation
        try:
            username = api.get_username()
        except DigitalOceanAPIError as e:
            console.print(f"[red]Error fetching username from DigitalOcean: {e}[/red]")
            raise typer.Exit(1)

        # Verify it's a tobcloud key for this user
        prefix = f"tobcloud-{username}-"

        if not key_name.startswith(prefix):
            console.print(f"[red]Error: Key '{key_name}' is not a tobcloud-managed key[/red]")
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
            console.print("[dim]Run 'tobcloud list-ssh-keys' to see available keys[/dim]")
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


def main():
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
