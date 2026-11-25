"""Cloud-init template rendering."""

from pathlib import Path

from jinja2 import Template

from dropkit.config import Config


def render_cloud_init(
    template_path: str,
    username: str,
    full_name: str,
    email: str,
    ssh_keys: list[str],
    tailscale_enabled: bool = True,
) -> str:
    """
    Render cloud-init template with user data.

    Args:
        template_path: Path to the cloud-init template file
        username: Username to create in the droplet
        full_name: Full name extracted from email (for git user.name)
        email: Email address from DigitalOcean account (for git user.email)
        ssh_keys: List of SSH public key file paths or inline agent keys
        tailscale_enabled: Whether to install Tailscale VPN (default: True)

    Returns:
        Rendered cloud-init configuration as string
    """
    # Read template
    template_file = Path(template_path).expanduser()
    if not template_file.exists():
        raise FileNotFoundError(f"Cloud-init template not found: {template_path}")

    with open(template_file) as f:
        template_content = f.read()

    # Render the same contents that passed validation, without reopening key files.
    ssh_key_contents = [Config.validate_ssh_public_key(key_path) for key_path in ssh_keys]

    # Render template with Jinja2
    template = Template(template_content)
    rendered = template.render(
        username=username,
        full_name=full_name,
        email=email,
        ssh_keys=ssh_key_contents,
        tailscale_enabled=tailscale_enabled,
    )

    return rendered
