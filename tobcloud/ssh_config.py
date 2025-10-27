"""SSH config file management."""

import shutil
from pathlib import Path


def _backup_config(config_file: Path) -> None:
    """
    Create a backup of the SSH config file.

    Args:
        config_file: Path to the SSH config file
    """
    if not config_file.exists():
        return

    backup_file = config_file.parent / f"{config_file.name}.bak"

    # Copy file
    shutil.copy2(config_file, backup_file)

    # Ensure backup has same permissions as original
    original_mode = config_file.stat().st_mode
    backup_file.chmod(original_mode)


def add_ssh_host(
    config_path: str,
    host_name: str,
    hostname: str,
    user: str,
    identity_file: str | None = None,
) -> None:
    """
    Add or update an SSH host entry in the SSH config file.

    Args:
        config_path: Path to SSH config file (e.g., ~/.ssh/config)
        host_name: Host alias to use (e.g., 'my-droplet')
        hostname: IP address or hostname
        user: SSH username
        identity_file: Path to SSH private key (optional)
    """
    config_file = Path(config_path).expanduser()

    # Create SSH directory if it doesn't exist
    config_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    # Backup existing config before modifying
    _backup_config(config_file)

    # Read existing config
    if config_file.exists():
        with open(config_file) as f:
            existing_content = f.read()
    else:
        existing_content = ""

    # Check if host already exists
    if f"Host {host_name}" in existing_content:
        # Host exists, update it
        lines = existing_content.split("\n")
        new_lines = []
        skip_until_next_host = False

        for line in lines:
            if line.startswith("Host "):
                if line == f"Host {host_name}":
                    # Found our host, skip this block
                    skip_until_next_host = True
                else:
                    # Different host
                    skip_until_next_host = False
                    new_lines.append(line)
            elif skip_until_next_host:
                # Skip lines in the old host block
                continue
            else:
                new_lines.append(line)

        existing_content = "\n".join(new_lines).rstrip() + "\n\n"

    # Create new host entry
    host_entry = f"Host {host_name}\n"
    host_entry += f"    HostName {hostname}\n"
    host_entry += "    ForwardAgent yes\n"
    host_entry += f"    User {user}\n"

    if identity_file:
        host_entry += f"    IdentityFile {identity_file}\n"

    # Append new entry
    new_content = existing_content + host_entry + "\n"

    # Write back to file
    with open(config_file, "w") as f:
        f.write(new_content)

    # Set restrictive permissions
    config_file.chmod(0o600)


def host_exists(config_path: str, host_name: str) -> bool:
    """
    Check if an SSH host entry exists in the SSH config file.

    Args:
        config_path: Path to SSH config file
        host_name: Host alias to check

    Returns:
        True if host exists, False otherwise
    """
    config_file = Path(config_path).expanduser()

    if not config_file.exists():
        return False

    with open(config_file) as f:
        content = f.read()

    return f"Host {host_name}" in content


def remove_ssh_host(config_path: str, host_name: str) -> bool:
    """
    Remove an SSH host entry from the SSH config file.

    Args:
        config_path: Path to SSH config file
        host_name: Host alias to remove

    Returns:
        True if host was found and removed, False otherwise
    """
    config_file = Path(config_path).expanduser()

    if not config_file.exists():
        return False

    # Backup existing config before modifying
    _backup_config(config_file)

    # Read existing config
    with open(config_file) as f:
        lines = f.readlines()

    # Find and remove the host block
    new_lines = []
    skip_until_next_host = False
    found = False

    for line in lines:
        if line.strip().startswith("Host "):
            if line.strip() == f"Host {host_name}":
                # Found our host, skip this block
                skip_until_next_host = True
                found = True
            else:
                # Different host
                skip_until_next_host = False
                new_lines.append(line)
        elif skip_until_next_host:
            # Skip lines in the host block (indented lines)
            if line.strip() and not line.startswith((" ", "\t")):
                # This is not an indented line, so we're past the block
                skip_until_next_host = False
                new_lines.append(line)
        else:
            new_lines.append(line)

    if found:
        # Write back to file
        with open(config_file, "w") as f:
            f.writelines(new_lines)

    return found
