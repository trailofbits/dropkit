"""SSH config file management."""

import shutil
import subprocess
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

    # Ensure existing content ends with newline before appending
    if existing_content and not existing_content.endswith("\n"):
        existing_content += "\n"

    # Append new entry
    new_content = existing_content + host_entry + "\n"

    # Write back to file
    with open(config_file, "w") as f:
        f.write(new_content)

    # Set restrictive permissions
    config_file.chmod(0o600)


def get_ssh_host_ip(config_path: str, host_name: str) -> str | None:
    """
    Get the HostName (IP address) for an SSH host entry.

    Args:
        config_path: Path to SSH config file
        host_name: Host alias to look up

    Returns:
        IP address/hostname if found, None otherwise
    """
    config_file = Path(config_path).expanduser()

    if not config_file.exists():
        return None

    with open(config_file) as f:
        lines = f.readlines()

    in_target_host = False
    for line in lines:
        stripped = line.strip()

        # Check for Host directive
        if stripped.startswith("Host "):
            # Extract host name (handle multiple hosts on same line)
            host_part = stripped[5:].strip()
            hosts = host_part.split()
            in_target_host = host_name in hosts
        elif in_target_host and stripped.startswith("HostName "):
            # Found HostName in target host block
            return stripped[9:].strip()
        elif in_target_host and stripped and not stripped.startswith((" ", "\t", "#")):
            # Left the host block (non-indented, non-comment line)
            # This handles case where there's no HostName
            if not line.startswith((" ", "\t")):
                in_target_host = False

    return None


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


def remove_known_hosts_entry(known_hosts_path: str, hostnames: list[str]) -> int:
    """
    Remove entries for specified hostnames from known_hosts file.

    Uses ssh-keygen -R which properly handles hashed entries.

    Args:
        known_hosts_path: Path to known_hosts file (e.g., ~/.ssh/known_hosts)
        hostnames: List of hostnames/IPs to remove

    Returns:
        Number of hostnames for which entries were removed
    """
    known_hosts_file = Path(known_hosts_path).expanduser()

    if not known_hosts_file.exists():
        return 0

    removed_count = 0

    for hostname in hostnames:
        result = subprocess.run(
            ["ssh-keygen", "-R", hostname, "-f", str(known_hosts_file)],
            capture_output=True,
            text=True,
        )
        # ssh-keygen -R returns 0 even if hostname not found
        # When it removes an entry, it prints to stdout:
        # "# Host <hostname> found: line N"
        # "<file> updated."
        # "Original contents retained as <file>.old"
        if "updated" in result.stdout:
            removed_count += 1

    return removed_count
