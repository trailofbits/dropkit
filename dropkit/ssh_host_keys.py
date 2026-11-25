"""Persistent OpenSSH host keys for Dropkit-managed connections."""

import subprocess
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile

HOST_KEY_ALIAS = "dropkit-instance"


def known_hosts_path(config_path: str, droplet_id: int | str) -> Path:
    return _pin_path(config_path, "droplet", droplet_id)


def snapshot_known_hosts_path(config_path: str, snapshot_id: int | str) -> Path:
    return _pin_path(config_path, "snapshot", snapshot_id)


def _pin_path(config_path: str, kind: str, resource_id: int | str) -> Path:
    resource_id = str(resource_id)
    if not resource_id.isascii() or not resource_id.isdecimal() or int(resource_id) <= 0:
        raise ValueError(f"Invalid DigitalOcean {kind} ID")
    return (
        Path(config_path).expanduser().absolute().parent
        / "dropkit_known_hosts"
        / (f"{kind}-{int(resource_id)}")
    )


def host_key_options(path: Path, *, enroll: bool = False) -> dict[str, str]:
    # OpenSSH expands '%' tokens and environment variables in known_hosts paths.
    path_value = str(path).replace("%", "%%")
    if any(char in path_value for char in '"\\\n\r') or "${" in path_value:
        raise ValueError("Unsupported character in Dropkit known_hosts path")
    return {
        "StrictHostKeyChecking": "accept-new" if enroll else "yes",
        "HostKeyAlias": HOST_KEY_ALIAS,
        "UserKnownHostsFile": f'"{path_value}"',
        "GlobalKnownHostsFile": "none",
        "KnownHostsCommand": "none",
        "VerifyHostKeyDNS": "no",
        "CheckHostIP": "no",
        "UpdateHostKeys": "no",
        "ControlPath": "none",
    }


def has_host_key(path: Path) -> bool:
    try:
        return path.stat().st_size > 0
    except FileNotFoundError:
        return False


def _write_pin(path: Path, contents: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
        pending = Path(temporary.name)
        try:
            temporary.write(contents)
            temporary.close()
            pending.replace(path)
        finally:
            pending.unlink(missing_ok=True)


def copy_host_key(source: Path, destination: Path) -> None:
    """Carry an existing pin across snapshot/restore without replacing a pin."""
    if has_host_key(source) and not has_host_key(destination):
        _write_pin(destination, source.read_bytes())


def import_host_key(source: Path, destination: Path) -> None:
    """Install a public host key that the operator verified independently."""
    contents = source.expanduser().read_text().strip()
    parts = contents.split()
    if (
        len(parts) < 2
        or not parts[0].startswith(("ssh-", "ecdsa-"))
        or len(contents.splitlines()) != 1
    ):
        raise ValueError("Expected a single SSH public host key")
    key = " ".join(parts[:2])
    result = subprocess.run(
        ["ssh-keygen", "-l", "-f", "-"], input=key + "\n", text=True, capture_output=True, timeout=5
    )
    if result.returncode != 0:
        raise ValueError("Invalid SSH public host key")
    _write_pin(destination, f"{HOST_KEY_ALIAS} {key}\n".encode())


@dataclass(frozen=True)
class SSHConnection:
    """A droplet's stable SSH identity and its current network route."""

    hostname: str
    config_path: str
    droplet_id: int | str
    address: str | None = None
    user: str | None = None
    identity_file: str | None = None

    @property
    def known_hosts(self) -> Path:
        return known_hosts_path(self.config_path, self.droplet_id)

    def command(self, command: str, connect_timeout: int) -> list[str]:
        return [*self._options(connect_timeout), "--", self.hostname, command]

    def enroll(self) -> None:
        """Record the first key for a fresh droplet without running a command."""
        if has_host_key(self.known_hosts):
            return
        self.known_hosts.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # User authentication is expected to fail. OpenSSH saves the host key
        # during key exchange, before authentication. The next SSH is strict.
        subprocess.run(
            [
                *self._options(5, enroll=True),
                "-o",
                "PreferredAuthentications=none",
                "-N",
                "--",
                self.hostname,
            ],
            capture_output=True,
            timeout=10,
        )

    def _options(self, connect_timeout: int, *, enroll: bool = False) -> list[str]:
        config = Path(self.config_path).expanduser()
        argv = ["ssh"]
        if config.absolute() != Path.home() / ".ssh" / "config":
            argv.extend(["-F", str(config) if config.is_file() else "none"])
        options = {
            **host_key_options(self.known_hosts, enroll=enroll),
            "BatchMode": "yes",
            "ForwardAgent": "no",
            "ClearAllForwardings": "yes",
            "PermitLocalCommand": "no",
            "RequestTTY": "no",
            "RemoteCommand": "none",
            "ConnectTimeout": str(connect_timeout),
        }
        if self.address is not None:
            options["HostName"] = self.address
        for name, value in options.items():
            argv.extend(["-o", f"{name}={value}"])
        if self.user is not None:
            argv.extend(["-l", self.user])
        if self.identity_file is not None:
            argv.extend(["-i", str(Path(self.identity_file).expanduser())])
        return argv
