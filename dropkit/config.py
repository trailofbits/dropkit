"""Configuration management for dropkit."""

import os
import subprocess
from pathlib import Path
from tempfile import NamedTemporaryFile

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

# Default slugs for droplet creation
DEFAULT_REGION = "nyc3"
DEFAULT_SIZE = "s-2vcpu-4gb"
DEFAULT_IMAGE = "ubuntu-26-04-x64"


class DigitalOceanConfig(BaseModel):
    """DigitalOcean API configuration."""

    token: str = Field(..., min_length=1, description="DigitalOcean API token")
    api_base: str = Field(default="https://api.digitalocean.com/v2", description="API base URL")

    @field_validator("token")
    @classmethod
    def token_not_empty(cls, v: str) -> str:
        """Validate token is not empty or whitespace."""
        if not v or not v.strip():
            raise ValueError("Token cannot be empty")
        return v.strip()


class DefaultsConfig(BaseModel):
    """Default settings for droplet creation."""

    region: str = Field(..., min_length=1, description="Default region slug")
    size: str = Field(..., min_length=1, description="Default droplet size slug")
    image: str = Field(..., min_length=1, description="Default image slug")
    extra_tags: list[str] = Field(
        default_factory=list,
        description="Extra tags (in addition to mandatory owner:<username> and firewall tags)",
    )
    project_id: str | None = Field(
        default=None,
        description="Default project ID (UUID) for new droplets",
    )


class CloudInitConfig(BaseModel):
    """Cloud-init configuration."""

    template_path: str | None = Field(
        default=None, description="Path to cloud-init template (None = use package default)"
    )
    ssh_keys: list[str] = Field(..., min_length=1, description="SSH public key paths")
    ssh_key_ids: list[int] = Field(
        ..., min_length=1, description="DigitalOcean SSH key IDs for root access"
    )

    @field_validator("ssh_keys")
    @classmethod
    def ssh_keys_not_empty(cls, v: list[str]) -> list[str]:
        """Validate at least one SSH key is provided."""
        if not v:
            raise ValueError("At least one SSH key must be configured")
        return v

    @field_validator("ssh_key_ids")
    @classmethod
    def ssh_key_ids_not_empty(cls, v: list[int]) -> list[int]:
        """Validate at least one SSH key ID is provided."""
        if not v:
            raise ValueError("At least one SSH key ID must be configured")
        return v


class SSHConfig(BaseModel):
    """SSH configuration."""

    config_path: str = Field(..., description="Path to SSH config file")
    auto_update: bool = Field(default=True, description="Auto-update SSH config")
    identity_file: str = Field(..., description="SSH identity file path")


class TailscaleConfig(BaseModel):
    """Tailscale VPN configuration."""

    enabled: bool = Field(default=True, description="Enable Tailscale by default for new droplets")
    lock_down_firewall: bool = Field(
        default=True, description="Reset UFW to only allow traffic on tailscale0 interface"
    )
    auth_timeout: int = Field(
        default=300, ge=30, description="Timeout in seconds for Tailscale authentication (min: 30)"
    )


class DropkitConfig(BaseModel):
    """Main dropkit configuration."""

    model_config = ConfigDict(extra="forbid")

    digitalocean: DigitalOceanConfig
    defaults: DefaultsConfig
    cloudinit: CloudInitConfig
    ssh: SSHConfig
    tailscale: TailscaleConfig = Field(default_factory=TailscaleConfig)


class Config:
    """Manages dropkit configuration with Pydantic validation."""

    CONFIG_DIR = Path.home() / ".config" / "dropkit"
    CONFIG_FILE = CONFIG_DIR / "config.yaml"
    CLOUD_INIT_FILE = CONFIG_DIR / "cloud-init.yaml"

    def __init__(self):
        """Initialize config manager."""
        self._config: DropkitConfig | None = None

    @property
    def config(self) -> DropkitConfig:
        """Get the validated configuration."""
        if self._config is None:
            raise ValueError("Configuration not loaded. Call load() first.")
        return self._config

    @classmethod
    def exists(cls) -> bool:
        """Check if config file exists."""
        return cls.CONFIG_FILE.exists()

    @classmethod
    def get_config_dir(cls) -> Path:
        """Get the config directory path."""
        return cls.CONFIG_DIR

    @staticmethod
    def get_default_template_path() -> Path:
        """Get the default cloud-init template path from package."""
        return Path(__file__).parent / "templates" / "default-cloud-init.yaml"

    @classmethod
    def ensure_config_dir(cls) -> None:
        """Create config directory if it doesn't exist."""
        cls.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        # Set restrictive permissions on config directory
        cls.CONFIG_DIR.chmod(0o700)

    def load(self) -> None:
        """Load and validate configuration from file."""
        if not self.CONFIG_FILE.exists():
            raise FileNotFoundError(
                f"Config file not found at {self.CONFIG_FILE}. Run 'dropkit init' first."
            )

        with open(self.CONFIG_FILE) as f:
            data = yaml.safe_load(f) or {}

        # Validate with Pydantic
        self._config = DropkitConfig(**data)

    def save(self) -> None:
        """Save configuration to file."""
        if self._config is None:
            raise ValueError("No configuration to save")

        self.ensure_config_dir()

        # Convert Pydantic model to dict for YAML serialization
        data = self._config.model_dump(mode="python")

        with open(self.CONFIG_FILE, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

        # Set restrictive permissions on config file (contains API token)
        self.CONFIG_FILE.chmod(0o600)

    @staticmethod
    def get_system_username() -> str:
        """
        Get current system username from environment.

        This is used for tagging droplets (owner:<username>) to track
        who created them.

        Returns:
            Current system username from $USER environment variable
        """
        return os.environ.get("USER", "user")

    @staticmethod
    def detect_ssh_keys() -> list[str]:
        """Auto-detect all SSH public keys (*.pub) in ~/.ssh/."""
        ssh_dir = Path.home() / ".ssh"
        if not ssh_dir.exists():
            return []

        # Find all .pub files in the SSH directory
        found_keys = [str(key_path) for key_path in ssh_dir.glob("*.pub")]

        # Sort by modification time (most recently modified first)
        found_keys.sort(key=lambda p: Path(p).stat().st_mtime, reverse=True)

        return found_keys

    @staticmethod
    def _get_ssh_agent_sock() -> str | None:
        """Resolve the SSH agent socket path.

        Checks in order:
        1. ``IdentityAgent`` from SSH config (via ``ssh -G localhost``) — this is
           how 1Password configures its agent.
        2. ``SSH_AUTH_SOCK`` environment variable.
        """
        # 1. Resolve IdentityAgent from SSH config
        try:
            result = subprocess.run(
                ["ssh", "-G", "localhost"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )
            for line in result.stdout.splitlines():
                key, _, value = line.partition(" ")
                if key == "identityagent" and value == "none":
                    return None
                if key == "identityagent" and value:
                    sock = Path(value).expanduser()
                    if sock.exists():
                        return str(sock)
        except (
            FileNotFoundError,
            subprocess.TimeoutExpired,
            subprocess.CalledProcessError,
            OSError,
        ):
            pass

        # 2. Fall back to SSH_AUTH_SOCK env var
        ssh_sock = os.environ.get("SSH_AUTH_SOCK")
        if ssh_sock and Path(ssh_sock).exists():
            return ssh_sock

        return None

    @staticmethod
    def detect_ssh_agent_keys() -> list[str]:
        """Detect SSH public keys available from the ssh-agent (e.g. 1Password).

        Resolves the agent socket (``IdentityAgent`` in SSH config or
        ``SSH_AUTH_SOCK``), runs ``ssh-add -L``, and returns public key strings
        that are not already present as ``.pub`` files in ``~/.ssh/``.

        Returns:
            List of inline public key strings from the agent (deduplicated
            against on-disk keys).
        """
        agent_sock = Config._get_ssh_agent_sock()
        if not agent_sock:
            return []

        env = {**os.environ, "SSH_AUTH_SOCK": agent_sock}
        try:
            result = subprocess.run(
                ["ssh-add", "-L"],
                capture_output=True,
                text=True,
                timeout=5,
                env=env,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

        if result.returncode != 0 or not result.stdout.strip():
            return []

        # Collect on-disk key contents for deduplication
        disk_key_contents: set[str] = set()
        ssh_dir = Path.home() / ".ssh"
        if ssh_dir.exists():
            for pub_file in ssh_dir.glob("*.pub"):
                try:
                    content = pub_file.read_text().strip()
                    # Normalize: compare only key-type + key-data (ignore comment)
                    parts = content.split()
                    if len(parts) >= 2:
                        disk_key_contents.add(f"{parts[0]} {parts[1]}")
                except OSError:
                    continue

        agent_keys: list[str] = []
        for raw_line in result.stdout.strip().splitlines():
            line = raw_line.strip()
            parts = line.split()
            if len(parts) >= 2 and f"{parts[0]} {parts[1]}" not in disk_key_contents:
                agent_keys.append(line)

        return agent_keys

    @staticmethod
    def validate_ssh_public_key(key_path_or_content: str) -> None:
        """
        Validate that a value is a valid SSH public key.

        Accepts either a file path to a ``.pub`` file or inline public key
        content (e.g. from the ssh-agent).

        Args:
            key_path_or_content: Path to SSH key file, or inline key content

        Raises:
            ValueError: If the key is not a valid SSH public key
            FileNotFoundError: If a file path is given and the file doesn't exist
        """
        path = Path(key_path_or_content).expanduser()

        try:
            is_file = path.is_file()
        except OSError:
            is_file = False

        if is_file:
            if not path.name.endswith(".pub"):
                raise ValueError(
                    f"SSH key file must be a public key (*.pub): {key_path_or_content}\n"
                    f"Private keys should NEVER be uploaded to DigitalOcean."
                )

            try:
                with open(path) as f:
                    content = f.read().strip()
            except OSError as e:
                raise ValueError(f"Cannot read SSH key file: {e}")
        else:
            if len(key_path_or_content.split()) < 2:
                raise FileNotFoundError(f"SSH key not found: {key_path_or_content}")
            content = key_path_or_content.strip()

        if not content:
            raise ValueError(f"SSH key file is empty: {key_path_or_content}")

        Config.compute_ssh_key_fingerprint(content)

    @staticmethod
    def read_ssh_key_content(key_path_or_content: str) -> str:
        """Read SSH public key content.

        Accepts a file path or inline key content (from ssh-agent).
        """
        path = Path(key_path_or_content).expanduser()
        try:
            if path.is_file():
                with open(path) as f:
                    return f.read().strip()
        except OSError:
            pass

        if len(key_path_or_content.split()) >= 2:
            return key_path_or_content

        raise FileNotFoundError(f"SSH key not found: {key_path_or_content}")

    @staticmethod
    def compute_ssh_key_fingerprint(public_key: str) -> str:
        """
        Compute MD5 fingerprint of an SSH public key.

        Args:
            public_key: SSH public key content

        Returns:
            MD5 fingerprint in format: aa:bb:cc:dd:...

        Raises:
            ValueError: If key format is invalid
        """
        content = public_key.strip()
        # ssh-keygen also accepts private keys and files containing multiple keys.
        # Only pass it a single public-key line intended for upload/cloud-init.
        if len(content.splitlines()) != 1 or content.startswith("-----BEGIN "):
            raise ValueError("Value does not appear to be a valid SSH public key")

        try:
            with NamedTemporaryFile(mode="w", suffix=".pub") as key_file:
                key_file.write(content + "\n")
                key_file.flush()
                result = subprocess.run(
                    ["ssh-keygen", "-l", "-E", "md5", "-f", key_file.name],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=5,
                )
        except FileNotFoundError:
            raise ValueError("OpenSSH ssh-keygen is required to validate SSH public keys")
        except subprocess.TimeoutExpired:
            raise ValueError("Timed out validating SSH public key with ssh-keygen")
        except subprocess.CalledProcessError:
            raise ValueError("Value does not appear to be a valid SSH public key")
        except OSError as e:
            raise ValueError(f"Cannot validate SSH public key: {e}")

        fields = result.stdout.split()
        if len(fields) < 2 or not fields[1].startswith("MD5:"):
            raise ValueError("ssh-keygen did not return an MD5 fingerprint")
        return fields[1].removeprefix("MD5:")

    def create_default_config(
        self,
        token: str,
        username: str,  # noqa: ARG002 - kept for API compatibility, username derived from DO API
        region: str = DEFAULT_REGION,
        size: str = DEFAULT_SIZE,
        image: str = DEFAULT_IMAGE,
        ssh_keys: list[str] | None = None,
        ssh_key_ids: list[int] | None = None,
        extra_tags: list[str] | None = None,
        project_id: str | None = None,
    ) -> None:
        """Create a default configuration with validation.

        Note: The mandatory tags owner:<username> and firewall are NOT stored in config.
        They are always added at runtime when creating droplets.
        """
        if ssh_keys is None:
            ssh_keys = self.detect_ssh_keys()

        if not ssh_keys:
            raise ValueError("No SSH keys found. Please specify SSH key paths.")

        if ssh_key_ids is None:
            raise ValueError("SSH key IDs must be provided from DigitalOcean.")

        # Store only extra tags (mandatory tags added at runtime)
        if extra_tags is None:
            extra_tags = []

        identity_file = None
        for key in ssh_keys:
            try:
                public_key_path = Path(key).expanduser()
                if public_key_path.is_file():
                    private_key_path = public_key_path.with_suffix("")
                    identity_file = str(
                        private_key_path if private_key_path.is_file() else public_key_path
                    )
                    break
            except OSError:
                pass
            if len(key.split()) < 2:
                identity_file = str(Path(key).expanduser()).removesuffix(".pub")
                break

        if identity_file is None:
            # OpenSSH can select a key in an agent using a local public IdentityFile.
            public_key = ssh_keys[0].strip()
            fingerprint = self.compute_ssh_key_fingerprint(public_key).replace(":", "")
            self.ensure_config_dir()
            key_dir = self.CONFIG_DIR / "ssh"
            key_dir.mkdir(mode=0o700, exist_ok=True)
            public_key_path = key_dir / f"agent-{fingerprint}.pub"
            public_key_path.write_text(public_key + "\n")
            public_key_path.chmod(0o600)
            identity_file = str(public_key_path)

        # Create validated Pydantic model
        self._config = DropkitConfig(
            digitalocean=DigitalOceanConfig(
                token=token,
                api_base="https://api.digitalocean.com/v2",
            ),
            defaults=DefaultsConfig(
                region=region,
                size=size,
                image=image,
                extra_tags=extra_tags,
                project_id=project_id,
            ),
            cloudinit=CloudInitConfig(
                ssh_keys=ssh_keys,
                ssh_key_ids=ssh_key_ids,
            ),
            ssh=SSHConfig(
                config_path=str(Path.home() / ".ssh" / "config"),
                auto_update=True,
                identity_file=identity_file,
            ),
        )
