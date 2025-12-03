"""Configuration management for tobcloud."""

import base64
import hashlib
import os
from pathlib import Path

import yaml
from cryptography.hazmat.primitives import serialization
from pydantic import BaseModel, ConfigDict, Field, field_validator


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


class TobcloudConfig(BaseModel):
    """Main tobcloud configuration."""

    model_config = ConfigDict(extra="forbid")

    digitalocean: DigitalOceanConfig
    defaults: DefaultsConfig
    cloudinit: CloudInitConfig
    ssh: SSHConfig
    tailscale: TailscaleConfig = Field(default_factory=TailscaleConfig)


class Config:
    """Manages tobcloud configuration with Pydantic validation."""

    CONFIG_DIR = Path.home() / ".config" / "tobcloud"
    CONFIG_FILE = CONFIG_DIR / "config.yaml"
    CLOUD_INIT_FILE = CONFIG_DIR / "cloud-init.yaml"

    def __init__(self):
        """Initialize config manager."""
        self._config: TobcloudConfig | None = None

    @property
    def config(self) -> TobcloudConfig:
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
                f"Config file not found at {self.CONFIG_FILE}. Run 'tobcloud init' first."
            )

        with open(self.CONFIG_FILE) as f:
            data = yaml.safe_load(f) or {}

        # Validate with Pydantic
        self._config = TobcloudConfig(**data)

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
    def validate_ssh_public_key(key_path: str) -> None:
        """
        Validate that a file is a valid SSH public key.

        Args:
            key_path: Path to the SSH key file

        Raises:
            ValueError: If the file is not a valid SSH public key
            FileNotFoundError: If the file doesn't exist
        """
        path = Path(key_path).expanduser()

        if not path.exists():
            raise FileNotFoundError(f"SSH key not found: {key_path}")

        # Check if filename ends with .pub
        if not path.name.endswith(".pub"):
            raise ValueError(
                f"SSH key file must be a public key (*.pub): {key_path}\n"
                f"Private keys should NEVER be uploaded to DigitalOcean."
            )

        # Read and validate content
        try:
            with open(path) as f:
                content = f.read().strip()
        except Exception as e:
            raise ValueError(f"Cannot read SSH key file: {e}")

        if not content:
            raise ValueError(f"SSH key file is empty: {key_path}")

        # Valid public key prefixes
        valid_prefixes = (
            "ssh-rsa ",
            "ssh-ed25519 ",
            "ecdsa-sha2-nistp256 ",
            "ecdsa-sha2-nistp384 ",
            "ecdsa-sha2-nistp521 ",
            "sk-ssh-ed25519@openssh.com ",
            "sk-ecdsa-sha2-nistp256@openssh.com ",
        )

        if not content.startswith(valid_prefixes):
            raise ValueError(
                f"File does not appear to be a valid SSH public key: {key_path}\n"
                f"Public keys should start with: {', '.join(p.strip() for p in valid_prefixes)}"
            )

    @staticmethod
    def read_ssh_key_content(key_path: str) -> str:
        """Read SSH public key content."""
        path = Path(key_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"SSH key not found: {key_path}")

        with open(path) as f:
            return f.read().strip()

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
        try:
            # Validate and load SSH public key using cryptography library
            serialization.load_ssh_public_key(public_key.encode())

            # Parse SSH public key format: "ssh-rsa AAAAB3... comment"
            # Extract the base64 key material (second field)
            parts = public_key.strip().split()
            if len(parts) < 2:
                raise ValueError("Invalid SSH public key format")

            # Decode the base64 key material and compute MD5
            key_data = base64.b64decode(parts[1])
            fingerprint = hashlib.md5(key_data).hexdigest()

            # Format as colon-separated hex pairs
            return ":".join(fingerprint[i : i + 2] for i in range(0, len(fingerprint), 2))
        except Exception as e:
            raise ValueError(f"Failed to compute SSH key fingerprint: {e}")

    def create_default_config(
        self,
        token: str,
        username: str,
        region: str = "nyc3",
        size: str = "s-2vcpu-4gb",
        image: str = "ubuntu-25-04-x64",
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

        # Create validated Pydantic model
        self._config = TobcloudConfig(
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
                identity_file=ssh_keys[0].replace(".pub", "") if ssh_keys else "~/.ssh/id_ed25519",
            ),
        )
