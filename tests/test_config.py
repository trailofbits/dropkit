"""Comprehensive tests for configuration management with Pydantic validation."""

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from dropkit.config import (
    DEFAULT_IMAGE,
    DEFAULT_REGION,
    DEFAULT_SIZE,
    CloudInitConfig,
    Config,
    DefaultsConfig,
    DigitalOceanConfig,
    DropkitConfig,
    SSHConfig,
)
from dropkit.ssh_config import add_ssh_host

SSH_PUBLIC_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFGW/ZeZ1NgiZQsIAI9rL+6IUhSpx9ujmL3RKwwUaNaq "
    "user@example.com"
)
SSH_FINGERPRINT = "ef:9f:b5:c6:6e:f9:3d:9c:6b:7b:02:b9:bb:5a:4a:2e"


@pytest.fixture
def temp_config_dir(tmp_path):
    """Create a temporary config directory for testing."""
    config_dir = tmp_path / ".config" / "dropkit"
    config_dir.mkdir(parents=True)
    yield config_dir


@pytest.fixture
def valid_config_dict():
    """Return a valid configuration dictionary."""
    return {
        "digitalocean": {
            "token": "dop_v1_test_token_12345",
            "api_base": "https://api.digitalocean.com/v2",
        },
        "defaults": {
            "region": DEFAULT_REGION,
            "size": DEFAULT_SIZE,
            "image": DEFAULT_IMAGE,
            "extra_tags": ["custom-tag"],
        },
        "cloudinit": {
            "template_path": "/home/user/.config/dropkit/cloud-init.yaml",
            "ssh_keys": ["/home/user/.ssh/id_ed25519.pub"],
            "ssh_key_ids": [12345678],
        },
        "ssh": {
            "config_path": "/home/user/.ssh/config",
            "auto_update": True,
            "identity_file": "/home/user/.ssh/id_ed25519",
        },
    }


class TestDigitalOceanConfig:
    """Tests for DigitalOceanConfig validation."""

    def test_valid_config(self):
        """Test valid DigitalOcean config."""
        config = DigitalOceanConfig(
            token="dop_v1_test_token", api_base="https://api.digitalocean.com/v2"
        )
        assert config.token == "dop_v1_test_token"
        assert config.api_base == "https://api.digitalocean.com/v2"

    def test_token_whitespace_stripped(self):
        """Test that token whitespace is stripped."""
        config = DigitalOceanConfig(token="  dop_v1_test  ")
        assert config.token == "dop_v1_test"

    def test_empty_token_fails(self):
        """Test that empty token fails validation."""
        with pytest.raises(ValidationError) as exc_info:
            DigitalOceanConfig(token="")
        # Pydantic catches this with min_length before our custom validator
        assert "token" in str(exc_info.value).lower()

    def test_whitespace_only_token_fails(self):
        """Test that whitespace-only token fails validation."""
        with pytest.raises(ValidationError) as exc_info:
            DigitalOceanConfig(token="   ")
        assert "Token cannot be empty" in str(exc_info.value)

    def test_missing_token_fails(self):
        """Test that missing token fails validation."""
        with pytest.raises(ValidationError):
            DigitalOceanConfig()

    def test_default_api_base(self):
        """Test default API base URL."""
        config = DigitalOceanConfig(token="test_token")
        assert config.api_base == "https://api.digitalocean.com/v2"


class TestDefaultsConfig:
    """Tests for DefaultsConfig validation."""

    def test_valid_config(self):
        """Test valid defaults config."""
        config = DefaultsConfig(
            region=DEFAULT_REGION,
            size=DEFAULT_SIZE,
            image=DEFAULT_IMAGE,
            extra_tags=["tag1", "tag2"],
        )
        assert config.region == DEFAULT_REGION
        assert config.size == DEFAULT_SIZE
        assert config.image == DEFAULT_IMAGE
        assert config.extra_tags == ["tag1", "tag2"]

    def test_empty_region_fails(self):
        """Test that empty region fails validation."""
        with pytest.raises(ValidationError):
            DefaultsConfig(
                region="",
                size=DEFAULT_SIZE,
                image=DEFAULT_IMAGE,
            )

    def test_empty_size_fails(self):
        """Test that empty size fails validation."""
        with pytest.raises(ValidationError):
            DefaultsConfig(
                region=DEFAULT_REGION,
                size="",
                image=DEFAULT_IMAGE,
            )

    def test_empty_image_fails(self):
        """Test that empty image fails validation."""
        with pytest.raises(ValidationError):
            DefaultsConfig(
                region=DEFAULT_REGION,
                size=DEFAULT_SIZE,
                image="",
            )

    def test_empty_extra_tags_allowed(self):
        """Test that empty extra_tags list is allowed."""
        config = DefaultsConfig(
            region=DEFAULT_REGION,
            size=DEFAULT_SIZE,
            image=DEFAULT_IMAGE,
            extra_tags=[],
        )
        assert config.extra_tags == []

    def test_missing_extra_tags_defaults_to_empty(self):
        """Test that missing extra_tags defaults to empty list."""
        config = DefaultsConfig(
            region=DEFAULT_REGION,
            size=DEFAULT_SIZE,
            image=DEFAULT_IMAGE,
        )
        assert config.extra_tags == []


class TestCloudInitConfig:
    """Tests for CloudInitConfig validation."""

    def test_valid_config(self):
        """Test valid cloud-init config."""
        config = CloudInitConfig(
            template_path="/path/to/template.yaml",
            ssh_keys=["/path/to/key1.pub", "/path/to/key2.pub"],
            ssh_key_ids=[12345, 67890],
        )
        assert config.template_path == "/path/to/template.yaml"
        assert len(config.ssh_keys) == 2
        assert len(config.ssh_key_ids) == 2

    def test_empty_ssh_keys_fails(self):
        """Test that empty SSH keys list fails validation."""
        with pytest.raises(ValidationError) as exc_info:
            CloudInitConfig(
                template_path="/path/to/template.yaml",
                ssh_keys=[],
                ssh_key_ids=[12345],
            )
        # Pydantic catches this with min_length
        assert "ssh_keys" in str(exc_info.value).lower()

    def test_missing_ssh_keys_fails(self):
        """Test that missing SSH keys fails validation."""
        with pytest.raises(ValidationError):
            CloudInitConfig(
                template_path="/path/to/template.yaml",
                ssh_key_ids=[12345],
            )

    def test_single_ssh_key_valid(self):
        """Test that single SSH key is valid."""
        config = CloudInitConfig(
            template_path="/path/to/template.yaml",
            ssh_keys=["/path/to/key.pub"],
            ssh_key_ids=[12345],
        )
        assert len(config.ssh_keys) == 1


class TestSSHConfig:
    """Tests for SSHConfig validation."""

    def test_valid_config(self):
        """Test valid SSH config."""
        config = SSHConfig(
            config_path="/home/user/.ssh/config",
            auto_update=True,
            identity_file="/home/user/.ssh/id_ed25519",
        )
        assert config.config_path == "/home/user/.ssh/config"
        assert config.auto_update is True
        assert config.identity_file == "/home/user/.ssh/id_ed25519"

    def test_auto_update_defaults_to_true(self):
        """Test that auto_update defaults to True."""
        config = SSHConfig(
            config_path="/home/user/.ssh/config",
            identity_file="/home/user/.ssh/id_ed25519",
        )
        assert config.auto_update is True

    def test_missing_config_path_fails(self):
        """Test that missing config_path fails validation."""
        with pytest.raises(ValidationError):
            SSHConfig(identity_file="/home/user/.ssh/id_ed25519")

    def test_missing_identity_file_fails(self):
        """Test that missing identity_file fails validation."""
        with pytest.raises(ValidationError):
            SSHConfig(config_path="/home/user/.ssh/config")


class TestDropkitConfig:
    """Tests for DropkitConfig (full configuration) validation."""

    def test_valid_full_config(self, valid_config_dict):
        """Test valid full configuration."""
        config = DropkitConfig(**valid_config_dict)
        assert config.digitalocean.token == "dop_v1_test_token_12345"
        assert config.defaults.region == DEFAULT_REGION
        assert config.cloudinit.ssh_keys[0] == "/home/user/.ssh/id_ed25519.pub"
        assert config.ssh.auto_update is True

    def test_missing_digitalocean_section_fails(self, valid_config_dict):
        """Test that missing digitalocean section fails validation."""
        del valid_config_dict["digitalocean"]
        with pytest.raises(ValidationError):
            DropkitConfig(**valid_config_dict)

    def test_missing_defaults_section_fails(self, valid_config_dict):
        """Test that missing defaults section fails validation."""
        del valid_config_dict["defaults"]
        with pytest.raises(ValidationError):
            DropkitConfig(**valid_config_dict)

    def test_missing_cloudinit_section_fails(self, valid_config_dict):
        """Test that missing cloudinit section fails validation."""
        del valid_config_dict["cloudinit"]
        with pytest.raises(ValidationError):
            DropkitConfig(**valid_config_dict)

    def test_missing_ssh_section_fails(self, valid_config_dict):
        """Test that missing ssh section fails validation."""
        del valid_config_dict["ssh"]
        with pytest.raises(ValidationError):
            DropkitConfig(**valid_config_dict)

    def test_extra_fields_forbidden(self, valid_config_dict):
        """Test that extra fields are forbidden."""
        valid_config_dict["extra_field"] = "not allowed"
        with pytest.raises(ValidationError) as exc_info:
            DropkitConfig(**valid_config_dict)
        assert "extra_field" in str(exc_info.value).lower()

    def test_nested_validation_error(self, valid_config_dict):
        """Test that nested validation errors are caught."""
        valid_config_dict["digitalocean"]["token"] = ""
        with pytest.raises(ValidationError) as exc_info:
            DropkitConfig(**valid_config_dict)
        assert "token" in str(exc_info.value).lower()


class TestConfigManager:
    """Tests for Config manager class."""

    def test_config_not_loaded_raises_error(self):
        """Test that accessing config before loading raises error."""
        config = Config()
        with pytest.raises(ValueError) as exc_info:
            _ = config.config
        assert "not loaded" in str(exc_info.value).lower()

    def test_create_default_config(self):
        """Test creating default configuration."""
        config = Config()
        config.create_default_config(
            token="test_token",
            username="testuser",
            region=DEFAULT_REGION,
            size=DEFAULT_SIZE,
            image=DEFAULT_IMAGE,
            ssh_keys=["/path/to/key.pub"],
            ssh_key_ids=[12345],
            extra_tags=["tag1", "tag2"],
        )

        # Should be able to access config now
        assert config.config.digitalocean.token == "test_token"
        assert config.config.defaults.region == DEFAULT_REGION
        assert config.config.defaults.extra_tags == ["tag1", "tag2"]
        assert config.config.cloudinit.ssh_key_ids == [12345]

    def test_create_config_without_ssh_keys_raises_error(self, monkeypatch):
        """Test that creating config without SSH keys raises error."""
        # Mock detect_ssh_keys to return empty list
        monkeypatch.setattr(Config, "detect_ssh_keys", staticmethod(list))

        config = Config()
        with pytest.raises(ValueError) as exc_info:
            config.create_default_config(
                token="test_token",
                username="testuser",
                ssh_keys=None,  # Will try to auto-detect
                ssh_key_ids=[12345],
            )
        assert "SSH key" in str(exc_info.value)

    def test_create_config_with_agent_key(self, temp_config_dir, monkeypatch):
        """Persist a usable public IdentityFile for a key held only by an agent."""
        monkeypatch.setattr(Config, "CONFIG_DIR", temp_config_dir)
        config = Config()
        config.create_default_config(
            token="test_token", username="testuser", ssh_keys=[SSH_PUBLIC_KEY], ssh_key_ids=[12345]
        )

        identity = Path(config.config.ssh.identity_file)
        assert identity.parent == temp_config_dir / "ssh"
        assert identity.suffix == ".pub"
        assert identity.read_text().strip() == SSH_PUBLIC_KEY
        assert identity.stat().st_mode & 0o777 == 0o600
        assert identity.parent.stat().st_mode & 0o777 == 0o700
        assert config.config.cloudinit.ssh_keys == [SSH_PUBLIC_KEY]
        Config.validate_ssh_public_key(str(identity))

        ssh_config = temp_config_dir / "ssh-config"
        ssh_config.write_text("Host *\n    IdentitiesOnly yes\n")
        add_ssh_host(str(ssh_config), "dropkit.test", "192.0.2.1", "testuser", str(identity))
        result = subprocess.run(
            ["ssh", "-G", "-F", str(ssh_config), "dropkit.test"],
            capture_output=True,
            text=True,
            check=True,
        )
        assert f"identityfile {identity}" in result.stdout.splitlines()
        assert "identitiesonly yes" in result.stdout.splitlines()

        # Reinitializing reuses the same public-key file.
        config.create_default_config(
            token="test_token", username="testuser", ssh_keys=[SSH_PUBLIC_KEY], ssh_key_ids=[12345]
        )
        assert config.config.ssh.identity_file == str(identity)
        assert list(identity.parent.iterdir()) == [identity]

    @pytest.mark.parametrize("has_private_key", [True, False])
    def test_create_config_with_file_key(self, tmp_path, has_private_key):
        """Use a private key when present, or its public file to select an agent key."""
        public_key = tmp_path / "id_ed25519.pub"
        public_key.write_text(SSH_PUBLIC_KEY + "\n")
        private_key = public_key.with_suffix("")
        if has_private_key:
            private_key.touch()
        config = Config()
        config.create_default_config(
            token="test_token",
            username="testuser",
            ssh_keys=[SSH_PUBLIC_KEY, str(public_key)],
            ssh_key_ids=[12345],
        )
        expected = private_key if has_private_key else public_key
        assert config.config.ssh.identity_file == str(expected)

    def test_save_without_config_raises_error(self):
        """Test that saving without config raises error."""
        config = Config()
        with pytest.raises(ValueError) as exc_info:
            config.save()
        assert "No configuration to save" in str(exc_info.value)

    def test_save_and_load_config(self, temp_config_dir, valid_config_dict, monkeypatch):
        """Test saving and loading configuration."""
        # Monkey patch Config paths
        monkeypatch.setattr(Config, "CONFIG_DIR", temp_config_dir)
        monkeypatch.setattr(Config, "CONFIG_FILE", temp_config_dir / "config.yaml")
        monkeypatch.setattr(Config, "CLOUD_INIT_FILE", temp_config_dir / "cloud-init.yaml")

        # Create and save config
        config = Config()
        config.create_default_config(
            token="test_token_save_load",
            username="testuser",
            region="sfo3",
            size="s-1vcpu-1gb",
            image=DEFAULT_IMAGE,
            ssh_keys=["/path/to/key.pub"],
            ssh_key_ids=[98765],
            extra_tags=["test_tag"],
        )
        config.save()

        # Verify file exists
        assert Config.CONFIG_FILE.exists()

        # Verify file permissions
        mode = Config.CONFIG_FILE.stat().st_mode & 0o777
        assert mode == 0o600

        # Load config in new instance
        config2 = Config()
        config2.load()

        # Verify loaded config matches
        assert config2.config.digitalocean.token == "test_token_save_load"
        assert config2.config.defaults.region == "sfo3"
        assert config2.config.defaults.size == "s-1vcpu-1gb"
        assert config2.config.defaults.extra_tags == ["test_tag"]
        assert config2.config.cloudinit.ssh_key_ids == [98765]

    def test_load_invalid_config_raises_validation_error(self, temp_config_dir, monkeypatch):
        """Test that loading invalid config raises validation error."""
        # Monkey patch Config paths
        monkeypatch.setattr(Config, "CONFIG_DIR", temp_config_dir)
        monkeypatch.setattr(Config, "CONFIG_FILE", temp_config_dir / "config.yaml")

        # Write invalid config (missing required fields)
        invalid_config = {
            "digitalocean": {
                "token": "",  # Empty token
            }
        }

        import yaml

        with open(Config.CONFIG_FILE, "w") as f:
            yaml.dump(invalid_config, f)

        # Try to load
        config = Config()
        with pytest.raises(ValidationError):
            config.load()

    def test_load_nonexistent_config_raises_file_not_found(self, temp_config_dir, monkeypatch):
        """Test that loading non-existent config raises FileNotFoundError."""
        # Monkey patch Config paths
        monkeypatch.setattr(Config, "CONFIG_DIR", temp_config_dir)
        monkeypatch.setattr(Config, "CONFIG_FILE", temp_config_dir / "nonexistent.yaml")

        config = Config()
        with pytest.raises(FileNotFoundError) as exc_info:
            config.load()
        assert "dropkit init" in str(exc_info.value)

    def test_get_system_username(self, monkeypatch):
        """Test getting system username."""
        monkeypatch.setenv("USER", "testuser")
        assert Config.get_system_username() == "testuser"

    def test_get_system_username_default(self, monkeypatch):
        """Test getting system username with no USER env var."""
        monkeypatch.delenv("USER", raising=False)
        assert Config.get_system_username() == "user"

    def test_detect_ssh_keys(self, tmp_path, monkeypatch):
        """Test SSH key detection."""
        # Create fake SSH directory
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()

        # Create some keys
        (ssh_dir / "id_ed25519.pub").touch()
        (ssh_dir / "id_rsa.pub").touch()

        # Monkey patch home directory
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        keys = Config.detect_ssh_keys()
        assert len(keys) == 2
        assert str(ssh_dir / "id_ed25519.pub") in keys
        assert str(ssh_dir / "id_rsa.pub") in keys

    def test_detect_ssh_keys_no_ssh_dir(self, tmp_path, monkeypatch):
        """Test SSH key detection with no .ssh directory."""
        # Monkey patch home directory (no .ssh dir)
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        keys = Config.detect_ssh_keys()
        assert keys == []

    def test_read_ssh_key_content(self, tmp_path):
        """Test reading SSH key content."""
        key_file = tmp_path / "test_key.pub"
        key_file.write_text("ssh-rsa AAAAB3... test@example.com\n")

        content = Config.read_ssh_key_content(str(key_file))
        assert content == "ssh-rsa AAAAB3... test@example.com"

    def test_read_ssh_key_nonexistent_raises_error(self):
        """Test reading non-existent SSH key raises error."""
        with pytest.raises(FileNotFoundError):
            Config.read_ssh_key_content("/nonexistent/key.pub")

    def test_validate_ssh_public_key_file(self, tmp_path):
        """Test validation of a public key file."""
        key_file = tmp_path / "id_ed25519.pub"
        key_file.write_text(SSH_PUBLIC_KEY + "\n")

        Config.validate_ssh_public_key(str(key_file))

    def test_validate_ssh_public_key_private_key_fails(self, tmp_path):
        """Test that private key (without .pub extension) fails validation."""
        key_file = tmp_path / "id_ed25519"
        key_file.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n...")

        with pytest.raises(ValueError) as exc_info:
            Config.validate_ssh_public_key(str(key_file))
        assert "must be a public key" in str(exc_info.value)
        assert "Private keys should NEVER" in str(exc_info.value)

    def test_validate_ssh_public_key_nonexistent_fails(self):
        """Test that non-existent key file fails validation."""
        with pytest.raises(FileNotFoundError) as exc_info:
            Config.validate_ssh_public_key("/nonexistent/key.pub")
        assert "not found" in str(exc_info.value)

    def test_validate_ssh_public_key_empty_file_fails(self, tmp_path):
        """Test that empty key file fails validation."""
        key_file = tmp_path / "empty.pub"
        key_file.write_text("")

        with pytest.raises(ValueError) as exc_info:
            Config.validate_ssh_public_key(str(key_file))
        assert "empty" in str(exc_info.value)

    def test_validate_ssh_public_key_invalid_content_fails(self, tmp_path):
        """Test that file with invalid content fails validation."""
        key_file = tmp_path / "invalid.pub"
        key_file.write_text("This is not a valid SSH public key\n")

        with pytest.raises(ValueError) as exc_info:
            Config.validate_ssh_public_key(str(key_file))
        assert "does not appear to be a valid SSH public key" in str(exc_info.value)

    def test_validate_ssh_public_key_private_key_header_fails(self, tmp_path):
        """Test that file with private key header fails validation."""
        key_file = tmp_path / "private.pub"  # Has .pub extension but contains private key
        key_file.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n")

        with pytest.raises(ValueError) as exc_info:
            Config.validate_ssh_public_key(str(key_file))
        assert "does not appear to be a valid SSH public key" in str(exc_info.value)

    def test_validate_ssh_public_key_inline_content(self):
        """Test that inline SSH key content passes validation."""
        Config.validate_ssh_public_key(SSH_PUBLIC_KEY)

    @pytest.mark.parametrize(
        "invalid_key",
        [
            "ssh-ed25519 AAAA user@example.com",
            SSH_PUBLIC_KEY.replace("ssh-ed25519", "invalid-key-type", 1),
            SSH_PUBLIC_KEY.replace("ssh-ed25519", "ssh-rsa", 1),
            SSH_PUBLIC_KEY + "\n" + SSH_PUBLIC_KEY,
        ],
        ids=["truncated-payload", "invalid-type", "mismatched-type", "multiple-keys"],
    )
    def test_malformed_keys_fail_validation_and_fingerprinting(self, invalid_key, tmp_path):
        """Both inline and file inputs must be valid single SSH public keys."""
        key_file = tmp_path / "invalid.pub"
        key_file.write_text(invalid_key + "\n")
        for entry in (invalid_key, str(key_file)):
            with pytest.raises(ValueError, match="does not appear to be a valid SSH public key"):
                Config.validate_ssh_public_key(entry)
        with pytest.raises(ValueError, match="does not appear to be a valid SSH public key"):
            Config.compute_ssh_key_fingerprint(invalid_key)

    def test_real_private_key_rejected_even_with_pub_extension(self, tmp_path):
        """ssh-keygen accepts private keys, so reject them before invoking it."""
        private_key = tmp_path / "private-key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private_key)],
            check=True,
        )
        content = private_key.read_text()
        disguised_key = tmp_path / "disguised.pub"
        disguised_key.write_text(content)
        for entry in (content, str(disguised_key)):
            with pytest.raises(ValueError, match="does not appear to be a valid SSH public key"):
                Config.validate_ssh_public_key(entry)

    def test_compute_ssh_key_fingerprint(self):
        """Keep DigitalOcean's colon-separated MD5 format without the MD5: prefix."""
        assert Config.compute_ssh_key_fingerprint(SSH_PUBLIC_KEY) == SSH_FINGERPRINT

    @pytest.mark.parametrize(
        ("error", "message"),
        [
            (FileNotFoundError(), "ssh-keygen is required"),
            (subprocess.TimeoutExpired("ssh-keygen", 5), "Timed out"),
        ],
    )
    def test_ssh_keygen_unavailable(self, error, message):
        """Report a useful error instead of falling back to weaker validation."""
        with (
            patch("dropkit.config.subprocess.run", side_effect=error),
            pytest.raises(ValueError, match=message),
        ):
            Config.validate_ssh_public_key(SSH_PUBLIC_KEY)

    def test_read_ssh_key_content_inline(self):
        """Test that inline SSH key content is returned as-is."""
        inline_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@example.com"
        assert Config.read_ssh_key_content(inline_key) == inline_key

    def test_detect_ssh_agent_keys(self, tmp_path, monkeypatch):
        """Test detection of SSH keys from ssh-agent."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        # Create .ssh dir with one on-disk key
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_ed25519.pub").write_text("ssh-ed25519 AAAADISK diskkey@host\n")

        # Mock ssh-add -L returning two keys (one matching disk, one new)
        agent_output = "ssh-ed25519 AAAADISK diskkey@host\nssh-ed25519 AAAANEW agentkey@1password\n"
        result = subprocess.CompletedProcess([], 0, stdout=agent_output)

        with (
            patch.object(Config, "_get_ssh_agent_sock", return_value="/tmp/agent.sock"),
            patch("dropkit.config.subprocess.run", return_value=result),
        ):
            keys = Config.detect_ssh_agent_keys()

        # Only the new agent key (not the one already on disk) should be returned
        assert len(keys) == 1
        assert "AAAANEW" in keys[0]
        assert "agentkey@1password" in keys[0]

    def test_detect_ssh_agent_keys_no_agent(self):
        """Test detection when no ssh-agent socket is available."""
        with patch.object(Config, "_get_ssh_agent_sock", return_value=None):
            keys = Config.detect_ssh_agent_keys()

        assert keys == []

    def test_detect_ssh_agent_keys_agent_empty(self):
        """Test detection when ssh-agent has no keys."""
        result = subprocess.CompletedProcess([], 1, stdout="The agent has no identities.\n")

        with (
            patch.object(Config, "_get_ssh_agent_sock", return_value="/tmp/agent.sock"),
            patch("dropkit.config.subprocess.run", return_value=result),
        ):
            keys = Config.detect_ssh_agent_keys()

        assert keys == []

    def test_get_ssh_agent_sock_from_ssh_config(self, tmp_path):
        """Test resolving agent socket from ssh -G localhost."""
        agent_sock = tmp_path / "1password-agent.sock"
        agent_sock.touch()
        result = subprocess.CompletedProcess(
            [],
            0,
            stdout=f"identityagent {agent_sock}\nuser testuser\n",
        )

        with patch("dropkit.config.subprocess.run", return_value=result):
            sock = Config._get_ssh_agent_sock()

        assert sock == str(agent_sock)

    def test_get_ssh_agent_sock_falls_back_to_env(self, tmp_path, monkeypatch):
        """Test falling back to SSH_AUTH_SOCK when ssh -G has no IdentityAgent."""
        ssh_g_output = "user testuser\nhostname localhost\n"
        result = subprocess.CompletedProcess([], 0, stdout=ssh_g_output)

        # Create a fake socket file
        fake_sock = tmp_path / "agent.sock"
        fake_sock.touch()
        monkeypatch.setenv("SSH_AUTH_SOCK", str(fake_sock))

        with patch("dropkit.config.subprocess.run", return_value=result):
            sock = Config._get_ssh_agent_sock()

        assert sock == str(fake_sock)

    def test_get_ssh_agent_sock_none_when_unavailable(self, monkeypatch):
        """Test returning None when no agent socket is available."""
        monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)

        with patch(
            "dropkit.config.subprocess.run",
            side_effect=FileNotFoundError,
        ):
            sock = Config._get_ssh_agent_sock()

        assert sock is None

    def test_identity_agent_none_disables_discovery(self, tmp_path, monkeypatch):
        """An explicit IdentityAgent none takes precedence over SSH_AUTH_SOCK."""
        agent_sock = tmp_path / "agent.sock"
        agent_sock.touch()
        monkeypatch.setenv("SSH_AUTH_SOCK", str(agent_sock))
        result = subprocess.CompletedProcess([], 0, stdout="identityagent none\n")
        with patch("dropkit.config.subprocess.run", return_value=result) as run:
            assert Config.detect_ssh_agent_keys() == []
        # Do not invoke ssh-add after the SSH config disables agent use.
        run.assert_called_once()
        assert run.call_args.args[0] == ["ssh", "-G", "localhost"]
