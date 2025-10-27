"""Comprehensive tests for configuration management with Pydantic validation."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from tobcloud.config import (
    CloudInitConfig,
    Config,
    DefaultsConfig,
    DigitalOceanConfig,
    SSHConfig,
    TobcloudConfig,
)


@pytest.fixture
def temp_config_dir(tmp_path):
    """Create a temporary config directory for testing."""
    config_dir = tmp_path / ".config" / "tobcloud"
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
            "region": "nyc3",
            "size": "s-2vcpu-4gb",
            "image": "ubuntu-25-04-x64",
            "extra_tags": ["custom-tag"],
        },
        "cloudinit": {
            "template_path": "/home/user/.config/tobcloud/cloud-init.yaml",
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
            region="nyc3",
            size="s-2vcpu-4gb",
            image="ubuntu-25-04-x64",
            extra_tags=["tag1", "tag2"],
        )
        assert config.region == "nyc3"
        assert config.size == "s-2vcpu-4gb"
        assert config.image == "ubuntu-25-04-x64"
        assert config.extra_tags == ["tag1", "tag2"]

    def test_empty_region_fails(self):
        """Test that empty region fails validation."""
        with pytest.raises(ValidationError):
            DefaultsConfig(
                region="",
                size="s-2vcpu-4gb",
                image="ubuntu-25-04-x64",
            )

    def test_empty_size_fails(self):
        """Test that empty size fails validation."""
        with pytest.raises(ValidationError):
            DefaultsConfig(
                region="nyc3",
                size="",
                image="ubuntu-25-04-x64",
            )

    def test_empty_image_fails(self):
        """Test that empty image fails validation."""
        with pytest.raises(ValidationError):
            DefaultsConfig(
                region="nyc3",
                size="s-2vcpu-4gb",
                image="",
            )

    def test_empty_extra_tags_allowed(self):
        """Test that empty extra_tags list is allowed."""
        config = DefaultsConfig(
            region="nyc3",
            size="s-2vcpu-4gb",
            image="ubuntu-25-04-x64",
            extra_tags=[],
        )
        assert config.extra_tags == []

    def test_missing_extra_tags_defaults_to_empty(self):
        """Test that missing extra_tags defaults to empty list."""
        config = DefaultsConfig(
            region="nyc3",
            size="s-2vcpu-4gb",
            image="ubuntu-25-04-x64",
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


class TestTobcloudConfig:
    """Tests for TobcloudConfig (full configuration) validation."""

    def test_valid_full_config(self, valid_config_dict):
        """Test valid full configuration."""
        config = TobcloudConfig(**valid_config_dict)
        assert config.digitalocean.token == "dop_v1_test_token_12345"
        assert config.defaults.region == "nyc3"
        assert config.cloudinit.ssh_keys[0] == "/home/user/.ssh/id_ed25519.pub"
        assert config.ssh.auto_update is True

    def test_missing_digitalocean_section_fails(self, valid_config_dict):
        """Test that missing digitalocean section fails validation."""
        del valid_config_dict["digitalocean"]
        with pytest.raises(ValidationError):
            TobcloudConfig(**valid_config_dict)

    def test_missing_defaults_section_fails(self, valid_config_dict):
        """Test that missing defaults section fails validation."""
        del valid_config_dict["defaults"]
        with pytest.raises(ValidationError):
            TobcloudConfig(**valid_config_dict)

    def test_missing_cloudinit_section_fails(self, valid_config_dict):
        """Test that missing cloudinit section fails validation."""
        del valid_config_dict["cloudinit"]
        with pytest.raises(ValidationError):
            TobcloudConfig(**valid_config_dict)

    def test_missing_ssh_section_fails(self, valid_config_dict):
        """Test that missing ssh section fails validation."""
        del valid_config_dict["ssh"]
        with pytest.raises(ValidationError):
            TobcloudConfig(**valid_config_dict)

    def test_extra_fields_forbidden(self, valid_config_dict):
        """Test that extra fields are forbidden."""
        valid_config_dict["extra_field"] = "not allowed"
        with pytest.raises(ValidationError) as exc_info:
            TobcloudConfig(**valid_config_dict)
        assert "extra_field" in str(exc_info.value).lower()

    def test_nested_validation_error(self, valid_config_dict):
        """Test that nested validation errors are caught."""
        valid_config_dict["digitalocean"]["token"] = ""
        with pytest.raises(ValidationError) as exc_info:
            TobcloudConfig(**valid_config_dict)
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
            region="nyc3",
            size="s-2vcpu-4gb",
            image="ubuntu-25-04-x64",
            ssh_keys=["/path/to/key.pub"],
            ssh_key_ids=[12345],
            extra_tags=["tag1", "tag2"],
        )

        # Should be able to access config now
        assert config.config.digitalocean.token == "test_token"
        assert config.config.defaults.region == "nyc3"
        assert config.config.defaults.extra_tags == ["tag1", "tag2"]
        assert config.config.cloudinit.ssh_key_ids == [12345]

    def test_create_config_without_ssh_keys_raises_error(self, monkeypatch):
        """Test that creating config without SSH keys raises error."""
        # Mock detect_ssh_keys to return empty list
        monkeypatch.setattr(Config, "detect_ssh_keys", staticmethod(lambda: []))

        config = Config()
        with pytest.raises(ValueError) as exc_info:
            config.create_default_config(
                token="test_token",
                username="testuser",
                ssh_keys=None,  # Will try to auto-detect
                ssh_key_ids=[12345],
            )
        assert "SSH key" in str(exc_info.value)

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
            image="ubuntu-25-04-x64",
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
        assert "tobcloud init" in str(exc_info.value)

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

    def test_validate_ssh_public_key_valid_ed25519(self, tmp_path):
        """Test validation of valid ED25519 public key."""
        key_file = tmp_path / "id_ed25519.pub"
        key_file.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@example.com\n")

        # Should not raise any exception
        Config.validate_ssh_public_key(str(key_file))

    def test_validate_ssh_public_key_valid_rsa(self, tmp_path):
        """Test validation of valid RSA public key."""
        key_file = tmp_path / "id_rsa.pub"
        key_file.write_text("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB... user@example.com\n")

        # Should not raise any exception
        Config.validate_ssh_public_key(str(key_file))

    def test_validate_ssh_public_key_valid_ecdsa(self, tmp_path):
        """Test validation of valid ECDSA public key."""
        key_file = tmp_path / "id_ecdsa.pub"
        key_file.write_text(
            "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNT... user@example.com\n"
        )

        # Should not raise any exception
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
