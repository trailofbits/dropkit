"""Tests for cloud-init template parsing and rendering."""

import json
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from jinja2 import Template, TemplateSyntaxError
from jsonschema import Draft4Validator

from dropkit.cloudinit import render_cloud_init
from dropkit.config import Config
from tests.test_config import SSH_PUBLIC_KEY

# Pinned to cloud-init 22.4.2 — the oldest version shipped by a
# currently supported DigitalOcean image (Debian 12 bookworm).
_SCHEMA_PATH = Path(__file__).parent / "data" / "schema-cloud-config-v1.json"


def _render_key(template_path: Path, key: str) -> str:
    return render_cloud_init(str(template_path), "testuser", "Test User", "test@example.com", [key])


def test_render_cloud_init_uses_validated_file_content(tmp_path):
    template = tmp_path / "cloud-init.yaml"
    template.write_text("{{ ssh_keys[0] }}")
    key_file = tmp_path / "id_ed25519.pub"
    key_file.write_text(SSH_PUBLIC_KEY + "\n")
    real_open = open
    key_reads = 0

    def changing_open(file, *args, **kwargs):
        nonlocal key_reads
        if str(file) == str(key_file):
            key_reads += 1
            return StringIO(SSH_PUBLIC_KEY if key_reads == 1 else "not a public key")
        return real_open(file, *args, **kwargs)

    with patch("builtins.open", side_effect=changing_open):
        rendered = _render_key(template, str(key_file))

    assert key_reads == 1
    assert rendered == SSH_PUBLIC_KEY


def test_render_cloud_init_accepts_inline_agent_key(tmp_path):
    template = tmp_path / "cloud-init.yaml"
    template.write_text("{{ ssh_keys[0] }}")

    assert _render_key(template, SSH_PUBLIC_KEY) == SSH_PUBLIC_KEY


@pytest.mark.parametrize(
    ("filename", "content", "error"),
    [
        ("private-key", SSH_PUBLIC_KEY, "must be a public key"),
        ("bad.pub", "not a public key", "does not appear to be a valid SSH public key"),
        ("empty.pub", "", "SSH key file is empty"),
    ],
)
def test_render_cloud_init_rejects_invalid_file(tmp_path, filename, content, error):
    template = tmp_path / "cloud-init.yaml"
    template.write_text("{{ ssh_keys[0] }}")
    key_file = tmp_path / filename
    key_file.write_text(content)

    with pytest.raises(ValueError, match=error):
        _render_key(template, str(key_file))


def test_render_cloud_init_rejects_missing_file(tmp_path):
    template = tmp_path / "cloud-init.yaml"
    template.write_text("{{ ssh_keys[0] }}")

    with pytest.raises(FileNotFoundError, match="SSH key not found"):
        _render_key(template, str(tmp_path / "missing.pub"))


@pytest.fixture(scope="module")
def cloud_config_schema():
    """Load the cloud-init JSON schema from local test data."""
    return json.loads(_SCHEMA_PATH.read_text())


def _load_default_template() -> str:
    """Load the default cloud-init template content."""
    path = Config.get_default_template_path()
    return path.read_text()


def test_default_template_parses():
    """Verify the default template is valid Jinja2 syntax."""
    content = _load_default_template()
    try:
        Template(content)
    except TemplateSyntaxError as exc:
        raise AssertionError(f"Template has Jinja2 syntax error: {exc}") from exc


def test_default_template_renders():
    """Verify the template renders with sample variables."""
    content = _load_default_template()
    template = Template(content)
    rendered = template.render(
        username="testuser",
        full_name="Test User",
        email="test@example.com",
        ssh_keys=["ssh-ed25519 AAAAC3... test@host"],
        tailscale_enabled=True,
    )
    assert "testuser" in rendered
    assert "ssh-ed25519 AAAAC3... test@host" in rendered
    assert "git config --global user.name 'Test User'" in rendered
    assert "git config --global user.email 'test@example.com'" in rendered
    assert "tailscale" in rendered


def test_default_template_renders_without_tailscale():
    """Verify the Tailscale section is absent when disabled."""
    content = _load_default_template()
    template = Template(content)
    rendered = template.render(
        username="testuser",
        full_name="Test User",
        email="test@example.com",
        ssh_keys=["ssh-ed25519 AAAAC3... test@host"],
        tailscale_enabled=False,
    )
    assert "testuser" in rendered
    assert "tailscale.com/install.sh" not in rendered


def _render_template(tailscale_enabled: bool = True) -> str:
    """Render the default template with sample variables."""
    content = _load_default_template()
    template = Template(content)
    return template.render(
        username="testuser",
        full_name="Test User",
        email="test@example.com",
        ssh_keys=["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 test@host"],
        tailscale_enabled=tailscale_enabled,
    )


def test_rendered_template_valid_cloud_config_schema(cloud_config_schema):
    """Verify the rendered template passes cloud-init schema validation."""
    rendered = _render_template(tailscale_enabled=True)
    doc = yaml.safe_load(rendered)
    validator = Draft4Validator(cloud_config_schema)
    errors = list(validator.iter_errors(doc))
    messages = [f"  - {e.message}" for e in errors]
    assert not errors, "Cloud-init schema errors:\n" + "\n".join(messages)


def test_rendered_template_no_tailscale_valid_schema(cloud_config_schema):
    """Verify the rendered template without Tailscale also passes schema validation."""
    rendered = _render_template(tailscale_enabled=False)
    doc = yaml.safe_load(rendered)
    validator = Draft4Validator(cloud_config_schema)
    errors = list(validator.iter_errors(doc))
    messages = [f"  - {e.message}" for e in errors]
    assert not errors, "Cloud-init schema errors:\n" + "\n".join(messages)


def test_docker_install_uses_distro_detection():
    """Verify Docker setup detects distro dynamically instead of hardcoding Ubuntu."""
    content = _load_default_template()
    template = Template(content)
    rendered = template.render(
        username="testuser",
        full_name="Test User",
        email="test@example.com",
        ssh_keys=["ssh-ed25519 AAAAC3... test@host"],
        tailscale_enabled=True,
    )
    # Must not hardcode Ubuntu — should use /etc/os-release for distro detection
    assert "download.docker.com/linux/ubuntu" not in rendered
    assert "/etc/os-release" in rendered
    assert "download.docker.com/linux/$ID" in rendered

    # Docker packages installed via runcmd, not apt sources
    assert "apt-get install -y docker-ce" in rendered

    # Architecture detected dynamically, not hardcoded amd64
    assert "dpkg --print-architecture" in rendered
