"""Tests for cloud-init template parsing and rendering."""

import json
import urllib.request

import pytest
import yaml
from jinja2 import Template, TemplateSyntaxError
from jsonschema import Draft4Validator

from dropkit.config import Config

CLOUD_CONFIG_SCHEMA_URL = (
    "https://raw.githubusercontent.com/canonical/cloud-init/main/"
    "cloudinit/config/schemas/schema-cloud-config-v1.json"
)


@pytest.fixture(scope="module")
def cloud_config_schema():
    """Fetch the official cloud-init JSON schema (skip if offline)."""
    try:
        with urllib.request.urlopen(CLOUD_CONFIG_SCHEMA_URL, timeout=10) as resp:  # noqa: S310
            return json.loads(resp.read())
    except (urllib.error.URLError, TimeoutError):
        pytest.skip("Could not fetch cloud-init schema (offline?)")


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
