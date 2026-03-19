"""Tests for cloud-init template parsing and rendering."""

from jinja2 import Template, TemplateSyntaxError

from dropkit.config import Config


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
