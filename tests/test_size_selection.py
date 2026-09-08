"""Command-level coverage for interactive droplet size filtering."""

from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from dropkit.main import app
from dropkit.ui import display_sizes

SIZES = [
    {"slug": "small", "memory": 1024, "vcpus": 1, "disk": 25, "price_monthly": 6},
    {"slug": "large", "memory": 16384, "vcpus": 8, "disk": 100, "price_monthly": 96},
    {"slug": "costly", "memory": 32768, "vcpus": 16, "disk": 200, "price_monthly": 192},
]


@pytest.fixture
def size_env(tmp_path):
    api = MagicMock()
    api.get_available_sizes.return_value = SIZES
    api.get_available_regions.return_value = [{"slug": "lon1"}]
    api.get_available_images.return_value = [{"slug": "ubuntu"}]
    api.get_default_project.return_value = None
    api.list_projects.return_value = []
    api.get_account.return_value = {"email": "test@example.com"}
    api.get_username.return_value = "testuser"
    api.get_snapshot_by_name.return_value = None
    droplet = {
        "id": 123,
        "size_slug": "small",
        "size": SIZES[0],
        "networks": {"v4": [{"type": "public", "ip_address": "192.0.2.1"}]},
    }
    api.create_droplet.return_value = droplet
    api.wait_for_droplet_active.return_value = droplet
    api.get_droplet.return_value = droplet
    api.resize_droplet.return_value = {"id": 456}
    api.power_on_droplet.return_value = {"id": 789}
    manager = MagicMock()
    manager.config.defaults.extra_tags = []
    manager.config.defaults.size = "small"
    manager.config.defaults.project_id = None
    manager.config.ssh.auto_update = False
    with ExitStack() as stack:
        stack.enter_context(patch("dropkit.lock.LOCK_FILE", tmp_path / "dropkit.lock"))
        stack.enter_context(patch("dropkit.main.Config", return_value=manager))
        stack.enter_context(patch("dropkit.main.DigitalOceanAPI", return_value=api))
        stack.enter_context(patch("dropkit.main.load_config_and_api", return_value=(manager, api)))
        find = stack.enter_context(
            patch("dropkit.main.find_user_droplet", return_value=(None, "testuser"))
        )
        stack.enter_context(patch("dropkit.main.render_cloud_init", return_value="#cloud-config"))
        stack.enter_context(patch("dropkit.main.wait_for_cloud_init", return_value=(True, False)))
        stack.enter_context(
            patch("dropkit.main.register_ssh_keys_with_do", return_value=([], [], "testuser"))
        )
        display = stack.enter_context(patch("dropkit.main.display_sizes", wraps=display_sizes))
        yield SimpleNamespace(api=api, find=find, droplet=droplet, display=display, manager=manager)


@pytest.mark.parametrize("command", ["init", "create", "resize_live", "resize_snapshot"])
@pytest.mark.parametrize("prefix", ["? ", ""])
def test_interactive_size_filter_reaches_api(size_env, command, prefix):
    env = size_env
    user_input = f"{prefix}mem>=16 cpu>=8 price<=100\nlarge\n"
    if command == "init":
        args = ["init", "--force"]
        user_input = f"test-token\nlon1\n{user_input}ubuntu\n\n"
    elif command == "create":
        args = ["create", "test", "--region", "lon1", "--image", "ubuntu", "--no-tailscale"]
    else:
        args = ["resize", "test", "--no-disk"]
        if command == "resize_live":
            env.find.return_value = (env.droplet, "testuser")
        else:
            env.api.get_snapshot_by_name.return_value = {"id": "456", "tags": ["size:small"]}

    result = CliRunner().invoke(app, args, input=user_input + "yes\n")

    assert result.exit_code == 0, result.output
    env.display.assert_called_once()
    assert env.display.call_args.args[0] == [SIZES[1]]
    assert "1 of 3 shown" in result.output
    assert "mem defaults to GB" in result.output
    if command == "init":
        env.manager.create_default_config.assert_called_once()
        assert env.manager.create_default_config.call_args.kwargs["size"] == "large"
        env.manager.save.assert_called_once()
    elif command == "create":
        env.api.create_droplet.assert_called_once()
        assert env.api.create_droplet.call_args.kwargs["size"] == "large"
    elif command == "resize_live":
        env.api.resize_droplet.assert_called_once_with(123, "large", disk=False)
    else:
        env.api.tag_resource.assert_called_once_with("size:large", "456", "image")
        env.api.untag_resource.assert_called_once_with("size:small", "456", "image")
