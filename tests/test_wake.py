"""Regression tests for interrupted snapshot restores."""

from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from dropkit.api import DigitalOceanAPI, DigitalOceanAPIError, DropletWaitTimeoutError
from dropkit.main import app, setup_tailscale
from dropkit.ssh_config import add_ssh_host, get_ssh_host_ip

runner = CliRunner()


@pytest.fixture
def wake_env(tmp_path):
    """Isolate all cloud, SSH, VPN, and lock effects."""
    api = MagicMock()
    api.get_username.return_value = "testuser"
    snapshot = {
        "id": "456",
        "regions": ["lon1"],
        "tags": ["owner:testuser", "size:s-8vcpu-16gb"],
    }
    droplet = {
        "id": 123,
        "name": "test-droplet",
        "image": {"id": 456},
        "status": "active",
        "networks": {"v4": [{"type": "public", "ip_address": "192.0.2.1"}]},
    }
    api.get_snapshot_by_name.return_value = snapshot
    api.create_droplet_from_snapshot.return_value = droplet
    api.wait_for_droplet_active.return_value = droplet
    config = SimpleNamespace(
        defaults=SimpleNamespace(extra_tags=[], size="s-8vcpu-16gb"),
        cloudinit=SimpleNamespace(ssh_key_ids=[789]),
        ssh=SimpleNamespace(
            auto_update=True, config_path="unused", identity_file="~/.ssh/test_key"
        ),
    )
    with ExitStack() as stack:
        stack.enter_context(patch("dropkit.lock.LOCK_FILE", tmp_path / "dropkit.lock"))
        stack.enter_context(
            patch(
                "dropkit.main.load_config_and_api",
                return_value=(SimpleNamespace(config=config), api),
            )
        )
        find = stack.enter_context(
            patch("dropkit.main.find_user_droplet", return_value=(None, "testuser"))
        )
        ssh = stack.enter_context(patch("dropkit.main.add_ssh_host"))
        vpn = stack.enter_context(patch("dropkit.main.setup_tailscale", return_value="100.64.0.1"))
        stack.enter_context(patch("dropkit.main.time.sleep"))
        yield SimpleNamespace(
            api=api,
            snapshot=snapshot,
            droplet=droplet,
            find=find,
            ssh=ssh,
            vpn=vpn,
            config=config,
        )


def test_timeout_then_retry_finishes_same_droplet(wake_env):
    """A slow restore must retain its resources and resume without creating another VM."""
    env = wake_env
    env.api.wait_for_droplet_active.side_effect = DropletWaitTimeoutError("timed out")
    result = runner.invoke(app, ["wake", "test-droplet", "--timeout", "300", "--no-tailscale"])
    assert result.exit_code == 1
    assert "DigitalOcean may still be restoring" in result.output
    assert "dropkit info test-droplet" in result.output
    assert "dropkit wake test-droplet --timeout 300 --no-tailscale" in result.output
    env.ssh.assert_not_called()
    env.api.delete_snapshot.assert_not_called()
    env.api.wait_for_droplet_active.assert_called_once_with(123, timeout=300)

    env.find.return_value = (env.droplet, "testuser")
    env.api.wait_for_droplet_active.side_effect = None
    result = runner.invoke(app, ["wake", "test-droplet"], input="no\n")
    assert result.exit_code == 0, result.output
    assert "Resuming wake" in result.output
    assert "ssh dropkit.test-droplet" in result.output
    env.api.create_droplet_from_snapshot.assert_called_once()
    env.api.wait_for_droplet_active.assert_called_with(123, timeout=900)
    env.ssh.assert_called_once_with(
        config_path="unused",
        host_name="dropkit.test-droplet",
        hostname="192.0.2.1",
        user="testuser",
        identity_file="~/.ssh/test_key",
    )
    env.api.delete_snapshot.assert_not_called()


@pytest.mark.parametrize("status", ["new", "active"])
def test_resume_retains_tailscale_setup_and_snapshot_prompt(wake_env, status):
    env = wake_env
    env.droplet["status"] = status
    env.find.return_value = (env.droplet, "testuser")
    env.snapshot["tags"].append("tailscale-lockdown")
    result = runner.invoke(app, ["wake", "test-droplet", "--timeout", "1800"], input="yes\n")
    assert result.exit_code == 0, result.output
    env.api.create_droplet_from_snapshot.assert_not_called()
    env.api.wait_for_droplet_active.assert_called_once_with(123, timeout=1800)
    env.vpn.assert_called_once()
    env.api.delete_snapshot.assert_called_once_with(456)


def test_resume_no_tailscale(wake_env):
    env = wake_env
    env.find.return_value = (env.droplet, "testuser")
    env.snapshot["tags"].append("tailscale-lockdown")
    result = runner.invoke(app, ["wake", "test-droplet", "--no-tailscale"], input="no\n")
    assert result.exit_code == 0, result.output
    env.vpn.assert_not_called()


@pytest.mark.parametrize("no_tailscale", [False, True])
def test_retry_after_firewall_lockdown_preserves_tailscale_ssh(wake_env, tmp_path, no_tailscale):
    env = wake_env
    env.config.ssh.config_path = str(tmp_path / "ssh_config")
    env.config.tailscale = SimpleNamespace(lock_down_firewall=True)
    env.snapshot["tags"].append("tailscale-lockdown")
    env.ssh.side_effect = add_ssh_host
    env.vpn.side_effect = setup_tailscale
    locked = False
    addresses = []

    def connect(ssh_hostname, verbose):
        """Simulate an authenticated node that rejects public SSH after lockdown."""
        address = get_ssh_host_ip(env.config.ssh.config_path, ssh_hostname)
        addresses.append(address)
        assert address == ("100.64.0.1" if locked else "192.0.2.1")

    def lockdown(ssh_hostname, verbose):
        nonlocal locked
        assert get_ssh_host_ip(env.config.ssh.config_path, ssh_hostname) == "100.64.0.1"
        locked = True
        return True

    with (
        patch("dropkit.main.run_tailscale_up", side_effect=connect),
        patch("dropkit.main.wait_for_tailscale_ip", return_value="100.64.0.1"),
        patch("dropkit.main.check_local_tailscale", return_value=True),
        patch("dropkit.main.lock_down_to_tailscale", side_effect=lockdown),
        patch("dropkit.main.verify_tailscale_ssh", return_value=True),
    ):
        with patch("dropkit.main.Prompt.ask", side_effect=KeyboardInterrupt):
            result = runner.invoke(app, ["wake", "test-droplet"])
        assert result.exit_code == 130, result.output
        assert locked
        env.api.delete_snapshot.assert_not_called()
        assert get_ssh_host_ip(env.config.ssh.config_path, "dropkit.test-droplet") == "100.64.0.1"

        env.find.return_value = (env.droplet, "testuser")
        args = ["wake", "test-droplet"]
        if no_tailscale:
            args.append("--no-tailscale")
        result = runner.invoke(app, args, input="yes\n")

    assert result.exit_code == 0, result.output
    assert addresses == (["192.0.2.1"] if no_tailscale else ["192.0.2.1", "100.64.0.1"])
    assert get_ssh_host_ip(env.config.ssh.config_path, "dropkit.test-droplet") == "100.64.0.1"
    env.api.create_droplet_from_snapshot.assert_called_once()
    env.api.delete_snapshot.assert_called_once_with(456)


def test_fresh_restore_replaces_stale_tailscale_ssh(wake_env, tmp_path):
    env = wake_env
    env.config.ssh.config_path = str(tmp_path / "ssh_config")
    add_ssh_host(env.config.ssh.config_path, "dropkit.test-droplet", "100.64.0.2", "testuser")
    env.ssh.side_effect = add_ssh_host

    result = runner.invoke(app, ["wake", "test-droplet"], input="no\n")

    assert result.exit_code == 0, result.output
    assert get_ssh_host_ip(env.config.ssh.config_path, "dropkit.test-droplet") == "192.0.2.1"


@pytest.mark.parametrize("image", [{"id": 999}, {}, {"id": None}])
def test_refuse_unrelated_existing_droplet(wake_env, image):
    env = wake_env
    env.droplet["image"] = image
    env.find.return_value = (env.droplet, "testuser")
    result = runner.invoke(app, ["wake", "test-droplet"])
    assert result.exit_code == 1
    assert "was not restored from this snapshot" in " ".join(result.output.split())
    assert "Destroy or rename" not in result.output
    env.api.create_droplet_from_snapshot.assert_not_called()
    env.api.wait_for_droplet_active.assert_not_called()
    env.api.delete_snapshot.assert_not_called()
    env.ssh.assert_not_called()


@pytest.mark.parametrize("status", ["off", "error", "archive"])
def test_refuse_resume_when_droplet_cannot_become_ready(wake_env, status):
    env = wake_env
    env.droplet["status"] = status
    env.find.return_value = (env.droplet, "testuser")
    result = runner.invoke(app, ["wake", "test-droplet"])
    assert result.exit_code == 1
    assert "Cannot resume wake" in result.output
    if status == "off":
        assert "dropkit on test-droplet" in result.output
    env.api.wait_for_droplet_active.assert_not_called()
    env.api.create_droplet_from_snapshot.assert_not_called()


def test_missing_snapshot_gives_existing_droplet_recovery_commands(wake_env):
    env = wake_env
    env.find.return_value = (env.droplet, "testuser")
    env.api.get_snapshot_by_name.return_value = None
    result = runner.invoke(app, ["wake", "test-droplet"])
    assert result.exit_code == 1
    assert "dropkit config-ssh test-droplet" in result.output
    env.api.create_droplet_from_snapshot.assert_not_called()
    env.ssh.assert_not_called()


def test_api_error_during_wait_keeps_resources(wake_env):
    env = wake_env
    env.api.wait_for_droplet_active.side_effect = DigitalOceanAPIError("Network error")
    result = runner.invoke(app, ["wake", "test-droplet"])
    assert result.exit_code == 1
    assert "Network error" in result.output
    assert "rerun wake to resume setup" in result.output
    env.ssh.assert_not_called()
    env.api.delete_snapshot.assert_not_called()


@pytest.mark.parametrize("failure", ["missing_ip", "ssh_config"])
def test_setup_failure_keeps_snapshot_for_retry(wake_env, failure):
    env = wake_env
    if failure == "missing_ip":
        env.droplet["networks"]["v4"] = []
    else:
        env.ssh.side_effect = OSError("read-only config")
    result = runner.invoke(app, ["wake", "test-droplet"])
    assert result.exit_code == 1
    assert "snapshot kept" in result.output.lower()
    env.api.delete_snapshot.assert_not_called()


@pytest.mark.parametrize("timeout", ["0", "-1"])
def test_timeout_must_be_positive(wake_env, timeout):
    result = runner.invoke(app, ["wake", "test-droplet", "--timeout", timeout])
    assert result.exit_code == 2
    wake_env.api.create_droplet_from_snapshot.assert_not_called()


def test_wait_times_out_at_deadline():
    api = DigitalOceanAPI("test-token")
    with (
        patch.object(api, "get_droplet", return_value={"status": "new"}),
        patch("time.monotonic", side_effect=[0, 0, 300]),
        patch("time.sleep"),
        pytest.raises(DropletWaitTimeoutError, match="waited 300s"),
    ):
        api.wait_for_droplet_active(123)


def test_wait_allows_restore_longer_than_five_minutes():
    api = DigitalOceanAPI("test-token")
    ready = {"status": "active"}
    with (
        patch.object(api, "get_droplet", side_effect=[{"status": "new"}, ready]),
        patch("time.monotonic", side_effect=[0, 395]),
        patch("time.sleep"),
    ):
        assert api.wait_for_droplet_active(123, timeout=900) == ready


def test_error_state_is_not_a_timeout():
    api = DigitalOceanAPI("test-token")
    with (
        patch.object(api, "get_droplet", return_value={"status": "error"}),
        pytest.raises(DigitalOceanAPIError, match="error state") as exc,
    ):
        api.wait_for_droplet_active(123)
    assert not isinstance(exc.value, DropletWaitTimeoutError)
