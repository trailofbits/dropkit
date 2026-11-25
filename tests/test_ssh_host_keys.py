"""Regression tests for the SSH enrollment and verification boundary."""

import subprocess
from dataclasses import replace
from unittest.mock import patch

import pytest
import typer

from dropkit.main import wait_for_cloud_init
from dropkit.ssh_config import add_ssh_host
from dropkit.ssh_host_keys import SSHConnection, copy_host_key, import_host_key


@pytest.fixture
def connection(tmp_path):
    return SSHConnection(
        "dropkit.test", str(tmp_path / "ssh config"), 123, address="192.0.2.1", user="test"
    )


def test_enrollment_precedes_cloud_init_command(connection):
    with patch("dropkit.main.time.sleep"), patch("subprocess.run") as run:

        def ssh(argv, **kwargs):
            if "-N" in argv:
                assert "StrictHostKeyChecking=accept-new" in argv
                assert "HostName=192.0.2.1" in argv
                assert "ForwardAgent=no" in argv
                connection.known_hosts.write_text("enrolled key\n")
                return subprocess.CompletedProcess(argv, 255, b"", b"Permission denied")

            assert connection.known_hosts.is_file()
            assert "StrictHostKeyChecking=yes" in argv
            # Preserve cloud-init's structured errors on nonzero exit.
            return subprocess.CompletedProcess(argv, 2, b'{"status":"error"}', b"")

        run.side_effect = ssh
        assert wait_for_cloud_init(connection) == (False, True)
        assert run.call_count == 2


def test_cannot_continue_without_saving_the_pin(connection):
    with patch("dropkit.main.time.sleep"), patch("subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess([], 255, b"", b"Connection refused")
        with pytest.raises(typer.Exit):
            wait_for_cloud_init(connection)
        assert run.call_count
        assert all("-N" in call.args[0] for call in run.call_args_list)


def test_changed_key_stops_cloud_init_polling(connection):
    connection.known_hosts.parent.mkdir()
    connection.known_hosts.write_text("existing pin\n")
    with patch("dropkit.main.time.sleep"), patch("subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess(
            [], 255, b"", b"Host key verification failed."
        )
        with pytest.raises(typer.Exit):
            wait_for_cloud_init(connection)

    run.assert_called_once()
    assert "StrictHostKeyChecking=yes" in run.call_args.args[0]
    assert connection.known_hosts.read_text() == "existing pin\n"


def test_snapshot_pin_copies_without_replacing_existing_pin(connection, tmp_path):
    snapshot = tmp_path / "snapshot"
    snapshot.write_bytes(b"snapshot pin\n")
    copy_host_key(snapshot, connection.known_hosts)
    assert connection.known_hosts.read_bytes() == b"snapshot pin\n"
    snapshot.write_bytes(b"another pin\n")
    copy_host_key(snapshot, connection.known_hosts)
    assert connection.known_hosts.read_bytes() == b"snapshot pin\n"


def test_config_uses_same_pin_after_route_change_and_rename(connection):
    config = connection.config_path
    with open(config, "w") as config_file:
        config_file.write("Host *\n    StrictHostKeyChecking no\n")
    renamed = replace(connection, hostname="dropkit.renamed", address="100.64.0.5")
    add_ssh_host(config, renamed.hostname, "100.64.0.5", "test", known_hosts=renamed.known_hosts)

    assert renamed.known_hosts == connection.known_hosts
    assert replace(connection, droplet_id=456).known_hosts != connection.known_hosts
    result = subprocess.run(
        ["ssh", "-G", "-F", config, renamed.hostname], capture_output=True, text=True, check=True
    )
    assert "stricthostkeychecking true\n" in result.stdout or (
        "stricthostkeychecking yes\n" in result.stdout
    )
    assert f"userknownhostsfile {connection.known_hosts}\n" in result.stdout
    assert "hostname 100.64.0.5\n" in result.stdout


def test_import_requires_a_public_key(connection, tmp_path):
    key = tmp_path / "host"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    public = key.with_suffix(".pub")
    import_host_key(public, connection.known_hosts)
    pin = connection.known_hosts.read_text()
    assert pin.split()[1:] == public.read_text().split()[:2]
    with pytest.raises(ValueError, match="single SSH public"):
        import_host_key(key, connection.known_hosts)
    assert connection.known_hosts.read_text() == pin
