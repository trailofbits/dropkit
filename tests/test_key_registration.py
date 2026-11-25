"""Registration uses the fingerprint of the key content it uploads."""

import subprocess
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest
import typer

from dropkit.config import Config
from dropkit.main import add_ssh_key_cmd, register_ssh_keys_with_do
from tests.test_config import SSH_PUBLIC_KEY


def test_registration_fingerprints_second_read_before_upload(tmp_path):
    key_file = tmp_path / "id_ed25519.pub"
    key_file.write_text(SSH_PUBLIC_KEY + "\n")
    other_key = tmp_path / "other-key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(other_key)],
        check=True,
        capture_output=True,
    )
    replacement_content = other_key.with_suffix(".pub").read_text().strip()
    replacement_fingerprint = Config.compute_ssh_key_fingerprint(replacement_content)

    real_open = open
    key_reads = 0

    def changing_open(file, *args, **kwargs):
        nonlocal key_reads
        if str(file) == str(key_file):
            key_reads += 1
            return StringIO(SSH_PUBLIC_KEY if key_reads == 1 else replacement_content)
        return real_open(file, *args, **kwargs)

    api = MagicMock()
    api.get_username.return_value = "testuser"
    api.get_ssh_key_by_fingerprint.return_value = None
    api.add_ssh_key.return_value = {"id": 123}
    with (
        patch.object(Config, "detect_ssh_keys", return_value=[str(key_file)]),
        patch.object(Config, "detect_ssh_agent_keys", return_value=[]),
        patch("builtins.open", side_effect=changing_open),
    ):
        paths, ids, username = register_ssh_keys_with_do(api)

    assert (paths, ids, username) == ([str(key_file)], [123], "testuser")
    assert key_reads == 2
    api.get_ssh_key_by_fingerprint.assert_called_once_with(replacement_fingerprint)
    api.add_ssh_key.assert_called_once_with(
        f"dropkit-testuser-{replacement_fingerprint.replace(':', '')[:8]}",
        replacement_content,
    )


def test_add_ssh_key_rechecks_second_read_before_upload(tmp_path):
    key_file = tmp_path / "id_ed25519.pub"
    key_file.write_text(SSH_PUBLIC_KEY + "\n")
    api = MagicMock()
    api.get_username.return_value = "testuser"

    with (
        patch("dropkit.main.load_config_and_api", return_value=(None, api)),
        patch.object(Config, "read_ssh_key_content", return_value="not a public key"),
        pytest.raises(typer.Exit),
    ):
        add_ssh_key_cmd.__wrapped__(str(key_file))

    api.get_ssh_key_by_fingerprint.assert_not_called()
    api.add_ssh_key.assert_not_called()
