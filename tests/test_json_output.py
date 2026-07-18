"""Tests for machine-readable --json output across read commands."""

import json
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from dropkit.main import app, build_droplet_detail, build_droplet_record, build_ssh_key_record

runner = CliRunner()


def make_detail_droplet() -> dict:
    """Build a raw droplet API object with detail fields for info tests."""
    return {
        "id": 1,
        "name": "srv",
        "status": "active",
        "created_at": "2026-01-01T00:00:00Z",
        "networks": {
            "v4": [{"type": "public", "ip_address": "1.2.3.4"}],
            "v6": [{"type": "public", "ip_address": "2001:db8::1"}],
        },
        "region": {"slug": "nyc3"},
        "size_slug": "s-1vcpu-1gb",
        "size": {"price_monthly": 6, "vcpus": 1, "memory": 1024, "disk": 25, "transfer": 1},
        "image": {"distribution": "Ubuntu", "name": "24.04", "slug": "ubuntu-24-04-x64"},
        "tags": ["owner:me"],
        "features": ["monitoring"],
    }


class TestBuildDropletDetail:
    """Tests for build_droplet_detail field extraction."""

    @patch("dropkit.main.is_tailscale_ip", return_value=False)
    @patch("dropkit.main.get_ssh_host_ip", return_value=None)
    @patch("dropkit.main.host_exists", return_value=True)
    def test_includes_base_and_detail_fields(self, mock_exists, mock_ip, mock_ts):
        detail = build_droplet_detail(make_detail_droplet(), "~/.ssh/config")
        # Base fields from build_droplet_record
        assert detail["ip"] == "1.2.3.4"
        assert detail["in_ssh_config"] is True
        # Detail-only fields
        assert detail["vcpus"] == 1
        assert detail["memory_mb"] == 1024
        assert detail["disk_gb"] == 25
        assert detail["image"]["slug"] == "ubuntu-24-04-x64"
        assert detail["features"] == ["monitoring"]
        # Full networks include IPv6
        assert detail["networks"]["v6"][0]["ip_address"] == "2001:db8::1"


class TestBuildDropletRecord:
    """Tests for build_droplet_record contract guarantees."""

    @patch("dropkit.main.is_tailscale_ip", return_value=False)
    @patch("dropkit.main.get_ssh_host_ip", return_value=None)
    @patch("dropkit.main.host_exists", return_value=False)
    def test_cost_monthly_none_when_price_absent(self, mock_exists, mock_ip, mock_ts):
        record = build_droplet_record({"name": "srv", "size": {}}, "~/.ssh/config")
        assert record["cost_monthly"] is None

    @patch("dropkit.main.is_tailscale_ip", return_value=False)
    @patch("dropkit.main.get_ssh_host_ip", return_value=None)
    @patch("dropkit.main.host_exists", return_value=False)
    def test_cost_monthly_zero_is_preserved(self, mock_exists, mock_ip, mock_ts):
        # A genuine $0 resource must stay 0.0, distinct from an unknown price.
        record = build_droplet_record(
            {"name": "srv", "size": {"price_monthly": 0}}, "~/.ssh/config"
        )
        assert record["cost_monthly"] == 0.0

    @patch("dropkit.main.is_tailscale_ip", return_value=False)
    @patch("dropkit.main.get_ssh_host_ip", return_value=None)
    @patch("dropkit.main.host_exists", return_value=False)
    def test_explicit_null_nested_objects_do_not_raise(self, mock_exists, mock_ip, mock_ts):
        # DO can serialize absent relations as null rather than omitting the key.
        droplet = {"name": "srv", "size": None, "region": None, "networks": None}
        record = build_droplet_record(droplet, "~/.ssh/config")
        assert record["cost_monthly"] is None
        assert record["region"] is None
        assert record["ip"] is None


class TestBuildDropletDetailNullSafety:
    """Tests that build_droplet_detail tolerates explicit-null nested objects."""

    @patch("dropkit.main.is_tailscale_ip", return_value=False)
    @patch("dropkit.main.get_ssh_host_ip", return_value=None)
    @patch("dropkit.main.host_exists", return_value=False)
    def test_null_size_and_image(self, mock_exists, mock_ip, mock_ts):
        detail = build_droplet_detail({"name": "srv", "size": None, "image": None}, "~/.ssh/config")
        assert detail["vcpus"] is None
        assert detail["image"]["slug"] is None


class TestInfoJsonErrors:
    """Tests that error paths keep stdout a clean JSON stream in --json mode."""

    @patch("dropkit.main.find_user_droplet")
    @patch("dropkit.main.load_config_and_api")
    def test_not_found_emits_json_error_on_stderr(self, mock_load, mock_find):
        mock_find.return_value = (None, "me")
        mock_load.return_value = (MagicMock(), MagicMock())

        result = runner.invoke(app, ["info", "missing", "--json"])

        assert result.exit_code == 1
        # stdout stays clean so `... --json | jq .` never sees the error text.
        assert result.stdout == ""
        error = json.loads(result.stderr)
        assert "missing" in error["error"]


class TestBuildSshKeyRecord:
    """Tests for build_ssh_key_record field extraction."""

    def test_extracts_name_id_fingerprint(self):
        record = build_ssh_key_record({"name": "k", "id": 9, "fingerprint": "aa:bb"})
        assert record == {"name": "k", "id": 9, "fingerprint": "aa:bb"}

    def test_missing_fields_are_none(self):
        assert build_ssh_key_record({}) == {"name": None, "id": None, "fingerprint": None}


class TestInfoJson:
    """Tests for `dropkit info --json`."""

    @patch("dropkit.main.is_tailscale_ip", return_value=False)
    @patch("dropkit.main.get_ssh_host_ip", return_value=None)
    @patch("dropkit.main.host_exists", return_value=True)
    @patch("dropkit.main.find_user_droplet")
    @patch("dropkit.main.load_config_and_api")
    def test_info_json_parseable(self, mock_load, mock_find, mock_exists, mock_ip, mock_ts):
        droplet = make_detail_droplet()
        mock_find.return_value = (droplet, "me")
        api = MagicMock()
        api.get_droplet.return_value = droplet
        cm = MagicMock()
        cm.config.ssh.config_path = "~/.ssh/config"
        mock_load.return_value = (cm, api)

        result = runner.invoke(app, ["info", "srv", "--json"])

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["name"] == "srv"
        assert payload["vcpus"] == 1


class TestListSshKeysJson:
    """Tests for `dropkit list-ssh-keys --json`."""

    @patch("dropkit.main.load_config_and_api")
    def test_only_dropkit_keys_returned(self, mock_load):
        api = MagicMock()
        api.get_username.return_value = "me"
        api.list_ssh_keys.return_value = [
            {"name": "dropkit-me-laptop", "id": 9, "fingerprint": "aa:bb"},
            {"name": "someone-elses-key", "id": 2, "fingerprint": "cc:dd"},
        ]
        mock_load.return_value = (MagicMock(), api)

        result = runner.invoke(app, ["list-ssh-keys", "--json"])

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["username"] == "me"
        assert [k["name"] for k in payload["ssh_keys"]] == ["dropkit-me-laptop"]

    @patch("dropkit.main.load_config_and_api")
    def test_empty_keys(self, mock_load):
        api = MagicMock()
        api.get_username.return_value = "me"
        api.list_ssh_keys.return_value = []
        mock_load.return_value = (MagicMock(), api)

        result = runner.invoke(app, ["list-ssh-keys", "--json"])

        assert result.exit_code == 0
        assert json.loads(result.output)["ssh_keys"] == []


class TestVersionJson:
    """Tests for `dropkit version --json`."""

    def test_version_json(self):
        result = runner.invoke(app, ["version", "--json"])
        assert result.exit_code == 0
        assert "version" in json.loads(result.output)
