"""Tests for the list command, including agent-friendly JSON output."""

import json
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from dropkit.main import app, build_droplet_record, build_hibernated_record

runner = CliRunner()


def make_droplet(name: str = "web-prod-uksouth-01") -> dict:
    """Build a raw droplet API object for tests."""
    return {
        "id": 123,
        "name": name,
        "status": "active",
        "networks": {
            "v4": [
                {"type": "private", "ip_address": "10.0.0.1"},
                {"type": "public", "ip_address": "164.92.1.5"},
            ]
        },
        "region": {"slug": "nyc3"},
        "size_slug": "s-1vcpu-1gb",
        "size": {"price_monthly": 6},
        "tags": ["owner:me", "firewall"],
    }


class TestBuildDropletRecord:
    """Tests for build_droplet_record field extraction."""

    @patch("dropkit.main.is_tailscale_ip", return_value=True)
    @patch("dropkit.main.get_ssh_host_ip", return_value="100.1.2.3")
    @patch("dropkit.main.host_exists", return_value=True)
    def test_extracts_public_ip_and_ssh_state(self, mock_exists, mock_ip, mock_ts):
        record = build_droplet_record(make_droplet(), "~/.ssh/config")
        assert record["ip"] == "164.92.1.5"
        assert record["tailscale_ip"] == "100.1.2.3"
        assert record["in_ssh_config"] is True
        assert record["ssh_hostname"] == "dropkit.web-prod-uksouth-01"
        assert record["cost_monthly"] == 6.0

    @patch("dropkit.main.is_tailscale_ip", return_value=False)
    @patch("dropkit.main.get_ssh_host_ip", return_value=None)
    @patch("dropkit.main.host_exists", return_value=False)
    def test_missing_values_are_none(self, mock_exists, mock_ip, mock_ts):
        bare = {"id": 1, "name": "x", "status": "new", "networks": {}}
        record = build_droplet_record(bare, "~/.ssh/config")
        assert record["ip"] is None
        assert record["tailscale_ip"] is None
        assert record["region"] is None
        assert record["size"] is None
        assert record["in_ssh_config"] is False


class TestBuildHibernatedRecord:
    """Tests for build_hibernated_record field extraction."""

    def test_extracts_name_size_and_cost(self):
        snapshot = {
            "name": "dropkit-web-prod",
            "tags": ["size:s-2vcpu-2gb"],
            "size_gigabytes": 25,
            "regions": ["nyc3"],
        }
        record = build_hibernated_record(snapshot)
        assert record["name"] == "web-prod"
        assert record["droplet_size"] == "s-2vcpu-2gb"
        assert record["image_size_gb"] == 25.0
        assert record["region"] == "nyc3"
        assert record["cost_monthly"] > 0


class TestListJsonOutput:
    """Tests for `dropkit list --json`."""

    @patch("dropkit.main.is_tailscale_ip", return_value=True)
    @patch("dropkit.main.get_ssh_host_ip", return_value="100.1.2.3")
    @patch("dropkit.main.host_exists", return_value=True)
    @patch("dropkit.main.get_user_hibernated_snapshots", return_value=[])
    @patch("dropkit.main.load_config_and_api")
    def test_json_is_parseable_and_untruncated(
        self, mock_load, mock_snaps, mock_exists, mock_ip, mock_ts
    ):
        mock_api = MagicMock()
        mock_api.get_username.return_value = "me"
        mock_api.list_droplets.return_value = [make_droplet("a-very-long-droplet-name-uksouth-01")]
        mock_config_manager = MagicMock()
        mock_config_manager.config.ssh.config_path = "~/.ssh/config"
        mock_load.return_value = (mock_config_manager, mock_api)

        result = runner.invoke(app, ["list", "--json"])

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["tag"] == "owner:me"
        assert payload["droplets"][0]["name"] == "a-very-long-droplet-name-uksouth-01"
        assert payload["droplets"][0]["id"] == 123
        assert payload["total_monthly_cost"] == 6.0
        assert payload["hibernated"] == []

    @patch("dropkit.main.get_user_hibernated_snapshots", return_value=[])
    @patch("dropkit.main.load_config_and_api")
    def test_json_empty(self, mock_load, mock_snaps):
        mock_api = MagicMock()
        mock_api.get_username.return_value = "me"
        mock_api.list_droplets.return_value = []
        mock_config_manager = MagicMock()
        mock_config_manager.config.ssh.config_path = "~/.ssh/config"
        mock_load.return_value = (mock_config_manager, mock_api)

        result = runner.invoke(app, ["list", "--json"])

        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["droplets"] == []
        assert payload["total_monthly_cost"] == 0
